//! `UpstreamRepo` over Postgres: the proxy cache (decision 07, S-19).
//!
//! Two rules are carried by SQL here rather than by the caller, because they are the ones a
//! bug would make invisible:
//!
//! - **A snapshot is an upsert, never a replace.** Versions absent from a newer listing keep
//!   their rows: we may already hold their bytes, and a hash in somebody's `pubspec.lock` has
//!   to keep resolving (docs/protocol.md sharp edge 3).
//! - **`archive_sha256` and `archive_size` freeze once `cached` is set** (S-19 byte-drift). The upsert's
//!   `CASE WHEN upstream_versions.cached THEN … END` is what makes "upstream changed its mind
//!   about bytes we already store" a *detectable* event instead of a silent overwrite of the
//!   hash we serve under. The size is frozen with it because it is *measured* while caching
//!   — upstream listings carry no size — and a later claim must not make the served
//!   `Content-Length` disagree with the bytes. The size is frozen with it because it is *measured* while caching
//!   — upstream listings carry no size — and a later claim must not make the served
//!   `Content-Length` disagree with the bytes.
//!
//! `JSONB` columns are bound as text with an explicit `::jsonb` cast and read back with
//! `::text`, matching the convention of the other repositories in this crate.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::package::{
    NewQuarantineEntry, NewShadowingAlarm, QuarantineEntry, ShadowingAlarm, UpstreamCacheEntry, UpstreamPackage,
    UpstreamSnapshot, UpstreamVersion,
};
use pub_core::page::{decode_cursor, decode_cursor_time, encode_cursor, encode_cursor_time};
use pub_core::traits::UpstreamRepo;
use pub_core::{Error, Format, OrgId, PackageId, Page, Result, SemVer, VersionId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// The quarantine page statement, with or without its keyset predicate
/// ([S-19.b](../../../../docs/security.md#4-supply-chain--registry-integrity)).
///
/// **Exported so the plan test can EXPLAIN the statement production emits instead of a copy of
/// it** — the drift roadmap [D52](../../../../docs/roadmap.md) describes, avoided here rather
/// than repeated. Binds, in order: the four cursor components when `with_cursor` (the first as a
/// `TIMESTAMPTZ`), then the row limit.
///
/// The seek is one row-value comparison over the whole key, descending in every component, which
/// is the direction pattern `upstream_quarantine_page_idx` (0015) carries. `last_seen_at` alone
/// is not a total order on this table — a tampering incident writes a block of rows inside one
/// fetch loop — so a cursor over it would skip or repeat rows.
pub fn quarantine_page_sql(with_cursor: bool) -> &'static str {
    if with_cursor {
        concat!(
            "SELECT format, name, version, upstream, expected_sha256, actual_sha256, occurrences, ",
            "first_seen_at, last_seen_at FROM upstream_quarantine ",
            "WHERE (last_seen_at, format, name, version) < ($1, $2, $3, $4) ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC, version DESC LIMIT $5",
        )
    } else {
        concat!(
            "SELECT format, name, version, upstream, expected_sha256, actual_sha256, occurrences, ",
            "first_seen_at, last_seen_at FROM upstream_quarantine ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC, version DESC LIMIT $1",
        )
    }
}

/// The shadowing page statement for one filter slice, with or without its keyset predicate
/// ([S-17.b](../../../../docs/security.md#4-supply-chain--registry-integrity)).
///
/// Exported for the same reason as [`quarantine_page_sql`]. Binds, in order: the three cursor
/// components when `with_cursor`, then the row limit.
///
/// The filter is baked into the statement rather than passed as a parameter: the old
/// `WHERE (NOT $1 OR acknowledged_at IS NULL)` shape cannot use a partial index at all, because
/// the planner has to assume the branch that reads every row. `Some(true)` seeks
/// `shadowing_alarms_active_idx`, the other two seek `shadowing_alarms_page_idx`.
pub fn shadowing_page_sql(active: Option<bool>, with_cursor: bool) -> &'static str {
    match (active, with_cursor) {
        (None, false) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $1",
        ),
        (None, true) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms ",
            "WHERE (last_seen_at, format, name) < ($1, $2, $3) ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $4",
        ),
        (Some(true), false) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms WHERE acknowledged_at IS NULL ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $1",
        ),
        (Some(true), true) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms WHERE acknowledged_at IS NULL ",
            "AND (last_seen_at, format, name) < ($1, $2, $3) ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $4",
        ),
        (Some(false), false) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms WHERE acknowledged_at IS NOT NULL ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $1",
        ),
        (Some(false), true) => concat!(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, ",
            "last_seen_at, acknowledged_at FROM shadowing_alarms WHERE acknowledged_at IS NOT NULL ",
            "AND (last_seen_at, format, name) < ($1, $2, $3) ",
            "ORDER BY last_seen_at DESC, format DESC, name DESC LIMIT $4",
        ),
    }
}

/// All upstream-package columns, in [`UpstreamPackageRow`] order.
const PKG_COLS: &str = "id, format, name, upstream, discontinued, replaced_by, advisories_updated, \
                        listing::text AS listing, fetched_at";

/// All upstream-version columns, in [`UpstreamVersionRow`] order.
const VER_COLS: &str = "id, upstream_package_id, version, pubspec::text AS pubspec, archive_sha256, archive_size, \
                        retracted, cached, published_at, fetched_at";

/// Postgres-backed [`UpstreamRepo`].
#[derive(Debug, Clone)]
pub struct PgUpstreamRepo {
    pool: PgPool,
}

impl PgUpstreamRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct UpstreamPackageRow {
    id: Uuid,
    format: String,
    name: String,
    upstream: String,
    discontinued: bool,
    replaced_by: Option<String>,
    advisories_updated: Option<String>,
    listing: Option<String>,
    fetched_at: DateTime<Utc>,
}

impl TryFrom<UpstreamPackageRow> for UpstreamPackage {
    type Error = Error;

    fn try_from(row: UpstreamPackageRow) -> Result<Self> {
        Ok(UpstreamPackage {
            id: PackageId::from_uuid(row.id),
            format: parse_col(&row.format)?,
            name: row.name,
            upstream: row.upstream,
            discontinued: row.discontinued,
            replaced_by: row.replaced_by,
            advisories_updated: row.advisories_updated,
            listing: row
                .listing
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|err| Error::Database { message: format!("corrupt upstream listing json: {err}") })?,
            fetched_at: row.fetched_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct UpstreamVersionRow {
    id: Uuid,
    upstream_package_id: Uuid,
    version: String,
    pubspec: String,
    archive_sha256: String,
    archive_size: Option<i64>,
    retracted: bool,
    cached: bool,
    published_at: Option<DateTime<Utc>>,
    fetched_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct QuarantineRow {
    format: String,
    name: String,
    version: String,
    upstream: String,
    expected_sha256: String,
    actual_sha256: String,
    occurrences: i64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

impl TryFrom<QuarantineRow> for QuarantineEntry {
    type Error = Error;

    fn try_from(row: QuarantineRow) -> Result<Self> {
        Ok(QuarantineEntry {
            format: parse_col(&row.format)?,
            name: row.name,
            version: row.version,
            upstream: row.upstream,
            expected_sha256: row.expected_sha256,
            actual_sha256: row.actual_sha256,
            occurrences: row.occurrences,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ShadowingRow {
    format: String,
    name: String,
    org_id: Uuid,
    upstream: String,
    upstream_version: Option<String>,
    observations: i64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    acknowledged_at: Option<DateTime<Utc>>,
}

impl TryFrom<ShadowingRow> for ShadowingAlarm {
    type Error = Error;

    fn try_from(row: ShadowingRow) -> Result<Self> {
        Ok(ShadowingAlarm {
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: OrgId::from_uuid(row.org_id),
            upstream: row.upstream,
            upstream_version: row.upstream_version,
            observations: row.observations,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            acknowledged_at: row.acknowledged_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CacheEntryRow {
    format: String,
    name: String,
    upstream: String,
    discontinued: bool,
    fetched_at: DateTime<Utc>,
    versions: i64,
    cached_versions: i64,
    cached_bytes: i64,
}

impl TryFrom<CacheEntryRow> for UpstreamCacheEntry {
    type Error = Error;

    fn try_from(row: CacheEntryRow) -> Result<Self> {
        Ok(UpstreamCacheEntry {
            format: parse_col(&row.format)?,
            name: row.name,
            upstream: row.upstream,
            versions: row.versions,
            cached_versions: row.cached_versions,
            cached_bytes: row.cached_bytes,
            discontinued: row.discontinued,
            fetched_at: row.fetched_at,
        })
    }
}

impl TryFrom<UpstreamVersionRow> for UpstreamVersion {
    type Error = Error;

    fn try_from(row: UpstreamVersionRow) -> Result<Self> {
        Ok(UpstreamVersion {
            id: VersionId::from_uuid(row.id),
            upstream_package_id: PackageId::from_uuid(row.upstream_package_id),
            version: parse_col::<SemVer>(&row.version)?,
            pubspec: serde_json::from_str(&row.pubspec)
                .map_err(|err| Error::Database { message: format!("corrupt upstream pubspec json: {err}") })?,
            archive_sha256: row.archive_sha256,
            archive_size: row.archive_size,
            retracted: row.retracted,
            cached: row.cached,
            published_at: row.published_at,
            fetched_at: row.fetched_at,
        })
    }
}

#[async_trait]
impl UpstreamRepo for PgUpstreamRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn get_package(&self, format: Format, name: &str) -> Result<Option<UpstreamPackage>> {
        let row: Option<UpstreamPackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM upstream_packages WHERE format = $1 AND name = $2"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_versions(&self, package: PackageId) -> Result<Vec<UpstreamVersion>> {
        // `version_sort` carries `COLLATE "C"` (migration 0004), so this ordering is the same
        // bytewise semver precedence a local listing comes out in.
        let rows: Vec<UpstreamVersionRow> = sqlx::query_as(q!(
            "SELECT {VER_COLS} FROM upstream_versions WHERE upstream_package_id = $1 ORDER BY version_sort, id"
        ))
        .bind(*package.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<UpstreamVersion>> {
        let row: Option<UpstreamVersionRow> = sqlx::query_as(q!(
            "SELECT {VER_COLS} FROM upstream_versions WHERE upstream_package_id = $1 AND version = $2"
        ))
        .bind(*package.as_uuid())
        .bind(version.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn save_snapshot(&self, snapshot: UpstreamSnapshot, now: DateTime<Utc>) -> Result<UpstreamPackage> {
        let listing = snapshot
            .listing
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| Error::Internal { message: format!("failed to encode upstream listing: {err}") })?;

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let package: UpstreamPackageRow = sqlx::query_as(q!(
            "INSERT INTO upstream_packages (id, format, name, upstream, discontinued, replaced_by, \
             advisories_updated, listing, fetched_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9) \
             ON CONFLICT (format, name) DO UPDATE SET upstream = excluded.upstream, \
             discontinued = excluded.discontinued, replaced_by = excluded.replaced_by, \
             advisories_updated = excluded.advisories_updated, listing = excluded.listing, \
             fetched_at = excluded.fetched_at RETURNING {PKG_COLS}"
        ))
        .bind(*PackageId::new().as_uuid())
        .bind(snapshot.format.as_str())
        .bind(&snapshot.name)
        .bind(&snapshot.upstream)
        .bind(snapshot.discontinued)
        .bind(snapshot.replaced_by.as_deref())
        .bind(snapshot.advisories_updated.as_deref())
        .bind(listing.as_deref())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        for version in &snapshot.versions {
            let pubspec = serde_json::to_string(&version.pubspec)
                .map_err(|err| Error::Internal { message: format!("failed to encode upstream pubspec: {err}") })?;
            sqlx::query(
                "INSERT INTO upstream_versions (id, upstream_package_id, version, version_sort, pubspec, \
                 archive_sha256, archive_size, retracted, cached, published_at, fetched_at) \
                 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, FALSE, $9, $10) \
                 ON CONFLICT (upstream_package_id, version) DO UPDATE SET pubspec = excluded.pubspec, \
                 archive_sha256 = CASE WHEN upstream_versions.cached THEN upstream_versions.archive_sha256 \
                 ELSE excluded.archive_sha256 END, \
                 archive_size = CASE WHEN upstream_versions.cached THEN upstream_versions.archive_size \
                 ELSE COALESCE(excluded.archive_size, upstream_versions.archive_size) END, \
                 retracted = excluded.retracted, \
                 published_at = excluded.published_at, fetched_at = excluded.fetched_at",
            )
            .bind(*VersionId::new().as_uuid())
            .bind(package.id)
            .bind(version.version.to_string())
            .bind(version.version.sort_key())
            .bind(&pubspec)
            .bind(&version.archive_sha256)
            .bind(version.archive_size)
            .bind(version.retracted)
            .bind(version.published_at)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        package.try_into()
    }

    async fn mark_cached(&self, id: VersionId, sha256: &str, size: i64, now: DateTime<Utc>) -> Result<bool> {
        // The hash is part of the predicate: a row whose hash moved under a concurrent
        // snapshot must not be marked cached for bytes that are no longer what it advertises.
        let result = sqlx::query(
            "UPDATE upstream_versions SET cached = TRUE, archive_size = $1, fetched_at = $2 \
             WHERE id = $3 AND archive_sha256 = $4",
        )
        .bind(size)
        .bind(now)
        .bind(*id.as_uuid())
        .bind(sha256)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_stale(&self, format: Format, before: DateTime<Utc>, limit: u32) -> Result<Vec<UpstreamPackage>> {
        let rows: Vec<UpstreamPackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM upstream_packages WHERE format = $1 AND fetched_at < $2 \
             ORDER BY fetched_at, name LIMIT $3"))
            .bind(format.as_str())
            .bind(before)
            .bind(i64::from(limit.clamp(1, MAX_PAGE)))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_cached(&self, format: Format, cursor: Option<&str>, limit: u32) -> Result<Page<UpstreamCacheEntry>> {
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        // The aggregate is computed in SQL: the alternative is one query per package for a
        // screen that lists hundreds of them.
        // The `::bigint` casts are load-bearing: `SUM()` over a `BIGINT` column answers
        // `NUMERIC` in Postgres, which does not decode into `i64` — and the SQLite backend
        // returns an integer, so without them the two backends would disagree on the row type.
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT p.format AS format, p.name AS name, p.upstream AS upstream, p.discontinued AS discontinued, \
             p.fetched_at AS fetched_at, COUNT(v.id) AS versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN 1 ELSE 0 END), 0)::bigint AS cached_versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN COALESCE(v.archive_size, 0) ELSE 0 END), 0)::bigint AS cached_bytes \
             FROM upstream_packages p LEFT JOIN upstream_versions v ON v.upstream_package_id = p.id \
             WHERE p.format = ",
        );
        query.push_bind(format.as_str());
        if let Some(cursor) = cursor {
            let parts = decode_cursor(cursor, 1)?;
            query.push(" AND p.name > ").push_bind(parts[0].clone());
        }
        query.push(" GROUP BY p.id ORDER BY p.name LIMIT ").push_bind(limit + 1);

        let rows: Vec<CacheEntryRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<UpstreamCacheEntry> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more { items.last().map(|entry| encode_cursor(&[&entry.name])) } else { None };
        Ok(Page { items, cursor, has_more })
    }

    async fn cache_stats(&self, format: Format) -> Result<pub_core::package::UpstreamCacheStats> {
        let row: PgRow = sqlx::query(
            "SELECT (SELECT COUNT(*) FROM upstream_packages WHERE format = $1) AS packages, \
             COUNT(v.id) AS versions, \
             COUNT(*) FILTER (WHERE v.cached) AS cached_versions, \
             COALESCE(SUM(v.archive_size) FILTER (WHERE v.cached), 0)::bigint AS cached_bytes \
             FROM upstream_versions v JOIN upstream_packages p ON p.id = v.upstream_package_id WHERE p.format = $1",
        )
        .bind(format.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(pub_core::package::UpstreamCacheStats {
            packages: row.get("packages"),
            versions: row.get("versions"),
            cached_versions: row.get("cached_versions"),
            cached_bytes: row.get("cached_bytes"),
        })
    }

    async fn count_cached_with_sha256(&self, sha256: &str) -> Result<u64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upstream_versions WHERE archive_sha256 = $1 AND cached")
                .bind(sha256)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(count.max(0) as u64)
    }

    async fn cached_sha256s(&self, hashes: &[String]) -> Result<HashSet<String>> {
        if hashes.is_empty() {
            return Ok(HashSet::new());
        }
        // `cached` is the whole distinction: a snapshot row carries the hash upstream advertised
        // long before this instance holds bytes for it, and only the rows that hold bytes are
        // blob references. `upstream_versions_sha256_idx` (0013) serves this.
        let found: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT archive_sha256 FROM upstream_versions WHERE cached AND archive_sha256 = ANY($1)",
        )
        .bind(hashes)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(found.into_iter().collect())
    }

    async fn record_quarantine(&self, entry: NewQuarantineEntry, now: DateTime<Utc>) -> Result<QuarantineEntry> {
        let row: QuarantineRow = sqlx::query_as(
            "INSERT INTO upstream_quarantine (format, name, version, upstream, expected_sha256, actual_sha256, \
             occurrences, first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $7) \
             ON CONFLICT (format, name, version) DO UPDATE SET upstream = excluded.upstream, \
             expected_sha256 = excluded.expected_sha256, actual_sha256 = excluded.actual_sha256, \
             occurrences = upstream_quarantine.occurrences + 1, last_seen_at = excluded.last_seen_at \
             RETURNING format, name, version, upstream, expected_sha256, actual_sha256, occurrences, first_seen_at, \
             last_seen_at",
        )
        .bind(entry.format.as_str())
        .bind(&entry.name)
        .bind(&entry.version)
        .bind(&entry.upstream)
        .bind(&entry.expected_sha256)
        .bind(&entry.actual_sha256)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_into()
    }

    async fn list_quarantine(&self, cursor: Option<&str>, limit: u32) -> Result<Page<QuarantineEntry>> {
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let keyset = cursor.map(|cursor| decode_cursor(cursor, 4)).transpose()?;
        let mut query = sqlx::query_as(quarantine_page_sql(keyset.is_some()));
        if let Some(parts) = &keyset {
            // The instant is parsed rather than bound as text: the column is `TIMESTAMPTZ`, and
            // a string bind would either fail the comparison or force a per-row cast that no
            // index can serve. A malformed instant inside a caller's cursor is `Invalid` — a
            // 400 — exactly like a malformed cursor envelope.
            query = query
                .bind(decode_cursor_time(&parts[0])?)
                .bind(parts[1].clone())
                .bind(parts[2].clone())
                .bind(parts[3].clone());
        }
        let rows: Vec<QuarantineRow> = query.bind(limit + 1).fetch_all(&self.pool).await.map_err(db_err)?;

        let has_more = rows.len() as i64 > limit;
        let items: Vec<QuarantineEntry> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more {
            items.last().map(|entry| {
                encode_cursor(&[
                    &encode_cursor_time(entry.last_seen_at),
                    entry.format.as_str(),
                    &entry.name,
                    &entry.version,
                ])
            })
        } else {
            None
        };
        Ok(Page { items, cursor, has_more })
    }

    async fn purge_quarantine_before(&self, cutoff: DateTime<Utc>, batch: u32) -> Result<u64> {
        // Bounded like every other retention delete (decision 30). The inner `ORDER BY
        // last_seen_at` takes the oldest rows first, so the caller's loop converges instead of
        // revisiting an arbitrary slice of the same backlog.
        let deleted = sqlx::query(
            "DELETE FROM upstream_quarantine WHERE (format, name, version) IN \
             (SELECT format, name, version FROM upstream_quarantine WHERE last_seen_at < $1 \
              ORDER BY last_seen_at LIMIT $2)",
        )
        .bind(cutoff)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(deleted.rows_affected())
    }

    async fn record_shadowing(&self, alarm: NewShadowingAlarm, now: DateTime<Utc>) -> Result<(ShadowingAlarm, bool)> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // `FOR UPDATE` on the alarm row: two mirror instances observing the same shadowed name
        // must not both decide they are the ones raising it (Postgres has concurrent writers).
        let existing: Option<ShadowingRow> = sqlx::query_as(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, last_seen_at, \
             acknowledged_at FROM shadowing_alarms WHERE format = $1 AND name = $2 FOR UPDATE",
        )
        .bind(alarm.format.as_str())
        .bind(&alarm.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        // A raise is the first sighting, or the first one after an admin acknowledged the
        // alarm — a re-raise starts a new incident, so `first_seen_at` moves with it. Every
        // other sighting is a counter, or a mirror sweep would re-page the same admins hourly.
        let raised = existing.as_ref().is_none_or(|row| row.acknowledged_at.is_some());
        let first_seen = match (&existing, raised) {
            (Some(row), false) => row.first_seen_at,
            _ => now,
        };
        let observations = if raised { 1 } else { existing.as_ref().map_or(1, |row| row.observations + 1) };

        let row: ShadowingRow = sqlx::query_as(
            "INSERT INTO shadowing_alarms (format, name, org_id, upstream, upstream_version, observations, \
             first_seen_at, last_seen_at, acknowledged_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL) \
             ON CONFLICT (format, name) DO UPDATE SET org_id = excluded.org_id, upstream = excluded.upstream, \
             upstream_version = excluded.upstream_version, observations = excluded.observations, \
             first_seen_at = excluded.first_seen_at, last_seen_at = excluded.last_seen_at, acknowledged_at = NULL \
             RETURNING format, name, org_id, upstream, upstream_version, observations, first_seen_at, last_seen_at, \
             acknowledged_at",
        )
        .bind(alarm.format.as_str())
        .bind(&alarm.name)
        .bind(*alarm.org_id.as_uuid())
        .bind(&alarm.upstream)
        .bind(alarm.upstream_version.as_deref())
        .bind(observations)
        .bind(first_seen)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "shadowing alarm already recorded", "org"))?;
        tx.commit().await.map_err(db_err)?;
        Ok((row.try_into()?, raised))
    }

    async fn list_shadowing(
        &self,
        active: Option<bool>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<ShadowingAlarm>> {
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let keyset = cursor.map(|cursor| decode_cursor(cursor, 3)).transpose()?;
        let mut query = sqlx::query_as(shadowing_page_sql(active, keyset.is_some()));
        if let Some(parts) = &keyset {
            query = query.bind(decode_cursor_time(&parts[0])?).bind(parts[1].clone()).bind(parts[2].clone());
        }
        let rows: Vec<ShadowingRow> = query.bind(limit + 1).fetch_all(&self.pool).await.map_err(db_err)?;

        let has_more = rows.len() as i64 > limit;
        let items: Vec<ShadowingAlarm> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more {
            items.last().map(|alarm| {
                encode_cursor(&[&encode_cursor_time(alarm.last_seen_at), alarm.format.as_str(), &alarm.name])
            })
        } else {
            None
        };
        Ok(Page { items, cursor, has_more })
    }

    async fn purge_shadowing_before(&self, cutoff: DateTime<Utc>, batch: u32) -> Result<u64> {
        // `acknowledged_at IS NOT NULL` is not redundant next to the comparison: it is what
        // makes an **active** alarm undeletable at every window (S-23.b), and it is the
        // predicate `shadowing_alarms_ack_idx` is partial on. The age is the acknowledgement,
        // never the sighting.
        let deleted = sqlx::query(
            "DELETE FROM shadowing_alarms WHERE (format, name) IN \
             (SELECT format, name FROM shadowing_alarms \
              WHERE acknowledged_at IS NOT NULL AND acknowledged_at < $1 ORDER BY acknowledged_at LIMIT $2)",
        )
        .bind(cutoff)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(deleted.rows_affected())
    }

    async fn acknowledge_shadowing(&self, format: Format, name: &str, now: DateTime<Utc>) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE shadowing_alarms SET acknowledged_at = $1 \
             WHERE format = $2 AND name = $3 AND acknowledged_at IS NULL",
        )
        .bind(now)
        .bind(format.as_str())
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}
