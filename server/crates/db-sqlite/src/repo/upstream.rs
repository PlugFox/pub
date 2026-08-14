//! `UpstreamRepo` over SQLite: the proxy cache (decision 07, S-19).
//!
//! Two rules are carried by SQL here rather than by the caller, because they are the ones a
//! bug would make invisible:
//!
//! - **A snapshot is an upsert, never a replace.** Versions absent from a newer listing keep
//!   their rows: we may already hold their bytes, and a hash in somebody's `pubspec.lock` has
//!   to keep resolving (docs/protocol.md sharp edge 3).
//! - **`archive_sha256` and `archive_size` freeze once `cached` is set** (S-19 byte-drift). The upsert's
//!   `CASE WHEN cached THEN archive_sha256 ELSE excluded.archive_sha256 END` is what makes
//!   "upstream changed its mind about bytes we already store" a *detectable* event instead of
//!   a silent overwrite of the hash we serve under.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::package::{
    NewQuarantineEntry, NewShadowingAlarm, QuarantineEntry, ShadowingAlarm, UpstreamCacheEntry, UpstreamPackage,
    UpstreamSnapshot, UpstreamVersion,
};
use pub_core::page::{decode_cursor, encode_cursor};
use pub_core::traits::UpstreamRepo;
use pub_core::{Error, Format, PackageId, Page, Result, SemVer, VersionId};
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row as _, Sqlite, SqlitePool};

use super::{db_err, parse_col, parse_ts, parse_ts_opt, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All upstream-package columns, in [`UpstreamPackageRow`] order.
const PKG_COLS: &str = "id, format, name, upstream, discontinued, replaced_by, advisories_updated, listing, fetched_at";

/// All upstream-version columns, in [`UpstreamVersionRow`] order.
const VER_COLS: &str = "id, upstream_package_id, version, pubspec, archive_sha256, archive_size, retracted, cached, \
                        published_at, fetched_at";

/// SQLite-backed [`UpstreamRepo`].
#[derive(Debug, Clone)]
pub struct SqliteUpstreamRepo {
    pool: SqlitePool,
}

impl SqliteUpstreamRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct UpstreamPackageRow {
    id: String,
    format: String,
    name: String,
    upstream: String,
    discontinued: bool,
    replaced_by: Option<String>,
    advisories_updated: Option<String>,
    listing: Option<String>,
    fetched_at: String,
}

impl TryFrom<UpstreamPackageRow> for UpstreamPackage {
    type Error = Error;

    fn try_from(row: UpstreamPackageRow) -> Result<Self> {
        Ok(UpstreamPackage {
            id: parse_col(&row.id)?,
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
            fetched_at: parse_ts(&row.fetched_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct UpstreamVersionRow {
    id: String,
    upstream_package_id: String,
    version: String,
    pubspec: String,
    archive_sha256: String,
    archive_size: Option<i64>,
    retracted: bool,
    cached: bool,
    published_at: Option<String>,
    fetched_at: String,
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
    first_seen_at: String,
    last_seen_at: String,
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
            first_seen_at: parse_ts(&row.first_seen_at)?,
            last_seen_at: parse_ts(&row.last_seen_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ShadowingRow {
    format: String,
    name: String,
    org_id: String,
    upstream: String,
    upstream_version: Option<String>,
    observations: i64,
    first_seen_at: String,
    last_seen_at: String,
    acknowledged_at: Option<String>,
}

impl TryFrom<ShadowingRow> for ShadowingAlarm {
    type Error = Error;

    fn try_from(row: ShadowingRow) -> Result<Self> {
        Ok(ShadowingAlarm {
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: parse_col(&row.org_id)?,
            upstream: row.upstream,
            upstream_version: row.upstream_version,
            observations: row.observations,
            first_seen_at: parse_ts(&row.first_seen_at)?,
            last_seen_at: parse_ts(&row.last_seen_at)?,
            acknowledged_at: parse_ts_opt(row.acknowledged_at.as_deref())?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CacheEntryRow {
    format: String,
    name: String,
    upstream: String,
    discontinued: bool,
    fetched_at: String,
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
            fetched_at: parse_ts(&row.fetched_at)?,
        })
    }
}

impl TryFrom<UpstreamVersionRow> for UpstreamVersion {
    type Error = Error;

    fn try_from(row: UpstreamVersionRow) -> Result<Self> {
        Ok(UpstreamVersion {
            id: parse_col(&row.id)?,
            upstream_package_id: parse_col(&row.upstream_package_id)?,
            version: parse_col::<SemVer>(&row.version)?,
            pubspec: serde_json::from_str(&row.pubspec)
                .map_err(|err| Error::Database { message: format!("corrupt upstream pubspec json: {err}") })?,
            archive_sha256: row.archive_sha256,
            archive_size: row.archive_size,
            retracted: row.retracted,
            cached: row.cached,
            published_at: parse_ts_opt(row.published_at.as_deref())?,
            fetched_at: parse_ts(&row.fetched_at)?,
        })
    }
}

#[async_trait]
impl UpstreamRepo for SqliteUpstreamRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn get_package(&self, format: Format, name: &str) -> Result<Option<UpstreamPackage>> {
        let row: Option<UpstreamPackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM upstream_packages WHERE format = ? AND name = ?"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_versions(&self, package: PackageId) -> Result<Vec<UpstreamVersion>> {
        // `version_sort` is the same bytewise precedence key the local `versions` table uses,
        // so a proxied listing comes out in exactly the order a local one does.
        let rows: Vec<UpstreamVersionRow> = sqlx::query_as(q!(
            "SELECT {VER_COLS} FROM upstream_versions WHERE upstream_package_id = ? ORDER BY version_sort, id"
        ))
        .bind(package.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<UpstreamVersion>> {
        let row: Option<UpstreamVersionRow> = sqlx::query_as(q!(
            "SELECT {VER_COLS} FROM upstream_versions WHERE upstream_package_id = ? AND version = ?"
        ))
        .bind(package.to_string())
        .bind(version.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn save_snapshot(&self, snapshot: UpstreamSnapshot, now: DateTime<Utc>) -> Result<UpstreamPackage> {
        let stamp = super::ts(now);
        let listing = snapshot
            .listing
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| Error::Internal { message: format!("failed to encode upstream listing: {err}") })?;

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let package: UpstreamPackageRow = sqlx::query_as(q!(
            "INSERT INTO upstream_packages (id, format, name, upstream, discontinued, replaced_by, \
             advisories_updated, listing, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (format, name) DO UPDATE SET upstream = excluded.upstream, \
             discontinued = excluded.discontinued, replaced_by = excluded.replaced_by, \
             advisories_updated = excluded.advisories_updated, listing = excluded.listing, \
             fetched_at = excluded.fetched_at RETURNING {PKG_COLS}"
        ))
        .bind(PackageId::new().to_string())
        .bind(snapshot.format.as_str())
        .bind(&snapshot.name)
        .bind(&snapshot.upstream)
        .bind(snapshot.discontinued)
        .bind(snapshot.replaced_by.as_deref())
        .bind(snapshot.advisories_updated.as_deref())
        .bind(listing.as_deref())
        .bind(&stamp)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        for version in &snapshot.versions {
            let pubspec = serde_json::to_string(&version.pubspec)
                .map_err(|err| Error::Internal { message: format!("failed to encode upstream pubspec: {err}") })?;
            sqlx::query(
                "INSERT INTO upstream_versions (id, upstream_package_id, version, version_sort, pubspec, \
                 archive_sha256, archive_size, retracted, cached, published_at, fetched_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?) \
                 ON CONFLICT (upstream_package_id, version) DO UPDATE SET pubspec = excluded.pubspec, \
                 archive_sha256 = CASE WHEN upstream_versions.cached THEN upstream_versions.archive_sha256 \
                 ELSE excluded.archive_sha256 END, \
                 archive_size = CASE WHEN upstream_versions.cached THEN upstream_versions.archive_size \
                 ELSE COALESCE(excluded.archive_size, upstream_versions.archive_size) END, \
                 retracted = excluded.retracted, \
                 published_at = excluded.published_at, fetched_at = excluded.fetched_at",
            )
            .bind(VersionId::new().to_string())
            .bind(&package.id)
            .bind(version.version.to_string())
            .bind(version.version.sort_key())
            .bind(&pubspec)
            .bind(&version.archive_sha256)
            .bind(version.archive_size)
            .bind(version.retracted)
            .bind(version.published_at.map(super::ts))
            .bind(&stamp)
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
            "UPDATE upstream_versions SET cached = 1, archive_size = ?, fetched_at = ? \
             WHERE id = ? AND archive_sha256 = ?",
        )
        .bind(size)
        .bind(super::ts(now))
        .bind(id.to_string())
        .bind(sha256)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_stale(&self, format: Format, before: DateTime<Utc>, limit: u32) -> Result<Vec<UpstreamPackage>> {
        let rows: Vec<UpstreamPackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM upstream_packages WHERE format = ? AND fetched_at < ? \
             ORDER BY fetched_at, name LIMIT ?"))
            .bind(format.as_str())
            .bind(super::ts(before))
            .bind(limit.clamp(1, MAX_PAGE) as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_cached(&self, format: Format, cursor: Option<&str>, limit: u32) -> Result<Page<UpstreamCacheEntry>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        // The aggregate is computed in SQL: the alternative is one query per package for a
        // screen that lists hundreds of them.
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT p.format AS format, p.name AS name, p.upstream AS upstream, p.discontinued AS discontinued, \
             p.fetched_at AS fetched_at, COUNT(v.id) AS versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN 1 ELSE 0 END), 0) AS cached_versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN COALESCE(v.archive_size, 0) ELSE 0 END), 0) AS cached_bytes \
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
        let row: SqliteRow = sqlx::query(
            "SELECT (SELECT COUNT(*) FROM upstream_packages WHERE format = ?) AS packages, \
             COUNT(v.id) AS versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN 1 ELSE 0 END), 0) AS cached_versions, \
             COALESCE(SUM(CASE WHEN v.cached THEN COALESCE(v.archive_size, 0) ELSE 0 END), 0) AS cached_bytes \
             FROM upstream_versions v JOIN upstream_packages p ON p.id = v.upstream_package_id WHERE p.format = ?",
        )
        .bind(format.as_str())
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
            sqlx::query_scalar("SELECT COUNT(*) FROM upstream_versions WHERE archive_sha256 = ? AND cached = 1")
                .bind(sha256)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(count.max(0) as u64)
    }

    async fn cached_sha256s(&self, hashes: &[String]) -> Result<HashSet<String>> {
        if hashes.is_empty() {
            // `IN ()` does not parse on SQLite, and the answer is known without asking.
            return Ok(HashSet::new());
        }
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT DISTINCT archive_sha256 FROM upstream_versions WHERE cached = 1 AND archive_sha256 IN (",
        );
        let mut list = query.separated(", ");
        for hash in hashes {
            list.push_bind(hash.clone());
        }
        list.push_unseparated(")");
        // `cached = 1` is the whole distinction: a snapshot row carries the hash upstream
        // advertised long before this instance holds any bytes for it, and only the rows that
        // hold bytes are blob references. `upstream_versions_sha256_idx` (0013) serves this.
        let found: Vec<String> = query.build_query_scalar().fetch_all(&self.pool).await.map_err(db_err)?;
        Ok(found.into_iter().collect())
    }

    async fn record_quarantine(&self, entry: NewQuarantineEntry, now: DateTime<Utc>) -> Result<QuarantineEntry> {
        let stamp = super::ts(now);
        let row: QuarantineRow = sqlx::query_as(
            "INSERT INTO upstream_quarantine (format, name, version, upstream, expected_sha256, actual_sha256, \
             occurrences, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) \
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
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_into()
    }

    async fn list_quarantine(&self, limit: u32) -> Result<Vec<QuarantineEntry>> {
        let rows: Vec<QuarantineRow> = sqlx::query_as(
            "SELECT format, name, version, upstream, expected_sha256, actual_sha256, occurrences, first_seen_at, \
             last_seen_at FROM upstream_quarantine ORDER BY last_seen_at DESC, name LIMIT ?",
        )
        .bind(limit.clamp(1, MAX_PAGE) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn record_shadowing(&self, alarm: NewShadowingAlarm, now: DateTime<Utc>) -> Result<(ShadowingAlarm, bool)> {
        let stamp = super::ts(now);
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let existing: Option<ShadowingRow> = sqlx::query_as(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, last_seen_at, \
             acknowledged_at FROM shadowing_alarms WHERE format = ? AND name = ?",
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
            (Some(row), false) => row.first_seen_at.clone(),
            _ => stamp.clone(),
        };
        let observations = if raised { 1 } else { existing.as_ref().map_or(1, |row| row.observations + 1) };

        let row: ShadowingRow = sqlx::query_as(
            "INSERT INTO shadowing_alarms (format, name, org_id, upstream, upstream_version, observations, \
             first_seen_at, last_seen_at, acknowledged_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) \
             ON CONFLICT (format, name) DO UPDATE SET org_id = excluded.org_id, upstream = excluded.upstream, \
             upstream_version = excluded.upstream_version, observations = excluded.observations, \
             first_seen_at = excluded.first_seen_at, last_seen_at = excluded.last_seen_at, acknowledged_at = NULL \
             RETURNING format, name, org_id, upstream, upstream_version, observations, first_seen_at, last_seen_at, \
             acknowledged_at",
        )
        .bind(alarm.format.as_str())
        .bind(&alarm.name)
        .bind(alarm.org_id.to_string())
        .bind(&alarm.upstream)
        .bind(alarm.upstream_version.as_deref())
        .bind(observations)
        .bind(&first_seen)
        .bind(&stamp)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "shadowing alarm already recorded", "org"))?;
        tx.commit().await.map_err(db_err)?;
        Ok((row.try_into()?, raised))
    }

    async fn list_shadowing(&self, active_only: bool, limit: u32) -> Result<Vec<ShadowingAlarm>> {
        let rows: Vec<ShadowingRow> = sqlx::query_as(
            "SELECT format, name, org_id, upstream, upstream_version, observations, first_seen_at, last_seen_at, \
             acknowledged_at FROM shadowing_alarms WHERE (? = 0 OR acknowledged_at IS NULL) \
             ORDER BY last_seen_at DESC, name LIMIT ?",
        )
        .bind(i64::from(active_only))
        .bind(limit.clamp(1, MAX_PAGE) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn acknowledge_shadowing(&self, format: Format, name: &str, now: DateTime<Utc>) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE shadowing_alarms SET acknowledged_at = ? \
             WHERE format = ? AND name = ? AND acknowledged_at IS NULL",
        )
        .bind(super::ts(now))
        .bind(format.as_str())
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}
