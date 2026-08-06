//! `PackageRepo` over Postgres: packages, immutable versions, and name claims.
//!
//! Two things carry the registry's invariants here:
//!
//! - **`create_version` is one transaction**, and — unlike SQLite's single writer — Postgres
//!   has concurrent ones. The claim row is the serialization anchor: existing claims are read
//!   `FOR UPDATE`, and a brand-new name is decided by the `name_claims` primary key, so two
//!   simultaneous first publishes of one name produce one winner and one `Conflict`.
//! - **Ordering is `version_sort`** (the precedence key from [`pub_core::SemVer::sort_key`]),
//!   whose column is declared `COLLATE "C"` in migration 0004 — under a locale collation the
//!   key's punctuation and case rules would be folded away and pre-releases would reorder.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::package::{
    NameClaim, NewPackage, NewVersion, Package, PackageOptions, PublishedVersion, Publisher, Version, Visibility,
};
use pub_core::page::{decode_cursor, encode_cursor};
use pub_core::traits::PackageRepo;
use pub_core::{Error, Format, OrgId, PackageId, Page, Result, SemVer, VersionId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All package columns, in [`PackageRow`] order.
const PKG_COLS: &str =
    "id, format, name, org_id, visibility, discontinued, replaced_by, unlisted, created_at, updated_at";

/// All version columns, in [`VersionRow`] order (`JSONB` reads back as text — see the crate
/// docs).
const VER_COLS: &str = "id, package_id, version, pubspec::text AS pubspec, archive_sha256, archive_size, \
                        published_by, published_by_token, published_at, retracted_at, tombstone, readme_html, \
                        changelog_html";

/// All name-claim columns, in [`ClaimRow`] order.
const CLAIM_COLS: &str = "format, name, org_id, claimed_at";

/// Postgres-backed [`PackageRepo`].
#[derive(Debug, Clone)]
pub struct PgPackageRepo {
    pool: PgPool,
}

impl PgPackageRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct PackageRow {
    id: Uuid,
    format: String,
    name: String,
    org_id: Uuid,
    visibility: String,
    discontinued: bool,
    replaced_by: Option<String>,
    unlisted: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<PackageRow> for Package {
    type Error = Error;

    fn try_from(row: PackageRow) -> Result<Self> {
        Ok(Package {
            id: PackageId::from_uuid(row.id),
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: OrgId::from_uuid(row.org_id),
            visibility: parse_col::<Visibility>(&row.visibility)?,
            discontinued: row.discontinued,
            replaced_by: row.replaced_by,
            unlisted: row.unlisted,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: Uuid,
    package_id: Uuid,
    version: String,
    pubspec: String,
    archive_sha256: String,
    archive_size: i64,
    published_by: Uuid,
    published_by_token: Option<Uuid>,
    published_at: DateTime<Utc>,
    retracted_at: Option<DateTime<Utc>>,
    tombstone: bool,
    readme_html: Option<String>,
    changelog_html: Option<String>,
}

impl TryFrom<VersionRow> for Version {
    type Error = Error;

    fn try_from(row: VersionRow) -> Result<Self> {
        Ok(Version {
            id: VersionId::from_uuid(row.id),
            package_id: PackageId::from_uuid(row.package_id),
            version: parse_col::<SemVer>(&row.version)?,
            pubspec: serde_json::from_str(&row.pubspec)
                .map_err(|err| Error::Database { message: format!("corrupt pubspec json: {err}") })?,
            archive_sha256: row.archive_sha256,
            archive_size: row.archive_size,
            published_by: Publisher {
                user_id: pub_core::UserId::from_uuid(row.published_by),
                token_id: row.published_by_token.map(pub_core::TokenId::from_uuid),
            },
            published_at: row.published_at,
            retracted_at: row.retracted_at,
            tombstone: row.tombstone,
            readme_html: row.readme_html,
            changelog_html: row.changelog_html,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ClaimRow {
    format: String,
    name: String,
    org_id: Uuid,
    claimed_at: DateTime<Utc>,
}

impl TryFrom<ClaimRow> for NameClaim {
    type Error = Error;

    fn try_from(row: ClaimRow) -> Result<Self> {
        Ok(NameClaim {
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: OrgId::from_uuid(row.org_id),
            claimed_at: row.claimed_at,
        })
    }
}

/// Takes the `(format, name)` claim inside a transaction: locks an existing claim row and
/// verifies ownership, or inserts a new one.
///
/// The `FOR UPDATE` lock is what serializes concurrent publishes of the same package under
/// Postgres' concurrent writers; a brand-new name is serialized by the primary key instead.
/// A name held by another org is [`Error::Forbidden`], and the message names only the package
/// — the API layer decides how much of that a caller may learn (S-04).
async fn claim_for(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    format: Format,
    name: &str,
    org: OrgId,
    now: DateTime<Utc>,
) -> Result<()> {
    let existing: Option<PgRow> =
        sqlx::query("SELECT org_id FROM name_claims WHERE format = $1 AND name = $2 FOR UPDATE")
            .bind(format.as_str())
            .bind(name)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err)?;

    match existing {
        Some(row) => {
            let holder = OrgId::from_uuid(row.get::<Uuid, _>("org_id"));
            if holder == org {
                Ok(())
            } else {
                Err(Error::Forbidden { message: format!("package name {name:?} is claimed by another organization") })
            }
        }
        None => {
            sqlx::query("INSERT INTO name_claims (format, name, org_id, claimed_at) VALUES ($1, $2, $3, $4)")
                .bind(format.as_str())
                .bind(name)
                .bind(*org.as_uuid())
                .bind(now)
                .execute(&mut **tx)
                .await
                // A concurrent first publish of the same name got there first.
                .map_err(|err| write_err(err, &format!("package name {name:?} was just claimed"), "org"))?;
            Ok(())
        }
    }
}

/// Reservation paths (`create_package`, `claim_name`) report a foreign holder as a plain
/// conflict: unlike a publish, they are not an authorization decision about a package that
/// exists, they are "this name is taken".
fn taken(err: Error, name: &str) -> Error {
    match err {
        Error::Forbidden { .. } => Error::Conflict { message: format!("package name {name:?} is already claimed") },
        other => other,
    }
}

#[async_trait]
impl PackageRepo for PgPackageRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create_package(&self, new: NewPackage, now: DateTime<Utc>) -> Result<Package> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, new.format, &new.name, new.org_id, now).await.map_err(|err| taken(err, &new.name))?;
        let row: PackageRow = sqlx::query_as(q!(
            "INSERT INTO packages (id, format, name, org_id, visibility, discontinued, replaced_by, unlisted, \
             created_at, updated_at) VALUES ($1, $2, $3, $4, $5, FALSE, NULL, FALSE, $6, $6) RETURNING {PKG_COLS}"
        ))
        .bind(*PackageId::new().as_uuid())
        .bind(new.format.as_str())
        .bind(&new.name)
        .bind(*new.org_id.as_uuid())
        .bind(new.visibility.as_str())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, &format!("package {:?} already exists", new.name), "org"))?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn get_package(&self, id: PackageId) -> Result<Option<Package>> {
        let row: Option<PackageRow> = sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE id = $1"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_name(&self, format: Format, name: &str) -> Result<Option<Package>> {
        let row: Option<PackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE format = $1 AND name = $2"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_for_org(&self, org: OrgId, cursor: Option<&str>, limit: u32) -> Result<Page<Package>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Postgres> =
            QueryBuilder::new(format!("SELECT {PKG_COLS} FROM packages WHERE org_id = "));
        query.push_bind(*org.as_uuid());
        if let Some(cursor) = cursor {
            // Keyset over (name, id): the id breaks ties that cannot occur today (names are
            // unique per format) but would appear the moment a listing spans formats.
            let parts = decode_cursor(cursor, 2)?;
            let id: Uuid =
                parts[1].parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {cursor}") })?;
            query.push(" AND (name > ").push_bind(parts[0].clone());
            query.push(" OR (name = ").push_bind(parts[0].clone());
            query.push(" AND id > ").push_bind(id).push("))");
        }
        query.push(" ORDER BY name, id LIMIT ").push_bind(limit + 1);

        let rows: Vec<PackageRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<Package> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more {
            items.last().map(|package| encode_cursor(&[&package.name, &package.id.to_string()]))
        } else {
            None
        };
        Ok(Page { items, cursor, has_more })
    }

    async fn set_options(&self, id: PackageId, options: &PackageOptions, now: DateTime<Utc>) -> Result<Package> {
        let row: Option<PackageRow> = sqlx::query_as(q!(
            "UPDATE packages SET visibility = $1, discontinued = $2, replaced_by = $3, unlisted = $4, \
             updated_at = $5 WHERE id = $6 RETURNING {PKG_COLS}"
        ))
        .bind(options.visibility.as_str())
        .bind(options.discontinued)
        .bind(options.replaced_by.as_deref())
        .bind(options.unlisted)
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("package {id}") })?.try_into()
    }

    async fn create_version(&self, new: NewVersion, now: DateTime<Utc>) -> Result<PublishedVersion> {
        let pubspec = serde_json::to_string(&new.pubspec)
            .map_err(|err| Error::Internal { message: format!("failed to encode pubspec json: {err}") })?;

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, new.format, &new.package_name, new.org_id, now).await?;

        // First publish of the name creates the package row in the same transaction.
        let existing: Option<PackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE format = $1 AND name = $2 FOR UPDATE"))
                .bind(new.format.as_str())
                .bind(&new.package_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let (package_row, package_created) = match existing {
            Some(row) => {
                // Defense in depth: the claim already proved ownership, but a package row
                // pointing elsewhere would mean the two disagree.
                if OrgId::from_uuid(row.org_id) != new.org_id {
                    return Err(Error::Forbidden {
                        message: format!("package {:?} belongs to another organization", new.package_name),
                    });
                }
                (row, false)
            }
            None => {
                let row: PackageRow = sqlx::query_as(q!(
                    "INSERT INTO packages (id, format, name, org_id, visibility, discontinued, replaced_by, \
                     unlisted, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, FALSE, NULL, FALSE, $6, $6) \
                     RETURNING {PKG_COLS}"
                ))
                .bind(*PackageId::new().as_uuid())
                .bind(new.format.as_str())
                .bind(&new.package_name)
                .bind(*new.org_id.as_uuid())
                .bind(new.visibility.as_str())
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| write_err(err, &format!("package {:?} already exists", new.package_name), "org"))?;
                (row, true)
            }
        };

        let version_row: VersionRow = sqlx::query_as(q!(
            "INSERT INTO versions (id, package_id, version, version_sort, pubspec, archive_sha256, archive_size, \
             published_by, published_by_token, published_at, retracted_at, tombstone, readme_html, changelog_html) \
             VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, NULL, FALSE, $11, $12) RETURNING {VER_COLS}"
        ))
        .bind(*VersionId::new().as_uuid())
        .bind(package_row.id)
        .bind(new.version.to_string())
        .bind(new.version.sort_key())
        .bind(&pubspec)
        .bind(&new.archive_sha256)
        .bind(new.archive_size)
        .bind(*new.published_by.user_id.as_uuid())
        .bind(new.published_by.token_id.map(|id| *id.as_uuid()))
        .bind(now)
        .bind(&new.readme_html)
        .bind(&new.changelog_html)
        .fetch_one(&mut *tx)
        .await
        // The unique index covers tombstones, so this also rejects re-publishing a
        // hard-deleted number (decision 06, S-18).
        .map_err(|err| {
            write_err(
                err,
                &format!("version {} of {} already exists", new.version, new.package_name),
                "package, user, or token",
            )
        })?;

        tx.commit().await.map_err(db_err)?;
        Ok(PublishedVersion { package: package_row.try_into()?, version: version_row.try_into()?, package_created })
    }

    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<Version>> {
        let row: Option<VersionRow> =
            sqlx::query_as(q!("SELECT {VER_COLS} FROM versions WHERE package_id = $1 AND version = $2"))
                .bind(*package.as_uuid())
                .bind(version.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_versions(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Postgres> =
            QueryBuilder::new(format!("SELECT {VER_COLS} FROM versions WHERE NOT tombstone AND package_id = "));
        query.push_bind(*package.as_uuid());
        if let Some(cursor) = cursor {
            let parts = decode_cursor(cursor, 2)?;
            let id: Uuid =
                parts[1].parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {cursor}") })?;
            query.push(" AND (version_sort > ").push_bind(parts[0].clone());
            query.push(" OR (version_sort = ").push_bind(parts[0].clone());
            query.push(" AND id > ").push_bind(id).push("))");
        }
        query.push(" ORDER BY version_sort, id LIMIT ").push_bind(limit + 1);

        let rows: Vec<VersionRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<Version> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more {
            items.last().map(|version| encode_cursor(&[&version.version.sort_key(), &version.id.to_string()]))
        } else {
            None
        };
        Ok(Page { items, cursor, has_more })
    }

    async fn set_retracted(&self, id: VersionId, retracted: bool, now: DateTime<Utc>) -> Result<Version> {
        // COALESCE keeps the original retraction instant when re-retracting (idempotent).
        let row: Option<VersionRow> = sqlx::query_as(q!(
            "UPDATE versions SET retracted_at = CASE WHEN $1 THEN COALESCE(retracted_at, $2) ELSE NULL END \
             WHERE id = $3 AND NOT tombstone RETURNING {VER_COLS}"
        ))
        .bind(retracted)
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            Some(row) => row.try_into(),
            None => Err(self.missing_or_tombstoned(id).await),
        }
    }

    async fn hard_delete_version(&self, id: VersionId) -> Result<Version> {
        // The row survives as a tombstone: metadata and rendered HTML are cleared (a hard
        // delete usually *is* the leaked-secret remedy), the number stays burned (S-18).
        let row: Option<VersionRow> =
            sqlx::query_as(q!("UPDATE versions SET tombstone = TRUE, pubspec = '{{}}'::jsonb, readme_html = NULL, \
             changelog_html = NULL WHERE id = $1 AND NOT tombstone RETURNING {VER_COLS}"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        match row {
            Some(row) => row.try_into(),
            None => Err(self.missing_or_tombstoned(id).await),
        }
    }

    async fn count_versions_with_sha256(&self, sha256: &str) -> Result<u64> {
        let row: PgRow = sqlx::query("SELECT COUNT(*) AS n FROM versions WHERE archive_sha256 = $1 AND NOT tombstone")
            .bind(sha256)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        let count: i64 = row.get("n");
        Ok(count.max(0) as u64)
    }

    async fn claim_name(&self, format: Format, name: &str, org: OrgId, now: DateTime<Utc>) -> Result<NameClaim> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, format, name, org, now).await.map_err(|err| taken(err, name))?;
        let row: ClaimRow = sqlx::query_as(q!("SELECT {CLAIM_COLS} FROM name_claims WHERE format = $1 AND name = $2"))
            .bind(format.as_str())
            .bind(name)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn lookup_claim(&self, format: Format, name: &str) -> Result<Option<NameClaim>> {
        let row: Option<ClaimRow> =
            sqlx::query_as(q!("SELECT {CLAIM_COLS} FROM name_claims WHERE format = $1 AND name = $2"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }
}

impl PgPackageRepo {
    /// Distinguishes "no such version" from "already tombstoned" after a guarded UPDATE
    /// matched nothing.
    async fn missing_or_tombstoned(&self, id: VersionId) -> Error {
        match sqlx::query("SELECT tombstone FROM versions WHERE id = $1")
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(_)) => Error::Conflict { message: format!("version {id} is hard-deleted") },
            Ok(None) => Error::NotFound { what: format!("version {id}") },
            Err(err) => db_err(err),
        }
    }
}
