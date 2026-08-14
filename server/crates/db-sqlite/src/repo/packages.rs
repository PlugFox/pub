//! `PackageRepo` over SQLite: packages, immutable versions, and name claims.
//!
//! Two things carry the registry's invariants here:
//!
//! - **`create_version` is one transaction** — claim check, first-publish package creation,
//!   and the version insert either all happen or none do. SQLite's single writer serializes
//!   concurrent publishes; the unique indexes decide the winner either way.
//! - **Ordering is `version_sort`**, the precedence key from [`pub_core::SemVer::sort_key`],
//!   compared with SQLite's default BINARY collation. Ordering by the version text would put
//!   `1.0.0-beta.11` before `1.0.0-beta.2`.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::package::{
    NameClaim, NewPackage, NewVersion, Package, PackageOptions, PublishedVersion, Publisher, Version, Visibility,
};
use pub_core::page::{decode_cursor, encode_cursor};
use pub_core::traits::PackageRepo;
use pub_core::{Error, Format, OrgId, PackageId, Page, Result, SemVer, VersionId};
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row as _, Sqlite, SqlitePool};

use super::{db_err, parse_col, parse_ts, parse_ts_opt, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All package columns, in [`PackageRow`] order.
const PKG_COLS: &str =
    "id, format, name, org_id, visibility, discontinued, replaced_by, unlisted, created_at, updated_at";

/// All version columns, in [`VersionRow`] order.
const VER_COLS: &str = "id, package_id, version, pubspec, archive_sha256, archive_size, published_by, \
                        published_by_token, published_at, retracted_at, tombstone, readme_html, changelog_html";

/// All name-claim columns, in [`ClaimRow`] order.
const CLAIM_COLS: &str = "format, name, org_id, claimed_at";

/// SQLite-backed [`PackageRepo`].
#[derive(Debug, Clone)]
pub struct SqlitePackageRepo {
    pool: SqlitePool,
}

impl SqlitePackageRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct PackageRow {
    id: String,
    format: String,
    name: String,
    org_id: String,
    visibility: String,
    discontinued: bool,
    replaced_by: Option<String>,
    unlisted: bool,
    created_at: String,
    updated_at: String,
}

impl TryFrom<PackageRow> for Package {
    type Error = Error;

    fn try_from(row: PackageRow) -> Result<Self> {
        Ok(Package {
            id: parse_col(&row.id)?,
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: parse_col(&row.org_id)?,
            visibility: parse_col::<Visibility>(&row.visibility)?,
            discontinued: row.discontinued,
            replaced_by: row.replaced_by,
            unlisted: row.unlisted,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: String,
    package_id: String,
    version: String,
    pubspec: String,
    archive_sha256: String,
    archive_size: i64,
    published_by: String,
    published_by_token: Option<String>,
    published_at: String,
    retracted_at: Option<String>,
    tombstone: bool,
    readme_html: Option<String>,
    changelog_html: Option<String>,
}

impl TryFrom<VersionRow> for Version {
    type Error = Error;

    fn try_from(row: VersionRow) -> Result<Self> {
        Ok(Version {
            id: parse_col(&row.id)?,
            package_id: parse_col(&row.package_id)?,
            version: parse_col::<SemVer>(&row.version)?,
            pubspec: serde_json::from_str(&row.pubspec)
                .map_err(|err| Error::Database { message: format!("corrupt pubspec json: {err}") })?,
            archive_sha256: row.archive_sha256,
            archive_size: row.archive_size,
            published_by: Publisher {
                user_id: parse_col(&row.published_by)?,
                token_id: row.published_by_token.as_deref().map(parse_col).transpose()?,
            },
            published_at: parse_ts(&row.published_at)?,
            retracted_at: parse_ts_opt(row.retracted_at.as_deref())?,
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
    org_id: String,
    claimed_at: String,
}

impl TryFrom<ClaimRow> for NameClaim {
    type Error = Error;

    fn try_from(row: ClaimRow) -> Result<Self> {
        Ok(NameClaim {
            format: parse_col(&row.format)?,
            name: row.name,
            org_id: parse_col(&row.org_id)?,
            claimed_at: parse_ts(&row.claimed_at)?,
        })
    }
}

/// Inserts the `(format, name)` claim inside a transaction, or verifies the existing one
/// belongs to `org`.
///
/// A name held by another org is [`Error::Forbidden`]: the message deliberately names only the
/// package, never the holding org — the API layer decides how much of that a caller may learn
/// (S-04).
async fn claim_for(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    format: Format,
    name: &str,
    org: OrgId,
    now: DateTime<Utc>,
) -> Result<()> {
    let existing: Option<SqliteRow> = sqlx::query("SELECT org_id FROM name_claims WHERE format = ? AND name = ?")
        .bind(format.as_str())
        .bind(name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;

    match existing {
        Some(row) => {
            let holder: OrgId = parse_col(row.get::<String, _>("org_id").as_str())?;
            if holder == org {
                Ok(())
            } else {
                Err(Error::Forbidden { message: format!("package name {name:?} is claimed by another organization") })
            }
        }
        None => {
            sqlx::query("INSERT INTO name_claims (format, name, org_id, claimed_at) VALUES (?, ?, ?, ?)")
                .bind(format.as_str())
                .bind(name)
                .bind(org.to_string())
                .bind(super::ts(now))
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
impl PackageRepo for SqlitePackageRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create_package(&self, new: NewPackage, now: DateTime<Utc>) -> Result<Package> {
        let stamp = super::ts(now);
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, new.format, &new.name, new.org_id, now).await.map_err(|err| taken(err, &new.name))?;
        let row: PackageRow = sqlx::query_as(q!(
            "INSERT INTO packages (id, format, name, org_id, visibility, discontinued, replaced_by, unlisted, \
             created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, NULL, 0, ?, ?) RETURNING {PKG_COLS}"
        ))
        .bind(PackageId::new().to_string())
        .bind(new.format.as_str())
        .bind(&new.name)
        .bind(new.org_id.to_string())
        .bind(new.visibility.as_str())
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, &format!("package {:?} already exists", new.name), "org"))?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn get_package(&self, id: PackageId) -> Result<Option<Package>> {
        let row: Option<PackageRow> = sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE id = ?"))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_name(&self, format: Format, name: &str) -> Result<Option<Package>> {
        let row: Option<PackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE format = ? AND name = ?"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_for_org(&self, org: OrgId, cursor: Option<&str>, limit: u32) -> Result<Page<Package>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT {PKG_COLS} FROM packages WHERE org_id = "));
        query.push_bind(org.to_string());
        if let Some(cursor) = cursor {
            // Keyset over (name, id): the id breaks ties that cannot occur today (names are
            // unique per format) but would appear the moment a listing spans formats.
            let parts = decode_cursor(cursor, 2)?;
            query.push(" AND (name > ").push_bind(parts[0].clone());
            query.push(" OR (name = ").push_bind(parts[0].clone());
            query.push(" AND id > ").push_bind(parts[1].clone()).push("))");
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

    async fn list_all(&self, cursor: Option<&str>, limit: u32) -> Result<Page<Package>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(format!("SELECT {PKG_COLS} FROM packages"));
        if let Some(cursor) = cursor {
            // `(format, name)` is unique instance-wide, so it is a total order on its own — no
            // id tiebreaker is needed or wanted here.
            let parts = decode_cursor(cursor, 2)?;
            query.push(" WHERE (format > ").push_bind(parts[0].clone());
            query.push(" OR (format = ").push_bind(parts[0].clone());
            query.push(" AND name > ").push_bind(parts[1].clone()).push("))");
        }
        query.push(" ORDER BY format, name LIMIT ").push_bind(limit + 1);

        let rows: Vec<PackageRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<Package> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more {
            items.last().map(|package| encode_cursor(&[package.format.as_str(), &package.name]))
        } else {
            None
        };
        Ok(Page { items, cursor, has_more })
    }

    async fn set_options(&self, id: PackageId, options: &PackageOptions, now: DateTime<Utc>) -> Result<Package> {
        let row: Option<PackageRow> = sqlx::query_as(q!(
            "UPDATE packages SET visibility = ?, discontinued = ?, replaced_by = ?, unlisted = ?, updated_at = ? \
             WHERE id = ? RETURNING {PKG_COLS}"
        ))
        .bind(options.visibility.as_str())
        .bind(options.discontinued)
        .bind(options.replaced_by.as_deref())
        .bind(options.unlisted)
        .bind(super::ts(now))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("package {id}") })?.try_into()
    }

    async fn create_version(&self, new: NewVersion, now: DateTime<Utc>) -> Result<PublishedVersion> {
        let stamp = super::ts(now);
        let pubspec = serde_json::to_string(&new.pubspec)
            .map_err(|err| Error::Internal { message: format!("failed to encode pubspec json: {err}") })?;

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, new.format, &new.package_name, new.org_id, now).await?;

        // First publish of the name creates the package row in the same transaction.
        let existing: Option<PackageRow> =
            sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE format = ? AND name = ?"))
                .bind(new.format.as_str())
                .bind(&new.package_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let (package_row, package_created) = match existing {
            Some(row) => {
                // Defense in depth: the claim already proved ownership, but a package row
                // pointing elsewhere would mean the two disagree.
                if parse_col::<OrgId>(&row.org_id)? != new.org_id {
                    return Err(Error::Forbidden {
                        message: format!("package {:?} belongs to another organization", new.package_name),
                    });
                }
                (row, false)
            }
            None => {
                let row: PackageRow = sqlx::query_as(q!(
                    "INSERT INTO packages (id, format, name, org_id, visibility, discontinued, replaced_by, \
                     unlisted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, NULL, 0, ?, ?) RETURNING {PKG_COLS}"
                ))
                .bind(PackageId::new().to_string())
                .bind(new.format.as_str())
                .bind(&new.package_name)
                .bind(new.org_id.to_string())
                .bind(new.visibility.as_str())
                .bind(&stamp)
                .bind(&stamp)
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| write_err(err, &format!("package {:?} already exists", new.package_name), "org"))?;
                (row, true)
            }
        };

        let version_row: VersionRow = sqlx::query_as(q!(
            "INSERT INTO versions (id, package_id, version, version_sort, pubspec, archive_sha256, archive_size, \
             published_by, published_by_token, published_at, retracted_at, tombstone, readme_html, changelog_html) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?) RETURNING {VER_COLS}"
        ))
        .bind(VersionId::new().to_string())
        .bind(&package_row.id)
        .bind(new.version.to_string())
        .bind(new.version.sort_key())
        .bind(&pubspec)
        .bind(&new.archive_sha256)
        .bind(new.archive_size)
        .bind(new.published_by.user_id.to_string())
        .bind(new.published_by.token_id.map(|id| id.to_string()))
        .bind(&stamp)
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
            sqlx::query_as(q!("SELECT {VER_COLS} FROM versions WHERE package_id = ? AND version = ?"))
                .bind(package.to_string())
                .bind(version.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_versions(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT {VER_COLS} FROM versions WHERE tombstone = 0 AND package_id = "));
        query.push_bind(package.to_string());
        if let Some(cursor) = cursor {
            let parts = decode_cursor(cursor, 2)?;
            query.push(" AND (version_sort > ").push_bind(parts[0].clone());
            query.push(" OR (version_sort = ").push_bind(parts[0].clone());
            query.push(" AND id > ").push_bind(parts[1].clone()).push("))");
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

    async fn list_versions_desc(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT {VER_COLS} FROM versions WHERE tombstone = 0 AND package_id = "));
        query.push_bind(package.to_string());
        if let Some(cursor) = cursor {
            let parts = decode_cursor(cursor, 2)?;
            query.push(" AND (version_sort < ").push_bind(parts[0].clone());
            query.push(" OR (version_sort = ").push_bind(parts[0].clone());
            query.push(" AND id < ").push_bind(parts[1].clone()).push("))");
        }
        query.push(" ORDER BY version_sort DESC, id DESC LIMIT ").push_bind(limit + 1);

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
            "UPDATE versions SET retracted_at = CASE WHEN ? THEN COALESCE(retracted_at, ?) ELSE NULL END \
             WHERE id = ? AND tombstone = 0 RETURNING {VER_COLS}"
        ))
        .bind(retracted)
        .bind(super::ts(now))
        .bind(id.to_string())
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
        let row: Option<VersionRow> = sqlx::query_as(q!(
            "UPDATE versions SET tombstone = 1, pubspec = '{{}}', readme_html = NULL, changelog_html = NULL \
             WHERE id = ? AND tombstone = 0 RETURNING {VER_COLS}"
        ))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            Some(row) => row.try_into(),
            None => Err(self.missing_or_tombstoned(id).await),
        }
    }

    async fn count_versions(&self, package: PackageId) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM versions WHERE package_id = ? AND tombstone = 0")
            .bind(package.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(count)
    }

    async fn count_versions_with_sha256(&self, sha256: &str) -> Result<u64> {
        let row: SqliteRow =
            sqlx::query("SELECT COUNT(*) AS n FROM versions WHERE archive_sha256 = ? AND tombstone = 0")
                .bind(sha256)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        let count: i64 = row.get("n");
        Ok(count.max(0) as u64)
    }

    async fn live_sha256s(&self, hashes: &[String]) -> Result<HashSet<String>> {
        if hashes.is_empty() {
            // An `IN ()` is a syntax error on SQLite, and a round trip that can only answer
            // "nothing" is one the collector should not be making in the first place.
            return Ok(HashSet::new());
        }
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT DISTINCT archive_sha256 FROM versions WHERE tombstone = 0 AND archive_sha256 IN (",
        );
        let mut list = query.separated(", ");
        for hash in hashes {
            list.push_bind(hash.clone());
        }
        list.push_unseparated(")");
        let found: Vec<String> = query.build_query_scalar().fetch_all(&self.pool).await.map_err(db_err)?;
        Ok(found.into_iter().collect())
    }

    async fn transfer(&self, id: PackageId, to_org: OrgId, now: DateTime<Utc>) -> Result<Package> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let current: Option<PackageRow> = sqlx::query_as(q!("SELECT {PKG_COLS} FROM packages WHERE id = ?"))
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let current: Package = current.ok_or_else(|| Error::NotFound { what: format!("package {id}") })?.try_into()?;
        if current.org_id == to_org {
            return Ok(current);
        }
        let stamp = super::ts(now);
        let row: PackageRow =
            sqlx::query_as(q!("UPDATE packages SET org_id = ?, updated_at = ? WHERE id = ? RETURNING {PKG_COLS}"))
                .bind(to_org.to_string())
                .bind(&stamp)
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| write_err(err, "package already exists in the target org", "target org"))?;
        // The claim moves with the package, in the same transaction: a claim pointing at the
        // old owner would stop the new one publishing the name they now hold, and would page
        // the wrong admins on a shadowing alarm (S-17).
        sqlx::query("UPDATE name_claims SET org_id = ? WHERE format = ? AND name = ?")
            .bind(to_org.to_string())
            .bind(current.format.as_str())
            .bind(&current.name)
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "name claim conflict", "target org"))?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn count_for_org(&self, org: OrgId) -> Result<i64> {
        let row: SqliteRow = sqlx::query("SELECT COUNT(*) AS n FROM packages WHERE org_id = ?")
            .bind(org.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.get("n"))
    }

    async fn stats(&self) -> Result<pub_core::package::RegistryStats> {
        let packages: SqliteRow =
            sqlx::query("SELECT COUNT(*) AS total, COALESCE(SUM(visibility = 'public'), 0) AS public FROM packages")
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        let versions: SqliteRow = sqlx::query(
            "SELECT COALESCE(SUM(tombstone = 0), 0) AS live, \
             COALESCE(SUM(tombstone = 0 AND retracted_at IS NOT NULL), 0) AS retracted, \
             COALESCE(SUM(tombstone = 1), 0) AS tombstoned, \
             COALESCE(SUM(CASE WHEN tombstone = 0 THEN archive_size ELSE 0 END), 0) AS bytes FROM versions",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(pub_core::package::RegistryStats {
            packages: packages.get("total"),
            public_packages: packages.get("public"),
            versions: versions.get("live"),
            retracted_versions: versions.get("retracted"),
            tombstoned_versions: versions.get("tombstoned"),
            archive_bytes: versions.get("bytes"),
        })
    }

    async fn claim_name(&self, format: Format, name: &str, org: OrgId, now: DateTime<Utc>) -> Result<NameClaim> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        claim_for(&mut tx, format, name, org, now).await.map_err(|err| taken(err, name))?;
        let row: ClaimRow = sqlx::query_as(q!("SELECT {CLAIM_COLS} FROM name_claims WHERE format = ? AND name = ?"))
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
            sqlx::query_as(q!("SELECT {CLAIM_COLS} FROM name_claims WHERE format = ? AND name = ?"))
                .bind(format.as_str())
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }
}

impl SqlitePackageRepo {
    /// Distinguishes "no such version" from "already tombstoned" after a guarded UPDATE
    /// matched nothing.
    async fn missing_or_tombstoned(&self, id: VersionId) -> Error {
        match sqlx::query("SELECT tombstone FROM versions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(_)) => Error::Conflict { message: format!("version {id} is hard-deleted") },
            Ok(None) => Error::NotFound { what: format!("version {id}") },
            Err(err) => db_err(err),
        }
    }
}
