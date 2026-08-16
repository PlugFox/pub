//! SQLite implementations of the identity & access repository traits.
//!
//! Conventions shared by every submodule:
//!
//! - **Ids** are UUID v7 stored as lowercase hyphenated TEXT; **timestamps** are RFC3339 UTC
//!   TEXT with a fixed-width 6-digit fraction and `Z` suffix, so lexicographic comparison in
//!   SQL equals chronological comparison ([`ts`]).
//! - **Atomic multi-step operations** (org create, invitation accept, refresh rotation,
//!   invariant-guarded member mutations) run inside a transaction; SQLite's single writer
//!   plus the schema's unique indexes backstop the read-then-write sections.
//! - **Error mapping**: unique-index violations become [`Error::Conflict`], foreign-key
//!   violations become [`Error::NotFound`] (the referenced entity does not exist), everything
//!   else is [`Error::Database`]. Domain rows that fail to parse are corruption and map to
//!   [`Error::Database`], never [`Error::Invalid`].

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use pub_core::Error;
use pub_core::traits::Repositories;
use sqlx::SqlitePool;

mod audit;
mod credentials;
mod jobs;
mod locks;
mod notifications;
mod orgs;
mod packages;
mod queue;
mod search;
mod sessions;
mod settings;
mod tokens;
mod upstream;
mod users;

pub use audit::SqliteAuditRepo;
pub use credentials::SqliteCredentialRepo;
pub use jobs::SqliteJobRepo;
pub use locks::SqliteJobLock;
pub use notifications::SqliteNotificationRepo;
pub use orgs::SqliteOrgRepo;
pub use packages::SqlitePackageRepo;
pub use queue::SqliteJobQueueRepo;
pub use search::{SqlitePackageSearch, SqliteStatsRepo};
pub use sessions::SqliteSessionRepo;
pub use settings::SqliteSettingsRepo;
pub use tokens::SqliteTokenRepo;
pub use upstream::{SqliteUpstreamRepo, quarantine_page_sql, shadowing_page_sql};
pub use users::SqliteUserRepo;

/// Builds a query string from **const fragments only** (column lists, table names) and marks
/// it SQL-safe for sqlx. Every dynamic value still travels through bind parameters — user
/// input never enters the SQL text, which is what `AssertSqlSafe` asserts.
macro_rules! q {
    ($($arg:tt)*) => {
        sqlx::AssertSqlSafe(format!($($arg)*))
    };
}
pub(crate) use q;

/// Bundles fresh repository instances over `pool` into the shared [`Repositories`] handle.
pub fn repositories(pool: SqlitePool) -> Repositories {
    Repositories {
        packages: Arc::new(SqlitePackageRepo::new(pool.clone())),
        upstream: Arc::new(SqliteUpstreamRepo::new(pool.clone())),
        users: Arc::new(SqliteUserRepo::new(pool.clone())),
        credentials: Arc::new(SqliteCredentialRepo::new(pool.clone())),
        orgs: Arc::new(SqliteOrgRepo::new(pool.clone())),
        sessions: Arc::new(SqliteSessionRepo::new(pool.clone())),
        tokens: Arc::new(SqliteTokenRepo::new(pool.clone())),
        audit: Arc::new(SqliteAuditRepo::new(pool.clone())),
        settings: Arc::new(SqliteSettingsRepo::new(pool.clone())),
        jobs: Arc::new(SqliteJobRepo::new(pool.clone())),
        locks: Arc::new(SqliteJobLock::new(pool.clone())),
        queue: Arc::new(SqliteJobQueueRepo::new(pool.clone())),
        search: Arc::new(SqlitePackageSearch::new(pool.clone())),
        stats: Arc::new(SqliteStatsRepo::new(pool.clone())),
        notifications: Arc::new(SqliteNotificationRepo::new(pool)),
    }
}

/// Formats a timestamp as fixed-width RFC3339 UTC (`2026-08-06T12:00:00.000000Z`).
///
/// Fixed width + UTC-only means SQL string comparison equals time comparison. Precision is
/// truncated to microseconds — every value written to and read from the database round-trips
/// exactly.
pub(crate) fn ts(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Parses a stored timestamp; failures are data corruption, i.e. [`Error::Database`].
pub(crate) fn parse_ts(raw: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| Error::Database { message: format!("corrupt timestamp {raw:?}: {err}") })
}

/// Parses an optional stored timestamp.
pub(crate) fn parse_ts_opt(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, Error> {
    raw.map(parse_ts).transpose()
}

/// Parses a stored id/enum column; failures are data corruption, i.e. [`Error::Database`].
pub(crate) fn parse_col<T>(raw: &str) -> Result<T, Error>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    raw.parse::<T>().map_err(|err| Error::Database { message: format!("corrupt column value {raw:?}: {err}") })
}

/// Maps a sqlx error on a plain read to a domain error.
pub(crate) fn db_err(err: sqlx::Error) -> Error {
    Error::Database { message: err.to_string() }
}

/// Maps a sqlx error on a write: unique violation → [`Error::Conflict`] with `conflict_msg`,
/// foreign-key violation → [`Error::NotFound`] with `fk_what`, otherwise [`Error::Database`].
pub(crate) fn write_err(err: sqlx::Error, conflict_msg: &str, fk_what: &str) -> Error {
    if let sqlx::Error::Database(db) = &err {
        if db.is_unique_violation() {
            return Error::Conflict { message: conflict_msg.to_owned() };
        }
        if db.is_foreign_key_violation() {
            return Error::NotFound { what: fk_what.to_owned() };
        }
    }
    db_err(err)
}

/// The lower bound of a sliding window: `now - window`, saturating at the minimum
/// representable instant when the window is enormous.
pub(crate) fn cutoff(now: DateTime<Utc>, window: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(window)
        .ok()
        .and_then(|delta| now.checked_sub_signed(delta))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn ts_is_fixed_width_and_round_trips() {
        let dt = Utc.with_ymd_and_hms(2026, 8, 6, 9, 5, 3).unwrap();
        let text = ts(dt);
        assert_eq!(text, "2026-08-06T09:05:03.000000Z");
        assert_eq!(parse_ts(&text).unwrap(), dt);
    }

    #[test]
    fn ts_ordering_matches_string_ordering() {
        let a = Utc.with_ymd_and_hms(2026, 8, 6, 9, 5, 3).unwrap();
        let b = a + chrono::Duration::microseconds(1);
        assert!(ts(a) < ts(b));
    }

    #[test]
    fn cutoff_saturates_on_huge_windows() {
        let now = Utc.with_ymd_and_hms(2026, 8, 6, 0, 0, 0).unwrap();
        assert_eq!(cutoff(now, Duration::MAX), DateTime::<Utc>::MIN_UTC);
        assert_eq!(cutoff(now, Duration::from_secs(60)), now - chrono::Duration::seconds(60));
    }

    #[test]
    fn parse_ts_rejects_garbage_as_database_error() {
        assert_eq!(parse_ts("not-a-time").unwrap_err().code(), "database_error");
    }
}
