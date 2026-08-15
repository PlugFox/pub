//! Postgres implementations of the identity & access repository traits.
//!
//! Conventions shared by every submodule:
//!
//! - **Ids** are UUID v7 stored natively as `UUID`; **timestamps** are `TIMESTAMPTZ` bound and
//!   read as `chrono::DateTime<Utc>` (microsecond precision — every value round-trips exactly).
//! - **`INET` and `JSONB` round-trip as text**: writes cast bound TEXT parameters
//!   (`$n::inet`, `$n::jsonb`); reads select `col::text` for JSONB and `host(col)` for INET
//!   (a bare `::text` cast would append the `/32`/`/128` netmask) — the repositories keep the
//!   exact serde encodings the SQLite backend uses, without pulling extra sqlx type features.
//! - **Atomic multi-step operations** (org create, invitation accept, refresh rotation,
//!   invariant-guarded member mutations) run inside a transaction. Postgres has concurrent
//!   writers (unlike SQLite's single writer), so the read-then-write sections additionally
//!   take row locks (`SELECT … FOR UPDATE`) on their serialization anchor: the org row for
//!   the ≥1-Owner invariant and membership writes, the invitation row for single-use
//!   acceptance, the session row for refresh rotation.
//! - **Error mapping**: unique-index violations become [`Error::Conflict`], foreign-key
//!   violations become [`Error::NotFound`] (the referenced entity does not exist), everything
//!   else is [`Error::Database`]. Domain rows that fail to parse are corruption and map to
//!   [`Error::Database`], never [`Error::Invalid`].
//!
//! Query style (runtime `query_as`, not compile-time macros) deliberately matches the SQLite
//! backend — the full rationale lives in the `pub-db-sqlite` crate docs; correctness is
//! carried by the shared contract suite (`pub-db-tests`) running against both backends.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone as _, Utc};
use pub_core::Error;
use pub_core::traits::Repositories;
use sqlx::PgPool;

mod audit;
mod credentials;
mod jobs;
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

pub use audit::PgAuditRepo;
pub use credentials::PgCredentialRepo;
pub use jobs::PgJobRepo;
pub use notifications::PgNotificationRepo;
pub use orgs::PgOrgRepo;
pub use packages::PgPackageRepo;
pub use queue::PgJobQueueRepo;
pub use search::{PgPackageSearch, PgStatsRepo};
pub use sessions::PgSessionRepo;
pub use settings::PgSettingsRepo;
pub use tokens::PgTokenRepo;
pub use upstream::{PgUpstreamRepo, quarantine_page_sql, shadowing_page_sql};
pub use users::PgUserRepo;

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
pub fn repositories(pool: PgPool) -> Repositories {
    Repositories {
        packages: Arc::new(PgPackageRepo::new(pool.clone())),
        upstream: Arc::new(PgUpstreamRepo::new(pool.clone())),
        users: Arc::new(PgUserRepo::new(pool.clone())),
        credentials: Arc::new(PgCredentialRepo::new(pool.clone())),
        orgs: Arc::new(PgOrgRepo::new(pool.clone())),
        sessions: Arc::new(PgSessionRepo::new(pool.clone())),
        tokens: Arc::new(PgTokenRepo::new(pool.clone())),
        audit: Arc::new(PgAuditRepo::new(pool.clone())),
        settings: Arc::new(PgSettingsRepo::new(pool.clone())),
        jobs: Arc::new(PgJobRepo::new(pool.clone())),
        queue: Arc::new(PgJobQueueRepo::new(pool.clone())),
        search: Arc::new(PgPackageSearch::new(pool.clone())),
        stats: Arc::new(PgStatsRepo::new(pool.clone())),
        notifications: Arc::new(PgNotificationRepo::new(pool)),
    }
}

/// Parses a stored enum/id text column; failures are data corruption, i.e. [`Error::Database`].
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

/// Saturation floor for sliding-window cutoffs: far before any stored timestamp yet safely
/// inside Postgres' `TIMESTAMPTZ` range (chrono's `MIN_UTC` is not representable in PG).
pub(crate) fn window_floor() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(-4000, 1, 1, 0, 0, 0).single().expect("year -4000 is a valid UTC instant")
}

/// The lower bound of a sliding window: `now - window`, saturating at [`window_floor`] when
/// the window is enormous. Every stored timestamp is later than the floor, so the saturated
/// comparison semantics match "no lower bound".
pub(crate) fn cutoff(now: DateTime<Utc>, window: Duration) -> DateTime<Utc> {
    let floor = window_floor();
    chrono::Duration::from_std(window)
        .ok()
        .and_then(|delta| now.checked_sub_signed(delta))
        .filter(|instant| *instant >= floor)
        .unwrap_or(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoff_saturates_on_huge_windows_within_pg_range() {
        let now = Utc.with_ymd_and_hms(2026, 8, 6, 0, 0, 0).unwrap();
        assert_eq!(cutoff(now, Duration::MAX), window_floor());
        assert_eq!(cutoff(now, Duration::from_secs(60)), now - chrono::Duration::seconds(60));
    }

    #[test]
    fn parse_col_rejects_garbage_as_database_error() {
        assert_eq!(parse_col::<pub_core::UserId>("not-a-uuid").unwrap_err().code(), "database_error");
    }
}
