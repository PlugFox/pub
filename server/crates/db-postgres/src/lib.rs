//! PostgreSQL database backend (decision 02).
//!
//! Repository trait implementations (`PackageRepo`, `UserRepo`, …) land in later roadmap
//! steps; this skeleton provides the pool constructor, migrations, and a health ping.
//! The CI backend matrix (Postgres via testcontainers) exercises this crate; local unit
//! tests stay connection-free.

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::Error;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Embedded migrations from `crates/db-postgres/migrations/`, run at startup.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A (lazily) connected PostgreSQL database.
#[derive(Debug, Clone)]
pub struct PostgresDb {
    pool: PgPool,
}

impl PostgresDb {
    /// Builds a lazily-connecting pool from configuration.
    ///
    /// No I/O happens here — the first query (migrations or ping) establishes connections,
    /// so construction is infallible with respect to the network.
    pub fn connect_lazy(cfg: &DatabaseConfig) -> Result<Self, Error> {
        if cfg.kind != DatabaseKind::Postgres {
            return Err(Error::Config {
                message: format!("PostgresDb::connect_lazy called with database.kind = {}", cfg.kind.as_str()),
            });
        }
        let url = cfg
            .url
            .as_deref()
            .ok_or_else(|| Error::Config { message: "database.kind = postgres requires database.url".to_owned() })?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(url)
            .map_err(|err| Error::Database { message: format!("invalid postgres url: {err}") })?;

        Ok(Self { pool })
    }

    /// Applies all pending migrations (forward-only — docs/rules/migrations.md).
    pub async fn run_migrations(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await.map_err(|err| Error::Database { message: format!("migration failed: {err}") })
    }

    /// Trivial connectivity probe (`SELECT 1`).
    pub async fn ping(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|err| Error::Database { message: err.to_string() })?;
        Ok(())
    }

    /// The underlying pool, for repository implementations within this crate.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pool construction spawns sqlx's reaper task, so a runtime must be present — but no
    // network I/O happens.
    #[tokio::test]
    async fn connect_lazy_builds_pool_without_io() {
        let cfg = DatabaseConfig {
            kind: DatabaseKind::Postgres,
            url: Some("postgres://pub:pub@127.0.0.1:1/pub".to_owned()),
            path: String::new(),
        };
        // Port 1 is never reachable — lazy construction must still succeed.
        PostgresDb::connect_lazy(&cfg).unwrap();
    }

    #[test]
    fn connect_lazy_requires_url() {
        let cfg = DatabaseConfig { kind: DatabaseKind::Postgres, url: None, path: String::new() };
        let err = PostgresDb::connect_lazy(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn connect_lazy_rejects_wrong_kind() {
        let cfg = DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned() };
        let err = PostgresDb::connect_lazy(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn migrator_contains_the_initial_migration() {
        assert_eq!(MIGRATOR.migrations.len(), 1);
        assert_eq!(MIGRATOR.migrations[0].version, 1);
    }
}
