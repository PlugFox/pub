//! PostgreSQL database backend (decision 02).
//!
//! Carries the full migration set (identical logical schema to `db-sqlite`) and the complete
//! identity & access repository implementations ([`repo`]), bundled by
//! [`PostgresDb::repositories`]. Local unit tests stay connection-free; the shared contract
//! suite (`pub-db-tests`) exercises every repository against a live server, gated by the
//! `PUB_TEST_POSTGRES_URL` environment variable (the CI backend matrix sets it).

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::Error;
use pub_core::traits::Repositories;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub mod repo;

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
            .max_connections(cfg.pool_max_connections())
            .acquire_timeout(cfg.pool_acquire_timeout())
            .idle_timeout(Some(cfg.pool_idle_timeout()))
            .max_lifetime(Some(cfg.pool_max_lifetime()))
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

    /// The identity & access repositories over this database, as the shared bundle carried
    /// in `AppState`. Cheap: repositories hold pool clones.
    pub fn repositories(&self) -> Repositories {
        repo::repositories(self.pool.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lazy_cfg() -> DatabaseConfig {
        DatabaseConfig {
            kind: DatabaseKind::Postgres,
            // Port 1 is never reachable — lazy construction must still succeed.
            url: Some("postgres://pub:pub@127.0.0.1:1/pub".to_owned()),
            path: String::new(),
            ..Default::default()
        }
    }

    // Pool construction spawns sqlx's reaper task, so a runtime must be present — but no
    // network I/O happens.
    #[tokio::test]
    async fn connect_lazy_builds_pool_without_io() {
        PostgresDb::connect_lazy(&lazy_cfg()).unwrap();
    }

    #[tokio::test]
    async fn pool_settings_from_config_are_applied_without_io() {
        let mut cfg = lazy_cfg();
        cfg.pool.max_connections = Some(7);
        cfg.pool.acquire_timeout_secs = 3;
        cfg.pool.idle_timeout_secs = 60;
        cfg.pool.max_lifetime_secs = 90;
        let db = PostgresDb::connect_lazy(&cfg).unwrap();
        let options = db.pool().options();
        assert_eq!(options.get_max_connections(), 7);
        assert_eq!(options.get_acquire_timeout(), std::time::Duration::from_secs(3));
        assert_eq!(options.get_idle_timeout(), Some(std::time::Duration::from_secs(60)));
        assert_eq!(options.get_max_lifetime(), Some(std::time::Duration::from_secs(90)));
    }

    #[tokio::test]
    async fn unset_pool_ceiling_resolves_to_the_postgres_default() {
        let db = PostgresDb::connect_lazy(&lazy_cfg()).unwrap();
        assert_eq!(db.pool().options().get_max_connections(), DatabaseConfig::POSTGRES_DEFAULT_MAX_CONNECTIONS);
    }

    #[test]
    fn connect_lazy_requires_url() {
        let cfg = DatabaseConfig { kind: DatabaseKind::Postgres, url: None, path: String::new(), ..Default::default() };
        let err = PostgresDb::connect_lazy(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn connect_lazy_rejects_wrong_kind() {
        let cfg =
            DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
        let err = PostgresDb::connect_lazy(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn migrator_contains_the_expected_migrations() {
        let versions: Vec<i64> = MIGRATOR.migrations.iter().map(|m| m.version).collect();
        assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }
}
