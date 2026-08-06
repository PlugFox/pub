//! SQLite database backend (decision 02).
//!
//! Zero-infrastructure default: a single file (or `:memory:`) with SQLite's single-writer
//! model. Repository trait implementations (`PackageRepo`, `UserRepo`, …) land in later
//! roadmap steps; this skeleton provides the pool constructor, migrations, and a health ping.
//!
//! Single-writer note: SQLite serializes writes; the pool is intentionally small and the
//! `:memory:` variant is pinned to one connection so every handle sees the same database.

use std::path::Path;

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::Error;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

/// Embedded migrations from `crates/db-sqlite/migrations/`, run at startup.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A connected SQLite database.
#[derive(Debug, Clone)]
pub struct SqliteDb {
    pool: SqlitePool,
}

impl SqliteDb {
    /// Opens (creating the file and parent directories if needed) the configured database.
    ///
    /// `database.path = ":memory:"` opens an in-memory database pinned to one connection.
    pub async fn connect(cfg: &DatabaseConfig) -> Result<Self, Error> {
        if cfg.kind != DatabaseKind::Sqlite {
            return Err(Error::Config {
                message: format!("SqliteDb::connect called with database.kind = {}", cfg.kind.as_str()),
            });
        }

        let in_memory = cfg.path == ":memory:";
        let options = if in_memory {
            SqliteConnectOptions::new().in_memory(true)
        } else {
            if let Some(parent) = Path::new(&cfg.path).parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|err| Error::Database {
                    message: format!("failed to create database directory {}: {err}", parent.display()),
                })?;
            }
            SqliteConnectOptions::new().filename(&cfg.path).create_if_missing(true)
        };

        let pool = SqlitePoolOptions::new()
            // :memory: databases are per-connection; a pool of one keeps a single database.
            .max_connections(if in_memory { 1 } else { 5 })
            .connect_with(options)
            .await
            .map_err(db_err)?;

        Ok(Self { pool })
    }

    /// Applies all pending migrations (forward-only — docs/rules/migrations.md).
    pub async fn run_migrations(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await.map_err(|err| Error::Database { message: format!("migration failed: {err}") })
    }

    /// Trivial connectivity probe (`SELECT 1`).
    pub async fn ping(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    /// The underlying pool, for repository implementations within this crate.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn db_err(err: sqlx::Error) -> Error {
    Error::Database { message: err.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_cfg() -> DatabaseConfig {
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned() }
    }

    #[tokio::test]
    async fn connect_migrate_ping_in_memory() {
        let db = SqliteDb::connect(&memory_cfg()).await.unwrap();
        db.run_migrations().await.unwrap();
        db.ping().await.unwrap();

        // The initial migration created the marker table and it is usable.
        sqlx::query("INSERT INTO schema_meta (key, value) VALUES ('probe', 'ok')").execute(db.pool()).await.unwrap();
        let row: (String,) =
            sqlx::query_as("SELECT value FROM schema_meta WHERE key = 'probe'").fetch_one(db.pool()).await.unwrap();
        assert_eq!(row.0, "ok");
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let db = SqliteDb::connect(&memory_cfg()).await.unwrap();
        db.run_migrations().await.unwrap();
        db.run_migrations().await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_wrong_kind() {
        let cfg = DatabaseConfig {
            kind: DatabaseKind::Postgres,
            url: Some("postgres://localhost/pub".to_owned()),
            path: String::new(),
        };
        let err = SqliteDb::connect(&cfg).await.unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn migrator_contains_the_initial_migration() {
        assert_eq!(MIGRATOR.migrations.len(), 1);
        assert_eq!(MIGRATOR.migrations[0].version, 1);
    }
}
