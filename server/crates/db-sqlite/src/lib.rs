//! SQLite database backend (decision 02).
//!
//! Zero-infrastructure default: a single file (or `:memory:`) with SQLite's single-writer
//! model. The identity & access repositories (`UserRepo`, `CredentialRepo`, `OrgRepo`,
//! `SessionRepo`, `TokenRepo`, `AuditRepo`, `SettingsRepo`) are implemented in [`repo`] and
//! bundled by [`SqliteDb::repositories`].
//!
//! Single-writer note: SQLite serializes writes; the pool defaults to a small size
//! (`database.pool.max_connections`, default 5) because connections beyond "the readers plus
//! the writer" only queue on the write lock, and the `:memory:` variant is pinned to one
//! connection so every handle sees the same database. File databases run WAL with
//! `synchronous = NORMAL` and a busy timeout, so concurrent writers wait out contention
//! instead of failing with `SQLITE_BUSY` (roadmap D4).
//!
//! # Query style — deliberate deviation from "sqlx compile-time macros where possible"
//!
//! Queries use **runtime `query`/`query_as` with explicit row structs**, not the `query!`
//! macro family. The compile-time-checked workflow needs a per-crate `sqlx.toml` +
//! `cargo sqlx prepare` against a migrated build-time database, with `.sqlx/` regenerated on
//! every schema or query change **per backend crate** — and the prepare metadata is coupled
//! to the exact sqlx version (workspace: 0.9). In this dual-backend workspace the ceremony
//! outweighs the benefit right now (dynamic filter queries could not use macros anyway);
//! correctness is carried by the shared contract test suite (`pub-db-tests`), which exercises
//! every repository method against a real migrated database. Revisit once the sqlx 0.9 CLI
//! workflow settles.

use std::path::Path;
use std::time::Duration;

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::Error;
use pub_core::traits::Repositories;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub mod repo;

/// How long a connection waits for a competing writer before surfacing `SQLITE_BUSY`.
///
/// 5 s is sqlx's own default, restated here so the D4 guarantee — write contention resolves
/// by waiting, not by failing — is explicit in this crate instead of inherited silently.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
            // Journal mode and synchronous are meaningless without a file: a memory database
            // keeps its MEMORY journal and never fsyncs.
            SqliteConnectOptions::new().in_memory(true)
        } else {
            if let Some(parent) = Path::new(&cfg.path).parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|err| Error::Database {
                    message: format!("failed to create database directory {}: {err}", parent.display()),
                })?;
            }
            SqliteConnectOptions::new()
                .filename(&cfg.path)
                .create_if_missing(true)
                // WAL instead of the rollback journal (roadmap D4): readers stop blocking the
                // writer and vice versa, so concurrent write transactions queue on the WAL
                // write lock and resolve within the busy timeout instead of deadlocking into
                // an immediate SQLITE_BUSY.
                .journal_mode(SqliteJournalMode::Wal)
                // NORMAL instead of the FULL default: in WAL mode NORMAL still guarantees a
                // consistent database after a crash — the WAL is a linear log, so power loss
                // can only lose the tail of recently committed transactions, never corrupt
                // the file. FULL would buy that tail back with an extra fsync per commit paid
                // by the single writer, the wrong trade for this deployment class.
                // https://www.sqlite.org/pragma.html#pragma_synchronous
                .synchronous(SqliteSynchronous::Normal)
        }
        // Referential integrity is per-connection in SQLite — enforce it explicitly rather
        // than relying on driver defaults.
        .foreign_keys(true)
        // Wait for a competing writer instead of failing on first contention (D4).
        .busy_timeout(BUSY_TIMEOUT);

        let pool_options = if in_memory {
            // :memory: databases are per-connection; a pool of one keeps a single database.
            // Idle/lifetime reaping is disabled because closing that sole connection would
            // drop the database itself.
            SqlitePoolOptions::new().max_connections(1).idle_timeout(None).max_lifetime(None)
        } else {
            SqlitePoolOptions::new()
                .max_connections(cfg.pool_max_connections())
                .idle_timeout(Some(cfg.pool_idle_timeout()))
                .max_lifetime(Some(cfg.pool_max_lifetime()))
        };
        let pool =
            pool_options.acquire_timeout(cfg.pool_acquire_timeout()).connect_with(options).await.map_err(db_err)?;

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

    /// The identity & access repositories over this database, as the shared bundle carried
    /// in `AppState`. Cheap: repositories hold pool clones.
    pub fn repositories(&self) -> Repositories {
        repo::repositories(self.pool.clone())
    }
}

fn db_err(err: sqlx::Error) -> Error {
    Error::Database { message: err.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_cfg() -> DatabaseConfig {
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() }
    }

    fn file_cfg(dir: &tempfile::TempDir) -> DatabaseConfig {
        DatabaseConfig {
            kind: DatabaseKind::Sqlite,
            url: None,
            path: dir.path().join("test.sqlite3").display().to_string(),
            ..Default::default()
        }
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
            ..Default::default()
        };
        let err = SqliteDb::connect(&cfg).await.unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[tokio::test]
    async fn file_databases_run_wal_normal_synchronous_busy_timeout_and_foreign_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = SqliteDb::connect(&file_cfg(&dir)).await.unwrap();
        let (journal,): (String,) = sqlx::query_as("PRAGMA journal_mode").fetch_one(db.pool()).await.unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        let (synchronous,): (i64,) = sqlx::query_as("PRAGMA synchronous").fetch_one(db.pool()).await.unwrap();
        assert_eq!(synchronous, 1, "1 = NORMAL");
        let (busy_ms,): (i64,) = sqlx::query_as("PRAGMA busy_timeout").fetch_one(db.pool()).await.unwrap();
        assert_eq!(busy_ms, BUSY_TIMEOUT.as_millis() as i64);
        let (foreign_keys,): (i64,) = sqlx::query_as("PRAGMA foreign_keys").fetch_one(db.pool()).await.unwrap();
        assert_eq!(foreign_keys, 1);
    }

    #[tokio::test]
    async fn pool_settings_from_config_are_applied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = file_cfg(&dir);
        cfg.pool.max_connections = Some(3);
        cfg.pool.acquire_timeout_secs = 7;
        cfg.pool.idle_timeout_secs = 120;
        cfg.pool.max_lifetime_secs = 240;
        let db = SqliteDb::connect(&cfg).await.unwrap();
        let options = db.pool().options();
        assert_eq!(options.get_max_connections(), 3);
        assert_eq!(options.get_acquire_timeout(), Duration::from_secs(7));
        assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(120)));
        assert_eq!(options.get_max_lifetime(), Some(Duration::from_secs(240)));
    }

    #[tokio::test]
    async fn unset_pool_ceiling_resolves_to_the_sqlite_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = SqliteDb::connect(&file_cfg(&dir)).await.unwrap();
        assert_eq!(db.pool().options().get_max_connections(), DatabaseConfig::SQLITE_DEFAULT_MAX_CONNECTIONS);
    }

    #[tokio::test]
    async fn memory_pool_is_one_connection_that_is_never_reaped() {
        let db = SqliteDb::connect(&memory_cfg()).await.unwrap();
        let options = db.pool().options();
        assert_eq!(options.get_max_connections(), 1, ":memory: is per-connection");
        assert_eq!(options.get_idle_timeout(), None, "reaping the sole connection would drop the database");
        assert_eq!(options.get_max_lifetime(), None, "recycling the sole connection would drop the database");
    }

    /// Roadmap D4: concurrent writers must resolve write contention by waiting on the busy
    /// timeout, never by surfacing `SQLITE_BUSY` ("database is locked") to a caller.
    #[tokio::test]
    async fn concurrent_writers_wait_out_contention_instead_of_failing_with_sqlite_busy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = SqliteDb::connect(&file_cfg(&dir)).await.unwrap();
        db.run_migrations().await.unwrap();

        const WRITERS: usize = 4;
        const INSERTS: usize = 25;
        let mut tasks = tokio::task::JoinSet::new();
        for writer in 0..WRITERS {
            let pool = db.pool().clone();
            tasks.spawn(async move {
                for i in 0..INSERTS {
                    // One transaction per insert maximizes commit contention: every commit
                    // takes the write lock.
                    let mut tx = pool.begin().await?;
                    sqlx::query("INSERT INTO schema_meta (key, value) VALUES (?, 'x')")
                        .bind(format!("w{writer}-{i}"))
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                }
                Ok::<(), sqlx::Error>(())
            });
        }
        while let Some(joined) = tasks.join_next().await {
            joined.expect("writer task panicked").expect("a concurrent writer hit SQLITE_BUSY");
        }
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_meta WHERE key LIKE 'w%'").fetch_one(db.pool()).await.unwrap();
        assert_eq!(count as usize, WRITERS * INSERTS, "every write must have landed exactly once");
    }

    /// Roadmap D4, the WAL half specifically: an open read transaction must not block
    /// writers. Under the rollback journal the reader's shared lock blocks every commit, so
    /// this exact sequence would exhaust the busy timeout and fail with `SQLITE_BUSY`.
    #[tokio::test]
    async fn writers_proceed_while_a_read_transaction_stays_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = SqliteDb::connect(&file_cfg(&dir)).await.unwrap();
        db.run_migrations().await.unwrap();
        sqlx::query("INSERT INTO schema_meta (key, value) VALUES ('anchor', 'x')")
            .execute(db.pool())
            .await
            .expect("seed anchor row");

        let mut reader = db.pool().begin().await.expect("begin read transaction");
        // The SELECT materializes the transaction's read snapshot, which it holds until commit.
        let _: (String,) = sqlx::query_as("SELECT value FROM schema_meta WHERE key = 'anchor'")
            .fetch_one(&mut *reader)
            .await
            .expect("read inside the open transaction");

        for i in 0..5 {
            sqlx::query("INSERT INTO schema_meta (key, value) VALUES (?, 'y')")
                .bind(format!("during-read-{i}"))
                .execute(db.pool())
                .await
                .expect("a writer must not block on the open read transaction");
        }
        reader.commit().await.expect("reader commit");
    }

    #[test]
    fn migrator_contains_the_expected_migrations() {
        let versions: Vec<i64> = MIGRATOR.migrations.iter().map(|m| m.version).collect();
        assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    }
}
