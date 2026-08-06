//! `pubd` — the Pub registry server binary.
//!
//! Startup sequence (docs/architecture.md): parse CLI → load layered config → init
//! telemetry → select backends by config kind → run migrations → build `AppState` → serve
//! with graceful shutdown.

use std::sync::Arc;

use anyhow::Context as _;
use clap::{CommandFactory as _, FromArgMatches as _};
use pub_api::AppState;
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobKind, CliArgs, DatabaseKind, KvKind, Settings};
use pub_core::traits::{BlobStore, Kv, Repositories};
use pub_db_postgres::PostgresDb;
use pub_db_sqlite::SqliteDb;
use pub_kv::{MemoryKv, RedisKv};
use pub_telemetry::LogFormat;

/// Version string surfaced by `pubd --version`: crate version + git hash + build date.
const VERSION: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (", env!("PUBD_GIT_HASH"), ", ", env!("PUBD_BUILD_DATE"), ")");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inject the git-stamped version so clap's --version prints it (the flag is disabled on
    // the shared derive struct precisely so this binary can own the version string).
    let matches = CliArgs::command().version(VERSION).disable_version_flag(false).get_matches();
    let cli = CliArgs::from_arg_matches(&matches).context("failed to parse command line")?;

    let settings = pub_config::load(&cli).context("failed to load configuration")?;
    let telemetry = pub_telemetry::init(LogFormat::Pretty, &settings.telemetry);
    tracing::info!(version = VERSION, "starting pubd");
    tracing::info!("{}", settings.summary());

    let repos = build_database(&settings).await?;
    let blob = build_blob(&settings)?;
    let kv = build_kv(&settings)?;

    let listen = settings.server.listen.clone();
    let state = AppState::new(settings, repos, blob, kv);
    let app = pub_api::router(state);

    let listener = tokio::net::TcpListener::bind(&listen).await.with_context(|| format!("failed to bind {listen}"))?;
    tracing::info!(%listen, "pubd listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await.context("server error")?;

    tracing::info!("pubd stopped");
    drop(telemetry);
    Ok(())
}

/// Connects the configured database, applies migrations (forward-only), and returns the
/// repository bundle over the live pool — the DB handle the whole app shares.
async fn build_database(settings: &Settings) -> anyhow::Result<Repositories> {
    let repos = match settings.database.kind {
        DatabaseKind::Sqlite => {
            let db = SqliteDb::connect(&settings.database).await.context("failed to open sqlite database")?;
            db.run_migrations().await.context("sqlite migrations failed")?;
            db.ping().await.context("sqlite ping failed")?;
            db.repositories()
        }
        DatabaseKind::Postgres => {
            let db = PostgresDb::connect_lazy(&settings.database).context("failed to configure postgres pool")?;
            db.run_migrations().await.context("postgres migrations failed")?;
            db.ping().await.context("postgres ping failed")?;
            db.repositories()
        }
    };
    tracing::info!(kind = settings.database.kind.as_str(), "database ready, migrations applied");
    Ok(repos)
}

/// Selects the blob backend by config kind (decision 09).
fn build_blob(settings: &Settings) -> anyhow::Result<Arc<dyn BlobStore>> {
    let blob: Arc<dyn BlobStore> = match settings.blob.kind {
        BlobKind::Fs => Arc::new(ObjectStoreBlob::fs(&settings.blob).context("failed to open fs blob store")?),
        BlobKind::S3 => Arc::new(ObjectStoreBlob::s3(&settings.blob).context("failed to configure s3 blob store")?),
        BlobKind::Memory => Arc::new(ObjectStoreBlob::memory()),
    };
    Ok(blob)
}

/// Selects the KV backend by config kind (decision 09; redis is mandatory for replicas > 1).
fn build_kv(settings: &Settings) -> anyhow::Result<Arc<dyn Kv>> {
    let kv: Arc<dyn Kv> = match settings.kv.kind {
        KvKind::Memory => Arc::new(MemoryKv::new()),
        KvKind::Redis => Arc::new(RedisKv::from_config(&settings.kv).context("failed to configure redis kv")?),
    };
    Ok(kv)
}

/// Resolves on SIGINT (Ctrl+C) or SIGTERM (orchestrator stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
