//! `pubd` — the Pub registry server binary.
//!
//! Startup sequence (docs/architecture.md): parse CLI → load layered config → init
//! telemetry → select backends by config kind → run migrations → build `AppState` → serve
//! with graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::{CommandFactory as _, FromArgMatches as _};
use pub_api::AppState;
use pub_auth::flows::{AuthPolicy, AuthService};
use pub_auth::jwt::Keyring;
use pub_auth::random::{OsRandom, RandomSource as _};
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobKind, CliArgs, DatabaseKind, KvKind, Settings, SmtpSecurityMode};
use pub_core::session::SessionLimits;
use pub_core::traits::{BlobStore, Kv, Mailer, Repositories};
use pub_db_postgres::PostgresDb;
use pub_db_sqlite::SqliteDb;
use pub_kv::{MemoryKv, RedisKv};
use pub_mail::{InMemoryMailer, SmtpMailer, SmtpSecurity, SmtpSettings};
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
    let mailer = build_mailer(&settings)?;
    let auth = build_auth(&settings, repos.clone(), Arc::clone(&kv), Arc::clone(&mailer))?;

    let listen = settings.server.listen.clone();
    let state = AppState::new(settings, repos, blob, kv, auth);
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

/// SMTP configured → [`SmtpMailer`]; otherwise the in-memory mailer with a loud warning
/// (dev convenience — OTP mails end up in memory, never delivered).
fn build_mailer(settings: &Settings) -> anyhow::Result<Arc<dyn Mailer>> {
    let mailer: Arc<dyn Mailer> = match &settings.smtp.host {
        Some(host) => {
            let smtp = SmtpSettings {
                host: host.clone(),
                port: settings.smtp.port,
                username: settings.smtp.username.clone(),
                // Env/boot-config only for now; moves into KEK-encrypted runtime settings
                // later (S-26).
                password: settings.smtp.password.clone(),
                from: settings.smtp.from.clone(),
                security: match settings.smtp.security {
                    SmtpSecurityMode::Tls => SmtpSecurity::Tls,
                    SmtpSecurityMode::Starttls => SmtpSecurity::Starttls,
                    SmtpSecurityMode::None => SmtpSecurity::None,
                },
            };
            tracing::info!(host = %smtp.host, port = smtp.port, "smtp mailer configured");
            Arc::new(SmtpMailer::new(&smtp).map_err(|err| anyhow::anyhow!("{err}"))?)
        }
        None => {
            tracing::warn!(
                "smtp.host is not configured — using the in-memory mailer: \
                 OTP and notification emails are NOT delivered anywhere"
            );
            Arc::new(InMemoryMailer::new())
        }
    };
    Ok(mailer)
}

/// Builds the auth service: keyring + pepper from config, with loud ephemeral dev fallbacks
/// (the config validator guarantees real secrets in production mode — S-25).
fn build_auth(
    settings: &Settings,
    repos: Repositories,
    kv: Arc<dyn Kv>,
    mailer: Arc<dyn Mailer>,
) -> anyhow::Result<Arc<AuthService>> {
    let rng = Arc::new(OsRandom);
    let auth_cfg = &settings.auth;

    let keyring = match (&auth_cfg.jwt.kid, &auth_cfg.jwt.signing_key) {
        (Some(kid), Some(key)) => {
            let verify: Vec<(String, String)> =
                auth_cfg.jwt.verify_keys.iter().map(|entry| (entry.kid.clone(), entry.key.clone())).collect();
            Keyring::from_base64(kid, key, &verify).map_err(|err| anyhow::anyhow!("{err}"))?
        }
        _ => {
            tracing::warn!(
                "auth.jwt.signing_key is not configured — generated an EPHEMERAL dev keyring: \
                 every session and access token dies with this process (dev mode only, S-25)"
            );
            Keyring::ephemeral(rng.as_ref())
        }
    };

    let otp_pepper = match &auth_cfg.otp_pepper {
        Some(pepper) => pepper.clone().into_bytes(),
        None => {
            tracing::warn!(
                "auth.otp_pepper is not configured — generated an EPHEMERAL dev pepper: \
                 outstanding OTP codes die with this process (dev mode only, S-25)"
            );
            let mut pepper = [0u8; 32];
            rng.fill(&mut pepper);
            pepper.to_vec()
        }
    };

    let policy = AuthPolicy {
        access_ttl: Duration::from_secs(auth_cfg.access_ttl_minutes * 60),
        session_limits: SessionLimits {
            idle_timeout: Duration::from_secs(auth_cfg.refresh_idle_days * 24 * 3600),
            absolute_cap: Duration::from_secs(auth_cfg.refresh_absolute_days * 24 * 3600),
        },
        otp_pepper,
        token_prefix: auth_cfg.token_prefix.clone(),
        allow_registration: auth_cfg.allow_registration,
        allowed_email_domains: auth_cfg.allowed_email_domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
        otp_per_email_hour: auth_cfg.rate_limit.otp_per_email_hour,
        otp_per_ip_hour: auth_cfg.rate_limit.otp_per_ip_hour,
    };
    Ok(Arc::new(AuthService::new(repos, kv, mailer, keyring, policy, rng)))
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
