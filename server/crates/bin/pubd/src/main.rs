//! `pubd` — the Pub registry server binary.
//!
//! Startup sequence (docs/architecture.md): parse CLI → load layered config → init
//! telemetry → select backends by config kind → run migrations → build `AppState` → serve
//! with graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use clap::{CommandFactory as _, FromArgMatches as _};
use pub_api::AppState;
use pub_auth::flows::{AuthPolicy, AuthService};
use pub_auth::jwt::Keyring;
use pub_auth::oidc::{OidcClient, ProviderConfig};
use pub_auth::random::{OsRandom, RandomSource as _};
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobKind, CliArgs, DatabaseKind, KvKind, MirrorModeConfig, Settings, SmtpSecurityMode};
use pub_core::Format;
use pub_core::event::{EventSink, NoopEventSink};
use pub_core::session::SessionLimits;
use pub_core::traits::JobLock;
use pub_core::traits::{BlobStore, Kv, Mailer, Repositories};
use pub_db_postgres::PostgresDb;
use pub_db_sqlite::SqliteDb;
use pub_jobs::{
    BLOB_GC_JOB, BlobGc, GcPolicy, InMemoryJobLock, MIRROR_JOB, MirrorMode, MirrorPolicy, MirrorWorker, Scheduler,
    SchedulerHandle,
};
use pub_kv::{MemoryKv, RedisKv};
use pub_mail::{InMemoryMailer, SmtpMailer, SmtpSecurity, SmtpSettings};
use pub_registry::upstream::http::{HttpUpstream, HttpUpstreamConfig};
use pub_registry::{
    ArchiveLimits, RegistryPolicy, RegistryService, UpstreamClient, UpstreamService, UpstreamServicePolicy,
};
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
    let registry = build_registry(&settings, repos.clone(), Arc::clone(&blob));
    let upstream = build_upstream(&settings, repos.clone(), Arc::clone(&blob))?;

    // The scheduler owns its tasks and aborts them when the handle drops, so it must outlive
    // `serve` — a mirror sweep that stops the moment the binding is dropped would be a very
    // confusing bug.
    let _jobs = spawn_jobs(&settings, repos.clone(), Arc::clone(&blob), upstream.clone());

    let listen = settings.server.listen.clone();
    let state = AppState::new(settings, repos, blob, kv, auth, registry).with_upstream(upstream);
    let app = pub_api::router(state);

    let listener = tokio::net::TcpListener::bind(&listen).await.with_context(|| format!("failed to bind {listen}"))?;
    tracing::info!(%listen, "pubd listening");
    // Connect info is what the rate limiter falls back to when forwarding headers are not
    // trusted (S-24) — without it an untrusted deployment would have no per-IP identity at all.
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

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

/// Builds the registry services from the `[registry]` config section (S-20 limits,
/// decision 06 restore window).
///
/// The publish lock is the in-process [`JobLock`] for now; the Redis-backed implementation
/// arrives with the multi-instance tier (decision 03), and the event sink is a no-op until
/// the domain event bus lands (decision 22). Both are `Arc<dyn …>` seams, so swapping them is
/// a wiring change here and nowhere else.
fn build_registry(settings: &Settings, repos: Repositories, blob: Arc<dyn BlobStore>) -> Arc<RegistryService> {
    let cfg = &settings.registry;
    let policy = RegistryPolicy {
        archive: ArchiveLimits {
            max_archive_bytes: cfg.max_archive_bytes,
            max_uncompressed_bytes: cfg.max_uncompressed_bytes,
            max_entries: cfg.max_entries,
            max_compression_ratio: cfg.max_compression_ratio,
            max_captured_file_bytes: cfg.max_captured_file_bytes,
        },
        unretract_window: chrono::Duration::days(cfg.unretract_window_days),
        ..RegistryPolicy::default()
    };
    let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
    let events: Arc<dyn EventSink> = Arc::new(NoopEventSink);
    Arc::new(RegistryService::new(repos, blob, lock, events, policy))
}

/// Builds the upstream read-through proxy from the `[upstream]` config section (decision 07).
///
/// Returns `None` when the proxy is disabled, and that `None` is load-bearing: with no service
/// in `AppState` there is no upstream branch in the resolution path at all, which is exactly
/// what an air-gapped deployment is buying (as opposed to a proxy that is configured but keeps
/// answering nothing).
fn build_upstream(
    settings: &Settings,
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
) -> anyhow::Result<Option<Arc<UpstreamService>>> {
    let cfg = &settings.upstream;
    if !cfg.enabled {
        tracing::info!("upstream proxy disabled — unclaimed package names resolve to 404");
        return Ok(None);
    }

    let client: Arc<dyn UpstreamClient> = Arc::new(
        HttpUpstream::new(HttpUpstreamConfig {
            base_url: cfg.base_url.clone(),
            user_agent: cfg.user_agent.clone(),
            auth_token: cfg.auth_token.as_ref().map(|token| token.expose().to_owned()),
            connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
            listing_timeout: Duration::from_secs(cfg.listing_timeout_secs),
            archive_timeout: Duration::from_secs(cfg.archive_timeout_secs),
            max_retries: cfg.max_retries,
            retry_backoff: Duration::from_millis(cfg.retry_backoff_ms),
            retry_max_backoff: Duration::from_millis(cfg.retry_max_backoff_ms),
            max_listing_bytes: cfg.max_listing_bytes,
            // The config validator already refuses a plaintext upstream in production mode;
            // this flag is what lets a dev instance point at a mock on localhost.
            allow_plaintext: settings.server.mode != pub_config::RunMode::Production,
        })
        .map_err(|err| anyhow::anyhow!("{err}"))?,
    );

    // The event sink is a no-op until the domain event bus lands (decision 22); the S-19
    // alarms it will carry are audit-logged unconditionally in the meantime.
    let events: Arc<dyn EventSink> = Arc::new(NoopEventSink);
    let policy = UpstreamServicePolicy {
        listing_ttl: chrono::Duration::seconds(cfg.listing_ttl_secs as i64),
        max_archive_bytes: cfg.max_archive_bytes,
        circuit_failure_threshold: cfg.circuit_failure_threshold,
        circuit_open: chrono::Duration::seconds(cfg.circuit_open_secs as i64),
        max_concurrent_fetches: cfg.max_concurrent_fetches as usize,
    };
    tracing::info!(upstream = %cfg.base_url, ttl_secs = cfg.listing_ttl_secs, "upstream read-through proxy enabled");
    Ok(Some(Arc::new(UpstreamService::new(repos, blob, client, events, policy))))
}

/// Registers the enabled background jobs and spawns the leader-locked scheduler
/// (decision 03; docs/architecture.md "Background jobs").
///
/// Both jobs are **off by default** and each is skipped entirely when it is: a job that is not
/// registered cannot tick, which is a stronger guarantee than a job whose body returns early —
/// and for the GC, which deletes bytes, that difference is the point.
///
/// The lock is the in-process one for now (single instance); the Redis-backed implementation
/// arrives with the multi-instance tier, and it is a one-line change here because the scheduler
/// only ever sees `Arc<dyn JobLock>`.
fn spawn_jobs(
    settings: &Settings,
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    upstream: Option<Arc<pub_registry::UpstreamService>>,
) -> Option<SchedulerHandle> {
    let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
    let mut scheduler = Scheduler::new(lock);
    let mut registered = Vec::new();

    let mirror_cfg = settings.upstream.mirror;
    if let Some(upstream) = upstream.filter(|_| mirror_cfg.mode.is_enabled()) {
        let policy = MirrorPolicy {
            mode: match mirror_cfg.mode {
                MirrorModeConfig::Off => MirrorMode::Off,
                MirrorModeConfig::Recent => MirrorMode::Recent,
                MirrorModeConfig::Full => MirrorMode::Full,
            },
            interval: Duration::from_secs(mirror_cfg.interval_secs),
            chunk: mirror_cfg.chunk as usize,
            concurrency: mirror_cfg.concurrency as usize,
            refresh_after: chrono::Duration::seconds(mirror_cfg.refresh_after_secs as i64),
            archives: mirror_cfg.archives,
            archive_versions: mirror_cfg.archive_versions as usize,
            resweep_after: chrono::Duration::seconds(mirror_cfg.resweep_after_secs as i64),
        };
        let interval = policy.interval;
        let worker = Arc::new(MirrorWorker::new(repos.clone(), upstream, Format::Pub, policy));
        scheduler.add(MIRROR_JOB, interval, move || {
            let worker = Arc::clone(&worker);
            async move {
                worker.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(MIRROR_JOB);
    }

    let gc_cfg = settings.jobs.blob_gc;
    if gc_cfg.enabled {
        let policy = GcPolicy {
            enabled: true,
            interval: Duration::from_secs(gc_cfg.interval_secs),
            dry_run: gc_cfg.dry_run,
            min_age: chrono::Duration::seconds(gc_cfg.min_age_secs as i64),
        };
        let interval = policy.interval;
        let gc = Arc::new(BlobGc::new(repos, blob, vec![Format::Pub], policy));
        scheduler.add(BLOB_GC_JOB, interval, move || {
            let gc = Arc::clone(&gc);
            async move {
                gc.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(BLOB_GC_JOB);
    }

    if registered.is_empty() {
        tracing::info!("no background jobs enabled");
        return None;
    }
    tracing::info!(jobs = ?registered, "background jobs scheduled");
    Some(scheduler.spawn())
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
                password: settings.smtp.password.as_ref().map(|secret| secret.expose().to_owned()),
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
            let verify: Vec<(String, String)> = auth_cfg
                .jwt
                .verify_keys
                .iter()
                .map(|entry| (entry.kid.clone(), entry.key.expose().to_owned()))
                .collect();
            Keyring::from_base64(kid, key.expose(), &verify).map_err(|err| anyhow::anyhow!("{err}"))?
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
        Some(pepper) => pepper.expose().as_bytes().to_vec(),
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

    // The KEK seals TOTP seeds at rest (S-05). The config validator guarantees base64 of
    // exactly 32 bytes whenever it is set, and requires it in production mode (S-25).
    let kek = match &auth_cfg.kek {
        Some(kek) => base64::engine::general_purpose::STANDARD
            .decode(kek.expose())
            .map_err(|_| anyhow::anyhow!("auth.kek is not valid base64"))?,
        None => {
            tracing::warn!(
                "auth.kek is not configured — generated an EPHEMERAL dev KEK: \
                 enrolled TOTP second factors become undecryptable when this process exits \
                 (dev mode only, S-25)"
            );
            let mut kek = [0u8; 32];
            rng.fill(&mut kek);
            kek.to_vec()
        }
    };

    let providers: Vec<ProviderConfig> = auth_cfg
        .oidc
        .iter()
        .map(|provider| ProviderConfig {
            id: provider.id.clone(),
            display_name: provider.display_name.clone(),
            issuer: provider.issuer.trim_end_matches('/').to_owned(),
            client_id: provider.client_id.clone(),
            client_secret: provider.client_secret.expose().to_owned(),
            scopes: provider.scopes.clone(),
        })
        .collect();
    if !providers.is_empty() {
        tracing::info!(
            providers = ?providers.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            "oidc sign-in enabled"
        );
    }
    let oidc = OidcClient::new(providers, &settings.server.public_url).map_err(|err| anyhow::anyhow!("{err}"))?;

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
        login_per_ip_minute: auth_cfg.rate_limit.login_per_ip_minute,
        token_auth_fail_per_ip_minute: auth_cfg.rate_limit.token_auth_fail_per_ip_minute,
        kek,
        step_up_window: Duration::from_secs(auth_cfg.step_up_minutes * 60),
        totp_issuer: "Pub".to_owned(),
    };
    Ok(Arc::new(AuthService::new(repos, kv, mailer, keyring, policy, rng, oidc)))
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
