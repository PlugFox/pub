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
use pub_admin::{AdminService, OrgPolicy, OrgService};
use pub_api::AppState;
use pub_auth::flows::{AuthPolicy, AuthService};
use pub_auth::jwt::Keyring;
use pub_auth::oidc::{OidcClient, ProviderConfig};
use pub_auth::random::{OsRandom, RandomSource as _};
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobKind, CliArgs, DatabaseKind, KvKind, MirrorModeConfig, Settings, SmtpSecurityMode};
use pub_core::Format;
use pub_core::event::EventSink;
use pub_core::session::SessionLimits;
use pub_core::settings::{SETTINGS_TOPIC, SettingsCache};
use pub_core::traits::{BlobStore, JobLock, JobTrigger, Kv, Mailer, Repositories};
use pub_db_postgres::PostgresDb;
use pub_db_sqlite::SqliteDb;
use pub_events::{EventBus, EventBusPolicy, EventConsumer, NotificationCenter, NotificationPolicy};
use pub_jobs::{
    BLOB_GC_JOB, BlobGc, DOWNLOAD_ROLLUP_JOB, DownloadRollup, DownloadRollupPolicy, GcPolicy, InMemoryJobLock,
    JobRegistry, MIRROR_JOB, MirrorMode, MirrorPolicy, MirrorWorker, REINDEX_JOB, ReindexPolicy, Reindexer, Scheduler,
    SchedulerHandle,
};
use pub_kv::{MemoryKv, RedisKv};
use pub_mail::{InMemoryMailer, SmtpMailer, SmtpSecurity, SmtpSettings};
use pub_registry::upstream::http::{HttpUpstream, HttpUpstreamConfig};
use pub_registry::{
    ArchiveLimits, DownloadRecorder, RegistryPolicy, RegistryService, UpstreamClient, UpstreamService,
    UpstreamServicePolicy,
};
use pub_telemetry::LogFormat;

/// Version string surfaced by `pubd --version`: the release/crate version
/// (`pub_core::version::VERSION`, decision 18 — the git tag's version in release builds,
/// crate version + `+dev` otherwise) + git hash + build date.
fn version_string() -> String {
    format!("{} ({}, {})", pub_core::version::VERSION, env!("PUBD_GIT_HASH"), env!("PUBD_BUILD_DATE"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inject the release/git-stamped version so clap's --version prints it (the flag is
    // disabled on the shared derive struct precisely so this binary can own the version).
    // One deliberate leak of a short string at startup: clap wants `&'static str` without
    // its `string` feature, and the version outlives the process anyway.
    let version: &'static str = Box::leak(version_string().into_boxed_str());
    let matches = CliArgs::command().version(version).disable_version_flag(false).get_matches();
    let cli = CliArgs::from_arg_matches(&matches).context("failed to parse command line")?;

    let settings = pub_config::load(&cli).context("failed to load configuration")?;
    let telemetry = pub_telemetry::init(LogFormat::Pretty, &settings.telemetry);
    tracing::info!(version, "starting pubd");
    tracing::info!("{}", settings.summary());

    let repos = build_database(&settings).await?;
    let blob = build_blob(&settings)?;
    let kv = build_kv(&settings)?;
    let mailer = build_mailer(&settings)?;

    // Runtime settings (decision 09) before anything that reads them: the cache is seeded from
    // boot config, then loaded from the database so this process starts on the instance's
    // current policy rather than on the operator's defaults.
    let runtime = Arc::new(SettingsCache::new(settings.runtime_defaults()));
    let version = runtime.reload(repos.settings.as_ref()).await.context("failed to load runtime settings")?;
    tracing::info!(version, "runtime settings loaded");

    let auth = build_auth(&settings, repos.clone(), Arc::clone(&kv), Arc::clone(&mailer), Arc::clone(&runtime))?;
    bootstrap_admins(&settings, &repos).await?;

    // The domain event bus (decision 22) is built before every service that emits into it, so
    // there is exactly one bus per process: the SSE stream this instance serves and the
    // notification rows it writes come from the same fan-out.
    let events = build_events(&settings, repos.clone(), Arc::clone(&kv), Arc::clone(&mailer));
    events.spawn_broker_subscription();
    let sink: Arc<dyn EventSink> = Arc::clone(&events) as Arc<dyn EventSink>;

    let registry = build_registry(&settings, repos.clone(), Arc::clone(&blob), Arc::clone(&sink));
    let upstream = build_upstream(&settings, repos.clone(), Arc::clone(&blob), Arc::clone(&sink))?;

    // One buffer, shared by the download handler that fills it and the rollup job that drains
    // it: two of them would mean counting into a map nothing ever writes out.
    let downloads = Arc::new(DownloadRecorder::new(settings.jobs.downloads.buffer_capacity));

    // The scheduler owns its tasks and aborts them when the handle drops, so it must outlive
    // `serve` — a mirror sweep that stops the moment the binding is dropped would be a very
    // confusing bug. The registry it hands back is the same job set, reachable on demand from
    // the admin surface under the same leader lock.
    let (_jobs, triggers) =
        spawn_jobs(&settings, repos.clone(), Arc::clone(&blob), upstream.clone(), Arc::clone(&downloads));

    let orgs = Arc::new(OrgService::new(
        repos.clone(),
        Arc::clone(&auth),
        Arc::clone(&registry),
        Arc::clone(&mailer),
        Arc::clone(&sink),
        Arc::new(OsRandom),
        OrgPolicy::default(),
    ));
    let admin = Arc::new(AdminService::new(
        repos.clone(),
        Arc::clone(&kv),
        Arc::clone(&runtime),
        Arc::clone(&auth),
        Arc::clone(&sink),
        triggers,
        Arc::new(OsRandom),
        kek(&settings)?,
    ));

    // Cross-instance settings invalidation: the broker subscription is the fast path and the
    // version poll is the reconciliation fallback for messages lost across a reconnect
    // (decision 09). Both are best-effort by design — the durable rows are the truth.
    spawn_settings_watch(Arc::clone(&runtime), repos.clone(), Arc::clone(&kv));

    let listen = settings.server.listen.clone();
    let state = AppState::new(settings, runtime, repos, blob, kv, auth, registry, orgs, admin)
        .with_upstream(upstream)
        .with_downloads(downloads)
        .with_events(events);
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
/// arrives with the multi-instance tier (decision 03). The event sink is the process-wide bus
/// (decision 22), so a publish reaches the SSE stream and the notification center through the
/// same seam the audit log already uses.
fn build_registry(
    settings: &Settings,
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    events: Arc<dyn EventSink>,
) -> Arc<RegistryService> {
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
    events: Arc<dyn EventSink>,
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
    downloads: Arc<DownloadRecorder>,
) -> (Option<SchedulerHandle>, Arc<dyn JobTrigger>) {
    let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
    let mut scheduler = Scheduler::new(Arc::clone(&lock));
    // The same lock, so an operator's "run now" and a scheduled tick can never both hold one
    // job's durable cursor.
    let mut triggers = JobRegistry::new(lock);
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
        triggers = triggers.with_mirror(Arc::clone(&worker));
        scheduler.add(MIRROR_JOB, interval, move || {
            let worker = Arc::clone(&worker);
            async move {
                worker.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(MIRROR_JOB);
    }

    let reindex_cfg = settings.jobs.reindex;
    if reindex_cfg.enabled {
        let policy = ReindexPolicy {
            enabled: true,
            interval: Duration::from_secs(reindex_cfg.interval_secs),
            chunk: reindex_cfg.chunk,
            resweep_after: chrono::Duration::seconds(reindex_cfg.resweep_after_secs as i64),
        };
        let interval = policy.interval;
        let worker = Arc::new(Reindexer::new(repos.clone(), policy));
        triggers = triggers.with_reindex(Arc::clone(&worker));
        scheduler.add(REINDEX_JOB, interval, move || {
            let worker = Arc::clone(&worker);
            async move {
                worker.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(REINDEX_JOB);
    }

    let downloads_cfg = settings.jobs.downloads;
    if downloads_cfg.enabled {
        let policy = DownloadRollupPolicy {
            enabled: true,
            interval: Duration::from_secs(downloads_cfg.interval_secs),
            recent_window: chrono::Duration::days(downloads_cfg.recent_window_days),
        };
        let interval = policy.interval;
        let rollup = Arc::new(DownloadRollup::new(repos.clone(), downloads, policy));
        triggers = triggers.with_downloads(Arc::clone(&rollup));
        scheduler.add(DOWNLOAD_ROLLUP_JOB, interval, move || {
            let rollup = Arc::clone(&rollup);
            async move {
                rollup.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(DOWNLOAD_ROLLUP_JOB);
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
        triggers = triggers.with_blob_gc(Arc::clone(&gc));
        scheduler.add(BLOB_GC_JOB, interval, move || {
            let gc = Arc::clone(&gc);
            async move {
                gc.run_once(chrono::Utc::now()).await?;
                Ok(())
            }
        });
        registered.push(BLOB_GC_JOB);
    }

    let triggers: Arc<dyn JobTrigger> = Arc::new(triggers);
    if registered.is_empty() {
        tracing::info!("no background jobs enabled");
        return (None, triggers);
    }
    tracing::info!(jobs = ?registered, "background jobs scheduled");
    (Some(scheduler.spawn()), triggers)
}

/// Grants instance-administrator rights to the configured email list (decision 09 bootstrap).
///
/// Runs at every startup and is idempotent: an operator adding an address to the list gets it
/// promoted on the next restart without touching the database, and removing one does **not**
/// demote — revoking administration is an audited action on the admin surface, not a silent
/// side effect of an edit to a config file somebody may have reverted by accident.
async fn bootstrap_admins(settings: &Settings, repos: &Repositories) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    for email in &settings.auth.instance_admins {
        match repos.users.find_by_email(email).await.context("admin bootstrap lookup failed")? {
            Some(user) if user.is_instance_admin => {}
            Some(user) => {
                repos.users.set_instance_admin(user.id, true, now).await.context("admin bootstrap failed")?;
                tracing::info!(user = %user.id, "granted instance administrator rights from auth.instance_admins");
            }
            // The account does not exist yet: the auth flow promotes it when it registers.
            None => tracing::info!(
                "auth.instance_admins lists an address with no account yet; it is promoted at registration"
            ),
        }
    }
    Ok(())
}

/// Keeps this instance's settings cache current (decision 09).
///
/// Two independent mechanisms, because neither is sufficient alone: the broker delivers a
/// change in milliseconds but guarantees nothing across a reconnect, and the poll always
/// converges but only within its interval.
fn spawn_settings_watch(cache: Arc<SettingsCache>, repos: Repositories, kv: Arc<dyn Kv>) {
    let broker = Arc::clone(&cache);
    let broker_repos = repos.clone();
    tokio::spawn(async move {
        let mut stream = match kv.subscribe(SETTINGS_TOPIC).await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "settings invalidation subscription failed; the version poll still converges");
                return;
            }
        };
        use futures::StreamExt as _;
        while let Some(message) = stream.next().await {
            tracing::debug!(payload = %message.payload, "settings invalidation received");
            if let Err(error) = broker.reload(broker_repos.settings.as_ref()).await {
                tracing::warn!(%error, "settings reload after an invalidation failed");
            }
        }
    });

    tokio::spawn(async move {
        let period = pub_admin::instance::SETTINGS_POLL_INTERVAL.to_std().expect("poll interval is positive");
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match pub_admin::instance::poll_settings(&cache, &repos).await {
                Ok(true) => tracing::info!(version = cache.version(), "runtime settings reconciled"),
                Ok(false) => {}
                Err(error) => tracing::warn!(%error, "runtime settings poll failed"),
            }
        }
    });
}

/// Builds the domain event bus and its consumers ([decision 22](../../../docs/decisions.md#22)).
///
/// The KV handle is attached unconditionally, including with the in-memory backend: the bridge
/// filters this instance's own messages out by origin, so a single-node deployment pays one
/// no-op publish per event and a Redis deployment gets cross-instance fan-out with no
/// configuration difference — the property decision 20 needs for "any instance can serve any
/// client's stream".
fn build_events(settings: &Settings, repos: Repositories, kv: Arc<dyn Kv>, mailer: Arc<dyn Mailer>) -> Arc<EventBus> {
    let realtime = settings.realtime;
    let bus = Arc::new(
        EventBus::new(EventBusPolicy {
            replay_buffer: realtime.replay_buffer,
            max_connections_per_user: realtime.max_connections_per_user,
        })
        .with_broker(kv),
    );
    let center = NotificationCenter::new(
        repos,
        mailer,
        NotificationPolicy {
            max_recipients: realtime.max_notification_recipients,
            email_enabled: realtime.notification_email,
        },
        settings.branding.name.clone(),
    );
    bus.add_consumer(Arc::new(center) as Arc<dyn EventConsumer>);
    bus
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
    runtime: Arc<SettingsCache>,
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

    let kek = kek(settings)?;

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
        instance_admins: auth_cfg.instance_admins.iter().map(|email| email.to_ascii_lowercase()).collect(),
        kek,
        step_up_window: Duration::from_secs(auth_cfg.step_up_minutes * 60),
        totp_issuer: "Pub".to_owned(),
    };
    Ok(Arc::new(AuthService::new(repos, kv, mailer, keyring, policy, runtime, rng, oidc)))
}

/// The 32-byte key-encryption key sealing data at rest (S-05 TOTP seeds, S-26 SMTP password).
///
/// The config validator guarantees base64 of exactly 32 bytes whenever it is set, and requires
/// it in production mode (S-25). Dev mode falls back to an ephemeral value with a loud warning:
/// everything sealed under it becomes undecryptable when the process exits, which is the right
/// outcome for a value nobody configured.
fn kek(settings: &Settings) -> anyhow::Result<Vec<u8>> {
    match &settings.auth.kek {
        Some(kek) => base64::engine::general_purpose::STANDARD
            .decode(kek.expose())
            .map_err(|_| anyhow::anyhow!("auth.kek is not valid base64")),
        None => {
            tracing::warn!(
                "auth.kek is not configured — generated an EPHEMERAL dev KEK: \
                 enrolled TOTP second factors and the stored SMTP password become undecryptable \
                 when this process exits (dev mode only, S-25)"
            );
            let mut kek = [0u8; 32];
            OsRandom.fill(&mut kek);
            Ok(kek.to_vec())
        }
    }
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
