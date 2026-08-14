//! Shared application state: effective config plus `Arc<dyn Trait>` backend handles
//! (decision 09 — runtime polymorphism, never cargo features).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pub_admin::{AdminService, OrgService};
use pub_auth::flows::AuthService;
use pub_config::Settings;
use pub_core::settings::SettingsCache;
use pub_core::traits::{BlobStore, Kv, Repositories};
use pub_events::{EventBus, EventBusPolicy};
use pub_registry::{DownloadRecorder, RegistryService, UpstreamService};

/// Clock handle: handlers read `now` from here and pass it down — repositories and flows
/// never touch the wall clock, so tests can pin time (docs/rules/rust.md).
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// State handed to every handler. Cloning is cheap (all fields are `Arc`s).
#[derive(Clone)]
pub struct AppState {
    /// Effective boot configuration.
    pub settings: Arc<Settings>,
    /// Runtime-changeable instance settings (decision 09), refreshed by the broker
    /// subscription and the reconciliation poll. Handlers read a snapshot per request rather
    /// than a boot value, so an admin's change takes effect without a restart.
    pub runtime: Arc<SettingsCache>,
    /// Identity & access repositories over the selected database backend.
    pub repos: Repositories,
    /// Blob storage backend.
    pub blob: Arc<dyn BlobStore>,
    /// Key-value store / broker backend.
    pub kv: Arc<dyn Kv>,
    /// Auth flows facade (OTP, sessions, JWT keyring, CLI tokens).
    pub auth: Arc<AuthService>,
    /// Registry services (publish pipeline, retraction, hard delete, transfer).
    pub registry: Arc<RegistryService>,
    /// Organization lifecycle: profile, members, invitations, deletion. Every membership
    /// mutation goes through here, which is what makes the S-09 session revocation
    /// unforgettable by a route.
    pub orgs: Arc<OrgService>,
    /// Instance administration: settings, users, orgs, audit, stats, manual job runs.
    pub admin: Arc<AdminService>,
    /// Upstream read-through proxy (decision 07); `None` when `[upstream].enabled = false`.
    ///
    /// An `Option` rather than a no-op implementation on purpose: "the proxy is off" and "the
    /// proxy answered nothing" must not be the same code path. With `None` there is no
    /// upstream branch to reach at all, which is what an air-gapped operator is buying.
    pub upstream: Option<Arc<UpstreamService>>,
    /// Buffered download counts awaiting the rollup job (docs/architecture.md
    /// `download_stats`).
    ///
    /// Shared with the job by `Arc` rather than reconstructed there: the buffer *is* the write
    /// path, and two of them would mean the handler counts into a map nothing ever drains.
    pub downloads: Arc<DownloadRecorder>,
    /// The domain event bus (decision 22) the SSE endpoint subscribes to.
    ///
    /// The same handle the domain services emit into — one bus per process, so an event
    /// produced by a publish on this instance reaches a stream served by this instance without
    /// a broker round trip, and reaches the others' through one.
    pub events: Arc<EventBus>,
    /// Source of "now" for request handling.
    pub clock: Clock,
    /// Memoized `/healthz` backend probes (see [`crate::routes::system`]).
    ///
    /// On the state rather than in a static so two instances in one test process cannot share
    /// a health verdict; in production there is exactly one of each per process anyway.
    pub health_probe: Arc<std::sync::Mutex<Option<(std::time::Instant, crate::routes::system::Checks)>>>,
    /// Permits bounding audit-log exports in flight (see [`crate::routes::admin`]).
    ///
    /// On the state for the same reason as `health_probe`: two instances in one test process must
    /// not share a budget. The resource it protects is this instance's database pool — an export
    /// keeps querying after its response head has released the D8 concurrency permit, so nothing
    /// else in the stack bounds it.
    pub export_slots: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    /// Bundles the configured backends into the shared state with the real clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: Settings,
        runtime: Arc<SettingsCache>,
        repos: Repositories,
        blob: Arc<dyn BlobStore>,
        kv: Arc<dyn Kv>,
        auth: Arc<AuthService>,
        registry: Arc<RegistryService>,
        orgs: Arc<OrgService>,
        admin: Arc<AdminService>,
    ) -> Self {
        Self {
            settings: Arc::new(settings),
            runtime,
            repos,
            blob,
            kv,
            auth,
            registry,
            orgs,
            admin,
            upstream: None,
            downloads: Arc::new(DownloadRecorder::default()),
            events: Arc::new(EventBus::new(EventBusPolicy::default())),
            clock: Arc::new(Utc::now),
            health_probe: Arc::default(),
            export_slots: Arc::new(tokio::sync::Semaphore::new(crate::routes::admin::MAX_CONCURRENT_EXPORTS)),
        }
    }

    /// Attaches the process-wide event bus (the domain services hold the same handle).
    #[must_use]
    pub fn with_events(mut self, events: Arc<EventBus>) -> Self {
        self.events = events;
        self
    }

    /// Seconds between SSE heartbeats — also the S-32 bound on how long a revoked session's
    /// stream survives.
    pub fn sse_heartbeat(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.settings.realtime.heartbeat_secs.max(1))
    }

    /// Attaches the shared download counter buffer (the rollup job holds the same handle).
    #[must_use]
    pub fn with_downloads(mut self, downloads: Arc<DownloadRecorder>) -> Self {
        self.downloads = downloads;
        self
    }

    /// Attaches the upstream proxy (decision 07). Absent = no proxying at all.
    #[must_use]
    pub fn with_upstream(mut self, upstream: Option<Arc<UpstreamService>>) -> Self {
        self.upstream = upstream;
        self
    }

    /// Replaces the clock — deterministic time for tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Whether `X-Forwarded-For` may be believed (S-24 trusted-proxy stance — see
    /// [`crate::extract::client_ip`]).
    pub fn trust_proxy_headers(&self) -> bool {
        self.settings.server.trust_proxy_headers
    }
}
