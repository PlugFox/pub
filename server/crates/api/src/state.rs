//! Shared application state: effective config plus `Arc<dyn Trait>` backend handles
//! (decision 09 — runtime polymorphism, never cargo features).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pub_auth::flows::AuthService;
use pub_config::Settings;
use pub_core::traits::{BlobStore, Kv, Repositories};
use pub_registry::{RegistryService, UpstreamService};

/// Clock handle: handlers read `now` from here and pass it down — repositories and flows
/// never touch the wall clock, so tests can pin time (docs/rules/rust.md).
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// State handed to every handler. Cloning is cheap (all fields are `Arc`s).
#[derive(Clone)]
pub struct AppState {
    /// Effective boot configuration.
    pub settings: Arc<Settings>,
    /// Identity & access repositories over the selected database backend.
    pub repos: Repositories,
    /// Blob storage backend.
    pub blob: Arc<dyn BlobStore>,
    /// Key-value store / broker backend.
    pub kv: Arc<dyn Kv>,
    /// Auth flows facade (OTP, sessions, JWT keyring, CLI tokens).
    pub auth: Arc<AuthService>,
    /// Registry services (publish pipeline, retraction, hard delete). The pub protocol routes
    /// land on top of this in the next roadmap step.
    pub registry: Arc<RegistryService>,
    /// Upstream read-through proxy (decision 07); `None` when `[upstream].enabled = false`.
    ///
    /// An `Option` rather than a no-op implementation on purpose: "the proxy is off" and "the
    /// proxy answered nothing" must not be the same code path. With `None` there is no
    /// upstream branch to reach at all, which is what an air-gapped operator is buying.
    pub upstream: Option<Arc<UpstreamService>>,
    /// Source of "now" for request handling.
    pub clock: Clock,
}

impl AppState {
    /// Bundles the configured backends into the shared state with the real clock.
    pub fn new(
        settings: Settings,
        repos: Repositories,
        blob: Arc<dyn BlobStore>,
        kv: Arc<dyn Kv>,
        auth: Arc<AuthService>,
        registry: Arc<RegistryService>,
    ) -> Self {
        Self {
            settings: Arc::new(settings),
            repos,
            blob,
            kv,
            auth,
            registry,
            upstream: None,
            clock: Arc::new(Utc::now),
        }
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
