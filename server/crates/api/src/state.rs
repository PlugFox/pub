//! Shared application state: effective config plus `Arc<dyn Trait>` backend handles
//! (decision 09 — runtime polymorphism, never cargo features).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pub_auth::flows::AuthService;
use pub_config::Settings;
use pub_core::traits::{BlobStore, Kv, Repositories};

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
    ) -> Self {
        Self { settings: Arc::new(settings), repos, blob, kv, auth, clock: Arc::new(Utc::now) }
    }

    /// Replaces the clock — deterministic time for tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }
}
