//! Shared application state: effective config plus `Arc<dyn Trait>` backend handles
//! (decision 09 — runtime polymorphism, never cargo features).

use std::sync::Arc;

use pub_config::Settings;
use pub_core::traits::{BlobStore, Kv, Repositories};

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
}

impl AppState {
    /// Bundles the configured backends into the shared state.
    pub fn new(settings: Settings, repos: Repositories, blob: Arc<dyn BlobStore>, kv: Arc<dyn Kv>) -> Self {
        Self { settings: Arc::new(settings), repos, blob, kv }
    }
}
