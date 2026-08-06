//! Shared application state: effective config plus `Arc<dyn Trait>` backend handles
//! (decision 09 — runtime polymorphism, never cargo features).

use std::sync::Arc;

use pub_config::Settings;
use pub_core::traits::{BlobStore, Kv};

/// State handed to every handler. Cloning is cheap (all fields are `Arc`s).
///
/// Repository handles (`Arc<dyn PackageRepo>`, …) join this struct as soon as the db crates
/// implement the core traits in the next roadmap step.
#[derive(Clone)]
pub struct AppState {
    /// Effective boot configuration.
    pub settings: Arc<Settings>,
    /// Blob storage backend.
    pub blob: Arc<dyn BlobStore>,
    /// Key-value store / broker backend.
    pub kv: Arc<dyn Kv>,
}

impl AppState {
    /// Bundles the configured backends into the shared state.
    pub fn new(settings: Settings, blob: Arc<dyn BlobStore>, kv: Arc<dyn Kv>) -> Self {
        Self { settings: Arc::new(settings), blob, kv }
    }
}
