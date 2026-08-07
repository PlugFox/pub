//! A scripted upstream for the proxy suite (decision 07).
//!
//! Implements [`UpstreamClient`] over in-memory maps, so no test in this workspace ever opens a
//! socket — and, more importantly, so every *misbehaviour* the pipeline exists to survive can
//! be produced on demand: an outage, a 404, a listing that disagrees with its own bytes, a
//! hostile pubspec, an oversized archive, and a slow response that makes concurrent callers
//! genuinely overlap.
//!
//! Every call is counted. "Served from cache" is only a claim unless the mock can prove it was
//! not asked.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use pub_registry::upstream::{UpstreamArchive, UpstreamClient, UpstreamError, UpstreamListing};
use serde_json::json;

/// The base URL the mock claims to be.
pub const UPSTREAM_BASE: &str = "https://upstream.test";

/// How the mock answers the next call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Serve whatever is scripted.
    Ok,
    /// Transient failure — the circuit-breaker and stale-serving path.
    Unavailable,
    /// Upstream says the package does not exist.
    NotFound,
}

/// A scripted upstream registry.
pub struct MockUpstream {
    listings: Mutex<HashMap<String, serde_json::Value>>,
    archives: Mutex<HashMap<String, Bytes>>,
    listing_calls: AtomicUsize,
    archive_calls: AtomicUsize,
    mode: Mutex<Mode>,
    delay: Mutex<Option<Duration>>,
}

impl Default for MockUpstream {
    fn default() -> Self {
        Self {
            listings: Mutex::new(HashMap::new()),
            archives: Mutex::new(HashMap::new()),
            listing_calls: AtomicUsize::new(0),
            archive_calls: AtomicUsize::new(0),
            mode: Mutex::new(Mode::Ok),
            delay: Mutex::new(None),
        }
    }
}

impl MockUpstream {
    /// The URL the mock advertises for a version's archive.
    pub fn archive_url(name: &str, version: &str) -> String {
        format!("https://cdn.upstream.test/packages/{name}-{version}.tar.gz")
    }

    /// One `versions[]` entry with a hash that matches the bytes it points at.
    pub fn version_entry(name: &str, version: &str, sha256: &str) -> serde_json::Value {
        json!({
            "version": version,
            "archive_url": Self::archive_url(name, version),
            "archive_sha256": sha256,
            "pubspec": {
                "name": name,
                "version": version,
                "description": "An upstream package.",
                "environment": { "sdk": ">=3.0.0 <4.0.0" },
            },
        })
    }

    /// A whole listing document.
    pub fn listing_doc(name: &str, versions: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "name": name,
            "latest": versions.last().cloned().unwrap_or(json!(null)),
            "versions": versions,
        })
    }

    /// Publishes versions upstream: bytes served, hash advertised, entry listed.
    pub fn publish(&self, name: &str, versions: &[(&str, &[u8])]) {
        let entries: Vec<serde_json::Value> = versions
            .iter()
            .map(|(version, bytes)| {
                self.archives
                    .lock()
                    .expect("mock mutex")
                    .insert(Self::archive_url(name, version), Bytes::copy_from_slice(bytes));
                Self::version_entry(name, version, &pub_registry::hex_sha256(bytes))
            })
            .collect();
        self.set_listing(name, Self::listing_doc(name, entries));
    }

    /// Replaces the listing document wholesale (hostile documents, flag combinations).
    pub fn set_listing(&self, name: &str, document: serde_json::Value) {
        self.listings.lock().expect("mock mutex").insert(name.to_owned(), document);
    }

    /// Replaces the bytes served for a version **without** touching its advertised hash.
    pub fn corrupt_archive(&self, name: &str, version: &str, bytes: &[u8]) {
        self.archives
            .lock()
            .expect("mock mutex")
            .insert(Self::archive_url(name, version), Bytes::copy_from_slice(bytes));
    }

    /// Switches the failure mode.
    pub fn set_mode(&self, mode: Mode) {
        *self.mode.lock().expect("mock mutex") = mode;
    }

    /// Makes every listing fetch take `delay`, so concurrent callers overlap.
    pub fn set_delay(&self, delay: Duration) {
        *self.delay.lock().expect("mock mutex") = Some(delay);
    }

    /// How many listing fetches reached upstream.
    pub fn listing_calls(&self) -> usize {
        self.listing_calls.load(Ordering::SeqCst)
    }

    /// How many archive downloads reached upstream.
    pub fn archive_calls(&self) -> usize {
        self.archive_calls.load(Ordering::SeqCst)
    }

    fn mode(&self) -> Mode {
        *self.mode.lock().expect("mock mutex")
    }
}

#[async_trait::async_trait]
impl UpstreamClient for MockUpstream {
    fn base_url(&self) -> &str {
        UPSTREAM_BASE
    }

    async fn fetch_listing(&self, name: &str) -> Result<UpstreamListing, UpstreamError> {
        self.listing_calls.fetch_add(1, Ordering::SeqCst);
        let delay = *self.delay.lock().expect("mock mutex");
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        match self.mode() {
            Mode::Unavailable => return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() }),
            Mode::NotFound => return Err(UpstreamError::NotFound),
            Mode::Ok => {}
        }
        let document = self.listings.lock().expect("mock mutex").get(name).cloned().ok_or(UpstreamError::NotFound)?;
        // Parsing here rather than in the harness keeps the mock honest: a hostile document
        // is refused by the *real* validator, not by the fixture.
        UpstreamListing::parse(name, document)
    }

    async fn fetch_archive(&self, url: &str) -> Result<UpstreamArchive, UpstreamError> {
        self.archive_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode() {
            Mode::Unavailable => return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() }),
            Mode::NotFound => return Err(UpstreamError::NotFound),
            Mode::Ok => {}
        }
        let bytes = self.archives.lock().expect("mock mutex").get(url).cloned().ok_or(UpstreamError::NotFound)?;
        let len = bytes.len() as u64;
        // Chunked so the size cap has to trip mid-stream rather than on one blob.
        let chunks: Vec<Bytes> = bytes.chunks(4096).map(Bytes::copy_from_slice).collect();
        Ok(UpstreamArchive {
            content_length: Some(len),
            body: futures::stream::iter(chunks.into_iter().map(Ok)).boxed(),
        })
    }
}
