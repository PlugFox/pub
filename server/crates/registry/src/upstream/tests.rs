//! Ingest-pipeline tests: the real [`UpstreamService`] over a real migrated SQLite database,
//! an in-memory blob store, and a scripted upstream.
//!
//! The HTTP-facing half of the proxy (resolution order, `archive_url` rewriting, org policy,
//! status codes) is asserted in `crates/api/tests/proxy.rs`; what lives here is the pipeline's
//! own contract — what gets stored, what never does, and what happens when upstream misbehaves.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::TimeZone as _;
use pub_core::audit::AuditFilter;
use pub_core::traits::{BlobStore, DownloadPlan, Repositories};
use pub_db_sqlite::SqliteDb;
use serde_json::json;

use super::*;

// --------------------------------------------------------------------------------- doubles

/// Blob store that keeps what it is given, so a test can assert that a refused archive never
/// reached storage.
#[derive(Default)]
struct MemoryBlob {
    objects: Mutex<HashMap<String, Bytes>>,
}

impl MemoryBlob {
    fn len(&self) -> usize {
        self.objects.lock().expect("blob mutex").len()
    }

    fn get(&self, key: &str) -> Option<Bytes> {
        self.objects.lock().expect("blob mutex").get(key).cloned()
    }
}

#[async_trait::async_trait]
impl BlobStore for MemoryBlob {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.objects.lock().expect("blob mutex").insert(key.to_owned(), bytes);
        Ok(())
    }

    async fn download(&self, key: &str) -> Result<DownloadPlan> {
        let bytes = self
            .objects
            .lock()
            .expect("blob mutex")
            .get(key)
            .cloned()
            .ok_or_else(|| Error::NotFound { what: format!("blob {key}") })?;
        Ok(DownloadPlan::Stream(futures::stream::once(async move { Ok(bytes) }).boxed()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().expect("blob mutex").remove(key);
        Ok(())
    }
}

/// Event sink that keeps what it was given (the SSE bus does not exist yet — decision 22).
#[derive(Default)]
struct RecordingEvents {
    events: Mutex<Vec<DomainEvent>>,
}

impl RecordingEvents {
    fn names(&self) -> Vec<&'static str> {
        self.events.lock().expect("events mutex").iter().map(DomainEvent::name).collect()
    }
}

#[async_trait::async_trait]
impl EventSink for RecordingEvents {
    async fn emit(&self, event: DomainEvent) {
        self.events.lock().expect("events mutex").push(event);
    }
}

/// How the scripted upstream behaves on the next call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ok,
    Unavailable,
    NotFound,
    /// Upstream answers, promptly and in full, with something we cannot use.
    Malformed,
    /// Upstream answers with a document larger than this instance accepts.
    TooLarge,
    /// Upstream announces a full archive and then stops halfway through the body.
    Truncated,
}

/// A scripted upstream: no sockets, exact call counting, and every misbehaviour the pipeline
/// has to survive.
struct MockUpstream {
    listings: Mutex<HashMap<String, serde_json::Value>>,
    archives: Mutex<HashMap<String, Bytes>>,
    listing_calls: AtomicUsize,
    archive_calls: AtomicUsize,
    mode: Mutex<Mode>,
    /// Sleep injected into `fetch_listing`, so concurrent callers genuinely overlap.
    delay: Mutex<Option<std::time::Duration>>,
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
    fn publish(&self, name: &str, versions: &[(&str, &[u8])]) {
        let entries: Vec<serde_json::Value> = versions
            .iter()
            .map(|(version, bytes)| {
                self.archives.lock().expect("mock").insert(archive_url(name, version), Bytes::copy_from_slice(bytes));
                version_entry(name, version, &hex_sha256(bytes))
            })
            .collect();
        self.listings.lock().expect("mock").insert(name.to_owned(), listing_doc(name, entries));
    }

    /// Replaces the listing wholesale (used to script drift and hostile documents).
    fn set_listing(&self, name: &str, document: serde_json::Value) {
        self.listings.lock().expect("mock").insert(name.to_owned(), document);
    }

    /// Replaces the bytes served for a version without touching its advertised hash.
    fn corrupt_archive(&self, name: &str, version: &str, bytes: &[u8]) {
        self.archives.lock().expect("mock").insert(archive_url(name, version), Bytes::copy_from_slice(bytes));
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().expect("mock") = mode;
    }

    fn set_delay(&self, delay: std::time::Duration) {
        *self.delay.lock().expect("mock") = Some(delay);
    }

    fn listing_calls(&self) -> usize {
        self.listing_calls.load(Ordering::SeqCst)
    }

    fn archive_calls(&self) -> usize {
        self.archive_calls.load(Ordering::SeqCst)
    }

    fn mode(&self) -> Mode {
        *self.mode.lock().expect("mock")
    }
}

#[async_trait::async_trait]
impl UpstreamClient for MockUpstream {
    fn base_url(&self) -> &str {
        "https://upstream.test"
    }

    async fn fetch_listing(&self, name: &str) -> std::result::Result<UpstreamListing, UpstreamError> {
        self.listing_calls.fetch_add(1, Ordering::SeqCst);
        let delay = *self.delay.lock().expect("mock");
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        match self.mode() {
            Mode::Unavailable => return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() }),
            Mode::NotFound => return Err(UpstreamError::NotFound),
            Mode::Malformed => {
                return Err(UpstreamError::Malformed { message: "scripted unusable document".to_owned() });
            }
            Mode::TooLarge => return Err(UpstreamError::TooLarge { limit: 1024 }),
            // Truncation is scripted for archive bodies only; listings answer normally.
            Mode::Ok | Mode::Truncated => {}
        }
        let document = self.listings.lock().expect("mock").get(name).cloned().ok_or(UpstreamError::NotFound)?;
        UpstreamListing::parse(name, document)
    }

    async fn fetch_archive(&self, url: &str) -> std::result::Result<UpstreamArchive, UpstreamError> {
        self.archive_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode() {
            Mode::Unavailable => return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() }),
            Mode::NotFound => return Err(UpstreamError::NotFound),
            Mode::Malformed => {
                return Err(UpstreamError::Malformed { message: "scripted unusable document".to_owned() });
            }
            Mode::TooLarge => return Err(UpstreamError::TooLarge { limit: 1024 }),
            Mode::Ok | Mode::Truncated => {}
        }
        let bytes = self.archives.lock().expect("mock").get(url).cloned().ok_or(UpstreamError::NotFound)?;
        let len = bytes.len() as u64;
        if self.mode() == Mode::Truncated {
            // The header promises the whole archive; the body stops halfway and the connection
            // simply ends — no error, which is the case a hash check alone would misdiagnose.
            let half = bytes.slice(..bytes.len() / 2);
            return Ok(UpstreamArchive { content_length: Some(len), body: futures::stream::iter([Ok(half)]).boxed() });
        }
        // Chunked on purpose: the size cap has to trip mid-stream, not on a single blob.
        let chunks: Vec<Bytes> = bytes.chunks(1024).map(Bytes::copy_from_slice).collect();
        Ok(UpstreamArchive {
            content_length: Some(len),
            body: futures::stream::iter(chunks.into_iter().map(Ok)).boxed(),
        })
    }
}

// -------------------------------------------------------------------------------- fixtures

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

fn archive_url(name: &str, version: &str) -> String {
    format!("https://cdn.upstream.test/packages/{name}-{version}.tar.gz")
}

fn version_entry(name: &str, version: &str, sha256: &str) -> serde_json::Value {
    json!({
        "version": version,
        "archive_url": archive_url(name, version),
        "archive_sha256": sha256,
        "pubspec": { "name": name, "version": version, "description": "upstream fixture" },
    })
}

fn listing_doc(name: &str, versions: Vec<serde_json::Value>) -> serde_json::Value {
    json!({ "name": name, "latest": versions.last().cloned().unwrap_or(json!(null)), "versions": versions })
}

struct Harness {
    service: UpstreamService,
    repos: Repositories,
    blob: Arc<MemoryBlob>,
    client: Arc<MockUpstream>,
    events: Arc<RecordingEvents>,
}

impl Harness {
    async fn new() -> Self {
        Self::with_policy(UpstreamServicePolicy::default()).await
    }

    async fn with_policy(policy: UpstreamServicePolicy) -> Self {
        let cfg = pub_config::DatabaseConfig {
            kind: pub_config::DatabaseKind::Sqlite,
            url: None,
            path: ":memory:".to_owned(),
            ..Default::default()
        };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();

        let blob = Arc::new(MemoryBlob::default());
        let client = Arc::new(MockUpstream::default());
        let events = Arc::new(RecordingEvents::default());
        let service = UpstreamService::new(
            repos.clone(),
            Arc::clone(&blob) as Arc<dyn BlobStore>,
            Arc::clone(&client) as Arc<dyn UpstreamClient>,
            Arc::clone(&events) as Arc<dyn EventSink>,
            policy,
        );
        Self { service, repos, blob, client, events }
    }

    async fn audit_actions(&self) -> Vec<String> {
        self.repos
            .audit
            .list(&AuditFilter::default(), None, 50)
            .await
            .expect("audit list")
            .items
            .into_iter()
            .map(|event| event.action)
            .collect()
    }
}

// ------------------------------------------------------------------------- listing parsing

#[test]
fn a_listing_for_another_package_is_refused() {
    // An upstream that can answer `foo` with `bar`'s versions substitutes a dependency
    // wholesale, and the sha256 check would confirm bar's own bytes quite happily.
    let document = listing_doc("other_pkg", vec![version_entry("other_pkg", "1.0.0", &"a".repeat(64))]);
    let err = UpstreamListing::parse("acme_core", document).unwrap_err();
    assert!(matches!(err, UpstreamError::Malformed { .. }), "got {err:?}");
}

#[test]
fn s20_a_hostile_upstream_pubspec_is_refused_by_the_publish_validator() {
    // The residue of a YAML alias bomb after JSON transport is the expanded document; the same
    // depth cap that stops the bomb at publish stops the expansion here.
    let mut deep = json!("leaf");
    for _ in 0..40 {
        deep = json!({ "nest": deep });
    }
    let entry = json!({
        "version": "1.0.0",
        "archive_url": archive_url("acme_core", "1.0.0"),
        "archive_sha256": "a".repeat(64),
        "pubspec": { "name": "acme_core", "version": "1.0.0", "deep": deep },
    });
    let err = UpstreamListing::parse("acme_core", listing_doc("acme_core", vec![entry])).unwrap_err();
    assert!(matches!(err, UpstreamError::Malformed { .. }), "got {err:?}");
}

#[test]
fn version_entries_must_agree_with_their_own_pubspec() {
    let mismatched = json!({
        "version": "1.0.0",
        "archive_url": archive_url("acme_core", "1.0.0"),
        "archive_sha256": "a".repeat(64),
        // A pubspec naming a different package would let an upstream smuggle one package's
        // metadata under another's name.
        "pubspec": { "name": "other_pkg", "version": "1.0.0" },
    });
    assert!(UpstreamListing::parse("acme_core", listing_doc("acme_core", vec![mismatched])).is_err());

    let wrong_version = json!({
        "version": "1.0.0",
        "archive_url": archive_url("acme_core", "1.0.0"),
        "archive_sha256": "a".repeat(64),
        "pubspec": { "name": "acme_core", "version": "9.9.9" },
    });
    assert!(UpstreamListing::parse("acme_core", listing_doc("acme_core", vec![wrong_version])).is_err());
}

#[test]
fn a_version_without_a_usable_sha256_is_dropped() {
    // docs/protocol.md sharp edge 10 — and a hash we cannot check is a version we will not
    // cache. One bad entry is dropped; a listing of nothing but bad entries is refused.
    let bad = json!({
        "version": "1.0.0",
        "archive_url": archive_url("acme_core", "1.0.0"),
        "archive_sha256": "NOTAHASH",
        "pubspec": { "name": "acme_core", "version": "1.0.0" },
    });
    let good = version_entry("acme_core", "1.1.0", &"b".repeat(64));
    let listing = UpstreamListing::parse("acme_core", listing_doc("acme_core", vec![bad.clone(), good])).unwrap();
    assert_eq!(listing.versions.len(), 1);
    assert_eq!(listing.versions[0].version.to_string(), "1.1.0");

    assert!(UpstreamListing::parse("acme_core", listing_doc("acme_core", vec![bad])).is_err());
}

#[test]
fn upstream_flags_are_preserved_verbatim() {
    let mut document = listing_doc("acme_core", vec![version_entry("acme_core", "1.0.0", &"a".repeat(64))]);
    document["isDiscontinued"] = json!(true);
    document["replacedBy"] = json!("acme_core2");
    document["advisoriesUpdated"] = json!("2026-08-01T00:00:00Z");
    document["versions"][0]["retracted"] = json!(true);

    let listing = UpstreamListing::parse("acme_core", document).unwrap();
    assert!(listing.discontinued);
    assert_eq!(listing.replaced_by.as_deref(), Some("acme_core2"));
    assert_eq!(listing.advisories_updated.as_deref(), Some("2026-08-01T00:00:00Z"));
    assert!(listing.versions[0].retracted);
}

#[test]
fn listing_versions_come_out_in_semver_precedence_order() {
    let versions = ["1.0.0", "1.0.0-beta.11", "1.0.0-beta.2", "0.9.0"]
        .iter()
        .map(|v| version_entry("acme_core", v, &"a".repeat(64)))
        .collect();
    let listing = UpstreamListing::parse("acme_core", listing_doc("acme_core", versions)).unwrap();
    let order: Vec<String> = listing.versions.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(order, ["0.9.0", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0"]);
}

// --------------------------------------------------------------------------- ingest & cache

#[tokio::test]
async fn a_cold_miss_fetches_stores_and_serves_the_snapshot() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one"), ("1.1.0", b"archive-two")]);

    let listing = h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("proxied listing");
    assert_eq!(listing.versions.len(), 2);
    assert!(!listing.stale);
    assert_eq!(listing.versions[1].archive_sha256, hex_sha256(b"archive-two"));
    // The pubspec is upstream's, verbatim.
    assert_eq!(listing.versions[0].pubspec["description"], "upstream fixture");
    assert_eq!(h.client.listing_calls(), 1);

    // The snapshot is durable, not just returned.
    let stored = h.repos.upstream.get_package(Format::Pub, "acme_core").await.unwrap().expect("snapshot row");
    assert_eq!(stored.upstream, "https://upstream.test");
    assert_eq!(h.repos.upstream.list_versions(stored.id).await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_fresh_snapshot_is_served_without_touching_upstream() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);

    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("first");
    h.service.listing(Format::Pub, "acme_core", t0() + Duration::seconds(60)).await.unwrap().expect("second");
    assert_eq!(h.client.listing_calls(), 1, "a within-TTL read must not reach upstream");

    // Past the TTL it does.
    h.service.listing(Format::Pub, "acme_core", t0() + Duration::seconds(600)).await.unwrap().expect("third");
    assert_eq!(h.client.listing_calls(), 2);
}

#[tokio::test]
async fn an_unknown_upstream_package_is_absent_not_an_error() {
    let h = Harness::new().await;
    assert!(h.service.listing(Format::Pub, "nope_pkg", t0()).await.unwrap().is_none());
    // No snapshot is written for a package upstream does not have.
    assert!(h.repos.upstream.get_package(Format::Pub, "nope_pkg").await.unwrap().is_none());
}

#[tokio::test]
async fn an_archive_is_verified_stored_content_addressed_and_reused() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("listing");

    let version = SemVer::parse("1.0.0").unwrap();
    let first = h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().expect("archive");
    assert!(!first.from_cache);
    assert_eq!(first.archive_sha256, hex_sha256(b"archive-one"));
    // Stored under the same content-addressed key a local publish would use, byte-identical.
    let key = RegistryService::blob_key(Format::Pub, &first.archive_sha256);
    assert_eq!(h.blob.get(&key).as_deref(), Some(&b"archive-one"[..]));

    let second = h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().expect("cached archive");
    assert!(second.from_cache);
    assert_eq!(h.client.archive_calls(), 1, "a cached archive must not be re-fetched");
}

#[tokio::test]
async fn an_archive_request_populates_its_own_listing_when_none_is_cached() {
    // An archive URL is a plain URL: it outlives its listing in lockfiles, mirroring scripts,
    // and CI caches. Answering 404 on a fresh instance would make a valid URL depend on
    // request order.
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);

    let version = SemVer::parse("1.0.0").unwrap();
    let archive = h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().expect("archive");
    assert_eq!(archive.archive_sha256, hex_sha256(b"archive-one"));
    assert_eq!(h.client.listing_calls(), 1, "exactly one listing fetch, not one per attempt");
    // A version upstream does not have is still absent.
    let missing = SemVer::parse("9.9.9").unwrap();
    assert!(h.service.archive(Format::Pub, "acme_core", &missing, t0()).await.unwrap().is_none());
    assert_eq!(h.client.listing_calls(), 1, "and the fresh snapshot is not re-fetched to prove it");
}

#[tokio::test]
async fn s19_a_sha256_mismatch_is_quarantined_never_stored_and_never_served() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"honest-archive")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("listing");
    // Upstream now serves different bytes under the same advertised hash.
    h.client.corrupt_archive("acme_core", "1.0.0", b"tampered-archive");

    let version = SemVer::parse("1.0.0").unwrap();
    assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());
    assert_eq!(h.blob.len(), 0, "quarantined bytes must never reach the blob store");
    assert!(h.audit_actions().await.contains(&"upstream.quarantine".to_owned()));
    assert!(h.events.names().contains(&"upstream.quarantine"));

    // And the version stays uncached, so a later honest answer can still be ingested.
    let stored = h.repos.upstream.get_package(Format::Pub, "acme_core").await.unwrap().unwrap();
    let row = h.repos.upstream.get_version(stored.id, &version).await.unwrap().unwrap();
    assert!(!row.cached);
}

#[tokio::test]
async fn s19_byte_drift_keeps_the_cached_bytes_and_raises_an_alarm() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"original-archive")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("listing");
    let version = SemVer::parse("1.0.0").unwrap();
    let cached = h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().expect("archive");

    // Upstream now advertises a *different* hash for a version whose bytes we already hold.
    h.client.publish("acme_core", &[("1.0.0", b"replacement-archive")]);
    let later = t0() + Duration::hours(1);
    let listing = h.service.listing(Format::Pub, "acme_core", later).await.unwrap().expect("refreshed listing");

    assert_eq!(listing.versions[0].archive_sha256, cached.archive_sha256, "the cached hash must win");
    assert_eq!(listing.versions[0].archive_sha256, hex_sha256(b"original-archive"));
    assert!(h.audit_actions().await.contains(&"upstream.drift".to_owned()));
    assert!(h.events.names().contains(&"upstream.drift"));

    // Serving still hands back the original bytes, and no second fetch happens.
    let served = h.service.archive(Format::Pub, "acme_core", &version, later).await.unwrap().expect("cached");
    assert!(served.from_cache);
    let key = RegistryService::blob_key(Format::Pub, &served.archive_sha256);
    assert_eq!(h.blob.get(&key).as_deref(), Some(&b"original-archive"[..]));
    assert_eq!(h.client.archive_calls(), 1);
}

#[tokio::test]
async fn drift_on_an_uncached_version_is_an_ordinary_update() {
    // The rule protects *bytes we hold*. A version we never fetched has nothing pinned to it,
    // so a changed hash is upstream correcting itself, not drift.
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"first")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("listing");

    h.client.publish("acme_core", &[("1.0.0", b"second")]);
    let listing = h.service.listing(Format::Pub, "acme_core", t0() + Duration::hours(1)).await.unwrap().unwrap();
    assert_eq!(listing.versions[0].archive_sha256, hex_sha256(b"second"));
    assert!(!h.audit_actions().await.contains(&"upstream.drift".to_owned()));
}

#[tokio::test]
async fn a_snapshot_never_removes_a_version_upstream_stopped_listing() {
    // We may already hold the bytes, and a hash pinned in somebody's `pubspec.lock` has to
    // keep resolving (docs/protocol.md sharp edge 3).
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"one"), ("1.1.0", b"two")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("first snapshot");

    // Upstream re-lists the package with 1.0.0 gone.
    h.client.set_listing(
        "acme_core",
        listing_doc("acme_core", vec![version_entry("acme_core", "1.1.0", &hex_sha256(b"two"))]),
    );
    let listing = h.service.listing(Format::Pub, "acme_core", t0() + Duration::hours(1)).await.unwrap().unwrap();
    let versions: Vec<String> = listing.versions.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"], "a dropped upstream version keeps its cached row");
}

#[tokio::test]
async fn an_oversized_upstream_archive_is_refused() {
    let policy = UpstreamServicePolicy { max_archive_bytes: 4096, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    let big = vec![b'x'; 8192];
    h.client.publish("acme_core", &[("1.0.0", &big)]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("listing");

    let version = SemVer::parse("1.0.0").unwrap();
    assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());
    assert_eq!(h.blob.len(), 0, "an oversized archive must never reach storage");
}

// ------------------------------------------------------------------- outages & degradation

#[tokio::test]
async fn an_upstream_outage_serves_the_cached_listing_marked_stale() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("warm the cache");

    h.client.set_mode(Mode::Unavailable);
    let later = t0() + Duration::hours(1);
    let listing = h.service.listing(Format::Pub, "acme_core", later).await.unwrap().expect("stale listing");
    assert!(listing.stale, "a cache-served answer under an outage must be marked stale");
    assert_eq!(listing.versions.len(), 1);
}

#[tokio::test]
async fn an_upstream_outage_on_a_package_we_never_cached_is_absent() {
    // Never a 5xx: the pub client retries those seven times (docs/protocol.md sharp edge 2).
    let h = Harness::new().await;
    h.client.set_mode(Mode::Unavailable);
    assert!(h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().is_none());
}

#[tokio::test]
async fn an_upstream_404_does_not_drop_a_snapshot_we_hold() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("warm the cache");

    h.client.set_mode(Mode::NotFound);
    let listing =
        h.service.listing(Format::Pub, "acme_core", t0() + Duration::hours(1)).await.unwrap().expect("still served");
    assert!(listing.stale);
    assert_eq!(listing.versions.len(), 1);
}

#[tokio::test]
async fn the_circuit_breaker_stops_hammering_a_dead_upstream_and_recovers() {
    let policy = UpstreamServicePolicy {
        circuit_failure_threshold: 3,
        circuit_open: Duration::seconds(30),
        ..UpstreamServicePolicy::default()
    };
    let h = Harness::with_policy(policy).await;
    h.client.set_mode(Mode::Unavailable);

    for i in 0..3 {
        assert!(h.service.listing(Format::Pub, "pkg_a", t0() + Duration::seconds(i)).await.unwrap().is_none());
    }
    assert_eq!(h.client.listing_calls(), 3, "three failures trip the breaker");

    // While open, nothing goes out at all.
    assert!(h.service.listing(Format::Pub, "pkg_b", t0() + Duration::seconds(5)).await.unwrap().is_none());
    assert_eq!(h.client.listing_calls(), 3, "an open circuit must not reach upstream");

    // After the window one probe is allowed; upstream is healthy again, so the circuit closes.
    h.client.set_mode(Mode::Ok);
    h.client.publish("pkg_b", &[("1.0.0", b"archive")]);
    let recovered = t0() + Duration::seconds(45);
    assert!(h.service.listing(Format::Pub, "pkg_b", recovered).await.unwrap().is_some());
    assert_eq!(h.client.listing_calls(), 4);
}

#[tokio::test]
async fn a_failed_half_open_probe_reopens_the_circuit_immediately() {
    let mut breaker = Breaker::default();
    let threshold = 3;
    let open_for = Duration::seconds(30);
    for _ in 0..threshold - 1 {
        assert!(!breaker.fail(t0(), threshold));
    }
    assert!(breaker.fail(t0(), threshold), "the threshold-th failure opens the circuit");
    assert!(!breaker.allows(t0() + Duration::seconds(10), open_for, threshold));

    // Half-open: one probe allowed, its budget already spent…
    assert!(breaker.allows(t0() + Duration::seconds(31), open_for, threshold));
    // …so a single failure re-opens rather than letting `threshold` requests hang again.
    assert!(breaker.fail(t0() + Duration::seconds(31), threshold));
    assert!(!breaker.allows(t0() + Duration::seconds(35), open_for, threshold));
}

#[tokio::test]
async fn a_listing_we_cannot_use_does_not_close_the_proxy_for_other_packages() {
    // The breaker is instance-wide. A document upstream answered promptly and in full but that
    // our validator refuses is a fact about *that package*, exactly like a 404 — counting it
    // would let one bad package (re-fetched before every resolve, by every developer) degrade
    // every other package on the instance to stale-or-404 for the whole open window.
    let policy = UpstreamServicePolicy { circuit_failure_threshold: 2, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    h.client.publish("good_pkg", &[("1.0.0", b"archive-one")]);

    h.client.set_mode(Mode::Malformed);
    for i in 0..5 {
        assert!(h.service.listing(Format::Pub, "bad_pkg", t0() + Duration::seconds(i)).await.unwrap().is_none());
    }
    assert_eq!(h.client.listing_calls(), 5, "every attempt must still reach upstream");

    // The circuit is still closed, so an unrelated package resolves normally.
    h.client.set_mode(Mode::Ok);
    let listing = h.service.listing(Format::Pub, "good_pkg", t0() + Duration::seconds(6)).await.unwrap();
    assert!(listing.is_some(), "an unusable document for one package must not close the proxy");
    assert_eq!(h.client.listing_calls(), 6);
}

#[tokio::test]
async fn an_oversized_listing_is_treated_as_a_fact_about_the_package_too() {
    // Same rule, other permanent-but-per-package outcome: upstream answered, the answer is
    // simply larger than this instance accepts.
    let policy = UpstreamServicePolicy { circuit_failure_threshold: 2, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    h.client.set_mode(Mode::TooLarge);
    for i in 0..4 {
        let now = t0() + Duration::seconds(i);
        assert!(h.service.listing(Format::Pub, "huge_pkg", now).await.unwrap().is_none());
    }
    assert_eq!(h.client.listing_calls(), 4, "an open circuit would have stopped these");
    assert!(!h.service.circuit_open(t0() + Duration::seconds(5)));
}

#[tokio::test]
async fn a_dead_archive_host_opens_the_circuit_even_with_a_warm_listing_cache() {
    // The failure mode this closes: listings served from cache reach upstream not at all, so
    // with archives failing the breaker never saw a single failure and every download paid the
    // full retry budget and timeout.
    let policy = UpstreamServicePolicy { circuit_failure_threshold: 2, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    h.client.publish("acme_core", &[("1.0.0", b"one"), ("1.1.0", b"two"), ("1.2.0", b"three")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("warm the listing cache");
    assert_eq!(h.client.listing_calls(), 1);

    h.client.set_mode(Mode::Unavailable);
    for raw in ["1.0.0", "1.1.0"] {
        let version = SemVer::parse(raw).unwrap();
        assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());
    }
    assert!(h.service.circuit_open(t0()), "two unreachable downloads must open the circuit");

    // …and the open circuit is then what keeps the third request off the network.
    let third = SemVer::parse("1.2.0").unwrap();
    assert!(h.service.archive(Format::Pub, "acme_core", &third, t0()).await.unwrap().is_none());
    assert_eq!(h.client.archive_calls(), 2, "an open circuit must not reach upstream");
}

#[tokio::test]
async fn a_successful_download_clears_the_breakers_failure_count() {
    let policy = UpstreamServicePolicy { circuit_failure_threshold: 3, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    h.client.publish("acme_core", &[("1.0.0", b"one"), ("1.1.0", b"two")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("warm the listing cache");

    let first = SemVer::parse("1.0.0").unwrap();
    let second = SemVer::parse("1.1.0").unwrap();
    h.client.set_mode(Mode::Unavailable);
    assert!(h.service.archive(Format::Pub, "acme_core", &first, t0()).await.unwrap().is_none());
    assert!(h.service.archive(Format::Pub, "acme_core", &second, t0()).await.unwrap().is_none());

    h.client.set_mode(Mode::Ok);
    assert!(h.service.archive(Format::Pub, "acme_core", &first, t0()).await.unwrap().is_some());
    // Budget reset: two further failures must not be enough to open a threshold-3 circuit.
    h.client.set_mode(Mode::Unavailable);
    assert!(h.service.archive(Format::Pub, "acme_core", &second, t0()).await.unwrap().is_none());
    assert!(!h.service.circuit_open(t0()));
}

#[tokio::test]
async fn a_truncated_archive_body_poisons_nothing_and_does_not_cry_tampering() {
    // The review question this answers: can a slow-loris or a dropped connection get bad bytes
    // into the cache? No — and it must also not be *reported* as tampering, because the S-19
    // quarantine register is the evidence surface an operator reads when a package really is
    // being substituted, and a register full of dropped connections is a register nobody reads.
    let h = Harness::new().await;
    let bytes = b"a complete upstream archive body".to_vec();
    h.client.publish("acme_core", &[("1.0.0", &bytes)]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().expect("warm the listing");

    let version = SemVer::parse("1.0.0").unwrap();
    h.client.set_mode(Mode::Truncated);
    assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());
    assert_eq!(h.blob.len(), 0, "a truncated body must never reach storage");
    assert!(
        h.repos.upstream.list_quarantine(None, 10).await.unwrap().items.is_empty(),
        "a dropped connection is not tampering"
    );
    assert!(!h.audit_actions().await.contains(&"upstream.quarantine".to_owned()));
    assert!(!h.events.names().contains(&"upstream.quarantined"));

    // …and the version stays ingestible, so the next honest answer is cached normally.
    h.client.set_mode(Mode::Ok);
    let archive = h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().expect("second attempt");
    assert_eq!(archive.archive_sha256, hex_sha256(&bytes));
    assert_eq!(h.blob.get(&RegistryService::blob_key(Format::Pub, &archive.archive_sha256)).unwrap(), bytes);
}

#[test]
fn the_archive_buffer_is_not_sized_from_upstreams_claim() {
    // `Content-Length` is upstream's claim. Reserving it outright turns that claim into an
    // allocation we perform on request — `max_archive_bytes` of resident memory per in-flight
    // fetch for an upstream that announces a large archive and then sends nothing.
    let limit = 100 * 1024 * 1024;
    assert_eq!(initial_capacity(Some(limit), limit), MAX_ARCHIVE_PREALLOC_BYTES as usize);
    assert_eq!(initial_capacity(Some(u64::MAX), limit), MAX_ARCHIVE_PREALLOC_BYTES as usize);
    assert_eq!(initial_capacity(None, limit), 0);
    // An honest small archive is still reserved exactly.
    assert_eq!(initial_capacity(Some(4096), limit), 4096);
    // …and a cap below the clamp still wins, so a tightened policy is never over-reserved.
    assert_eq!(initial_capacity(Some(u64::MAX), 8192), 8192);
}

#[tokio::test]
async fn an_upstream_404_does_not_count_against_the_breaker() {
    // A missing package is a fact about the package, not about upstream's health; counting it
    // would let a handful of typos close the proxy for everybody.
    let policy = UpstreamServicePolicy { circuit_failure_threshold: 2, ..UpstreamServicePolicy::default() };
    let h = Harness::with_policy(policy).await;
    h.client.set_mode(Mode::NotFound);
    for i in 0..5 {
        assert!(h.service.listing(Format::Pub, "nope_pkg", t0() + Duration::seconds(i)).await.unwrap().is_none());
    }
    assert_eq!(h.client.listing_calls(), 5, "every miss must still reach upstream");
}

// ------------------------------------------------------------------------------ concurrency

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_collapses_concurrent_misses_onto_one_fetch() {
    let h = Arc::new(Harness::new().await);
    h.client.publish("acme_core", &[("1.0.0", b"archive-one")]);
    h.client.set_delay(std::time::Duration::from_millis(120));

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let h = Arc::clone(&h);
        set.spawn(async move { h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap().is_some() });
    }
    let results = set.join_all().await;
    assert!(results.iter().all(|served| *served), "every caller must be served");
    assert_eq!(h.client.listing_calls(), 1, "N concurrent misses of one package are one fetch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_does_not_serialize_different_packages() {
    let h = Arc::new(Harness::new().await);
    for name in ["pkg_one", "pkg_two", "pkg_three"] {
        h.client.publish(name, &[("1.0.0", b"archive")]);
    }
    let mut set = tokio::task::JoinSet::new();
    for name in ["pkg_one", "pkg_two", "pkg_three"] {
        let h = Arc::clone(&h);
        set.spawn(async move { h.service.listing(Format::Pub, name, t0()).await.unwrap().is_some() });
    }
    assert!(set.join_all().await.into_iter().all(|served| served));
    assert_eq!(h.client.listing_calls(), 3, "distinct packages must not queue behind each other");
}

#[tokio::test]
async fn single_flight_slots_are_released() {
    // An entry per key that never went away would be an unbounded map keyed by attacker-chosen
    // package names.
    let flights = SingleFlight::default();
    {
        let _guard = flights.enter("acme_core").await;
        assert_eq!(flights.slots.lock().unwrap().len(), 1);
    }
    assert!(flights.slots.lock().unwrap().is_empty(), "the slot must be dropped with its guard");
}

// ------------------------------------------------------------------- mirror-facing surface

#[tokio::test]
async fn refresh_bypasses_the_read_ttl_but_honours_its_own_freshness_floor() {
    // The mirror's entry point is the same pipeline with a different clock: the read TTL is
    // what a *client* is served from, the freshness floor is what the worker re-asks for.
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"one")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    assert_eq!(h.client.listing_calls(), 1);
    h.client.publish("acme_core", &[("1.0.0", b"one"), ("1.1.0", b"two")]);

    // Well inside the 300 s read TTL, a reader is still served the old snapshot…
    let served = h.service.listing(Format::Pub, "acme_core", t0() + Duration::seconds(30)).await.unwrap().unwrap();
    assert_eq!(served.versions.len(), 1);
    assert_eq!(h.client.listing_calls(), 1);

    // …while the worker, whose floor has passed, refreshes it.
    let outcome = h
        .service
        .refresh(Format::Pub, "acme_core", t0() + Duration::seconds(10), t0() + Duration::seconds(30))
        .await
        .unwrap();
    let RefreshOutcome::Updated(listing) = outcome else { panic!("expected an update, got {outcome:?}") };
    assert_eq!(listing.versions.len(), 2);
    assert_eq!(h.client.listing_calls(), 2);

    // A second pass inside the floor asks nobody.
    let outcome = h
        .service
        .refresh(Format::Pub, "acme_core", t0() + Duration::seconds(10), t0() + Duration::seconds(40))
        .await
        .unwrap();
    assert_eq!(outcome, RefreshOutcome::Fresh);
    assert_eq!(h.client.listing_calls(), 2);
}

#[tokio::test]
async fn refresh_reports_a_degraded_upstream_rather_than_claiming_a_sync() {
    // A stale answer is a perfectly good *serve* and a failed *sync*; conflating them would
    // make `last_success_at` — and therefore the mirror's lag — a lie.
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"one")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    h.client.set_mode(Mode::Unavailable);

    let outcome = h
        .service
        .refresh(Format::Pub, "acme_core", t0() + Duration::hours(1), t0() + Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(outcome, RefreshOutcome::Unavailable);
    // An unknown package is the same answer: the mirror counts it, nothing is stored.
    let outcome = h.service.refresh(Format::Pub, "nope_pkg", t0(), t0()).await.unwrap();
    assert_eq!(outcome, RefreshOutcome::Unavailable);
    // A name that could never be a pub package never reaches a URL or a database key.
    let outcome = h.service.refresh(Format::Pub, "../etc/passwd", t0(), t0()).await.unwrap();
    assert_eq!(outcome, RefreshOutcome::Unavailable);
    assert!(h.repos.upstream.get_package(Format::Pub, "nope_pkg").await.unwrap().is_none());
}

#[tokio::test]
async fn a_quarantine_is_recorded_for_the_admin_surface() {
    // S-19's refusal used to exist only as a log line and an audit row; an operator asking
    // "what is my proxy currently rejecting" needs a register.
    let h = Harness::new().await;
    let honest = b"honest bytes";
    h.client.publish("acme_core", &[("1.0.0", honest)]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    h.client.corrupt_archive("acme_core", "1.0.0", b"tampered");

    let version = SemVer::parse("1.0.0").unwrap();
    assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());

    let quarantined = h.repos.upstream.list_quarantine(None, 10).await.unwrap().items;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].name, "acme_core");
    assert_eq!(quarantined[0].version, "1.0.0");
    assert_eq!(quarantined[0].expected_sha256, hex_sha256(honest));
    assert_eq!(quarantined[0].actual_sha256, hex_sha256(b"tampered"));
    assert_eq!(quarantined[0].occurrences, 1);

    // A second attempt is the same incident, counted — not a second row to scroll past.
    assert!(h.service.archive(Format::Pub, "acme_core", &version, t0()).await.unwrap().is_none());
    assert_eq!(h.repos.upstream.list_quarantine(None, 10).await.unwrap().items[0].occurrences, 2);
    assert_eq!(h.repos.upstream.list_quarantine(None, 10).await.unwrap().items.len(), 1);
}

#[tokio::test]
async fn the_cache_inventory_reports_what_the_proxy_is_holding() {
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"one"), ("1.1.0", b"two")]);
    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    h.service.archive(Format::Pub, "acme_core", &SemVer::parse("1.0.0").unwrap(), t0()).await.unwrap();

    let page = h.service.cached_packages(Format::Pub, None, 50).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].name, "acme_core");
    assert_eq!(page.items[0].versions, 2);
    assert_eq!(page.items[0].cached_versions, 1, "metadata for two, bytes for one");
    assert_eq!(page.items[0].cached_bytes, b"one".len() as i64);
}

#[tokio::test]
async fn the_cache_hit_ratio_tracks_what_left_the_instance() {
    // The number an operator tunes `listing_ttl_secs` against (decision 23).
    let h = Harness::new().await;
    h.client.publish("acme_core", &[("1.0.0", b"one")]);
    assert_eq!(h.service.cache_hit_ratio(), 1.0, "no traffic is not a cache miss");

    h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    assert_eq!(h.service.cache_hit_ratio(), 0.0, "the cold miss is a miss");
    for _ in 0..3 {
        h.service.listing(Format::Pub, "acme_core", t0()).await.unwrap();
    }
    assert_eq!(h.service.cache_hit_ratio(), 0.75);
}

#[tokio::test]
async fn an_open_circuit_is_visible_without_spending_the_probe() {
    // The worker asks before feeding a chunk in; asking must not consume the one half-open
    // request a real caller should get.
    let h = Harness::with_policy(UpstreamServicePolicy {
        circuit_failure_threshold: 2,
        circuit_open: Duration::seconds(30),
        ..UpstreamServicePolicy::default()
    })
    .await;
    h.client.set_mode(Mode::Unavailable);
    assert!(!h.service.circuit_open(t0()));

    for _ in 0..2 {
        let _ = h.service.listing(Format::Pub, "acme_core", t0()).await;
    }
    assert!(h.service.circuit_open(t0()));
    // Peeking twice does not transition it into half-open.
    assert!(h.service.circuit_open(t0()));
    let calls = h.client.listing_calls();
    let _ = h.service.listing(Format::Pub, "acme_core", t0()).await;
    assert_eq!(h.client.listing_calls(), calls, "an open circuit answers from cache without a fetch");

    // Past the window the probe is still there for a real request.
    assert!(!h.service.circuit_open(t0() + Duration::seconds(45)));
    let _ = h.service.listing(Format::Pub, "acme_core", t0() + Duration::seconds(45)).await;
    assert_eq!(h.client.listing_calls(), calls + 1);
}
