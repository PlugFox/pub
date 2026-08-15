//! Upstream proxy ingest — the read-through cache of decision 07, first half.
//!
//! One pipeline serves two callers: the read-through path wired into the pub protocol routes
//! today, and the mirror-sync worker of decision 07's second half, which is "read-through
//! warmed by a job" rather than a second implementation. Everything that decides *what is
//! stored* lives in [`UpstreamService`]; [`UpstreamClient`] is the network seam, so no test
//! in this workspace ever opens a socket.
//!
//! ```text
//!  GET B/api/packages/{name}                 GET B/api/archives/{name}-{v}.tar.gz
//!            │                                              │
//!    resolve_in_base ⇒ Unclaimed                     cached? ──yes──► serve our bytes
//!            │  (the ONLY door to upstream — S-16)           │no
//!            ▼                                               ▼
//!   listing(): fresh snapshot? ──yes──► serve         archive(): single-flight
//!            │no                                              │
//!      single-flight ─► circuit open? ─yes─► stale       fetch ─► sha256 == advertised?
//!            │no                                              │            │
//!       fetch + validate (S-20 pubspec rules)             no ──┘            └── yes
//!            │                                        quarantine:              store
//!       save snapshot (flags verbatim, S-19)          never store,          content-addressed,
//!            │                                        never serve,          mark cached
//!            └─ failure ─► breaker++ ─► serve stale    audit + alarm
//!                             │ or 404 when nothing is cached (sharp edge 2: never 5xx)
//! ```
//!
//! The four rules that make this a *supply-chain* component rather than a cache:
//!
//! 1. **Hash before store** (S-19). Bytes are verified against the sha256 upstream advertised
//!    in its listing *before* they reach the blob store. A mismatch is quarantined: not
//!    stored, not served, audited, alarmed.
//! 2. **Cached bytes are final** (S-19 byte-drift). If upstream later advertises a different
//!    hash for a version we already hold, the cached bytes keep being served and the change is
//!    an alarm — never an overwrite. Somebody's `pubspec.lock` pins the old hash.
//! 3. **Upstream state is copied verbatim.** `retracted`, `isDiscontinued`, `replacedBy`,
//!    `advisoriesUpdated`, and the full pubspec are upstream's truth and are re-emitted
//!    unchanged. The single exception is `archive_url`, rewritten to our own base by the
//!    protocol layer (docs/protocol.md sharp edge 3) — and that rewrite happens *there*, so
//!    this module never has to know the request's base.
//! 4. **A degraded upstream is never a 5xx.** Unreachable upstream, open circuit, refused
//!    bytes: whatever we have cached is served with a staleness marker, and what we have never
//!    cached is a **404**. The pub client retries 5xx up to seven times (docs/protocol.md
//!    sharp edge 2), so a 5xx here would turn one upstream outage into a retry storm.
//! 5. **Only *reachability* failures reach the circuit breaker.** The breaker is instance-wide,
//!    so anything that opens it degrades every package. A 404, a listing our validator refuses,
//!    and a listing past the size cap are all facts about **one package** — upstream answered,
//!    promptly and in full — and are counted as fetch outcomes but never as failures. Timeouts,
//!    connection errors, and the transient status family are facts about **upstream**, and
//!    those are what the breaker exists for, on the archive path as much as the listing one.

pub mod http;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::package::{
    NewQuarantineEntry, NewUpstreamVersion, UpstreamCacheEntry, UpstreamPackage, UpstreamSnapshot, UpstreamVersion,
};
use pub_core::traits::{BlobStore, Repositories};
use pub_core::{Error, Format, Page, Result, SemVer};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use crate::publish::{RegistryService, hex_sha256};
use crate::pubspec::{Pubspec, validate_package_name};
use crate::shadow::{self, ShadowObservation, ShadowOutcome};

// ------------------------------------------------------------------------------ client seam

/// Why an upstream request did not produce a usable answer.
///
/// The split that matters is [`UpstreamError::NotFound`] versus everything else: a 404 from
/// upstream is a *fact about the package* and must not count against the circuit breaker,
/// while every other failure is a fact about the upstream's health and does.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UpstreamError {
    /// Upstream says the package or version does not exist.
    #[error("upstream has no such package")]
    NotFound,
    /// Upstream is unreachable, timed out, or answered 5xx — transient by assumption.
    #[error("upstream is unavailable: {message}")]
    Unavailable {
        /// Diagnostic detail; never rendered to a client.
        message: String,
    },
    /// Upstream answered, but not with something we can parse or accept.
    #[error("upstream answered with an unusable document: {message}")]
    Malformed {
        /// Diagnostic detail; never rendered to a client.
        message: String,
    },
    /// The upstream payload is larger than this instance accepts.
    #[error("upstream payload exceeds the {limit}-byte limit")]
    TooLarge {
        /// The configured cap.
        limit: u64,
    },
    /// The URL upstream asked us to fetch is not one we will fetch (SSRF guard).
    #[error("refusing to fetch upstream url: {reason}")]
    RefusedUrl {
        /// Why the URL was refused.
        reason: String,
    },
}

/// A streamed upstream archive body.
pub type UpstreamBody = BoxStream<'static, std::result::Result<Bytes, UpstreamError>>;

/// The response of [`UpstreamClient::fetch_archive`].
///
/// Deliberately a stream rather than a `Vec<u8>`: the size cap has to be enforced *while*
/// bytes arrive. Buffering first and checking afterwards means an upstream that lies about
/// `Content-Length` decides how much memory we allocate.
pub struct UpstreamArchive {
    /// `Content-Length`, when upstream sent one. A claim, not a guarantee — checked early as
    /// a cheap reject, then re-checked against the bytes actually received.
    pub content_length: Option<u64>,
    /// The body.
    pub body: UpstreamBody,
}

impl std::fmt::Debug for UpstreamArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamArchive").field("content_length", &self.content_length).finish_non_exhaustive()
    }
}

/// The network seam of the proxy (decision 07).
///
/// A trait rather than a concrete HTTP client for one reason that is not testing convenience:
/// every behaviour worth asserting here — integrity refusal, byte-drift, stale serving,
/// circuit breaking, single-flight — is defined by how upstream *misbehaves*, and a suite that
/// needs a misbehaving pub.dev to run is a suite that does not run.
#[async_trait::async_trait]
pub trait UpstreamClient: Send + Sync {
    /// The upstream base URL this client talks to, recorded on every cached row.
    fn base_url(&self) -> &str;

    /// Fetches and parses a package's version listing.
    async fn fetch_listing(&self, name: &str) -> std::result::Result<UpstreamListing, UpstreamError>;

    /// Opens a streamed download of an archive URL taken from a listing.
    async fn fetch_archive(&self, url: &str) -> std::result::Result<UpstreamArchive, UpstreamError>;

    /// One page of the upstream package-name index — the mirror's full-sweep input
    /// (decision 07: "full enumeration via `/api/package-names` for the initial sweep").
    ///
    /// `cursor` is whatever the previous page reported as its continuation, opaque to the
    /// caller. The default answers [`UpstreamError::NotFound`]: enumeration is a pub.dev
    /// *convention*, not part of the spec ([docs/protocol.md](../../../docs/protocol.md)
    /// "Client-side facts"), so an upstream that does not expose one is not broken — it just
    /// cannot be full-swept, and the mirror reports that instead of silently mirroring nothing.
    async fn fetch_package_names(&self, cursor: Option<&str>) -> std::result::Result<UpstreamNamePage, UpstreamError> {
        let _ = cursor;
        Err(UpstreamError::NotFound)
    }
}

// ----------------------------------------------------------------------------- wire shapes

/// One version as an upstream listing advertises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamVersionEntry {
    /// Version string, exactly as upstream wrote it.
    pub version: SemVer,
    /// Upstream's own archive URL — used to fetch, **never** re-emitted to a client
    /// (docs/protocol.md sharp edge 3).
    pub archive_url: String,
    /// Upstream-advertised sha256 of the archive (64 lowercase hex).
    pub archive_sha256: String,
    /// Upstream `retracted` flag, verbatim.
    pub retracted: bool,
    /// Upstream publication time, when reported.
    pub published_at: Option<DateTime<Utc>>,
    /// The version's full pubspec document, validated by the publish rules (S-20).
    pub pubspec: serde_json::Value,
}

/// One page of the upstream package-name index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamNamePage {
    /// Package names, in whatever order upstream reports them.
    pub names: Vec<String>,
    /// Continuation token for the next page; `None` = this was the last one.
    pub next: Option<String>,
}

/// A parsed upstream version listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamListing {
    /// Package name upstream.
    pub name: String,
    /// Upstream `isDiscontinued`, verbatim.
    pub discontinued: bool,
    /// Upstream `replacedBy`, verbatim.
    pub replaced_by: Option<String>,
    /// Upstream `advisoriesUpdated`, verbatim.
    pub advisories_updated: Option<String>,
    /// Every advertised version, ascending by semver precedence.
    pub versions: Vec<UpstreamVersionEntry>,
    /// The raw document, kept as the snapshot we can re-derive archive URLs from.
    pub raw: serde_json::Value,
}

impl UpstreamListing {
    /// Parses and validates a listing document.
    ///
    /// `name` is what *we* asked for. A listing that describes some other package is refused
    /// rather than stored under the requested name: an upstream (or an on-path attacker with
    /// a plaintext upstream) that can answer `foo` with `bar`'s versions can substitute a
    /// dependency wholesale, and the sha256 check would happily confirm bar's own bytes.
    ///
    /// Every version's pubspec goes through [`Pubspec::from_json`] — the same rules a local
    /// publish clears (S-20) — and must agree with the listing on both name and version.
    /// Entries that fail are dropped rather than failing the whole listing **only** when the
    /// listing still has usable versions left; a listing with nothing valid is `Malformed`.
    pub fn parse(name: &str, raw: serde_json::Value) -> std::result::Result<Self, UpstreamError> {
        let malformed = |message: String| UpstreamError::Malformed { message };
        validate_package_name(name).map_err(|err| malformed(err.to_string()))?;

        let object = raw.as_object().ok_or_else(|| malformed("listing is not a JSON object".to_owned()))?;
        let listed_name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed("listing has no name".to_owned()))?;
        if listed_name != name {
            return Err(malformed(format!("listing describes {listed_name:?}, not the requested package")));
        }

        let raw_versions = object
            .get("versions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| malformed("listing has no versions array".to_owned()))?;

        let mut versions = Vec::with_capacity(raw_versions.len());
        let mut rejected = 0usize;
        for entry in raw_versions {
            match parse_version_entry(name, entry) {
                Ok(parsed) => versions.push(parsed),
                Err(reason) => {
                    rejected += 1;
                    // Named at debug level, counted at warn level below: one bad version in a
                    // 300-version listing must not spam a log line per request.
                    tracing::debug!(package = name, %reason, "dropped an unusable upstream version entry");
                }
            }
        }
        if rejected > 0 {
            tracing::warn!(
                package = name,
                rejected,
                kept = versions.len(),
                "upstream listing carried unusable versions"
            );
            metrics::counter!("upstream_versions_rejected_total").increment(rejected as u64);
        }
        if versions.is_empty() {
            return Err(malformed("listing has no usable versions".to_owned()));
        }
        versions.sort_by(|a, b| a.version.cmp(&b.version));

        Ok(Self {
            name: name.to_owned(),
            discontinued: object.get("isDiscontinued").and_then(serde_json::Value::as_bool).unwrap_or(false),
            replaced_by: object.get("replacedBy").and_then(serde_json::Value::as_str).map(str::to_owned),
            advisories_updated: object.get("advisoriesUpdated").and_then(serde_json::Value::as_str).map(str::to_owned),
            versions,
            raw,
        })
    }
}

/// Parses one `versions[]` entry, applying the publish-path pubspec rules.
fn parse_version_entry(name: &str, entry: &serde_json::Value) -> std::result::Result<UpstreamVersionEntry, String> {
    let object = entry.as_object().ok_or("version entry is not an object")?;
    let raw_version =
        object.get("version").and_then(serde_json::Value::as_str).ok_or("version entry has no version")?;
    let version = SemVer::parse(raw_version).map_err(|err| format!("unparsable version: {err}"))?;

    let archive_url =
        object.get("archive_url").and_then(serde_json::Value::as_str).ok_or("version entry has no archive_url")?;
    let archive_sha256 = object
        .get("archive_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or("version entry has no archive_sha256")?;
    if !is_sha256_hex(archive_sha256) {
        // docs/protocol.md sharp edge 10: exactly 64 lowercase hex. A listing we cannot
        // integrity-check is a listing we will not cache.
        return Err("archive_sha256 is not 64 lowercase hex characters".to_owned());
    }

    let pubspec = object.get("pubspec").cloned().ok_or("version entry has no pubspec")?;
    let parsed = Pubspec::from_json(pubspec).map_err(|err| err.to_string())?;
    if parsed.name != name {
        return Err(format!("pubspec declares {:?}, not the requested package", parsed.name));
    }
    if parsed.version != version {
        return Err(format!("pubspec declares version {}, entry says {version}", parsed.version));
    }

    Ok(UpstreamVersionEntry {
        version,
        archive_url: archive_url.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        retracted: object.get("retracted").and_then(serde_json::Value::as_bool).unwrap_or(false),
        published_at: object
            .get("published")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .map(|dt| dt.with_timezone(&Utc)),
        pubspec: parsed.json,
    })
}

/// Whether `raw` is exactly 64 lowercase hex characters.
pub fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Ceiling on the buffer reserved up-front for an upstream archive.
///
/// Deliberately far below `max_archive_bytes`: see [`initial_capacity`].
const MAX_ARCHIVE_PREALLOC_BYTES: u64 = 1024 * 1024;

/// How much to reserve before the first byte of an archive arrives.
///
/// `Content-Length` is upstream's *claim*, and reserving it outright turns that claim into an
/// allocation this process performs on request: an upstream (or an on-path attacker) that
/// announces `max_archive_bytes` and then sends nothing costs us a full archive cap of resident
/// memory per in-flight fetch, times `max_concurrent_fetches`, for as long as the archive
/// timeout allows. The hint is therefore clamped; `Vec`'s amortized growth pays for genuinely
/// large archives, which is a handful of reallocations on a transfer that already crossed a
/// network.
fn initial_capacity(content_length: Option<u64>, limit: u64) -> usize {
    content_length.unwrap_or(0).min(limit).min(MAX_ARCHIVE_PREALLOC_BYTES) as usize
}

// -------------------------------------------------------------------------------- policy

/// Instance policy for the proxy (built from the `[upstream]` config section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamServicePolicy {
    /// How long a cached listing is served without re-asking upstream.
    pub listing_ttl: Duration,
    /// Largest archive accepted from upstream, in bytes.
    pub max_archive_bytes: u64,
    /// Consecutive failures that trip the circuit breaker.
    pub circuit_failure_threshold: u32,
    /// How long the breaker stays open before it lets one probe through.
    pub circuit_open: Duration,
    /// Maximum simultaneous upstream requests from this instance.
    pub max_concurrent_fetches: usize,
}

impl Default for UpstreamServicePolicy {
    fn default() -> Self {
        Self {
            listing_ttl: Duration::seconds(300),
            max_archive_bytes: 100 * 1024 * 1024,
            circuit_failure_threshold: 5,
            circuit_open: Duration::seconds(30),
            max_concurrent_fetches: 8,
        }
    }
}

// -------------------------------------------------------------------------- served shapes

/// A version of a proxied package, ready for re-emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedVersion {
    /// The version.
    pub version: SemVer,
    /// Upstream's `retracted` flag, verbatim.
    pub retracted: bool,
    /// Upstream's `archive_sha256`, verbatim — what the client pins.
    pub archive_sha256: String,
    /// The full pubspec document, verbatim.
    pub pubspec: serde_json::Value,
}

/// A proxied listing, as the protocol layer re-emits it (with `archive_url` rewritten there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedListing {
    /// Package name.
    pub name: String,
    /// Upstream `isDiscontinued`.
    pub discontinued: bool,
    /// Upstream `replacedBy`.
    pub replaced_by: Option<String>,
    /// Upstream `advisoriesUpdated`.
    pub advisories_updated: Option<String>,
    /// Every known version, ascending by semver precedence.
    pub versions: Vec<ProxiedVersion>,
    /// Whether this answer came from cache because upstream could not be consulted (outage or
    /// open circuit). Surfaced in tracing and metrics, never on the wire.
    pub stale: bool,
}

/// What [`UpstreamService::archive`] resolved a request to: the content hash whose bytes are
/// now in our blob store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedArchive {
    /// Content hash — the blob key is derived from it, so serving is content-addressed.
    pub archive_sha256: String,
    /// Size in bytes, when known.
    pub archive_size: Option<i64>,
    /// Whether the bytes were already cached (no upstream request was made).
    pub from_cache: bool,
}

// --------------------------------------------------------------------------- the service

/// What [`UpstreamService::refresh`] did — the mirror worker's per-package result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The cached snapshot was already newer than the caller's freshness floor; upstream was
    /// not asked. This is what makes a re-run of an interrupted sweep cheap instead of a
    /// second full crawl.
    Fresh,
    /// A new snapshot was fetched and stored.
    Updated(Box<ProxiedListing>),
    /// Upstream could not be consulted (outage, open circuit) or does not have the package.
    /// Never an error: a mirror pass over 60 000 names must not abort on one of them.
    Unavailable,
}

/// The proxy ingest pipeline (decision 07).
pub struct UpstreamService {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    client: Arc<dyn UpstreamClient>,
    events: Arc<dyn EventSink>,
    policy: UpstreamServicePolicy,
    breaker: StdMutex<Breaker>,
    flights: SingleFlight,
    concurrency: Arc<Semaphore>,
    /// Cache hits and misses since startup, feeding the `cache_hit_ratio` gauge (decision 23).
    /// In-process on purpose: it describes *this* instance's traffic, which is the thing an
    /// operator tunes `listing_ttl_secs` against.
    hits: AtomicU64,
    misses: AtomicU64,
}

impl std::fmt::Debug for UpstreamService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamService")
            .field("upstream", &self.client.base_url())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl UpstreamService {
    /// Builds the service over the configured backends.
    pub fn new(
        repos: Repositories,
        blob: Arc<dyn BlobStore>,
        client: Arc<dyn UpstreamClient>,
        events: Arc<dyn EventSink>,
        policy: UpstreamServicePolicy,
    ) -> Self {
        let permits = policy.max_concurrent_fetches.max(1);
        Self {
            repos,
            blob,
            client,
            events,
            policy,
            breaker: StdMutex::new(Breaker::default()),
            flights: SingleFlight::default(),
            concurrency: Arc::new(Semaphore::new(permits)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// The upstream this service proxies.
    pub fn upstream(&self) -> &str {
        self.client.base_url()
    }

    /// The listing for an **unclaimed** name: cached when fresh, refreshed when stale, served
    /// stale when upstream cannot be reached, `None` when we neither have it nor can get it.
    ///
    /// `None` is the whole error surface on purpose. Every failure mode here — upstream down,
    /// circuit open, listing malformed, package genuinely absent — has to become the same 404
    /// as an unknown local name (docs/protocol.md sharp edge 2, S-04): a 5xx would be retried
    /// seven times by the client, and a *distinguishable* failure would tell a prober whether
    /// pub.dev has a package this instance has never heard of.
    pub async fn listing(&self, format: Format, name: &str, now: DateTime<Utc>) -> Result<Option<ProxiedListing>> {
        if let Some(fresh) = self.cached_listing(format, name, now, true).await? {
            self.record_fetch("listing", "hit");
            return Ok(Some(fresh));
        }

        // Single-flight: N concurrent misses of one package produce one upstream request.
        let _flight = self.flights.enter(&format!("listing:{format}:{name}")).await;
        // Re-check under the guard — whoever held it before us may have just refreshed.
        if let Some(fresh) = self.cached_listing(format, name, now, true).await? {
            self.record_fetch("listing", "collapsed");
            return Ok(Some(fresh));
        }

        self.fetch_and_ingest(format, name, now).await
    }

    /// Refreshes a snapshot on the mirror worker's behalf, bypassing the read TTL
    /// (decision 07 mirror mode: "read-through warmed by a worker", not a second pipeline).
    ///
    /// `stale_before` is the caller's freshness floor: a snapshot fetched at or after it is
    /// left alone and reported [`RefreshOutcome::Fresh`]. That is what makes a sweep idempotent
    /// — a restart re-walking names it already covered pays one indexed read each instead of a
    /// second crawl — and it is also the only throttle the worker needs against re-fetching a
    /// package the read path just fetched.
    ///
    /// Everything else is the *same* pipeline the read path uses: same validator, same
    /// integrity rules, same breaker, same single-flight, same snapshot writer.
    pub async fn refresh(
        &self,
        format: Format,
        name: &str,
        stale_before: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome> {
        if validate_package_name(name).is_err() {
            // Upstream's own name index is not trusted input: a name that could never be a pub
            // package must not reach a URL or a database key.
            return Ok(RefreshOutcome::Unavailable);
        }
        if self.is_fresh(format, name, stale_before).await? {
            return Ok(RefreshOutcome::Fresh);
        }
        let _flight = self.flights.enter(&format!("listing:{format}:{name}")).await;
        // Re-check under the guard: a read-through miss may have refreshed it while we queued.
        if self.is_fresh(format, name, stale_before).await? {
            return Ok(RefreshOutcome::Fresh);
        }
        match self.fetch_and_ingest(format, name, now).await? {
            Some(listing) if !listing.stale => Ok(RefreshOutcome::Updated(Box::new(listing))),
            // A stale answer means upstream could not be consulted; the mirror counts that as
            // "not synced", not as a successful pass over the package.
            _ => Ok(RefreshOutcome::Unavailable),
        }
    }

    /// The shared "ask upstream and store what comes back" half of [`UpstreamService::listing`]
    /// and [`UpstreamService::refresh`] — breaker, permit, fetch, ingest, stale fallback.
    async fn fetch_and_ingest(&self, format: Format, name: &str, now: DateTime<Utc>) -> Result<Option<ProxiedListing>> {
        if !self.breaker_allows(now) {
            self.record_fetch("listing", "circuit_open");
            return self.stale_listing(format, name, now, "circuit open").await;
        }

        let _permit = self.acquire_permit().await?;
        match self.client.fetch_listing(name).await {
            Ok(listing) => {
                self.record_success();
                let stored = self.ingest_listing(format, listing, now).await?;
                self.record_fetch("listing", "fetched");
                Ok(Some(stored))
            }
            // Upstream says the package does not exist. That is not an upstream fault, so the
            // breaker stays closed — but it is also not a reason to drop a snapshot we hold:
            // pub.dev does not unpublish, so a 404 for a package we have cached is far more
            // likely a transient upstream defect than a real disappearance.
            Err(UpstreamError::NotFound) => {
                self.record_success();
                self.record_fetch("listing", "not_found");
                self.stale_listing(format, name, now, "upstream 404").await
            }
            // Upstream answered promptly and completely; we just cannot use the answer for
            // *this* package — a listing our validator rejects, or one past the size cap. Like
            // a 404, that is a fact about the package, not about upstream's health, so it must
            // not spend the breaker's budget: five such packages would otherwise close the
            // proxy for every *other* package on the instance, and the pub client re-fetches a
            // listing before every resolve, so one CI job on one bad package is enough.
            Err(err @ (UpstreamError::Malformed { .. } | UpstreamError::TooLarge { .. })) => {
                tracing::warn!(
                    package = name,
                    upstream = self.client.base_url(),
                    error = %err,
                    "upstream answered with a document we cannot use; not counting it against the breaker"
                );
                self.record_fetch("listing", "unusable");
                self.stale_listing(format, name, now, &err.to_string()).await
            }
            Err(err) => {
                self.record_failure(now, &err);
                self.record_fetch("listing", "error");
                self.stale_listing(format, name, now, &err.to_string()).await
            }
        }
    }

    /// The archive of a proxied version: from cache when we hold it, fetched-verified-stored
    /// otherwise. `None` when the version is unknown or its bytes cannot be obtained.
    ///
    /// Nothing here can return a 5xx-shaped error to a client for an upstream problem, for the
    /// same reason [`UpstreamService::listing`] cannot.
    pub async fn archive(
        &self,
        format: Format,
        name: &str,
        version: &SemVer,
        now: DateTime<Utc>,
    ) -> Result<Option<ProxiedArchive>> {
        let mut known = self.cached_version(format, name, version).await?;
        if known.is_none() {
            // No snapshot covers this version yet. The pub client always re-fetches the listing
            // before a download, but an archive URL is a plain URL: it outlives its listing in
            // lockfiles, mirroring scripts, and CI caches, and answering those 404 on a fresh
            // instance would make a perfectly valid URL depend on request order. One listing
            // fetch (single-flighted, breaker-gated, and a no-op when the snapshot is fresh)
            // makes the archive route self-sufficient.
            self.listing(format, name, now).await?;
            known = self.cached_version(format, name, version).await?;
        }
        let Some(cached) = known else {
            return Ok(None);
        };
        if cached.cached {
            self.record_fetch("archive", "hit");
            return Ok(Some(ProxiedArchive {
                archive_sha256: cached.archive_sha256,
                archive_size: cached.archive_size,
                from_cache: true,
            }));
        }

        let _flight = self.flights.enter(&format!("archive:{format}:{name}:{version}")).await;
        // Re-check under the guard: a concurrent miss may already have stored the bytes.
        let Some(cached) = self.cached_version(format, name, version).await? else {
            return Ok(None);
        };
        if cached.cached {
            self.record_fetch("archive", "collapsed");
            return Ok(Some(ProxiedArchive {
                archive_sha256: cached.archive_sha256,
                archive_size: cached.archive_size,
                from_cache: true,
            }));
        }

        if !self.breaker_allows(now) {
            // A version we have never cached is a 404 while the circuit is open — the
            // alternative is a 5xx the client would hammer six more times.
            tracing::warn!(package = name, %version, "upstream circuit open and archive not cached");
            self.record_fetch("archive", "circuit_open");
            return Ok(None);
        }

        let Some(url) = self.archive_url(format, name, version).await? else {
            tracing::warn!(package = name, %version, "cached upstream listing carries no archive url");
            return Ok(None);
        };

        let _permit = self.acquire_permit().await?;
        // Archive downloads feed the breaker on the same rule the listing path uses: only a
        // *reachability* failure counts. Without this the breaker was blind to exactly the
        // requests that hold a permit longest — with a warm listing cache and a dead archive
        // host, nothing else reaches upstream at all, so every download would pay the full
        // retry budget and timeout with no circuit ever opening.
        let bytes = match self.download(&url).await {
            Ok(bytes) => {
                self.record_success();
                bytes
            }
            Err(err) => {
                if matches!(err, UpstreamError::Unavailable { .. }) {
                    self.record_failure(now, &err);
                }
                self.record_fetch("archive", "error");
                tracing::warn!(package = name, %version, error = %err, "upstream archive fetch failed");
                return Ok(None);
            }
        };

        let actual = tokio::task::spawn_blocking(move || (hex_sha256(&bytes), bytes))
            .await
            .map_err(|err| Error::Internal { message: format!("upstream hashing task failed: {err}") })?;
        let (actual_sha256, bytes) = actual;
        if actual_sha256 != cached.archive_sha256 {
            self.quarantine(format, name, version, &cached.archive_sha256, &actual_sha256, now).await;
            self.record_fetch("archive", "quarantined");
            return Ok(None);
        }

        let size = bytes.len() as i64;
        // Content-addressed exactly like a local publish, and byte-identical: the archive is
        // never re-tarred or re-gzipped, because the hash in the listing — the one a
        // `pubspec.lock` pins — is the hash of these exact bytes.
        self.blob.put(&RegistryService::blob_key(format, &actual_sha256), bytes).await?;
        self.repos.upstream.mark_cached(cached.id, &actual_sha256, size, now).await?;

        self.record_fetch("archive", "fetched");
        tracing::info!(package = name, %version, sha256 = %actual_sha256, size, "cached an upstream archive");
        Ok(Some(ProxiedArchive { archive_sha256: actual_sha256, archive_size: Some(size), from_cache: false }))
    }

    // -------------------------------------------------------------------- mirror & admin

    /// Records a sighting of `name` upstream, alarming when the name is claimed here (S-17).
    ///
    /// The mirror worker's entry point into [`crate::shadow`]: it is the only component that
    /// ever *looks* at upstream for a claimed name, because the read path structurally cannot
    /// (S-16). Serving is unaffected — local wins before and after the alarm.
    pub async fn observe_shadowing(
        &self,
        format: Format,
        name: &str,
        upstream_version: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Option<ShadowOutcome>> {
        shadow::observe(
            &self.repos,
            self.events.as_ref(),
            ShadowObservation { format, name, upstream: self.client.base_url(), upstream_version },
            now,
        )
        .await
    }

    /// One page of the upstream package-name index (the mirror's full-sweep input).
    pub async fn package_names(&self, cursor: Option<&str>) -> std::result::Result<UpstreamNamePage, UpstreamError> {
        let _permit = self
            .acquire_permit()
            .await
            .map_err(|err| UpstreamError::Unavailable { message: format!("concurrency limiter closed: {err}") })?;
        self.client.fetch_package_names(cursor).await
    }

    /// Cached snapshots older than `before`, oldest first — the mirror's steady-state queue.
    pub async fn stale_packages(
        &self,
        format: Format,
        before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<UpstreamPackage>> {
        self.repos.upstream.list_stale(format, before, limit).await
    }

    /// The admin cache inventory: cached upstream packages with their sizes (decision 07).
    pub async fn cached_packages(
        &self,
        format: Format,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<UpstreamCacheEntry>> {
        self.repos.upstream.list_cached(format, cursor, limit).await
    }

    // Reading either register is deliberately **not** here either (decision 33), for the same
    // reason acknowledging is not: they are instance state that outlives `[upstream].enabled`,
    // and `AppState::upstream` is `None` on an instance whose operator turned the proxy off —
    // very possibly *because* of what the register holds. Both listings live on `AdminService`.

    // Acknowledging a shadowing alarm is deliberately **not** here (decision 33). It is an
    // operator action over instance state, not a proxy operation: it must stay reachable on an
    // instance whose `[upstream]` is disabled — the alarms outlive the setting — and it must be
    // audited with the acting administrator, which this module's `audit()` helper cannot do
    // (it files `AuditActor::System` with `AuditResult::Failure`, right for an integrity event
    // the proxy observed and wrong for a person pressing a button). It lives on `AdminService`,
    // beside the listings, and reads the same repository this module does.

    /// Whether the circuit is currently open, without transitioning it.
    ///
    /// The mirror asks before starting a chunk: a worker that keeps feeding a dead upstream
    /// burns the half-open probe every tick and turns the breaker into a slow retry loop.
    pub fn circuit_open(&self, now: DateTime<Utc>) -> bool {
        self.breaker.lock().expect("upstream breaker mutex poisoned").is_open(now, self.policy.circuit_open)
    }

    /// Cache hit ratio since startup, in `0.0..=1.0`; `1.0` before any traffic.
    pub fn cache_hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        match hits + misses {
            0 => 1.0,
            total => hits as f64 / total as f64,
        }
    }

    // ------------------------------------------------------------------ ingest internals

    /// Stores a fetched listing, preserving cached hashes and alarming on byte-drift (S-19).
    async fn ingest_listing(
        &self,
        format: Format,
        listing: UpstreamListing,
        now: DateTime<Utc>,
    ) -> Result<ProxiedListing> {
        let known = self.known_versions(format, &listing.name).await?;

        let mut versions = Vec::with_capacity(listing.versions.len());
        for entry in &listing.versions {
            // Byte-drift (S-19): upstream now advertises a different hash for bytes we
            // already hold. The cached hash wins — a client has pinned it — and the change is
            // an alarm, not an update.
            let sha256 = match known.get(&entry.version) {
                Some(existing) if existing.cached && existing.archive_sha256 != entry.archive_sha256 => {
                    self.report_drift(
                        format,
                        &listing.name,
                        &entry.version,
                        &existing.archive_sha256,
                        &entry.archive_sha256,
                        now,
                    )
                    .await;
                    existing.archive_sha256.clone()
                }
                _ => entry.archive_sha256.clone(),
            };
            versions.push(NewUpstreamVersion {
                version: entry.version.clone(),
                pubspec: entry.pubspec.clone(),
                archive_sha256: sha256,
                archive_size: None,
                retracted: entry.retracted,
                published_at: entry.published_at,
            });
        }

        self.repos
            .upstream
            .save_snapshot(
                UpstreamSnapshot {
                    format,
                    name: listing.name.clone(),
                    upstream: self.client.base_url().to_owned(),
                    discontinued: listing.discontinued,
                    replaced_by: listing.replaced_by.clone(),
                    advisories_updated: listing.advisories_updated.clone(),
                    listing: Some(listing.raw.clone()),
                    versions,
                },
                now,
            )
            .await?;

        // Read the stored snapshot back rather than projecting the fetched one: what we serve
        // must be what we persisted, drift-preserved hashes and all.
        self.cached_listing(format, &listing.name, now, false).await?.ok_or_else(|| Error::Internal {
            message: format!("upstream snapshot for {} vanished after saving", listing.name),
        })
    }

    /// Refuses and reports an archive whose bytes do not match the advertised hash (S-19).
    async fn quarantine(
        &self,
        format: Format,
        name: &str,
        version: &SemVer,
        expected: &str,
        actual: &str,
        now: DateTime<Utc>,
    ) {
        tracing::error!(
            package = name,
            %version,
            upstream = self.client.base_url(),
            expected,
            actual,
            "QUARANTINE: upstream archive does not match its advertised sha256; not stored, not served"
        );
        metrics::counter!("quarantine_total").increment(1);
        self.audit(
            "upstream.quarantine",
            Some(format!("{name}@{version}")),
            serde_json::json!({
                "format": format.as_str(),
                "upstream": self.client.base_url(),
                "package": name,
                "version": version.to_string(),
                "expected_sha256": expected,
                "actual_sha256": actual,
            }),
            now,
        )
        .await;
        // The register (S-19's admin surface) is best-effort in the same way the audit log is:
        // the bytes were already refused before this line, so a write failure here loses
        // evidence, never containment.
        if let Err(err) = self
            .repos
            .upstream
            .record_quarantine(
                NewQuarantineEntry {
                    format,
                    name: name.to_owned(),
                    version: version.to_string(),
                    upstream: self.client.base_url().to_owned(),
                    expected_sha256: expected.to_owned(),
                    actual_sha256: actual.to_owned(),
                },
                now,
            )
            .await
        {
            tracing::error!(package = name, %version, error = %err, "failed to record a quarantine entry");
        }
        self.events
            .emit(DomainEvent::UpstreamQuarantined {
                format,
                upstream: self.client.base_url().to_owned(),
                name: name.to_owned(),
                version: version.to_string(),
                expected_sha256: expected.to_owned(),
                actual_sha256: actual.to_owned(),
                at: now,
            })
            .await;
    }

    /// Reports upstream changing its mind about bytes we already hold (S-19 byte-drift).
    async fn report_drift(
        &self,
        format: Format,
        name: &str,
        version: &SemVer,
        cached: &str,
        upstream: &str,
        now: DateTime<Utc>,
    ) {
        tracing::error!(
            package = name,
            %version,
            upstream = self.client.base_url(),
            cached_sha256 = cached,
            upstream_sha256 = upstream,
            "BYTE DRIFT: upstream advertises a different sha256 for a cached version; keeping the cached bytes"
        );
        metrics::counter!("upstream_drift_total").increment(1);
        self.audit(
            "upstream.drift",
            Some(format!("{name}@{version}")),
            serde_json::json!({
                "format": format.as_str(),
                "upstream": self.client.base_url(),
                "package": name,
                "version": version.to_string(),
                "cached_sha256": cached,
                "upstream_sha256": upstream,
            }),
            now,
        )
        .await;
        self.events
            .emit(DomainEvent::UpstreamDrifted {
                format,
                upstream: self.client.base_url().to_owned(),
                name: name.to_owned(),
                version: version.to_string(),
                cached_sha256: cached.to_owned(),
                upstream_sha256: upstream.to_owned(),
                at: now,
            })
            .await;
    }

    /// Streams an archive with the size cap enforced *while* it arrives.
    async fn download(&self, url: &str) -> std::result::Result<Bytes, UpstreamError> {
        let limit = self.policy.max_archive_bytes;
        let archive = self.client.fetch_archive(url).await?;
        // A `Content-Length` past the cap is a free early reject; it is upstream's claim, so
        // the running count below is what actually enforces the limit.
        if archive.content_length.is_some_and(|len| len > limit) {
            return Err(UpstreamError::TooLarge { limit });
        }

        let mut body = archive.body;
        let mut buf: Vec<u8> = Vec::with_capacity(initial_capacity(archive.content_length, limit));
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if buf.len() as u64 + chunk.len() as u64 > limit {
                return Err(UpstreamError::TooLarge { limit });
            }
            buf.extend_from_slice(&chunk);
        }
        if buf.is_empty() {
            return Err(UpstreamError::Malformed { message: "upstream archive is empty".to_owned() });
        }
        // A body that stopped short of its own `Content-Length` is a **transport** failure, and
        // has to be named as one. Falling through to the hash check would reach the right
        // conclusion — truncated bytes hash to something else, so they are never stored — but by
        // the wrong route: it would file a dropped connection in the S-19 quarantine register as
        // upstream tampering and emit a security-category alarm for a network hiccup. The
        // transport usually catches this first; this makes it a property of the pipeline rather
        // than of the HTTP client underneath it.
        if let Some(expected) = archive.content_length
            && buf.len() as u64 != expected
        {
            return Err(UpstreamError::Unavailable {
                message: format!("upstream archive ended after {} of {expected} bytes", buf.len()),
            });
        }
        Ok(Bytes::from(buf))
    }

    /// The upstream archive URL for a version, read out of the stored listing snapshot.
    ///
    /// Deriving it from the snapshot instead of storing a column keeps `archive_url` where it
    /// belongs — inside upstream's own document — and makes it structurally impossible for a
    /// stale URL to outlive the listing it came from.
    async fn archive_url(&self, format: Format, name: &str, version: &SemVer) -> Result<Option<String>> {
        let Some(package) = self.repos.upstream.get_package(format, name).await? else {
            return Ok(None);
        };
        let Some(raw) = package.listing else {
            return Ok(None);
        };
        let wanted = version.to_string();
        let url = raw
            .get("versions")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .find(|entry| entry.get("version").and_then(serde_json::Value::as_str) == Some(wanted.as_str()))
            .and_then(|entry| entry.get("archive_url"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        Ok(url)
    }

    // ------------------------------------------------------------------- cache internals

    /// Whether a stored snapshot for `name` was refreshed at or after `stale_before`.
    async fn is_fresh(&self, format: Format, name: &str, stale_before: DateTime<Utc>) -> Result<bool> {
        Ok(self.repos.upstream.get_package(format, name).await?.is_some_and(|row| row.fetched_at >= stale_before))
    }

    /// The cached listing, optionally only when it is still inside its TTL.
    async fn cached_listing(
        &self,
        format: Format,
        name: &str,
        now: DateTime<Utc>,
        require_fresh: bool,
    ) -> Result<Option<ProxiedListing>> {
        let Some(package) = self.repos.upstream.get_package(format, name).await? else {
            return Ok(None);
        };
        if require_fresh && now.signed_duration_since(package.fetched_at) >= self.policy.listing_ttl {
            return Ok(None);
        }
        let versions = self.repos.upstream.list_versions(package.id).await?;
        if versions.is_empty() {
            return Ok(None);
        }
        Ok(Some(ProxiedListing {
            name: package.name,
            discontinued: package.discontinued,
            replaced_by: package.replaced_by,
            advisories_updated: package.advisories_updated,
            versions: versions
                .into_iter()
                .map(|version| ProxiedVersion {
                    version: version.version,
                    retracted: version.retracted,
                    archive_sha256: version.archive_sha256,
                    pubspec: version.pubspec,
                })
                .collect(),
            stale: false,
        }))
    }

    /// Serves whatever snapshot we hold, marked stale — or `None`, which the caller turns
    /// into a 404 (never a 5xx).
    async fn stale_listing(
        &self,
        format: Format,
        name: &str,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<Option<ProxiedListing>> {
        match self.cached_listing(format, name, now, false).await? {
            Some(mut listing) => {
                listing.stale = true;
                tracing::warn!(
                    package = name,
                    upstream = self.client.base_url(),
                    reason,
                    upstream_stale = true,
                    "serving a stale upstream listing from cache"
                );
                metrics::counter!("upstream_stale_served_total").increment(1);
                Ok(Some(listing))
            }
            None => {
                tracing::info!(
                    package = name,
                    upstream = self.client.base_url(),
                    reason,
                    "upstream unavailable and nothing cached; answering as unknown"
                );
                Ok(None)
            }
        }
    }

    /// The cached row for one version of one upstream package.
    async fn cached_version(&self, format: Format, name: &str, version: &SemVer) -> Result<Option<UpstreamVersion>> {
        let Some(package) = self.repos.upstream.get_package(format, name).await? else {
            return Ok(None);
        };
        self.repos.upstream.get_version(package.id, version).await
    }

    /// Every known version of a cached upstream package, keyed by version.
    async fn known_versions(&self, format: Format, name: &str) -> Result<HashMap<SemVer, UpstreamVersion>> {
        let Some(package) = self.repos.upstream.get_package(format, name).await? else {
            return Ok(HashMap::new());
        };
        let versions = self.repos.upstream.list_versions(package.id).await?;
        Ok(versions.into_iter().map(|version| (version.version.clone(), version)).collect())
    }

    // ---------------------------------------------------------------- breaker & throttling

    /// Records one listing/archive resolution against `upstream_fetch_total` and the cache
    /// hit-ratio gauge (decision 23: the counters are always maintained, the *exporter* is what
    /// is off by default).
    ///
    /// `hit` and `collapsed` are the cache-served outcomes: the second is a caller that queued
    /// behind a single-flight leader and then read the cache, which is a hit from the
    /// upstream's point of view — no request left the instance.
    fn record_fetch(&self, kind: &'static str, outcome: &'static str) {
        metrics::counter!("upstream_fetch_total", "kind" => kind, "outcome" => outcome).increment(1);
        let counter = match outcome {
            "hit" | "collapsed" => &self.hits,
            _ => &self.misses,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        metrics::gauge!("cache_hit_ratio").set(self.cache_hit_ratio());
    }

    /// Whether the circuit permits an upstream request right now.
    fn breaker_allows(&self, now: DateTime<Utc>) -> bool {
        let mut breaker = self.breaker.lock().expect("upstream breaker mutex poisoned");
        breaker.allows(now, self.policy.circuit_open, self.policy.circuit_failure_threshold)
    }

    fn record_success(&self) {
        self.breaker.lock().expect("upstream breaker mutex poisoned").succeed();
    }

    fn record_failure(&self, now: DateTime<Utc>, err: &UpstreamError) {
        let opened = self
            .breaker
            .lock()
            .expect("upstream breaker mutex poisoned")
            .fail(now, self.policy.circuit_failure_threshold);
        metrics::counter!("upstream_failure_total").increment(1);
        if opened {
            tracing::error!(
                upstream = self.client.base_url(),
                error = %err,
                open_secs = self.policy.circuit_open.num_seconds(),
                "upstream circuit breaker opened; serving cached data only"
            );
            metrics::counter!("upstream_circuit_opened_total").increment(1);
        }
    }

    /// Takes one of the per-upstream concurrency permits.
    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.concurrency)
            .acquire_owned()
            .await
            .map_err(|err| Error::Internal { message: format!("upstream concurrency limiter closed: {err}") })
    }

    /// Appends an audit event as the system actor. Failures are logged, never propagated — an
    /// audit outage must not also take the proxy down.
    async fn audit(&self, action: &str, target: Option<String>, metadata: serde_json::Value, now: DateTime<Utc>) {
        let event = NewAuditEvent {
            actor: AuditActor::System,
            ip: None,
            user_agent: None,
            org_id: None,
            action: action.to_owned(),
            target,
            result: AuditResult::Failure,
            metadata: Some(metadata),
        };
        if let Err(err) = self.repos.audit.append(event, now).await {
            tracing::error!(action, error = %err, "audit append failed for an upstream integrity event");
        }
    }
}

// ------------------------------------------------------------------------ circuit breaker

/// Consecutive-failure circuit breaker over one upstream.
///
/// In-process by design. It protects *this* instance's request threads and this instance's
/// latency; a shared breaker in the KV layer would make one instance's network partition
/// everybody's outage, which is the opposite of what a breaker is for.
#[derive(Debug, Default)]
struct Breaker {
    failures: u32,
    opened_at: Option<DateTime<Utc>>,
}

impl Breaker {
    /// Whether a request may go out, transitioning out of `open` into a one-probe half-open
    /// state when the window has elapsed.
    fn allows(&mut self, now: DateTime<Utc>, open_for: Duration, threshold: u32) -> bool {
        match self.opened_at {
            Some(opened) if now.signed_duration_since(opened) < open_for => false,
            Some(_) => {
                // Half-open: let exactly one request through, with the failure budget already
                // spent, so a single failed probe re-opens the circuit immediately instead of
                // letting `threshold` requests hang again.
                self.opened_at = None;
                self.failures = threshold.saturating_sub(1);
                true
            }
            None => true,
        }
    }

    /// Whether the circuit is open **without** transitioning it into half-open.
    ///
    /// Distinct from [`Breaker::allows`] on purpose: a caller that only wants to know whether
    /// to bother (the mirror worker, deciding to skip a chunk) must not consume the one
    /// half-open probe that a real request should get.
    fn is_open(&self, now: DateTime<Utc>, open_for: Duration) -> bool {
        self.opened_at.is_some_and(|opened| now.signed_duration_since(opened) < open_for)
    }

    fn succeed(&mut self) {
        self.failures = 0;
        self.opened_at = None;
    }

    /// Records a failure; returns whether this one opened the circuit.
    fn fail(&mut self, now: DateTime<Utc>, threshold: u32) -> bool {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= threshold {
            self.failures = 0;
            self.opened_at = Some(now);
            return true;
        }
        false
    }
}

// --------------------------------------------------------------------------- single-flight

/// Collapses concurrent work on the same key onto one worker.
///
/// The guard is a plain per-key async mutex rather than a shared-future map: callers re-check
/// the cache after acquiring it, so the *second* arrival finds the first one's result and
/// never reaches the network. That is weaker than a shared future (the followers pay a cache
/// read) and much simpler to reason about — in particular it cannot hand one caller another
/// caller's error.
#[derive(Default)]
struct SingleFlight {
    slots: Arc<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

/// Held for the duration of one flight; drops the slot when nobody is waiting on it.
struct Flight {
    slots: Arc<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    key: String,
    _guard: OwnedMutexGuard<()>,
}

impl SingleFlight {
    async fn enter(&self, key: &str) -> Flight {
        let slot = {
            let mut slots = self.slots.lock().expect("single-flight mutex poisoned");
            Arc::clone(slots.entry(key.to_owned()).or_default())
        };
        // The clone above already bumped the strong count, which is what makes the cleanup in
        // `Drop` sound: a task parked in `lock_owned()` is counted before it awaits.
        let guard = Arc::clone(&slot).lock_owned().await;
        Flight { slots: Arc::clone(&self.slots), key: key.to_owned(), _guard: guard }
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        let mut slots = self.slots.lock().expect("single-flight mutex poisoned");
        // Two references means the map's and our own guard's: nobody else is queued, so the
        // entry can go. Fields are dropped *after* this body, hence 2 rather than 1.
        if slots.get(&self.key).is_some_and(|slot| Arc::strong_count(slot) == 2) {
            slots.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests;
