//! Domain services for the Pub registry — everything about publishing and the version
//! lifecycle except HTTP.
//!
//! ```text
//! upload bytes ─► archive::validate_archive ─► pubspec::Pubspec::parse ─► markdown::render
//!                          │                          │                        │
//!                    (S-20 limits,             (name/version rules,      (S-11 sanitized
//!                  no disk extraction)          untrusted YAML)            HTML, once)
//!                          └──────────────► publish::RegistryService ◄──────────┘
//!                                                    │
//!                          content-addressed blob ───┤─── transactional DB insert
//!                                                    │
//!                                  audit event (S-22)┴─ domain event (decision 22)
//! ```
//!
//! Module map:
//!
//! - [`archive`] — streaming tar.gz inspection with hard limits; rejects traversal, escaping
//!   links, duplicates, and gzip bombs, and never extracts to disk (S-20).
//! - [`pubspec`] — `pubspec.yaml` parsing over a bomb-proof YAML parser plus pub's package-name
//!   rules.
//! - [`markdown`] — README/CHANGELOG → sanitized HTML, rendered once at publish (S-11).
//! - [`publish`] — the pipeline itself and the retract / hard-delete services, including the
//!   per-name [`pub_core::traits::JobLock`], audit events, and domain events.
//! - [`upstream`] — the read-through proxy ingest of decision 07: fetch, verify against the
//!   advertised sha256 before storing (S-19), snapshot upstream state verbatim, serve stale
//!   under an outage, and collapse concurrent misses onto one upstream request. The mirror
//!   worker in `pub-jobs` warms this same pipeline through
//!   [`upstream::UpstreamService::refresh`] — decision 07's "mirror mode is read-through warmed
//!   by a job", not a second implementation.
//! - [`index`] — the search-index projection (decision 11): one document per package, derived
//!   from the package row plus its newest live version, refreshed by every lifecycle change and
//!   rebuildable in full by the reindex job.
//! - [`stats`] — the download counter's write path: an in-process buffer the rollup job drains
//!   into `download_stats`, so counting a download costs no I/O.
//! - [`shadow`] — S-17 shadowing alarms: a name claimed here observed upstream. Called from
//!   both arrival orders (a publish claiming a name we proxy; the mirror finding a name we
//!   claim), and never from the read path, which structurally never asks upstream about a
//!   claimed name.
//!
//! Apart from the upstream HTTP transport — which *is* an infrastructure concern, isolated
//! behind [`upstream::UpstreamClient`] — everything here builds against `pub-core` traits only.

pub mod archive;
pub mod index;
pub mod markdown;
pub mod publish;
pub mod pubspec;
pub mod shadow;
pub mod stats;
pub mod upstream;

pub use archive::{ArchiveContents, ArchiveError, ArchiveLimits, validate_archive};
pub use index::{PackageIndexer, ReindexPage, build_document, latest_index};
pub use publish::{
    ActorMeta, HardDeleteOutcome, HardDeleteRequest, PublishOutcome, PublishRequest, RegistryPolicy, RegistryService,
    RetractRequest, TransferRequest, hex_sha256,
};
pub use pubspec::{Pubspec, PubspecError, validate_package_name};
pub use shadow::{ShadowObservation, ShadowOutcome};
pub use stats::{DEFAULT_BUFFER_CAPACITY, DownloadRecorder, FlushReport};
pub use upstream::{
    ProxiedArchive, ProxiedListing, ProxiedVersion, RefreshOutcome, UpstreamArchive, UpstreamClient, UpstreamError,
    UpstreamListing, UpstreamNamePage, UpstreamService, UpstreamServicePolicy, UpstreamVersionEntry,
};
