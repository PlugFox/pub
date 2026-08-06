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
//!
//! Still to come with their own roadmap steps: resolution policy across org/instance/upstream
//! (decision 01), proxy ingest and mirror sync (decision 07), and shadowing alarms (S-17).
//! Everything here builds against `pub-core` traits only — no infrastructure types leak in.

pub mod archive;
pub mod markdown;
pub mod publish;
pub mod pubspec;

pub use archive::{ArchiveContents, ArchiveError, ArchiveLimits, validate_archive};
pub use publish::{
    ActorMeta, HardDeleteOutcome, HardDeleteRequest, PublishOutcome, PublishRequest, RegistryPolicy, RegistryService,
    RetractRequest, hex_sha256,
};
pub use pubspec::{Pubspec, PubspecError, validate_package_name};
