//! Unreferenced-blob GC.
//!
//! The job deletes bytes permanently, and byte stability is the one property this system cannot
//! repair afterwards (S-18, docs/protocol.md sharp edge 3) — so every test here is about
//! something it must **not** delete, and only one is about what it may.
//!
//! | Rule | Test |
//! |------|------|
//! | Shared content hashes survive a hard delete | [`bytes_shared_with_a_live_version_survive_a_hard_delete`] |
//! | A proxied archive counts as a reference | [`a_cached_upstream_archive_is_a_reference`] |
//! | Young blobs are inside the publish/staging window | [`objects_inside_the_grace_period_are_never_touched`] |
//! | Dry run reports and deletes nothing | [`a_dry_run_reports_exactly_what_it_would_delete`] |
//! | Foreign keys are left strictly alone | [`unrecognized_keys_are_left_alone`] |
//! | Abandoned staged uploads are collected | [`abandoned_staged_uploads_are_collected_after_the_grace_period`] |

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use pub_blob::ObjectStoreBlob;
use pub_core::org::NewOrg;
use pub_core::package::{NewUpstreamVersion, NewVersion, Publisher, UpstreamSnapshot, Visibility};
use pub_core::traits::{BlobStore, Repositories};
use pub_core::user::NewUser;
use pub_core::{Format, OrgId, SemVer, UserId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{BLOB_GC_JOB, BlobGc, GcPolicy};
use pub_registry::{RegistryService, hex_sha256};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

/// GC runs "now" far enough ahead that the objects written during setup are outside the grace
/// period — the store stamps them with the wall clock, which the tests do not control.
fn later() -> DateTime<Utc> {
    Utc::now() + Duration::days(365)
}

struct Harness {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    org: OrgId,
    user: UserId,
}

impl Harness {
    async fn new() -> Self {
        let cfg = pub_config::DatabaseConfig {
            kind: pub_config::DatabaseKind::Sqlite,
            url: None,
            path: ":memory:".to_owned(),
            ..Default::default()
        };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();
        let user = repos
            .users
            .create(
                NewUser {
                    email: Some("owner@corp.com".to_owned()),
                    email_verified: true,
                    display_name: "Owner".to_owned(),
                },
                t0(),
            )
            .await
            .expect("user")
            .id;
        let org = repos.orgs.create(NewOrg::new("Acme", "acme"), user, t0()).await.expect("org").id;
        Self { repos, blob: Arc::new(ObjectStoreBlob::memory()), org, user }
    }

    /// Publishes a version whose archive is `bytes`, storing the blob exactly as the publish
    /// pipeline does (content-addressed, byte-verbatim).
    async fn publish(&self, name: &str, version: &str, bytes: &[u8]) -> String {
        let sha256 = hex_sha256(bytes);
        let key = RegistryService::blob_key(Format::Pub, &sha256);
        self.blob.put(&key, Bytes::copy_from_slice(bytes)).await.expect("blob");
        self.repos
            .packages
            .create_version(
                NewVersion {
                    format: Format::Pub,
                    package_name: name.to_owned(),
                    org_id: self.org,
                    visibility: Visibility::Private,
                    version: SemVer::parse(version).expect("semver"),
                    pubspec: serde_json::json!({ "name": name, "version": version }),
                    archive_sha256: sha256.clone(),
                    archive_size: bytes.len() as i64,
                    published_by: Publisher { user_id: self.user, token_id: None },
                    readme_html: None,
                    changelog_html: None,
                },
                t0(),
            )
            .await
            .expect("publish");
        key
    }

    fn gc(&self, policy: GcPolicy) -> BlobGc {
        BlobGc::new(self.repos.clone(), Arc::clone(&self.blob), vec![Format::Pub], policy)
    }

    async fn exists(&self, key: &str) -> bool {
        self.blob.get(key).await.is_ok()
    }
}

fn sweeping() -> GcPolicy {
    GcPolicy { enabled: true, dry_run: false, min_age: Duration::hours(24), ..GcPolicy::default() }
}

#[tokio::test]
async fn bytes_shared_with_a_live_version_survive_a_hard_delete() {
    // Content addressing means one object can back versions that never met — here two packages
    // whose uploads are byte-identical. Deleting the object when the first one is burned would
    // break a hash the second one has already published to somebody's `pubspec.lock` (S-18).
    let harness = Harness::new().await;
    let shared = b"identical archive bytes";
    let key = harness.publish("acme_core", "1.0.0", shared).await;
    assert_eq!(harness.publish("acme_twin", "1.0.0", shared).await, key, "the two share one object");

    let burned = harness.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package");
    let version = harness
        .repos
        .packages
        .get_version(burned.id, &SemVer::parse("1.0.0").unwrap())
        .await
        .expect("get")
        .expect("version");
    harness.repos.packages.hard_delete_version(version.id).await.expect("hard delete");

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 0, "the twin still resolves through this hash");
    assert_eq!(report.referenced, 1);
    assert!(harness.exists(&key).await);

    // Burn the twin too: now nothing live points at the bytes and they may go.
    let twin = harness.repos.packages.get_by_name(Format::Pub, "acme_twin").await.expect("get").expect("package");
    let twin_version = harness
        .repos
        .packages
        .get_version(twin.id, &SemVer::parse("1.0.0").unwrap())
        .await
        .expect("get")
        .expect("version");
    harness.repos.packages.hard_delete_version(twin_version.id).await.expect("hard delete");

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1);
    assert_eq!(report.bytes, shared.len() as u64);
    assert!(!harness.exists(&key).await);

    // A second pass over an already-clean store is a no-op, not an error (idempotence).
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.scanned, 0);
    assert_eq!(report.deleted, 0);
}

#[tokio::test]
async fn a_cached_upstream_archive_is_a_reference() {
    // The proxy stores its archives under the *same* content-addressed keys a local publish
    // uses, so a GC that only consulted the local version table would delete the mirror.
    let harness = Harness::new().await;
    let bytes = b"an upstream archive";
    let sha256 = hex_sha256(bytes);
    let key = RegistryService::blob_key(Format::Pub, &sha256);
    harness.blob.put(&key, Bytes::from_static(b"an upstream archive")).await.expect("blob");

    let snapshot = harness
        .repos
        .upstream
        .save_snapshot(
            UpstreamSnapshot {
                format: Format::Pub,
                name: "http".to_owned(),
                upstream: "https://pub.dev".to_owned(),
                discontinued: false,
                replaced_by: None,
                advisories_updated: None,
                listing: None,
                versions: vec![NewUpstreamVersion {
                    version: SemVer::parse("1.0.0").expect("semver"),
                    pubspec: serde_json::json!({ "name": "http", "version": "1.0.0" }),
                    archive_sha256: sha256.clone(),
                    archive_size: None,
                    retracted: false,
                    published_at: None,
                }],
            },
            t0(),
        )
        .await
        .expect("snapshot");

    // A snapshot alone holds no bytes — the row exists, the archive does not belong to it yet.
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1, "an uncached snapshot is not a blob reference");

    // Once the version is marked cached, the same bytes are protected.
    harness.blob.put(&key, Bytes::from_static(b"an upstream archive")).await.expect("blob");
    let version = harness
        .repos
        .upstream
        .get_version(snapshot.id, &SemVer::parse("1.0.0").unwrap())
        .await
        .expect("get")
        .expect("row");
    assert!(harness.repos.upstream.mark_cached(version.id, &sha256, bytes.len() as i64, t0()).await.expect("cache"));

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.referenced, 1);
    assert!(harness.exists(&key).await);
}

#[tokio::test]
async fn objects_inside_the_grace_period_are_never_touched() {
    // The publish pipeline writes bytes *before* the version row, so "unreferenced" is the
    // normal state of a blob for the width of a transaction — and a staged upload is
    // finalizable for a whole hour with nothing referencing it at all.
    let harness = Harness::new().await;
    let key = RegistryService::blob_key(Format::Pub, &hex_sha256(b"just written"));
    harness.blob.put(&key, Bytes::from_static(b"just written")).await.expect("blob");

    let report = harness.gc(sweeping()).run_once(Utc::now()).await.expect("gc");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.too_young, 1);
    assert!(harness.exists(&key).await);

    // Past the grace period the same object is collectable.
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1);
}

#[tokio::test]
async fn a_dry_run_reports_exactly_what_it_would_delete() {
    // The first thing an operator wants from a job that erases bytes is the list.
    let harness = Harness::new().await;
    let key = RegistryService::blob_key(Format::Pub, &hex_sha256(b"orphan"));
    harness.blob.put(&key, Bytes::from_static(b"orphan")).await.expect("blob");

    let report = harness.gc(GcPolicy { dry_run: true, ..sweeping() }).run_once(later()).await.expect("gc");
    assert!(report.dry_run);
    assert_eq!(report.deleted, 1, "the count is what a real pass would delete");
    assert_eq!(report.bytes, 6);
    assert!(harness.exists(&key).await, "a dry run must not delete anything");

    // The job records its outcome either way, so an operator can see the pass happened.
    let state = harness.repos.jobs.get(BLOB_GC_JOB).await.expect("state").expect("row");
    assert_eq!(state.phase, "dry-run");
    assert_eq!(state.runs, 1);
    assert!(state.last_success_at.is_some());
    assert_eq!(state.processed, 1);
}

#[tokio::test]
async fn unrecognized_keys_are_left_alone() {
    // A key this job does not fully recognize is one whose references it cannot reason about.
    let harness = Harness::new().await;
    for key in ["pub/ab/not-a-hash.tar.gz", "pub/zz/deadbeef.txt", "pub/ab/nested/dir/file.tar.gz"] {
        harness.blob.put(key, Bytes::from_static(b"mystery")).await.expect("blob");
    }

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.unrecognized, 3);
    for key in ["pub/ab/not-a-hash.tar.gz", "pub/zz/deadbeef.txt", "pub/ab/nested/dir/file.tar.gz"] {
        assert!(harness.exists(key).await, "{key} was deleted on a guess");
    }
}

#[tokio::test]
async fn abandoned_staged_uploads_are_collected_after_the_grace_period() {
    // A staged upload whose session record has expired can no longer be finalized by anybody,
    // so its bytes are garbage — the second half of the S-20.a storage gap.
    let harness = Harness::new().await;
    harness.blob.put("uploads/pub/deadbeef.tar.gz", Bytes::from_static(b"abandoned")).await.expect("blob");

    let fresh = harness.gc(sweeping()).run_once(Utc::now()).await.expect("gc");
    assert_eq!(fresh.deleted, 0, "an upload is finalizable for an hour with nothing referencing it");
    assert_eq!(fresh.too_young, 1);

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.staged, 1);
    assert_eq!(report.deleted, 1);
    assert!(!harness.exists("uploads/pub/deadbeef.tar.gz").await);
}

#[tokio::test]
async fn a_backend_that_cannot_enumerate_fails_the_job_rather_than_deleting() {
    // "I could not list the store" must never be read as "there is nothing to keep".
    struct Blind;

    #[async_trait::async_trait]
    impl BlobStore for Blind {
        async fn ping(&self) -> pub_core::Result<()> {
            Ok(())
        }

        async fn put(&self, _key: &str, _bytes: Bytes) -> pub_core::Result<()> {
            Ok(())
        }

        async fn download(&self, key: &str) -> pub_core::Result<pub_core::traits::DownloadPlan> {
            Err(pub_core::Error::NotFound { what: key.to_owned() })
        }

        async fn delete(&self, _key: &str) -> pub_core::Result<()> {
            panic!("a store that cannot be listed must never be deleted from");
        }
    }

    let harness = Harness::new().await;
    let gc = BlobGc::new(harness.repos.clone(), Arc::new(Blind), vec![Format::Pub], sweeping());
    assert_eq!(gc.run_once(later()).await.unwrap_err().code(), "unimplemented");
    let state = harness.repos.jobs.get(BLOB_GC_JOB).await.expect("state").expect("row");
    assert!(state.last_error.is_some(), "the failure is visible to an operator");
}
