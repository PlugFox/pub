//! Unreferenced-blob GC.
//!
//! The job deletes bytes permanently, and byte stability is the one property this system cannot
//! repair afterwards (S-18, docs/protocol.md sharp edge 3) — so most of what is asserted here is
//! about something it must **not** delete, and the rest is about staying bounded while it does
//! delete ([decision 31](../../../../docs/decisions.md)).
//!
//! | Rule | Test |
//! |------|------|
//! | Shared content hashes survive a hard delete | [`bytes_shared_with_a_live_version_survive_a_hard_delete`] |
//! | A proxied archive counts as a reference | [`a_cached_upstream_archive_is_a_reference`] |
//! | Young blobs are inside the publish window | [`objects_inside_the_grace_period_are_never_touched`] |
//! | A key rewritten under the sweep is left | [`a_key_rewritten_while_the_sweep_ran_is_not_deleted`] |
//! | Dry run reports and deletes nothing | [`a_dry_run_reports_exactly_what_it_would_delete`] |
//! | Foreign keys and prefixes are left alone | [`unrecognized_keys_and_prefixes_are_left_alone`] |
//! | Staged uploads belong to the other job | [`the_staging_namespace_is_not_this_jobs_business`] |
//! | One batch decides many keys | [`a_batch_smaller_than_the_shard_still_decides_every_key`] |
//! | A spent budget records where to resume | [`a_pass_that_runs_out_of_budget_says_where_it_stopped`] |
//! | The budget bounds the walk, not the deletes | [`the_budget_is_checked_per_object_not_per_deletion`] |
//! | A resumed pass skips what is done | [`a_resumed_pass_starts_at_its_cursor_and_clears_it`] |
//! | An unreadable cursor restarts, never stalls | [`a_cursor_this_build_cannot_read_restarts_the_rotation`] |

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use pub_blob::ObjectStoreBlob;
use pub_core::jobs::JobProgress;
use pub_core::org::NewOrg;
use pub_core::package::{NewUpstreamVersion, NewVersion, Publisher, UpstreamSnapshot, Visibility};
use pub_core::traits::{BlobObject, BlobStore, DownloadMethod, DownloadPlan, PrefixListing, Repositories};
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

    /// Writes archive bytes with no version row — an interrupted publish, which is exactly what
    /// this job exists to collect.
    async fn orphan(&self, bytes: &[u8]) -> String {
        let key = RegistryService::blob_key(Format::Pub, &hex_sha256(bytes));
        self.blob.put(&key, Bytes::copy_from_slice(bytes)).await.expect("blob");
        key
    }

    fn gc(&self, policy: GcPolicy) -> BlobGc {
        BlobGc::new(self.repos.clone(), Arc::clone(&self.blob), vec![Format::Pub], policy)
    }

    fn gc_over(&self, blob: Arc<dyn BlobStore>, policy: GcPolicy) -> BlobGc {
        BlobGc::new(self.repos.clone(), blob, vec![Format::Pub], policy)
    }

    async fn exists(&self, key: &str) -> bool {
        self.blob.get(key).await.is_ok()
    }

    /// Plants a durable resume point, as a pass that ran out of budget would have left.
    async fn set_cursor(&self, cursor: &str) {
        let progress =
            JobProgress { cursor: Some(cursor.to_owned()), phase: "swept".to_owned(), processed: 0, failed: 0 };
        self.repos.jobs.checkpoint(BLOB_GC_JOB, &progress, t0()).await.expect("checkpoint");
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
    assert!(report.converged, "an empty key space is a finished sweep");
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
    // normal state of a blob for the width of a transaction.
    let harness = Harness::new().await;
    let key = harness.orphan(b"just written").await;

    let report = harness.gc(sweeping()).run_once(Utc::now()).await.expect("gc");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.too_young, 1);
    assert!(harness.exists(&key).await);

    // Past the grace period the same object is collectable.
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1);
}

#[tokio::test]
async fn a_key_rewritten_while_the_sweep_ran_is_not_deleted() {
    // The race this closes: a listing says "old and unreferenced", and before the delete lands a
    // publish of byte-identical content rewrites the object (`put` is an idempotent overwrite on
    // a content-addressed key) and commits the row. The re-read before the delete is what sees
    // the refreshed timestamp — without it the new version would point at nothing.
    let harness = Harness::new().await;
    let key = harness.orphan(b"about to be republished").await;

    let rewritten: Arc<dyn BlobStore> = Arc::new(RewrittenOnHead { inner: Arc::clone(&harness.blob) });
    let report = harness.gc_over(rewritten, sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 0, "a key that got younger under the sweep must survive it");
    assert_eq!(report.contested, 1);
    assert_eq!(report.bytes, 0);
    assert!(harness.exists(&key).await);
}

#[tokio::test]
async fn a_dry_run_reports_exactly_what_it_would_delete() {
    // The first thing an operator wants from a job that erases bytes is the list.
    let harness = Harness::new().await;
    let key = harness.orphan(b"orphan").await;

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
    assert!(state.cursor.is_none(), "a finished sweep leaves nothing to resume");
}

#[tokio::test]
async fn unrecognized_keys_and_prefixes_are_left_alone() {
    // A key this job does not fully recognize is one whose references it cannot reason about.
    // `pub/zz/` is not a shard, so it is reported without being walked at all; the two inside a
    // real shard are reported per object.
    let harness = Harness::new().await;
    for key in ["pub/ab/not-a-hash.tar.gz", "pub/zz/deadbeef.txt", "pub/ab/nested/dir/file.tar.gz", "pub/stray.txt"] {
        harness.blob.put(key, Bytes::from_static(b"mystery")).await.expect("blob");
    }

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.unrecognized, 4, "two objects in a shard, one foreign prefix, one object at the root");
    for key in ["pub/ab/not-a-hash.tar.gz", "pub/zz/deadbeef.txt", "pub/ab/nested/dir/file.tar.gz", "pub/stray.txt"] {
        assert!(harness.exists(key).await, "{key} was deleted on a guess");
    }
}

#[tokio::test]
async fn the_staging_namespace_is_not_this_jobs_business() {
    // Staged uploads moved to their own job, which is on by default while this one is off
    // (decision 31). This job must not touch them — and must not count them either, or the two
    // reports would double-count the same bytes.
    let harness = Harness::new().await;
    harness.blob.put("uploads/pub/deadbeef.tar.gz", Bytes::from_static(b"staged")).await.expect("blob");

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.scanned, 0);
    assert_eq!(report.deleted, 0);
    assert!(harness.exists("uploads/pub/deadbeef.tar.gz").await);
}

#[tokio::test]
async fn a_batch_smaller_than_the_shard_still_decides_every_key() {
    // References are resolved a batch at a time — two queries per batch instead of two per
    // object — and a batch is flushed inside one shard, so the boundary between batches is where
    // a bug would drop or double-count a key. These five payloads were picked because their
    // hashes share a shard (`06`): five keys in one stream, a batch of two, so the pass makes two
    // full batches and a short tail.
    let harness = Harness::new().await;
    let mut orphans = Vec::new();
    for payload in ["orphan-170", "orphan-279", "orphan-451", "orphan-711", "orphan-940"] {
        let key = harness.orphan(payload.as_bytes()).await;
        assert!(key.starts_with("pub/06/"), "{key} must share the shard this test is about");
        orphans.push(key);
    }
    let kept = harness.publish("acme_core", "1.0.0", b"a live archive").await;

    let report = harness.gc(GcPolicy { batch: 2, ..sweeping() }).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 5, "every orphan is decided regardless of where the batch boundaries fall");
    assert_eq!(report.referenced, 1);
    assert_eq!(report.scanned, 6);
    for key in &orphans {
        assert!(!harness.exists(key).await, "{key} survived");
    }
    assert!(harness.exists(&kept).await);
}

#[tokio::test]
async fn a_pass_that_runs_out_of_budget_says_where_it_stopped() {
    // The budget is what makes this job safe to enable on a large bucket: it stops, records a
    // resume point, and releases the lock instead of holding it for a whole sweep.
    let harness = Harness::new().await;
    let key = harness.orphan(b"first orphan").await;

    let slow: Arc<dyn BlobStore> = Arc::new(SlowListing { inner: Arc::clone(&harness.blob), per_object: false });
    let policy = GcPolicy { budget: std::time::Duration::from_millis(1), ..sweeping() };
    let report = harness.gc_over(slow, policy).run_once(later()).await.expect("gc");

    assert!(!report.converged, "the budget was spent before the first shard");
    assert_eq!(report.cursor.as_deref(), Some("pub:11"), "the resume point names the shard it did not walk");
    assert_eq!(report.deleted, 0);
    assert!(harness.exists(&key).await);

    let state = harness.repos.jobs.get(BLOB_GC_JOB).await.expect("state").expect("row");
    assert_eq!(state.cursor.as_deref(), Some("pub:11"), "the resume point is durable, not in-process");
    assert_eq!(state.phase, "swept, resumes at pub:11", "an operator reads this in the admin jobs table");
}

#[tokio::test]
async fn the_budget_is_checked_per_object_not_per_deletion() {
    // The failure this pins: a shard whose keys are all too young, all foreign, or all
    // referenced never fills a batch and never deletes anything — so a budget consulted only
    // when a batch flushes, or only after a delete, does not bound that walk at all. It is
    // exactly the key space that is expensive to walk, and the lock is held throughout.
    let harness = Harness::new().await;
    let key = harness.orphan(b"first orphan").await;

    let slow: Arc<dyn BlobStore> = Arc::new(SlowListing { inner: Arc::clone(&harness.blob), per_object: true });
    let policy = GcPolicy { budget: std::time::Duration::from_millis(1), ..sweeping() };
    let report = harness.gc_over(slow, policy).run_once(later()).await.expect("gc");

    assert!(!report.converged, "the pass must stop inside the shard, not walk it to the end");
    assert_eq!(report.cursor.as_deref(), Some("pub:11"), "the unfinished shard is where the next pass resumes");
    assert_eq!(report.deleted, 0);
    assert!(harness.exists(&key).await);
}

#[tokio::test]
async fn a_resumed_pass_starts_at_its_cursor_and_clears_it() {
    // Coverage rotates: a pass that stopped mid-key-space picks up where it left off, and the
    // one that reaches the end clears the cursor so the next rotation starts over.
    let harness = Harness::new().await;
    let early = harness.orphan(b"first orphan").await; // shard 11
    let late = harness.orphan(b"second orphan").await; // shard 28
    assert!(early.starts_with("pub/11/") && late.starts_with("pub/28/"), "{early} / {late}");

    harness.set_cursor("pub:28").await;
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1, "only the shard at and after the cursor is walked");
    assert_eq!(report.scanned, 1, "the earlier shard is not even listed");
    assert!(report.converged);
    assert!(report.cursor.is_none(), "reaching the end starts the next rotation from the beginning");
    assert!(harness.exists(&early).await, "the shard before the cursor is this rotation's already-done half");
    assert!(!harness.exists(&late).await);

    // The next pass has no cursor, so it collects what the previous rotation skipped.
    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1);
    assert!(!harness.exists(&early).await);
}

#[tokio::test]
async fn a_cursor_this_build_cannot_read_restarts_the_rotation() {
    // A cursor written by another build, or truncated, must never be the reason collection
    // stops — and must never be mistaken for a shard name.
    let harness = Harness::new().await;
    let key = harness.orphan(b"first orphan").await;
    harness.set_cursor("garbage-not-a-cursor").await;

    let report = harness.gc(sweeping()).run_once(later()).await.expect("gc");
    assert_eq!(report.deleted, 1);
    assert!(report.converged);
    assert!(!harness.exists(&key).await);
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

        async fn download(&self, key: &str, _method: DownloadMethod) -> pub_core::Result<DownloadPlan> {
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

/// A store whose `head` reports a *fresh* object — a concurrent republish, seen from the
/// collector's side.
struct RewrittenOnHead {
    inner: Arc<dyn BlobStore>,
}

#[async_trait::async_trait]
impl BlobStore for RewrittenOnHead {
    async fn ping(&self) -> pub_core::Result<()> {
        self.inner.ping().await
    }

    async fn put(&self, key: &str, bytes: Bytes) -> pub_core::Result<()> {
        self.inner.put(key, bytes).await
    }

    async fn download(&self, key: &str, method: DownloadMethod) -> pub_core::Result<DownloadPlan> {
        self.inner.download(key, method).await
    }

    async fn delete(&self, _key: &str) -> pub_core::Result<()> {
        panic!("a rewritten key must not be deleted");
    }

    fn list_stream<'a>(&'a self, prefix: &'a str) -> BoxStream<'a, pub_core::Result<BlobObject>> {
        self.inner.list_stream(prefix)
    }

    async fn list_prefixes(&self, prefix: &str) -> pub_core::Result<PrefixListing> {
        self.inner.list_prefixes(prefix).await
    }

    async fn head(&self, key: &str) -> pub_core::Result<Option<BlobObject>> {
        Ok(self.inner.head(key).await?.map(|object| BlobObject { last_modified: Some(later()), ..object }))
    }
}

/// A store that spends the pass's whole budget answering the first listing.
struct SlowListing {
    inner: Arc<dyn BlobStore>,
    /// Where the time goes: the shard listing, or every object streamed out of a shard.
    per_object: bool,
}

#[async_trait::async_trait]
impl BlobStore for SlowListing {
    async fn ping(&self) -> pub_core::Result<()> {
        self.inner.ping().await
    }

    async fn put(&self, key: &str, bytes: Bytes) -> pub_core::Result<()> {
        self.inner.put(key, bytes).await
    }

    async fn download(&self, key: &str, method: DownloadMethod) -> pub_core::Result<DownloadPlan> {
        self.inner.download(key, method).await
    }

    async fn delete(&self, _key: &str) -> pub_core::Result<()> {
        panic!("a pass that never reached a shard must not delete anything");
    }

    fn list_stream<'a>(&'a self, prefix: &'a str) -> BoxStream<'a, pub_core::Result<BlobObject>> {
        if !self.per_object {
            return self.inner.list_stream(prefix);
        }
        self.inner
            .list_stream(prefix)
            .then(|object| async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                object
            })
            .boxed()
    }

    async fn list_prefixes(&self, prefix: &str) -> pub_core::Result<PrefixListing> {
        // Real sleep, not a paused clock: the budget is wall-clock by construction, and 20 ms
        // against a 1 ms budget is not a race that can go the other way.
        if !self.per_object {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.inner.list_prefixes(prefix).await
    }

    async fn head(&self, key: &str) -> pub_core::Result<Option<BlobObject>> {
        self.inner.head(key).await
    }
}
