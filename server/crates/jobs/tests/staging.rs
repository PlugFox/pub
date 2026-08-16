//! Abandoned staged uploads — the byte collector that runs on a default install
//! ([decision 31](../../../../docs/decisions.md), [S-20.a](../../../../docs/security.md)).
//!
//! | Rule | Test |
//! |------|------|
//! | An abandoned upload is collected by age alone | [`an_abandoned_upload_is_collected_after_the_grace_period`] |
//! | An upload that can still be finalized is kept | [`an_upload_inside_the_grace_period_is_never_touched`] |
//! | Published archives are the other job's business | [`the_archive_namespace_is_not_this_jobs_business`] |
//! | Foreign keys under the prefix are left alone | [`keys_that_are_not_staged_uploads_are_left_alone`] |
//! | A key rewritten under the pass is left | [`a_key_rewritten_while_the_pass_ran_is_not_deleted`] |
//! | Dry run reports and deletes nothing | [`a_dry_run_reports_exactly_what_it_would_delete`] |
//! | The budget bounds the walk, not the deletes | [`the_budget_is_checked_per_object_not_per_deletion`] |
//! | A blind backend fails the job, never deletes | [`a_backend_that_cannot_enumerate_fails_the_job_rather_than_deleting`] |

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use pub_blob::ObjectStoreBlob;
use pub_core::traits::{BlobObject, BlobStore, DownloadMethod, DownloadPlan, PrefixListing, Repositories};
use pub_core::{Format, Result};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{STAGING_SWEEP_JOB, StagingPolicy, StagingSweeper};

/// A session id of the shape `newUpload` mints: 128 bits, lowercase hex.
const SESSION: &str = "0123456789abcdef0123456789abcdef";

/// Far enough ahead that objects written during setup are outside the grace period — the store
/// stamps them with the wall clock, which the tests do not control.
fn later() -> DateTime<Utc> {
    Utc::now() + Duration::days(365)
}

fn staged(session: &str) -> String {
    format!("uploads/pub/{session}.tar.gz")
}

struct Harness {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
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
        Self { repos: db.repositories(), blob: Arc::new(ObjectStoreBlob::memory()) }
    }

    async fn put(&self, key: &str, bytes: &'static [u8]) {
        self.blob.put(key, Bytes::from_static(bytes)).await.expect("blob");
    }

    fn sweeper(&self, policy: StagingPolicy) -> StagingSweeper {
        StagingSweeper::new(self.repos.clone(), Arc::clone(&self.blob), vec![Format::Pub], policy)
    }

    fn sweeper_over(&self, blob: Arc<dyn BlobStore>, policy: StagingPolicy) -> StagingSweeper {
        StagingSweeper::new(self.repos.clone(), blob, vec![Format::Pub], policy)
    }

    async fn exists(&self, key: &str) -> bool {
        self.blob.get(key).await.is_ok()
    }
}

#[tokio::test]
async fn an_abandoned_upload_is_collected_after_the_grace_period() {
    // The D22 case: a publish that was never finished. Its KV record expired an hour after the
    // upload, so `newUploadFinish` can only answer "expired" — nothing can reach these bytes.
    let harness = Harness::new().await;
    harness.put(&staged(SESSION), b"abandoned").await;

    let report = harness.sweeper(StagingPolicy::default()).run_once(later()).await.expect("sweep");
    assert_eq!(report.deleted, 1);
    assert_eq!(report.bytes, 9);
    assert!(report.converged);
    assert!(!harness.exists(&staged(SESSION)).await);

    // The pass is recorded whether or not it found anything, and a second one is a clean no-op.
    let state = harness.repos.jobs.get(STAGING_SWEEP_JOB).await.expect("state").expect("row");
    assert_eq!(state.phase, "swept");
    assert_eq!(state.processed, 1);
    assert!(state.last_success_at.is_some());

    let report = harness.sweeper(StagingPolicy::default()).run_once(later()).await.expect("sweep");
    assert_eq!(report.scanned, 0);
    assert_eq!(report.deleted, 0);
}

#[tokio::test]
async fn an_upload_inside_the_grace_period_is_never_touched() {
    // For a whole hour after the bytes land, the session record still exists and the client can
    // still finalize — with no database row referencing the object. Deleting one here would fail
    // a publish that was doing nothing wrong.
    let harness = Harness::new().await;
    harness.put(&staged(SESSION), b"still finalizable").await;

    let report = harness.sweeper(StagingPolicy::default()).run_once(Utc::now()).await.expect("sweep");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.too_young, 1);
    assert!(harness.exists(&staged(SESSION)).await);
}

#[tokio::test]
async fn the_archive_namespace_is_not_this_jobs_business() {
    // This job asks the database nothing, which is only safe because it never looks at keys that
    // a version row could reference. A published archive is the other collector's job, and that
    // one is off by default precisely because it can be wrong.
    let harness = Harness::new().await;
    harness.put("pub/ab/abcd.tar.gz", b"a published archive").await;

    let report = harness.sweeper(StagingPolicy::default()).run_once(later()).await.expect("sweep");
    assert_eq!(report.scanned, 0, "the archive key space is outside this job's prefix");
    assert_eq!(report.deleted, 0);
    assert!(harness.exists("pub/ab/abcd.tar.gz").await);
}

#[tokio::test]
async fn keys_that_are_not_staged_uploads_are_left_alone() {
    // The predecessor deleted anything under `uploads/` on age alone. A key this job does not
    // fully recognize was put there by something else, and that something else is entitled to
    // keep it.
    let harness = Harness::new().await;
    let strangers = [
        format!("uploads/pub/{SESSION}.zip"),
        format!("uploads/pub/nested/{SESSION}.tar.gz"),
        "uploads/pub/not-a-session.tar.gz".to_owned(),
        format!("uploads/pub/{}.tar.gz", SESSION.to_uppercase()),
    ];
    for key in &strangers {
        harness.blob.put(key, Bytes::from_static(b"mystery")).await.expect("blob");
    }

    let report = harness.sweeper(StagingPolicy::default()).run_once(later()).await.expect("sweep");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.unrecognized, strangers.len());
    for key in &strangers {
        assert!(harness.exists(key).await, "{key} was deleted on a guess");
    }
}

#[tokio::test]
async fn a_key_rewritten_while_the_pass_ran_is_not_deleted() {
    // Same rule as the archive collector: the listing is a snapshot, and the delete is decided
    // on a re-read rather than on it.
    let harness = Harness::new().await;
    harness.put(&staged(SESSION), b"rewritten").await;

    let rewritten: Arc<dyn BlobStore> = Arc::new(RewrittenOnHead { inner: Arc::clone(&harness.blob) });
    let report = harness.sweeper_over(rewritten, StagingPolicy::default()).run_once(later()).await.expect("sweep");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.contested, 1);
    assert!(harness.exists(&staged(SESSION)).await);
}

#[tokio::test]
async fn a_dry_run_reports_exactly_what_it_would_delete() {
    // Not the default here — this job deletes for real out of the box — but an operator who has
    // just been surprised by a report wants to see the list before the next pass acts on it.
    let harness = Harness::new().await;
    harness.put(&staged(SESSION), b"abandoned").await;

    let policy = StagingPolicy { dry_run: true, ..StagingPolicy::default() };
    let report = harness.sweeper(policy).run_once(later()).await.expect("sweep");
    assert!(report.dry_run);
    assert_eq!(report.deleted, 1);
    assert_eq!(report.bytes, 9);
    assert!(harness.exists(&staged(SESSION)).await);
    let state = harness.repos.jobs.get(STAGING_SWEEP_JOB).await.expect("state").expect("row");
    assert_eq!(state.phase, "dry-run");
}

#[tokio::test]
async fn the_budget_is_checked_per_object_not_per_deletion() {
    // A staging area full of uploads still inside their grace period — or of keys this job does
    // not recognize — deletes nothing, so a budget consulted only after a deletion would leave
    // that walk unbounded under the job's lock. The check has to sit on the object, not on the
    // delete.
    let harness = Harness::new().await;
    harness.put(&staged(SESSION), b"abandoned").await;

    let slow: Arc<dyn BlobStore> = Arc::new(SlowListing { inner: Arc::clone(&harness.blob) });
    let policy = StagingPolicy { budget: std::time::Duration::from_millis(1), ..StagingPolicy::default() };
    let report = harness.sweeper_over(slow, policy).run_once(later()).await.expect("sweep");

    assert!(!report.converged, "the pass must stop rather than walk the namespace to the end");
    assert_eq!(report.scanned, 0);
    assert_eq!(report.deleted, 0);
    assert!(harness.exists(&staged(SESSION)).await);

    let state = harness.repos.jobs.get(STAGING_SWEEP_JOB).await.expect("state").expect("row");
    assert_eq!(state.phase, "swept, budget spent", "an operator reads this in the admin jobs table");
}

#[tokio::test]
async fn a_backend_that_cannot_enumerate_fails_the_job_rather_than_deleting() {
    // "I could not list the staging area" must never be read as "there is nothing there".
    struct Blind;

    #[async_trait::async_trait]
    impl BlobStore for Blind {
        async fn ping(&self) -> Result<()> {
            Ok(())
        }

        async fn put(&self, _key: &str, _bytes: Bytes) -> Result<()> {
            Ok(())
        }

        async fn download(&self, key: &str, _method: DownloadMethod) -> Result<DownloadPlan> {
            Err(pub_core::Error::NotFound { what: key.to_owned() })
        }

        async fn delete(&self, _key: &str) -> Result<()> {
            panic!("a store that cannot be listed must never be deleted from");
        }
    }

    let harness = Harness::new().await;
    let sweeper =
        StagingSweeper::new(harness.repos.clone(), Arc::new(Blind), vec![Format::Pub], StagingPolicy::default());
    assert_eq!(sweeper.run_once(later()).await.unwrap_err().code(), "unimplemented");
    let state = harness.repos.jobs.get(STAGING_SWEEP_JOB).await.expect("state").expect("row");
    assert!(state.last_error.is_some(), "the failure is visible to an operator");
}

/// A store that spends the pass's whole budget handing out its first object.
struct SlowListing {
    inner: Arc<dyn BlobStore>,
}

#[async_trait::async_trait]
impl BlobStore for SlowListing {
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.inner.put(key, bytes).await
    }

    async fn download(&self, key: &str, method: DownloadMethod) -> Result<DownloadPlan> {
        self.inner.download(key, method).await
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        panic!("a pass that ran out of budget must not delete anything");
    }

    fn list_stream<'a>(&'a self, prefix: &'a str) -> BoxStream<'a, Result<BlobObject>> {
        // Real sleep against a 1 ms budget: not a race that can go the other way.
        self.inner
            .list_stream(prefix)
            .then(|object| async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                object
            })
            .boxed()
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<PrefixListing> {
        self.inner.list_prefixes(prefix).await
    }

    async fn head(&self, key: &str) -> Result<Option<BlobObject>> {
        self.inner.head(key).await
    }
}

/// A store whose `head` reports a fresh object — an upload being written while the pass runs.
struct RewrittenOnHead {
    inner: Arc<dyn BlobStore>,
}

#[async_trait::async_trait]
impl BlobStore for RewrittenOnHead {
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.inner.put(key, bytes).await
    }

    async fn download(&self, key: &str, method: DownloadMethod) -> Result<DownloadPlan> {
        self.inner.download(key, method).await
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        panic!("a rewritten key must not be deleted");
    }

    fn list_stream<'a>(&'a self, prefix: &'a str) -> BoxStream<'a, Result<BlobObject>> {
        self.inner.list_stream(prefix)
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<PrefixListing> {
        self.inner.list_prefixes(prefix).await
    }

    async fn head(&self, key: &str) -> Result<Option<BlobObject>> {
        Ok(self.inner.head(key).await?.map(|object| BlobObject { last_modified: Some(later()), ..object }))
    }
}
