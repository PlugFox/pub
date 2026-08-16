//! The manual-run registry behind `POST /api/v1/admin/jobs/{job}/run`.
//!
//! The admin surface needs two things the scheduler does not expose: *which* jobs this instance
//! actually registered, and a way to run one out of band. Both live here rather than in the
//! scheduler because a manual run is not a tick — it has a caller waiting for a result, and it
//! must not be silently skipped when the leader lock is held elsewhere.
//!
//! Two rules make an operator-triggered run safe:
//!
//! - **It takes the same [`JobLock`] the scheduler takes**, under the same name **and for the same
//!   lifetime**. A manual sweep racing a scheduled one would mean two writers on one durable
//!   cursor, which is precisely the state the lock exists to prevent. A lock held elsewhere is
//!   answered with [`Error::Conflict`] rather than a no-op: "it is already running" is information.
//!   The lifetime comes from the [`JobLockTtls`] table the scheduler was given — until decision 30
//!   this path used its own hardcoded 300 s while the scheduler used a global value derived from a
//!   queue lease, which is two answers to "how long may this job hold its lock" (D48).
//! - **Only registered jobs are listed and runnable.** A job the operator disabled is not in
//!   the map, so the button for it does not exist — the same "a job that is not registered
//!   cannot tick" property the scheduler relies on, extended to the manual path.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::FutureExt as _;
use futures::future::BoxFuture;
use pub_core::traits::{JobLock, JobTrigger, LockToken};
use pub_core::{Error, Result};

use crate::downloads::{DOWNLOAD_ROLLUP_JOB, DownloadRollup};
use crate::gc::{BLOB_GC_JOB, BlobGc};
use crate::lifecycle::{LIFECYCLE_JOB, LifecycleWorker};
use crate::lock::JobLockTtls;
use crate::mirror::{MIRROR_JOB, MirrorWorker};
use crate::queue::{QUEUE_JOB, QueueWorker};
use crate::reindex::{REINDEX_JOB, Reindexer};
use crate::staging::{STAGING_SWEEP_JOB, StagingSweeper};

/// Releases a job lock when dropped, including when the run it guards is **cancelled**.
///
/// `release` is async and `Drop` is not, so the release is spawned. That is the point rather than a
/// compromise: the case this exists for is a dropped future, where there is no `.await` left to run
/// it on. A leaked lock is not merely untidy here — it is invisible for the whole TTL, and the
/// scheduler reports the skipped ticks only at `debug` (`scheduler.rs`).
struct LockGuard {
    lock: Arc<dyn JobLock>,
    name: String,
    token: Option<LockToken>,
}

impl LockGuard {
    /// Releases the lock **synchronously**, disarming the drop path.
    ///
    /// The normal exit. `Drop` is the fallback for the case that has no `.await` left to run on,
    /// and it must stay a fallback: a spawned release has not happened yet when `run_now` returns,
    /// so an operator pressing "run now" twice would race their own previous release.
    async fn release(mut self) {
        let Some(token) = self.token.take() else { return };
        if let Err(err) = self.lock.release(&self.name, token).await {
            tracing::warn!(job = %self.name, error = %err, "failed to release the job lock after a manual run");
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Only reached when the run was cancelled — `release` takes the token on the normal path.
        let Some(token) = self.token.take() else { return };
        let lock = Arc::clone(&self.lock);
        let name = self.name.clone();
        // A runtime is always present: this only ever drops inside a task that was polling the run.
        tokio::spawn(async move {
            if let Err(err) = lock.release(&name, token).await {
                // A leaked lock still expires on its own TTL; failing louder than a warning here
                // would mean a release error taking down the request that already finished.
                tracing::warn!(job = %name, error = %err, "failed to release the job lock after a manual run");
            }
        });
    }
}

/// One registered runner: a factory producing one future per invocation.
type Runner = Arc<dyn Fn(DateTime<Utc>) -> BoxFuture<'static, Result<serde_json::Value>> + Send + Sync>;

/// The set of jobs this instance can run on demand.
#[derive(Clone)]
pub struct JobRegistry {
    lock: Arc<dyn JobLock>,
    ttls: JobLockTtls,
    runners: BTreeMap<String, Runner>,
}

impl std::fmt::Debug for JobRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRegistry").field("jobs", &self.runners.keys().collect::<Vec<_>>()).finish()
    }
}

impl JobRegistry {
    /// An empty registry sharing the scheduler's leader lock **and** its per-job lock lifetimes.
    pub fn new(lock: Arc<dyn JobLock>, ttls: JobLockTtls) -> Self {
        Self { lock, ttls, runners: BTreeMap::new() }
    }

    /// Registers the mirror sync worker (decision 07).
    #[must_use]
    pub fn with_mirror(mut self, worker: Arc<MirrorWorker>) -> Self {
        self.runners.insert(
            MIRROR_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "phase": report.phase,
                        "refreshed": report.refreshed,
                        "skipped": report.skipped,
                        "unavailable": report.unavailable,
                        "shadowed": report.shadowed,
                        "alarms_raised": report.alarms_raised,
                        "archives_cached": report.archives_cached,
                        "sweep_complete": report.sweep_complete,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// Registers the search reindex worker (decision 11).
    #[must_use]
    pub fn with_reindex(mut self, worker: Arc<Reindexer>) -> Self {
        self.runners.insert(
            REINDEX_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "indexed": report.indexed,
                        "removed": report.removed,
                        "completed": report.completed,
                        "skipped": report.skipped,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// Registers the download-statistics rollup.
    #[must_use]
    pub fn with_downloads(mut self, worker: Arc<DownloadRollup>) -> Self {
        self.runners.insert(
            DOWNLOAD_ROLLUP_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "downloads": report.downloads,
                        "rows": report.rows,
                        "packages": report.packages,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// Registers the durable work queue's drain (decision 26).
    ///
    /// The report carries `dead_pending` — the standing dead-letter count, not just this run's
    /// — because a dead-lettered sign-in message is an account lockout with no other visible
    /// cause, and a per-run number would read as zero on every tick after the one that failed.
    ///
    /// It also carries `lost`: completions that applied to nothing because the item had been
    /// reaped and re-claimed by another drain ([D45](../../../../docs/roadmap.md), decision 36).
    /// With the leader lease in place that should be unreachable outside a crash window, which is
    /// why a non-zero value is worth an operator's attention rather than a log line nobody reads.
    #[must_use]
    pub fn with_queue(mut self, worker: Arc<QueueWorker>) -> Self {
        self.runners.insert(
            QUEUE_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "claimed": report.claimed,
                        "delivered": report.delivered,
                        "retried": report.retried,
                        "dead": report.dead,
                        "reaped": report.reaped,
                        "lost": report.lost,
                        "dead_pending": report.dead_pending,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// The lock lifetime this registry would use for `job`.
    ///
    /// Exposed so the manual-run path's TTL is observable at all: `JobLock` implementations store
    /// the deadline privately, so a test that only watches `try_acquire` succeed or fail cannot tell
    /// a per-job lifetime from a hardcoded one — which is precisely how D48 survived.
    #[must_use]
    pub fn lock_ttl(&self, job: &str) -> std::time::Duration {
        self.ttls.get(job)
    }

    /// Registers the retention sweeper (decision 30).
    ///
    /// The report is a line per table rather than a total, because "how many rows went" is not the
    /// question an operator has: they want to know which table is still working through a backlog
    /// and which one the database refused.
    #[must_use]
    pub fn with_lifecycle(mut self, worker: Arc<LifecycleWorker>) -> Self {
        self.runners.insert(
            LIFECYCLE_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    let tables: serde_json::Map<String, serde_json::Value> = report
                        .tables
                        .iter()
                        .map(|line| {
                            let value = match &line.outcome {
                                pub_core::retention::TableOutcome::Disabled => {
                                    serde_json::json!({ "state": "keep-forever" })
                                }
                                pub_core::retention::TableOutcome::Skipped => {
                                    serde_json::json!({ "state": "not-reached" })
                                }
                                pub_core::retention::TableOutcome::Swept { deleted, passes, converged } => {
                                    serde_json::json!({
                                        "state": if *converged { "drained" } else { "backlog" },
                                        "deleted": deleted,
                                        "passes": passes,
                                    })
                                }
                                pub_core::retention::TableOutcome::Refused { reason } => {
                                    serde_json::json!({ "state": "refused", "reason": reason })
                                }
                            };
                            (line.table.to_owned(), value)
                        })
                        .collect();
                    Ok(serde_json::json!({
                        "deleted": report.deleted_total(),
                        "refused": report.any_refused(),
                        "tables": tables,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// Registers the unreferenced-blob collector (decision 06 addendum, decision 31).
    #[must_use]
    pub fn with_blob_gc(mut self, worker: Arc<BlobGc>) -> Self {
        self.runners.insert(
            BLOB_GC_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "scanned": report.scanned,
                        "deleted": report.deleted,
                        "bytes": report.bytes,
                        "referenced": report.referenced,
                        "too_young": report.too_young,
                        "contested": report.contested,
                        "unrecognized": report.unrecognized,
                        "shards": report.shards,
                        // A manual run that stopped on its budget has to say so: "deleted 0" and
                        // "did not get there" are the same number and different facts.
                        "converged": report.converged,
                        "resumes_at": report.cursor,
                        "dry_run": report.dry_run,
                    }))
                }
                .boxed()
            }),
        );
        self
    }

    /// Registers the abandoned-staged-upload sweep (decision 31).
    #[must_use]
    pub fn with_staging_sweep(mut self, worker: Arc<StagingSweeper>) -> Self {
        self.runners.insert(
            STAGING_SWEEP_JOB.to_owned(),
            Arc::new(move |now| {
                let worker = Arc::clone(&worker);
                async move {
                    let report = worker.run_once(now).await?;
                    Ok(serde_json::json!({
                        "scanned": report.scanned,
                        "deleted": report.deleted,
                        "bytes": report.bytes,
                        "too_young": report.too_young,
                        "contested": report.contested,
                        "unrecognized": report.unrecognized,
                        "converged": report.converged,
                        "dry_run": report.dry_run,
                    }))
                }
                .boxed()
            }),
        );
        self
    }
}

#[async_trait]
impl JobTrigger for JobRegistry {
    fn names(&self) -> Vec<String> {
        self.runners.keys().cloned().collect()
    }

    async fn run_now(&self, name: &str, now: DateTime<Utc>) -> Result<serde_json::Value> {
        let runner = self.runners.get(name).cloned().ok_or_else(|| Error::NotFound { what: format!("job {name}") })?;
        let Some(token) = self.lock.try_acquire(name, self.ttls.get(name)).await? else {
            return Err(Error::Conflict { message: format!("job {name} is already running on this cluster") });
        };
        // The release has to survive **cancellation**, not just an error return. This future is
        // awaited inside an HTTP handler, under the D13 request deadline — 30 s by default — and a
        // deadline that fires drops the handler future, so a plain `release` after the await is
        // simply never reached. That was survivable while the manual TTL was a hardcoded 300 s; it
        // stopped being survivable when D48 tied it to the job's own lifetime, because the drain's
        // is derived from `jobs.queue.lease_secs` and the retention pass's from its wall-clock
        // budget. An operator who raised `lease_secs` to 1800 because their relay is slow would
        // have wedged sign-in mail for half an hour by pressing "run now" once.
        let guard = LockGuard { lock: Arc::clone(&self.lock), name: name.to_owned(), token: Some(token) };
        let outcome = runner(now).await;
        guard.release().await;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::lock::InMemoryJobLock;

    #[tokio::test]
    async fn an_empty_registry_lists_nothing_and_runs_nothing() {
        let registry = JobRegistry::new(Arc::new(InMemoryJobLock::new()), JobLockTtls::default());
        assert!(registry.names().is_empty());
        let err = registry.run_now("mirror-sync", Utc::now()).await.unwrap_err();
        // A job this instance did not register is indistinguishable from one that does not
        // exist — the admin UI offers exactly what `names()` reports.
        assert_eq!(err.code(), "not_found");
    }

    #[tokio::test]
    async fn a_job_held_by_another_runner_is_a_conflict_not_a_silent_skip() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let mut registry = JobRegistry::new(Arc::clone(&lock), JobLockTtls::default());
        registry.runners.insert("probe".to_owned(), Arc::new(|_| async { Ok(serde_json::json!({})) }.boxed()));

        let token = lock.try_acquire("probe", Duration::from_secs(60)).await.unwrap().expect("free");
        let err = registry.run_now("probe", Utc::now()).await.unwrap_err();
        assert_eq!(err.code(), "conflict");

        lock.release("probe", token).await.unwrap();
        assert_eq!(registry.run_now("probe", Utc::now()).await.unwrap(), serde_json::json!({}));
    }

    #[tokio::test]
    async fn the_lock_is_released_even_when_the_run_fails() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let mut registry = JobRegistry::new(Arc::clone(&lock), JobLockTtls::default());
        registry.runners.insert(
            "flaky".to_owned(),
            Arc::new(|_| async { Err(Error::Internal { message: "boom".to_owned() }) }.boxed()),
        );
        assert!(registry.run_now("flaky", Utc::now()).await.is_err());
        // A failed manual run must not wedge the scheduled one.
        assert!(lock.try_acquire("flaky", Duration::from_secs(1)).await.unwrap().is_some());
    }

    /// A lock that records the TTL every acquisition asked for.
    ///
    /// `InMemoryJobLock` keeps its deadline private, so the duration that actually reached
    /// `try_acquire` is unobservable through it — and a test that cannot observe the duration cannot
    /// tell `self.ttls.get(name)` from a hardcoded 300 s, which is the mutant D48 is about.
    #[derive(Default)]
    struct RecordingLock {
        inner: InMemoryJobLock,
        seen: std::sync::Mutex<Vec<(String, Duration)>>,
    }

    #[async_trait]
    impl JobLock for RecordingLock {
        async fn ping(&self) -> Result<()> {
            self.inner.ping().await
        }

        async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<Option<pub_core::traits::LockToken>> {
            self.seen.lock().unwrap().push((name.to_owned(), ttl));
            self.inner.try_acquire(name, ttl).await
        }

        async fn release(&self, name: &str, token: pub_core::traits::LockToken) -> Result<()> {
            self.inner.release(name, token).await
        }
    }

    #[tokio::test]
    async fn a_manual_run_takes_the_lock_for_the_jobs_configured_ttl() {
        // The property: the duration `run_now` hands to `try_acquire` comes from the shared table,
        // not from a constant of its own. Asserted on the duration itself — the previous version of
        // this test asserted only that the lock was *held*, which is true for any TTL including the
        // hardcoded 300 s this wave deleted.
        let lock = Arc::new(RecordingLock::default());
        let ttls = JobLockTtls::default().set("slow", Duration::from_secs(1800));
        let mut registry = JobRegistry::new(Arc::clone(&lock) as Arc<dyn JobLock>, ttls);
        registry.runners.insert("slow".to_owned(), Arc::new(|_| async { Ok(serde_json::json!({})) }.boxed()));
        registry.runners.insert("plain".to_owned(), Arc::new(|_| async { Ok(serde_json::json!({})) }.boxed()));

        registry.run_now("slow", Utc::now()).await.unwrap();
        registry.run_now("plain", Utc::now()).await.unwrap();

        let seen = lock.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                ("slow".to_owned(), Duration::from_secs(1800)),
                // A job with no entry falls back to the default rather than panicking.
                ("plain".to_owned(), JobLockTtls::DEFAULT),
            ],
            "the manual run must take each job's own lifetime; a hardcoded TTL shows up here"
        );
        assert_eq!(registry.lock_ttl("slow"), Duration::from_secs(1800));
    }

    #[tokio::test]
    async fn a_manual_run_holds_the_lock_for_the_jobs_own_ttl_not_a_hardcoded_one() {
        // D48: this path used a hardcoded 300 s while the scheduler applied one global value to
        // every job. Both now read the same per-job table, and this asserts the registry actually
        // consults it — the observable difference is the TTL the lock is taken for, so the test
        // reads it back off a lock the runner is still holding.
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let ttls = JobLockTtls::default().set("slow", Duration::from_secs(1800));
        let mut registry = JobRegistry::new(Arc::clone(&lock), ttls.clone());
        let seen = Arc::new(std::sync::Mutex::new(None));
        let recorder = Arc::clone(&seen);
        let probe = Arc::clone(&lock);
        registry.runners.insert(
            "slow".to_owned(),
            Arc::new(move |_| {
                let recorder = Arc::clone(&recorder);
                let probe = Arc::clone(&probe);
                async move {
                    // While the runner holds it, a second acquisition must fail — and the TTL it
                    // was taken for is the registry's answer to "how long may this job run".
                    let contended = probe.try_acquire("slow", Duration::from_secs(1)).await.unwrap();
                    *recorder.lock().unwrap() = Some(contended.is_none());
                    Ok(serde_json::json!({}))
                }
                .boxed()
            }),
        );

        registry.run_now("slow", Utc::now()).await.unwrap();
        assert_eq!(*seen.lock().unwrap(), Some(true), "the manual run must hold the job's lock while it runs");
        assert_eq!(ttls.get("slow"), Duration::from_secs(1800));
        // A name nobody configured still runs, on the default rather than on a panic.
        assert_eq!(ttls.get("unregistered"), JobLockTtls::DEFAULT);
    }
}
