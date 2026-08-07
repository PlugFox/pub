//! The manual-run registry behind `POST /api/v1/admin/jobs/{job}/run`.
//!
//! The admin surface needs two things the scheduler does not expose: *which* jobs this instance
//! actually registered, and a way to run one out of band. Both live here rather than in the
//! scheduler because a manual run is not a tick — it has a caller waiting for a result, and it
//! must not be silently skipped when the leader lock is held elsewhere.
//!
//! Two rules make an operator-triggered run safe:
//!
//! - **It takes the same [`JobLock`] the scheduler takes**, under the same name. A manual sweep
//!   racing a scheduled one would mean two writers on one durable cursor, which is precisely
//!   the state the lock exists to prevent. A lock held elsewhere is answered with
//!   [`Error::Conflict`] rather than a no-op: "it is already running" is information.
//! - **Only registered jobs are listed and runnable.** A job the operator disabled is not in
//!   the map, so the button for it does not exist — the same "a job that is not registered
//!   cannot tick" property the scheduler relies on, extended to the manual path.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::FutureExt as _;
use futures::future::BoxFuture;
use pub_core::traits::{JobLock, JobTrigger};
use pub_core::{Error, Result};

use crate::downloads::{DOWNLOAD_ROLLUP_JOB, DownloadRollup};
use crate::gc::{BLOB_GC_JOB, BlobGc};
use crate::mirror::{MIRROR_JOB, MirrorWorker};
use crate::reindex::{REINDEX_JOB, Reindexer};

/// How long a manually triggered run may hold the job lock.
const MANUAL_LOCK_TTL: Duration = Duration::from_secs(300);

/// One registered runner: a factory producing one future per invocation.
type Runner = Arc<dyn Fn(DateTime<Utc>) -> BoxFuture<'static, Result<serde_json::Value>> + Send + Sync>;

/// The set of jobs this instance can run on demand.
#[derive(Clone)]
pub struct JobRegistry {
    lock: Arc<dyn JobLock>,
    runners: BTreeMap<String, Runner>,
}

impl std::fmt::Debug for JobRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRegistry").field("jobs", &self.runners.keys().collect::<Vec<_>>()).finish()
    }
}

impl JobRegistry {
    /// An empty registry sharing the scheduler's leader lock.
    pub fn new(lock: Arc<dyn JobLock>) -> Self {
        Self { lock, runners: BTreeMap::new() }
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

    /// Registers the unreferenced-blob collector (decision 06 addendum).
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
                        "staged": report.staged,
                        "unrecognized": report.unrecognized,
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
        if !self.lock.try_acquire(name, MANUAL_LOCK_TTL).await? {
            return Err(Error::Conflict { message: format!("job {name} is already running on this cluster") });
        }
        let outcome = runner(now).await;
        if let Err(err) = self.lock.release(name).await {
            // A leaked lock expires on its own TTL; failing an otherwise successful run over
            // the release would be the worse answer.
            tracing::warn!(job = name, error = %err, "failed to release the job lock after a manual run");
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::InMemoryJobLock;

    #[tokio::test]
    async fn an_empty_registry_lists_nothing_and_runs_nothing() {
        let registry = JobRegistry::new(Arc::new(InMemoryJobLock::new()));
        assert!(registry.names().is_empty());
        let err = registry.run_now("mirror-sync", Utc::now()).await.unwrap_err();
        // A job this instance did not register is indistinguishable from one that does not
        // exist — the admin UI offers exactly what `names()` reports.
        assert_eq!(err.code(), "not_found");
    }

    #[tokio::test]
    async fn a_job_held_by_another_runner_is_a_conflict_not_a_silent_skip() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let mut registry = JobRegistry::new(Arc::clone(&lock));
        registry.runners.insert("probe".to_owned(), Arc::new(|_| async { Ok(serde_json::json!({})) }.boxed()));

        assert!(lock.try_acquire("probe", Duration::from_secs(60)).await.unwrap());
        let err = registry.run_now("probe", Utc::now()).await.unwrap_err();
        assert_eq!(err.code(), "conflict");

        lock.release("probe").await.unwrap();
        assert_eq!(registry.run_now("probe", Utc::now()).await.unwrap(), serde_json::json!({}));
    }

    #[tokio::test]
    async fn the_lock_is_released_even_when_the_run_fails() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let mut registry = JobRegistry::new(Arc::clone(&lock));
        registry.runners.insert(
            "flaky".to_owned(),
            Arc::new(|_| async { Err(Error::Internal { message: "boom".to_owned() }) }.boxed()),
        );
        assert!(registry.run_now("flaky", Utc::now()).await.is_err());
        // A failed manual run must not wedge the scheduled one.
        assert!(lock.try_acquire("flaky", Duration::from_secs(1)).await.unwrap());
    }
}
