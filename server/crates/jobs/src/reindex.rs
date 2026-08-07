//! Search-index rebuild (decision 11).
//!
//! The index is a projection of `packages` + `versions` (`pub_registry::index`), maintained
//! incrementally by every publish, retraction, hard delete, and option change. This job exists
//! because that maintenance is deliberately **best-effort**: an index write that fails must not
//! fail a publish whose bytes and rows are already committed, so something has to close the
//! gap. It is also the only way to populate the index after migration 0007 on an instance that
//! already has packages, and the repair path after a schema or scoring change.
//!
//! Two properties make it safe to run at any time:
//!
//! - **Idempotent.** Rebuilding a document produces exactly what incremental maintenance would
//!   have written — same [`pub_registry::index::build_document`], same rules — so a pass over
//!   an already-correct index changes nothing.
//! - **Chunked and resumable.** `chunk` bounds how long one tick holds the leader lock;
//!   `jobs.cursor` holds the `(format, name)` position, so a restart or a leader change
//!   continues rather than starting over. A finished sweep clears the cursor and the next tick
//!   starts a new one after `resweep_after`.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use pub_core::Result;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::Repositories;
use pub_registry::PackageIndexer;
use serde::{Deserialize, Serialize};

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const REINDEX_JOB: &str = "search-reindex";

/// The phase written alongside the cursor while a sweep is in flight.
const PHASE_SWEEP: &str = "sweep";

/// The phase written when a sweep has completed and the next one is waiting.
const PHASE_IDLE: &str = "idle";

/// Reindex policy (projected from the `[jobs.reindex]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReindexPolicy {
    /// Whether the job is scheduled at all.
    pub enabled: bool,
    /// How often a tick fires.
    pub interval: StdDuration,
    /// Packages rebuilt per tick — the tick's cost bound.
    pub chunk: u32,
    /// How long after a completed sweep the next one starts.
    pub resweep_after: Duration,
}

impl Default for ReindexPolicy {
    fn default() -> Self {
        Self { enabled: false, interval: StdDuration::from_secs(300), chunk: 200, resweep_after: Duration::hours(24) }
    }
}

/// Durable sweep position, stored as `jobs.cursor` JSON.
///
/// The cursor is the repository's opaque `(format, name)` token; `completed_at` is what makes
/// `resweep_after` a *period between sweeps* rather than a period between ticks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SweepCursor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    position: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_at: Option<DateTime<Utc>>,
}

/// What one [`Reindexer::run_once`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReindexReport {
    /// Documents written.
    pub indexed: usize,
    /// Packages dropped from the index (nothing live to show).
    pub removed: usize,
    /// Whether this tick finished the sweep.
    pub completed: bool,
    /// Whether this tick did nothing because the previous sweep is still inside
    /// `resweep_after`.
    pub skipped: bool,
}

/// The reindex worker.
pub struct Reindexer {
    repos: Repositories,
    indexer: Arc<PackageIndexer>,
    policy: ReindexPolicy,
}

impl std::fmt::Debug for Reindexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reindexer").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl Reindexer {
    /// Builds the worker over the configured repositories.
    pub fn new(repos: Repositories, policy: ReindexPolicy) -> Self {
        let indexer = Arc::new(PackageIndexer::new(repos.clone()));
        Self { repos, indexer, policy }
    }

    /// The configured policy.
    pub fn policy(&self) -> &ReindexPolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last reindex".
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(REINDEX_JOB).await?.unwrap_or_else(|| JobState::fresh(REINDEX_JOB, now)))
    }

    /// Rebuilds one chunk, resuming from the durable cursor.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<ReindexReport> {
        let state = self.repos.jobs.begin_run(REINDEX_JOB, now).await?;
        let sweep: SweepCursor =
            state.cursor.as_deref().and_then(|raw| serde_json::from_str(raw).ok()).unwrap_or_default();

        // A completed sweep waits out its window. Checking here rather than in the scheduler
        // keeps the decision with the durable state: a restart must not restart the sweep.
        if sweep.position.is_none()
            && let Some(completed) = sweep.completed_at
            && now - completed < self.policy.resweep_after
        {
            self.repos.jobs.finish_run(REINDEX_JOB, JobOutcome::Success, now).await?;
            return Ok(ReindexReport { skipped: true, ..ReindexReport::default() });
        }

        let outcome = self.indexer.reindex_page(sweep.position.as_deref(), self.policy.chunk).await;
        let page = match outcome {
            Ok(page) => page,
            Err(err) => {
                // The cursor is left untouched, so the next tick retries the same chunk.
                self.repos.jobs.finish_run(REINDEX_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        let completed = !page.has_more;
        let next = if completed {
            SweepCursor { position: None, completed_at: Some(now) }
        } else {
            SweepCursor { position: page.cursor.clone(), completed_at: sweep.completed_at }
        };
        let progress = JobProgress {
            cursor: Some(serde_json::to_string(&next).unwrap_or_default()),
            phase: if completed { PHASE_IDLE.to_owned() } else { PHASE_SWEEP.to_owned() },
            processed: (page.indexed + page.removed) as u64,
            failed: 0,
        };
        self.repos.jobs.checkpoint(REINDEX_JOB, &progress, now).await?;
        self.repos.jobs.finish_run(REINDEX_JOB, JobOutcome::Success, now).await?;

        metrics::counter!("search_reindex_documents_total").increment(page.indexed as u64);
        metrics::counter!("search_reindex_removed_total").increment(page.removed as u64);
        tracing::debug!(indexed = page.indexed, removed = page.removed, completed, "search reindex chunk finished");
        Ok(ReindexReport { indexed: page.indexed, removed: page.removed, completed, skipped: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_is_off_and_chunked() {
        let policy = ReindexPolicy::default();
        assert!(!policy.enabled, "a full-instance sweep is opt-in");
        assert!(policy.chunk > 0, "an unbounded chunk would hold the leader lock for a whole sweep");
    }

    #[test]
    fn the_sweep_cursor_round_trips_through_json() {
        let cursor = SweepCursor { position: Some("abc".to_owned()), completed_at: Some(Utc::now()) };
        let raw = serde_json::to_string(&cursor).unwrap();
        assert_eq!(serde_json::from_str::<SweepCursor>(&raw).unwrap(), cursor);
        // A cursor written by an older build (or a corrupt one) restarts the sweep rather than
        // wedging the job.
        assert_eq!(serde_json::from_str::<SweepCursor>("{}").unwrap(), SweepCursor::default());
        assert!(serde_json::from_str::<SweepCursor>("not json").is_err());
    }
}
