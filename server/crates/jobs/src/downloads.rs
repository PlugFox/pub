//! Download-statistics rollup (docs/architecture.md `download_stats`).
//!
//! Two steps per tick, in this order:
//!
//! 1. **Flush** the in-process counter buffer (`pub_registry::DownloadRecorder`) into the daily
//!    rollup table with an additive upsert. The buffer is what keeps a download from costing a
//!    database round trip; this job is the other half of that bargain, and the flush interval
//!    is therefore also the window a crash can lose.
//! 2. **Write back** the touched packages' totals onto their search documents, so
//!    `sort:downloads` and the package cards read one indexed column instead of aggregating
//!    the rollup table on every request.
//!
//! Only packages that actually moved are written back — the flush reports them — so a quiet
//! instance does no work beyond one empty drain, and a busy one pays proportionally to the
//! number of *distinct* packages downloaded rather than to the number of downloads.
//!
//! Unlike the mirror and GC jobs this one is **on by default**: it is the only thing that ever
//! moves buffered counts into the database, and an operator who disables it does not get
//! "fewer statistics", they get a counter buffer that fills up and starts dropping.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use pub_core::Result;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::Repositories;
use pub_registry::DownloadRecorder;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const DOWNLOAD_ROLLUP_JOB: &str = "download-rollup";

/// Rollup policy (projected from the `[jobs.downloads]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownloadRollupPolicy {
    /// Whether the job is scheduled at all.
    pub enabled: bool,
    /// How often the buffer is flushed — also the width of the window a crash can lose.
    pub interval: StdDuration,
    /// The trailing window behind the "recent downloads" figure.
    pub recent_window: Duration,
}

impl Default for DownloadRollupPolicy {
    fn default() -> Self {
        Self { enabled: true, interval: StdDuration::from_secs(60), recent_window: Duration::days(30) }
    }
}

impl DownloadRollupPolicy {
    /// The first day inside the trailing window at `now`.
    pub fn since(&self, now: DateTime<Utc>) -> chrono::NaiveDate {
        (now - self.recent_window).date_naive()
    }
}

/// What one [`DownloadRollup::run_once`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RollupReport {
    /// Downloads folded into the rollup table.
    pub downloads: i64,
    /// Rollup rows inserted or updated.
    pub rows: u64,
    /// Packages whose denormalized totals were refreshed.
    pub packages: usize,
}

/// The rollup worker.
pub struct DownloadRollup {
    repos: Repositories,
    recorder: Arc<DownloadRecorder>,
    policy: DownloadRollupPolicy,
}

impl std::fmt::Debug for DownloadRollup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadRollup").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl DownloadRollup {
    /// Builds the worker over the shared counter buffer.
    ///
    /// The `Arc` is the same one the HTTP layer holds: the buffer lives in the process, so the
    /// job and the download handler have to be looking at one map.
    pub fn new(repos: Repositories, recorder: Arc<DownloadRecorder>, policy: DownloadRollupPolicy) -> Self {
        Self { repos, recorder, policy }
    }

    /// The configured policy.
    pub fn policy(&self) -> &DownloadRollupPolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last rollup".
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(DOWNLOAD_ROLLUP_JOB).await?.unwrap_or_else(|| JobState::fresh(DOWNLOAD_ROLLUP_JOB, now)))
    }

    /// Flushes the buffer and refreshes the touched packages' totals.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<RollupReport> {
        self.repos.jobs.begin_run(DOWNLOAD_ROLLUP_JOB, now).await?;
        match self.rollup(now).await {
            Ok(report) => {
                let progress = JobProgress {
                    cursor: None,
                    phase: "flush".to_owned(),
                    processed: report.downloads.max(0) as u64,
                    failed: 0,
                };
                self.repos.jobs.checkpoint(DOWNLOAD_ROLLUP_JOB, &progress, now).await?;
                self.repos.jobs.finish_run(DOWNLOAD_ROLLUP_JOB, JobOutcome::Success, now).await?;
                metrics::counter!("downloads_total").increment(report.downloads.max(0) as u64);
                Ok(report)
            }
            Err(err) => {
                // The recorder put its deltas back, so the next tick retries them.
                self.repos.jobs.finish_run(DOWNLOAD_ROLLUP_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                Err(err)
            }
        }
    }

    async fn rollup(&self, now: DateTime<Utc>) -> Result<RollupReport> {
        let flushed = self.recorder.flush(self.repos.stats.as_ref()).await?;
        if flushed.packages.is_empty() {
            return Ok(RollupReport::default());
        }

        let since = self.policy.since(now);
        let totals = self.repos.stats.totals_for(&flushed.packages, since).await?;
        let mut written = 0usize;
        for entry in totals {
            // A package whose document was removed (every version hard-deleted) simply has
            // nothing to update — `set_downloads` is a no-op there by contract.
            self.repos.search.set_downloads(entry.package_id, entry.totals).await?;
            written += 1;
        }
        Ok(RollupReport { downloads: flushed.downloads, rows: flushed.rows, packages: written })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn the_rollup_is_on_by_default() {
        // Off, this job does not mean "no statistics" — it means a buffer that fills up and
        // starts dropping counts.
        assert!(DownloadRollupPolicy::default().enabled);
    }

    #[test]
    fn the_recent_window_is_a_trailing_day_range() {
        let policy = DownloadRollupPolicy { recent_window: Duration::days(30), ..DownloadRollupPolicy::default() };
        let now = Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap();
        assert_eq!(policy.since(now), Utc.with_ymd_and_hms(2026, 7, 8, 12, 0, 0).unwrap().date_naive());
    }
}
