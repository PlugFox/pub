//! Retention: the one job in the instance that deletes rows
//! ([decision 30](../../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature),
//! [S-23](../../../../docs/security.md#5-audit--abuse)).
//!
//! Six tables used to grow without a bound — `sessions`, `invitations`, `notifications`,
//! `download_stats`, `audit_log` and `job_queue`. The last of those had retention already, spent as
//! three unbounded `DELETE`s on every five-second drain tick, outside that drain's own wall-clock
//! budget ([D47](../../../../docs/roadmap.md)). This job is where all of it lives now, and four
//! properties are the reason it is one job rather than a clause in six:
//!
//! - **Every delete is bounded, and a bound needs a loop.** A repository method deletes at most one
//!   `batch` and reports how many rows that was; [`LifecycleWorker::sweep_table`] loops until a pass
//!   comes back short. On SQLite the bound is the load-bearing part: one unbounded `DELETE` holds
//!   the process's single writer for its full duration, and a hold past the 5 s busy timeout turns a
//!   concurrent publish-finalize or sign-in into `SQLITE_BUSY` rather than a wait. Steady state is
//!   one short statement per table; the shapes that release a whole backlog at once are ordinary
//!   operator actions — lowering a window, restoring a backup, a forward clock correction, a stop
//!   long enough for a block of rows to cross the cutoff.
//! - **The loop is bounded too.** A backlog large enough to outlive the pass's budget is drained
//!   across ticks, and the report says so ([`TableOutcome::Swept::converged`]) rather than letting
//!   "there is nothing left" and "I ran out of time" look identical.
//! - **A refusal disables one table, not the pass.** On a Postgres provisioned per the hardened
//!   S-22 template the audit prune can be refused at the database, because the app role holds
//!   `EXECUTE` on `pub_audit_prune` and no `DELETE` on `audit_log`. That is reported as
//!   [`TableOutcome::Refused`], logged with the grant an operator needs, and the remaining tables
//!   are still swept. An error return here would mean a missing grant on one table stops sessions
//!   from ever being purged.
//! - **Order is oldest-first inside a table and cheapest-first across them.** The queue's
//!   `suppressed` rows go first: they are filed by an *unauthenticated* endpoint, one per
//!   policy-rejected sign-in, each carrying the attempted address in the clear, and nothing reads
//!   one after the request that filed it returned (S-04.a). They have the shortest window in the
//!   product and they are the rows whose deletion should never be the thing that ran out of budget.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::queue::{QueuePurged, QueueRetention, QueueState};
use pub_core::retention::{RetentionPolicy, RetentionReport, TableOutcome};
use pub_core::traits::Repositories;
use pub_core::{Error, Result};
use tokio::time::Instant;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const LIFECYCLE_JOB: &str = "lifecycle-purge";

/// Ceiling on batches per table per pass.
///
/// The wall-clock budget is the real bound; this exists so a repository that reports a full batch
/// while deleting nothing — a predicate that cannot make progress — spins a bounded number of times
/// instead of until the budget expires. Both bounds are cheap and they fail differently.
const MAX_BATCHES_PER_TABLE: u32 = 512;

/// What the lifecycle job is configured to delete and how hard it may work at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecyclePolicy {
    /// How often a pass fires.
    pub interval: StdDuration,
    /// Per-table windows plus the batch bound and the pass budget.
    pub retention: RetentionPolicy,
    /// The queue's own per-state windows, read from `[jobs.queue]` where they already live and are
    /// already validated: they are per-*state* properties of that one table, and renaming them into
    /// this section would break every existing config file for no behavioural gain.
    pub queue_done: Duration,
    /// Window for `suppressed` rows — the shortest in the product, and the security-relevant one.
    pub queue_suppressed: Duration,
    /// Window for dead letters — long, because a dead-lettered sign-in message is an account
    /// lockout with no other visible cause, and bounded all the same.
    pub queue_dead: Duration,
}

/// The retention sweeper.
pub struct LifecycleWorker {
    repos: Repositories,
    policy: LifecyclePolicy,
}

impl std::fmt::Debug for LifecycleWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleWorker").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl LifecycleWorker {
    /// Builds the sweeper over the configured repositories.
    pub fn new(repos: Repositories, policy: LifecyclePolicy) -> Self {
        Self { repos, policy }
    }

    /// The configured policy.
    pub fn policy(&self) -> &LifecyclePolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last retention pass", never-run included.
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(LIFECYCLE_JOB).await?.unwrap_or_else(|| JobState::fresh(LIFECYCLE_JOB, now)))
    }

    /// Runs one retention pass over every table.
    ///
    /// Returns `Ok` whenever the pass completed, including when a table was refused: a refusal is a
    /// reported outcome, and the run is recorded as a *failure* in the durable job state so the
    /// admin surface and `/metrics` both show it, without the error propagating and taking the
    /// other tables' sweeps with it.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<RetentionReport> {
        self.repos.jobs.begin_run(LIFECYCLE_JOB, now).await?;
        let started = Instant::now();
        let report = match self.sweep(now, started).await {
            Ok(report) => report,
            Err(err) => {
                self.repos.jobs.finish_run(LIFECYCLE_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        let refusals: Vec<&str> =
            report.tables.iter().filter(|line| line.outcome.is_refused()).map(|line| line.table).collect();
        let outcome = if refusals.is_empty() {
            JobOutcome::Success
        } else {
            JobOutcome::Failure(format!("retention refused by the database for: {}", refusals.join(", ")))
        };
        self.repos.jobs.finish_run(LIFECYCLE_JOB, outcome, now).await?;

        let unconverged = report.unconverged();
        let progress = JobProgress {
            cursor: None,
            phase: if unconverged.is_empty() {
                "drained".to_owned()
            } else {
                // Visible in the admin jobs table, which renders `phase`: a backlog still in
                // progress is a state an operator should be able to read without parsing JSON.
                format!("backlog: {}", unconverged.join(", "))
            },
            processed: report.deleted_total(),
            failed: refusals.len() as u64,
        };
        self.repos.jobs.checkpoint(LIFECYCLE_JOB, &progress, now).await?;

        for line in &report.tables {
            // Emitted for every table, including the ones that deleted nothing: a counter that
            // only appears once a table starts shrinking is a counter whose absence reads as
            // "healthy" on every scrape-based backend.
            metrics::counter!("retention_deleted_total", "table" => line.table).increment(line.outcome.deleted());
        }
        metrics::gauge!("retention_refused_tables").set(refusals.len() as f64);
        metrics::gauge!("retention_backlog_tables").set(unconverged.len() as f64);
        metrics::gauge!("retention_skipped_tables").set(report.skipped().len() as f64);
        tracing::info!(
            job = LIFECYCLE_JOB,
            deleted = report.deleted_total(),
            refused = refusals.len(),
            backlog = unconverged.len(),
            "retention pass finished"
        );
        Ok(report)
    }

    async fn sweep(&self, now: DateTime<Utc>, started: Instant) -> Result<RetentionReport> {
        let mut report = RetentionReport::default();
        let policy = self.policy.retention;

        // The queue first, and its `suppressed` lane first inside that: those rows hold addresses
        // typed at a login form by unauthenticated callers on the shortest window in the product,
        // so they are never the deletion that ran out of budget.
        self.sweep_queue(now, started, &mut report).await;

        // Audit second, right after the queue, and ahead of the tables whose loss is cosmetic. It
        // is the window with a compliance requirement behind it, and with one shared budget the
        // sweep order decides who starves: last place on a backlogged instance means never swept.
        // A refusal here no longer costs the others anything — it is an outcome, not an error.
        let audit = RetentionPolicy::cutoff(policy.audit, now);
        let outcome = self
            .sweep_table(started, audit, |cutoff, batch| {
                let repos = self.repos.clone();
                async move { repos.audit.prune_before(cutoff, now, batch).await }
            })
            .await;
        if let TableOutcome::Refused { reason } = &outcome {
            tracing::error!(
                job = LIFECYCLE_JOB,
                error = %reason,
                "audit retention was refused by the database; grant EXECUTE ON FUNCTION \
                 pub_audit_prune(TIMESTAMPTZ, INT) to the application role (see docs/ops/monitoring.md)"
            );
        }
        report.record("audit_log", outcome);

        let sessions = RetentionPolicy::cutoff(policy.sessions, now);
        let outcome = self
            .sweep_table(started, sessions, |cutoff, batch| {
                let repos = self.repos.clone();
                async move { repos.sessions.purge_before(cutoff, batch).await }
            })
            .await;
        report.record("sessions", outcome);

        let invitations = RetentionPolicy::cutoff(policy.invitations, now);
        let outcome = self
            .sweep_table(started, invitations, |cutoff, batch| {
                let repos = self.repos.clone();
                async move { repos.orgs.purge_invitations_before(cutoff, batch).await }
            })
            .await;
        report.record("invitations", outcome);

        let notifications = RetentionPolicy::cutoff(policy.notifications, now);
        let outcome = self
            .sweep_table(started, notifications, |cutoff, batch| {
                let repos = self.repos.clone();
                async move { repos.notifications.purge_before(cutoff, batch).await }
            })
            .await;
        report.record("notifications", outcome);

        let stats = RetentionPolicy::cutoff(policy.download_stats, now);
        let outcome = self
            .sweep_table(started, stats, |cutoff, batch| {
                let repos = self.repos.clone();
                async move { repos.stats.purge_before(cutoff.date_naive(), batch).await }
            })
            .await;
        report.record("download_stats", outcome);

        Ok(report)
    }

    /// One table's bounded, converging sweep.
    ///
    /// `None` for the cutoff is "keep forever" and is reported as [`TableOutcome::Disabled`] rather
    /// than silently skipped — a table missing from the report reads as one the job forgot.
    async fn sweep_table<F, Fut>(
        &self,
        started: Instant,
        cutoff: Option<DateTime<Utc>>,
        mut delete_batch: F,
    ) -> TableOutcome
    where
        F: FnMut(DateTime<Utc>, u32) -> Fut,
        Fut: Future<Output = Result<u64>>,
    {
        let Some(cutoff) = cutoff else { return TableOutcome::Disabled };
        if started.elapsed() >= self.policy.retention.budget {
            // Never reached. Reported as its own outcome rather than as an empty unconverged sweep:
            // a table the pass runs out of budget before touching, pass after pass, has no
            // retention at all, and that must not read the same as one making progress.
            return TableOutcome::Skipped;
        }
        let batch = self.policy.retention.batch.max(1);
        let mut deleted = 0_u64;
        let mut passes = 0_u32;

        loop {
            if started.elapsed() >= self.policy.retention.budget {
                // Out of time with work possibly left: not converged, and the report says so.
                return TableOutcome::Swept { deleted, passes, converged: false };
            }
            match delete_batch(cutoff, batch).await {
                Ok(rows) => {
                    deleted += rows;
                    passes += 1;
                    if rows < u64::from(batch) {
                        return TableOutcome::Swept { deleted, passes, converged: true };
                    }
                    if passes >= MAX_BATCHES_PER_TABLE {
                        return TableOutcome::Swept { deleted, passes, converged: false };
                    }
                }
                Err(err) => {
                    // Every error is a refusal from this job's point of view: it names the table,
                    // carries the database's own message, and does not abort the pass. A privilege
                    // error and a transient connection error want the same handling here — report,
                    // keep going, try again next tick.
                    return TableOutcome::Refused { reason: refusal_reason(&err) };
                }
            }
        }
    }

    /// The queue's three terminal states, swept oldest-window-first.
    ///
    /// One repository call covers all three states, so the convergence loop is written out here
    /// rather than reusing [`Self::sweep_table`]: a pass is short only when *every* state came back
    /// short.
    ///
    /// It reports **three** lines rather than one, and that is not cosmetic. Decision 26 calls the
    /// dead-letter deletion "the one deletion here that destroys a record somebody may still need,
    /// so it is the one that is never silent" — a single `job_queue` total would fold it into the
    /// completed rows nobody misses, leaving that promise visible only in a metric label. The three
    /// windows are configured separately in `[jobs.queue]`; they are reported separately too.
    async fn sweep_queue(&self, now: DateTime<Utc>, started: Instant, report: &mut RetentionReport) {
        let retention = QueueRetention {
            done_before: now - self.policy.queue_done,
            suppressed_before: now - self.policy.queue_suppressed,
            dead_before: now - self.policy.queue_dead,
        };
        let batch = self.policy.retention.batch.max(1);
        let mut totals = QueuePurged::default();
        let mut passes = 0_u32;
        let mut refusal = None;
        let mut converged = false;

        loop {
            if started.elapsed() >= self.policy.retention.budget {
                break;
            }
            match self.repos.queue.purge(&retention, batch).await {
                Ok(purged) => {
                    passes += 1;
                    totals.done += purged.done;
                    totals.suppressed += purged.suppressed;
                    totals.dead += purged.dead;
                    for (state, count) in [
                        (QueueState::Done, purged.done),
                        (QueueState::Suppressed, purged.suppressed),
                        (QueueState::Dead, purged.dead),
                    ] {
                        metrics::counter!("queue_retention_deleted_total", "state" => state.as_str()).increment(count);
                    }
                    let full = u64::from(batch);
                    if purged.done < full && purged.suppressed < full && purged.dead < full {
                        converged = true;
                        break;
                    }
                    if passes >= MAX_BATCHES_PER_TABLE {
                        break;
                    }
                }
                Err(err) => {
                    refusal = Some(refusal_reason(&err));
                    break;
                }
            }
        }

        if totals.dead > 0 {
            tracing::warn!(
                deleted = totals.dead,
                retained_days = self.policy.queue_dead.num_days(),
                "retention deleted dead-lettered queue items"
            );
        }
        for (table, deleted) in [
            ("job_queue:done", totals.done),
            ("job_queue:suppressed", totals.suppressed),
            ("job_queue:dead", totals.dead),
        ] {
            let outcome = match &refusal {
                Some(reason) => TableOutcome::Refused { reason: reason.clone() },
                None => TableOutcome::Swept { deleted, passes, converged },
            };
            report.record(table, outcome);
        }
    }
}

impl LifecyclePolicy {
    /// Whether the configured audit window respects the S-22.a floor.
    ///
    /// The config validator refuses to build a policy that fails this; the method exists so that
    /// check and this job's own expectation are the same expression rather than two copies of a
    /// number.
    #[must_use]
    pub fn audit_window_is_above_the_floor(&self) -> bool {
        self.retention.audit.is_none_or(|window| window >= RetentionPolicy::AUDIT_FLOOR)
    }
}

/// The message a refusal carries: the database's own text, so an operator sees the grant or the
/// constraint rather than a category.
fn refusal_reason(err: &Error) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(batch: u32, budget: StdDuration) -> LifecyclePolicy {
        LifecyclePolicy {
            interval: StdDuration::from_secs(900),
            retention: RetentionPolicy {
                audit: Some(Duration::days(730)),
                sessions: Some(Duration::days(30)),
                invitations: Some(Duration::days(30)),
                notifications: Some(Duration::days(180)),
                download_stats: None,
                batch,
                budget,
            },
            queue_done: Duration::hours(24),
            queue_suppressed: Duration::hours(1),
            queue_dead: Duration::days(30),
        }
    }

    #[test]
    fn the_default_shape_deletes_but_never_download_stats() {
        let policy = policy(1_000, StdDuration::from_secs(60));
        // Retention has no off switch of its own — every window is one, and `0` is "keep forever"
        // — with the one table that ships keeping forever.
        assert!(policy.audit_window_is_above_the_floor());
        assert_eq!(policy.retention.download_stats, None);
    }

    #[test]
    fn a_window_below_the_audit_floor_is_detectable_before_a_pass() {
        let mut policy = policy(1_000, StdDuration::from_secs(60));
        policy.retention.audit = Some(Duration::days(29));
        assert!(!policy.audit_window_is_above_the_floor());
    }
}
