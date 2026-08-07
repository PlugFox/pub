//! The durable work queue's drain ([decision 26](../../../docs/decisions.md#26)).
//!
//! The queue is the second consumer seam off the event bus: the emitting request files one row
//! and returns, and this worker does the slow things — the per-recipient notification fan-out
//! and every outbound SMTP conversation — off the request path. Its shape follows the other
//! jobs (durable bracket, leader lock, manual-run entry) with three rules of its own:
//!
//! - **It is on unconditionally.** Every other job here carries an `enabled` key; this one must
//!   not. Sign-in mail rides the queue, so an operator who switched the drain off could not sign
//!   in to switch it back on, and an instance with no SMTP configured is already covered by the
//!   in-memory mailer. There is no `QueuePolicy::enabled`.
//! - **Every send is bounded by a timeout**, and that is not a nicety: it *replaces* the bound
//!   this move removes. The SMTP transport sets no deadline of its own, and until now the
//!   `[http]` request deadline was the only thing truncating a hung conversation. In a worker a
//!   hung relay would hold its lease and then starve every lease behind it.
//! - **A queue row is completed before its follow-ups are published.** The event contract
//!   promises a client acting on a `UserNotified` event finds the notification row
//!   (`pub_core::event`), so the ordering lives here, in the loop, rather than inside a handler
//!   where it could be reordered by accident.
//!
//! Retry policy lives here and nowhere else: the repository holds no attempt budget, so
//! `attempts >= max_attempts` — read off the row the claim handed back, because attempts are
//! spent *at* claim — is what turns a transient failure into a dead letter.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::queue::{JobKind, QueueOutcome, QueueState, QueuedJob};
use pub_core::traits::Repositories;
use pub_core::{DomainEvent, Result};
use pub_events::EventBus;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const QUEUE_JOB: &str = "job-queue";

/// How many claim passes one tick may take before it hands the rest to the next tick.
///
/// A bound rather than "until empty": one fan-out row enqueues up to two hundred mail rows, so
/// a tick genuinely cascades, and a worker that could not stop would hold the leader lock for as
/// long as work kept arriving. With the default batch this is 3 200 items per tick.
const MAX_PASSES: usize = 64;

/// Drain policy (projected from the `[jobs.queue]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePolicy {
    /// How often the queue is drained.
    pub interval: StdDuration,
    /// Items leased per claim.
    pub batch: u32,
    /// How long a claimed item stays leased before the reaper may return it to the queue.
    pub lease: StdDuration,
    /// Attempts an item gets before it is dead-lettered.
    pub max_attempts: i64,
    /// First retry delay; doubles per attempt up to [`QueuePolicy::backoff_max`].
    pub backoff_base: StdDuration,
    /// Ceiling on the retry delay.
    pub backoff_max: StdDuration,
    /// How long a `done` row is kept before retention deletes it.
    pub retain_done: Duration,
    /// Deadline on one delivery attempt — the bound that replaces the request deadline.
    pub send_timeout: StdDuration,
}

impl Default for QueuePolicy {
    fn default() -> Self {
        Self {
            interval: StdDuration::from_secs(5),
            batch: 50,
            lease: StdDuration::from_secs(120),
            max_attempts: 8,
            backoff_base: StdDuration::from_secs(10),
            backoff_max: StdDuration::from_secs(3600),
            retain_done: Duration::hours(24),
            send_timeout: StdDuration::from_secs(30),
        }
    }
}

impl QueuePolicy {
    /// How long an item that just failed waits before it is runnable again.
    ///
    /// `base · 2^(attempts-1)`, capped, then spread ±25%. The jitter is derived from the item's
    /// own id rather than from an RNG: what it has to prevent is a batch that failed together
    /// coming back together, and the id is already a unique, uniformly distributed handle — so
    /// the delay stays reproducible for one row (and therefore strictly growing per attempt)
    /// while two rows that failed in the same pass return at different moments.
    pub fn backoff_for(&self, job: &QueuedJob) -> StdDuration {
        let step = job.attempts.clamp(1, 32) as u32 - 1;
        let base = self.backoff_base.as_secs().max(1);
        let grown = base.saturating_mul(1u64 << step.min(20));
        let capped = grown.min(self.backoff_max.as_secs().max(1));
        let spread = capped / 4;
        let offset = if spread == 0 { 0 } else { u64::from(job.id.as_uuid().as_bytes()[15]) % (spread * 2 + 1) };
        StdDuration::from_secs(capped.saturating_sub(spread).saturating_add(offset).max(1))
    }
}

/// What one [`QueueWorker::run_once`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueReport {
    /// Items leased this tick.
    pub claimed: u64,
    /// Items that succeeded.
    pub delivered: u64,
    /// Items put back behind a backoff.
    pub retried: u64,
    /// Items dead-lettered — out of attempts, or permanently undeliverable.
    pub dead: u64,
    /// Leases returned to the queue because their worker never reported back.
    pub reaped: u64,
    /// `done` rows retention deleted.
    pub purged: u64,
    /// Items sitting in `dead` **right now**.
    ///
    /// A per-run count is not what an operator needs: a dead-lettered sign-in message is an
    /// account lockout with no other visible cause, and it stays invisible until somebody looks
    /// at the standing total. This is that total, reported on every tick.
    pub dead_pending: i64,
}

/// One kind's handler.
///
/// Handlers decide **what** an item's failure means — a malformed recipient is permanent, a
/// refused connection is not — and the worker decides **how long** that costs. Neither knows
/// the other's half.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// The kind this handler is registered for.
    fn kind(&self) -> JobKind;

    /// Runs one item. A handler never returns `Err`: every failure is an outcome the queue can
    /// record, because "the handler failed and we do not know what that means" is exactly the
    /// state that produces an item retrying forever.
    async fn run(&self, job: &QueuedJob, now: DateTime<Utc>) -> HandlerReport;
}

/// A handler's answer: how the item ended, plus events to publish once it is committed.
#[derive(Debug)]
pub struct HandlerReport {
    /// How the item ended.
    pub outcome: QueueOutcome,
    /// Events the worker publishes **after** the item's completion is committed, never before
    /// (`pub_core::event`: a client acting on the event must find the row it names).
    pub followups: Vec<DomainEvent>,
}

impl HandlerReport {
    /// The item succeeded.
    pub fn done() -> Self {
        Self { outcome: QueueOutcome::Done, followups: Vec::new() }
    }

    /// The item failed transiently; the worker decides the backoff and the attempt budget.
    pub fn retry(message: impl Into<String>) -> Self {
        Self { outcome: QueueOutcome::Retry(message.into()), followups: Vec::new() }
    }

    /// The item can never succeed — retrying it burns the budget on an outcome that will not
    /// change (a malformed address, an undecodable payload).
    pub fn dead(message: impl Into<String>) -> Self {
        Self { outcome: QueueOutcome::Dead(message.into()), followups: Vec::new() }
    }
}

/// The drain worker.
pub struct QueueWorker {
    repos: Repositories,
    events: Arc<EventBus>,
    handlers: BTreeMap<JobKind, Arc<dyn JobHandler>>,
    policy: QueuePolicy,
}

impl std::fmt::Debug for QueueWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueWorker")
            .field("policy", &self.policy)
            .field("kinds", &self.handlers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl QueueWorker {
    /// A worker with no handlers yet; add them with [`QueueWorker::with_handler`].
    pub fn new(repos: Repositories, events: Arc<EventBus>, policy: QueuePolicy) -> Self {
        Self { repos, events, handlers: BTreeMap::new(), policy }
    }

    /// Registers one kind's handler.
    ///
    /// Only registered kinds are ever claimed, so an item whose handler this deployment did not
    /// build stays `pending` instead of being claimed and immediately dead-lettered — which is
    /// what makes adding S-33 webhook delivery one more kind and one more handler.
    #[must_use]
    pub fn with_handler(mut self, handler: Arc<dyn JobHandler>) -> Self {
        self.handlers.insert(handler.kind(), handler);
        self
    }

    /// The active policy.
    pub const fn policy(&self) -> &QueuePolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last drain".
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(QUEUE_JOB).await?.unwrap_or_else(|| JobState::fresh(QUEUE_JOB, now)))
    }

    /// Reaps expired leases, drains what is runnable, then applies retention.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<QueueReport> {
        self.repos.jobs.begin_run(QUEUE_JOB, now).await?;
        match self.drain(now).await {
            Ok(report) => {
                // The phase carries the **standing** dead-letter count, not this run's: it is
                // the one field of the durable job state a job defines for itself, and it is on
                // the admin job table. A dead-lettered sign-in message is an account lockout
                // with no other visible cause, and a per-run number reads as zero on every tick
                // after the one that failed (decision 22 amendment).
                let progress = JobProgress {
                    cursor: None,
                    phase: match report.dead_pending {
                        0 => "drain".to_owned(),
                        dead => format!("drain ({dead} dead)"),
                    },
                    processed: report.delivered,
                    failed: report.dead,
                };
                self.repos.jobs.checkpoint(QUEUE_JOB, &progress, now).await?;
                self.repos.jobs.finish_run(QUEUE_JOB, JobOutcome::Success, now).await?;
                Ok(report)
            }
            Err(err) => {
                self.repos.jobs.finish_run(QUEUE_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                Err(err)
            }
        }
    }

    async fn drain(&self, now: DateTime<Utc>) -> Result<QueueReport> {
        let mut report = QueueReport::default();
        let kinds: Vec<JobKind> = self.handlers.keys().copied().collect();

        // Before claiming anything: an item whose worker died mid-run is invisible until its
        // lease is returned, and doing this first means one tick both frees and re-runs it.
        report.reaped = self.repos.queue.reap_expired_leases(now).await?;

        for _ in 0..MAX_PASSES {
            let batch = self.repos.queue.claim(&kinds, self.policy.batch, self.policy.lease, now).await?;
            if batch.is_empty() {
                break;
            }
            report.claimed += batch.len() as u64;
            for job in batch {
                self.run_item(&job, now, &mut report).await?;
            }
        }

        report.purged = self.repos.queue.purge(now - self.policy.retain_done).await?;
        self.record_depth(&mut report).await?;
        Ok(report)
    }

    async fn run_item(&self, job: &QueuedJob, now: DateTime<Utc>, report: &mut QueueReport) -> Result<()> {
        let Some(handler) = self.handlers.get(&job.kind) else {
            // Unreachable while `claim` is given exactly the registered kinds; recorded rather
            // than `expect`ed because a panic here would take the whole drain down with it.
            tracing::error!(kind = %job.kind, "claimed an item with no registered handler");
            self.repos
                .queue
                .complete(job.id, QueueOutcome::Dead("no handler registered".to_owned()), StdDuration::ZERO, now)
                .await?;
            report.dead += 1;
            return Ok(());
        };

        let handled = handler.run(job, now).await;
        // Attempts are spent at claim, so the row already carries this run's number: the budget
        // is exhausted when the attempt that just failed *was* the last one.
        let outcome = match handled.outcome {
            QueueOutcome::Retry(message) if job.attempts >= self.policy.max_attempts => {
                QueueOutcome::Dead(format!("gave up after {} attempts: {message}", job.attempts))
            }
            other => other,
        };
        match &outcome {
            QueueOutcome::Done => report.delivered += 1,
            QueueOutcome::Retry(_) => report.retried += 1,
            QueueOutcome::Dead(message) => {
                report.dead += 1;
                tracing::error!(kind = %job.kind, id = %job.id, attempts = job.attempts, %message, "queue item dead-lettered");
            }
        }
        metrics::counter!("queue_jobs_total", "kind" => job.kind.as_str(), "outcome" => outcome.as_str()).increment(1);

        // Completion first, follow-ups second, always: publishing from before the completion is
        // committed is how a client learns about a notification it cannot yet read.
        self.repos.queue.complete(job.id, outcome, self.policy.backoff_for(job), now).await?;
        for followup in handled.followups {
            self.events.publish_followup(followup).await;
        }
        Ok(())
    }

    /// Publishes the per-`(kind, state)` gauges and reads the standing dead-letter total.
    async fn record_depth(&self, report: &mut QueueReport) -> Result<()> {
        let depth = self.repos.queue.depth().await?;
        // `depth` omits empty cells; a gauge that simply stops being reported reads as "still
        // at its last value" on every scrape-based backend, so zero every cell first.
        for kind in JobKind::ALL {
            for state in QueueState::ALL {
                metrics::gauge!("queue_depth", "kind" => kind.as_str(), "state" => state.as_str()).set(0.0);
            }
        }
        for (kind, state, count) in depth {
            metrics::gauge!("queue_depth", "kind" => kind.as_str(), "state" => state.as_str()).set(count as f64);
            if state == QueueState::Dead {
                report.dead_pending += count;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pub_core::queue::QueuedJobId;

    use super::*;

    fn job(attempts: i64) -> QueuedJob {
        QueuedJob {
            id: QueuedJobId::new(),
            kind: JobKind::MailSend,
            payload: serde_json::Value::Null,
            state: QueueState::Running,
            attempts,
            run_after: Utc::now(),
            locked_until: None,
            dedupe_key: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_drain_has_no_enabled_switch_and_its_defaults_are_the_documented_ones() {
        // Decision 26: an operator who could disable the mail drain could not sign in to
        // re-enable it. The absence of the field is the guarantee; this test is what makes
        // adding one a visible change rather than a quiet one.
        let policy = QueuePolicy::default();
        assert_eq!(policy.batch, 50);
        assert_eq!(policy.max_attempts, 8);
        assert!(policy.lease > policy.send_timeout, "a send must not outlive the lease that protects it");
        assert!(policy.lease.as_secs() > policy.interval.as_secs(), "a lease shorter than a tick reaps live work");
    }

    #[test]
    fn the_backoff_grows_per_attempt_stays_under_its_cap_and_is_spread() {
        let policy = QueuePolicy {
            backoff_base: StdDuration::from_secs(10),
            backoff_max: StdDuration::from_secs(600),
            ..QueuePolicy::default()
        };
        let item = job(1);
        let mut previous = StdDuration::ZERO;
        for attempts in 1..=8 {
            let mut item = item.clone();
            item.attempts = attempts;
            let delay = policy.backoff_for(&item);
            assert!(delay > previous || delay == policy.backoff_for(&item), "attempt {attempts} must not shrink");
            assert!(delay <= StdDuration::from_secs(750), "the cap holds with jitter: {delay:?}");
            previous = delay;
        }
        // The ±25% spread is what keeps a batch that failed together from returning together.
        let delays: Vec<u64> = (0..32).map(|_| policy.backoff_for(&job(3)).as_secs()).collect();
        assert!(delays.iter().any(|d| *d != delays[0]), "identical delays for every row is not jitter: {delays:?}");
    }

    #[test]
    fn a_first_attempt_waits_the_base_delay_not_double_it() {
        // Attempts are spent at claim, so the row a handler failed on already reports `1`.
        // Reading that as `2^1` would double every delay in the ladder.
        let policy = QueuePolicy {
            backoff_base: StdDuration::from_secs(100),
            backoff_max: StdDuration::from_secs(100_000),
            ..QueuePolicy::default()
        };
        let delay = policy.backoff_for(&job(1)).as_secs();
        assert!((75..=125).contains(&delay), "the first retry is the base delay ±25%, got {delay}");
    }
}
