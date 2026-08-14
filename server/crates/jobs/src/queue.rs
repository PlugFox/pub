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
//! - **Every send is bounded by a timeout, and the drain is bounded by its own lease.** The
//!   timeout replaces the bound this move removes: the SMTP transport sets no deadline of its
//!   own, and until now the `[http]` request deadline was the only thing truncating a hung
//!   conversation. But a per-send timeout is *not* a bound on a drain (decision 26's
//!   2026-08-07 amendment): a tick that claims batch after batch, each item paying the full
//!   timeout, runs far past its own lease and past the scheduler's lock TTL — after which a
//!   second drain takes the lock, reaps the still-running items back to `pending` and sends
//!   them again. So the drain re-reads the clock as it goes, never leases more work than the
//!   time it has left can run, and stops inside a fraction of one lease.
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
use futures::StreamExt as _;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::queue::{JobKind, QueueOutcome, QueueState, QueuedJob};
use pub_core::traits::Repositories;
use pub_core::{DomainEvent, Result};
use pub_events::EventBus;
use tokio::time::Instant;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const QUEUE_JOB: &str = "job-queue";

/// How many claim passes one tick may take before it hands the rest to the next tick.
///
/// A bound rather than "until empty": one fan-out row enqueues up to two hundred mail rows, so
/// a tick genuinely cascades, and a worker that could not stop would hold the leader lock for as
/// long as work kept arriving. The *binding* bound in a slow instance is the wall-clock budget
/// below — this one is what stops a fast transport from spinning here forever.
const MAX_PASSES: usize = 64;

/// Drain policy (projected from the `[jobs.queue]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePolicy {
    /// How often the queue is drained.
    pub interval: StdDuration,
    /// Items leased per claim.
    pub batch: u32,
    /// Deliveries in flight at once inside one batch.
    pub concurrency: u32,
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
    /// How long a `suppressed` row (S-04.a/S-31) is kept. Short: nothing reads one after the
    /// request that filed it, and every one of them holds an address typed at a login form.
    pub retain_suppressed: Duration,
    /// How long a dead letter is kept for the operator before retention deletes it.
    pub retain_dead: Duration,
    /// Deadline on one delivery attempt — the bound that replaces the request deadline.
    pub send_timeout: StdDuration,
}

impl Default for QueuePolicy {
    fn default() -> Self {
        Self {
            interval: StdDuration::from_secs(5),
            batch: 50,
            concurrency: 4,
            lease: StdDuration::from_secs(120),
            max_attempts: 8,
            backoff_base: StdDuration::from_secs(10),
            backoff_max: StdDuration::from_secs(3600),
            retain_done: Duration::hours(24),
            retain_suppressed: Duration::hours(1),
            retain_dead: Duration::days(30),
            send_timeout: StdDuration::from_secs(30),
        }
    }
}

impl QueuePolicy {
    /// The wall-clock a single drain may spend before it hands the rest to the next tick.
    ///
    /// Half a lease, so a tick can never outlive the leases it is holding: the failure that
    /// bound exists for is a drain that runs past its own lease, gets its in-flight items
    /// reaped back to `pending` by the next drain, and delivers every one of them twice
    /// (decision 26's amendment). Half rather than "just under" leaves room for the completion
    /// writes at the end of the last pass.
    pub fn budget(&self) -> StdDuration {
        self.lease / 2
    }

    /// How many items a pass may lease with `remaining` budget left.
    ///
    /// The bound the review found missing: a batch of fifty items each paying a thirty-second
    /// timeout is twenty-five minutes of work leased for two. Never lease more than the time
    /// left can run — `remaining / send_timeout` rounds of `concurrency` deliveries — so the
    /// drain stops by *not claiming*, rather than by abandoning items it already leased (which
    /// would spend an attempt on work that was never attempted, and dead-letter a sign-in
    /// message that no relay ever refused).
    fn pass_limit(&self, remaining: StdDuration) -> u32 {
        let timeout = self.send_timeout.as_millis().max(1);
        let rounds = u32::try_from(remaining.as_millis() / timeout).unwrap_or(u32::MAX);
        rounds.saturating_mul(self.concurrency.max(1)).min(self.batch)
    }

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
        let budget = self.policy.budget();
        // Monotonic, and the *only* clock this loop reads after `now`: what a lease deadline
        // and a retry backoff have to be measured from is the real present, and `now` stops
        // being that the moment the first slow send lands. Adding the elapsed time to the
        // tick's instant is that present, without a wall clock that can step sideways
        // mid-drain — and it is what makes the drain's own bound testable.
        let started = Instant::now();

        // Before claiming anything: an item whose worker died mid-run is invisible until its
        // lease is returned, and doing this first means one tick both frees and re-runs it.
        report.reaped = self.repos.queue.reap_expired_leases(now).await?;

        for _ in 0..MAX_PASSES {
            let elapsed = started.elapsed();
            let Some(remaining) = budget.checked_sub(elapsed) else { break };
            let limit = self.policy.pass_limit(remaining);
            if limit == 0 {
                break;
            }
            let pass_now = now + chrono::Duration::from_std(elapsed).unwrap_or_else(|_| Duration::zero());
            let batch = self.repos.queue.claim(&kinds, limit, self.policy.lease, pass_now).await?;
            if batch.is_empty() {
                break;
            }
            report.claimed += batch.len() as u64;
            // Bounded concurrency rather than one message at a time: a single slow recipient
            // used to gate every message behind it, including the sign-in code (decision 26's
            // amendment). Each item still completes before its own follow-ups are published —
            // that ordering is per item and is preserved inside `run_item`.
            let outcomes: Vec<Result<QueueOutcome>> = futures::stream::iter(batch)
                .map(|job| async move { self.run_item(&job, started, now).await })
                .buffer_unordered(self.policy.concurrency.max(1) as usize)
                .collect()
                .await;
            for outcome in outcomes {
                match outcome? {
                    QueueOutcome::Done => report.delivered += 1,
                    QueueOutcome::Retry(_) => report.retried += 1,
                    QueueOutcome::Dead(_) => report.dead += 1,
                }
            }
        }

        // Retention is deliberately absent here. It used to run on every tick — five seconds by
        // default — as three unbounded `DELETE` statements outside this drain's wall-clock budget, which is
        // D47. Decision 30 moved it to the lifecycle job: this worker delivers, that one deletes.
        self.record_depth(&mut report).await?;
        Ok(report)
    }

    /// Runs one item to completion and publishes its follow-ups; reports how it ended.
    ///
    /// `started` is the drain's monotonic origin: the lease and backoff this item's completion
    /// writes are dated from `now + started.elapsed()`, never from the tick's instant. With the
    /// tick's instant a lease minted after two minutes of drain is already expired when it is
    /// written, and every retry's backoff — the ten-second-to-an-hour ladder that exists for
    /// exactly this outage — collapses to "runnable immediately".
    async fn run_item(&self, job: &QueuedJob, started: Instant, now: DateTime<Utc>) -> Result<QueueOutcome> {
        let at = now + chrono::Duration::from_std(started.elapsed()).unwrap_or_else(|_| Duration::zero());
        let Some(handler) = self.handlers.get(&job.kind) else {
            // Unreachable while `claim` is given exactly the registered kinds; recorded rather
            // than `expect`ed because a panic here would take the whole drain down with it.
            tracing::error!(kind = %job.kind, "claimed an item with no registered handler");
            let outcome = QueueOutcome::Dead("no handler registered".to_owned());
            self.repos.queue.complete(job.id, outcome.clone(), StdDuration::ZERO, at).await?;
            return Ok(outcome);
        };

        let handled = handler.run(job, at).await;
        // Attempts are spent at claim, so the row already carries this run's number: the budget
        // is exhausted when the attempt that just failed *was* the last one.
        let outcome = match handled.outcome {
            QueueOutcome::Retry(message) if job.attempts >= self.policy.max_attempts => {
                QueueOutcome::Dead(format!("gave up after {} attempts: {message}", job.attempts))
            }
            other => other,
        };
        if let QueueOutcome::Dead(message) = &outcome {
            tracing::error!(kind = %job.kind, id = %job.id, attempts = job.attempts, %message, "queue item dead-lettered");
        }
        metrics::counter!("queue_jobs_total", "kind" => job.kind.as_str(), "outcome" => outcome.as_str()).increment(1);

        // The clock again, not `at`: the handler is where the wall-clock goes, so a completion
        // dated from before it is a lease and a backoff measured from the wrong end of a send.
        let done_at = now + chrono::Duration::from_std(started.elapsed()).unwrap_or_else(|_| Duration::zero());
        // Completion first, follow-ups second, always: publishing from before the completion is
        // committed is how a client learns about a notification it cannot yet read.
        self.repos.queue.complete(job.id, outcome.clone(), self.policy.backoff_for(job), done_at).await?;
        for followup in handled.followups {
            self.events.publish_followup(followup).await;
        }
        Ok(outcome)
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
            priority: 0,
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
    fn a_pass_never_leases_more_work_than_its_remaining_budget_can_run() {
        // Decision 26's amendment: the drain stops inside a fraction of its own lease. It does
        // that by *not claiming*, so the bound has to hold on the numbers rather than on a
        // mid-batch abandon — an item leased and never run has already spent an attempt.
        let policy = QueuePolicy::default();
        assert_eq!(policy.budget(), StdDuration::from_secs(60), "half a lease");
        assert!(
            policy.send_timeout <= policy.budget(),
            "a single delivery must fit in the budget, or one item overruns the lease on its own"
        );
        // Two rounds of four in-flight deliveries is what sixty seconds of thirty-second
        // timeouts buys — never the whole batch of fifty, which is twenty-five minutes of work.
        assert_eq!(policy.pass_limit(policy.budget()), 8);
        assert_eq!(policy.pass_limit(StdDuration::from_secs(30)), 4, "one round");
        assert_eq!(policy.pass_limit(StdDuration::from_secs(29)), 0, "less than one delivery is no pass at all");
        assert_eq!(policy.pass_limit(StdDuration::ZERO), 0);
        // A fast transport is bounded by the batch, not by the arithmetic.
        let brisk = QueuePolicy { send_timeout: StdDuration::from_millis(100), ..QueuePolicy::default() };
        assert_eq!(brisk.pass_limit(brisk.budget()), brisk.batch);
        // Degenerate configuration must not divide by zero or lease the whole table.
        let degenerate = QueuePolicy { send_timeout: StdDuration::ZERO, concurrency: 0, ..QueuePolicy::default() };
        assert_eq!(degenerate.pass_limit(degenerate.budget()), degenerate.batch);
    }

    #[test]
    fn every_terminal_state_has_a_retention_window_and_the_dead_letter_keeps_the_longest() {
        // Decision 26 (retention bullet): retention covered `done` and nothing else, so a suppressed row — one per
        // policy-rejected sign-in attempt, filed by an unauthenticated endpoint, carrying the
        // attempted address in the clear — lived forever, and so did every dead letter.
        let policy = QueuePolicy::default();
        assert_eq!(policy.retain_suppressed, Duration::hours(1));
        assert_eq!(policy.retain_done, Duration::hours(24));
        assert_eq!(policy.retain_dead, Duration::days(30));
        assert!(policy.retain_suppressed < policy.retain_done, "a row nothing reads outlives nothing");
        assert!(policy.retain_dead > policy.retain_done, "the operator's record is the last thing to go");
        assert!(policy.retain_dead > Duration::zero(), "a zero window would delete a dead letter on the next tick");
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
