//! The durable work queue's drain over a real migrated database (decision 26).
//!
//! Everything here runs the production [`QueueWorker`] against real rows: the queue sits on the
//! sign-in path, so a suite that asserted against a repository double would be proving that the
//! double behaves, not that mail leaves.
//!
//! | Rule | Test |
//! |------|------|
//! | A transient failure backs off, grows, and finally dead-letters | [`d2_a_failing_mailer_retries_with_growing_backoff_then_deadletters`] |
//! | A worker that dies mid-run releases its item | [`d2_an_expired_lease_returns_the_item_to_the_queue`] |
//! | A hung relay cannot hold a lease | [`d2_a_mail_send_that_hangs_is_bounded_by_its_timeout`] |
//! | A hung relay cannot make a drain outlive its lease | [`d2_a_drain_stops_inside_its_own_lease_and_backs_off_from_the_present`] |
//! | A pass claims against the clock the drain has reached | [`d2_a_later_pass_claims_against_the_clock_the_drain_has_reached`] |
//! | A batch is dispatched with bounded concurrency | [`d2_a_claimed_batch_is_dispatched_with_bounded_concurrency`] |
//! | A sign-in code is never starved by bulk mail | [`d2_a_sign_in_code_overtakes_a_backlog_of_notification_mail`] |
//! | The fan-out row is bulk, not only its mail | [`d2_the_fanout_row_itself_is_bulk_not_only_the_mail_it_produces`] |
//! | A hung fan-out cannot outrun its own budget | [`d2_a_fanout_that_hangs_is_bounded_by_the_deadline_its_budget_prices_it_at`] |
//! | A permanent failure does not burn the budget | [`d2_a_malformed_recipient_deadletters_immediately`] |
//! | One event, one batch, one mail item per recipient | [`d2_the_fanout_files_every_recipient_in_one_batch_and_queues_their_mail`] |
//! | Re-enqueueing one event is a no-op | [`d2_a_duplicate_enqueue_of_one_event_is_a_no_op`] |
//! | A re-run fan-out re-sends no message and files no second row | [`d2_a_fanout_retry_never_sends_a_second_copy_of_a_message`] |
//! | A notification email that cannot be queued is not lost | [`d44_a_notification_email_that_cannot_be_queued_is_not_lost_in_silence`] |
//! | The item is completed before its follow-ups are published | [`d2_an_item_is_completed_before_its_followups_are_published`] |
//! | Retention deletes done rows and keeps dead ones | [`d12_retention_purges_done_rows_and_keeps_the_operators_record`] |
//! | Every terminal state has a retention window | [`d43_retention_bounds_every_terminal_state_not_only_the_completed_one`] |

use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use pub_core::event::EventEnvelope;
use pub_core::notification::NotificationCategory;
use pub_core::org::NewOrg;
use pub_core::queue::{FanoutJob, JobKind, MailJob, NewQueuedJob, QueueOutcome, QueueState, QueuedJob, QueuedJobId};
use pub_core::settings::SettingsCache;
use pub_core::traits::{Kv, Mailer, MessageStream, Repositories};
use pub_core::user::NewUser;
use pub_core::{DomainEvent, Error, Format, OrgId, PackageId, Result, RoleLevel, UserId, VersionId};
use pub_db_sqlite::SqliteDb;
use pub_events::{
    EventBus, EventBusPolicy, EventConsumer, NotificationCenter, NotificationEnqueuer, NotificationPolicy,
};
use pub_jobs::queue::{HandlerReport, JobHandler};
use pub_jobs::{FanoutHandler, MailHandler, QueuePolicy, QueueWorker};

const KEK: [u8; 32] = [11u8; 32];

/// The per-item deadline a handler built outside [`Harness::worker`] gets — the drain's own
/// `send_timeout`, which is what both registered kinds are budgeted at.
const SEND_TIMEOUT: StdDuration = StdDuration::from_secs(30);

/// The sign-in code the S-26.b regression looks for, in the row and in the delivered message.
const CODE: &str = "12345678";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

/// How the scripted mailer behaves on the next send.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MailMode {
    /// Accepts everything.
    Deliver,
    /// Fails the way a refused relay does — transient.
    Refuse,
    /// Fails the way a malformed address does — permanent.
    Reject,
    /// Never returns. The reason [`QueuePolicy::send_timeout`] exists.
    Hang,
    /// Accepts everything, slowly — a relay that works and takes its time, which is what makes
    /// the drain's own wall-clock observable.
    Slow(StdDuration),
}

struct ScriptedMailer {
    mode: Mutex<MailMode>,
    sent: Mutex<Vec<(String, String, String)>>,
    /// Sends currently inside `send`, and the most that were ever there at once — how the
    /// dispatch's concurrency is asserted without measuring wall-clock.
    in_flight: Mutex<(usize, usize)>,
}

impl ScriptedMailer {
    fn new(mode: MailMode) -> Arc<Self> {
        Arc::new(Self { mode: Mutex::new(mode), sent: Mutex::new(Vec::new()), in_flight: Mutex::new((0, 0)) })
    }

    fn set(&self, mode: MailMode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn sent(&self) -> Vec<(String, String, String)> {
        self.sent.lock().unwrap().clone()
    }

    fn peak_in_flight(&self) -> usize {
        self.in_flight.lock().unwrap().1
    }

    fn enter(&self) {
        let mut counts = self.in_flight.lock().unwrap();
        counts.0 += 1;
        counts.1 = counts.1.max(counts.0);
    }

    fn leave(&self) {
        self.in_flight.lock().unwrap().0 -= 1;
    }
}

#[async_trait]
impl Mailer for ScriptedMailer {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let mode = *self.mode.lock().unwrap();
        // A guard rather than a decrement after the await: a send that is cancelled by the
        // handler's timeout never reaches the line after it.
        let _in_flight = InFlight::enter(self);
        self.deliver(mode, to, subject, body).await
    }
}

/// Counts one send for as long as it is inside the transport, cancellation included.
struct InFlight<'a>(&'a ScriptedMailer);

impl<'a> InFlight<'a> {
    fn enter(mailer: &'a ScriptedMailer) -> Self {
        mailer.enter();
        Self(mailer)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.leave();
    }
}

impl ScriptedMailer {
    async fn deliver(&self, mode: MailMode, to: &str, subject: &str, body: &str) -> Result<()> {
        match mode {
            MailMode::Deliver => {
                self.sent.lock().unwrap().push((to.to_owned(), subject.to_owned(), body.to_owned()));
                Ok(())
            }
            MailMode::Refuse => Err(Error::Internal { message: "smtp delivery failed: connection refused".to_owned() }),
            MailMode::Reject => Err(Error::Invalid { message: "invalid recipient address".to_owned() }),
            MailMode::Hang => {
                // Deliberately longer than any timeout under test: the assertion is that the
                // handler gives up, not that this future eventually resolves.
                tokio::time::sleep(StdDuration::from_secs(3600)).await;
                Ok(())
            }
            MailMode::Slow(delay) => {
                tokio::time::sleep(delay).await;
                self.sent.lock().unwrap().push((to.to_owned(), subject.to_owned(), body.to_owned()));
                Ok(())
            }
        }
    }
}

/// A KV whose `publish` samples the queue row's state at the instant the bus publishes.
///
/// This is how the "completed before the follow-ups go out" ordering becomes observable: the
/// broker publish happens *inside* `EventBus::publish_followup`, so what it sees is the state
/// the row was in when the worker handed the event back.
struct OrderingKv {
    repos: Repositories,
    watching: Mutex<Option<QueuedJobId>>,
    observed: Mutex<Vec<Option<QueueState>>>,
}

#[async_trait]
impl Kv for OrderingKv {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn get(&self, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }

    async fn set_ttl(&self, _key: &str, _value: &str, _ttl: StdDuration) -> Result<()> {
        Ok(())
    }

    async fn incr(&self, _key: &str, _ttl: StdDuration) -> Result<u64> {
        Ok(1)
    }

    async fn del(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    async fn publish(&self, _topic: &str, _payload: &str) -> Result<()> {
        let watching = *self.watching.lock().unwrap();
        if let Some(id) = watching {
            let state = self.repos.queue.get(id).await?.map(|job| job.state);
            self.observed.lock().unwrap().push(state);
        }
        Ok(())
    }

    async fn subscribe(&self, _topic: &str) -> Result<MessageStream> {
        Err(Error::Kv { message: "this test kv does not subscribe".to_owned() })
    }
}

struct Harness {
    repos: Repositories,
    bus: Arc<EventBus>,
    mailer: Arc<ScriptedMailer>,
    org: OrgId,
}

impl Harness {
    async fn new(mode: MailMode) -> Self {
        let cfg = pub_config::DatabaseConfig {
            kind: pub_config::DatabaseKind::Sqlite,
            url: None,
            path: ":memory:".to_owned(),
            ..Default::default()
        };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();
        let owner = repos
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
            .expect("owner")
            .id;
        let org = repos.orgs.create(NewOrg::new("Acme", "acme"), owner, t0()).await.expect("org").id;
        Self { repos, bus: Arc::new(EventBus::new(EventBusPolicy::default())), mailer: ScriptedMailer::new(mode), org }
    }

    /// Seeds `count` extra org members and returns their ids.
    async fn members(&self, count: usize) -> Vec<UserId> {
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let user = self
                .repos
                .users
                .create(
                    NewUser {
                        email: Some(format!("member{index}@corp.com")),
                        email_verified: true,
                        display_name: format!("Member {index}"),
                    },
                    t0(),
                )
                .await
                .expect("member")
                .id;
            self.repos.orgs.add_member(self.org, user, RoleLevel::WRITE, t0()).await.expect("membership");
            ids.push(user);
        }
        ids
    }

    fn center(&self) -> Arc<NotificationCenter> {
        Arc::new(NotificationCenter::new(
            self.repos.clone(),
            NotificationPolicy::default(),
            Arc::new(SettingsCache::new(pub_core::settings::RuntimeSettings::default())),
        ))
    }

    fn worker(&self, policy: QueuePolicy) -> QueueWorker {
        QueueWorker::new(self.repos.clone(), Arc::clone(&self.bus), policy)
            .with_handler(Arc::new(FanoutHandler::new(
                self.center(),
                Arc::clone(&self.repos.queue),
                policy.send_timeout,
            )))
            .with_handler(Arc::new(MailHandler::new(
                Arc::clone(&self.mailer) as Arc<dyn Mailer>,
                KEK.to_vec(),
                policy.send_timeout,
            )))
    }

    async fn enqueue_mail(&self, to: &str) -> QueuedJobId {
        self.enqueue_mail_at(to, t0()).await
    }

    async fn enqueue_mail_at(&self, to: &str, at: DateTime<Utc>) -> QueuedJobId {
        let job = MailJob {
            to: to.to_owned(),
            subject: "Your sign-in code".to_owned(),
            text: "Your code is 12345678".to_owned(),
            html: None,
            sealed: false,
        };
        let payload = serde_json::to_value(&job).unwrap();
        self.repos
            .queue
            .enqueue(&NewQueuedJob::pending(MailJob::KIND, payload).with_run_after(at), at)
            .await
            .expect("enqueue")
            .expect("a fresh row")
            .id
    }

    async fn row(&self, id: QueuedJobId) -> QueuedJob {
        self.repos.queue.get(id).await.expect("get").expect("the row must still exist")
    }

    async fn queued(&self, kind: JobKind, state: QueueState) -> i64 {
        self.repos
            .queue
            .depth()
            .await
            .expect("depth")
            .into_iter()
            .find(|(k, s, _)| *k == kind && *s == state)
            .map_or(0, |(_, _, count)| count)
    }
}

fn published(org: OrgId) -> DomainEvent {
    DomainEvent::PackagePublished {
        format: Format::Pub,
        org_id: org,
        package_id: PackageId::new(),
        name: "acme_core".to_owned(),
        version: "1.0.0".to_owned(),
        version_id: VersionId::new(),
        package_created: false,
        at: t0(),
    }
}

/// A membership change is an `org`-category event, which is the tier that reaches a mailbox.
fn membership(org: OrgId, user: UserId) -> DomainEvent {
    DomainEvent::OrgMembershipChanged { org_id: org, user_id: user, role: Some(RoleLevel::WRITE.level()), at: t0() }
}

#[tokio::test]
async fn d2_a_failing_mailer_retries_with_growing_backoff_then_deadletters() {
    let harness = Harness::new(MailMode::Refuse).await;
    let policy = QueuePolicy {
        max_attempts: 3,
        backoff_base: StdDuration::from_secs(10),
        backoff_max: StdDuration::from_secs(3600),
        ..QueuePolicy::default()
    };
    let worker = harness.worker(policy);
    let id = harness.enqueue_mail("alice@corp.com").await;

    let mut now = t0();
    let mut previous = Duration::zero();
    for attempt in 1..=2u32 {
        let report = worker.run_once(now).await.expect("drain");
        assert_eq!(report.retried, 1, "attempt {attempt} must retry, not give up");
        let row = harness.row(id).await;
        assert_eq!(row.state, QueueState::Pending, "a retry goes back to the queue");
        assert_eq!(row.attempts, i64::from(attempt), "attempts are spent at claim");
        assert!(row.last_error.is_some(), "the operator needs to see why");

        let delay = row.run_after - now;
        assert!(delay > previous, "attempt {attempt} must wait longer than the last: {delay} vs {previous}");
        previous = delay;

        // A second drain at the same instant claims nothing: the backoff is real, not a label.
        assert_eq!(worker.run_once(now).await.expect("drain").claimed, 0, "a backed-off row is not runnable yet");
        now = row.run_after;
    }

    let report = worker.run_once(now).await.expect("drain");
    assert_eq!(report.dead, 1, "the budget is spent");
    let row = harness.row(id).await;
    assert_eq!(row.state, QueueState::Dead);
    assert_eq!(row.attempts, 3);
    assert!(row.last_error.unwrap().contains("gave up after 3 attempts"), "the dead letter must say why");
    assert_eq!(report.dead_pending, 1, "the standing dead-letter count is what an operator watches");

    // A dead row is never claimed again, however long the queue runs.
    assert_eq!(worker.run_once(now + Duration::days(7)).await.expect("drain").claimed, 0);
    assert!(harness.mailer.sent().is_empty());
}

#[tokio::test]
async fn d2_an_expired_lease_returns_the_item_to_the_queue() {
    // The "worker died mid-run" case: nothing ever reports the outcome, so only the lease's
    // expiry can make the item runnable again — and the attempt it burnt is not refunded,
    // which is what keeps an item that kills its handler from retrying forever.
    let harness = Harness::new(MailMode::Deliver).await;
    let policy = QueuePolicy { lease: StdDuration::from_secs(120), ..QueuePolicy::default() };
    let id = harness.enqueue_mail("alice@corp.com").await;

    let claimed = harness.repos.queue.claim(&[JobKind::MailSend], 10, policy.lease, t0()).await.expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempts, 1);

    let worker = harness.worker(policy);
    // Still leased: a drain inside the lease window sees nothing and sends nothing.
    assert_eq!(worker.run_once(t0() + Duration::seconds(30)).await.expect("drain").claimed, 0);
    assert!(harness.mailer.sent().is_empty());

    let report = worker.run_once(t0() + Duration::seconds(300)).await.expect("drain");
    assert_eq!(report.reaped, 1, "the expired lease must be returned");
    assert_eq!(report.delivered, 1, "and the item run in the same tick");
    let row = harness.row(id).await;
    assert_eq!(row.state, QueueState::Done);
    assert_eq!(row.attempts, 2, "the attempt the dead worker spent is not refunded");
    assert_eq!(harness.mailer.sent().len(), 1);
}

#[tokio::test]
async fn d2_a_mail_send_that_hangs_is_bounded_by_its_timeout() {
    // This bound *replaces* the `[http]` request deadline that used to truncate a hung SMTP
    // conversation. Without it the relay below would hold this lease and then every lease
    // behind it, and the queue would simply stop.
    let harness = Harness::new(MailMode::Hang).await;
    let policy = QueuePolicy { send_timeout: StdDuration::from_millis(50), ..QueuePolicy::default() };
    let worker = harness.worker(policy);
    let id = harness.enqueue_mail("alice@corp.com").await;

    let started = std::time::Instant::now();
    let report = worker.run_once(t0()).await.expect("drain");
    let elapsed = started.elapsed();

    assert_eq!(report.retried, 1, "a hung transport is transient, not permanent");
    assert!(elapsed < StdDuration::from_secs(5), "the handler must give up on its own: took {elapsed:?}");
    let row = harness.row(id).await;
    assert_eq!(row.state, QueueState::Pending, "the lease is released, not held");
    assert!(row.last_error.unwrap().contains("exceeded"), "the retry must name the timeout");

    // The relay recovers; the next runnable moment delivers.
    harness.mailer.set(MailMode::Deliver);
    let row = harness.row(id).await;
    assert_eq!(worker.run_once(row.run_after).await.expect("drain").delivered, 1);
}

#[tokio::test]
async fn d2_a_drain_stops_inside_its_own_lease_and_backs_off_from_the_present() {
    // The bound decision 26's amendment adds: a per-send timeout is not a bound on a *drain*.
    // With a relay that connects and says nothing, this tick used to claim the whole batch and
    // pay the timeout for every item — fifty items at thirty seconds is twenty-five minutes of
    // work leased for two — so it ran past its own lease, past the scheduler's lock TTL, and a
    // second drain reaped its in-flight items and sent them again. Two properties here:
    // the drain never spends more than half a lease, and the retry backoffs it writes are
    // measured from the real present rather than from the tick's start (with the tick's start
    // they land in the past, and the whole ten-second-to-an-hour ladder becomes "retry now").
    // Real time, deliberately: the `:memory:` database is pinned to a single connection and
    // sqlx validates it on every acquire, so a paused clock jumps straight to the pool's own
    // acquire timeout and the test would be measuring sqlx rather than the drain. The
    // durations are therefore small — the ratios are what matter, not the units.
    let harness = Harness::new(MailMode::Hang).await;
    let policy = QueuePolicy {
        send_timeout: StdDuration::from_millis(60),
        lease: StdDuration::from_millis(400),
        // One at a time here on purpose: this test is about the clock, not the dispatch.
        concurrency: 1,
        batch: 50,
        ..QueuePolicy::default()
    };
    let worker = harness.worker(policy);
    let mut filed = Vec::new();
    for index in 0..20 {
        filed.push(harness.enqueue_mail(&format!("member{index}@corp.com")).await);
    }

    let started = std::time::Instant::now();
    let report = worker.run_once(t0()).await.expect("drain");
    let elapsed = started.elapsed();

    assert!(
        elapsed <= policy.lease,
        "one drain outlived the lease it holds its items under: {elapsed:?} of {:?}",
        policy.lease
    );
    assert!(
        (1..=5).contains(&report.claimed),
        "a pass leased more work than its budget could run — twenty hung sends is twenty timeouts: {}",
        report.claimed
    );
    assert_eq!(report.retried, report.claimed, "a hung relay is transient");
    assert_eq!(
        harness.queued(JobKind::MailSend, QueueState::Pending).await,
        20,
        "everything is runnable again: what was never claimed, plus what came back behind a backoff"
    );

    let retried = harness.row(filed[0]).await;
    assert_eq!(retried.attempts, 1, "an item is never leased twice in one drain");
    // `updated_at` is the instant the completion was written with, and it is the same instant
    // the retry's `run_after = now + backoff` is measured from. With the tick's instant it is
    // `t0()` exactly however long the drain ran — which is how the backoff ladder collapsed to
    // "runnable immediately" in precisely the outage it exists for.
    assert!(
        retried.updated_at >= t0() + Duration::milliseconds(50),
        "the completion was stamped with the tick's start, not with the present: {} vs {}",
        retried.updated_at,
        t0()
    );
    assert!(retried.run_after > retried.updated_at, "and the backoff runs from there");
    assert!(harness.mailer.sent().is_empty(), "nothing was delivered by a relay that never answered");
}

#[tokio::test]
async fn d2_a_claimed_batch_is_dispatched_with_bounded_concurrency() {
    // The other half of the fairness fix (decision 26's amendment): one message at a time makes
    // the queue's throughput 1/send-latency, so one slow recipient gates every message behind
    // it — including the sign-in code. Counted rather than timed: under the serial loop the
    // in-flight count is exactly one, whatever the machine's mood.
    let harness = Harness::new(MailMode::Slow(StdDuration::from_millis(20))).await;
    let policy = QueuePolicy { concurrency: 4, ..QueuePolicy::default() };
    let worker = harness.worker(policy);
    for index in 0..4 {
        harness.enqueue_mail(&format!("member{index}@corp.com")).await;
    }

    let report = worker.run_once(t0()).await.expect("drain");
    assert_eq!(report.delivered, 4);
    let peak = harness.mailer.peak_in_flight();
    assert!(peak > 1, "the batch was dispatched one message at a time: peak in flight {peak}");
    assert!(peak <= 4, "concurrency is bounded — the other end is somebody's relay: peak in flight {peak}");
}

#[tokio::test]
async fn d2_a_later_pass_claims_against_the_clock_the_drain_has_reached() {
    // The other half of the same amendment: the claim's `now` decides which rows are runnable
    // and how far into the future their leases reach. A drain that keeps using the instant it
    // started at mints leases that are already expired — reapable the moment they are taken —
    // and cannot see work that became runnable while it was running. Here the fourth message is
    // deliberately not runnable at the tick's instant, and is runnable by the time three
    // fifty-millisecond deliveries have gone by. Real time for the same reason as the drain
    // budget test above; a sleep only ever overshoots, so the ordering below cannot invert.
    let harness = Harness::new(MailMode::Slow(StdDuration::from_millis(50))).await;
    let policy = QueuePolicy {
        send_timeout: StdDuration::from_millis(200),
        lease: StdDuration::from_secs(2),
        concurrency: 1,
        batch: 50,
        ..QueuePolicy::default()
    };
    let worker = harness.worker(policy);
    for index in 0..3 {
        harness.enqueue_mail(&format!("now{index}@corp.com")).await;
    }
    let delayed = harness.enqueue_mail_at("delayed@corp.com", t0() + Duration::milliseconds(120)).await;

    let report = worker.run_once(t0()).await.expect("drain");

    assert_eq!(report.claimed, 4, "the row that became runnable mid-drain was claimed by the pass that reached it");
    assert_eq!(report.delivered, 4);
    let row = harness.row(delayed).await;
    assert_eq!(row.state, QueueState::Done);
    assert!(
        row.updated_at >= t0() + Duration::milliseconds(150),
        "its completion is stamped with the drain's real present, not with the tick's start: {}",
        row.updated_at
    );
    assert_eq!(harness.mailer.sent().len(), 4);
}

#[tokio::test]
async fn d2_a_malformed_recipient_deadletters_immediately() {
    // An address the message builder rejects will never become valid, so spending eight
    // attempts on it only delays the dead letter that says so.
    let harness = Harness::new(MailMode::Reject).await;
    let worker = harness.worker(QueuePolicy::default());
    let id = harness.enqueue_mail("not an address").await;

    let report = worker.run_once(t0()).await.expect("drain");
    assert_eq!(report.dead, 1);
    assert_eq!(report.retried, 0, "a permanent failure must not consume the retry budget");
    let row = harness.row(id).await;
    assert_eq!(row.state, QueueState::Dead);
    assert_eq!(row.attempts, 1, "one attempt, not the whole budget");
    assert!(row.last_error.unwrap().contains("undeliverable recipient"));
}

#[tokio::test]
async fn d2_the_fanout_files_every_recipient_in_one_batch_and_queues_their_mail() {
    let harness = Harness::new(MailMode::Deliver).await;
    let members = harness.members(20).await;
    let worker = harness.worker(QueuePolicy::default());

    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let payload = serde_json::to_value(FanoutJob { envelope: envelope.clone() }).unwrap();
    harness
        .repos
        .queue
        .enqueue(&NewQueuedJob::pending(FanoutJob::KIND, payload), t0())
        .await
        .expect("enqueue")
        .expect("a fresh row");

    // One drain resolves the whole cascade: the fan-out item, then the mail items it filed.
    let report = worker.run_once(t0()).await.expect("drain");
    assert_eq!(report.claimed, 22, "one fan-out item plus one mail item per recipient");
    assert_eq!(report.delivered, 22);

    for (index, member) in members.iter().enumerate() {
        let feed = harness.repos.notifications.list(*member, false, None, 10).await.expect("feed");
        assert_eq!(feed.items.len(), 1, "member {index} must have exactly one row");
        assert_eq!(feed.items[0].event, "org.member");
        assert_eq!(feed.items[0].created_at, t0(), "the row is stamped with the event, not the drain");
    }
    // The org owner is a recipient too — 20 members plus the creator.
    assert_eq!(harness.mailer.sent().len(), 21, "one message per recipient, never one message with 21 addresses");

    // Every recipient's `UserNotified` carries their own badge number.
    let followups: Vec<EventEnvelope> = harness.bus.replay_since(&envelope.id);
    let notified = followups.iter().filter(|e| e.event.name() == "notification.new").count();
    assert_eq!(notified, 21, "one follow-up per filed row");
    for envelope in &followups {
        if let DomainEvent::UserNotified { unread, category, .. } = &envelope.event {
            assert_eq!(*unread, 1, "the badge is this recipient's own count");
            assert_eq!(*category, NotificationCategory::Org);
        }
    }
}

#[tokio::test]
async fn d2_a_sign_in_code_overtakes_a_backlog_of_notification_mail() {
    // The starvation decision 26's amendment names: one FIFO across kinds means a CI pipeline
    // publishing into a large org files thousands of per-recipient broadcast rows, and the next
    // sign-in code is claimed after every one of them — at a realistic SMTP pace, long after
    // the ten-minute OTP TTL has expired. Sign-in is then down instance-wide because of
    // unrelated traffic, with nothing dead-lettered and nothing on the admin surface.
    let harness = Harness::new(MailMode::Deliver).await;
    let members = harness.members(5).await;

    // Phase one: the fan-out files the broadcast. Only the fan-out handler is registered, so
    // the mail it files stays in the table instead of being drained in the same tick.
    let filer = QueueWorker::new(harness.repos.clone(), Arc::clone(&harness.bus), QueuePolicy::default())
        .with_handler(Arc::new(FanoutHandler::new(harness.center(), Arc::clone(&harness.repos.queue), SEND_TIMEOUT)));
    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let payload = serde_json::to_value(FanoutJob { envelope }).unwrap();
    harness
        .repos
        .queue
        .enqueue(&NewQueuedJob::pending(FanoutJob::KIND, payload), t0())
        .await
        .expect("enqueue")
        .expect("a fresh row");
    filer.run_once(t0()).await.expect("fan-out");
    // A second later, because the fan-out stamps the rows it files with the drain's own
    // present, which is a few milliseconds past the tick's instant.
    let inspect = t0() + Duration::seconds(1);
    let queued =
        harness.repos.queue.claim(&[JobKind::MailSend], 50, StdDuration::from_secs(1), inspect).await.expect("claim");
    assert_eq!(queued.len(), 6, "one message per recipient — five members plus the owner");
    assert!(
        queued.iter().all(|job| job.priority == NewQueuedJob::BULK),
        "notification mail must be filed as bulk, or it sits in front of the next sign-in code"
    );
    // Put the batch back the way the lease reaper would, so the drain below starts from a
    // backlog of runnable bulk mail.
    assert_eq!(harness.repos.queue.reap_expired_leases(inspect + Duration::seconds(2)).await.expect("reap"), 6);

    // Phase two: a sign-in code arrives *after* the whole backlog and is still delivered first.
    let code = harness.enqueue_mail_at("late@corp.com", t0() + Duration::seconds(3)).await;
    let worker = harness.worker(QueuePolicy { concurrency: 1, ..QueuePolicy::default() });
    worker.run_once(t0() + Duration::seconds(4)).await.expect("drain");

    let sent = harness.mailer.sent();
    assert_eq!(sent.len(), 7);
    assert_eq!(
        sent[0].0,
        "late@corp.com",
        "the sign-in code was delivered after {} broadcast messages filed before it",
        sent.iter().take_while(|message| message.0 != "late@corp.com").count()
    );
    assert_eq!(harness.row(code).await.state, QueueState::Done);
}

#[tokio::test]
async fn d2_the_fanout_row_itself_is_bulk_not_only_the_mail_it_produces() {
    // The residue of the fix above: the per-recipient broadcast *mail* was moved into the bulk
    // lane and the `notification.fanout` row that produces it was left interactive — although a
    // fan-out is work filed on somebody else's behalf by definition, and is the far more
    // expensive of the two (an audience resolution, a `create_many` of up to five hundred rows
    // and up to two hundred sequential enqueues, against one SMTP conversation). A CI pipeline
    // publishing into a large org therefore still filed thousands of rows in front of the next
    // sign-in code — the exact failure the priority dimension was added to remove, one level up.
    // This drives the real bus consumer, because the lane is decided where the row is filed.
    let harness = Harness::new(MailMode::Deliver).await;
    let enqueuer = NotificationEnqueuer::new(Arc::clone(&harness.repos.queue));
    let mut fanouts = Vec::new();
    for _ in 0..3 {
        let envelope = EventEnvelope::new(membership(harness.org, UserId::new()));
        enqueuer.handle(&envelope).await.expect("the consumer files one row per notifiable event");
        fanouts.push(envelope.id);
    }
    assert_eq!(harness.queued(JobKind::NotificationFanout, QueueState::Pending).await, 3);

    // The sign-in code arrives last and is claimed first, ahead of every fan-out.
    let code = harness.enqueue_mail_at("late@corp.com", t0() + Duration::seconds(1)).await;
    let claimed = harness
        .repos
        .queue
        .claim(&JobKind::ALL, 10, StdDuration::from_secs(60), t0() + Duration::seconds(2))
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 4);
    assert_eq!(claimed[0].id, code, "the sign-in code waited behind {} fan-out rows", fanouts.len());
    for job in &claimed[1..] {
        assert_eq!(job.kind, JobKind::NotificationFanout);
        assert_eq!(job.priority, NewQueuedJob::BULK, "a fan-out is bulk work by the lane's own definition");
    }
}

#[tokio::test]
async fn d2_a_fanout_that_hangs_is_bounded_by_the_deadline_its_budget_prices_it_at() {
    // The drain leases `remaining / send_timeout` rounds of work per pass and re-checks its
    // budget only *between* passes, so that arithmetic is a bound only if every registered kind
    // honours the deadline it is priced at. `MailHandler` did; this one had no timeout anywhere,
    // while being the kind whose cost is unbounded database work rather than one SMTP
    // conversation. A pass that claimed fan-out items could therefore run past the leases it had
    // just minted, after which the next drain reaps them back to `pending` and spends a second
    // attempt on every one of them.
    struct HangingQueue {
        inner: Arc<dyn pub_core::traits::JobQueueRepo>,
    }

    #[async_trait]
    impl pub_core::traits::JobQueueRepo for HangingQueue {
        async fn ping(&self) -> Result<()> {
            self.inner.ping().await
        }

        async fn enqueue(&self, _new: &NewQueuedJob, _now: DateTime<Utc>) -> Result<Option<QueuedJob>> {
            // The shape a contended SQLite writer has: the statement never comes back inside
            // any interval the caller cares about.
            tokio::time::sleep(StdDuration::from_secs(60)).await;
            unreachable!("the deadline must fire first")
        }

        async fn get(&self, id: QueuedJobId) -> Result<Option<QueuedJob>> {
            self.inner.get(id).await
        }

        async fn claim(
            &self,
            kinds: &[JobKind],
            limit: u32,
            lease: StdDuration,
            now: DateTime<Utc>,
        ) -> Result<Vec<QueuedJob>> {
            self.inner.claim(kinds, limit, lease, now).await
        }

        async fn complete(
            &self,
            id: QueuedJobId,
            outcome: QueueOutcome,
            backoff: StdDuration,
            now: DateTime<Utc>,
        ) -> Result<()> {
            self.inner.complete(id, outcome, backoff, now).await
        }

        async fn reap_expired_leases(&self, now: DateTime<Utc>) -> Result<u64> {
            self.inner.reap_expired_leases(now).await
        }

        async fn purge(&self, retention: &pub_core::queue::QueueRetention) -> Result<pub_core::queue::QueuePurged> {
            self.inner.purge(retention).await
        }

        async fn depth(&self) -> Result<Vec<(JobKind, QueueState, i64)>> {
            self.inner.depth().await
        }
    }

    let harness = Harness::new(MailMode::Deliver).await;
    let members = harness.members(2).await;
    let hanging = Arc::new(HangingQueue { inner: Arc::clone(&harness.repos.queue) });
    let handler = FanoutHandler::new(
        harness.center(),
        hanging as Arc<dyn pub_core::traits::JobQueueRepo>,
        StdDuration::from_millis(50),
    );
    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let job = QueuedJob {
        id: QueuedJobId::new(),
        kind: JobKind::NotificationFanout,
        priority: NewQueuedJob::BULK,
        payload: serde_json::to_value(FanoutJob { envelope }).unwrap(),
        state: QueueState::Running,
        attempts: 1,
        run_after: t0(),
        locked_until: None,
        dedupe_key: None,
        last_error: None,
        created_at: t0(),
        updated_at: t0(),
    };

    let started = std::time::Instant::now();
    let report = handler.run(&job, t0()).await;
    let elapsed = started.elapsed();
    assert!(elapsed < StdDuration::from_secs(5), "the handler must give up on its own: took {elapsed:?}");
    match report.outcome {
        // Transient: the rows this run did file are idempotent, so the retry converges.
        QueueOutcome::Retry(message) => {
            assert!(message.contains("exceeded"), "the retry must name the deadline: {message}")
        }
        other => panic!("an unbounded fan-out must not report success: {other:?}"),
    }
}

#[tokio::test]
async fn d43_retention_bounds_every_terminal_state_not_only_the_completed_one() {
    // Decision 26 promises the queue "does not become the next unbounded table", and retention
    // covered exactly one of the three states a row settles in. The two it missed are the ones
    // that matter: a suppressed row is filed by an *unauthenticated* endpoint, one per
    // policy-rejected sign-in attempt, each carrying the attempted address in the clear and
    // with no reader once the request that filed it returned; dead letters accumulate one per
    // message that never arrived.
    let harness = Harness::new(MailMode::Deliver).await;
    let policy = QueuePolicy {
        retain_suppressed: Duration::hours(1),
        retain_done: Duration::hours(24),
        retain_dead: Duration::days(30),
        max_attempts: 1,
        ..QueuePolicy::default()
    };
    let worker = harness.worker(policy);

    let suppressed = harness
        .repos
        .queue
        .enqueue(&NewQueuedJob::suppressed(MailJob::KIND, serde_json::json!({ "to": "blocked@evil.test" })), t0())
        .await
        .expect("enqueue")
        .expect("row")
        .id;
    harness.enqueue_mail("alice@corp.com").await;
    worker.run_once(t0()).await.expect("drain");
    harness.mailer.set(MailMode::Reject);
    harness.enqueue_mail("not an address").await;
    worker.run_once(t0()).await.expect("drain");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Suppressed).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // Two hours on: the suppressed row is gone and nothing else is.
    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("drain");
    assert_eq!(report.purged, 1);
    assert_eq!(report.purged_dead, 0);
    assert_eq!(harness.repos.queue.get(suppressed).await.expect("get"), None, "a suppressed row is not kept for a day");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // A day on: the completed row goes, the dead letter stays for the operator.
    let report = worker.run_once(t0() + Duration::hours(25)).await.expect("drain");
    assert_eq!(report.purged, 1);
    assert_eq!(report.purged_dead, 0);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // A month on: the record is bounded too, and the drain reports what it destroyed.
    let report = worker.run_once(t0() + Duration::days(31)).await.expect("drain");
    assert_eq!(report.purged, 1);
    assert_eq!(report.purged_dead, 1, "an operator has to be able to see that a dead letter was deleted");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 0);
    assert_eq!(report.dead_pending, 0);
}

#[tokio::test]
async fn d2_a_duplicate_enqueue_of_one_event_is_a_no_op() {
    // The bus swallows consumer errors, so a retried emission of the same envelope is a real
    // shape — and it must not become a second copy of everybody's notification.
    let harness = Harness::new(MailMode::Deliver).await;
    let envelope = EventEnvelope::new(published(harness.org));
    let job = FanoutJob { envelope: envelope.clone() };
    let payload = serde_json::to_value(&job).unwrap();
    let new = NewQueuedJob::pending(FanoutJob::KIND, payload).with_dedupe_key(job.dedupe_key());

    assert!(harness.repos.queue.enqueue(&new, t0()).await.expect("first").is_some());
    assert!(harness.repos.queue.enqueue(&new, t0()).await.expect("second").is_none(), "a repeat is a no-op");
    assert_eq!(harness.queued(JobKind::NotificationFanout, QueueState::Pending).await, 1);

    // A *second emission* of the same event is a different work item: the id is minted per
    // emission, so two genuine publishes are still two fan-outs.
    let second = FanoutJob { envelope: EventEnvelope::new(published(harness.org)) };
    let payload = serde_json::to_value(&second).unwrap();
    let new = NewQueuedJob::pending(FanoutJob::KIND, payload).with_dedupe_key(second.dedupe_key());
    assert!(harness.repos.queue.enqueue(&new, t0()).await.expect("third").is_some());
    assert_eq!(harness.queued(JobKind::NotificationFanout, QueueState::Pending).await, 2);
}

#[tokio::test]
async fn d2_a_fanout_retry_never_sends_a_second_copy_of_a_message() {
    // A fan-out that is re-run — a crash between the batch and the completion, a reaped lease —
    // must not mail everybody twice. Each mail item is keyed on `(event, recipient)`, so the
    // second run's enqueues are no-ops.
    let harness = Harness::new(MailMode::Deliver).await;
    let members = harness.members(3).await;
    let center = harness.center();
    let handler = FanoutHandler::new(center, Arc::clone(&harness.repos.queue), SEND_TIMEOUT);
    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let payload = serde_json::to_value(FanoutJob { envelope: envelope.clone() }).unwrap();
    let job = QueuedJob {
        id: QueuedJobId::new(),
        kind: JobKind::NotificationFanout,
        priority: NewQueuedJob::INTERACTIVE,
        payload,
        state: QueueState::Running,
        attempts: 1,
        run_after: t0(),
        locked_until: None,
        dedupe_key: Some(format!("fanout:{}", envelope.id)),
        last_error: None,
        created_at: t0(),
        updated_at: t0(),
    };

    let first = handler.run(&job, t0()).await;
    let after_first = harness.queued(JobKind::MailSend, QueueState::Pending).await;
    assert_eq!(after_first, 4, "one message per recipient (three members plus the owner)");
    assert_eq!(first.followups.len(), 4, "one `UserNotified` per row the run filed");

    let second = handler.run(&job, t0()).await;
    assert_eq!(
        harness.queued(JobKind::MailSend, QueueState::Pending).await,
        after_first,
        "a re-run fan-out must not file a second copy of anybody's message"
    );
    // And — the half the dedupe key could never cover — no second *notification row* either.
    // Decision 26's amendment moved that guarantee from a cross-table transaction the
    // repositories cannot express to a uniqueness constraint on `(user_id, event_id)`, which
    // also holds against any future path that re-emits an event.
    for member in &members {
        let feed = harness.repos.notifications.list(*member, false, None, 10).await.expect("feed");
        assert_eq!(feed.items.len(), 1, "a re-run fan-out filed a second copy of somebody's notification");
    }
    assert!(
        second.followups.is_empty(),
        "a re-run announces only the rows it filed, and it filed none: {:?}",
        second.followups.len()
    );

    let worker = harness.worker(QueuePolicy::default());
    worker.run_once(t0()).await.expect("drain");
    assert_eq!(harness.mailer.sent().len(), 4, "and therefore must not send one either");
}

#[tokio::test]
async fn d44_a_notification_email_that_cannot_be_queued_is_not_lost_in_silence() {
    // The fan-out logged a failed per-recipient enqueue and reported `Done` anyway, so one
    // recipient's email disappeared with no metric, no dead letter and nothing on the admin
    // surface — while the same failure one layer up increments `notification_enqueue_failed_total`
    // (decision 22's amendment makes that observability contractual). The item now asks to be
    // run again, which is safe because both halves of a fan-out are idempotent.
    struct RefusingQueue {
        inner: Arc<dyn pub_core::traits::JobQueueRepo>,
        refuse: Mutex<bool>,
    }

    #[async_trait]
    impl pub_core::traits::JobQueueRepo for RefusingQueue {
        async fn ping(&self) -> Result<()> {
            self.inner.ping().await
        }

        async fn enqueue(&self, new: &NewQueuedJob, now: DateTime<Utc>) -> Result<Option<QueuedJob>> {
            if *self.refuse.lock().unwrap() {
                return Err(Error::Database { message: "the queue is unavailable".to_owned() });
            }
            self.inner.enqueue(new, now).await
        }

        async fn get(&self, id: QueuedJobId) -> Result<Option<QueuedJob>> {
            self.inner.get(id).await
        }

        async fn claim(
            &self,
            kinds: &[JobKind],
            limit: u32,
            lease: StdDuration,
            now: DateTime<Utc>,
        ) -> Result<Vec<QueuedJob>> {
            self.inner.claim(kinds, limit, lease, now).await
        }

        async fn complete(
            &self,
            id: QueuedJobId,
            outcome: QueueOutcome,
            backoff: StdDuration,
            now: DateTime<Utc>,
        ) -> Result<()> {
            self.inner.complete(id, outcome, backoff, now).await
        }

        async fn reap_expired_leases(&self, now: DateTime<Utc>) -> Result<u64> {
            self.inner.reap_expired_leases(now).await
        }

        async fn purge(&self, retention: &pub_core::queue::QueueRetention) -> Result<pub_core::queue::QueuePurged> {
            self.inner.purge(retention).await
        }

        async fn depth(&self) -> Result<Vec<(JobKind, QueueState, i64)>> {
            self.inner.depth().await
        }
    }

    let harness = Harness::new(MailMode::Deliver).await;
    let members = harness.members(2).await;
    let refusing = Arc::new(RefusingQueue { inner: Arc::clone(&harness.repos.queue), refuse: Mutex::new(true) });
    let handler = FanoutHandler::new(
        harness.center(),
        Arc::clone(&refusing) as Arc<dyn pub_core::traits::JobQueueRepo>,
        SEND_TIMEOUT,
    );
    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let job = QueuedJob {
        id: QueuedJobId::new(),
        kind: JobKind::NotificationFanout,
        priority: NewQueuedJob::INTERACTIVE,
        payload: serde_json::to_value(FanoutJob { envelope }).unwrap(),
        state: QueueState::Running,
        attempts: 1,
        run_after: t0(),
        locked_until: None,
        dedupe_key: None,
        last_error: None,
        created_at: t0(),
        updated_at: t0(),
    };

    let report = handler.run(&job, t0()).await;
    match report.outcome {
        QueueOutcome::Retry(message) => assert!(message.contains("could not be queued"), "{message}"),
        other => panic!("a lost notification email must not report success: {other:?}"),
    }
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Pending).await, 0, "nothing was queued");

    // The retry recovers the messages rather than duplicating the rows the first run filed.
    *refusing.refuse.lock().unwrap() = false;
    let second = handler.run(&job, t0()).await;
    assert_eq!(second.outcome, QueueOutcome::Done);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Pending).await, 3, "every recipient's mail is filed now");
    for member in &members {
        assert_eq!(harness.repos.notifications.list(*member, false, None, 10).await.expect("feed").items.len(), 1);
    }
}

#[tokio::test]
async fn d2_an_item_is_completed_before_its_followups_are_published() {
    // `pub_core::event` promises a client acting on an event finds the row it names. The queue
    // keeps that by completing the item first and publishing second — asserted here by sampling
    // the row's state from inside the broker publish the bus performs.
    struct Followup;

    #[async_trait]
    impl JobHandler for Followup {
        fn kind(&self) -> JobKind {
            JobKind::MailSend
        }

        async fn run(&self, _job: &QueuedJob, _now: DateTime<Utc>) -> HandlerReport {
            HandlerReport {
                outcome: QueueOutcome::Done,
                followups: vec![DomainEvent::UserNotified {
                    user_id: UserId::new(),
                    notification_id: pub_core::NotificationId::new(),
                    category: NotificationCategory::Org,
                    title: "filed".to_owned(),
                    unread: 1,
                    at: t0(),
                }],
            }
        }
    }

    let harness = Harness::new(MailMode::Deliver).await;
    let kv = Arc::new(OrderingKv {
        repos: harness.repos.clone(),
        watching: Mutex::new(None),
        observed: Mutex::new(Vec::new()),
    });
    let bus = Arc::new(EventBus::new(EventBusPolicy::default()).with_broker(Arc::clone(&kv) as Arc<dyn Kv>));
    let worker = QueueWorker::new(harness.repos.clone(), bus, QueuePolicy::default()).with_handler(Arc::new(Followup));

    let id = harness.enqueue_mail("alice@corp.com").await;
    *kv.watching.lock().unwrap() = Some(id);
    worker.run_once(t0()).await.expect("drain");

    let observed = kv.observed.lock().unwrap().clone();
    assert_eq!(
        observed,
        vec![Some(QueueState::Done)],
        "the follow-up was published while the item was still {observed:?} — a reader would act on \
         an event whose row is not committed"
    );
}

#[tokio::test]
async fn d12_retention_purges_done_rows_and_keeps_the_operators_record() {
    let harness = Harness::new(MailMode::Deliver).await;
    let policy = QueuePolicy { retain_done: Duration::hours(24), max_attempts: 1, ..QueuePolicy::default() };
    let worker = harness.worker(policy);

    harness.enqueue_mail("alice@corp.com").await;
    worker.run_once(t0()).await.expect("drain");
    harness.mailer.set(MailMode::Reject);
    harness.enqueue_mail("not an address").await;
    worker.run_once(t0()).await.expect("drain");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // A tick a day later collects the completed row and leaves the dead letter alone: a
    // dead-lettered sign-in message is an account lockout with no other visible cause, so it is
    // the operator's record and retention must never eat it.
    let report = worker.run_once(t0() + Duration::hours(25)).await.expect("drain");
    assert_eq!(report.purged, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 0);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);
    assert_eq!(report.dead_pending, 1);
}

#[tokio::test]
async fn s26_b_a_queued_sign_in_body_is_unreadable_in_the_table_and_delivered_in_the_clear() {
    // The row a database dump, a replica or a backup would contain must not hold a redeemable
    // code; the worker is the only thing that ever sees the plaintext.
    //
    // The payload is built from the **production renderer**, not from a hand-written literal.
    // Every one of the suite's seven `MailJob` construction sites used to hard-code a benign
    // subject, so the assertion below passed while production shipped `"{code} is your sign-in
    // code"` — the code in the clear in the one column that is deliberately not sealed. A test
    // that constructs its own subject cannot see a leak in the template that makes them.
    let harness = Harness::new(MailMode::Deliver).await;
    let rendered = pub_mail::render_otp_email(CODE, Some("203.0.113.7"), 10).expect("render the sign-in email");
    let seal = |plaintext: &str| {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pub_auth::secretbox::seal(&KEK, &pub_auth::random::OsRandom, plaintext.as_bytes()).unwrap(),
        )
    };
    let payload = serde_json::to_value(MailJob {
        to: "alice@corp.com".to_owned(),
        subject: rendered.subject.clone(),
        text: seal(&rendered.text),
        html: Some(seal(&rendered.html)),
        sealed: true,
    })
    .unwrap();
    let id = harness
        .repos
        .queue
        .enqueue(&NewQueuedJob::pending(MailJob::KIND, payload), t0())
        .await
        .expect("enqueue")
        .expect("row")
        .id;

    let stored = harness.row(id).await;
    assert!(!stored.payload.to_string().contains(CODE), "the stored row must not hold the code: {}", stored.payload);
    assert!(stored.payload["to"].as_str() == Some("alice@corp.com"), "the recipient stays identifiable");
    assert!(!stored.payload["subject"].as_str().expect("subject").is_empty(), "a dead letter stays identifiable");
    // Nor may a log line: the row's own `Debug` redacts the payload (S-25.a).
    assert!(!format!("{stored:?}").contains(CODE));

    harness.worker(QueuePolicy::default()).run_once(t0()).await.expect("drain");
    assert!(harness.mailer.sent()[0].2.contains(CODE), "the delivered message is the plaintext");
}

#[tokio::test]
async fn the_admin_job_table_reports_the_standing_dead_letter_count() {
    // Decision 22's amendment makes this part of the contract rather than instrumentation: a
    // dead-lettered sign-in message is an account lockout with no other visible cause, so it
    // has to be readable on the surface an operator already looks at.
    let harness = Harness::new(MailMode::Reject).await;
    let worker = harness.worker(QueuePolicy::default());
    harness.enqueue_mail("not an address").await;
    worker.run_once(t0()).await.expect("drain");

    let state = worker.status(t0()).await.expect("job state");
    assert_eq!(state.phase, "drain (1 dead)", "the dead letter must be visible without reading the queue table");
    assert_eq!(state.failures, 1);

    // A clean instance says nothing alarming.
    let clean = Harness::new(MailMode::Deliver).await;
    let clean_worker = clean.worker(QueuePolicy::default());
    clean.enqueue_mail("alice@corp.com").await;
    clean_worker.run_once(t0()).await.expect("drain");
    assert_eq!(clean_worker.status(t0()).await.expect("job state").phase, "drain");
}
