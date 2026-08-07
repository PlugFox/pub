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
//! | A permanent failure does not burn the budget | [`d2_a_malformed_recipient_deadletters_immediately`] |
//! | One event, one batch, one mail item per recipient | [`d2_the_fanout_files_every_recipient_in_one_batch_and_queues_their_mail`] |
//! | Re-enqueueing one event is a no-op | [`d2_a_duplicate_enqueue_of_one_event_is_a_no_op`] |
//! | A re-run fan-out never re-sends a message | [`d2_a_fanout_retry_never_sends_a_second_copy_of_a_message`] |
//! | The item is completed before its follow-ups are published | [`d2_an_item_is_completed_before_its_followups_are_published`] |
//! | Retention deletes done rows and keeps dead ones | [`d12_retention_purges_done_rows_and_keeps_the_operators_record`] |

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
use pub_events::{EventBus, EventBusPolicy, NotificationCenter, NotificationPolicy};
use pub_jobs::queue::{HandlerReport, JobHandler};
use pub_jobs::{FanoutHandler, MailHandler, QueuePolicy, QueueWorker};

const KEK: [u8; 32] = [11u8; 32];

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
}

struct ScriptedMailer {
    mode: Mutex<MailMode>,
    sent: Mutex<Vec<(String, String, String)>>,
}

impl ScriptedMailer {
    fn new(mode: MailMode) -> Arc<Self> {
        Arc::new(Self { mode: Mutex::new(mode), sent: Mutex::new(Vec::new()) })
    }

    fn set(&self, mode: MailMode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn sent(&self) -> Vec<(String, String, String)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl Mailer for ScriptedMailer {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let mode = *self.mode.lock().unwrap();
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
            .with_handler(Arc::new(FanoutHandler::new(self.center(), Arc::clone(&self.repos.queue))))
            .with_handler(Arc::new(MailHandler::new(
                Arc::clone(&self.mailer) as Arc<dyn Mailer>,
                KEK.to_vec(),
                policy.send_timeout,
            )))
    }

    async fn enqueue_mail(&self, to: &str) -> QueuedJobId {
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
            .enqueue(&NewQueuedJob::pending(MailJob::KIND, payload), t0())
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
    let handler = FanoutHandler::new(center, Arc::clone(&harness.repos.queue));
    let envelope = EventEnvelope::new(membership(harness.org, members[0]));
    let payload = serde_json::to_value(FanoutJob { envelope: envelope.clone() }).unwrap();
    let job = QueuedJob {
        id: QueuedJobId::new(),
        kind: JobKind::NotificationFanout,
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

    handler.run(&job, t0()).await;
    let after_first = harness.queued(JobKind::MailSend, QueueState::Pending).await;
    assert_eq!(after_first, 4, "one message per recipient (three members plus the owner)");

    handler.run(&job, t0()).await;
    assert_eq!(
        harness.queued(JobKind::MailSend, QueueState::Pending).await,
        after_first,
        "a re-run fan-out must not file a second copy of anybody's message"
    );

    let worker = harness.worker(QueuePolicy::default());
    worker.run_once(t0()).await.expect("drain");
    assert_eq!(harness.mailer.sent().len(), 4, "and therefore must not send one either");
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
