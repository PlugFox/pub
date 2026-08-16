//! S-23 retention over a real migrated database (decision 30).
//!
//! Everything here runs the production [`LifecycleWorker`] against real rows in a real schema. A
//! retention suite against repository doubles would prove the doubles delete, which is not the
//! property at risk: the risks are a predicate that deletes a row somebody can still use, a bound
//! that does not actually bound, and a loop that reports "drained" when it ran out of time.
//!
//! | Rule | Test |
//! |------|------|
//! | Every terminal queue state has a window | [`d43_retention_bounds_every_terminal_state_not_only_the_completed_one`] |
//! | A deleted dead letter is reported apart from the rest | [`d43_a_deleted_dead_letter_is_never_silent`] |
//! | A truncated pass reports what it deleted and resumes | [`d47_a_truncated_pass_reports_the_rows_it_did_delete_and_resumes_next_tick`] |
//! | Done rows go, the operator's dead letter stays | [`d12_retention_purges_done_rows_and_keeps_the_operators_record`] |
//! | A released backlog is drained across statements, not in one | [`d47_a_released_backlog_is_deleted_in_batches_not_in_one_statement`] |
//! | A live session survives retention | [`d12_a_session_that_can_still_authenticate_is_never_purged`] |
//! | A live invitation survives any window | [`d12_a_live_invitation_is_undeletable_at_any_retention_window`] |
//! | Notifications age by date, not by read state | [`d12_notifications_are_purged_by_age_regardless_of_read_state`] |
//! | The audit floor refuses a recent cutoff | [`s22_a_an_audit_cutoff_inside_the_floor_is_refused`] |
//! | A refused table does not cost the others their sweep | [`s22_a_a_refused_audit_prune_still_lets_every_other_table_sweep`] |
//! | Every table appears in the report, including disabled ones | [`d12_the_report_names_every_table_including_the_ones_kept_forever`] |
//! | A table the budget never reached is not a backlog | [`d12_a_table_the_budget_never_reached_is_not_reported_as_a_backlog`] |

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, NaiveDate, TimeZone as _, Utc};
use pub_core::audit::{AuditActor, AuditEvent, AuditFilter, AuditResult, NewAuditEvent};
use pub_core::notification::{NewNotification, NotificationCategory};
use pub_core::org::{NewInvitation, NewOrg};
use pub_core::queue::{JobKind, MailJob, NewQueuedJob, QueueOutcome, QueueState};
use pub_core::retention::{RetentionPolicy, RetentionReport, TableOutcome};
use pub_core::session::NewSession;
use pub_core::traits::{AuditRepo, Repositories};
use pub_core::user::NewUser;
use pub_core::{Error, OrgId, Page, Result, RoleLevel, UserId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{LifecyclePolicy, LifecycleWorker};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

/// A real migrated SQLite database with one org and one owner.
struct Harness {
    repos: Repositories,
    owner: UserId,
    org: OrgId,
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
        Self { repos, owner, org }
    }

    fn worker(&self, policy: LifecyclePolicy) -> LifecycleWorker {
        LifecycleWorker::new(self.repos.clone(), policy)
    }

    /// A worker over repositories whose audit log is `audit` instead of the real one.
    fn worker_with_audit(&self, policy: LifecyclePolicy, audit: Arc<dyn AuditRepo>) -> LifecycleWorker {
        let mut repos = self.repos.clone();
        repos.audit = audit;
        LifecycleWorker::new(repos, policy)
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

    /// Files one mail row and settles it into `state` without running a real drain.
    async fn settled_mail(&self, to: &str, state: QueueState, at: DateTime<Utc>) {
        let job = MailJob::KIND;
        let payload = serde_json::json!({ "to": to });
        match state {
            QueueState::Suppressed => {
                self.repos
                    .queue
                    .enqueue(&NewQueuedJob::suppressed(job, payload), at)
                    .await
                    .expect("enqueue")
                    .expect("row");
            }
            QueueState::Done | QueueState::Dead => {
                let id = self
                    .repos
                    .queue
                    .enqueue(&NewQueuedJob::pending(job, payload), at)
                    .await
                    .expect("enqueue")
                    .expect("row")
                    .id;
                let claimed = self.repos.queue.claim(&[job], 10, StdDuration::from_secs(60), at).await.expect("claim");
                let outcome = if state == QueueState::Done {
                    QueueOutcome::Done
                } else {
                    QueueOutcome::Dead("undeliverable".to_owned())
                };
                self.repos
                    .queue
                    .complete(id, claimed[0].attempts, outcome, StdDuration::ZERO, at)
                    .await
                    .expect("complete");
            }
            QueueState::Pending | QueueState::Running => panic!("not a settled state"),
        }
    }

    async fn session(&self, hash: &str, last_seen: DateTime<Utc>) -> pub_core::SessionId {
        let session = self
            .repos
            .sessions
            .create(
                NewSession {
                    user_id: self.owner,
                    refresh_hash: hash.to_owned(),
                    user_agent: Some("test".to_owned()),
                    ip: Some("203.0.113.9".to_owned()),
                },
                last_seen,
            )
            .await
            .expect("session");
        session.id
    }

    async fn invitation(&self, email: &str, hash: &str, expires_at: DateTime<Utc>) {
        self.repos
            .orgs
            .create_invitation(
                NewInvitation {
                    org_id: self.org,
                    email: email.to_owned(),
                    role: RoleLevel::READ,
                    invited_by: self.owner,
                    token_hash: hash.to_owned(),
                    expires_at,
                },
                expires_at - Duration::days(7),
            )
            .await
            .expect("invitation");
    }

    async fn notification(&self, title: &str, at: DateTime<Utc>, read: bool) {
        let rows = self
            .repos
            .notifications
            .create_many(
                &[NewNotification {
                    user_id: self.owner,
                    category: NotificationCategory::Package,
                    event_id: None,
                    event: "package.published".to_owned(),
                    title: title.to_owned(),
                    org_id: Some(self.org),
                    payload: serde_json::json!({}),
                }],
                at,
            )
            .await
            .expect("notification");
        if read {
            let ids: Vec<_> = rows.iter().map(|row| row.id).collect();
            self.repos.notifications.mark_read(self.owner, &ids, at).await.expect("mark read");
        }
    }

    async fn audit(&self, action: &str, at: DateTime<Utc>) {
        self.repos
            .audit
            .append(
                NewAuditEvent {
                    actor: AuditActor::System,
                    ip: None,
                    user_agent: None,
                    org_id: Some(self.org),
                    action: action.to_owned(),
                    target: None,
                    result: AuditResult::Success,
                    metadata: None,
                },
                at,
            )
            .await
            .expect("audit row");
    }

    async fn audit_count(&self) -> usize {
        self.repos.audit.list(&AuditFilter::default(), None, 200).await.expect("list").items.len()
    }

    async fn notification_count(&self) -> i64 {
        self.repos.notifications.list(self.owner, false, None, 200).await.expect("list").items.len().try_into().unwrap()
    }
}

/// The shipped defaults, with the batch and budget a test wants to control.
fn policy(batch: u32, budget: StdDuration) -> LifecyclePolicy {
    LifecyclePolicy {
        interval: StdDuration::from_secs(900),
        retention: RetentionPolicy {
            audit: Some(Duration::days(730)),
            sessions: Some(Duration::days(30)),
            invitations: Some(Duration::days(30)),
            notifications: Some(Duration::days(180)),
            download_stats: None,
            quarantine: Some(Duration::days(730)),
            shadowing: Some(Duration::days(730)),
            batch,
            budget,
        },
        queue_done: Duration::hours(24),
        queue_suppressed: Duration::hours(1),
        queue_dead: Duration::days(30),
    }
}

/// The line a report carries for one table.
fn outcome_for<'a>(report: &'a RetentionReport, table: &str) -> &'a TableOutcome {
    &report.tables.iter().find(|line| line.table == table).expect("table in the report").outcome
}

fn deleted_from(report: &RetentionReport, table: &str) -> u64 {
    outcome_for(report, table).deleted()
}

#[tokio::test]
async fn d43_retention_bounds_every_terminal_state_not_only_the_completed_one() {
    // Moved here from the drain's suite when decision 30 made this job the only thing that
    // deletes. The property is unchanged: every state a row settles in has a window, and the two
    // that used to be missed are the ones that matter — a `suppressed` row is filed by an
    // *unauthenticated* endpoint, one per policy-rejected sign-in, each carrying the attempted
    // address in the clear and with no reader once the request that filed it returned; dead letters
    // accumulate one per message that never arrived.
    let harness = Harness::new().await;
    harness.settled_mail("blocked@evil.test", QueueState::Suppressed, t0()).await;
    harness.settled_mail("alice@corp.com", QueueState::Done, t0()).await;
    harness.settled_mail("not an address", QueueState::Dead, t0()).await;
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Suppressed).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    let worker = harness.worker(policy(1_000, StdDuration::from_secs(60)));

    // Two hours on: the suppressed row is gone and nothing else is.
    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("pass");
    assert_eq!(deleted_from(&report, "job_queue:suppressed"), 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Suppressed).await, 0, "not kept for a day");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // A day on: the completed row goes, the dead letter stays for the operator.
    let report = worker.run_once(t0() + Duration::hours(25)).await.expect("pass");
    assert_eq!(deleted_from(&report, "job_queue:done"), 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);

    // A month on: the record is bounded too.
    let report = worker.run_once(t0() + Duration::days(31)).await.expect("pass");
    assert_eq!(deleted_from(&report, "job_queue:dead"), 1);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 0);
}

#[tokio::test]
async fn d12_retention_purges_done_rows_and_keeps_the_operators_record() {
    let harness = Harness::new().await;
    harness.settled_mail("alice@corp.com", QueueState::Done, t0()).await;
    harness.settled_mail("not an address", QueueState::Dead, t0()).await;

    // A pass a day later collects the completed row and leaves the dead letter alone: a
    // dead-lettered sign-in message is an account lockout with no other visible cause, so it is
    // the operator's record and retention must never eat it early.
    let worker = harness.worker(policy(1_000, StdDuration::from_secs(60)));
    let report = worker.run_once(t0() + Duration::hours(25)).await.expect("pass");
    assert_eq!(deleted_from(&report, "job_queue:done"), 1);
    assert_eq!(deleted_from(&report, "job_queue:dead"), 0, "the operator's record is not retention's yet");
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Done).await, 0);
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Dead).await, 1);
}

#[tokio::test]
async fn d47_a_released_backlog_is_deleted_in_batches_not_in_one_statement() {
    // The exit condition for D47: an operator lowering a window, a restored backup or a forward
    // clock correction releases a whole backlog at once, and the pass must take it in bounded
    // statements. Unbounded, that one DELETE holds SQLite's single writer for its full duration
    // and every concurrent publish-finalize or sign-in becomes SQLITE_BUSY instead of a wait.
    let harness = Harness::new().await;
    for index in 0..25 {
        harness.notification(&format!("old {index}"), t0(), index % 2 == 0).await;
    }
    assert_eq!(harness.notification_count().await, 25);

    let worker = harness.worker(policy(10, StdDuration::from_secs(60)));
    let report = worker.run_once(t0() + Duration::days(200)).await.expect("pass");

    match outcome_for(&report, "notifications") {
        TableOutcome::Swept { deleted, passes, converged } => {
            assert_eq!(*deleted, 25);
            // 10 + 10 + 5: three statements, and the third is what proves convergence rather
            // than a fourth empty one.
            assert_eq!(*passes, 3, "a batch of 10 over 25 rows must be three statements");
            assert!(converged, "a short pass means the table is drained");
        }
        other => panic!("expected a swept table, got {other:?}"),
    }
    assert_eq!(harness.notification_count().await, 0);
}

#[tokio::test]
async fn d47_a_truncated_pass_reports_the_rows_it_did_delete_and_resumes_next_tick() {
    // The property D47's exit rests on: a released backlog is drained *across ticks*, and the pass
    // that stops halfway says so while still reporting what it removed. Asserted on the queue,
    // which is swept first — so "the budget ran out mid-loop" is deterministic here, where on a
    // later table it would race the earlier tables' statements. It is also the only coverage
    // `sweep_queue`'s own budget-and-convergence loop has.
    let harness = Harness::new().await;
    for index in 0..60 {
        harness.settled_mail(&format!("blocked{index}@evil.test"), QueueState::Suppressed, t0()).await;
    }
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Suppressed).await, 60);

    // One row per statement against a budget that expires part-way through sixty of them.
    let worker = harness.worker(policy(1, StdDuration::from_millis(5)));
    let first = worker.run_once(t0() + Duration::hours(2)).await.expect("pass");

    match outcome_for(&first, "job_queue:suppressed") {
        TableOutcome::Swept { deleted, passes, converged } => {
            assert!(*deleted > 0, "a truncated pass must report the rows it actually deleted, not zero");
            assert_eq!(u64::from(*passes), *deleted, "one row per statement at batch = 1");
            assert!(!converged, "sixty rows cannot drain one at a time inside five milliseconds");
        }
        other => panic!("expected a swept table, got {other:?}"),
    }
    let left = harness.queued(JobKind::MailSend, QueueState::Suppressed).await;
    assert!(left > 0 && left < 60, "the pass deleted some and left some, got {left}");
    assert!(first.unconverged().contains(&"job_queue:suppressed"));

    // Ticks continue from where the last one stopped — no cursor, just the same predicate. This is
    // the "drained across ticks" half of the promise, which nothing else asserts.
    let generous = harness.worker(policy(1_000, StdDuration::from_secs(60)));
    let second = generous.run_once(t0() + Duration::hours(2)).await.expect("pass");
    assert_eq!(deleted_from(&second, "job_queue:suppressed"), u64::try_from(left).expect("non-negative"));
    assert_eq!(harness.queued(JobKind::MailSend, QueueState::Suppressed).await, 0);
}

#[tokio::test]
async fn d43_a_deleted_dead_letter_is_never_silent() {
    // Decision 26 calls the dead-letter deletion "the one deletion here that destroys a record
    // somebody may still need, so it is the one that is never silent". When retention moved off the
    // drain the per-state split left the report — `TableOutcome::deleted` is one total across all
    // three states — so nothing observed that promise any more. The observable that survived the
    // move is the metric, and this asserts the job reaches it with the dead count specifically.
    let harness = Harness::new().await;
    harness.settled_mail("gone@corp.com", QueueState::Done, t0()).await;
    harness.settled_mail("never arrived", QueueState::Dead, t0()).await;

    let worker = harness.worker(policy(1_000, StdDuration::from_secs(60)));
    let report = worker.run_once(t0() + Duration::days(31)).await.expect("pass");

    // Reported apart from the completed row, not folded into a `job_queue` total where nobody would
    // notice which of the two it was.
    assert_eq!(deleted_from(&report, "job_queue:done"), 1);
    assert_eq!(deleted_from(&report, "job_queue:dead"), 1, "the deletion that destroys the operator's record");
    assert_eq!(deleted_from(&report, "job_queue:suppressed"), 0);
}

#[tokio::test]
async fn d12_a_session_that_can_still_authenticate_is_never_purged() {
    // The predicate is `last_seen_at < cutoff`, and the window is validated at or above the idle
    // window, so a purged row is one that had already stopped being usable. This asserts the
    // boundary from both sides on one pass.
    let harness = Harness::new().await;
    let stale = harness.session("a".repeat(64).as_str(), t0() - Duration::days(31)).await;
    let live = harness.session("b".repeat(64).as_str(), t0() - Duration::days(29)).await;

    let worker = harness.worker(policy(1_000, StdDuration::from_secs(60)));
    let report = worker.run_once(t0()).await.expect("pass");

    assert_eq!(deleted_from(&report, "sessions"), 1);
    assert!(harness.repos.sessions.list_for_user(harness.owner).await.expect("list").iter().any(|s| s.id == live));
    assert!(!harness.repos.sessions.list_for_user(harness.owner).await.expect("list").iter().any(|s| s.id == stale));
}

#[tokio::test]
async fn d12_a_live_invitation_is_undeletable_at_any_retention_window() {
    // The reason the predicate uses `COALESCE(accepted_at, revoked_at, expires_at)` and not
    // `created_at`: a one-day retention window must not be able to delete a seven-day invitation
    // link that somebody is still holding. The property comes from the statement, not from a
    // validator that happens to keep the window longer than the invitation TTL.
    let harness = Harness::new().await;
    harness.invitation("live@corp.com", &"c".repeat(64), t0() + Duration::days(5)).await;
    harness.invitation("expired@corp.com", &"d".repeat(64), t0() - Duration::days(40)).await;

    let mut policy = policy(1_000, StdDuration::from_secs(60));
    policy.retention.invitations = Some(Duration::days(1));
    let report = harness.worker(policy).run_once(t0()).await.expect("pass");

    assert_eq!(deleted_from(&report, "invitations"), 1, "only the settled one goes");
    let pending = harness.repos.orgs.list_invitations(harness.org).await.expect("list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].email, "live@corp.com");
}

#[tokio::test]
async fn d12_notifications_are_purged_by_age_regardless_of_read_state() {
    // Read state is deliberately not in the predicate: a window that depends on it is a table
    // whose growth depends on user behaviour.
    let harness = Harness::new().await;
    harness.notification("old and unread", t0() - Duration::days(200), false).await;
    harness.notification("old and read", t0() - Duration::days(200), true).await;
    harness.notification("recent and unread", t0() - Duration::days(10), false).await;

    let worker = harness.worker(policy(1_000, StdDuration::from_secs(60)));
    let report = worker.run_once(t0()).await.expect("pass");

    assert_eq!(deleted_from(&report, "notifications"), 2);
    assert_eq!(harness.notification_count().await, 1);
}

#[tokio::test]
async fn s22_a_an_audit_cutoff_inside_the_floor_is_refused() {
    // The floor is the property that makes the app's reachable capability "delete audit rows older
    // than a month" rather than "delete audit rows" — evidence of an attack is recent. On SQLite
    // the repository is the only place that can enforce it, so this asserts the repository, not the
    // Postgres function that also does.
    let harness = Harness::new().await;
    harness.audit("auth.signin", t0() - Duration::days(400)).await;

    let err = harness
        .repos
        .audit
        .prune_before(t0() - Duration::days(29), t0(), 100)
        .await
        .expect_err("a cutoff inside the floor must be refused");
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(harness.audit_count().await, 1, "a refused prune deletes nothing");

    // One day outside the floor is accepted, so the boundary is a boundary and not a blanket ban.
    assert_eq!(harness.repos.audit.prune_before(t0() - Duration::days(31), t0(), 100).await.expect("prune"), 1);
}

/// An audit log that refuses to prune the way a hardened Postgres without the `EXECUTE` grant
/// does, and records everything else faithfully.
struct RefusingAudit;

#[async_trait]
impl AuditRepo for RefusingAudit {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn append(&self, _event: NewAuditEvent, _now: DateTime<Utc>) -> Result<AuditEvent> {
        unimplemented!("the retention pass never appends")
    }

    async fn list(&self, _filter: &AuditFilter, _cursor: Option<&str>, _limit: u32) -> Result<Page<AuditEvent>> {
        unimplemented!("the retention pass never reads")
    }

    async fn prune_before(&self, _cutoff: DateTime<Utc>, _now: DateTime<Utc>, _batch: u32) -> Result<u64> {
        Err(Error::Database { message: "permission denied for function pub_audit_prune".to_owned() })
    }
}

#[tokio::test]
async fn s22_a_a_refused_audit_prune_still_lets_every_other_table_sweep() {
    // The failure this prevents: a missing grant on one table stopping sessions and notifications
    // from ever being purged. A refusal is an outcome, not an error — reported, logged with the
    // grant, and recorded as a failed run in the durable job state, with the rest of the pass done.
    let harness = Harness::new().await;
    harness.session(&"e".repeat(64), t0() - Duration::days(60)).await;
    harness.notification("old", t0() - Duration::days(200), false).await;

    let worker = harness.worker_with_audit(policy(1_000, StdDuration::from_secs(60)), Arc::new(RefusingAudit));
    let report = worker.run_once(t0()).await.expect("a refusal is not an error");

    assert!(matches!(outcome_for(&report, "audit_log"), TableOutcome::Refused { .. }));
    assert!(report.any_refused());
    assert_eq!(deleted_from(&report, "sessions"), 1, "the refusal must not cost sessions their sweep");
    assert_eq!(deleted_from(&report, "notifications"), 1);

    // And the operator can see it without reading logs: the run is durably a failure.
    let state = worker.status(t0()).await.expect("status");
    assert!(
        state.last_error.as_deref().is_some_and(|error| error.contains("audit_log")),
        "the durable job state must name the refused table, got {:?}",
        state.last_error
    );
}

#[tokio::test]
async fn d12_the_report_names_every_table_including_the_ones_kept_forever() {
    // A table missing from the report reads as one the job forgot, which is exactly the bug a
    // non-zero-only report would hide. `download_stats` is the one window that ships disabled —
    // those rows are the only record of per-version daily downloads and the honest bound on them is
    // a roll-up, not a delete — so it must appear as a deliberate "keep forever".
    let harness = Harness::new().await;
    let report = harness.worker(policy(1_000, StdDuration::from_secs(60))).run_once(t0()).await.expect("pass");

    let named: Vec<&str> = report.tables.iter().map(|line| line.table).collect();
    assert_eq!(
        named,
        vec![
            "job_queue:done",
            "job_queue:suppressed",
            "job_queue:dead",
            // Audit ahead of the tables whose loss is cosmetic: with one shared budget the sweep
            // order decides which table starves on a backlogged instance, and this is the one with
            // a compliance requirement behind it.
            "audit_log",
            "sessions",
            "invitations",
            "notifications",
            "download_stats",
            // The two supply-chain registers (S-23.b): last because they are the smallest, and
            // present because a register missing from the report is one nobody would notice
            // growing — which is what they both did until decision 33.
            "upstream_quarantine",
            "shadowing_alarms",
        ]
    );
    assert_eq!(outcome_for(&report, "download_stats"), &TableOutcome::Disabled);
    assert_eq!(report.deleted_total(), 0, "an empty instance deletes nothing and still reports every table");
}

#[tokio::test]
async fn d12_a_table_the_budget_never_reached_is_not_reported_as_a_backlog() {
    // "Never touched" and "touched and ran out of time" are both `there may be more`, and only one
    // of them means the job tried. A table that is never reached pass after pass has no retention at
    // all; reporting it in the same words as one draining slowly is how that goes unnoticed.
    let harness = Harness::new().await;
    harness.notification("old", t0() - Duration::days(200), false).await;

    // A zero budget means the very first table is already out of time, so every later one is
    // untouched rather than swept-and-truncated.
    let report = harness.worker(policy(1, StdDuration::ZERO)).run_once(t0()).await.expect("pass");

    assert_eq!(outcome_for(&report, "notifications"), &TableOutcome::Skipped);
    assert_eq!(outcome_for(&report, "sessions"), &TableOutcome::Skipped);
    assert!(report.skipped().contains(&"notifications"));
    // Still counted as a backlog for the operator-facing signal — the distinction is which table,
    // not whether to worry.
    assert!(report.unconverged().contains(&"notifications"));
    // A disabled window is still not a skip: it was decided, not missed.
    assert_eq!(outcome_for(&report, "download_stats"), &TableOutcome::Disabled);
    assert_eq!(harness.notification_count().await, 1, "nothing was deleted");
}

#[tokio::test]
async fn d12_download_stats_retention_is_off_by_default_and_works_when_asked_for() {
    // Off by default is a decision, not an omission — so the mechanism still has to be correct for
    // the operator who turns it on. The key here is composite, so the batch is bound by a row-value
    // `IN` rather than by an `id`, which is worth exercising against the real schema.
    let harness = Harness::new().await;
    let mut policy = policy(1_000, StdDuration::from_secs(60));
    policy.retention.download_stats = Some(Duration::days(90));

    let report = harness.worker(policy).run_once(t0()).await.expect("pass");
    match outcome_for(&report, "download_stats") {
        TableOutcome::Swept { deleted, converged, .. } => {
            assert_eq!(*deleted, 0, "nothing recorded, nothing to delete");
            assert!(converged);
        }
        other => panic!("an enabled window must sweep, got {other:?}"),
    }
    // The date arithmetic is the part worth pinning: the cutoff is a calendar date, not an instant.
    assert_eq!(
        RetentionPolicy::cutoff(Some(Duration::days(90)), t0()).map(|cutoff| cutoff.date_naive()),
        Some(NaiveDate::from_ymd_opt(2026, 5, 9).unwrap())
    );
}
