//! The durable work queue's domain types (decision 26).
//!
//! The queue is the second consumer seam off the event bus: the emitting request files one
//! row and returns, and a leader-locked worker does the slow things — the per-recipient
//! notification fan-out and every outbound SMTP conversation — off the request path.
//!
//! Four properties shape the types here:
//!
//! - **A row is a work item, not a cursor.** [`crate::jobs::JobState`] is one row per job
//!   *name* holding where a sweep got to; this is one row per *thing to do*, with its own
//!   attempts, its own backoff and its own dead-letter state. The two are deliberately
//!   different tables and different traits.
//! - **Two granularities.** One row per *event* for [`JobKind::NotificationFanout`], one row
//!   per *message* for [`JobKind::MailSend`]. A per-event fan-out row is what makes the
//!   fan-out deduplicable; per-message mail rows are what give one bad recipient its own
//!   retry and its own dead letter instead of poisoning the other 199.
//! - **State is a ladder with one dead end that is never entered by a worker.**
//!   [`QueueState::Suppressed`] is written at enqueue time and is *never* claimable: it exists
//!   so that an address rejected by policy costs the request exactly the same work as an
//!   accepted one ([S-04.a](../../../docs/security.md), [S-31](../../../docs/security.md))
//!   without ever producing a deliverable message.
//! - **A queued mail body is a live credential.** A rendered OTP body sitting in a table is
//!   the thing [S-26.b](../../../docs/security.md) is about: the payload is sealed under the
//!   boot KEK before the row is written, and every type here that can hold a rendered body
//!   hand-writes `Debug` ([S-25.a](../../../docs/security.md)) — a derived one is how it
//!   would reach a `tracing` field or a panic message.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;
use crate::event::EventEnvelope;

/// Identifier of one queued work item.
///
/// UUID v7 like every other entity id, and here the time ordering is load-bearing rather than
/// incidental: the claim query orders by id, so **arrival order is claim order** and the table
/// needs no separate sequence column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QueuedJobId(Uuid);

impl QueuedJobId {
    /// Generates a fresh time-ordered (UUID v7) identifier.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID (e.g. loaded from storage).
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The underlying UUID.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for QueuedJobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QueuedJobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for QueuedJobId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self).map_err(|err| Error::Invalid { message: format!("invalid QueuedJobId: {err}") })
    }
}

/// What kind of work one row carries — the dispatch key the drain worker matches on.
///
/// The stored column is deliberately **not** CHECK-constrained in either dialect: decision 26
/// promises that [S-33](../../../docs/security.md) webhook delivery lands as one more variant
/// here plus one more handler, and a schema migration is not "nothing else".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum JobKind {
    /// Resolve one event's audience and file every recipient's notification row.
    #[serde(rename = "notification.fanout")]
    NotificationFanout,
    /// Deliver one message to one recipient.
    #[serde(rename = "mail.send")]
    MailSend,
}

impl JobKind {
    /// Every kind, in dispatch-table order.
    pub const ALL: [Self; 2] = [Self::NotificationFanout, Self::MailSend];

    /// Stable stored/wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotificationFanout => "notification.fanout",
            Self::MailSend => "mail.send",
        }
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "notification.fanout" => Ok(Self::NotificationFanout),
            "mail.send" => Ok(Self::MailSend),
            other => Err(Error::Invalid { message: format!("unknown job kind {other:?}") }),
        }
    }
}

/// Where one work item is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueState {
    /// Waiting to be claimed, at or after its `run_after`.
    Pending,
    /// Leased by a worker until its `locked_until`.
    Running,
    /// Finished; kept only until retention purges it.
    Done,
    /// Out of attempts. Kept for the operator — a dead-lettered sign-in mail is an account
    /// lockout with no other visible cause, so it must be readable on the admin job surface.
    Dead,
    /// Written by the request path so that a rejected address costs exactly what an accepted
    /// one costs, and **never claimable** (S-04.a, S-31). Nothing moves a row out of this
    /// state: a suppressed message has no deliverable payload and never acquires one.
    Suppressed,
}

impl QueueState {
    /// Every state, in ladder order.
    pub const ALL: [Self; 5] = [Self::Pending, Self::Running, Self::Done, Self::Dead, Self::Suppressed];

    /// Stable stored/wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Done => "done",
            Self::Dead => "dead",
            Self::Suppressed => "suppressed",
        }
    }

    /// Whether a row in this state can ever be handed to a worker.
    pub const fn is_claimable(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Whether a row may be *created* in this state.
    ///
    /// Only the two the request path decides between: an item to run, and an item that exists
    /// solely to make the two branches of a rejection cost the same. Everything else is a
    /// state a worker moves a row *into*, and enqueueing directly into it would file work that
    /// is already finished — or, for `running`, work nobody holds a lease on.
    pub const fn is_admissible(self) -> bool {
        matches!(self, Self::Pending | Self::Suppressed)
    }
}

impl fmt::Display for QueueState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QueueState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "done" => Ok(Self::Done),
            "dead" => Ok(Self::Dead),
            "suppressed" => Ok(Self::Suppressed),
            other => Err(Error::Invalid { message: format!("unknown queue state {other:?}") }),
        }
    }
}

/// One stored work item.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedJob {
    /// Item id — also the claim order (UUID v7, time-ordered).
    pub id: QueuedJobId,
    /// Which handler runs this.
    pub kind: JobKind,
    /// The handler's own document ([`MailJob`], [`FanoutJob`]), opaque to the repository.
    pub payload: serde_json::Value,
    /// Where the item is in its life.
    pub state: QueueState,
    /// How many times this item has been claimed. Incremented **when the lease is taken**,
    /// not when the work reports back, so a worker that dies mid-run still burns an attempt —
    /// otherwise an item that kills its handler retries forever.
    pub attempts: i64,
    /// Not runnable before this instant (backoff, or a deliberately delayed enqueue).
    pub run_after: DateTime<Utc>,
    /// When the current lease expires; `None` unless the item is `running`.
    pub locked_until: Option<DateTime<Utc>>,
    /// Idempotency key, unique across the whole table when present.
    pub dedupe_key: Option<String>,
    /// The last failure's message, kept for the admin surface.
    pub last_error: Option<String>,
    /// When the item was filed (UTC).
    pub created_at: DateTime<Utc>,
    /// Last write (UTC) — the instant retention measures a `done` row's age from.
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for QueuedJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The payload of a `mail.send` row is a rendered message body; sealed at rest, but
        // plaintext in this struct the moment a handler decodes and re-wraps one (S-25.a).
        f.debug_struct("QueuedJob")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("payload", &"<redacted>")
            .field("state", &self.state)
            .field("attempts", &self.attempts)
            .field("run_after", &self.run_after)
            .field("locked_until", &self.locked_until)
            .field("dedupe_key", &self.dedupe_key)
            .field("last_error", &self.last_error)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A work item about to be filed.
#[derive(Clone, PartialEq, Eq)]
pub struct NewQueuedJob {
    /// Which handler will run this.
    pub kind: JobKind,
    /// The handler's own document.
    pub payload: serde_json::Value,
    /// [`QueueState::Pending`] or [`QueueState::Suppressed`] — see
    /// [`QueueState::is_admissible`].
    pub state: QueueState,
    /// Earliest run instant; `None` means "as soon as a worker picks it up".
    pub run_after: Option<DateTime<Utc>>,
    /// Idempotency key. Present ⇒ a second enqueue under the same key is a no-op rather than a
    /// duplicate. The key space is shared by every kind, so each kind prefixes its own (see
    /// [`FanoutJob::dedupe_key`]).
    pub dedupe_key: Option<String>,
}

impl NewQueuedJob {
    /// An item to run as soon as a worker gets to it.
    pub fn pending(kind: JobKind, payload: serde_json::Value) -> Self {
        Self { kind, payload, state: QueueState::Pending, run_after: None, dedupe_key: None }
    }

    /// An item that is filed but must never be delivered (S-04.a, S-31).
    pub fn suppressed(kind: JobKind, payload: serde_json::Value) -> Self {
        Self { kind, payload, state: QueueState::Suppressed, run_after: None, dedupe_key: None }
    }

    /// Sets the idempotency key.
    pub fn with_dedupe_key(mut self, key: impl Into<String>) -> Self {
        self.dedupe_key = Some(key.into());
        self
    }

    /// Delays the item until `at`.
    pub fn with_run_after(mut self, at: DateTime<Utc>) -> Self {
        self.run_after = Some(at);
        self
    }
}

impl fmt::Debug for NewQueuedJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same reason as [`QueuedJob`]: this is the struct that holds a freshly rendered OTP
        // body on its way to the table.
        f.debug_struct("NewQueuedJob")
            .field("kind", &self.kind)
            .field("payload", &"<redacted>")
            .field("state", &self.state)
            .field("run_after", &self.run_after)
            .field("dedupe_key", &self.dedupe_key)
            .finish()
    }
}

/// How one claimed item ended (see [`crate::traits::JobQueueRepo::complete`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueOutcome {
    /// The handler succeeded; the row becomes [`QueueState::Done`] and retention owns it.
    Done,
    /// A transient failure: the row goes back to [`QueueState::Pending`] behind its backoff.
    Retry(String),
    /// A permanent failure — a malformed recipient, an exhausted attempt budget. The row goes
    /// to [`QueueState::Dead`] and stays there for the operator.
    Dead(String),
}

impl QueueOutcome {
    /// Stable label for metrics and the admin surface.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Retry(_) => "retry",
            Self::Dead(_) => "dead",
        }
    }

    /// The message an unsuccessful outcome carries.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Done => None,
            Self::Retry(message) | Self::Dead(message) => Some(message),
        }
    }
}

/// The payload of a [`JobKind::MailSend`] row: one message, one recipient.
///
/// Deliberately **not** one row per multi-recipient message: per-recipient rows are what give a
/// single bad address its own retry and its own dead letter, which one `To:` list with two
/// hundred entries cannot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailJob {
    /// Recipient address.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body — or, when [`MailJob::sealed`], base64 of its sealed form.
    pub text: String,
    /// HTML alternative, same sealing rule; `None` sends a plain-text-only message.
    pub html: Option<String>,
    /// Whether [`MailJob::text`] and [`MailJob::html`] are sealed under the boot KEK
    /// (S-26.b) rather than plaintext.
    ///
    /// A flag rather than a convention because the worker must not have to *guess* whether the
    /// bytes it claimed are a body or a ciphertext: with the ephemeral development KEK a restart
    /// makes yesterday's rows un-unsealable, and "this was sealed and the key is gone" has to
    /// become a reportable dead letter rather than a message whose body is base64. The recipient
    /// and the subject stay in the clear on purpose — a dead-lettered message has to be
    /// identifiable on the admin surface, and neither of them is redeemable.
    pub sealed: bool,
}

impl MailJob {
    /// The kind a [`MailJob`] payload rides in.
    pub const KIND: JobKind = JobKind::MailSend;
}

impl fmt::Debug for MailJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The body of a sign-in message *is* the credential (S-25.a). `sealed` is reported
        // because "was this one sealed" is exactly the question a log line is asked.
        f.debug_struct("MailJob")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("text", &"<redacted>")
            .field("html", &self.html.as_ref().map(|_| "<redacted>"))
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// The payload of a [`JobKind::NotificationFanout`] row: the whole event envelope.
///
/// One row per event, never per recipient: the emitting request must do constant work
/// regardless of how large the audience is, and resolving that audience is the worker's job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanoutJob {
    /// The event to fan out, exactly as the bus carried it.
    pub envelope: EventEnvelope,
}

impl FanoutJob {
    /// The kind a [`FanoutJob`] payload rides in.
    pub const KIND: JobKind = JobKind::NotificationFanout;

    /// The idempotency key for this event's fan-out.
    ///
    /// The event id is minted once per emission, so a retried enqueue after a partial failure
    /// is a no-op instead of a second copy of everybody's notification. Prefixed because the
    /// dedupe key space is shared by every kind.
    pub fn dedupe_key(&self) -> String {
        format!("fanout:{}", self.envelope.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_states_round_trip_through_their_stored_names() {
        for kind in JobKind::ALL {
            assert_eq!(kind.as_str().parse::<JobKind>().unwrap(), kind);
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(kind.as_str()));
        }
        for state in QueueState::ALL {
            assert_eq!(state.as_str().parse::<QueueState>().unwrap(), state);
            assert_eq!(serde_json::to_value(state).unwrap(), serde_json::json!(state.as_str()));
        }
        assert_eq!("webhook.deliver".parse::<JobKind>().unwrap_err().code(), "invalid_argument");
        assert_eq!("queued".parse::<QueueState>().unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn only_pending_is_claimable_and_only_pending_or_suppressed_may_be_enqueued() {
        // S-31: a suppressed row is filed so the two branches cost the same, and there is no
        // state transition that could ever turn it into a deliverable message.
        assert!(QueueState::Pending.is_claimable());
        for state in [QueueState::Running, QueueState::Done, QueueState::Dead, QueueState::Suppressed] {
            assert!(!state.is_claimable(), "{state} must never be handed to a worker");
        }
        assert!(QueueState::Pending.is_admissible());
        assert!(QueueState::Suppressed.is_admissible());
        for state in [QueueState::Running, QueueState::Done, QueueState::Dead] {
            assert!(!state.is_admissible(), "{state} is a state a worker moves a row into");
        }
    }

    #[test]
    fn s25_a_rendered_body_never_reaches_a_debug_line() {
        let job = MailJob {
            to: "alice@corp.com".to_owned(),
            subject: "Your sign-in code".to_owned(),
            text: "Your code is 12345678".to_owned(),
            html: Some("<p>12345678</p>".to_owned()),
            sealed: false,
        };
        let rendered = format!("{job:?}");
        assert!(!rendered.contains("12345678"), "{rendered}");
        assert!(rendered.contains("alice@corp.com"), "the recipient stays readable: {rendered}");
        assert!(rendered.contains("sealed: false"), "{rendered}");

        let queued = NewQueuedJob::pending(MailJob::KIND, serde_json::to_value(&job).unwrap());
        assert!(!format!("{queued:?}").contains("12345678"), "the enqueue struct leaks the body");
        let stored = QueuedJob {
            id: QueuedJobId::new(),
            kind: queued.kind,
            payload: queued.payload.clone(),
            state: QueueState::Pending,
            attempts: 0,
            run_after: Utc::now(),
            locked_until: None,
            dedupe_key: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(!format!("{stored:?}").contains("12345678"), "the stored row leaks the body");
    }

    #[test]
    fn a_fanout_dedupe_key_is_the_event_id_in_its_own_namespace() {
        let envelope = EventEnvelope::new(crate::DomainEvent::UserNotified {
            user_id: crate::UserId::new(),
            notification_id: crate::NotificationId::new(),
            category: crate::notification::NotificationCategory::Org,
            title: "hi".to_owned(),
            unread: 1,
            at: Utc::now(),
        });
        let job = FanoutJob { envelope: envelope.clone() };
        assert_eq!(job.dedupe_key(), format!("fanout:{}", envelope.id));
        // Two emissions of the same event are two work items; one emission enqueued twice is one.
        let second = FanoutJob { envelope: EventEnvelope::new(envelope.event.clone()) };
        assert_ne!(job.dedupe_key(), second.dedupe_key());
    }

    #[test]
    fn ids_are_uuid_v7_and_round_trip() {
        let id = QueuedJobId::new();
        assert_eq!(id.as_uuid().get_version_num(), 7);
        assert_eq!(id.to_string().parse::<QueuedJobId>().unwrap(), id);
        assert_eq!("not-a-uuid".parse::<QueuedJobId>().unwrap_err().code(), "invalid_argument");
        // Claim order is id order, so minting has to be monotonic within a millisecond.
        assert!(id < QueuedJobId::new());
    }

    #[test]
    fn an_outcome_reports_its_label_and_its_message() {
        assert_eq!(QueueOutcome::Done.as_str(), "done");
        assert_eq!(QueueOutcome::Done.message(), None);
        assert_eq!(QueueOutcome::Retry("smtp timeout".to_owned()).as_str(), "retry");
        assert_eq!(QueueOutcome::Dead("bad address".to_owned()).message(), Some("bad address"));
    }
}
