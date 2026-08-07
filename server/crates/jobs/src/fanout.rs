//! Notification fan-out off the request path ([decision 26](../../../docs/decisions.md#26)).
//!
//! One row per **event**, never per recipient: the emitting request must do constant work
//! regardless of how large the audience is, and resolving that audience is this handler's job.
//! What it drives is [`pub_events::NotificationCenter`] — the same audience policy the request
//! path used to run inline, moved rather than forked, so there is still exactly one answer to
//! "who hears about this".
//!
//! Ordering is the whole contract here. The recipients' rows are written, the per-recipient mail
//! items are filed, and only then does the worker complete this item and publish the
//! `UserNotified` follow-ups — because the event contract promises a client acting on one finds
//! the notification it names.
//!
//! Re-running this handler is safe by construction rather than by luck (decision 26's
//! 2026-08-07 amendment): `notifications` is unique on `(user_id, event_id)` and every mail item
//! carries a `mail:{event}:{recipient}` dedupe key, so a second run files no second row and
//! sends no second message. That is what lets a partially failed fan-out ask to be run again
//! instead of swallowing the recipients it could not queue.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::queue::{FanoutJob, JobKind, QueuedJob};
use pub_core::traits::JobQueueRepo;
use pub_events::NotificationCenter;

use crate::queue::{HandlerReport, JobHandler};

/// Fans one event out to its audience.
pub struct FanoutHandler {
    center: Arc<NotificationCenter>,
    queue: Arc<dyn JobQueueRepo>,
}

impl std::fmt::Debug for FanoutHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanoutHandler").finish_non_exhaustive()
    }
}

impl FanoutHandler {
    /// Builds the handler over the notification center and the queue it files mail into.
    pub fn new(center: Arc<NotificationCenter>, queue: Arc<dyn JobQueueRepo>) -> Self {
        Self { center, queue }
    }
}

#[async_trait]
impl JobHandler for FanoutHandler {
    fn kind(&self) -> JobKind {
        JobKind::NotificationFanout
    }

    async fn run(&self, job: &QueuedJob, now: DateTime<Utc>) -> HandlerReport {
        let fanout: FanoutJob = match serde_json::from_value(job.payload.clone()) {
            Ok(fanout) => fanout,
            Err(err) => return HandlerReport::dead(format!("undecodable fan-out payload: {err}")),
        };

        let delivery = match self.center.deliver(&fanout.envelope).await {
            Ok(delivery) => delivery,
            // Audience resolution and the batched insert are database work: a failure here is
            // the kind a retry fixes.
            Err(err) => return HandlerReport::retry(format!("fan-out failed: {err}")),
        };

        let mut lost = 0u64;
        for mail in &delivery.mail {
            if let Err(error) = self.queue.enqueue(mail, now).await {
                // Counted, not just logged (decision 22's amendment makes observability of a
                // swallowed enqueue contractual): the analogous failure at the bus boundary
                // increments `notification_enqueue_failed_total`, and one recipient's mail
                // going missing with no metric and no dead letter is the same invisible
                // failure one layer down.
                metrics::counter!("notification_mail_enqueue_failed_total", "event" => fanout.envelope.event.name())
                    .increment(1);
                tracing::error!(%error, event = fanout.envelope.event.name(), "queueing a notification email failed");
                lost += 1;
            }
        }

        let outcome = if lost > 0 {
            // Re-running the fan-out is now the *cheap* answer, which it was not when this
            // handler was written: `(user_id, event_id)` is unique so the recipients' rows are
            // filed once however many times this runs, and each mail item's
            // `mail:{event}:{recipient}` key makes the enqueues that already landed no-ops. So
            // the retry costs one audience resolution and recovers the messages that were lost,
            // and a failure that outlives the attempt budget becomes a visible dead letter
            // instead of a mailbox that stays empty.
            pub_core::queue::QueueOutcome::Retry(format!("{lost} notification emails could not be queued"))
        } else {
            pub_core::queue::QueueOutcome::Done
        };
        // The follow-ups ride along whatever the outcome is: the recipients' rows *are* written,
        // and this is the only run that will ever carry them — the retry's `create_many` finds
        // them already there and reports nothing to announce.
        HandlerReport { outcome, followups: delivery.followups }
    }
}
