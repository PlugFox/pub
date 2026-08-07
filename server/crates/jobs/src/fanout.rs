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

        for mail in &delivery.mail {
            // Deliberately not fatal, and deliberately not a retry of the whole item: the
            // recipients' rows are already written, so re-running this item would file them a
            // second time. Each mail item carries a `(event, recipient)` dedupe key, so the
            // ones that *did* land are not duplicated either.
            if let Err(error) = self.queue.enqueue(mail, now).await {
                tracing::error!(%error, event = fanout.envelope.event.name(), "queueing a notification email failed");
            }
        }

        HandlerReport { outcome: pub_core::queue::QueueOutcome::Done, followups: delivery.followups }
    }
}
