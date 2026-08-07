//! The notification center: what turns a domain event into per-user feed rows and, for the
//! high-importance categories, an email (decision 20).
//!
//! Fan-out happens **at write time**, not at read time: one row per recipient, decided against
//! the membership as it stands the moment the event happens. The alternative — storing the
//! event once and filtering per reader — would mean a member who joins tomorrow inherits
//! today's private-package activity, and a member who leaves keeps seeing it as long as the row
//! exists. Neither is what a feed should do.
//!
//! Write time is not the *emitting request* though (decision 26). The file splits in two:
//!
//! - [`NotificationEnqueuer`] is the bus consumer. It files **one** durable job carrying the
//!   envelope and returns; the emitting request's cost is therefore constant in the audience
//!   size, which is what a publish finalize with two hundred members needed.
//! - [`NotificationCenter`] keeps the audience policy and the batched writes, and is driven by
//!   the queue worker. Its per-recipient loop is gone: one `create_many`, one `unread_counts`
//!   and a mail item per recipient, so an event costs a fixed five queries instead of `2N + 3`
//!   and zero SMTP conversations inside anybody's request.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::event::{EventAudience, EventEnvelope};
use pub_core::notification::{NewNotification, NotificationCategory, NotificationPreference};
use pub_core::queue::{FanoutJob, MailJob, NewQueuedJob};
use pub_core::settings::SettingsCache;
use pub_core::traits::{JobQueueRepo, Repositories};
use pub_core::user::{UserFilter, UserStatus};
use pub_core::{DomainEvent, Error, OrgId, Result, UserId};

use crate::EventConsumer;

/// Tunables for the notification center.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPolicy {
    /// Largest audience one event may reach.
    ///
    /// Off the request path this is no longer a latency guard — it is a pure abuse bound, and
    /// its cost is now a *correctness* one: members past the bound never learn about the event
    /// (decision 20's 2026-08-07 amendment records this and defers the number to D42). Past the
    /// bound the recipients are the highest-role ones and the rest are counted in a warning.
    pub max_recipients: usize,
    /// Whether high-importance categories are emailed at all (an operator kill switch for
    /// instances with no working SMTP).
    pub email_enabled: bool,
}

impl Default for NotificationPolicy {
    fn default() -> Self {
        Self { max_recipients: 200, email_enabled: true }
    }
}

/// One event's whole fan-out, computed by the worker.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fanout {
    /// One [`DomainEvent::UserNotified`] per filed row, in recipient order.
    ///
    /// Published by the worker **after** the fan-out's own queue row is completed, never
    /// before: `pub_core::event` promises a client acting on one of these finds the row it
    /// names.
    pub followups: Vec<DomainEvent>,
    /// The per-recipient mail items to file — one row per message, so a single bad address
    /// gets its own retry and its own dead letter.
    pub mail: Vec<NewQueuedJob>,
    /// How many recipients the audience resolved to (before per-category preferences).
    pub recipients: usize,
}

/// The bus consumer: one enqueue per event, and nothing else.
///
/// It exists as its own type rather than as a method on [`NotificationCenter`] because the two
/// run in different places — this one on the instance that emitted the event, inside the
/// emitting request; the center on whichever instance holds the drain's leader lock.
pub struct NotificationEnqueuer {
    queue: Arc<dyn JobQueueRepo>,
}

impl std::fmt::Debug for NotificationEnqueuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationEnqueuer").finish_non_exhaustive()
    }
}

impl NotificationEnqueuer {
    /// Builds the consumer over the durable queue.
    pub fn new(queue: Arc<dyn JobQueueRepo>) -> Self {
        Self { queue }
    }
}

#[async_trait]
impl EventConsumer for NotificationEnqueuer {
    fn name(&self) -> &'static str {
        "notification-enqueue"
    }

    async fn handle(&self, envelope: &EventEnvelope) -> Result<Vec<DomainEvent>> {
        // No category = not a feed item. `UserNotified` is the important member of that set:
        // it is the fan-out's own output, and the absence of a category is what keeps the
        // fan-out from feeding itself even if a follow-up ever reached a consumer.
        if envelope.event.notification_category().is_none() {
            return Ok(Vec::new());
        }

        let job = FanoutJob { envelope: envelope.clone() };
        let payload = serde_json::to_value(&job)
            .map_err(|err| Error::Internal { message: format!("failed to encode a fan-out payload: {err}") })?;
        let queued = NewQueuedJob::pending(FanoutJob::KIND, payload).with_dedupe_key(job.dedupe_key());
        // The event's own timestamp, not the wall clock: an event is stamped where it happens,
        // and the queue row it produces belongs to that same moment.
        match self.queue.enqueue(&queued, event_time(&envelope.event)).await {
            Ok(_) => Ok(Vec::new()),
            Err(error) => {
                // Decision 22's amendment: the bus still swallows this — a publish whose bytes,
                // rows and audit record are committed must not fail because a notification could
                // not be written — but one swallowed enqueue now costs an entire event's
                // fan-out *and* every email it would have produced, including a sign-in code.
                // The counter is part of that bargain, not optional instrumentation.
                metrics::counter!("notification_enqueue_failed_total", "event" => envelope.event.name()).increment(1);
                Err(error)
            }
        }
    }
}

/// The audience policy and the batched writes behind `GET /api/v1/notifications`.
pub struct NotificationCenter {
    repos: Repositories,
    policy: NotificationPolicy,
    /// Runtime settings (decision 09), read at send time so a rename brands the very next
    /// message rather than the next restart's (decision 17 amendment, D31).
    runtime: Arc<SettingsCache>,
}

impl std::fmt::Debug for NotificationCenter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationCenter").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl NotificationCenter {
    /// Builds the center over the configured backends.
    pub fn new(repos: Repositories, policy: NotificationPolicy, runtime: Arc<SettingsCache>) -> Self {
        Self { repos, policy, runtime }
    }

    /// Resolves one event's audience, files every recipient's row in one batch, and reports the
    /// follow-ups and the mail items the worker still has to queue.
    ///
    /// Called only by the drain worker. Nothing here writes to the queue or publishes anything:
    /// the caller owns both, because both have to happen in a fixed order relative to the
    /// fan-out item's own completion.
    pub async fn deliver(&self, envelope: &EventEnvelope) -> Result<Fanout> {
        let event = &envelope.event;
        let Some(category) = event.notification_category() else { return Ok(Fanout::default()) };

        let recipients = self.recipients(event, category).await?;
        if recipients.is_empty() {
            return Ok(Fanout::default());
        }

        let stored: BTreeMap<UserId, NotificationPreference> =
            self.repos.notifications.stored_preferences(&recipients, category).await?.into_iter().collect();
        let accounts = self.repos.users.get_many(&recipients).await?;
        let emails: BTreeMap<UserId, String> = accounts
            .iter()
            .filter(|user| user.status == UserStatus::Active && user.email_verified)
            .filter_map(|user| user.email.clone().map(|email| (user.id, email)))
            .collect();

        // The event's own time, not the drain's: a delayed drain must not reorder a feed or
        // stamp a publish with the moment somebody got round to it.
        let now = event_time(event);
        let title = event.summary();
        let payload = serde_json::to_value(event).unwrap_or(serde_json::Value::Null);
        let preference = |user: &UserId| stored.get(user).copied().unwrap_or_else(|| category.default_preference());

        // One batched insert in recipient order — `create_many` mints ids in that order, so
        // each recipient's feed reads back correctly without a second sort.
        let filed: Vec<UserId> = recipients.iter().copied().filter(|user| preference(user).in_app).collect();
        let rows: Vec<NewNotification> = filed
            .iter()
            .map(|user| NewNotification {
                user_id: *user,
                category,
                event: event.name().to_owned(),
                title: title.clone(),
                org_id: event.org_id(),
                payload: payload.clone(),
            })
            .collect();
        let stored_rows = self.repos.notifications.create_many(&rows, now).await?;
        let unread: BTreeMap<UserId, i64> = self.repos.notifications.unread_counts(&filed).await?.into_iter().collect();
        let followups = stored_rows
            .iter()
            .map(|row| DomainEvent::UserNotified {
                user_id: row.user_id,
                notification_id: row.id,
                category,
                title: title.clone(),
                // A user with nothing unread is absent from a `GROUP BY`, so a missing entry
                // is zero rather than a bug.
                unread: unread.get(&row.user_id).copied().unwrap_or(0),
                at: now,
            })
            .collect();

        let mail = if self.policy.email_enabled {
            let subject = format!("[{}] {title}", self.runtime.current().branding.name);
            let body = format!(
                "{title}\n\nEvent: {}\n\nYou are receiving this because it is a high-importance \
                 notification category. Change what reaches your mailbox under Account → \
                 Notifications.\n",
                event.name()
            );
            recipients
                .iter()
                .filter(|user| preference(user).email)
                .filter_map(|user| emails.get(user).map(|address| (*user, address)))
                .map(|(user, address)| {
                    let job = MailJob {
                        to: address.clone(),
                        subject: subject.clone(),
                        // Not sealed: this body carries a one-line summary and an event name,
                        // never a credential — and the center has no KEK by construction
                        // (pub-events depends on pub-core alone). The senders that *do* render
                        // credentials — the sign-in code, an invitation token — seal their own.
                        text: body.clone(),
                        html: None,
                        sealed: false,
                    };
                    let payload = serde_json::to_value(&job).unwrap_or(serde_json::Value::Null);
                    // `(event, recipient)` rather than a fresh id: if this fan-out is re-run
                    // after a crash, the recipients who were already mailed are not mailed twice.
                    NewQueuedJob::pending(MailJob::KIND, payload)
                        .with_dedupe_key(format!("mail:{}:{}", envelope.id, user))
                })
                .collect()
        } else {
            Vec::new()
        };

        Ok(Fanout { followups, mail, recipients: recipients.len() })
    }

    /// Who should hear about this event, highest authority first.
    ///
    /// The audience is [`DomainEvent::audience`] — the event's own answer — narrowed by the
    /// category's minimum role. Nothing here re-derives visibility from package flags: an
    /// org-scoped event goes to that org's members at the required level and to nobody else,
    /// which is the same predicate `authorize(actor, ReadPackages, org)` applies on the read
    /// paths (S-32).
    async fn recipients(&self, event: &DomainEvent, category: NotificationCategory) -> Result<Vec<UserId>> {
        let mut users = match event.audience() {
            EventAudience::User(user) => vec![user],
            EventAudience::Org(org) => self.org_recipients(org, category).await?,
            EventAudience::Instance => self.instance_admins().await?,
        };
        // A transfer has two audiences: the org losing the package needs to know as much as the
        // one gaining it, and `audience()` can only name one.
        if let DomainEvent::PackageTransferred { from_org_id, .. } = event {
            users.extend(self.org_recipients(*from_org_id, category).await?);
        }
        let mut seen = HashSet::new();
        users.retain(|user| seen.insert(*user));
        if users.len() > self.policy.max_recipients {
            tracing::warn!(
                event = event.name(),
                recipients = users.len(),
                cap = self.policy.max_recipients,
                "notification fan-out capped"
            );
            users.truncate(self.policy.max_recipients);
        }
        Ok(users)
    }

    /// The org's members at or above the category's minimum role, highest role first.
    async fn org_recipients(&self, org: OrgId, category: NotificationCategory) -> Result<Vec<UserId>> {
        let required = category.min_role();
        Ok(self
            .repos
            .orgs
            .list_members(org)
            .await?
            .into_iter()
            .filter(|member| member.role.satisfies(required))
            .map(|member| member.user_id)
            .collect())
    }

    /// Every active instance administrator — the audience of an org-less event.
    async fn instance_admins(&self) -> Result<Vec<UserId>> {
        let filter = UserFilter { query: None, status: Some(UserStatus::Active), admins_only: true };
        let page = self.repos.users.list(&filter, None, self.policy.max_recipients as u32).await?;
        Ok(page.items.into_iter().map(|user| user.id).collect())
    }
}

/// The event's own timestamp — notifications are stamped with when the thing happened, not
/// with when the consumer got round to it.
fn event_time(event: &DomainEvent) -> DateTime<Utc> {
    serde_json::to_value(event)
        .ok()
        .and_then(|value| value.get("at").and_then(|at| at.as_str().map(ToOwned::to_owned)))
        .and_then(|at| DateTime::parse_from_rfc3339(&at).ok())
        .map(|at| at.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use pub_core::Format;

    use super::*;

    #[test]
    fn the_event_timestamp_is_the_notification_timestamp() {
        let at = Utc.with_ymd_and_hms(2026, 8, 7, 9, 0, 0).unwrap();
        let event = DomainEvent::PackageShadowed {
            format: Format::Pub,
            org_id: OrgId::new(),
            name: "acme_core".to_owned(),
            upstream: "https://pub.dev".to_owned(),
            upstream_version: None,
            at,
        };
        assert_eq!(event_time(&event), at);
    }

    #[test]
    fn security_notifications_stop_at_admins_and_the_rest_reach_readers() {
        // The min-role split is the whole audience policy for org-scoped events; asserting it
        // here keeps it from drifting into a per-variant special case downstream.
        assert_eq!(NotificationCategory::Security.min_role(), pub_core::RoleLevel::ADMIN);
        assert_eq!(NotificationCategory::Package.min_role(), pub_core::RoleLevel::READ);
        assert_eq!(NotificationCategory::Org.min_role(), pub_core::RoleLevel::READ);
    }
}
