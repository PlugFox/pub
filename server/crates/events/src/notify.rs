//! The notification center: the bus consumer that turns a domain event into per-user feed
//! rows and, for the high-importance categories, an email (decision 20).
//!
//! Fan-out happens **at write time**, not at read time: one row per recipient, decided against
//! the membership as it stands the moment the event happens. The alternative — storing the
//! event once and filtering per reader — would mean a member who joins tomorrow inherits
//! today's private-package activity, and a member who leaves keeps seeing it as long as the row
//! exists. Neither is what a feed should do.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::event::{EventAudience, EventEnvelope};
use pub_core::notification::{NewNotification, NotificationCategory, NotificationPreference};
use pub_core::traits::{Mailer, Repositories};
use pub_core::user::{UserFilter, UserStatus};
use pub_core::{DomainEvent, OrgId, Result, UserId};

use crate::EventConsumer;

/// Tunables for the notification center.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPolicy {
    /// Largest audience one event may reach.
    ///
    /// A bound rather than an unbounded walk: fan-out writes one row per recipient inside the
    /// emitting request, and an org with thousands of members would otherwise turn one publish
    /// into thousands of inserts on the publish path. Past the bound the recipients are the
    /// highest-role ones and the rest are counted in a warning — the REST feed is not the only
    /// way to learn what happened.
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

/// The bus consumer behind `GET /api/v1/notifications`.
pub struct NotificationCenter {
    repos: Repositories,
    mailer: Arc<dyn Mailer>,
    policy: NotificationPolicy,
    instance_name: String,
}

impl std::fmt::Debug for NotificationCenter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationCenter").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl NotificationCenter {
    /// Builds the center over the configured backends.
    pub fn new(
        repos: Repositories,
        mailer: Arc<dyn Mailer>,
        policy: NotificationPolicy,
        instance_name: impl Into<String>,
    ) -> Self {
        Self { repos, mailer, policy, instance_name: instance_name.into() }
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

    /// Files one notification and returns the follow-up stream event.
    async fn file(
        &self,
        user: UserId,
        event: &DomainEvent,
        category: NotificationCategory,
        title: &str,
        payload: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<DomainEvent> {
        let stored = self
            .repos
            .notifications
            .create(
                NewNotification {
                    user_id: user,
                    category,
                    event: event.name().to_owned(),
                    title: title.to_owned(),
                    org_id: event.org_id(),
                    payload: payload.clone(),
                },
                now,
            )
            .await?;
        let unread = self.repos.notifications.unread_count(user).await?;
        Ok(DomainEvent::UserNotified {
            user_id: user,
            notification_id: stored.id,
            category,
            title: title.to_owned(),
            unread,
            at: now,
        })
    }

    /// Best-effort email for a recipient whose preference asks for one.
    ///
    /// Failures are logged, never propagated: the feed row is already committed, and an SMTP
    /// outage must not make the whole fan-out look failed (which would also lose the remaining
    /// recipients' rows).
    async fn email(&self, address: &str, title: &str, event: &DomainEvent) {
        let subject = format!("[{}] {title}", self.instance_name);
        let body = format!(
            "{title}\n\nEvent: {}\n\nYou are receiving this because it is a high-importance \
             notification category. Change what reaches your mailbox under Account → \
             Notifications.\n",
            event.name()
        );
        if let Err(error) = self.mailer.send(address, &subject, &body).await {
            tracing::warn!(%error, event = event.name(), "notification email delivery failed");
        }
    }
}

#[async_trait]
impl EventConsumer for NotificationCenter {
    fn name(&self) -> &'static str {
        "notifications"
    }

    async fn handle(&self, envelope: &EventEnvelope) -> Result<Vec<DomainEvent>> {
        let event = &envelope.event;
        // No category = not a feed item. `UserNotified` is the important member of that set:
        // it is this consumer's own output, and the absence of a category is what keeps the
        // fan-out from feeding itself.
        let Some(category) = event.notification_category() else { return Ok(Vec::new()) };

        let recipients = self.recipients(event, category).await?;
        if recipients.is_empty() {
            return Ok(Vec::new());
        }

        let stored: BTreeMap<UserId, NotificationPreference> =
            self.repos.notifications.stored_preferences(&recipients, category).await?.into_iter().collect();
        let accounts = self.repos.users.get_many(&recipients).await?;
        let emails: BTreeMap<UserId, String> = accounts
            .iter()
            .filter(|user| user.status == UserStatus::Active && user.email_verified)
            .filter_map(|user| user.email.clone().map(|email| (user.id, email)))
            .collect();

        let now = event_time(event);
        let title = event.summary();
        let payload = serde_json::to_value(event).unwrap_or(serde_json::Value::Null);

        let mut followups = Vec::new();
        for user in recipients {
            let preference = stored.get(&user).copied().unwrap_or_else(|| category.default_preference());
            if preference.in_app {
                match self.file(user, event, category, &title, &payload, now).await {
                    Ok(followup) => followups.push(followup),
                    // One recipient's row failing must not cost the others theirs.
                    Err(error) => tracing::error!(%error, %user, event = event.name(), "notification write failed"),
                }
            }
            if preference.email
                && self.policy.email_enabled
                && let Some(address) = emails.get(&user)
            {
                self.email(address, &title, event).await;
            }
        }
        Ok(followups)
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
