//! Notification center types (decision 20): the per-user feed the SSE stream announces and
//! the REST API pages through.
//!
//! A notification is a **projection of a domain event onto one account**, not a second source
//! of truth: it carries what the feed renders (category, title, the event payload) and nothing
//! the recipient could not already read through the REST API. The fan-out decides who gets a
//! row; this module only describes the row.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::EventId;
use crate::{Error, NotificationId, OrgId, UserId};

/// The per-category subscription axis (decision 20 "preferences per category").
///
/// Three categories, not one per event type: a preference list a user has to curate per event
/// name is a preference list nobody curates. The mapping from event to category lives on
/// [`crate::DomainEvent::notification_category`], so a new event joins an existing category
/// rather than silently becoming unsubscribable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationCategory {
    /// Package lifecycle: publishes, retractions, option changes, transfers.
    Package,
    /// Organization lifecycle: membership and role changes, profile and policy changes.
    Org,
    /// Security-relevant events: hard deletes, shadowing alarms, proxy integrity alarms,
    /// instance settings changes.
    Security,
}

impl NotificationCategory {
    /// Every category, in preference-screen order.
    pub const ALL: [Self; 3] = [Self::Package, Self::Org, Self::Security];

    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Org => "org",
            Self::Security => "security",
        }
    }

    /// Whether this category reaches a mailbox unless the user turned it off (decision 20:
    /// "email delivery for high-importance ones").
    ///
    /// `org` and `security` are high-importance; `package` is not. The split is about whether
    /// missing the event costs anything: a membership change alters what somebody may do and a
    /// security alarm needs a human, while a publish is a feed item that a busy repository
    /// would otherwise turn into a mail flood — the fastest way to make people filter the
    /// sender into a folder and miss the other two.
    pub const fn high_importance(self) -> bool {
        matches!(self, Self::Org | Self::Security)
    }

    /// The default preference for a user who has never touched the settings screen.
    pub const fn default_preference(self) -> NotificationPreference {
        NotificationPreference { category: self, in_app: true, email: self.high_importance() }
    }

    /// The org role a member must hold to be a recipient of an org-scoped event in this
    /// category.
    ///
    /// `security` is Admin+ — a shadowing alarm ([S-17](../../../docs/security.md)) or a hard
    /// delete is addressed to the people who can act on it, and paging an entire engineering
    /// org about a supply-chain condition they cannot resolve is how the channel stops being
    /// read. Everything else is Read+, i.e. everybody who can already see the resource.
    pub const fn min_role(self) -> crate::RoleLevel {
        match self {
            Self::Security => crate::RoleLevel::ADMIN,
            Self::Package | Self::Org => crate::RoleLevel::READ,
        }
    }
}

impl fmt::Display for NotificationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NotificationCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "package" => Ok(Self::Package),
            "org" => Ok(Self::Org),
            "security" => Ok(Self::Security),
            other => Err(Error::Invalid {
                message: format!("unknown notification category {other:?}: use package, org, or security"),
            }),
        }
    }
}

/// One row of a user's feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// Notification id — also the keyset cursor (UUID v7, time-ordered).
    pub id: NotificationId,
    /// Recipient.
    pub user_id: UserId,
    /// Subscription axis.
    pub category: NotificationCategory,
    /// The originating event's dot-namespaced name (`package.publish`), so the UI can pick an
    /// icon and a deep link without parsing the payload.
    pub event: String,
    /// Rendered one-line summary.
    pub title: String,
    /// Org the event belonged to, when it had one.
    pub org_id: Option<OrgId>,
    /// The event payload verbatim — the same document the SSE stream carried.
    pub payload: serde_json::Value,
    /// When it was filed.
    pub created_at: DateTime<Utc>,
    /// When the recipient marked it read; `None` = unread.
    pub read_at: Option<DateTime<Utc>>,
}

impl Notification {
    /// Whether the recipient has not read this yet.
    pub const fn is_unread(&self) -> bool {
        self.read_at.is_none()
    }
}

/// A notification about to be filed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewNotification {
    /// Recipient.
    pub user_id: UserId,
    /// Subscription axis.
    pub category: NotificationCategory,
    /// The id of the emission this row projects, when it came from one.
    ///
    /// This is what makes fan-out exactly once (decision 26's amendment): `(user_id,
    /// event_id)` is unique, so a fan-out re-run after a crash — or any future path that
    /// re-emits an event — converges on the same rows instead of filing a second copy of
    /// everybody's feed item. `None` for a row that belongs to no emission, which is why the
    /// constraint is a *partial* unique index rather than a plain one.
    pub event_id: Option<EventId>,
    /// Originating event name.
    pub event: String,
    /// Rendered one-line summary.
    pub title: String,
    /// Org context, when the event had one.
    pub org_id: Option<OrgId>,
    /// Event payload.
    pub payload: serde_json::Value,
}

/// One category's delivery preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreference {
    /// The category this applies to.
    pub category: NotificationCategory,
    /// Whether matching events are filed into the feed at all.
    pub in_app: bool,
    /// Whether matching events are also emailed.
    pub email: bool,
}

/// A user's full preference set — every category, defaults filled in.
///
/// A total function of the stored rows rather than "whatever rows exist": a category added by a
/// later release must behave like its default for accounts that predate it, and a caller
/// reading preferences must never have to know which rows happen to be there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationPreferences(Vec<NotificationPreference>);

impl NotificationPreferences {
    /// Builds the complete set from the rows a repository returned, filling gaps with defaults
    /// and dropping duplicates (last one wins).
    pub fn from_rows(rows: &[NotificationPreference]) -> Self {
        Self(
            NotificationCategory::ALL
                .iter()
                .map(|category| {
                    rows.iter()
                        .rev()
                        .find(|row| row.category == *category)
                        .copied()
                        .unwrap_or_else(|| category.default_preference())
                })
                .collect(),
        )
    }

    /// The preferences, in [`NotificationCategory::ALL`] order.
    pub fn all(&self) -> &[NotificationPreference] {
        &self.0
    }

    /// The preference for one category.
    pub fn for_category(&self, category: NotificationCategory) -> NotificationPreference {
        self.0.iter().find(|pref| pref.category == category).copied().unwrap_or_else(|| category.default_preference())
    }
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self::from_rows(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_round_trip_through_their_wire_names() {
        for category in NotificationCategory::ALL {
            assert_eq!(category.as_str().parse::<NotificationCategory>().unwrap(), category);
        }
        assert_eq!("nonsense".parse::<NotificationCategory>().unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn only_org_and_security_reach_a_mailbox_by_default() {
        // Decision 20's "high-importance ones": a publish firehose in everybody's inbox is how
        // the two categories that matter get filtered away.
        assert!(!NotificationCategory::Package.high_importance());
        assert!(NotificationCategory::Org.high_importance());
        assert!(NotificationCategory::Security.high_importance());
        assert!(NotificationCategory::Package.default_preference().in_app);
        assert!(!NotificationCategory::Package.default_preference().email);
    }

    #[test]
    fn preferences_are_total_even_when_nothing_is_stored() {
        let prefs = NotificationPreferences::default();
        assert_eq!(prefs.all().len(), NotificationCategory::ALL.len());
        assert!(prefs.for_category(NotificationCategory::Security).email);
    }

    #[test]
    fn stored_rows_override_defaults_and_gaps_stay_default() {
        let stored = [NotificationPreference { category: NotificationCategory::Security, in_app: true, email: false }];
        let prefs = NotificationPreferences::from_rows(&stored);
        assert!(!prefs.for_category(NotificationCategory::Security).email, "the stored row must win");
        assert!(prefs.for_category(NotificationCategory::Org).email, "an absent row keeps its default");
    }
}
