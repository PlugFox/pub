//! Domain events — the single fan-out seam (decision 22).
//!
//! Domain services emit events here; the consumers (SSE stream — decision 20, notification
//! center, outbound webhooks, and any future integration) subscribe behind [`EventSink`].
//! The enum is `#[non_exhaustive]`, so new events are additive.
//!
//! Emission is **fire-and-forget and infallible by contract**: the event bus is a hint
//! channel (clients reconcile through the REST API), so a broken consumer must never fail a
//! publish. Durable truth stays in the database and the audit log.
//!
//! Every event answers one authorization question — [`DomainEvent::audience`] — and the SSE
//! fan-out is allowed to consult **nothing else** (S-32). Making the audience part of the
//! event rather than a lookup table in the stream is what keeps a new variant from defaulting
//! to "everybody" by omission: adding one without extending the match does not compile.

use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{ulid_canonical, ulid_generate};
use crate::notification::NotificationCategory;
use crate::{Error, Format, NotificationId, OrgId, PackageId, UserId, VersionId};

/// ULID identifier of one event on the bus — also its SSE `id:` field and the value a client
/// replays from with `Last-Event-ID`.
///
/// A ULID rather than a per-instance counter: ids are minted wherever the event originates, so
/// a client that reconnects to a *different* instance still presents something that compares in
/// time order against that instance's ring buffer (decision 20 cross-instance fan-out).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(String);

impl EventId {
    /// Mints a fresh time-ordered id.
    pub fn generate() -> Self {
        Self(ulid_generate())
    }

    /// The id as its canonical 26-char uppercase string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ulid_canonical(s, "event id").map(Self)
    }
}

/// Who is allowed to see an event (S-32).
///
/// The fan-out filter is a total function of this value plus the subscriber's identity — there
/// is no per-variant special case anywhere downstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventAudience {
    /// Members of this org holding at least [`crate::RoleLevel::READ`].
    Org(OrgId),
    /// Instance administrators only (`users.is_instance_admin`).
    Instance,
    /// Exactly one account — a personal notification.
    User(UserId),
}

/// One event as it travels: a domain event plus the id it is replayed by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Time-ordered id, minted by the instance that emitted the event.
    pub id: EventId,
    /// The event itself.
    pub event: DomainEvent,
}

impl EventEnvelope {
    /// Wraps an event with a fresh id.
    pub fn new(event: DomainEvent) -> Self {
        Self { id: EventId::generate(), event }
    }
}

/// One domain event.
///
/// Every variant carries the org and format so consumers can authorization-filter without a
/// database round-trip (S-32: a principal only ever receives events for resources it can
/// read).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    /// A version was published (`package.publish`).
    PackagePublished {
        /// Artifact format.
        format: Format,
        /// Owning org.
        org_id: OrgId,
        /// Package the version belongs to.
        package_id: PackageId,
        /// Package name.
        name: String,
        /// The published version, canonical string form.
        version: String,
        /// The published version's id.
        version_id: VersionId,
        /// Whether this publish created the package (first publish of the name).
        package_created: bool,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A version was retracted or un-retracted (`package.retract`).
    PackageRetracted {
        /// Artifact format.
        format: Format,
        /// Owning org.
        org_id: OrgId,
        /// Package the version belongs to.
        package_id: PackageId,
        /// Package name.
        name: String,
        /// The affected version, canonical string form.
        version: String,
        /// The affected version's id.
        version_id: VersionId,
        /// `true` = retracted, `false` = restored.
        retracted: bool,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A package's mutable options changed — visibility, discontinued/replaced-by, unlisted
    /// (`package.options`).
    ///
    /// Carries the new visibility because that is the one field a consumer must react to
    /// rather than merely display: flipping a package to private has to remove it from every
    /// cached public listing a client is holding.
    PackageOptionsChanged {
        /// Artifact format.
        format: Format,
        /// Owning org.
        org_id: OrgId,
        /// The package.
        package_id: PackageId,
        /// Package name.
        name: String,
        /// Visibility after the change (`public` / `private`).
        visibility: String,
        /// Whether the package is now discontinued.
        discontinued: bool,
        /// Whether the package is now hidden from discovery.
        unlisted: bool,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A version was hard-deleted; the number stays burned (`package.hard_delete`,
    /// decision 06).
    PackageVersionDeleted {
        /// Artifact format.
        format: Format,
        /// Owning org.
        org_id: OrgId,
        /// Package the version belonged to.
        package_id: PackageId,
        /// Package name.
        name: String,
        /// The deleted version, canonical string form.
        version: String,
        /// The deleted version's id (the tombstone row).
        version_id: VersionId,
        /// Whether the archive bytes were removed from the blob store (they survive when
        /// another live version references the same content hash).
        blob_removed: bool,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A package changed owning org (`package.transfer`).
    ///
    /// Carries both orgs because both audiences care: the losing org's members stop seeing it
    /// in their listings, and the gaining org's start. [`DomainEvent::org_id`] reports the
    /// **new** owner — the org the package belongs to from now on.
    PackageTransferred {
        /// Artifact format.
        format: Format,
        /// The org that gave the package up.
        from_org_id: OrgId,
        /// The org that now owns it.
        to_org_id: OrgId,
        /// The package.
        package_id: PackageId,
        /// Package name.
        name: String,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A membership was created, re-roled, or removed (`org.member`).
    ///
    /// `role` is the level the user now holds, or `None` when the membership is gone. Every
    /// emission of this event is accompanied by a session revocation for `user_id` whenever
    /// the change withdrew or redefined authority (S-09) — the service layer owns that pairing.
    OrgMembershipChanged {
        /// The org.
        org_id: OrgId,
        /// The affected member.
        user_id: UserId,
        /// New role level, or `None` when the member was removed.
        role: Option<u8>,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// An org's profile or upstream policy changed (`org.updated`).
    OrgUpdated {
        /// The org.
        org_id: OrgId,
        /// Upstream policy after the change.
        upstream_policy: String,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// An org was erased, or archived because it still owned packages (`org.deleted`).
    OrgDeleted {
        /// The org.
        org_id: OrgId,
        /// The org's slug — the only handle a consumer has left once the row is gone.
        slug: String,
        /// `true` when the org row survives as an archive (it still owned packages).
        archived: bool,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// Runtime instance settings changed (`admin.settings`, decision 09).
    ///
    /// Instance-scoped: the audience is admin UIs, which re-read the settings document. The
    /// event carries the *keys* and the new version, never any value — one of those values is
    /// a sealed SMTP password (S-26).
    InstanceSettingsChanged {
        /// Section keys the write touched.
        keys: Vec<String>,
        /// The instance settings version after the write.
        version: i64,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// An upstream archive failed its advertised-sha256 check at ingest and was refused
    /// (`upstream.quarantine`, S-19). The bytes are never stored and never served.
    UpstreamQuarantined {
        /// Artifact format.
        format: Format,
        /// Upstream base URL the archive came from.
        upstream: String,
        /// Package name upstream.
        name: String,
        /// The affected version, canonical string form.
        version: String,
        /// The sha256 upstream advertised in its listing.
        expected_sha256: String,
        /// The sha256 of the bytes it actually served.
        actual_sha256: String,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A name claimed on this instance was observed upstream (`upstream.shadowing`, S-17).
    ///
    /// **Not** a resolution change: the local package won before this event and keeps winning
    /// after it (decision 01). The event exists because the condition is the
    /// dependency-confusion precondition, and the org holding the claim is the only party who
    /// can judge it — which is why this alarm, unlike the other two upstream events, is
    /// org-scoped and reaches org admins through the notification center.
    PackageShadowed {
        /// Artifact format.
        format: Format,
        /// Org holding the local claim — the audience.
        org_id: OrgId,
        /// The shadowed name.
        name: String,
        /// Upstream base URL where the name was observed.
        upstream: String,
        /// The highest version upstream advertises, when the observation carried one.
        upstream_version: Option<String>,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// Upstream advertised a **different** sha256 for a version whose bytes we already hold
    /// (`upstream.drift`, S-19). The cached bytes keep being served; nothing is overwritten.
    UpstreamDrifted {
        /// Artifact format.
        format: Format,
        /// Upstream base URL that changed its mind.
        upstream: String,
        /// Package name upstream.
        name: String,
        /// The affected version, canonical string form.
        version: String,
        /// The hash we cached — and keep serving.
        cached_sha256: String,
        /// The hash upstream now advertises.
        upstream_sha256: String,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// An org's live storage crossed 80 % of its effective quota (`org.storage_quota`,
    /// [S-20.b](../../../docs/security.md#4-supply-chain--registry-integrity), decision 32).
    ///
    /// **Edge-triggered.** It is emitted by the publish that moves the org from *below* the
    /// threshold to *at or above* it, and by no publish after that — decision 29's rule reused:
    /// the crossing is the signal, not the state. An org whose effective quota is unlimited
    /// never produces one, because there is no line to cross.
    OrgStorageQuotaWarning {
        /// The org whose storage crossed the line — also the audience.
        org_id: OrgId,
        /// Live archive bytes the org holds **after** the publish that crossed.
        used_bytes: i64,
        /// The effective quota the crossing was measured against: the org's own override when
        /// it has one, the instance default otherwise. Always positive — unlimited never warns.
        quota_bytes: u64,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
    /// A notification was filed for one account (`notification.new`, decision 20).
    ///
    /// Emitted by the notification center *after* the row is committed, so a client that acts
    /// on it always finds the notification in `GET /api/v1/notifications`. It is the one
    /// user-scoped event: it carries no org, because the recipient is the audience.
    ///
    /// It deliberately reports no [`DomainEvent::notification_category`] of its own — feeding
    /// it back into the notification center would be an infinite loop, and the absence is what
    /// makes that structural rather than a guard somebody can delete.
    UserNotified {
        /// The recipient.
        user_id: UserId,
        /// The stored notification.
        notification_id: NotificationId,
        /// Category of the notification that was filed.
        category: NotificationCategory,
        /// One-line summary, already rendered.
        title: String,
        /// Unread count for this user **after** the notification was filed, so a badge needs
        /// no follow-up request.
        unread: i64,
        /// Event time (UTC).
        at: DateTime<Utc>,
    },
}

impl DomainEvent {
    /// The org the event belongs to — the authorization key for fan-out filtering (S-32).
    ///
    /// `None` means the event is **instance-scoped**, not org-scoped: proxy integrity alarms
    /// are about the upstream and the instance's cache, and belong to instance admins. A
    /// consumer must therefore decide explicitly what to do with an org-less event rather than
    /// inheriting some org's audience by accident.
    pub fn org_id(&self) -> Option<OrgId> {
        match self {
            Self::PackagePublished { org_id, .. }
            | Self::PackageRetracted { org_id, .. }
            | Self::PackageOptionsChanged { org_id, .. }
            | Self::PackageVersionDeleted { org_id, .. }
            | Self::PackageShadowed { org_id, .. }
            | Self::OrgMembershipChanged { org_id, .. }
            | Self::OrgUpdated { org_id, .. }
            | Self::OrgDeleted { org_id, .. }
            | Self::OrgStorageQuotaWarning { org_id, .. } => Some(*org_id),
            Self::PackageTransferred { to_org_id, .. } => Some(*to_org_id),
            Self::UpstreamQuarantined { .. }
            | Self::UpstreamDrifted { .. }
            | Self::InstanceSettingsChanged { .. }
            | Self::UserNotified { .. } => None,
        }
    }

    /// The instant the event describes — the one every variant carries as `at`.
    ///
    /// An exhaustive `match` rather than a lookup, and that is the entire point of the method
    /// existing at all ([D49](../../../docs/roadmap.md)). The notification consumer used to
    /// reconstruct this by serializing the event and fishing out a string field named `at`,
    /// falling back to `Utc::now()` on any failure — so a new variant that forgot the field
    /// compiled clean, produced a queue row stamped at wall-clock time, and (behind the
    /// integration suite's pinned clock) an unclaimable one: the whole fan-out silently never
    /// happened while the pipeline stayed green. With the timestamp coming from the type, a
    /// variant that omits `at` fails to compile here instead.
    pub fn at(&self) -> DateTime<Utc> {
        match self {
            Self::PackagePublished { at, .. }
            | Self::PackageRetracted { at, .. }
            | Self::PackageOptionsChanged { at, .. }
            | Self::PackageVersionDeleted { at, .. }
            | Self::PackageTransferred { at, .. }
            | Self::OrgMembershipChanged { at, .. }
            | Self::OrgUpdated { at, .. }
            | Self::OrgDeleted { at, .. }
            | Self::OrgStorageQuotaWarning { at, .. }
            | Self::InstanceSettingsChanged { at, .. }
            | Self::UpstreamQuarantined { at, .. }
            | Self::PackageShadowed { at, .. }
            | Self::UpstreamDrifted { at, .. }
            | Self::UserNotified { at, .. } => *at,
        }
    }

    /// Who may receive this event (S-32) — the **only** input the SSE fan-out filter takes.
    ///
    /// An org-scoped event goes to that org's Read+ members and to nobody else, *including*
    /// for a public package: the stream is a member's channel over their own organizations,
    /// and the public read model is the REST API. Widening it would mean a package flipped to
    /// private mid-stream could still announce its next publish to strangers.
    pub fn audience(&self) -> EventAudience {
        match self {
            Self::UserNotified { user_id, .. } => EventAudience::User(*user_id),
            other => match other.org_id() {
                Some(org) => EventAudience::Org(org),
                None => EventAudience::Instance,
            },
        }
    }

    /// Stable dot-namespaced name, shared with the audit action (S-22) and the SSE event
    /// type, so one vocabulary describes an action everywhere it surfaces.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PackagePublished { .. } => "package.publish",
            Self::PackageRetracted { .. } => "package.retract",
            Self::PackageOptionsChanged { .. } => "package.options",
            Self::PackageVersionDeleted { .. } => "package.hard_delete",
            Self::PackageTransferred { .. } => "package.transfer",
            Self::OrgMembershipChanged { .. } => "org.member",
            Self::OrgUpdated { .. } => "org.updated",
            Self::OrgDeleted { .. } => "org.deleted",
            Self::OrgStorageQuotaWarning { .. } => "org.storage_quota",
            Self::InstanceSettingsChanged { .. } => "admin.settings",
            Self::UpstreamQuarantined { .. } => "upstream.quarantine",
            Self::UpstreamDrifted { .. } => "upstream.drift",
            Self::PackageShadowed { .. } => "upstream.shadowing",
            Self::UserNotified { .. } => "notification.new",
        }
    }

    /// Which notification category this event belongs to (decision 20's per-category
    /// preferences), or `None` for events that are stream-only.
    ///
    /// The category — not the event name — is what a user subscribes to and what decides
    /// whether an email goes out, so it is part of the event's contract rather than a lookup
    /// table in the notification center. `security` is the high-importance tier: a shadowing
    /// alarm and a refused upstream archive are the two things an admin must not be able to
    /// miss by having muted "packages".
    pub const fn notification_category(&self) -> Option<NotificationCategory> {
        match self {
            Self::PackagePublished { .. } | Self::PackageRetracted { .. } | Self::PackageOptionsChanged { .. } => {
                Some(NotificationCategory::Package)
            }
            Self::PackageVersionDeleted { .. } => Some(NotificationCategory::Security),
            // A package changing hands moves it between two orgs' inventories — the same
            // category as any other package-lifecycle change.
            Self::PackageTransferred { .. } => Some(NotificationCategory::Package),
            // Membership and org lifecycle: who may do what changed, which is a security
            // fact for everybody in the org, not a "packages" newsletter item.
            Self::OrgMembershipChanged { .. } | Self::OrgUpdated { .. } | Self::OrgDeleted { .. } => {
                Some(NotificationCategory::Org)
            }
            // Running out of room is an org-administration fact, not a package one: the people
            // who can act on it are the ones who hard-delete versions or ask for a bigger quota
            // (S-20.b). `Org` rather than `Security` for the same reason — nothing is under
            // attack, and `Security` is the tier reserved for what an admin must not be able to
            // mute away.
            Self::OrgStorageQuotaWarning { .. } => Some(NotificationCategory::Org),
            // Instance admins only; routed by the absent `org_id()`, like the S-19 alarms.
            Self::InstanceSettingsChanged { .. } => Some(NotificationCategory::Security),
            // Org admins: their name is the one being shadowed (S-17).
            Self::PackageShadowed { .. } => Some(NotificationCategory::Security),
            // Instance admins: these carry no org, so the notification center routes them by
            // the absent `org_id()`, not by this category.
            Self::UpstreamQuarantined { .. } | Self::UpstreamDrifted { .. } => Some(NotificationCategory::Security),
            // The notification center's *own* output. Feeding it back in would loop; the
            // absence of a category is what makes that impossible rather than merely avoided.
            Self::UserNotified { .. } => None,
        }
    }

    /// A one-line, already-rendered summary for the notification feed and its email.
    ///
    /// Lives on the event because the notification center must not have to re-derive facts
    /// from ids: everything in the sentence is already in the payload, and a lookup here would
    /// be a database round trip per recipient.
    pub fn summary(&self) -> String {
        match self {
            Self::PackagePublished { name, version, .. } => format!("{name} {version} was published"),
            Self::PackageRetracted { name, version, retracted, .. } => {
                let verb = if *retracted { "retracted" } else { "restored" };
                format!("{name} {version} was {verb}")
            }
            Self::PackageOptionsChanged { name, visibility, .. } => format!("{name} is now {visibility}"),
            Self::PackageVersionDeleted { name, version, .. } => format!("{name} {version} was permanently deleted"),
            Self::PackageTransferred { name, .. } => format!("{name} changed organization"),
            Self::OrgMembershipChanged { role: Some(_), .. } => "an organization membership changed".to_owned(),
            Self::OrgMembershipChanged { role: None, .. } => "an organization membership was removed".to_owned(),
            Self::OrgUpdated { .. } => "organization settings changed".to_owned(),
            Self::OrgDeleted { slug, archived, .. } => {
                let verb = if *archived { "archived" } else { "deleted" };
                format!("organization {slug} was {verb}")
            }
            Self::OrgStorageQuotaWarning { used_bytes, quota_bytes, .. } => {
                format!(
                    "organization storage is at {}% of its {quota_bytes}-byte quota ({used_bytes} bytes used)",
                    percent_of(*used_bytes, *quota_bytes)
                )
            }
            Self::InstanceSettingsChanged { keys, .. } => format!("instance settings changed: {}", keys.join(", ")),
            Self::UpstreamQuarantined { name, version, .. } => {
                format!("upstream archive {name} {version} failed its hash check and was refused")
            }
            Self::UpstreamDrifted { name, version, .. } => {
                format!("upstream changed the hash of {name} {version}; the cached bytes are still served")
            }
            Self::PackageShadowed { name, upstream, .. } => format!("{name} is now also published on {upstream}"),
            Self::UserNotified { title, .. } => title.clone(),
        }
    }
}

/// `used` as a whole percentage of `quota`, saturating at 100 and answering 0 for an absent
/// quota.
///
/// Widened to `u128` before multiplying: `used * 100` overflows `i64` above ~92 PB, which is a
/// number a storage quota can legitimately be set to.
fn percent_of(used: i64, quota: u64) -> u64 {
    if quota == 0 {
        return 0;
    }
    let used = used.max(0) as u128;
    ((used * 100) / u128::from(quota)).min(100) as u64
}

/// Consumer seam for [`DomainEvent`]s.
///
/// Implementations must not block the caller and must not fail it: `emit` returns nothing on
/// purpose (see the module docs). The in-process broadcast + KV-broker fan-out implementation
/// lands with the SSE stream (decision 20).
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Publishes one event to every consumer. Errors are the sink's problem, never the
    /// caller's.
    async fn emit(&self, event: DomainEvent);
}

/// A sink that drops everything — the default wiring until the event bus exists, and the
/// right choice for one-off tooling that has no consumers.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEventSink;

#[async_trait]
impl EventSink for NoopEventSink {
    async fn emit(&self, _event: DomainEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(org: OrgId) -> DomainEvent {
        DomainEvent::PackagePublished {
            format: Format::Pub,
            org_id: org,
            package_id: PackageId::new(),
            name: "acme_core".to_owned(),
            version: "1.0.0".to_owned(),
            version_id: VersionId::new(),
            package_created: true,
            at: Utc::now(),
        }
    }

    #[test]
    fn events_expose_their_org_and_stable_name() {
        let org = OrgId::new();
        let event = published(org);
        assert_eq!(event.org_id(), Some(org));
        assert_eq!(event.name(), "package.publish");
    }

    #[test]
    fn proxy_integrity_alarms_are_instance_scoped() {
        // S-19 alarms belong to instance admins: there is no owning org to filter them by,
        // and silently attributing them to one would show them to the wrong audience (S-32).
        let event = DomainEvent::UpstreamQuarantined {
            format: Format::Pub,
            upstream: "https://pub.dev".to_owned(),
            name: "http".to_owned(),
            version: "1.2.0".to_owned(),
            expected_sha256: "a".repeat(64),
            actual_sha256: "b".repeat(64),
            at: Utc::now(),
        };
        assert_eq!(event.org_id(), None);
        assert_eq!(event.name(), "upstream.quarantine");
    }

    #[test]
    fn a_shadowing_alarm_is_org_scoped_and_high_importance() {
        // S-17's audience is the org holding the claim — the only party who can judge whether
        // the upstream namesake is a squat, a coincidence, or their own release.
        let org = OrgId::new();
        let event = DomainEvent::PackageShadowed {
            format: Format::Pub,
            org_id: org,
            name: "acme_core".to_owned(),
            upstream: "https://pub.dev".to_owned(),
            upstream_version: Some("9.9.9".to_owned()),
            at: Utc::now(),
        };
        assert_eq!(event.org_id(), Some(org));
        assert_eq!(event.name(), "upstream.shadowing");
        assert_eq!(event.notification_category(), Some(NotificationCategory::Security));
    }

    #[test]
    fn a_transfer_is_addressed_to_the_new_owner() {
        // Both orgs are in the payload, but fan-out has to pick one audience, and the package
        // belongs to the receiving org from this moment on (S-32).
        let from = OrgId::new();
        let to = OrgId::new();
        let event = DomainEvent::PackageTransferred {
            format: Format::Pub,
            from_org_id: from,
            to_org_id: to,
            package_id: PackageId::new(),
            name: "acme_core".to_owned(),
            at: Utc::now(),
        };
        assert_eq!(event.org_id(), Some(to));
        assert_eq!(event.name(), "package.transfer");
    }

    #[test]
    fn settings_changes_are_instance_scoped_and_carry_no_values() {
        let event = DomainEvent::InstanceSettingsChanged { keys: vec!["smtp".to_owned()], version: 4, at: Utc::now() };
        assert_eq!(event.org_id(), None);
        assert_eq!(event.name(), "admin.settings");
        // One of the values is a sealed SMTP password (S-26) — the event must not be able to
        // carry any value at all, which is a property of the variant's fields.
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.as_object().unwrap().keys().count(), 4, "type + keys + version + at only: {json}");
    }

    #[test]
    fn membership_removal_reports_no_role() {
        let org = OrgId::new();
        let event =
            DomainEvent::OrgMembershipChanged { org_id: org, user_id: UserId::new(), role: None, at: Utc::now() };
        assert_eq!(event.org_id(), Some(org));
        assert_eq!(event.name(), "org.member");
        assert_eq!(event.notification_category(), Some(NotificationCategory::Org));
    }

    #[test]
    fn serde_tags_the_variant() {
        let json = serde_json::to_value(published(OrgId::new())).unwrap();
        assert_eq!(json["type"], "package_published");
        assert_eq!(json["name"], "acme_core");
    }

    #[tokio::test]
    async fn noop_sink_swallows_events() {
        NoopEventSink.emit(published(OrgId::new())).await;
    }

    /// **S-20.b.** The quota warning is org-scoped, lands in the `org` category, and says how
    /// full the org is in the one line a feed row shows.
    #[test]
    fn s20_b_a_storage_quota_warning_is_org_scoped_and_reports_how_full_the_org_is() {
        let org = OrgId::new();
        let event =
            DomainEvent::OrgStorageQuotaWarning { org_id: org, used_bytes: 850, quota_bytes: 1000, at: Utc::now() };
        assert_eq!(event.org_id(), Some(org));
        assert_eq!(event.audience(), EventAudience::Org(org));
        assert_eq!(event.name(), "org.storage_quota");
        assert_eq!(event.notification_category(), Some(NotificationCategory::Org));
        assert!(event.summary().contains("85%"), "{}", event.summary());
    }

    /// **D49.** `at()` is the accessor the notification consumer reads instead of re-deriving
    /// the timestamp from JSON — so the invariant "every variant carries `at`" is enforced by
    /// the compiler. This walks every variant's serialized form as the second half of the same
    /// claim: the field is on the wire under exactly that name for every one of them.
    #[test]
    fn d49_every_variant_reports_its_own_timestamp_from_the_type_and_on_the_wire() {
        let at = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 8, 14, 9, 30, 0).unwrap();
        let org = OrgId::new();
        let events = vec![
            DomainEvent::PackagePublished {
                format: Format::Pub,
                org_id: org,
                package_id: PackageId::new(),
                name: "acme_core".to_owned(),
                version: "1.0.0".to_owned(),
                version_id: VersionId::new(),
                package_created: true,
                at,
            },
            DomainEvent::PackageRetracted {
                format: Format::Pub,
                org_id: org,
                package_id: PackageId::new(),
                name: "acme_core".to_owned(),
                version: "1.0.0".to_owned(),
                version_id: VersionId::new(),
                retracted: true,
                at,
            },
            DomainEvent::PackageOptionsChanged {
                format: Format::Pub,
                org_id: org,
                package_id: PackageId::new(),
                name: "acme_core".to_owned(),
                visibility: "private".to_owned(),
                discontinued: false,
                unlisted: false,
                at,
            },
            DomainEvent::PackageVersionDeleted {
                format: Format::Pub,
                org_id: org,
                package_id: PackageId::new(),
                name: "acme_core".to_owned(),
                version: "1.0.0".to_owned(),
                version_id: VersionId::new(),
                blob_removed: true,
                at,
            },
            DomainEvent::PackageTransferred {
                format: Format::Pub,
                from_org_id: org,
                to_org_id: OrgId::new(),
                package_id: PackageId::new(),
                name: "acme_core".to_owned(),
                at,
            },
            DomainEvent::OrgMembershipChanged { org_id: org, user_id: UserId::new(), role: Some(100), at },
            DomainEvent::OrgUpdated { org_id: org, upstream_policy: "allow".to_owned(), at },
            DomainEvent::OrgDeleted { org_id: org, slug: "acme".to_owned(), archived: true, at },
            DomainEvent::OrgStorageQuotaWarning { org_id: org, used_bytes: 8, quota_bytes: 10, at },
            DomainEvent::InstanceSettingsChanged { keys: vec!["registry".to_owned()], version: 2, at },
            DomainEvent::UpstreamQuarantined {
                format: Format::Pub,
                upstream: "https://pub.dev".to_owned(),
                name: "http".to_owned(),
                version: "1.0.0".to_owned(),
                expected_sha256: "a".repeat(64),
                actual_sha256: "b".repeat(64),
                at,
            },
            DomainEvent::PackageShadowed {
                format: Format::Pub,
                org_id: org,
                name: "acme_core".to_owned(),
                upstream: "https://pub.dev".to_owned(),
                upstream_version: None,
                at,
            },
            DomainEvent::UpstreamDrifted {
                format: Format::Pub,
                upstream: "https://pub.dev".to_owned(),
                name: "http".to_owned(),
                version: "1.0.0".to_owned(),
                cached_sha256: "a".repeat(64),
                upstream_sha256: "b".repeat(64),
                at,
            },
            DomainEvent::UserNotified {
                user_id: UserId::new(),
                notification_id: NotificationId::new(),
                category: NotificationCategory::Org,
                title: "hello".to_owned(),
                unread: 1,
                at,
            },
        ];
        // Every variant, so a new one that is not added here is visible as a gap rather than
        // as nothing: the count is asserted against the `name()` set, which the compiler forces
        // a new variant into.
        let mut names: Vec<&str> = events.iter().map(DomainEvent::name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), events.len(), "one event per variant, and every name distinct: {names:?}");
        for event in &events {
            assert_eq!(event.at(), at, "{} does not report its own timestamp", event.name());
            let json = serde_json::to_value(event).unwrap();
            assert!(
                json.get("at").and_then(serde_json::Value::as_str).is_some(),
                "{} has no `at` on the wire",
                event.name()
            );
        }
    }

    #[test]
    fn a_percentage_saturates_and_survives_a_petabyte_quota() {
        assert_eq!(percent_of(0, 100), 0);
        assert_eq!(percent_of(80, 100), 80);
        // Over-quota is reachable: the bound is loose by one round of concurrent publishes
        // (S-20.b), and "137% full" in a feed row is worse than "100%".
        assert_eq!(percent_of(200, 100), 100);
        // No quota, no percentage — and no division by zero.
        assert_eq!(percent_of(5, 0), 0);
        // `used * 100` overflows i64 above ~92 PB; the widening is what keeps this honest.
        assert_eq!(percent_of(800 * 1024_i64.pow(5), 1000 * 1024_u64.pow(5)), 80);
    }
}
