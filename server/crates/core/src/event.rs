//! Domain events — the single fan-out seam (decision 22).
//!
//! Domain services emit events here; the consumers (SSE stream — decision 20, notification
//! center, outbound webhooks, and any future integration) subscribe behind [`EventSink`].
//! Only the registry lifecycle events exist in this phase; membership, invitation, and
//! shadowing events join as their flows land. The enum is `#[non_exhaustive]` so that is
//! additive.
//!
//! Emission is **fire-and-forget and infallible by contract**: the event bus is a hint
//! channel (clients reconcile through the REST API), so a broken consumer must never fail a
//! publish. Durable truth stays in the database and the audit log.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Format, OrgId, PackageId, VersionId};

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
            | Self::PackageVersionDeleted { org_id, .. }
            | Self::PackageShadowed { org_id, .. } => Some(*org_id),
            Self::UpstreamQuarantined { .. } | Self::UpstreamDrifted { .. } => None,
        }
    }

    /// Stable dot-namespaced name, shared with the audit action (S-22) and the SSE event
    /// type, so one vocabulary describes an action everywhere it surfaces.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PackagePublished { .. } => "package.publish",
            Self::PackageRetracted { .. } => "package.retract",
            Self::PackageVersionDeleted { .. } => "package.hard_delete",
            Self::UpstreamQuarantined { .. } => "upstream.quarantine",
            Self::UpstreamDrifted { .. } => "upstream.drift",
            Self::PackageShadowed { .. } => "upstream.shadowing",
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
    pub const fn notification_category(&self) -> Option<&'static str> {
        match self {
            Self::PackagePublished { .. } | Self::PackageRetracted { .. } => Some("package"),
            Self::PackageVersionDeleted { .. } => Some("security"),
            // Org admins: their name is the one being shadowed (S-17).
            Self::PackageShadowed { .. } => Some("security"),
            // Instance admins: these carry no org, so the notification center routes them by
            // the absent `org_id()`, not by this category.
            Self::UpstreamQuarantined { .. } | Self::UpstreamDrifted { .. } => Some("security"),
        }
    }
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
        assert_eq!(event.notification_category(), Some("security"));
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
}
