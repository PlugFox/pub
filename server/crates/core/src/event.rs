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
}

impl DomainEvent {
    /// The org the event belongs to — the authorization key for fan-out filtering (S-32).
    pub fn org_id(&self) -> OrgId {
        match self {
            Self::PackagePublished { org_id, .. }
            | Self::PackageRetracted { org_id, .. }
            | Self::PackageVersionDeleted { org_id, .. } => *org_id,
        }
    }

    /// Stable dot-namespaced name, shared with the audit action (S-22) and the SSE event
    /// type, so one vocabulary describes an action everywhere it surfaces.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PackagePublished { .. } => "package.publish",
            Self::PackageRetracted { .. } => "package.retract",
            Self::PackageVersionDeleted { .. } => "package.hard_delete",
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
        assert_eq!(event.org_id(), org);
        assert_eq!(event.name(), "package.publish");
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
