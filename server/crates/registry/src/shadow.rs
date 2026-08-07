//! Shadowing alarms — S-17, the supply-chain half of decision 01's "local always wins".
//!
//! The condition is narrow and the response is deliberately not: a name **claimed on this
//! instance** exists upstream too. Resolution does not change — it cannot, or the claim would
//! stop meaning anything — so nothing here touches what a client gets. What it does is make the
//! condition *visible*, because it is the precondition of dependency confusion: from the moment
//! upstream carries the name, a developer whose `PUB_HOSTED_URL` is not this instance resolves a
//! different package under it, and only the org holding the claim can judge whether that is a
//! squat, a coincidence, or their own open-source release.
//!
//! One function, two callers, because the condition has two arrival orders and both are real:
//!
//! - **Publish** claims a name we already proxy (the org releases `acme_core` internally, and
//!   `acme_core` is already on pub.dev). Detected in the publish pipeline, at the moment the
//!   claim is created.
//! - **The mirror worker** walks upstream's package-name list and finds a name we claim (the
//!   squatter publishes *after* us). Detected on the sweep — and it is the only place it *can*
//!   be detected, because the read path structurally never asks upstream about a claimed name
//!   (S-16).
//!
//! The alarm is raised once per incident, not once per sighting: `record_shadowing` reports
//! whether this observation raised it, and only a raise audits, emits, and notifies. A sweep
//! that re-observes an ongoing condition every hour must not re-page the same admins.

use chrono::{DateTime, Utc};
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::package::{NewShadowingAlarm, ShadowingAlarm};
use pub_core::traits::Repositories;
use pub_core::{Format, Result};

/// One sighting of a name upstream, before we know whether it is claimed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowObservation<'a> {
    /// Artifact format.
    pub format: Format,
    /// The name observed upstream.
    pub name: &'a str,
    /// Upstream base URL where it was observed.
    pub upstream: &'a str,
    /// The highest version upstream advertises, when the observation carried one.
    pub upstream_version: Option<String>,
}

/// What [`observe`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowOutcome {
    /// The stored alarm row.
    pub alarm: ShadowingAlarm,
    /// Whether this observation **raised** the alarm — a first sighting, or the first one after
    /// an admin acknowledged it. Only a raise is audited, emitted, and notified.
    pub raised: bool,
}

/// Records a sighting of `name` upstream, alarming when the name is claimed here (S-17).
///
/// Returns `None` when the name is not claimed on this instance — the overwhelmingly common
/// case, and one indexed lookup. Errors from the alarm's *reporting* side (audit, events) are
/// logged rather than propagated, for the same reason the rest of the registry does it: an
/// audit outage must not take the mirror down. A failure to *record* the alarm is propagated,
/// because an alarm nobody can list is not an alarm.
pub async fn observe(
    repos: &Repositories,
    events: &dyn EventSink,
    observation: ShadowObservation<'_>,
    now: DateTime<Utc>,
) -> Result<Option<ShadowOutcome>> {
    let ShadowObservation { format, name, upstream, upstream_version } = observation;
    // "Claimed here" is exactly the claim table, the same source `resolve_in_base` consults —
    // so a reserved name with nothing published shadows too. It is precisely the name somebody
    // is holding *for* a future release, which is the one worth alarming on.
    let Some(claim) = repos.packages.lookup_claim(format, name).await? else {
        return Ok(None);
    };

    let (alarm, raised) = repos
        .upstream
        .record_shadowing(
            NewShadowingAlarm {
                format,
                name: name.to_owned(),
                org_id: claim.org_id,
                upstream: upstream.to_owned(),
                upstream_version: upstream_version.clone(),
            },
            now,
        )
        .await?;

    if raised {
        tracing::warn!(
            package = name,
            org = %claim.org_id,
            upstream,
            upstream_version = upstream_version.as_deref().unwrap_or("<unknown>"),
            "SHADOWING: a locally claimed name exists upstream; still serving the local package"
        );
        metrics::counter!("shadowing_alarms_total").increment(1);

        let event = NewAuditEvent {
            actor: AuditActor::System,
            ip: None,
            user_agent: None,
            org_id: Some(claim.org_id),
            action: "upstream.shadowing".to_owned(),
            target: Some(name.to_owned()),
            // An alarm is not a successful action; filing it under `failure` keeps every
            // supply-chain alarm on one audit filter with the S-19 pair.
            result: AuditResult::Failure,
            metadata: Some(serde_json::json!({
                "format": format.as_str(),
                "package": name,
                "upstream": upstream,
                "upstream_version": upstream_version,
            })),
        };
        if let Err(err) = repos.audit.append(event, now).await {
            tracing::error!(package = name, error = %err, "audit append failed for a shadowing alarm");
        }

        events
            .emit(DomainEvent::PackageShadowed {
                format,
                org_id: claim.org_id,
                name: name.to_owned(),
                upstream: upstream.to_owned(),
                upstream_version,
                at: now,
            })
            .await;
    }

    Ok(Some(ShadowOutcome { alarm, raised }))
}
