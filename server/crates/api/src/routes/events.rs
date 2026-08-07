//! `GET /api/v1/events` — the Server-Sent-Events stream (decision 20, S-32).
//!
//! Four properties, each of which is the reason a line of this module exists:
//!
//! - **Authenticated like every other route.** The access JWT arrives in `Authorization`, which
//!   is why the browser client uses fetch-streaming rather than `EventSource` (it cannot set
//!   headers). The [`AuthContext`] extractor runs the same keyring verification and revoked-`sid`
//!   fast path the REST routes do, so a stream cannot be opened with a credential a request
//!   could not use.
//! - **The heartbeat is a revocation re-check.** Every `realtime.heartbeat_secs` the stream
//!   re-asks the KV blocklist and the durable user row; a revoked session, a suspended account,
//!   or a demoted administrator ends the stream on the next tick. The config validator refuses
//!   a heartbeat at or above the access TTL, so "within one access TTL" (S-32) is enforced by
//!   startup rather than by hope. The stream additionally ends at the token's own `exp`: a
//!   connection opened with a 10-minute token does not become an unbounded session.
//! - **Every event is authorization-filtered.** The filter reads
//!   [`DomainEvent::audience`](pub_core::DomainEvent::audience) and nothing else, and the
//!   principal's org roles come from the access token — which a role change revokes (S-09), so
//!   they cannot go stale beyond the same window.
//! - **Replay is best-effort and filtered identically.** `Last-Event-ID` replays from the
//!   per-instance ring through the *same* filter, so a reconnect can never widen what a
//!   principal sees.

use std::convert::Infallible;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use pub_core::authorize::{Action, ActorContext, Resource, authorize};
use pub_core::event::{EventAudience, EventEnvelope, EventId};
use pub_core::user::UserStatus;
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;

use crate::dto::StreamEventDto;
use crate::envelope::ErrorEnvelope;
use crate::error::ApiError;
use crate::extract::AuthContext;
use crate::state::AppState;

/// How many events the outbound channel buffers before the writer waits on the client.
const CHANNEL_CAPACITY: usize = 64;

/// The live event stream.
#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "events",
    security(("bearer_auth" = [])),
    params(
        ("Last-Event-ID" = Option<String>, Header, description =
            "Replay events newer than this id from the instance's short ring buffer (best-effort)"),
    ),
    responses(
        (status = OK, content_type = "text/event-stream", description =
            "Server-Sent Events. Each message carries `id:` (an event id, usable as Last-Event-ID), \
             `event:` (the dot-namespaced type) and `data:` (a StreamEvent document). Comment \
             lines (`:heartbeat`) are keep-alives.", body = StreamEventDto),
        (status = UNAUTHORIZED, description = "Missing, invalid, or revoked access token", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "Per-user concurrent-stream cap reached (S-32)", body = ErrorEnvelope),
    )
)]
pub async fn stream(
    State(state): State<AppState>,
    auth: AuthContext,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    // The account row decides the instance-admin audience, and it is re-read on every
    // heartbeat — a demotion must not keep delivering instance-scoped alarms (S-07).
    let user = state
        .repos
        .users
        .get(auth.claims.sub)
        .await?
        .filter(|user| user.status == UserStatus::Active)
        .ok_or_else(|| ApiError::unauthorized("account unavailable"))?;

    // S-32 per-user cap. The guard is moved into the writer task, so the slot is released on
    // every exit path including a client that simply vanishes.
    let guard = state.events.acquire_connection(auth.claims.sub).map_err(ApiError)?;

    let mut receiver = state.events.subscribe();
    let actor = auth.actor.clone().with_instance_admin(user.is_instance_admin);
    let replay = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.parse::<EventId>().ok())
        .map(|id| state.events.replay_since(&id))
        .unwrap_or_default();

    let (sender, outbound) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(CHANNEL_CAPACITY);
    let heartbeat = state.sse_heartbeat();
    let expires_at = auth.claims.exp;
    let sid = auth.claims.sid;
    let user_id = auth.claims.sub;
    let bus_state = state.clone();

    tokio::spawn(async move {
        // Held for the life of the stream; dropping it returns the connection slot.
        let _guard = guard;

        for envelope in replay {
            if !visible(&actor, &envelope) {
                continue;
            }
            if sender.send(Ok(sse_event(&envelope))).await.is_err() {
                return;
            }
        }

        let mut ticker = tokio::time::interval(heartbeat);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick fires immediately; spend it so the first heartbeat is one interval in.
        ticker.tick().await;

        let mut actor = actor;
        loop {
            tokio::select! {
                received = receiver.recv() => match received {
                    Ok(envelope) => {
                        if visible(&actor, &envelope) && sender.send(Ok(sse_event(&envelope))).await.is_err() {
                            return;
                        }
                    }
                    // A slow client missed events. The stream is a hint channel, so the right
                    // answer is to say so and keep going — the REST API is the reconciliation
                    // path — not to drop a connection the client would immediately reopen.
                    Err(RecvError::Lagged(missed)) => {
                        let notice = Event::default().event("stream.lagged").data(missed.to_string());
                        if sender.send(Ok(notice)).await.is_err() {
                            return;
                        }
                    }
                    Err(RecvError::Closed) => return,
                },
                _ = ticker.tick() => {
                    match recheck(&bus_state, user_id, sid, expires_at, &mut actor).await {
                        Ok(()) => {
                            if sender.send(Ok(Event::default().comment("heartbeat"))).await.is_err() {
                                return;
                            }
                        }
                        Err(reason) => {
                            // One last frame so the client can distinguish "your session ended"
                            // from a network drop and stop reconnecting with a dead credential.
                            let _ = sender.send(Ok(Event::default().event("stream.closed").data(reason))).await;
                            return;
                        }
                    }
                }
            }
        }
    });

    // No axum keep-alive layer: this stream's liveness signal *is* the revocation re-check, and
    // a second, unconditional keep-alive would make a dead session look alive to the client.
    Ok(Sse::new(ReceiverStream::new(outbound)).keep_alive(KeepAlive::default().interval(heartbeat * 4)).into_response())
}

/// Whether this principal may receive this event (S-32).
fn visible(actor: &ActorContext, envelope: &EventEnvelope) -> bool {
    match envelope.event.audience() {
        // One chokepoint (decision 19): membership is decided by `authorize`, never by an
        // inline level comparison.
        EventAudience::Org(org) => authorize(actor, Action::ReadPackages, &Resource::Org(org)).is_ok(),
        EventAudience::Instance => authorize(actor, Action::AdministerInstance, &Resource::Instance).is_ok(),
        EventAudience::User(user) => actor.user_id == Some(user),
    }
}

/// Projects an envelope onto its SSE frame.
fn sse_event(envelope: &EventEnvelope) -> Event {
    let dto = StreamEventDto::from(envelope);
    Event::default()
        .id(envelope.id.to_string())
        .event(envelope.event.name())
        // Serialization of a plain struct of owned scalars cannot fail; a `data:` we could not
        // build would still have to be a frame, so the fallback is an empty object rather than
        // a dropped event.
        .data(serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_owned()))
}

/// The heartbeat's real job: is this stream still entitled to exist?
///
/// `Err(reason)` ends the stream. Four conditions, in the order they matter: the access token
/// expired, the session was revoked (S-09 fast path), the account stopped being active, and the
/// instance-admin flag changed (which is not a termination — it narrows the audience live).
async fn recheck(
    state: &AppState,
    user: pub_core::UserId,
    sid: pub_core::SessionId,
    expires_at: i64,
    actor: &mut ActorContext,
) -> Result<(), String> {
    if (state.clock)().timestamp() >= expires_at {
        return Err("token_expired".to_owned());
    }
    match state.auth.is_sid_revoked(sid).await {
        Ok(true) => return Err("session_revoked".to_owned()),
        Ok(false) => {}
        // The revocation check fails closed on the request path (S-09); it must fail closed
        // here too, or a KV outage would turn every open stream into an unrevokable one.
        Err(error) => {
            tracing::warn!(%error, "sse revocation re-check failed; closing the stream");
            return Err("revocation_check_unavailable".to_owned());
        }
    }
    match state.repos.users.get(user).await {
        Ok(Some(row)) if row.status == UserStatus::Active => {
            actor.is_instance_admin = row.is_instance_admin;
            Ok(())
        }
        Ok(_) => Err("account_unavailable".to_owned()),
        Err(error) => {
            tracing::warn!(%error, "sse account re-check failed; closing the stream");
            Err("account_check_unavailable".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use pub_core::{DomainEvent, Format, OrgId, PackageId, RoleLevel, UserId, VersionId};

    use super::*;

    fn member(org: OrgId, level: u8) -> ActorContext {
        ActorContext::user(UserId::new(), BTreeMap::from([(org, RoleLevel::new(level))]))
    }

    fn publish(org: OrgId) -> EventEnvelope {
        EventEnvelope::new(DomainEvent::PackagePublished {
            format: Format::Pub,
            org_id: org,
            package_id: PackageId::new(),
            name: "acme_core".to_owned(),
            version: "1.0.0".to_owned(),
            version_id: VersionId::new(),
            package_created: false,
            at: Utc::now(),
        })
    }

    #[test]
    fn s32_org_events_reach_members_and_nobody_else() {
        let org = OrgId::new();
        let event = publish(org);
        assert!(visible(&member(org, RoleLevel::READ.level()), &event));
        assert!(!visible(&member(OrgId::new(), RoleLevel::OWNER.level()), &event), "another org's member");
        assert!(!visible(&ActorContext::anonymous(), &event), "anonymous");
        // A membership below Read is not a membership.
        assert!(!visible(&member(org, 49), &event));
    }

    #[test]
    fn s32_instance_events_reach_only_instance_admins() {
        let event = EventEnvelope::new(DomainEvent::UpstreamQuarantined {
            format: Format::Pub,
            upstream: "https://pub.dev".to_owned(),
            name: "http".to_owned(),
            version: "1.0.0".to_owned(),
            expected_sha256: "a".repeat(64),
            actual_sha256: "b".repeat(64),
            at: Utc::now(),
        });
        let org = OrgId::new();
        assert!(!visible(&member(org, RoleLevel::OWNER.level()), &event), "an org Owner is not an instance admin");
        assert!(visible(&member(org, RoleLevel::READ.level()).with_instance_admin(true), &event));
    }

    #[test]
    fn s32_personal_events_reach_exactly_one_account() {
        let me = UserId::new();
        let event = EventEnvelope::new(DomainEvent::UserNotified {
            user_id: me,
            notification_id: pub_core::NotificationId::new(),
            category: pub_core::notification::NotificationCategory::Org,
            title: "you were added".to_owned(),
            unread: 1,
            at: Utc::now(),
        });
        let mine = ActorContext::user(me, BTreeMap::new());
        assert!(visible(&mine, &event));
        assert!(!visible(&ActorContext::user(UserId::new(), BTreeMap::new()), &event));
        // Not even an instance administrator reads somebody else's notifications.
        assert!(!visible(&ActorContext::user(UserId::new(), BTreeMap::new()).with_instance_admin(true), &event));
    }

    #[test]
    fn the_frame_carries_the_id_and_the_event_name() {
        let org = OrgId::new();
        let envelope = publish(org);
        let rendered = format!("{:?}", sse_event(&envelope));
        assert!(rendered.contains(envelope.id.as_str()), "the id must be replayable: {rendered}");
        assert!(rendered.contains("package.publish"), "the event name must be on the frame: {rendered}");
    }
}
