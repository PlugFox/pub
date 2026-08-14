//! System routes: health and ping. Every route is registered through utoipa's
//! `OpenApiRouter` so the OpenAPI document can never drift from the router
//! (docs/rules/api.md).

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::envelope::OkEnvelope;

/// `/healthz` response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// `"ok"` when every configured backend responds, `"degraded"` otherwise.
    pub status: String,
    /// Server version: the release version injected from the git tag at build time
    /// (decision 18), or the crate version marked `+dev` for non-release builds.
    /// Git metadata is in `pubd --version`.
    pub version: String,
    /// Which backend kinds this instance is configured with.
    pub backends: Backends,
    /// Live connectivity per backend — each is an actual ping, not an echo of config.
    pub checks: Checks,
}

/// Configured backend kinds, as selected by config (decision 09).
#[derive(Debug, Serialize, ToSchema)]
pub struct Backends {
    /// Database backend: `sqlite` | `postgres`.
    pub database: String,
    /// Blob backend: `fs` | `s3` | `memory`.
    pub blob: String,
    /// KV backend: `memory` | `redis`.
    pub kv: String,
}

/// Live ping results per backend.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
pub struct Checks {
    /// The database answered a probe query.
    pub database: bool,
    /// The blob store answered a probe.
    pub blob: bool,
    /// The KV store answered a probe.
    pub kv: bool,
}

/// Liveness/readiness probe. Always on, never authenticated (decision 23); orchestrators
/// poll it, so it must stay cheap — one trivial query per backend.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses((status = OK, description = "Service health and configured backends", body = Health))
)]
pub async fn healthz(State(state): State<AppState>) -> Json<Health> {
    let Checks { database: db_ok, blob: blob_ok, kv: kv_ok } = probe(&state).await;
    let status = if db_ok && blob_ok && kv_ok { "ok" } else { "degraded" };
    Json(Health {
        status: status.to_owned(),
        version: pub_core::version::VERSION.to_owned(),
        backends: Backends {
            database: state.settings.database.kind.as_str().to_owned(),
            blob: state.settings.blob.kind.as_str().to_owned(),
            kv: state.settings.kv.kind.as_str().to_owned(),
        },
        checks: Checks { database: db_ok, blob: blob_ok, kv: kv_ok },
    })
}

/// How long a probe result stands in for the next caller's.
///
/// `/healthz` is exempt from the read buckets because S-24 exempts health checks — which left
/// it as the one unauthenticated route that costs three backend round trips per request, and
/// therefore the cheapest amplifier on the instance (roadmap D14). One second collapses a
/// flood to one probe per backend per second and is far below any orchestrator's poll interval,
/// so no probe ever reads a verdict it would not have computed itself.
const PROBE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Pings every backend, or reuses a result younger than [`PROBE_TTL`].
///
/// The memo lives on [`AppState`], **not** in a process-wide static. In production the two are
/// the same thing — one instance, one state — but a static would make two `TestApp`s in one test
/// binary share health verdicts, so the first suite to probe a healthy instance would hide a
/// later one's deliberately broken backend. That is a test that passes for the wrong reason,
/// which is the failure mode this codebase spends its review budget on.
///
/// Deliberately not a single-flight: two probes racing on a cold cache cost one extra round
/// trip each and nothing else, whereas holding the lock across three `await`s would let a hung
/// backend serialize every liveness check behind it — turning the memo into the outage.
async fn probe(state: &AppState) -> Checks {
    let now = std::time::Instant::now();
    if let Some((taken, checks)) = state.health_probe.lock().expect("health probe mutex poisoned").as_ref()
        && now.duration_since(*taken) < PROBE_TTL
    {
        return *checks;
    }
    // The database check goes through a live repository handle over the selected backend.
    let checks = Checks {
        database: state.repos.users.ping().await.is_ok(),
        blob: state.blob.ping().await.is_ok(),
        kv: state.kv.ping().await.is_ok(),
    };
    *state.health_probe.lock().expect("health probe mutex poisoned") = Some((std::time::Instant::now(), checks));
    checks
}

/// Trivial app-API echo endpoint proving the envelope contract end-to-end.
#[utoipa::path(
    get,
    path = "/api/v1/ping",
    tag = "system",
    responses((status = OK, description = "Envelope round-trip probe", body = OkEnvelope<String>))
)]
pub async fn ping() -> Json<OkEnvelope<String>> {
    Json(OkEnvelope::new("pong".to_owned()))
}
