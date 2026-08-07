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
#[derive(Debug, Serialize, ToSchema)]
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
    // The database check goes through a live repository handle over the selected backend.
    let db_ok = state.repos.users.ping().await.is_ok();
    let blob_ok = state.blob.ping().await.is_ok();
    let kv_ok = state.kv.ping().await.is_ok();
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
