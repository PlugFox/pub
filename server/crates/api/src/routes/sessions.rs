//! Session management routes (S-09, S-10): list with current flag, revoke one, revoke all.

use axum::Json;
use axum::extract::{Path, State};
use pub_core::{Error, SessionId};

use crate::dto::{ListDto, RevokedDto, SessionDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, StepUp};
use crate::state::AppState;

/// Lists the caller's live sessions, most recently seen first, with the current flag (S-10).
#[utoipa::path(
    get,
    path = "/api/v1/sessions",
    tag = "sessions",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "The caller's sessions", body = OkEnvelope<ListDto<SessionDto>>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OkEnvelope<ListDto<SessionDto>>>, ApiError> {
    let sessions = state.auth.list_sessions(auth.claims.sub).await?;
    let items = sessions.iter().map(|session| SessionDto::from_session(session, auth.claims.sid)).collect();
    Ok(Json(OkEnvelope::new(ListDto::single_page(items))))
}

/// Revokes one of the caller's sessions (S-09/S-10). A session the caller does not own is
/// indistinguishable from a nonexistent one: 404 either way (S-04).
#[utoipa::path(
    delete,
    path = "/api/v1/sessions/{sid}",
    tag = "sessions",
    security(("bearer_auth" = [])),
    params(("sid" = String, Path, description = "Session id to revoke")),
    responses(
        (status = OK, description = "Session revoked", body = OkEnvelope<RevokedDto>),
        (status = NOT_FOUND, description = "Unknown or foreign session id", body = ErrorEnvelope),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(sid): Path<String>,
) -> Result<Json<OkEnvelope<RevokedDto>>, ApiError> {
    // A malformed sid can only be a nonexistent one — same 404, no shape oracle (S-04).
    let sid: SessionId = sid.parse().map_err(|_| Error::NotFound { what: format!("session {sid}") })?;
    let now = (state.clock)();
    state.auth.revoke_session(auth.claims.sub, sid, &meta, now).await?;
    Ok(Json(OkEnvelope::new(RevokedDto { revoked: 1 })))
}

/// Revokes every session of the caller (S-09 revoke-all), the current one included.
/// **Step-up gated** (S-06): the explicit revoke-all is on the dangerous-action list.
#[utoipa::path(
    post,
    path = "/api/v1/sessions/revoke-all",
    tag = "sessions",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "All sessions revoked", body = OkEnvelope<RevokedDto>),
        (status = FORBIDDEN, description = "step_up_required — re-authenticate first", body = ErrorEnvelope),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn revoke_all(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
) -> Result<Json<OkEnvelope<RevokedDto>>, ApiError> {
    let now = (state.clock)();
    let revoked = state.auth.revoke_all_sessions(auth.claims.sub, &meta, now).await?;
    Ok(Json(OkEnvelope::new(RevokedDto { revoked })))
}
