//! OIDC sign-in routes (S-01, S-02, decision 12): provider listing, flow start, callback.
//!
//! OIDC is optional — with zero providers configured, the listing is empty and the
//! per-provider routes answer 404. The browser dance: `start` hands back the IdP authorize
//! URL plus an opaque `flow_id` (held client-side, e.g. sessionStorage); the IdP redirects
//! to `{public_url}/auth/callback/{provider}`, where the SPA posts `flow_id` + `code` +
//! `state` to `callback` and receives the same session pair as the OTP path (or a
//! pending-MFA handle, S-05).

use axum::Json;
use axum::extract::{Path, State};

use crate::dto::{LoginDto, OidcCallbackBody, OidcStartDto, ProviderDto, ProvidersDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::RequestMeta;
use crate::state::AppState;

/// Lists the configured OIDC providers for the login screen (public, no secrets).
#[utoipa::path(
    get,
    path = "/api/v1/auth/providers",
    tag = "auth",
    responses(
        (status = OK, description = "Configured providers; empty = email OTP only", body = OkEnvelope<ProvidersDto>),
    )
)]
pub async fn providers(State(state): State<AppState>) -> Json<OkEnvelope<ProvidersDto>> {
    let providers = state.auth.oidc_providers().iter().map(ProviderDto::from).collect();
    Json(OkEnvelope::new(ProvidersDto { providers }))
}

/// Starts an OIDC flow: state/nonce/PKCE are minted and stored server-side under the
/// returned `flow_id` (S-01); the browser navigates to `authorize_url`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/oidc/{provider}/start",
    tag = "auth",
    params(("provider" = String, Path, description = "Provider id from the listing")),
    responses(
        (status = OK, description = "Authorize URL + flow handle", body = OkEnvelope<OidcStartDto>),
        (status = NOT_FOUND, description = "Provider not configured", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "Rate limited; Retry-After set", body = ErrorEnvelope),
    )
)]
pub async fn start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Json<OkEnvelope<OidcStartDto>>, ApiError> {
    let now = (state.clock)();
    let flow = state.auth.oidc_start(&provider, now).await?;
    Ok(Json(OkEnvelope::new(OidcStartDto::from(flow))))
}

/// Finishes an OIDC flow: single-use state, server-side code exchange (confidential client
/// + PKCE), full id_token validation, S-02 linking policy, S-31 domain gate.
///
/// Every authentication failure is the same 401 — the reason lives in the audit log only.
#[utoipa::path(
    post,
    path = "/api/v1/auth/oidc/{provider}/callback",
    tag = "auth",
    params(("provider" = String, Path, description = "Provider id from the listing")),
    request_body = OidcCallbackBody,
    responses(
        (status = OK, description = "Signed in (or pending MFA)", body = OkEnvelope<LoginDto>),
        (status = UNAUTHORIZED, description = "Uniform sign-in failure", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Provider not configured", body = ErrorEnvelope),
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<OidcCallbackBody>,
) -> Result<Json<OkEnvelope<LoginDto>>, ApiError> {
    let now = (state.clock)();
    let outcome = state.auth.oidc_login(&provider, &body.flow_id, &body.state, &body.code, &meta, now).await?;
    Ok(Json(OkEnvelope::new(LoginDto::from(outcome))))
}
