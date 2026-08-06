//! Auth routes: OTP request/verify, refresh, logout (S-03, S-04, S-08, S-09).

use axum::Json;
use axum::extract::State;

use crate::dto::{LoginDto, OtpRequestBody, OtpVerifyBody, PendingDto, RefreshBody, RevokedDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta};
use crate::state::AppState;

/// Requests an email OTP.
///
/// The response is uniform whether the email is known, unknown, or rejected by instance
/// policy (S-04/S-31): always `200 {pending_id}` — rejected addresses simply never receive
/// mail, and only the audit log knows why. Rate limits: 5/h/email + 20/h/IP → 429 with
/// `Retry-After` (S-24).
#[utoipa::path(
    post,
    path = "/api/v1/auth/otp/request",
    tag = "auth",
    request_body = OtpRequestBody,
    responses(
        (status = OK, description = "Pending-auth handle (uniform for every outcome)", body = OkEnvelope<PendingDto>),
        (status = TOO_MANY_REQUESTS, description = "Rate limited; Retry-After set", body = ErrorEnvelope),
    )
)]
pub async fn otp_request(
    State(state): State<AppState>,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<OtpRequestBody>,
) -> Result<Json<OkEnvelope<PendingDto>>, ApiError> {
    let now = (state.clock)();
    let pending_id = state.auth.request_otp(&body.email, &meta, now).await?;
    Ok(Json(OkEnvelope::new(PendingDto { pending_id })))
}

/// Redeems an OTP for a session (access + refresh pair) — or, when the account has an
/// active TOTP second factor, for a pending-MFA handle (`mfa_required = true`, S-05).
///
/// Every failure — wrong code, expired record, unknown pending id — answers with the same
/// `invalid_code` 401 (S-03/S-04); a code survives at most 5 wrong attempts.
#[utoipa::path(
    post,
    path = "/api/v1/auth/otp/verify",
    tag = "auth",
    request_body = OtpVerifyBody,
    responses(
        (status = OK, description = "Signed in, or pending MFA", body = OkEnvelope<LoginDto>),
        (status = UNAUTHORIZED, description = "invalid_code — uniform for every failure", body = ErrorEnvelope),
    )
)]
pub async fn otp_verify(
    State(state): State<AppState>,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<OtpVerifyBody>,
) -> Result<Json<OkEnvelope<LoginDto>>, ApiError> {
    let now = (state.clock)();
    let login = state.auth.verify_otp(&body.pending_id, &body.email, &body.code, &meta, now).await?;
    Ok(Json(OkEnvelope::new(LoginDto::from(login))))
}

/// Rotates a refresh token into a fresh pair (S-08).
///
/// Reuse of a rotated-out token answers 401 with the distinct `refresh_reused` code — the
/// whole session family is already revoked at that point.
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshBody,
    responses(
        (status = OK, description = "Rotated pair", body = OkEnvelope<LoginDto>),
        (status = UNAUTHORIZED, description = "unauthorized or refresh_reused", body = ErrorEnvelope),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<RefreshBody>,
) -> Result<Json<OkEnvelope<LoginDto>>, ApiError> {
    let now = (state.clock)();
    let login = state.auth.refresh(&body.refresh_token, &meta, now).await?;
    Ok(Json(OkEnvelope::new(LoginDto::from(login))))
}

/// Revokes the current session (S-09): DB truth plus immediate KV blocklist.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Session revoked", body = OkEnvelope<RevokedDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
) -> Result<Json<OkEnvelope<RevokedDto>>, ApiError> {
    let now = (state.clock)();
    state.auth.logout(auth.claims.sub, auth.claims.sid, &meta, now).await?;
    Ok(Json(OkEnvelope::new(RevokedDto { revoked: 1 })))
}
