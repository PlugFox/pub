//! TOTP second factor + step-up routes (S-05, S-06): enroll, confirm, disable, the
//! login-time MFA step, and the "sudo mode" refresh.

use axum::Json;
use axum::extract::State;

use crate::dto::{
    LoginDto, MfaVerifyBody, RevokedDto, StepUpBody, StepUpDto, TotpConfirmBody, TotpConfirmedDto, TotpEnrollDto,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, StepUp};
use crate::state::AppState;

/// Starts a TOTP enrollment: returns the base32 seed and `otpauth://` URL. Nothing is
/// active until `confirm` proves the authenticator works (S-05).
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/enroll",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Provisioning material (short-lived, confirm to activate)", body = OkEnvelope<TotpEnrollDto>),
        (status = CONFLICT, description = "TOTP already enrolled", body = ErrorEnvelope),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn totp_enroll(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OkEnvelope<TotpEnrollDto>>, ApiError> {
    let now = (state.clock)();
    let (secret, otpauth_url) = state.auth.enroll_totp(auth.claims.sub, now).await?;
    Ok(Json(OkEnvelope::new(TotpEnrollDto { secret, otpauth_url })))
}

/// Activates the pending enrollment with a live code and returns the ten single-use
/// recovery codes — the only time they are ever visible (S-05).
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/confirm",
    tag = "auth",
    security(("bearer_auth" = [])),
    request_body = TotpConfirmBody,
    responses(
        (status = OK, description = "Second factor active; recovery codes shown once", body = OkEnvelope<TotpConfirmedDto>),
        (status = UNAUTHORIZED, description = "Wrong code (uniform)", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "No enrollment in progress", body = ErrorEnvelope),
    )
)]
pub async fn totp_confirm(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<TotpConfirmBody>,
) -> Result<Json<OkEnvelope<TotpConfirmedDto>>, ApiError> {
    let now = (state.clock)();
    let recovery_codes = state.auth.confirm_totp(auth.claims.sub, &body.code, &meta, now).await?;
    Ok(Json(OkEnvelope::new(TotpConfirmedDto { recovery_codes })))
}

/// Disables the second factor (TOTP + remaining recovery codes). **Step-up required**
/// (S-06): a stolen stale session must not be able to strip the account's MFA.
#[utoipa::path(
    delete,
    path = "/api/v1/auth/totp",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Second factor removed", body = OkEnvelope<RevokedDto>),
        (status = FORBIDDEN, description = "step_up_required — verify a fresh second factor first", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "No TOTP enrolled", body = ErrorEnvelope),
    )
)]
pub async fn totp_disable(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
) -> Result<Json<OkEnvelope<RevokedDto>>, ApiError> {
    let now = (state.clock)();
    state.auth.disable_totp(auth.claims.sub, &meta, now).await?;
    Ok(Json(OkEnvelope::new(RevokedDto { revoked: 1 })))
}

/// Completes a pending-MFA login (S-05): the `mfa_token` from the first-factor response
/// plus exactly one of a TOTP code or a recovery code. ≤5 failures per pending attempt,
/// then exponential backoff (429 + `Retry-After`).
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/verify",
    tag = "auth",
    request_body = MfaVerifyBody,
    responses(
        (status = OK, description = "Signed in", body = OkEnvelope<LoginDto>),
        (status = UNAUTHORIZED, description = "invalid_code — uniform for every failure", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "MFA backoff engaged; Retry-After set", body = ErrorEnvelope),
    )
)]
pub async fn totp_verify(
    State(state): State<AppState>,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Json<OkEnvelope<LoginDto>>, ApiError> {
    let now = (state.clock)();
    let login =
        state.auth.verify_mfa(&body.mfa_token, body.code.as_deref(), body.recovery_code.as_deref(), &meta, now).await?;
    Ok(Json(OkEnvelope::new(LoginDto::from(login))))
}

/// Marks the current session step-up-fresh after a live second-factor check (S-06 "sudo
/// mode"). Accounts without TOTP re-authenticate by signing in again instead.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up",
    tag = "auth",
    security(("bearer_auth" = [])),
    request_body = StepUpBody,
    responses(
        (status = OK, description = "Session is step-up-fresh until valid_until", body = OkEnvelope<StepUpDto>),
        (status = UNAUTHORIZED, description = "invalid_code — uniform for every failure", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "No second factor enrolled", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "MFA backoff engaged; Retry-After set", body = ErrorEnvelope),
    )
)]
pub async fn step_up(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<StepUpBody>,
) -> Result<Json<OkEnvelope<StepUpDto>>, ApiError> {
    let now = (state.clock)();
    let valid_until = state
        .auth
        .step_up(auth.claims.sub, auth.claims.sid, body.code.as_deref(), body.recovery_code.as_deref(), &meta, now)
        .await?;
    Ok(Json(OkEnvelope::new(StepUpDto { valid_until })))
}
