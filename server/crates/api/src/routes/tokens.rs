//! CLI/API token routes (S-13): mint (show-once secret), list (hints only), revoke.

use axum::Json;
use axum::extract::{Path, State};
use pub_auth::flows::TokenRequest;
use pub_core::token::TokenScope;
use pub_core::{Error, OrgId, TokenId};

use crate::dto::{ListDto, RevokedDto, TokenCreateBody, TokenCreatedDto, TokenDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, require_step_up};
use crate::state::AppState;

/// Mints a CLI/API token. The secret appears in this response and never again (S-13
/// show-once); at rest only its SHA-256 and a first-8-chars hint survive.
///
/// Two independent step-up gates, both decided here because both depend on the parsed body:
/// minting `publish`/`admin` scopes (S-06 — a stolen stale web session must not escalate
/// around the CLI-token publish boundary), and minting a **non-expiring** token at any scope
/// ([S-06.d](../../../../docs/security.md#1-authentication) — the lifetime is what is
/// dangerous there, not the scope). An expiring `read`/`retract` mint stays ungated.
#[utoipa::path(
    post,
    path = "/api/v1/tokens",
    tag = "tokens",
    security(("bearer_auth" = [])),
    request_body = TokenCreateBody,
    responses(
        (status = OK, description = "Minted token — the secret is shown once", body = OkEnvelope<TokenCreatedDto>),
        (status = BAD_REQUEST, description = "Malformed pattern, expires_days outside 1..=3650, or a non-expiring token with a write scope", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Org role below the requested scopes, or step_up_required for publish/admin scopes and for a non-expiring token", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or invisible org", body = ErrorEnvelope),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<TokenCreateBody>,
) -> Result<Json<OkEnvelope<TokenCreatedDto>>, ApiError> {
    let org: OrgId = body.org_id.parse().map_err(|_| Error::Invalid { message: "org_id must be a UUID".into() })?;
    let scopes = body.scopes.iter().map(|scope| scope.parse::<TokenScope>()).collect::<Result<Vec<_>, _>>()?;
    let escalating = scopes.iter().any(|scope| matches!(scope, TokenScope::Publish | TokenScope::Admin));
    // Absent and explicit `null` are the same request — "never" — and both are gated. That is
    // what keeps decision 33's wire-contract change loud: a client written against the old
    // meaning ("null = the 90-day default") meets this gate instead of an eternal credential.
    let non_expiring = body.expires_days.is_none();
    if escalating || non_expiring {
        require_step_up(&state, &auth).await?;
    }
    let now = (state.clock)();
    let request = TokenRequest {
        label: body.label,
        scopes,
        package_patterns: body.package_patterns.unwrap_or_default(),
        expires_days: body.expires_days,
    };
    let (token, secret) = state.auth.mint_token(auth.claims.sub, org, request, &meta, now).await?;
    Ok(Json(OkEnvelope::new(TokenCreatedDto { secret, token: TokenDto::from(&token) })))
}

/// Lists the caller's tokens: hints, scopes, last-used, expiry — never secrets (S-13).
#[utoipa::path(
    get,
    path = "/api/v1/tokens",
    tag = "tokens",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "The caller's tokens", body = OkEnvelope<ListDto<TokenDto>>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OkEnvelope<ListDto<TokenDto>>>, ApiError> {
    let tokens = state.auth.list_tokens(auth.claims.sub).await?;
    let items = tokens.iter().map(TokenDto::from).collect();
    Ok(Json(OkEnvelope::new(ListDto::single_page(items))))
}

/// Revokes one of the caller's tokens — effective everywhere within ≤ 60 s (S-13).
/// Foreign and unknown ids are both 404 (S-04).
#[utoipa::path(
    delete,
    path = "/api/v1/tokens/{id}",
    tag = "tokens",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Token id to revoke")),
    responses(
        (status = OK, description = "Token revoked", body = OkEnvelope<RevokedDto>),
        (status = NOT_FOUND, description = "Unknown or foreign token id", body = ErrorEnvelope),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(id): Path<String>,
) -> Result<Json<OkEnvelope<RevokedDto>>, ApiError> {
    let id: TokenId = id.parse().map_err(|_| Error::NotFound { what: format!("token {id}") })?;
    let now = (state.clock)();
    state.auth.revoke_token(auth.claims.sub, id, &meta, now).await?;
    Ok(Json(OkEnvelope::new(RevokedDto { revoked: 1 })))
}
