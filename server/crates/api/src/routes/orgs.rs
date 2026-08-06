//! Minimal org routes: create (creator becomes Owner — decision 19) and list. Enough to
//! bind CLI tokens to an org; the full org surface arrives with its roadmap step.

use axum::Json;
use axum::extract::State;
use pub_core::Error;
use pub_core::org::NewOrg;

use crate::dto::{ListDto, OrgCreateBody, OrgDto, OrgMembershipDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::AuthContext;
use crate::state::AppState;

/// Longest allowed slug (URL segment budget).
const MAX_SLUG: usize = 64;

/// Longest allowed display name.
const MAX_NAME: usize = 128;

/// Creates an org; the caller becomes its Owner in the same transaction (decision 19).
#[utoipa::path(
    post,
    path = "/api/v1/orgs",
    tag = "orgs",
    security(("bearer_auth" = [])),
    request_body = OrgCreateBody,
    responses(
        (status = OK, description = "Created org", body = OkEnvelope<OrgDto>),
        (status = CONFLICT, description = "Slug already taken", body = ErrorEnvelope),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<OrgCreateBody>,
) -> Result<Json<OkEnvelope<OrgDto>>, ApiError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(Error::Invalid { message: format!("org name must be 1..={MAX_NAME} characters") }.into());
    }
    let slug = body.slug.trim().to_ascii_lowercase();
    let slug_ok = slug.len() >= 2
        && slug.len() <= MAX_SLUG
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-');
    if !slug_ok {
        return Err(Error::Invalid {
            message: format!("org slug must be 2..={MAX_SLUG} chars of [a-z0-9-], not edged with '-'"),
        }
        .into());
    }

    let now = (state.clock)();
    let org = state.repos.orgs.create(NewOrg { name, slug }, auth.claims.sub, now).await?;
    Ok(Json(OkEnvelope::new(OrgDto::from(&org))))
}

/// Lists the caller's orgs with their role names.
#[utoipa::path(
    get,
    path = "/api/v1/orgs",
    tag = "orgs",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "The caller's orgs", body = OkEnvelope<ListDto<OrgMembershipDto>>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OkEnvelope<ListDto<OrgMembershipDto>>>, ApiError> {
    let memberships = state.repos.orgs.list_for_user(auth.claims.sub).await?;
    let items = memberships.iter().map(OrgMembershipDto::from).collect();
    Ok(Json(OkEnvelope::new(ListDto::single_page(items))))
}
