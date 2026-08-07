//! Org routes: create (creator becomes Owner — decision 19), the caller's own orgs, the public
//! org profile that anchors the web UI's org page, and the org danger zone (profile patch,
//! deletion).
//!
//! Member and invitation management lives in [`crate::routes::members`]; both modules share
//! [`org_for`], the one place that turns a slug plus an [`Action`] into an authorized org.

use axum::Json;
use axum::extract::{Path, State};
use pub_core::Error;
use pub_core::authorize::{Action, Resource, authorize};
use pub_core::org::{NewOrg, Org, OrgProfile, UpstreamPolicy};
use pub_core::search::{SearchQuery, SearchSort, SearchView};

use crate::dto::{
    ListDto, OrgCreateBody, OrgDeleteBody, OrgDeletedDto, OrgDto, OrgMembershipDto, OrgProfileDto, OrgUpdateBody,
    PackageSummaryDto, role_name,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, MaybeAuth, QueryParams, RequestMeta, StepUp};
use crate::routes::actor_meta;
use crate::routes::packages::PageParams;
use crate::state::AppState;

/// Longest allowed slug (URL segment budget).
const MAX_SLUG: usize = 64;

/// Longest allowed display name.
const MAX_NAME: usize = 128;

/// Longest allowed org description.
const MAX_DESCRIPTION: usize = 2000;

/// Resolves `slug` and authorizes `action` on it — the single door into org management.
///
/// The 404-vs-403 split here is deliberate and different from the package routes'. Org slugs
/// are **not** secret ([S-04.b](../../../../docs/security.md): any prober who knows one public
/// package name can already tell an existing base from a missing one), so an unknown slug is
/// 404 and an insufficient role on a real org is 403 — which is also the only answer that lets
/// a member understand they need a higher role rather than a different URL.
///
/// An **archived** org answers 404 on every management route: it has no members, serves
/// nothing, and exists only so its name claims stay burned. Nothing about it is manageable.
pub(crate) async fn org_for(state: &AppState, auth: &AuthContext, slug: &str, action: Action) -> Result<Org, ApiError> {
    let org = state.repos.orgs.get_by_slug(slug).await?.filter(|org| !org.is_archived()).ok_or_else(|| {
        Error::NotFound { what: format!("organization {}", slug.chars().take(64).collect::<String>()) }
    })?;
    authorize(&auth.actor, action, &Resource::Org(org.id))?;
    Ok(org)
}

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
    RequestMeta(meta): RequestMeta,
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
    // The instance's *current* default upstream policy (decision 09 runtime setting), not the
    // column default: an operator who blocked upstream by policy must not have to re-block
    // every org somebody creates afterwards.
    let upstream_policy = state.runtime.current().upstream.default_org_policy;
    let new = NewOrg { name, slug, description: String::new(), upstream_policy };
    // Through the service, not the repository: creating an org is an audited event (S-22), and
    // a handler that writes the row itself is a handler that can forget to say so.
    let org = state.orgs.create_org(new, auth.claims.sub, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(OrgDto::from(&org))))
}

/// Updates an org's profile: display name, description, upstream policy (Admin+).
///
/// The slug is absent by design — it is the org's virtual registry base (decision 01), and
/// renaming it would break every `PUB_HOSTED_URL`, lockfile `archive_url`, and CI token
/// configuration pointing at the old one.
#[utoipa::path(
    patch,
    path = "/api/v1/orgs/{slug}",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    request_body = OrgUpdateBody,
    responses(
        (status = OK, description = "Updated org", body = OkEnvelope<OrgDto>),
        (status = FORBIDDEN, description = "Below Admin in this org", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or archived org", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Invalid name, description, or policy", body = ErrorEnvelope),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(slug): Path<String>,
    Json(body): Json<OrgUpdateBody>,
) -> Result<Json<OkEnvelope<OrgDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    // Unset field = keep current: the repository takes a whole profile, and resolving the
    // partial patch here keeps read-modify-write out of two SQL dialects.
    let mut profile = OrgProfile::from(&org);
    if let Some(name) = body.name {
        let name = name.trim().to_owned();
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::Invalid { message: format!("org name must be 1..={MAX_NAME} characters") }.into());
        }
        profile.name = name;
    }
    if let Some(description) = body.description {
        if description.len() > MAX_DESCRIPTION {
            return Err(Error::Invalid {
                message: format!("org description must be at most {MAX_DESCRIPTION} characters"),
            }
            .into());
        }
        profile.description = description.trim().to_owned();
    }
    if let Some(policy) = body.upstream_policy {
        profile.upstream_policy = policy.parse::<UpstreamPolicy>()?;
    }

    let now = (state.clock)();
    let updated = state.orgs.update_profile(&org, profile, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(OrgDto::from(&updated))))
}

/// Deletes an org (Owner + step-up).
///
/// Refuses with `409 conflict` while the org owns packages. Forcing **archives** instead of
/// erasing: decision 06 and S-18 keep name claims and version rows forever and both hang off
/// the org row, so erasing it would un-burn a package name. An archived org loses its members,
/// invitations, and tokens, and every package it owns goes private + unlisted + discontinued.
/// Every removed member's sessions are revoked (S-09).
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{slug}",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    request_body = OrgDeleteBody,
    responses(
        (status = OK, description = "Org deleted or archived", body = OkEnvelope<OrgDeletedDto>),
        (status = CONFLICT, description = "The org still owns packages and force was not set", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an Owner, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or archived org", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "confirm does not match the slug", body = ErrorEnvelope),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Path(slug): Path<String>,
    Json(body): Json<OrgDeleteBody>,
) -> Result<Json<OkEnvelope<OrgDeletedDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageOrg).await?;
    if !body.confirm.eq_ignore_ascii_case(&org.slug) {
        return Err(Error::Invalid { message: "confirm must repeat the org slug".to_owned() }.into());
    }
    let now = (state.clock)();
    let outcome = state.orgs.delete_org(&org, body.force, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(OrgDeletedDto {
        archived: outcome.archived,
        packages: outcome.packages,
        members: outcome.members,
        sessions_revoked: outcome.sessions_revoked,
    })))
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

/// Public org profile plus the packages this caller may see.
///
/// Anonymous-reachable: org slugs are not secret ([S-04.b](../../../docs/security.md)) — any
/// prober who knows one public package name can already tell an existing org base from a
/// missing one — and an unknown slug answers the same 404 the pub protocol gives. What *is*
/// protected is the package list, which runs through the same [`SearchView`] as search, so a
/// non-member sees exactly the org's public, listed packages.
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{slug}",
    tag = "orgs",
    params(("slug" = String, Path, description = "Org slug"), PageParams),
    responses(
        (status = OK, description = "Org profile and its visible packages", body = OkEnvelope<OrgProfileDto>),
        (status = NOT_FOUND, description = "Unknown org", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn profile(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Path(slug): Path<String>,
    QueryParams(params): QueryParams<PageParams>,
) -> Result<Json<OkEnvelope<OrgProfileDto>>, ApiError> {
    // An archived org is gone as far as the product is concerned: no members, no listed
    // packages, nothing to render. Answering 404 keeps it indistinguishable from a slug nobody
    // ever took, which is also what the management routes do.
    let org = state.repos.orgs.get_by_slug(&slug).await?.filter(|org| !org.is_archived()).ok_or_else(|| {
        Error::NotFound { what: format!("organization {}", slug.chars().take(64).collect::<String>()) }
    })?;

    let mut query = SearchQuery::browse(SearchSort::Updated);
    query.orgs.any.push(org.slug.to_ascii_lowercase());
    let view = SearchView::for_actor(auth.actor());
    let page = state.repos.search.search(&query, &view, params.cursor.as_deref(), params.limit()).await?;

    // The caller's own role, when they hold one — the profile doubles as the entry point to the
    // org's management screens, and the UI needs to know whether to offer them.
    let role = auth.0.as_ref().map(|auth| auth.actor.role_in(org.id)).filter(|role| role.level() > 0).map(role_name);

    Ok(Json(OkEnvelope::new(OrgProfileDto {
        org: OrgDto::from(&org),
        role,
        packages: ListDto {
            items: page.items.iter().map(PackageSummaryDto::from).collect(),
            cursor: page.cursor,
            has_more: page.has_more,
        },
    })))
}
