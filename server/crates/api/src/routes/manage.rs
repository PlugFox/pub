//! Package management: options, retraction, hard delete, transfer (decisions 06/19, S-06).
//!
//! Every route resolves the package first and authorizes against **its owning org**, which is
//! the only org that can be right — a package's name is instance-wide, so the caller cannot
//! name the org and the route must not let them try.
//!
//! The 404-vs-403 ladder is the read model's, extended to writes: a package the caller cannot
//! *read* answers the same 404 an unknown name does (S-04), and only a package they can see
//! but not change answers 403. That ordering matters — checking the role first would turn
//! `PATCH /api/v1/packages/acme_secret/options` into an existence oracle for another org's
//! private package.

use axum::Json;
use axum::extract::{Path, State};
use pub_core::authorize::{Action, Resource, authorize};
use pub_core::package::{Package, PackageOptions, Visibility};
use pub_core::{Error, SemVer};
use pub_registry::{HardDeleteRequest, RetractRequest, TransferRequest};

use crate::dto::{
    HardDeleteBody, HardDeletedDto, PackageOptionsBody, PackageOptionsDto, PackageTransferBody, PackageTransferredDto,
    VersionRetractedDto,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, StepUp};
use crate::routes::actor_meta;
use crate::routes::packages::{FORMAT, readable};
use crate::state::AppState;

/// Longest accepted hard-delete reason (S-22 metadata, not an essay field).
const MAX_REASON: usize = 500;

/// Resolves a package for a **write**: readable first (S-04), then the role gate.
async fn manageable(state: &AppState, auth: &AuthContext, name: &str, action: Action) -> Result<Package, ApiError> {
    // The read model's own resolution ladder, reused verbatim: visibility is decided before
    // the role, so an unreadable name is a 404 rather than a 403 that confirms it exists.
    let package = readable(state, &auth.actor, name).await?;
    authorize(&auth.actor, action, &Resource::Org(package.org_id))?;
    Ok(package)
}

/// Replaces a package's mutable options (Write+ in the owning org).
///
/// Not step-up gated: these flags are reversible and none of them destroys anything. Flipping
/// a package to private is the sharpest of them, and it *narrows* access rather than widening
/// it.
#[utoipa::path(
    patch,
    path = "/api/v1/packages/{name}/options",
    tag = "packages",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Package name")),
    request_body = PackageOptionsBody,
    responses(
        (status = OK, description = "Updated options", body = OkEnvelope<PackageOptionsDto>),
        (status = FORBIDDEN, description = "Below Write in the owning org", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown name, or one this principal may not read (S-04)", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Unknown visibility value", body = ErrorEnvelope),
    )
)]
pub async fn set_options(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(name): Path<String>,
    Json(body): Json<PackageOptionsBody>,
) -> Result<Json<OkEnvelope<PackageOptionsDto>>, ApiError> {
    let package = manageable(&state, &auth, &name, Action::PublishPackages).await?;

    // Unset field = keep current. `PackageOptions` is a *replace* payload on purpose (the four
    // flags are interdependent), so the partial patch is resolved here against the loaded row.
    let mut options = PackageOptions::from(&package);
    if let Some(visibility) = body.visibility {
        options.visibility = visibility.parse::<Visibility>()?;
    }
    if let Some(discontinued) = body.discontinued {
        options.discontinued = discontinued;
    }
    if let Some(replaced_by) = body.replaced_by {
        let trimmed = replaced_by.trim();
        options.replaced_by = if trimmed.is_empty() {
            None
        } else {
            // A replacement pointing at a name that could never exist is a dead link in every
            // client's warning text.
            pub_registry::validate_package_name(trimmed)
                .map_err(|err| Error::Invalid { message: format!("replaced_by: {err}") })?;
            Some(trimmed.to_owned())
        };
    }
    if let Some(unlisted) = body.unlisted {
        options.unlisted = unlisted;
    }

    let now = (state.clock)();
    let updated = state
        .registry
        .set_options(FORMAT, package.org_id, &package.name, &options, &actor_meta(&auth, &meta), now)
        .await?;
    Ok(Json(OkEnvelope::new(PackageOptionsDto::from(&updated))))
}

/// Retracts a version (Write+, step-up — S-06).
#[utoipa::path(
    post,
    path = "/api/v1/packages/{name}/versions/{version}/retract",
    tag = "packages",
    security(("bearer_auth" = [])),
    params(
        ("name" = String, Path, description = "Package name"),
        ("version" = String, Path, description = "Exact version"),
    ),
    responses(
        (status = OK, description = "Version retracted", body = OkEnvelope<VersionRetractedDto>),
        (status = FORBIDDEN, description = "Below Write, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown package or version", body = ErrorEnvelope),
    )
)]
pub async fn retract(
    State(state): State<AppState>,
    step_up: StepUp,
    meta: RequestMeta,
    path: Path<(String, String)>,
) -> Result<Json<OkEnvelope<VersionRetractedDto>>, ApiError> {
    set_retracted(state, step_up, meta, path, true).await
}

/// Restores a retracted version (Write+, step-up).
///
/// Allowed only inside `registry.unretract_window_days` (default 7 — decision 06). The flag is
/// a resolution signal that lockfiles and downstream caches have already reacted to, so
/// flipping it back weeks later would resurrect a version the ecosystem routed around; outside
/// the window the answer is a `409 conflict` that names the window.
#[utoipa::path(
    post,
    path = "/api/v1/packages/{name}/versions/{version}/unretract",
    tag = "packages",
    security(("bearer_auth" = [])),
    params(
        ("name" = String, Path, description = "Package name"),
        ("version" = String, Path, description = "Exact version"),
    ),
    responses(
        (status = OK, description = "Version restored", body = OkEnvelope<VersionRetractedDto>),
        (status = CONFLICT, description = "Not retracted, or past the restore window", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Below Write, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown package or version", body = ErrorEnvelope),
    )
)]
pub async fn unretract(
    State(state): State<AppState>,
    step_up: StepUp,
    meta: RequestMeta,
    path: Path<(String, String)>,
) -> Result<Json<OkEnvelope<VersionRetractedDto>>, ApiError> {
    set_retracted(state, step_up, meta, path, false).await
}

/// The shared body of retract and unretract.
async fn set_retracted(
    state: AppState,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Path((name, version)): Path<(String, String)>,
    retracted: bool,
) -> Result<Json<OkEnvelope<VersionRetractedDto>>, ApiError> {
    let package = manageable(&state, &auth, &name, Action::PublishPackages).await?;
    let parsed = parse_version(&name, &version)?;
    let now = (state.clock)();
    let updated = state
        .registry
        .set_retracted(
            RetractRequest {
                format: FORMAT,
                org_id: package.org_id,
                name: package.name.clone(),
                version: parsed,
                retracted,
                actor: actor_meta(&auth, &meta),
            },
            now,
        )
        .await?;
    Ok(Json(OkEnvelope::new(VersionRetractedDto {
        version: updated.version.to_string(),
        retracted: updated.is_retracted(),
        retracted_at: updated.retracted_at,
        restorable_until: updated.retracted_at.map(|at| at + state.registry.policy().unretract_window),
    })))
}

/// Hard-deletes a version (Admin+, step-up, and an explicit confirmation — decision 06).
///
/// Three gates rather than one because this is the only operation in the system that destroys
/// bytes somebody may already depend on: the role (Admin, not Write — publishing and erasing
/// are different authorities), a fresh second factor (S-06), and a `confirm` field naming
/// exactly `{name}@{version}`. The tombstone survives, so the number is burned forever (S-18),
/// and the blob is removed only when no live version still shares its content hash.
#[utoipa::path(
    delete,
    path = "/api/v1/packages/{name}/versions/{version}",
    tag = "packages",
    security(("bearer_auth" = [])),
    params(
        ("name" = String, Path, description = "Package name"),
        ("version" = String, Path, description = "Exact version"),
    ),
    request_body = HardDeleteBody,
    responses(
        (status = OK, description = "Version hard-deleted; the number stays burned", body = OkEnvelope<HardDeletedDto>),
        (status = FORBIDDEN, description = "Below Admin, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown package or version", body = ErrorEnvelope),
        (status = CONFLICT, description = "Already a tombstone", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "confirm does not name this version, or reason is missing", body = ErrorEnvelope),
    )
)]
pub async fn hard_delete(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Path((name, version)): Path<(String, String)>,
    Json(body): Json<HardDeleteBody>,
) -> Result<Json<OkEnvelope<HardDeletedDto>>, ApiError> {
    let package = manageable(&state, &auth, &name, Action::ManageMembers).await?;
    let parsed = parse_version(&name, &version)?;

    let expected = format!("{}@{}", package.name, parsed);
    if body.confirm != expected {
        return Err(Error::Invalid { message: format!("confirm must be exactly {expected:?}") }.into());
    }
    let reason = body.reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON {
        return Err(Error::Invalid { message: format!("reason must be 1..={MAX_REASON} characters") }.into());
    }

    let now = (state.clock)();
    let outcome = state
        .registry
        .hard_delete(
            HardDeleteRequest {
                format: FORMAT,
                org_id: package.org_id,
                name: package.name.clone(),
                version: parsed,
                reason: Some(reason.to_owned()),
                actor: actor_meta(&auth, &meta),
            },
            now,
        )
        .await?;
    Ok(Json(OkEnvelope::new(HardDeletedDto {
        version: outcome.version.version.to_string(),
        tombstone: outcome.version.tombstone,
        blob_removed: outcome.blob_removed,
    })))
}

/// Transfers a package to another org (Owner of **both**, step-up — S-06 ownership transfer).
///
/// Owner on both sides because the operation is two decisions: giving a name away, and taking
/// responsibility for one. The receiving org inherits the name claim, so its admins are the
/// ones a shadowing alarm will page from then on (S-17).
#[utoipa::path(
    post,
    path = "/api/v1/packages/{name}/transfer",
    tag = "packages",
    security(("bearer_auth" = [])),
    params(("name" = String, Path, description = "Package name")),
    request_body = PackageTransferBody,
    responses(
        (status = OK, description = "Package transferred", body = OkEnvelope<PackageTransferredDto>),
        (status = FORBIDDEN, description = "Not an Owner of both orgs, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown package or target org", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "confirm does not match, or the target is the current owner", body = ErrorEnvelope),
    )
)]
pub async fn transfer(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Path(name): Path<String>,
    Json(body): Json<PackageTransferBody>,
) -> Result<Json<OkEnvelope<PackageTransferredDto>>, ApiError> {
    let package = manageable(&state, &auth, &name, Action::ManageOrg).await?;
    if body.confirm != package.name {
        return Err(Error::Invalid { message: "confirm must repeat the package name".to_owned() }.into());
    }
    let target =
        state.repos.orgs.get_by_slug(&body.target_org).await?.filter(|org| !org.is_archived()).ok_or_else(|| {
            Error::NotFound { what: format!("organization {}", body.target_org.chars().take(64).collect::<String>()) }
        })?;
    // Owner on the receiving side too — through the chokepoint, like every other check.
    authorize(&auth.actor, Action::ManageOrg, &Resource::Org(target.id))?;

    let now = (state.clock)();
    let moved = state
        .registry
        .transfer(
            TransferRequest {
                format: FORMAT,
                from_org: package.org_id,
                to_org: target.id,
                name: package.name.clone(),
                actor: actor_meta(&auth, &meta),
            },
            now,
        )
        .await?;
    Ok(Json(OkEnvelope::new(PackageTransferredDto { name: moved.name, org: target.slug })))
}

/// Parses a version path segment; a malformed one is the same 404 an unknown one gets (S-04).
fn parse_version(name: &str, version: &str) -> Result<SemVer, ApiError> {
    SemVer::parse(version).map_err(|_| {
        Error::NotFound {
            what: format!(
                "version {} of package {}",
                version.chars().take(80).collect::<String>(),
                name.chars().take(80).collect::<String>()
            ),
        }
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_version_is_a_404_not_a_400() {
        let err = parse_version("acme_core", "not-a-version").unwrap_err();
        assert_eq!(err.0.code(), "not_found");
    }

    #[test]
    fn caller_supplied_segments_are_clipped_before_they_reach_a_message() {
        let err = parse_version(&"a".repeat(500), &"9".repeat(500)).unwrap_err();
        assert!(err.0.to_string().len() < 250, "unbounded reflection");
    }
}
