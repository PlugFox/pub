//! Org members and invitations (decision 19, S-06, S-09).
//!
//! Two things every route here shares, and both are enforced one layer down rather than per
//! handler:
//!
//! - **S-09.** A role change or a removal revokes the affected user's sessions. The handlers
//!   never touch [`OrgRepo`](pub_core::traits::OrgRepo) directly; they call
//!   [`OrgService`](pub_admin::OrgService), which pairs every membership mutation with its
//!   [`AuthorityChange`](pub_admin::AuthorityChange) classification.
//! - **S-06 step-up.** Sending an invitation, and granting or changing a role at **Write level
//!   or above**, demand a fresh second factor. Grants *below* Write do not: S-06's list is
//!   about escalation, and forcing a re-auth to add a read-only teammate trains people to
//!   treat the prompt as noise.
//!
//! The **role-grant ceiling** (decision 19 addendum, D39) is likewise enforced one layer down:
//! every mutation passes the caller's own level (`auth.actor.role_in`) to the service, which
//! refuses a non-Owner touching a level at or above their own with a plain `403 forbidden`
//! naming the role. The handlers carry no ceiling logic of their own.
//!
//! The ≥1-Owner invariant is not checked here at all — it is transactional in the repository
//! and surfaces as `409 last_owner`, which is the only place it can be race-free.

use axum::Json;
use axum::extract::{Path, State};
use pub_core::authorize::Action;
use pub_core::org::Org;
use pub_core::{Error, InvitationId, RoleLevel, UserId};

use crate::dto::{
    InvitationAcceptBody, InvitationCreateBody, InvitationCreatedDto, InvitationDto, ListDto, MemberAddBody, MemberDto,
    MemberRoleBody, MembershipChangedDto, OrgDto, parse_role, role_name,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, require_step_up};
use crate::routes::actor_meta;
use crate::routes::orgs::org_for;
use crate::state::AppState;

/// Most invitation rows one response carries (see [`list_invitations`]).
const MAX_INVITATIONS: usize = 200;

/// Whether granting `role` needs a fresh second factor (S-06: "granting or changing member
/// roles at Write level or above").
fn needs_step_up(role: RoleLevel) -> bool {
    role.satisfies(RoleLevel::WRITE)
}

/// The org's members (Admin+).
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{slug}/members",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    responses(
        (status = OK, description = "Members, highest role first", body = OkEnvelope<ListDto<MemberDto>>),
        (status = FORBIDDEN, description = "Below Admin in this org", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or archived org", body = ErrorEnvelope),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(slug): Path<String>,
) -> Result<Json<OkEnvelope<ListDto<MemberDto>>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    let rows = state.orgs.list_members(org.id).await?;
    let items = rows
        .iter()
        .map(|(member, user)| MemberDto {
            user_id: member.user_id.to_string(),
            display_name: user.as_ref().map(|u| u.display_name.clone()).unwrap_or_else(|| "unknown".to_owned()),
            email: user.as_ref().and_then(|u| u.email.clone()),
            role: role_name(member.role),
            created_at: member.created_at,
            updated_at: member.updated_at,
        })
        .collect();
    Ok(Json(OkEnvelope::new(ListDto::single_page(items))))
}

/// Adds an existing account as a member (Admin+; step-up for Write and above; the granted
/// level must sit below the caller's own unless the caller is an Owner — D39).
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{slug}/members",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    request_body = MemberAddBody,
    responses(
        (status = OK, description = "Member added", body = OkEnvelope<MemberDto>),
        (status = FORBIDDEN, description = "Below Admin, a grant at or above the caller's ceiling (D39), or step_up_required for a Write+ grant", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown org, or no verified account with that email", body = ErrorEnvelope),
        (status = CONFLICT, description = "Already a member", body = ErrorEnvelope),
    )
)]
pub async fn add(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(slug): Path<String>,
    Json(body): Json<MemberAddBody>,
) -> Result<Json<OkEnvelope<MemberDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    let role = body.role.as_deref().map(parse_role).transpose()?.unwrap_or(RoleLevel::READ);
    // Decided after the body is parsed, because the gate depends on the level being granted.
    if needs_step_up(role) {
        require_step_up(&state, &auth).await?;
    }
    let now = (state.clock)();
    let acting_role = auth.actor.role_in(org.id);
    let member = state.orgs.add_member(&org, &body.email, role, acting_role, &actor_meta(&auth, &meta), now).await?;
    let user = state.repos.users.get(member.user_id).await?;
    Ok(Json(OkEnvelope::new(MemberDto {
        user_id: member.user_id.to_string(),
        display_name: user.as_ref().map(|u| u.display_name.clone()).unwrap_or_else(|| "unknown".to_owned()),
        email: user.and_then(|u| u.email),
        role: role_name(member.role),
        created_at: member.created_at,
        updated_at: member.updated_at,
    })))
}

/// Changes a member's role (Admin+; step-up when either the old or the new level is Write+;
/// both the target's current level and the new one must sit below a non-Owner caller's own —
/// D39).
///
/// The gate covers **demotions from** Write+ as well as promotions **to** it: taking somebody's
/// publish rights away is exactly as consequential as granting them, and a stolen stale admin
/// session must not be able to lock the real owners out.
#[utoipa::path(
    patch,
    path = "/api/v1/orgs/{slug}/members/{user_id}",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(
        ("slug" = String, Path, description = "Org slug"),
        ("user_id" = String, Path, description = "Member's user id"),
    ),
    request_body = MemberRoleBody,
    responses(
        (status = OK, description = "Role changed; the member's sessions were revoked (S-09) along with any org tokens the new level can no longer mint (D37)", body = OkEnvelope<MembershipChangedDto>),
        (status = CONFLICT, description = "last_owner — the org would be left without an Owner", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Below Admin, a level at or above the caller's ceiling (D39), or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown org or membership", body = ErrorEnvelope),
    )
)]
pub async fn update_role(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path((slug, user_id)): Path<(String, String)>,
    Json(body): Json<MemberRoleBody>,
) -> Result<Json<OkEnvelope<MembershipChangedDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    let user = parse_user(&user_id)?;
    let role = parse_role(&body.role)?;
    let current = state
        .repos
        .orgs
        .get_member(org.id, user)
        .await?
        .ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {slug}") })?;
    if needs_step_up(role) || needs_step_up(current.role) {
        require_step_up(&state, &auth).await?;
    }
    let now = (state.clock)();
    let acting_role = auth.actor.role_in(org.id);
    let (member, revoked) =
        state.orgs.change_role(&org, user, role, acting_role, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(MembershipChangedDto {
        role: Some(role_name(member.role)),
        sessions_revoked: revoked.sessions,
        tokens_revoked: revoked.tokens,
    })))
}

/// Removes a member (Admin+; the target's level must sit below a non-Owner caller's own —
/// D39). Their sessions are revoked (S-09) along with every CLI token they held in this org
/// (D37).
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{slug}/members/{user_id}",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(
        ("slug" = String, Path, description = "Org slug"),
        ("user_id" = String, Path, description = "Member's user id"),
    ),
    responses(
        (status = OK, description = "Member removed; their sessions (S-09) and their CLI tokens in this org (D37) were revoked", body = OkEnvelope<MembershipChangedDto>),
        (status = CONFLICT, description = "last_owner — the org would be left without an Owner", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Below Admin, or a target at or above the caller's ceiling (D39)", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown org or membership", body = ErrorEnvelope),
    )
)]
pub async fn remove(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path((slug, user_id)): Path<(String, String)>,
) -> Result<Json<OkEnvelope<MembershipChangedDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    let user = parse_user(&user_id)?;
    let now = (state.clock)();
    let acting_role = auth.actor.role_in(org.id);
    let revoked = state.orgs.remove_member(&org, user, acting_role, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(MembershipChangedDto {
        role: None,
        sessions_revoked: revoked.sessions,
        tokens_revoked: revoked.tokens,
    })))
}

/// The org's invitations, newest first (Admin+).
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{slug}/invitations",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    responses(
        (status = OK, description = "Invitations in every lifecycle state", body = OkEnvelope<ListDto<InvitationDto>>),
        (status = FORBIDDEN, description = "Below Admin in this org", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or archived org", body = ErrorEnvelope),
    )
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(slug): Path<String>,
) -> Result<Json<OkEnvelope<ListDto<InvitationDto>>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    let now = (state.clock)();
    let all = state.orgs.list_invitations(org.id).await?;
    // Bounded, and honest about it. Invitations accumulate without anybody deleting them — the
    // S-24 budget alone allows 20 a day forever — so an unbounded response here grows without
    // limit on an authenticated route. The rows are newest-first, which is the order the screen
    // wants, and `has_more` says the tail exists; a cursor lands when this screen gains filters.
    let has_more = all.len() > MAX_INVITATIONS;
    let items =
        all.iter().take(MAX_INVITATIONS).map(|inv| InvitationDto::from_invitation(inv, now)).collect::<Vec<_>>();
    Ok(Json(OkEnvelope::new(ListDto { items, cursor: None, has_more })))
}

/// Sends an invitation (Admin+ and **always** step-up gated — S-06).
///
/// Unconditionally gated, unlike a direct member add: an invitation reaches an address that
/// may not have an account yet, so a stolen admin session could otherwise invite an
/// attacker-controlled mailbox and escalate around the CLI-token publish boundary.
///
/// Budgeted twice (S-24.h): per org and per actor **within** that org, both runtime-changeable
/// and both exact database counts over a genuinely rolling 24 hours rather than KV buckets —
/// this is the one mutation whose cost is mail delivered to a third party.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{slug}/invitations",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Org slug")),
    request_body = InvitationCreateBody,
    responses(
        (status = OK, description = "Invitation created; the token is shown once", body = OkEnvelope<InvitationCreatedDto>),
        (status = FORBIDDEN, description = "Below Admin, a role at or above the caller's ceiling (D39), step_up_required, or a domain the S-31 allowlist rejects", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "The org's or the actor's daily invitation budget is spent (S-24.h)", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or archived org", body = ErrorEnvelope),
    )
)]
pub async fn invite(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path(slug): Path<String>,
    Json(body): Json<InvitationCreateBody>,
) -> Result<Json<OkEnvelope<InvitationCreatedDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    require_step_up(&state, &auth).await?;
    let role = body.role.as_deref().map(parse_role).transpose()?.unwrap_or(RoleLevel::READ);
    let now = (state.clock)();
    let acting_role = auth.actor.role_in(org.id);
    let created = state.orgs.invite(&org, &body.email, role, acting_role, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(InvitationCreatedDto {
        invitation: InvitationDto::from_invitation(&created.invitation, now),
        token: created.token,
    })))
}

/// Revokes a pending invitation (Admin+, step-up — the same gate that created it).
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{slug}/invitations/{id}",
    tag = "orgs",
    security(("bearer_auth" = [])),
    params(
        ("slug" = String, Path, description = "Org slug"),
        ("id" = String, Path, description = "Invitation id"),
    ),
    responses(
        (status = OK, description = "Invitation revoked", body = OkEnvelope<InvitationDto>),
        (status = CONFLICT, description = "Already accepted or revoked", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Below Admin, or step_up_required", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown org or invitation", body = ErrorEnvelope),
    )
)]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Path((slug, id)): Path<(String, String)>,
) -> Result<Json<OkEnvelope<InvitationDto>>, ApiError> {
    let org = org_for(&state, &auth, &slug, Action::ManageMembers).await?;
    require_step_up(&state, &auth).await?;
    // A malformed id can only be a nonexistent one — same 404, no shape oracle (S-04).
    let id: InvitationId = id.parse().map_err(|_| Error::NotFound { what: format!("invitation {id}") })?;
    let now = (state.clock)();
    let invitation = state.orgs.revoke_invitation(&org, id, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(InvitationDto::from_invitation(&invitation, now))))
}

/// Accepts an invitation as the signed-in user.
///
/// Not org-scoped and not step-up gated: the caller is the *invitee*, the token is the
/// authorization, and the repository additionally binds acceptance to the invited address in
/// verified state. Accepting is a pure grant, so it does **not** revoke the caller's sessions
/// (S-09.a) — logging somebody out of every device the moment they join would be a cost with
/// no security benefit.
#[utoipa::path(
    post,
    path = "/api/v1/invitations/accept",
    tag = "orgs",
    security(("bearer_auth" = [])),
    request_body = InvitationAcceptBody,
    responses(
        (status = OK, description = "Joined the org", body = OkEnvelope<OrgDto>),
        (status = FORBIDDEN, description = "The invitation is bound to a different verified email", body = ErrorEnvelope),
        (status = CONFLICT, description = "Already accepted or revoked", body = ErrorEnvelope),
        (status = GONE, description = "The invitation expired", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown token", body = ErrorEnvelope),
    )
)]
pub async fn accept(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<InvitationAcceptBody>,
) -> Result<Json<OkEnvelope<OrgDto>>, ApiError> {
    let now = (state.clock)();
    let invitation = state.orgs.accept_invitation(&body.token, auth.claims.sub, &actor_meta(&auth, &meta), now).await?;
    let org: Org = state
        .repos
        .orgs
        .get(invitation.org_id)
        .await?
        .ok_or_else(|| Error::NotFound { what: "organization".to_owned() })?;
    Ok(Json(OkEnvelope::new(OrgDto::from(&org))))
}

/// Parses a member's user id. A malformed id is `NotFound`, like a nonexistent one (S-04).
fn parse_user(raw: &str) -> Result<UserId, ApiError> {
    raw.parse().map_err(|_| Error::NotFound { what: format!("membership of {raw}") }.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s06_step_up_covers_write_and_above_only() {
        assert!(!needs_step_up(RoleLevel::READ));
        assert!(needs_step_up(RoleLevel::WRITE));
        assert!(needs_step_up(RoleLevel::ADMIN));
        assert!(needs_step_up(RoleLevel::OWNER));
        // A future intermediate role above Write inherits the gate rather than slipping under
        // it: the check is the ladder, not an enumeration.
        assert!(needs_step_up(RoleLevel::new(150)));
    }

    #[test]
    fn a_malformed_member_id_is_a_404_not_a_400() {
        let err = parse_user("not-a-uuid").unwrap_err();
        assert_eq!(err.0.code(), "not_found");
    }
}
