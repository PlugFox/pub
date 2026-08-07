//! The single `authorize()` chokepoint (decision 19).
//!
//! Every org-role check in the system flows through [`authorize`] — handlers and services
//! never compare role levels inline (docs/rules/rust.md). The check is the cumulative ladder:
//! the actor's level in the resource's org must satisfy (`>=`) the action's required level.
//!
//! # Scope of this module
//!
//! - **Role ladder only.** Token scopes (`read`/`publish`/`retract`/`admin`) are the second,
//!   non-linear permission plane; scope checks join this chokepoint when the token auth flow
//!   lands. The `Action` set will grow with those flows — adding variants is additive.
//! - **Instance administration is a second, orthogonal plane.** [`Action::AdministerInstance`]
//!   on [`Resource::Instance`] is decided by [`ActorContext::is_instance_admin`], a flag on the
//!   *user row* — not by any org role, and not by a JWT claim. An org Owner is not an instance
//!   admin and an instance admin holds no org role they were not granted: the two ladders never
//!   imply each other, so "owner of one org" can never become "reads every org's private
//!   inventory". Deliberately resolved from the durable row on the admin routes rather than
//!   carried in the access token ([S-07](../../../docs/security.md) keeps claims to `sub`/`sid`/
//!   org levels/timestamps), which also makes a demotion effective immediately instead of
//!   within one access TTL.
//! - **Visibility is decided elsewhere.** Public-package reads by anonymous principals
//!   (decision 05) are resolution policy, applied before `authorize` is ever consulted;
//!   `authorize` answers questions about org-scoped capabilities.
//! - **Object-level invariants are decided in repositories.** In particular, **last-Owner
//!   protection**: `authorize` may well grant an Owner the `ManageMembers`/`ManageOrg`
//!   capability, and the concrete mutation can *still* fail with
//!   [`Error::LastOwner`](crate::Error::LastOwner) — `OrgRepo::update_member_role` and
//!   `OrgRepo::remove_member` enforce the ≥1-Owner invariant transactionally, because only
//!   the repository can check it race-free against current data. Both layers are required:
//!   `authorize` gates *who may try*, the repository guards *what may happen*.
//!
//! Denials are [`Error::Forbidden`](crate::Error::Forbidden); the API layer maps that to the
//! 403-vs-404 ladder (decision 05 / S-04) per route — this module never decides HTTP shapes.

use std::collections::BTreeMap;

use crate::{Error, OrgId, Result, RoleLevel, UserId};

/// The acting principal, as reconstructed from JWT claims (web plane) or a token row
/// (CLI plane) by the auth extractors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActorContext {
    /// Authenticated user, if any; `None` = anonymous.
    pub user_id: Option<UserId>,
    /// The actor's role level per org (JWT `{org_id: level}` claims — decision 03).
    pub org_roles: BTreeMap<OrgId, RoleLevel>,
    /// Whether the acting user carries the instance-admin flag on their user row.
    ///
    /// Defaults to `false` and is set **only** where the durable row was read: the admin
    /// extractor. Nothing derives it from an org role, and nothing reads it from a token.
    pub is_instance_admin: bool,
}

impl ActorContext {
    /// An unauthenticated actor: no user, no roles.
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// An authenticated actor with the given per-org role levels.
    pub fn user(user_id: UserId, org_roles: BTreeMap<OrgId, RoleLevel>) -> Self {
        Self { user_id: Some(user_id), org_roles, is_instance_admin: false }
    }

    /// The same actor, marked (or unmarked) as an instance admin.
    #[must_use]
    pub fn with_instance_admin(mut self, is_instance_admin: bool) -> Self {
        self.is_instance_admin = is_instance_admin;
        self
    }

    /// The actor's level in `org`; [`RoleLevel::NONE`] when not a member.
    pub fn role_in(&self, org: OrgId) -> RoleLevel {
        self.org_roles.get(&org).copied().unwrap_or(RoleLevel::NONE)
    }
}

/// Org-scoped action classes, each mapping to the minimum role level that may perform them
/// (decision 19 ladder).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Resolve and download the org's packages (incl. private ones) — requires Read (50).
    ReadPackages,
    /// Publish versions and manage own packages — requires Write (100).
    PublishPackages,
    /// Manage members, invitations, tokens, and package settings — requires Admin (200).
    ManageMembers,
    /// Org lifecycle and danger zone (rename, delete, ownership transfer) — requires
    /// Owner (250).
    ManageOrg,
    /// Instance administration: runtime settings, user/org moderation, the audit viewer,
    /// instance statistics, manual job runs. Not an org role — see the module docs.
    AdministerInstance,
}

impl Action {
    /// The minimum org role level this action demands, or `None` for actions that are not
    /// decided by the org ladder at all ([`Action::AdministerInstance`]).
    pub const fn required_level(self) -> Option<RoleLevel> {
        match self {
            Self::ReadPackages => Some(RoleLevel::READ),
            Self::PublishPackages => Some(RoleLevel::WRITE),
            Self::ManageMembers => Some(RoleLevel::ADMIN),
            Self::ManageOrg => Some(RoleLevel::OWNER),
            Self::AdministerInstance => None,
        }
    }
}

/// What the action targets.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    /// An organization (and, transitively, everything it owns).
    Org(OrgId),
    /// The instance itself: runtime settings, users, orgs, audit, jobs.
    Instance,
}

/// Grants or denies `action` on `resource` for `actor` — the single chokepoint.
///
/// Returns `Ok(())` when the actor's role level in the resource's org satisfies the action's
/// required level, [`Error::Forbidden`](crate::Error::Forbidden) otherwise. Anonymous actors
/// hold no roles and are always denied here (their public-read path never reaches this
/// function — see the module docs).
///
/// Action and resource must **agree**: an org action against [`Resource::Instance`], or
/// [`Action::AdministerInstance`] against an org, is a denial rather than a fallthrough. The
/// two ladders are orthogonal, and a mismatched pair is a programming error that must not
/// silently succeed on the other plane's authority.
pub fn authorize(actor: &ActorContext, action: Action, resource: &Resource) -> Result<()> {
    match (resource, action.required_level()) {
        (Resource::Org(org), Some(required)) => {
            let held = actor.role_in(*org);
            if held.satisfies(required) {
                Ok(())
            } else {
                Err(Error::Forbidden {
                    message: format!(
                        "{action:?} on org {org} requires role level {} but the actor holds {}",
                        required.level(),
                        held.level()
                    ),
                })
            }
        }
        (Resource::Instance, None) if actor.is_instance_admin => Ok(()),
        (Resource::Instance, None) => {
            Err(Error::Forbidden { message: "this action requires instance administrator rights".to_owned() })
        }
        // Mismatched plane: an org action aimed at the instance, or the instance action aimed
        // at an org. Never satisfiable, never an accident that grants anything.
        (Resource::Org(_), None) | (Resource::Instance, Some(_)) => {
            Err(Error::Forbidden { message: format!("{action:?} does not apply to {resource:?}") })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor_with_level(org: OrgId, level: u8) -> ActorContext {
        ActorContext::user(UserId::new(), BTreeMap::from([(org, RoleLevel::new(level))]))
    }

    fn allowed(level: u8, action: Action) -> bool {
        let org = OrgId::new();
        authorize(&actor_with_level(org, level), action, &Resource::Org(org)).is_ok()
    }

    #[test]
    fn read_boundary_is_exactly_50() {
        assert!(!allowed(49, Action::ReadPackages));
        assert!(allowed(50, Action::ReadPackages));
    }

    #[test]
    fn publish_boundary_is_exactly_100() {
        assert!(!allowed(99, Action::PublishPackages));
        assert!(allowed(100, Action::PublishPackages));
    }

    #[test]
    fn manage_members_boundary_is_exactly_200() {
        assert!(!allowed(199, Action::ManageMembers));
        assert!(allowed(200, Action::ManageMembers));
    }

    #[test]
    fn manage_org_boundary_is_exactly_250() {
        assert!(!allowed(249, Action::ManageOrg));
        assert!(allowed(250, Action::ManageOrg));
    }

    #[test]
    fn ladder_is_cumulative_owner_can_do_everything() {
        for action in [Action::ReadPackages, Action::PublishPackages, Action::ManageMembers, Action::ManageOrg] {
            assert!(allowed(RoleLevel::OWNER.level(), action), "owner denied {action:?}");
        }
    }

    #[test]
    fn instance_administration_is_a_separate_plane_from_the_org_ladder() {
        let org = OrgId::new();
        // An org Owner is not an instance admin.
        let owner = actor_with_level(org, RoleLevel::OWNER.level());
        assert!(authorize(&owner, Action::AdministerInstance, &Resource::Instance).is_err());
        // An instance admin holding no org role administers the instance and nothing else.
        let admin = ActorContext::user(UserId::new(), BTreeMap::new()).with_instance_admin(true);
        assert!(authorize(&admin, Action::AdministerInstance, &Resource::Instance).is_ok());
        assert!(authorize(&admin, Action::ReadPackages, &Resource::Org(org)).is_err());
        // Anonymous never administers anything.
        assert!(authorize(&ActorContext::anonymous(), Action::AdministerInstance, &Resource::Instance).is_err());
    }

    #[test]
    fn a_mismatched_action_and_resource_is_always_a_denial() {
        let org = OrgId::new();
        let admin = actor_with_level(org, RoleLevel::OWNER.level()).with_instance_admin(true);
        // Even for a principal who holds *both* authorities, the planes do not cross-apply.
        assert!(authorize(&admin, Action::AdministerInstance, &Resource::Org(org)).is_err());
        assert!(authorize(&admin, Action::ManageOrg, &Resource::Instance).is_err());
    }

    #[test]
    fn future_intermediate_role_slots_into_the_ladder() {
        // A hypothetical Maintainer(150) may publish but not manage members.
        assert!(allowed(150, Action::PublishPackages));
        assert!(!allowed(150, Action::ManageMembers));
    }

    #[test]
    fn anonymous_actor_is_denied() {
        let org = OrgId::new();
        let err = authorize(&ActorContext::anonymous(), Action::ReadPackages, &Resource::Org(org)).unwrap_err();
        assert_eq!(err.code(), "forbidden");
    }

    #[test]
    fn role_in_one_org_grants_nothing_in_another() {
        let member_org = OrgId::new();
        let other_org = OrgId::new();
        let actor = actor_with_level(member_org, RoleLevel::OWNER.level());
        assert!(authorize(&actor, Action::ReadPackages, &Resource::Org(other_org)).is_err());
    }

    #[test]
    fn denial_is_forbidden_with_context() {
        let org = OrgId::new();
        let err = authorize(&actor_with_level(org, 50), Action::ManageMembers, &Resource::Org(org)).unwrap_err();
        assert_eq!(err.code(), "forbidden");
        let msg = err.to_string();
        assert!(msg.contains("200") && msg.contains("50"), "message must name both levels: {msg}");
    }
}
