//! Organization lifecycle: profile, members, invitations, deletion.
//!
//! The load-bearing rule of this module is [`AuthorityChange`]: every membership mutation is
//! classified, and a change that **redefines or withdraws** authority revokes the affected
//! user's sessions before the call returns (S-09). Granting authority to somebody who had none
//! does not — a stale access token that predates the grant simply lacks the claim and fails
//! closed, and logging a person out of every device the instant they accept an invitation is a
//! cost with no security benefit. That distinction is written down in
//! [S-09.a](../../../../docs/security.md) and asserted by the tests.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Duration, Utc};
use pub_auth::flows::{AuthService, ClientMeta};
use pub_auth::random::RandomSource;
use pub_auth::token::sha256_hex;
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::org::{Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgProfile};
use pub_core::package::PackageOptions;
use pub_core::traits::{Mailer, Repositories};
use pub_core::user::User;
use pub_core::{Error, Format, InvitationId, OrgId, Result, RoleLevel, UserId};
use pub_registry::{ActorMeta, RegistryService};

/// How many packages a forced org archive will flip in one call before giving up.
///
/// A bound rather than an unbounded walk: the operation holds no lock and writes one row plus
/// one index document per package, and an org with tens of thousands of packages is a case an
/// operator should resolve by transferring them, not by a request that runs for minutes.
const MAX_FORCED_PACKAGES: u32 = 500;

/// How many accounts one batched member lookup asks for at a time.
///
/// Below the repositories' own `get_many` bound, so a large org is several round trips instead
/// of one refused query — the failure mode a naive single call would have had at 501 members.
const ACCOUNT_BATCH: usize = 200;

/// Instance policy for the org surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgPolicy {
    /// How long an invitation stays redeemable (docs/architecture.md default: 7 days).
    pub invitation_ttl: Duration,
    /// S-24 invitation budget: invitations per org per day.
    pub invitations_per_day_org: i64,
}

impl Default for OrgPolicy {
    fn default() -> Self {
        Self { invitation_ttl: Duration::days(7), invitations_per_day_org: 20 }
    }
}

/// What a membership mutation did to the affected user's authority — the S-09 decision, made
/// once and in the open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityChange {
    /// A user who was not a member became one.
    Granted,
    /// An existing member's role changed (up or down).
    Redefined,
    /// A member was removed.
    Withdrawn,
}

impl AuthorityChange {
    /// Whether this change must revoke every session of the affected user (S-09).
    ///
    /// A **grant** does not: no token issued before it carries the new claim, so nothing stale
    /// can spend authority the grant created. A **redefinition** and a **withdrawal** both do:
    /// an access token minted a minute ago still carries the old, higher level, and it would
    /// keep working for up to one access TTL — which is exactly the window S-09 exists to
    /// close.
    pub const fn revokes_sessions(self) -> bool {
        matches!(self, Self::Redefined | Self::Withdrawn)
    }

    /// The reason string recorded on the revocation's audit event.
    const fn reason(self) -> &'static str {
        match self {
            Self::Granted => "role_granted",
            Self::Redefined => "role_changed",
            Self::Withdrawn => "membership_removed",
        }
    }
}

/// A freshly created invitation plus its single-use token — shown exactly once.
#[derive(Debug, Clone)]
pub struct InvitationCreated {
    /// The stored row.
    pub invitation: Invitation,
    /// The plaintext token. Only its SHA-256 is stored; it is mailed to the invitee **and**
    /// returned here so an instance running without SMTP (the documented single-binary
    /// minimum, decision 04) can still onboard anybody. Handing it to the inviting admin
    /// discloses nothing they could not re-create: acceptance is bound to the invited
    /// address's *verified* holder, so the token is useless to anyone else.
    pub token: String,
}

/// What deleting an org actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgDeletion {
    /// `true` when the org row survives as an archive because it still owned packages.
    pub archived: bool,
    /// How many packages were made unreachable (forced archive only).
    pub packages: i64,
    /// How many members were removed.
    pub members: i64,
    /// How many sessions the removals revoked (S-09).
    pub sessions_revoked: u64,
}

/// The organization lifecycle service.
pub struct OrgService {
    repos: Repositories,
    auth: Arc<AuthService>,
    registry: Arc<RegistryService>,
    mailer: Arc<dyn Mailer>,
    events: Arc<dyn EventSink>,
    rng: Arc<dyn RandomSource>,
    policy: OrgPolicy,
}

impl std::fmt::Debug for OrgService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgService").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl OrgService {
    /// Builds the service over the configured backends.
    pub fn new(
        repos: Repositories,
        auth: Arc<AuthService>,
        registry: Arc<RegistryService>,
        mailer: Arc<dyn Mailer>,
        events: Arc<dyn EventSink>,
        rng: Arc<dyn RandomSource>,
        policy: OrgPolicy,
    ) -> Self {
        Self { repos, auth, registry, mailer, events, rng, policy }
    }

    /// The active policy.
    pub fn policy(&self) -> &OrgPolicy {
        &self.policy
    }

    // ------------------------------------------------------------------------------ profile

    /// Creates an org; the caller becomes its Owner in the same transaction (decision 19).
    ///
    /// Goes through the service rather than straight to the repository for one reason: S-22
    /// lists "org/membership changes" among the audited events, and creating an organization —
    /// which mints a name space, an Owner, and a virtual registry base — is the first of them.
    /// Before this existed the only trace of a new org was the row itself.
    pub async fn create_org(&self, new: NewOrg, creator: UserId, actor: &ActorMeta, now: DateTime<Utc>) -> Result<Org> {
        let org = self.repos.orgs.create(new, creator, now).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.created",
            Some(org.slug.clone()),
            AuditResult::Success,
            serde_json::json!({ "name": org.name, "upstream_policy": org.upstream_policy.as_str() }),
            now,
        )
        .await;
        // Deliberately no domain event. The org's only member at this instant is the person who
        // just created it, so a notification would tell somebody something they did one
        // millisecond ago, and `OrgUpdated` would be a lie about which field changed. The audit
        // row above is the durable record; a dedicated `org.created` event joins the enum when
        // there is an audience for it (instance-admin dashboards).
        Ok(org)
    }

    /// Replaces the org's profile (name, description, upstream policy).
    pub async fn update_profile(
        &self,
        org: &Org,
        profile: OrgProfile,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<Org> {
        let before = OrgProfile::from(org);
        let updated = self.repos.orgs.update_profile(org.id, &profile, now).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.updated",
            Some(org.slug.clone()),
            AuditResult::Success,
            serde_json::json!({ "before": before, "after": profile }),
            now,
        )
        .await;
        self.events
            .emit(DomainEvent::OrgUpdated {
                org_id: org.id,
                upstream_policy: updated.upstream_policy.as_str().to_owned(),
                at: now,
            })
            .await;
        Ok(updated)
    }

    // ------------------------------------------------------------------------------ members

    /// The org's members, each paired with the account behind it (deleted accounts yield
    /// `None`, so a tombstoned publisher still shows as a row rather than vanishing).
    pub async fn list_members(&self, org: OrgId) -> Result<Vec<(OrgMember, Option<User>)>> {
        let members = self.repos.orgs.list_members(org).await?;
        // Batch reads, not one per row. The obvious loop here was an N+1: an org with a few
        // hundred members turned one Admin request into a few hundred queries. Chunked because
        // the repository bounds how many ids one `IN (…)` may carry.
        let ids: Vec<UserId> = members.iter().map(|member| member.user_id).collect();
        let mut accounts: std::collections::HashMap<UserId, User> = std::collections::HashMap::new();
        for chunk in ids.chunks(ACCOUNT_BATCH) {
            accounts.extend(self.repos.users.get_many(chunk).await?.into_iter().map(|user| (user.id, user)));
        }
        Ok(members
            .into_iter()
            .map(|member| {
                let user = accounts.get(&member.user_id).cloned();
                (member, user)
            })
            .collect())
    }

    /// Adds a member by **verified** email at `role`.
    ///
    /// An address with no verified account is `NotFound`: an org admin adding somebody who has
    /// never signed in should be told to invite them, not handed a membership pointing at
    /// nobody. (The invitation path is what creates the account.)
    pub async fn add_member(
        &self,
        org: &Org,
        email: &str,
        role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<OrgMember> {
        let user = self
            .repos
            .users
            .find_by_email(email)
            .await?
            .ok_or_else(|| Error::NotFound { what: "a verified account with that email".to_owned() })?;
        let member = self.repos.orgs.add_member(org.id, user.id, role, now).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.member.add",
            Some(user.id.to_string()),
            AuditResult::Success,
            serde_json::json!({ "role": role.level(), "email": email }),
            now,
        )
        .await;
        self.apply_authority_change(org.id, user.id, Some(role), AuthorityChange::Granted, actor, now).await?;
        Ok(member)
    }

    /// Changes a member's role; returns the new membership and how many of that user's
    /// sessions the change revoked (S-09 — always all of them).
    ///
    /// The ≥1-Owner invariant is enforced in the repository, transactionally, and surfaces as
    /// [`Error::LastOwner`].
    pub async fn change_role(
        &self,
        org: &Org,
        user: UserId,
        role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<(OrgMember, u64)> {
        let before = self
            .repos
            .orgs
            .get_member(org.id, user)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {}", org.slug) })?;
        let member = self.repos.orgs.update_member_role(org.id, user, role, now).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.member.role",
            Some(user.to_string()),
            AuditResult::Success,
            serde_json::json!({ "before": before.role.level(), "after": role.level() }),
            now,
        )
        .await;
        let revoked =
            self.apply_authority_change(org.id, user, Some(role), AuthorityChange::Redefined, actor, now).await?;
        Ok((member, revoked))
    }

    /// Removes a member (≥1-Owner enforced in the repository).
    pub async fn remove_member(&self, org: &Org, user: UserId, actor: &ActorMeta, now: DateTime<Utc>) -> Result<u64> {
        let before = self
            .repos
            .orgs
            .get_member(org.id, user)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {}", org.slug) })?;
        self.repos.orgs.remove_member(org.id, user).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.member.remove",
            Some(user.to_string()),
            AuditResult::Success,
            serde_json::json!({ "role": before.role.level() }),
            now,
        )
        .await;
        self.apply_authority_change(org.id, user, None, AuthorityChange::Withdrawn, actor, now).await
    }

    /// **The S-09 chokepoint.** Emits the membership event and, for a change that redefines or
    /// withdraws authority, revokes every session of the affected user.
    ///
    /// Private and called by every membership mutation above; there is no other path to
    /// `OrgRepo`'s membership mutators in the codebase, which is what makes "no route can
    /// forget" a structural property rather than a review item.
    async fn apply_authority_change(
        &self,
        org: OrgId,
        user: UserId,
        role: Option<RoleLevel>,
        change: AuthorityChange,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        self.events
            .emit(DomainEvent::OrgMembershipChanged {
                org_id: org,
                user_id: user,
                role: role.map(RoleLevel::level),
                at: now,
            })
            .await;
        if !change.revokes_sessions() {
            return Ok(0);
        }
        let meta = ClientMeta { ip: actor.ip.clone(), user_agent: actor.user_agent.clone() };
        self.auth.revoke_sessions_after_authority_change(user, change.reason(), &meta, now).await
    }

    // -------------------------------------------------------------------------- invitations

    /// Creates an invitation (S-06: step-up gated at the API layer; default role Read).
    ///
    /// The S-24 per-org budget (≤20/day) is spent here rather than in a middleware because it
    /// is keyed on the org, which only exists once the route has resolved the slug.
    pub async fn invite(
        &self,
        org: &Org,
        email: &str,
        role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<InvitationCreated> {
        let email = email.trim().to_ascii_lowercase();
        if !email.contains('@') || email.len() > 320 {
            return Err(Error::Invalid { message: "invite email is not an address".to_owned() });
        }
        // S-31 applies to invitations too: inviting an address that could never sign in is a
        // dead end the admin should hear about now, not the invitee at redemption time.
        if !self.auth.settings().registration.domain_allowed(&email) {
            return Err(Error::Forbidden {
                message: "that email domain is not allowed to sign in on this instance".to_owned(),
            });
        }
        let sent_today = self.repos.orgs.count_invitations_since(org.id, now - Duration::days(1)).await?;
        if sent_today >= self.policy.invitations_per_day_org {
            self.audit(
                actor,
                Some(org.id),
                "auth.throttled",
                Some(org.slug.clone()),
                AuditResult::Failure,
                serde_json::json!({ "limit": "invitations_per_day_org", "value": self.policy.invitations_per_day_org }),
                now,
            )
            .await;
            // The window is a rolling day; the hint is the coarse remainder of it.
            return Err(Error::RateLimited { retry_after_secs: 3600 });
        }

        let mut secret = [0u8; 32];
        self.rng.fill(&mut secret);
        let token = B64URL.encode(secret);
        let invitation = self
            .repos
            .orgs
            .create_invitation(
                NewInvitation {
                    org_id: org.id,
                    email: email.clone(),
                    role,
                    invited_by: actor.user_id,
                    token_hash: sha256_hex(&token),
                    expires_at: now + self.policy.invitation_ttl,
                },
                now,
            )
            .await?;

        // Best-effort delivery: the token is also returned to the caller, so a mail outage
        // degrades the flow to "copy the link" instead of failing a committed invitation.
        let body = format!(
            "You have been invited to join the organization \"{}\" on this package registry.\n\n\
             Accept with this invitation code:\n\n  {token}\n\n\
             The code expires in {} days and can be used once.\n",
            org.name,
            self.policy.invitation_ttl.num_days().max(1),
        );
        if let Err(err) = self.mailer.send(&email, "You have been invited to an organization", &body).await {
            tracing::error!(error = %err, "invitation mail delivery failed; the token was still issued");
        }

        self.audit(
            actor,
            Some(org.id),
            "org.invitation.create",
            Some(invitation.id.to_string()),
            AuditResult::Success,
            serde_json::json!({ "email": email, "role": role.level() }),
            now,
        )
        .await;
        Ok(InvitationCreated { invitation, token })
    }

    /// The org's invitations, newest first (every lifecycle state).
    pub async fn list_invitations(&self, org: OrgId) -> Result<Vec<Invitation>> {
        self.repos.orgs.list_invitations(org).await
    }

    /// Revokes a pending invitation. An invitation belonging to a different org is `NotFound`,
    /// never `Forbidden` — the id must not confirm an invitation exists elsewhere (S-04).
    pub async fn revoke_invitation(
        &self,
        org: &Org,
        id: InvitationId,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<Invitation> {
        let belongs = self.repos.orgs.list_invitations(org.id).await?.into_iter().any(|invitation| invitation.id == id);
        if !belongs {
            return Err(Error::NotFound { what: format!("invitation {id}") });
        }
        let invitation = self.repos.orgs.revoke_invitation(id, now).await?;
        self.audit(
            actor,
            Some(org.id),
            "org.invitation.revoke",
            Some(id.to_string()),
            AuditResult::Success,
            serde_json::json!({ "email": invitation.email }),
            now,
        )
        .await;
        Ok(invitation)
    }

    /// Redeems an invitation token as `user`.
    ///
    /// The repository consumes the invitation and creates (or raises) the membership in one
    /// transaction. This is an authority **grant**, so it does not revoke the accepting user's
    /// sessions — see [`AuthorityChange`].
    pub async fn accept_invitation(
        &self,
        token: &str,
        user: UserId,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<Invitation> {
        let invitation = self.repos.orgs.accept_invitation(&sha256_hex(token), user, now).await?;
        self.audit(
            actor,
            Some(invitation.org_id),
            "org.invitation.accept",
            Some(invitation.id.to_string()),
            AuditResult::Success,
            serde_json::json!({ "role": invitation.role.level() }),
            now,
        )
        .await;
        self.apply_authority_change(
            invitation.org_id,
            user,
            Some(invitation.role),
            AuthorityChange::Granted,
            actor,
            now,
        )
        .await?;
        Ok(invitation)
    }

    // ----------------------------------------------------------------------------- deletion

    /// Deletes an org (Owner + step-up at the API layer).
    ///
    /// Two outcomes, and which one happens is decided by whether the org owns packages:
    ///
    /// - **No packages** — the org row and everything that exists only to describe it
    ///   (memberships, invitations, org-bound tokens) are erased.
    /// - **Packages** — refused with `Conflict` unless `force`. Forcing **archives**: every
    ///   package is flipped private + unlisted + discontinued through the registry service (so
    ///   the search index follows), then the org is stamped `archived_at` with its members,
    ///   invitations, and tokens stripped. The row survives because decision 06 and S-18 keep
    ///   name claims and version rows forever, and both hang off it — erasing the org would
    ///   un-burn a package name, which is the one thing hard delete promises never happens.
    ///
    /// Either way every removed member's sessions are revoked (S-09): they just lost authority.
    pub async fn delete_org(
        &self,
        org: &Org,
        force: bool,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<OrgDeletion> {
        let packages = self.repos.packages.count_for_org(org.id).await?;
        if packages > 0 && !force {
            return Err(Error::Conflict {
                message: format!(
                    "org {} still owns {packages} package(s); transfer them, or repeat with force to archive the org",
                    org.slug
                ),
            });
        }
        if packages > i64::from(MAX_FORCED_PACKAGES) {
            return Err(Error::Conflict {
                message: format!(
                    "org {} owns {packages} packages, more than the {MAX_FORCED_PACKAGES} a forced archive will \
                     move; transfer them to another organization first",
                    org.slug
                ),
            });
        }

        let members = self.repos.orgs.list_members(org.id).await?;
        let archived = packages > 0;
        if archived {
            self.hide_packages(org, actor, now).await?;
        }

        if archived {
            self.repos.orgs.archive(org.id, now).await?;
        } else {
            self.repos.orgs.delete(org.id).await?;
        }

        let mut sessions_revoked = 0;
        for member in &members {
            sessions_revoked += self
                .apply_authority_change(org.id, member.user_id, None, AuthorityChange::Withdrawn, actor, now)
                .await?;
        }

        self.audit(
            actor,
            Some(org.id),
            "org.deleted",
            Some(org.slug.clone()),
            AuditResult::Success,
            serde_json::json!({
                "archived": archived,
                "forced": force,
                "packages": packages,
                "members": members.len(),
                "sessions_revoked": sessions_revoked,
            }),
            now,
        )
        .await;
        self.events.emit(DomainEvent::OrgDeleted { org_id: org.id, slug: org.slug.clone(), archived, at: now }).await;

        Ok(OrgDeletion { archived, packages, members: members.len() as i64, sessions_revoked })
    }

    /// Makes every package of a forcibly archived org unreachable: private, unlisted, and
    /// discontinued, through the registry service so the search document is rebuilt.
    async fn hide_packages(&self, org: &Org, actor: &ActorMeta, now: DateTime<Utc>) -> Result<()> {
        let mut cursor: Option<String> = None;
        loop {
            let page = self.repos.packages.list_for_org(org.id, cursor.as_deref(), 100).await?;
            for package in &page.items {
                let options = PackageOptions {
                    visibility: pub_core::package::Visibility::Private,
                    discontinued: true,
                    replaced_by: package.replaced_by.clone(),
                    unlisted: true,
                };
                self.registry.set_options(Format::Pub, org.id, &package.name, &options, actor, now).await?;
            }
            match page.cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(()),
            }
        }
    }

    /// Appends an audit event. Failures are logged, never propagated — an audit outage must
    /// not take org management down with it (the same stance as the auth and registry
    /// services).
    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        actor: &ActorMeta,
        org: Option<OrgId>,
        action: &str,
        target: Option<String>,
        result: AuditResult,
        metadata: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        let event = NewAuditEvent {
            actor: match actor.token_id {
                Some(token) => AuditActor::Token(token),
                None => AuditActor::User(actor.user_id),
            },
            ip: actor.ip.clone(),
            user_agent: actor.user_agent.clone(),
            org_id: org,
            action: action.to_owned(),
            target,
            result,
            metadata: Some(metadata),
        };
        if let Err(err) = self.repos.audit.append(event, now).await {
            tracing::error!(action, error = %err, "audit append failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s09_only_a_redefinition_or_a_withdrawal_revokes_sessions() {
        // The whole S-09 policy of this module, in one assertion. A grant cannot be spent by a
        // token minted before it (the claim is simply absent), while a demotion or a removal
        // would otherwise keep working for up to one access TTL.
        assert!(!AuthorityChange::Granted.revokes_sessions());
        assert!(AuthorityChange::Redefined.revokes_sessions());
        assert!(AuthorityChange::Withdrawn.revokes_sessions());
    }

    #[test]
    fn every_authority_change_names_itself_in_the_audit_trail() {
        let reasons: Vec<&str> = [AuthorityChange::Granted, AuthorityChange::Redefined, AuthorityChange::Withdrawn]
            .into_iter()
            .map(AuthorityChange::reason)
            .collect();
        assert_eq!(reasons, vec!["role_granted", "role_changed", "membership_removed"]);
    }

    #[test]
    fn default_policy_matches_the_documented_defaults() {
        let policy = OrgPolicy::default();
        assert_eq!(policy.invitation_ttl, Duration::days(7));
        assert_eq!(policy.invitations_per_day_org, 20);
    }
}
