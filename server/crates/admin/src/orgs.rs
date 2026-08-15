//! Organization lifecycle: profile, members, invitations, deletion.
//!
//! The load-bearing rule of this module is [`AuthorityChange`]: every membership mutation is
//! classified, and a change that **redefines or withdraws** authority revokes the affected
//! user's sessions before the call returns (S-09). Granting authority to somebody who had none
//! does not — a stale access token that predates the grant simply lacks the claim and fails
//! closed, and logging a person out of every device the instant they accept an invitation is a
//! cost with no security benefit. That distinction is written down in
//! [S-09.a](../../../../docs/security.md) and asserted by the tests.
//!
//! Two more rules ride the same chokepoints:
//!
//! - **The role-grant ceiling** (decision 19 addendum, D39): a non-Owner actor manages only
//!   levels strictly below their own; an Owner manages every level. Checked by
//!   [`check_role_ceiling`] inside each mutation, so every path — add, role change, removal,
//!   invitation creation — inherits it and no route can forget it. Acceptance of an
//!   invitation is deliberately *not* re-checked: the role was frozen into the row when the
//!   ceiling was satisfied ("an invitation never lowers").
//! - **Authority changes reach the token plane** (decision 13 addendum, D37): a lowered
//!   redefinition revokes the member's org-bound CLI tokens whose scopes exceed the new
//!   level, and a withdrawal revokes them all — inside [`AuthorityChange`]'s application,
//!   **after** the S-09 session sweep and best-effort, so a token-plane failure can never
//!   leave a session alive. A grant or a raise revokes nothing.

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
use pub_core::queue::{MailJob, NewQueuedJob};
use pub_core::token::TokenScope;
use pub_core::traits::Repositories;
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
///
/// The S-24 invitation budgets used to live here as compile-time constants. They are runtime
/// settings now ([S-24.h](../../../../docs/security.md#5-audit--abuse), decision 32) and are
/// read from the settings cache per invitation, so an instance being spammed can respond from
/// the admin surface instead of a rebuild — and so there is one source of truth rather than a
/// constant and a settings row that can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgPolicy {
    /// How long an invitation stays redeemable (docs/architecture.md default: 7 days).
    pub invitation_ttl: Duration,
}

impl Default for OrgPolicy {
    fn default() -> Self {
        Self { invitation_ttl: Duration::days(7) }
    }
}

/// What a membership mutation did to the affected user's authority — the S-09 decision, made
/// once and in the open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityChange {
    /// A user who was not a member became one.
    Granted,
    /// An existing member's role changed (up or down). Carrying both levels here is what lets
    /// the token sweep (D37) tell a demotion from a promotion without a second lookup — a
    /// redefinition cannot be classified without saying what it redefined.
    Redefined {
        /// The level the member held before the change.
        from: RoleLevel,
        /// The level the member holds after it.
        to: RoleLevel,
    },
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
        matches!(self, Self::Redefined { .. } | Self::Withdrawn)
    }

    /// The level the affected user's org-bound CLI tokens must fit under after this change,
    /// or `None` when the token plane is untouched (decision 13 addendum, D37).
    ///
    /// A **grant** and a **raise** revoke nothing — mirroring S-09.a's grant row, nothing
    /// stale outranks authority that only grew. A **lowered** redefinition returns the new
    /// level; a **withdrawal** returns [`RoleLevel::NONE`], under which no token fits (an
    /// empty scope set fails closed in [`scopes_exceed`]), which is how "removal revokes them
    /// all" falls out of the same rule.
    const fn token_ceiling(self) -> Option<RoleLevel> {
        match self {
            Self::Granted => None,
            Self::Redefined { from, to } => {
                if to.level() < from.level() {
                    Some(to)
                } else {
                    None
                }
            }
            Self::Withdrawn => Some(RoleLevel::NONE),
        }
    }

    /// The reason string recorded on the revocation's audit event.
    const fn reason(self) -> &'static str {
        match self {
            Self::Granted => "role_granted",
            Self::Redefined { .. } => "role_changed",
            Self::Withdrawn => "membership_removed",
        }
    }
}

/// How much credential state an [`AuthorityChange`] swept alongside the membership write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthorityRevocations {
    /// Sessions revoked (S-09 — always every live session of the affected user).
    pub sessions: u64,
    /// Org-bound CLI tokens revoked (D37 — those whose scopes exceed the new level; every one
    /// of them on a withdrawal; none on a grant or a raise).
    pub tokens: u64,
}

/// The role-grant ceiling (decision 19 addendum, D39).
///
/// A non-Owner actor manages only levels **strictly below** their own — both the level being
/// granted and the level the target already holds — so an org Admin can neither appoint a
/// fellow Admin nor demote, remove, or out-invite one. An **Owner is exempt** and manages
/// every level, other Owners included (the ≥1-Owner invariant stays transactional in the
/// repositories and is unaffected). Lives here in the service so every mutation path inherits
/// it; the denial names role *names*, never numbers (decision 19's wire rule).
fn check_role_ceiling(acting: RoleLevel, subject: RoleLevel) -> Result<()> {
    if acting.satisfies(RoleLevel::OWNER) || subject < acting {
        return Ok(());
    }
    Err(Error::Forbidden { message: format!("your role {acting} manages only roles below {acting}") })
}

/// The self-reduction carve-out from the D39 ceiling (decision 19 addendum): a mutation aimed
/// at the actor **themselves** that does not *raise* their level bypasses [`check_role_ceiling`]
/// entirely — self-demotion to any lower (or the same) level, and self-removal (`new` =
/// [`RoleLevel::NONE`]), because lowering your own authority is never an escalation; it is how
/// an Admin leaves an organization. A self-**raise** is not exempt: an Admin promoting
/// themselves to Owner is exactly the escalation the ceiling exists to stop. The ≥1-Owner
/// invariant is untouched — a sole Owner's self-removal or self-demotion still hits the
/// repository's transactional `last_owner` conflict.
fn is_self_reduction(actor: &ActorMeta, target: UserId, current: RoleLevel, new: RoleLevel) -> bool {
    actor.user_id == target && new <= current
}

/// Whether any of the token's scopes demands a role level above `ceiling` — the D37 sweep
/// predicate, evaluated over the mint gate's own scope→action mapping
/// ([`TokenScope::required_action`]) so "what a scope is worth" has exactly one source.
fn scopes_exceed(scopes: &[TokenScope], ceiling: RoleLevel) -> bool {
    // An empty scope set proves nothing about fitting under any ceiling. The repository
    // refuses to mint one, so this arm defends against a row that predates or bypassed that
    // rule — and an unclassifiable credential is revoked rather than spared, the same
    // failing-closed direction as the unmapped-scope arm below.
    if scopes.is_empty() {
        return true;
    }
    scopes.iter().any(|scope| match scope.required_action().required_level() {
        Some(required) => !ceiling.satisfies(required),
        // Every scope maps onto an org action, which always carries a level. Should that ever
        // stop holding, an unclassifiable credential is revoked rather than spared — the
        // failing-closed direction.
        None => true,
    })
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
        events: Arc<dyn EventSink>,
        rng: Arc<dyn RandomSource>,
        policy: OrgPolicy,
    ) -> Self {
        Self { repos, auth, registry, events, rng, policy }
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
    ///
    /// `acting_role` is the caller's own level in the org, checked against the D39 ceiling:
    /// a non-Owner grants only levels below their own.
    pub async fn add_member(
        &self,
        org: &Org,
        email: &str,
        role: RoleLevel,
        acting_role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<OrgMember> {
        check_role_ceiling(acting_role, role)?;
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

    /// Changes a member's role; returns the new membership and the credential sweep the
    /// change triggered (S-09 sessions — always all of them; D37 tokens on a demotion).
    ///
    /// The D39 ceiling covers **both** levels: the one the target currently holds and the one
    /// being assigned — an Admin neither demotes a fellow Admin nor promotes anybody to one.
    /// The one exemption is [`is_self_reduction`]: demoting *yourself* is always allowed,
    /// promoting yourself never is. The ≥1-Owner invariant is enforced in the repository,
    /// transactionally, and surfaces as [`Error::LastOwner`].
    pub async fn change_role(
        &self,
        org: &Org,
        user: UserId,
        role: RoleLevel,
        acting_role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<(OrgMember, AuthorityRevocations)> {
        let before = self
            .repos
            .orgs
            .get_member(org.id, user)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {}", org.slug) })?;
        // The ceiling governs what an actor does to others — and any raise, their own
        // included. Lowering your own level is exempt (decision 19 addendum); the ≥1-Owner
        // invariant in the repository still has the last word on a sole Owner.
        if !is_self_reduction(actor, user, before.role, role) {
            check_role_ceiling(acting_role, before.role)?;
            check_role_ceiling(acting_role, role)?;
        }
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
        let change = AuthorityChange::Redefined { from: before.role, to: role };
        let revoked = self.apply_authority_change(org.id, user, Some(role), change, actor, now).await?;
        Ok((member, revoked))
    }

    /// Removes a member (≥1-Owner enforced in the repository; the D39 ceiling covers the
    /// target's current level — an Admin does not remove a fellow Admin, but does remove
    /// **themselves**: self-removal is a reduction and bypasses the ceiling).
    pub async fn remove_member(
        &self,
        org: &Org,
        user: UserId,
        acting_role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<AuthorityRevocations> {
        let before = self
            .repos
            .orgs
            .get_member(org.id, user)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {}", org.slug) })?;
        if !is_self_reduction(actor, user, before.role, RoleLevel::NONE) {
            check_role_ceiling(acting_role, before.role)?;
        }
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

    /// **The S-09/D37 chokepoint.** Emits the membership event; for a change that redefines
    /// or withdraws authority, revokes every session of the affected user (S-09); and for a
    /// change that *lowers* or withdraws it, revokes the member's org-bound CLI tokens the new
    /// level could no longer mint (decision 13 addendum, D37).
    ///
    /// **Ordering is load-bearing.** The membership row is already committed by the caller, so
    /// the S-09 session sweep runs **first** and fallibly — a demoted member's live sessions
    /// are the one thing that must not survive this call. The D37 token sweep runs after and
    /// is best-effort: a token-plane hiccup can neither block S-09 nor fail a mutation that
    /// has already happened.
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
    ) -> Result<AuthorityRevocations> {
        self.events
            .emit(DomainEvent::OrgMembershipChanged {
                org_id: org,
                user_id: user,
                role: role.map(RoleLevel::level),
                at: now,
            })
            .await;
        let mut revoked = AuthorityRevocations::default();
        if change.revokes_sessions() {
            let meta = ClientMeta { ip: actor.ip.clone(), user_agent: actor.user_agent.clone() };
            revoked.sessions =
                self.auth.revoke_sessions_after_authority_change(user, change.reason(), &meta, now).await?;
        }
        if let Some(ceiling) = change.token_ceiling() {
            revoked.tokens = self.revoke_outleveled_tokens(org, user, ceiling, change.reason(), actor, now).await;
        }
        Ok(revoked)
    }

    /// Revokes the member's CLI tokens in `org` whose scopes exceed `ceiling` (decision 13
    /// addendum, D37): a demotion takes the credentials the new role could no longer mint, a
    /// withdrawal (`ceiling` = [`RoleLevel::NONE`]) takes them all. Tokens in the user's
    /// *other* orgs are untouched — authority changed in this org only — and a token scoped at
    /// or below the new level survives, because the sweep compares the **token's scopes**, not
    /// the holder. The comparison runs in Rust over `list` + `revoke`, never per-dialect SQL.
    ///
    /// **Best-effort, deliberately** — the same stance as the search-index write on the
    /// publish path. By the time this runs the membership row is committed and the S-09
    /// session sweep has already happened, so propagating a token-plane error would report a
    /// completed demotion as failed while revoking nothing more. Instead the walk continues
    /// past per-token failures (loud in the log), the audit row carries the count actually
    /// revoked, and a token that slips through still *authorizes* nothing above the new level,
    /// because the role is re-derived per request (decision 13) — the sweep removes the
    /// credential, the chokepoint removes the authority. Returns the honest count.
    async fn revoke_outleveled_tokens(
        &self,
        org: OrgId,
        user: UserId,
        ceiling: RoleLevel,
        reason: &str,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> u64 {
        let tokens = match self.repos.tokens.list_for_user(user).await {
            Ok(tokens) => tokens,
            Err(err) => {
                tracing::warn!(%user, %org, error = %err, "D37 token sweep could not list the member's tokens");
                return 0;
            }
        };
        let mut count = 0u64;
        for token in tokens {
            if token.org_id != org || !scopes_exceed(&token.scopes, ceiling) {
                continue;
            }
            match self.repos.tokens.revoke(token.id, now).await {
                Ok(()) => count += 1,
                Err(err) => {
                    tracing::warn!(token = %token.id, %user, %org, error = %err, "D37 token sweep failed to revoke a token; continuing with the rest");
                }
            }
        }
        if count > 0 {
            // The **system** is the audit actor, like the S-09 session sweep: the person
            // losing credentials is not the person who acted. Failures are logged, never
            // propagated — same stance as `audit` below.
            let event = NewAuditEvent {
                actor: AuditActor::System,
                ip: actor.ip.clone(),
                user_agent: actor.user_agent.clone(),
                org_id: Some(org),
                action: "token.revoked".to_owned(),
                target: Some(user.to_string()),
                result: AuditResult::Success,
                metadata: Some(serde_json::json!({ "reason": reason, "count": count })),
            };
            if let Err(err) = self.repos.audit.append(event, now).await {
                tracing::error!(action = "token.revoked", error = %err, "audit append failed");
            }
        }
        count
    }

    // -------------------------------------------------------------------------- invitations

    /// Creates an invitation (S-06: step-up gated at the API layer; default role Read).
    ///
    /// The D39 ceiling applies at **creation**: the role is frozen into the row here, exactly
    /// as it always was ("an invitation never lowers"), so acceptance never re-checks it and a
    /// later demotion of the inviter does not retroactively invalidate an outstanding
    /// invitation. The S-24.h budgets — per org **and** per actor within that org — are spent
    /// here rather than in a middleware because they are keyed on the org, which only exists
    /// once the route has resolved the slug.
    ///
    /// **Both budgets stay database counts** rather than moving onto the KV limiter that bounds
    /// every other mutation (S-24.g). The count is exact, its 24-hour window genuinely rolls
    /// instead of tumbling, and it survives a KV outage — three properties the buckets do not
    /// have, on the one mutation whose cost is mail delivered to a third party.
    pub async fn invite(
        &self,
        org: &Org,
        email: &str,
        role: RoleLevel,
        acting_role: RoleLevel,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<InvitationCreated> {
        check_role_ceiling(acting_role, role)?;
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
        // One source of truth for both numbers: the runtime settings cache (decision 09/32).
        let limits = self.auth.settings().rate_limits;
        let since = now - Duration::days(1);

        let sent_today = self.repos.orgs.count_invitations_since(org.id, since).await?;
        if sent_today >= i64::from(limits.invitations_per_day_org) {
            self.invitation_throttled(org, actor, "invitations_per_day_org", limits.invitations_per_day_org, now).await;
            // The window is a rolling day; the hint is the coarse remainder of it.
            return Err(Error::RateLimited { retry_after_secs: 3600 });
        }
        // The per-actor half (S-24.h): the org cap bounds the org, this one stops a single
        // member spending the whole org's budget on their own. Scoped to this org — an actor
        // who is Admin in N orgs can still send N × this cap, each bounded by its own org cap,
        // which decision 32 states as the accepted residue.
        let sent_by_actor = self.repos.orgs.count_invitations_since_by_actor(org.id, actor.user_id, since).await?;
        if sent_by_actor >= i64::from(limits.invitations_per_day_actor) {
            self.invitation_throttled(org, actor, "invitations_per_day_actor", limits.invitations_per_day_actor, now)
                .await;
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
        // The body carries the invitation token, which is a credential — so the queued payload
        // is sealed under the boot KEK exactly like a sign-in code (S-26.b).
        let body = format!(
            "You have been invited to join the organization \"{}\" on this package registry.\n\n\
             Accept with this invitation code:\n\n  {token}\n\n\
             The code expires in {} days and can be used once.\n",
            org.name,
            self.policy.invitation_ttl.num_days().max(1),
        );
        self.queue_mail(&email, "You have been invited to an organization", &body, "org.invitation", now).await;

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

        // Ordering matters for the token plane (D37): `archive` bulk-revokes and `delete`
        // erases every org-bound token transactionally *above*, so the per-member Withdrawn
        // sweep below finds none left — revoked tokens are excluded from `list_for_user` — and
        // cannot double-revoke or double-audit. Pinned by the contract suite's archive walk.
        let mut sessions_revoked = 0;
        for member in &members {
            sessions_revoked += self
                .apply_authority_change(org.id, member.user_id, None, AuthorityChange::Withdrawn, actor, now)
                .await?
                .sessions;
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

    /// Files one message on the durable queue, best-effort (decision 26).
    ///
    /// Sealed under the boot KEK ([S-26.b](../../../../docs/security.md)): the one message this
    /// service sends carries an invitation token, which is a credential sitting in a table until
    /// a worker claims it. The KEK is the auth policy's — the same one the TOTP seeds and the
    /// stored SMTP password use, reached through the service that owns it rather than copied.
    ///
    /// Never fatal: the token is also returned to the caller, so an outage here degrades the
    /// flow to "copy the code" instead of failing a committed invitation.
    async fn queue_mail(&self, to: &str, subject: &str, body: &str, what: &str, now: DateTime<Utc>) {
        let sealed = pub_auth::secretbox::seal(&self.auth.policy().kek, self.rng.as_ref(), body.as_bytes())
            .map(|blob| base64::engine::general_purpose::STANDARD.encode(blob));
        let payload = match sealed {
            Ok(text) => serde_json::to_value(MailJob {
                to: to.to_owned(),
                subject: subject.to_owned(),
                text,
                html: None,
                sealed: true,
            }),
            Err(error) => {
                tracing::error!(%error, what, "sealing a queued message failed; the token was still issued");
                return;
            }
        };
        let payload = match payload {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(%error, what, "encoding a queued message failed; the token was still issued");
                return;
            }
        };
        if let Err(error) = self.repos.queue.enqueue(&NewQueuedJob::pending(MailJob::KIND, payload), now).await {
            tracing::error!(%error, what, "queueing a message failed; the token was still issued");
        }
    }

    /// Files an invitation-throttle refusal: the `rate_limit_trips_total` counter on **every**
    /// refusal, and at most **one audit row per (org, actor) per hour**.
    ///
    /// **This site used to write a row per refusal, deliberately, and the reasoning was wrong.**
    /// The argument was that the amplification `Decision::first_in_window` exists to stop is not
    /// reachable here — the actor is authenticated, step-up gated (S-06) and org-scoped, and
    /// "already bounded by S-24.g's write bucket at the same number as every other mutation".
    /// That last clause is false, and it was the load-bearing one: every *other* throttle site
    /// dedupes, so their ceiling is one row per window; without a dedupe this site's ceiling is
    /// one row per **request**. At `write_per_identity_minute` = 300 an actor who has spent
    /// their daily invitation cap sustains 300 rows/minute — 432 000 a day, retained for
    /// S-23's default 730 days — which made a *refused* invitation the cheapest audit-row
    /// primitive on the API, while a *successful* one costs real work and is capped at ten a day.
    ///
    /// The evidence [S-22] requires survives the dedupe: one row per hour still names the actor,
    /// the org and which cap was hit, which is what an operator investigating invitation abuse
    /// reads. What is lost is only the repetition.
    ///
    /// **Enforcement does not go through this function.** The refusal itself is still decided by
    /// an exact rolling `COUNT(*)` (S-24.h) — that is why the caps survive a KV outage. Only the
    /// audit row is suppressed here, so a KV outage degrades evidence rather than the cap: the
    /// in-process fallback's slot collisions can merge two orgs' suppression keys and drop a row
    /// that should have been written. That is the acceptable direction for a bounded table
    /// during an outage, and it is bounded — the counter is unaffected either way.
    ///
    /// [S-22]: ../../../../docs/security.md#5-audit--abuse
    async fn invitation_throttled(
        &self,
        org: &Org,
        actor: &ActorMeta,
        limit: &'static str,
        value: u32,
        now: DateTime<Utc>,
    ) {
        metrics::counter!("rate_limit_trips_total", "limit" => limit).increment(1);
        // The key carries the **cap** as well as the org and the actor. Without it the two caps
        // share one suppression window, so an actor refused by the per-actor cap at 10:05 and by
        // the org cap at 10:20 leaves one row naming only the first — an operator reading the log
        // would see the wrong reason, which is worse than seeing one row fewer.
        let suppression_key = format!("rl:invite_audit:{}:{}:{limit}", org.id, actor.user_id);
        if !self.auth.suppress_once(&suppression_key, Duration::hours(1), now).await {
            return;
        }
        self.audit(
            actor,
            Some(org.id),
            "org.invitation.throttled",
            Some(org.slug.clone()),
            AuditResult::Failure,
            serde_json::json!({ "limit": limit, "value": value }),
            now,
        )
        .await;
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

    /// A demotion, for the tests that only need "some redefinition".
    const DEMOTION: AuthorityChange = AuthorityChange::Redefined { from: RoleLevel::ADMIN, to: RoleLevel::WRITE };

    #[test]
    fn s09_only_a_redefinition_or_a_withdrawal_revokes_sessions() {
        // The whole S-09 policy of this module, in one assertion. A grant cannot be spent by a
        // token minted before it (the claim is simply absent), while a demotion or a removal
        // would otherwise keep working for up to one access TTL.
        assert!(!AuthorityChange::Granted.revokes_sessions());
        assert!(DEMOTION.revokes_sessions());
        // A *raise* revokes sessions too: the stale claim carries the old, now-wrong level.
        assert!(AuthorityChange::Redefined { from: RoleLevel::READ, to: RoleLevel::ADMIN }.revokes_sessions());
        assert!(AuthorityChange::Withdrawn.revokes_sessions());
    }

    #[test]
    fn every_authority_change_names_itself_in_the_audit_trail() {
        let reasons: Vec<&str> = [AuthorityChange::Granted, DEMOTION, AuthorityChange::Withdrawn]
            .into_iter()
            .map(AuthorityChange::reason)
            .collect();
        assert_eq!(reasons, vec!["role_granted", "role_changed", "membership_removed"]);
    }

    #[test]
    fn s13_only_a_lowered_redefinition_or_a_withdrawal_touches_the_token_plane() {
        // The whole D37 token policy (decision 13 addendum), in one assertion set. A grant and
        // a raise revoke nothing — mirroring S-09.a's grant row; a demotion caps tokens at the
        // new level; a withdrawal caps them at NONE, under which no token fits.
        assert_eq!(AuthorityChange::Granted.token_ceiling(), None);
        assert_eq!(AuthorityChange::Redefined { from: RoleLevel::READ, to: RoleLevel::ADMIN }.token_ceiling(), None);
        assert_eq!(
            AuthorityChange::Redefined { from: RoleLevel::WRITE, to: RoleLevel::WRITE }.token_ceiling(),
            None,
            "re-assigning the same level is not a demotion"
        );
        assert_eq!(DEMOTION.token_ceiling(), Some(RoleLevel::WRITE));
        assert_eq!(AuthorityChange::Withdrawn.token_ceiling(), Some(RoleLevel::NONE));
    }

    #[test]
    fn s13_the_sweep_compares_the_tokens_scopes_not_the_holder() {
        // Per scope: the mint gate's mapping decides what each scope is worth.
        assert!(!scopes_exceed(&[TokenScope::Read], RoleLevel::READ));
        assert!(scopes_exceed(&[TokenScope::Read], RoleLevel::NONE), "a withdrawal takes even a read token");
        assert!(scopes_exceed(&[TokenScope::Publish], RoleLevel::READ));
        assert!(!scopes_exceed(&[TokenScope::Publish], RoleLevel::WRITE));
        assert!(!scopes_exceed(&[TokenScope::Retract], RoleLevel::WRITE));
        assert!(scopes_exceed(&[TokenScope::Admin], RoleLevel::WRITE));
        assert!(!scopes_exceed(&[TokenScope::Admin], RoleLevel::ADMIN));
        // One out-of-rank scope condemns the whole token: scopes are granted as a set.
        assert!(scopes_exceed(&[TokenScope::Read, TokenScope::Publish], RoleLevel::READ));
        // A token deliberately scoped below the holder's old role survives the demotion.
        assert!(!scopes_exceed(&[TokenScope::Read], RoleLevel::WRITE));
    }

    #[test]
    fn s13_an_empty_scope_set_fails_closed_under_every_ceiling() {
        // The repository refuses to mint a scopeless token, so this is defense in depth: a row
        // that predates or bypassed that rule is unclassifiable, and an unclassifiable
        // credential is revoked, not spared — even under the most permissive ceiling.
        assert!(scopes_exceed(&[], RoleLevel::OWNER), "an empty scope set must exceed even the owner ceiling");
        assert!(scopes_exceed(&[], RoleLevel::ADMIN));
        assert!(scopes_exceed(&[], RoleLevel::NONE));
    }

    #[test]
    fn d39_self_reduction_is_exempt_from_the_ceiling_but_a_self_raise_is_not() {
        let me = UserId::new();
        let actor = ActorMeta::user(me);
        // Demoting yourself — to any lower level, or all the way out — is a reduction.
        assert!(is_self_reduction(&actor, me, RoleLevel::ADMIN, RoleLevel::WRITE));
        assert!(is_self_reduction(&actor, me, RoleLevel::ADMIN, RoleLevel::NONE), "self-removal is a reduction");
        assert!(
            is_self_reduction(&actor, me, RoleLevel::OWNER, RoleLevel::NONE),
            "even for an owner (the ≥1-Owner invariant is the repository's, not the ceiling's)"
        );
        // Re-assigning your own current level is not an escalation either.
        assert!(is_self_reduction(&actor, me, RoleLevel::ADMIN, RoleLevel::ADMIN));
        // Raising yourself is exactly what the ceiling exists to stop.
        assert!(!is_self_reduction(&actor, me, RoleLevel::ADMIN, RoleLevel::OWNER));
        assert!(!is_self_reduction(&actor, me, RoleLevel::WRITE, RoleLevel::ADMIN));
        // Somebody else's membership is never a self-reduction, however low the new level.
        assert!(!is_self_reduction(&actor, UserId::new(), RoleLevel::ADMIN, RoleLevel::NONE));
    }

    #[test]
    fn d39_the_ceiling_stops_non_owners_at_their_own_level() {
        // An Owner is exempt: they manage every level, other Owners included.
        for subject in [RoleLevel::READ, RoleLevel::WRITE, RoleLevel::ADMIN, RoleLevel::OWNER] {
            assert!(check_role_ceiling(RoleLevel::OWNER, subject).is_ok(), "owner must manage {subject}");
        }
        // An Admin manages strictly below admin — never a peer, never an Owner.
        assert!(check_role_ceiling(RoleLevel::ADMIN, RoleLevel::READ).is_ok());
        assert!(check_role_ceiling(RoleLevel::ADMIN, RoleLevel::WRITE).is_ok());
        assert!(check_role_ceiling(RoleLevel::ADMIN, RoleLevel::ADMIN).is_err());
        assert!(check_role_ceiling(RoleLevel::ADMIN, RoleLevel::OWNER).is_err());
        // A future intermediate role inherits the rule rather than slipping under it.
        assert!(check_role_ceiling(RoleLevel::new(150), RoleLevel::WRITE).is_ok());
        assert!(check_role_ceiling(RoleLevel::new(150), RoleLevel::new(150)).is_err());
        assert!(check_role_ceiling(RoleLevel::new(150), RoleLevel::ADMIN).is_err());
    }

    #[test]
    fn d39_the_denial_names_role_names_not_numbers() {
        let err = check_role_ceiling(RoleLevel::ADMIN, RoleLevel::OWNER).unwrap_err();
        assert_eq!(err.code(), "forbidden");
        let message = err.to_string();
        assert!(message.contains("your role admin manages only roles below admin"), "unexpected message: {message}");
        assert!(!message.contains("200") && !message.contains("250"), "numbers must not leak: {message}");
    }

    #[test]
    fn default_policy_matches_the_documented_defaults() {
        let policy = OrgPolicy::default();
        assert_eq!(policy.invitation_ttl, Duration::days(7));
    }

    /// **S-24.h.** The invitation budgets have exactly one source — the runtime settings
    /// section — and it is not this struct. A compile-time constant beside a settings row is
    /// two numbers that can disagree, and the one an operator edits would be the one that lost.
    #[test]
    fn s24_h_the_invitation_budgets_are_settings_not_policy_constants() {
        let defaults = pub_core::settings::RateLimitSettings::default();
        assert_eq!(defaults.invitations_per_day_org, 20, "the shipped org cap must survive the move");
        assert_eq!(defaults.invitations_per_day_actor, 10);
        // A compile-time assertion that `OrgPolicy` carries no budget any more: the struct is
        // built from its one remaining field, so re-adding one breaks this line.
        let _exhaustive = OrgPolicy { invitation_ttl: Duration::days(7) };
    }
}
