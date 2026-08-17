//! The account surface: what a person may read, change and destroy about **their own** account
//! ([S-29](../../../../docs/security.md#7-platform), [decision 39](../../../../docs/decisions.md#39--the-account-surface-one-me-the-client-can-trust-an-email-change-that-proves-both-addresses-an-export-that-streams-and-a-deletion-that-keeps-the-attribution-and-nothing-else)).
//!
//! It lives beside [`OrgService`](crate::OrgService) for that module's reasons, both of which
//! apply here more sharply than anywhere else in the codebase:
//!
//! - **Deletion needs more than one repository and has an order.** Sessions, CLI tokens,
//!   credentials, memberships, notifications and the user row all have to go, in a sequence where
//!   two of the steps are load-bearing for reasons a handler author cannot be expected to know
//!   (see [`AccountService::delete`]). A route that assembled this itself would be correct on the
//!   day it was written.
//! - **Every mutation is audited**, and an account deletion is the one audit row that outlives
//!   the account it describes.
//!
//! The email change is deliberately **not** here: it is an OTP flow with a pending record, a
//! pepper and an attempt budget, and those belong to
//! [`AuthService`](pub_auth::flows::AuthService) where the sign-in code's identical machinery
//! already lives. Splitting it would have meant a second implementation of S-03's budget.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pub_auth::flows::{AuthService, ClientMeta};
use pub_core::audit::{AuditActor, AuditEvent, AuditFilter, AuditResult, NewAuditEvent};
use pub_core::notification::{Notification, NotificationPreference};
use pub_core::org::{Org, OrgMembership};
use pub_core::session::Session;
use pub_core::token::Token;
use pub_core::traits::Repositories;
use pub_core::user::{User, UserStatus};
use pub_core::{Error, Page, Result, RoleLevel, UserId};

use crate::ActorMeta;
use crate::orgs::OrgService;

/// Longest display name an account may carry.
///
/// A bound rather than a policy: the name is rendered in member tables, package pages and
/// notification titles, and the only thing an unbounded one buys is a way to make those
/// unreadable for everybody else. Eighty characters is past every real name and short of a
/// paragraph.
pub const MAX_DISPLAY_NAME: usize = 80;

/// How many notification or audit rows one export page carries.
///
/// Larger than the interactive page sizes because nobody is reading these one screen at a time,
/// and small enough that the walker's bounded channel holds a page rather than a table.
pub const EXPORT_PAGE: u32 = 200;

/// The caller's own account, plus the one credential fact that has no other home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProfile {
    /// The account row.
    pub user: User,
    /// Whether a TOTP second factor is enrolled (S-05).
    ///
    /// A **read**, not a claim: the access token deliberately carries no such field (S-07), and
    /// before this existed the account screen tracked enrollment in a session-local flag that was
    /// wrong for every device except the one that enrolled.
    pub totp_enabled: bool,
}

/// Everything an export carries that is bounded by the account rather than by a window.
#[derive(Debug, Clone)]
pub struct AccountSnapshot {
    /// The profile, including the TOTP fact.
    pub profile: AccountProfile,
    /// The caller's org memberships — their own row in each org, never the roster.
    pub memberships: Vec<OrgMembership>,
    /// Live sessions (S-10).
    pub sessions: Vec<Session>,
    /// CLI tokens as metadata; the hash is not in the type and cannot be exported.
    pub tokens: Vec<Token>,
    /// Stored notification preferences (categories never touched are absent).
    pub preferences: Vec<NotificationPreference>,
}

/// What a deletion actually removed — every figure is a count the caller can be shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountDeletion {
    /// Sessions revoked (S-09).
    pub sessions_revoked: u64,
    /// CLI tokens revoked (S-13).
    pub tokens_revoked: u64,
    /// Credential rows deleted — OIDC links, the email identity, the second factor.
    pub credentials_deleted: u64,
    /// Notification and preference rows deleted.
    pub notifications_deleted: u64,
    /// Organizations the account was removed from.
    pub memberships_removed: u64,
}

/// The account service. See the module docs for why it is a service rather than a handler.
pub struct AccountService {
    repos: Repositories,
    auth: Arc<AuthService>,
    orgs: Arc<OrgService>,
}

impl std::fmt::Debug for AccountService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountService").finish_non_exhaustive()
    }
}

impl AccountService {
    /// Builds the service over the configured backends.
    pub fn new(repos: Repositories, auth: Arc<AuthService>, orgs: Arc<OrgService>) -> Self {
        Self { repos, auth, orgs }
    }

    // ------------------------------------------------------------------------------ profile

    /// The caller's account plus whether a second factor is enrolled.
    pub async fn profile(&self, user: UserId) -> Result<AccountProfile> {
        let account =
            self.repos.users.get(user).await?.ok_or_else(|| Error::NotFound { what: "account".to_owned() })?;
        let totp_enabled = self.repos.credentials.find_totp(user).await?.is_some();
        Ok(AccountProfile { user: account, totp_enabled })
    }

    /// Renames the account.
    ///
    /// The email is **not** changeable here — it moves through the S-03.b confirmation flow, and
    /// a combined "update profile" call is exactly how a change that needs a proof would come to
    /// share a path with one that does not.
    pub async fn rename(&self, user: &User, display_name: &str, actor: &ActorMeta, now: DateTime<Utc>) -> Result<User> {
        let name = validate_display_name(display_name)?;
        let updated = self.repos.users.update_profile(user.id, &name, now).await?;
        self.audit(
            actor,
            "account.profile",
            Some(user.id.to_string()),
            AuditResult::Success,
            serde_json::json!({ "before": user.display_name, "after": name }),
            now,
        )
        .await;
        Ok(updated)
    }

    // ------------------------------------------------------------------------------- export

    /// The bounded half of an export: everything that fits in one round of reads.
    pub async fn snapshot(&self, user: UserId) -> Result<AccountSnapshot> {
        Ok(AccountSnapshot {
            profile: self.profile(user).await?,
            memberships: self.repos.orgs.list_for_user(user).await?,
            sessions: self.repos.sessions.list_for_user(user).await?,
            tokens: self.repos.tokens.list_for_user(user).await?,
            preferences: self.repos.notifications.preferences(user).await?,
        })
    }

    /// One page of the caller's notification feed, newest first.
    pub async fn export_notifications_page(&self, user: UserId, cursor: Option<&str>) -> Result<Page<Notification>> {
        self.repos.notifications.list(user, false, cursor, EXPORT_PAGE).await
    }

    /// One page of the audit rows whose **actor** is the caller, newest first.
    ///
    /// Only the `user` actor kind: a CLI token's rows belong to the token's audit identity, and
    /// this walk keys on the account. The predicate is what migration 0018's index serves —
    /// without it this is a full scan of the largest table in the instance, once per page.
    pub async fn export_audit_page(&self, user: UserId, cursor: Option<&str>) -> Result<Page<AuditEvent>> {
        let filter = AuditFilter { actor: Some(AuditActor::User(user)), ..AuditFilter::default() };
        self.repos.audit.list(&filter, cursor, EXPORT_PAGE).await
    }

    // ----------------------------------------------------------------------------- deletion

    /// The organizations this account is the **last Owner** of.
    ///
    /// Empty means a deletion can proceed. The repositories refuse to strand an org
    /// transactionally either way — this read exists so the refusal can name what is in the way
    /// instead of failing on the third of five steps.
    pub async fn blocking_orgs(&self, user: UserId) -> Result<Vec<Org>> {
        let mut blocking = Vec::new();
        for membership in self.repos.orgs.list_for_user(user).await? {
            if membership.role != RoleLevel::OWNER {
                continue;
            }
            let owners = self
                .repos
                .orgs
                .list_members(membership.org.id)
                .await?
                .into_iter()
                .filter(|member| member.role == RoleLevel::OWNER)
                .count();
            if owners <= 1 {
                blocking.push(membership.org);
            }
        }
        Ok(blocking)
    }

    /// Deletes the account: erases the identity, keeps the attribution
    /// ([S-29.a](../../../../docs/security.md#7-platform)).
    ///
    /// **Immediate and irreversible.** There is no pending state and no undo — the caller proved
    /// a second factor and typed their own address, and that is the whole of the protection
    /// (decision 39, taken by the owner).
    ///
    /// The order is normative and two steps in it are not obvious:
    ///
    /// - **Credentials are deleted, all of them.** The sign-in paths resolve a known `(iss, sub)`
    ///   to its user and then require `status == Active`, so an OIDC row left on a tombstone binds
    ///   that identity to a dead account *permanently*: the same person coming back through the
    ///   same provider is refused, and no screen in the product can explain why.
    /// - **Memberships are removed through [`OrgService`], not through the repository.** That is
    ///   what makes each removal audited and each org's members told through
    ///   `OrgMembershipChanged`; a direct repository call would leave the other members watching a
    ///   row disappear with no event.
    ///
    /// Two refusals come **before** anything is touched: the caller may not be the last owner of
    /// an organization, and may not be the last instance administrator (anonymization drops that
    /// flag, and an instance without one hands it to whoever registers next).
    ///
    /// A failure part-way leaves an account that is signed out and has no credentials but still
    /// holds its address — recoverable by retrying, and deliberately preferred to the alternative
    /// ordering, where an anonymized row could still be reachable through a live session.
    pub async fn delete(&self, user: &User, actor: &ActorMeta, now: DateTime<Utc>) -> Result<AccountDeletion> {
        // The instance's own last-owner rule, and it exists for a sharper reason than the org
        // one. Anonymization drops the instance-admin flag, so deleting the only administrator
        // would leave an instance with none — and `claim_first_admin` hands the flag to the next
        // account that registers. On an open-registration instance that is a takeover waiting for
        // somebody to notice, arrived at by an action a person took about *their own* account.
        if user.is_instance_admin && self.repos.users.counts().await?.admins <= 1 {
            self.audit(
                actor,
                "account.deleted",
                Some(user.id.to_string()),
                AuditResult::Failure,
                serde_json::json!({ "reason": "last_instance_admin" }),
                now,
            )
            .await;
            return Err(Error::Conflict {
                message: "you are the last instance administrator: promote somebody else first".to_owned(),
            });
        }

        let blocking = self.blocking_orgs(user.id).await?;
        if !blocking.is_empty() {
            let slugs: Vec<&str> = blocking.iter().map(|org| org.slug.as_str()).collect();
            self.audit(
                actor,
                "account.deleted",
                Some(user.id.to_string()),
                AuditResult::Failure,
                serde_json::json!({ "reason": "last_owner", "orgs": slugs }),
                now,
            )
            .await;
            return Err(Error::Conflict {
                message: format!(
                    "you are the last owner of {}: transfer ownership or delete {} first",
                    slugs.join(", "),
                    if slugs.len() == 1 { "it" } else { "them" },
                ),
            });
        }

        let meta = ClientMeta { ip: actor.ip.clone(), user_agent: actor.user_agent.clone() };
        let mut outcome = AccountDeletion {
            sessions_revoked: self.auth.revoke_all_sessions(user.id, &meta, now).await?,
            ..AccountDeletion::default()
        };

        // Best-effort past this point in the same sense the D37 sweep is: the credential plane is
        // already gone by the time a per-token failure could happen, so aborting would report a
        // deletion that mostly happened as one that did not.
        for token in self.repos.tokens.list_for_user(user.id).await? {
            match self.repos.tokens.revoke(token.id, now).await {
                Ok(()) => outcome.tokens_revoked += 1,
                Err(error) => tracing::warn!(%error, token = %token.id, "revoking a token during account deletion"),
            }
        }
        outcome.credentials_deleted = self.repos.credentials.delete_all_for_user(user.id).await?;

        for membership in self.repos.orgs.list_for_user(user.id).await? {
            // Self-removal at any role: the D39 ceiling carve-out, and the ≥1-Owner invariant
            // still holds because `blocking_orgs` refused every org where it would not.
            //
            // **Fatal, unlike the token sweep above.** `blocking_orgs` is a read, so a co-owner
            // who leaves between that read and this write turns this call into a `last_owner`
            // refusal — and continuing past it would anonymize an account that is still an org's
            // only Owner, stranding the org under a tombstone nobody can sign in as. Aborting
            // here leaves an account that is signed out and credential-less but still identifiable,
            // which the caller resolves by transferring ownership and asking again: the loop
            // re-reads the memberships, so a retry sees only what is left.
            self.orgs.remove_member(&membership.org, user.id, membership.role, actor, now).await?;
            outcome.memberships_removed += 1;
        }
        outcome.notifications_deleted = self.repos.notifications.delete_for_user(user.id).await?;

        // Last, because everything above needs the account to still be identifiable.
        self.repos.users.update_status(user.id, UserStatus::Deleted, now).await?;
        self.audit(
            actor,
            "account.deleted",
            Some(user.id.to_string()),
            AuditResult::Success,
            serde_json::json!({
                "sessions_revoked": outcome.sessions_revoked,
                "tokens_revoked": outcome.tokens_revoked,
                "credentials_deleted": outcome.credentials_deleted,
                "memberships_removed": outcome.memberships_removed,
                "notifications_deleted": outcome.notifications_deleted,
            }),
            now,
        )
        .await;
        Ok(outcome)
    }

    // ---------------------------------------------------------------------------- internals

    async fn audit(
        &self,
        actor: &ActorMeta,
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
            org_id: None,
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

/// Trims and bounds a display name.
///
/// Control characters are refused rather than stripped: a name is shown next to other people's
/// names, and silently rewriting somebody's input is how a caller learns their name is "wrong"
/// only by looking at a member table later.
fn validate_display_name(raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(Error::Invalid { message: "a display name cannot be empty".to_owned() });
    }
    if name.chars().count() > MAX_DISPLAY_NAME {
        return Err(Error::Invalid { message: format!("a display name may be at most {MAX_DISPLAY_NAME} characters") });
    }
    if name.chars().any(char::is_control) {
        return Err(Error::Invalid { message: "a display name cannot contain control characters".to_owned() });
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_display_name_is_trimmed_bounded_and_free_of_control_characters() {
        assert_eq!(validate_display_name("  Alice  ").unwrap(), "Alice");
        assert_eq!(validate_display_name("").unwrap_err().code(), "invalid_argument");
        assert_eq!(validate_display_name("   ").unwrap_err().code(), "invalid_argument");
        assert_eq!(validate_display_name("a\u{7}b").unwrap_err().code(), "invalid_argument");
        // The bound counts characters rather than bytes: a name of eighty non-ASCII letters is a
        // name, and refusing it because UTF-8 spends more bytes on it would be a locale tax.
        let cyrillic = "я".repeat(MAX_DISPLAY_NAME);
        assert_eq!(validate_display_name(&cyrillic).unwrap().chars().count(), MAX_DISPLAY_NAME);
        assert_eq!(validate_display_name(&"x".repeat(MAX_DISPLAY_NAME + 1)).unwrap_err().code(), "invalid_argument");
    }
}
