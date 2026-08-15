//! Organizations, memberships, and invitations (decision 19).
//!
//! A membership carries a cumulative [`RoleLevel`]; every org keeps at least one Owner — the
//! invariant is enforced inside the repository implementations, transactionally, so no
//! sequence of role updates or removals can strand an org.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, InvitationId, OrgId, Result, RoleLevel, UserId};

/// Whether an org's virtual registry may fall through to the upstream proxy for names that
/// are unclaimed on this instance (decision 01, S-16).
///
/// Only the two terminal answers exist today. Decision 01 also names `delay` (quarantine a
/// freshly published upstream version for N hours) and `allowlist` (proxy only named
/// packages); both are *additional* variants of this enum rather than a different mechanism,
/// which is why the field and its enforcement point land now — retrofitting a policy column
/// onto orgs after the proxy is in production means a migration plus a behaviour change on a
/// live resolution path.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamPolicy {
    /// Unclaimed names resolve through the proxy (the default — decision 07 read-through).
    #[default]
    Allow,
    /// Unclaimed names never reach upstream: this org's registry serves local packages only.
    /// Reads of an unclaimed name answer the same 404 as an unknown one (S-04).
    Block,
}

impl UpstreamPolicy {
    /// Canonical lowercase name as stored and used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }

    /// Whether this policy permits an upstream lookup at all.
    pub const fn allows_upstream(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl std::fmt::Display for UpstreamPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UpstreamPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            other => Err(Error::Invalid { message: format!("unknown upstream policy: {other}") }),
        }
    }
}

/// An organization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    /// Entity id (UUID v7).
    pub id: OrgId,
    /// Human-readable display name.
    pub name: String,
    /// URL slug used in virtual registry bases (`/o/{slug}/pub`); unique case-insensitively.
    pub slug: String,
    /// Free-text description shown on the org profile; empty = none.
    pub description: String,
    /// Whether this org's registry may fall through to the upstream proxy (decision 01).
    pub upstream_policy: UpstreamPolicy,
    /// Per-org override of the instance storage quota in bytes; `None` = follow the instance
    /// default ([S-20.b](../../../docs/security.md#4-supply-chain--registry-integrity),
    /// [decision 32](../../../docs/decisions.md#32)).
    ///
    /// The `Option` is the point: "no override" and "unlimited" are different rows. The
    /// effective limit is `override ?? registry.storage_quota_bytes`, so an org left at `None`
    /// follows an instance default an operator changes later, while an org set to `0` keeps the
    /// instance default's spelling of "unlimited" whatever the default becomes.
    ///
    /// Deliberately **not** on [`OrgProfile`]: that payload is what `PATCH /api/v1/orgs/{slug}`
    /// writes, which an org Admin can reach, and a quota an org can raise for itself is not a
    /// quota (decision 32). It is set by an instance admin through
    /// [`crate::traits::OrgRepo::set_storage_quota`], the same shape
    /// [`crate::traits::OrgRepo::set_upstream_policy`] uses for the other policy field.
    pub storage_quota_bytes: Option<i64>,
    /// When the org was archived — the terminal state of a *forced* deletion, used when the
    /// org still owns packages and therefore cannot be erased (decision 06 keeps name claims
    /// and version rows alive forever). `None` = a normal, live org.
    ///
    /// An archived org has no members, no invitations, and no live tokens, and every package
    /// it owns was flipped private + unlisted + discontinued, so it serves nothing and
    /// discloses nothing — but its slug stays taken and its claims stay burned.
    pub archived_at: Option<DateTime<Utc>>,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Last update time (UTC).
    pub updated_at: DateTime<Utc>,
}

impl Org {
    /// Whether the org is archived (see [`Org::archived_at`]).
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }
}

/// Payload for creating an org (id and timestamps are assigned by the repo; the creator
/// becomes Owner in the same transaction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewOrg {
    /// Display name.
    pub name: String,
    /// URL slug; must be unique on the instance (case-insensitive).
    pub slug: String,
    /// Free-text description; empty = none.
    pub description: String,
    /// Initial upstream policy — the instance default from runtime settings (decision 09),
    /// not a hardcoded column default, so an operator who blocks upstream by policy does not
    /// have to re-block every new org.
    pub upstream_policy: UpstreamPolicy,
}

impl NewOrg {
    /// A new org with the default (empty) description and the default upstream policy.
    pub fn new(name: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            slug: slug.into(),
            description: String::new(),
            upstream_policy: UpstreamPolicy::default(),
        }
    }
}

/// The mutable profile fields of an org (`PATCH /api/v1/orgs/{slug}`).
///
/// A *replace* payload like [`crate::package::PackageOptions`], for the same reason: the API
/// layer resolves "unset field = keep current" against the loaded row, so the repository never
/// has to reason about partial updates.
///
/// [`Org::storage_quota_bytes`] is **not** here, and that is the security property rather than
/// an omission: this route is reachable by an org Admin, so a quota in this payload would be a
/// quota its subject can raise (decision 32). It moves through
/// [`crate::traits::OrgRepo::set_storage_quota`] from the instance-admin plane instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgProfile {
    /// Display name.
    pub name: String,
    /// Free-text description; empty = none.
    pub description: String,
    /// Upstream proxy policy (decision 01, S-16).
    pub upstream_policy: UpstreamPolicy,
}

impl From<&Org> for OrgProfile {
    fn from(org: &Org) -> Self {
        Self { name: org.name.clone(), description: org.description.clone(), upstream_policy: org.upstream_policy }
    }
}

/// One row of the admin org listing: the org plus the two numbers that decide whether it can
/// be deleted and who to talk to about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgOverview {
    /// The org.
    pub org: Org,
    /// How many members it has.
    pub members: i64,
    /// How many packages it owns (any visibility).
    pub packages: i64,
}

/// A membership row: one user's role in one org.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMember {
    /// The org.
    pub org_id: OrgId,
    /// The member.
    pub user_id: UserId,
    /// Cumulative role level (decision 19); always `> 0` — level 0 means "not a member" and
    /// is represented by the absence of a row.
    pub role: RoleLevel,
    /// When the membership was created (UTC).
    pub created_at: DateTime<Utc>,
    /// When the role last changed (UTC).
    pub updated_at: DateTime<Utc>,
}

/// An org together with the querying user's role in it (for "my orgs" listings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMembership {
    /// The org.
    pub org: Org,
    /// The user's role in it.
    pub role: RoleLevel,
}

/// An invitation to join an org, bound to an email address (S-06: defaults to Read).
///
/// The single-use invite token is never stored — only its SHA-256 hash. Lifecycle: pending →
/// accepted (`accepted_at`) | revoked (`revoked_at`) | expired (`expires_at` in the past).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    /// Entity id (UUID v7).
    pub id: InvitationId,
    /// Target org.
    pub org_id: OrgId,
    /// Email the invitation is bound to; only a user holding this verified email may accept.
    pub email: String,
    /// Role granted on acceptance.
    pub role: RoleLevel,
    /// User who sent the invitation.
    pub invited_by: UserId,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Expiry time (UTC); default 7 days from creation (docs/architecture.md).
    pub expires_at: DateTime<Utc>,
    /// When the invitation was accepted, if it was.
    pub accepted_at: Option<DateTime<Utc>>,
    /// Who accepted it.
    pub accepted_by: Option<UserId>,
    /// When the invitation was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Payload for creating an invitation (id and `created_at` are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewInvitation {
    /// Target org.
    pub org_id: OrgId,
    /// Email the invitation is bound to.
    pub email: String,
    /// Role granted on acceptance; [`NewInvitation::new`] defaults it to Read
    /// (least privilege — S-06).
    pub role: RoleLevel,
    /// User sending the invitation.
    pub invited_by: UserId,
    /// SHA-256 hex of the single-use invite token; the plaintext lives only in the invite
    /// email.
    pub token_hash: String,
    /// Expiry time (UTC).
    pub expires_at: DateTime<Utc>,
}

impl NewInvitation {
    /// Builds an invitation payload with the default Read role (S-06 least privilege).
    pub fn new(
        org_id: OrgId,
        email: impl Into<String>,
        invited_by: UserId,
        token_hash: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            org_id,
            email: email.into(),
            role: RoleLevel::READ,
            invited_by,
            token_hash: token_hash.into(),
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn new_invitation_defaults_to_read_role() {
        let expires = Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0).unwrap();
        let inv = NewInvitation::new(OrgId::new(), "dev@corp.com", UserId::new(), "hash", expires);
        assert_eq!(inv.role, RoleLevel::READ);
        assert_eq!(inv.expires_at, expires);
    }

    #[test]
    fn new_org_defaults_are_empty_description_and_allow() {
        let new = NewOrg::new("Acme", "acme");
        assert!(new.description.is_empty());
        assert_eq!(new.upstream_policy, UpstreamPolicy::Allow);
    }

    #[test]
    fn upstream_policy_round_trips_and_defaults_to_allow() {
        for policy in [UpstreamPolicy::Allow, UpstreamPolicy::Block] {
            assert_eq!(UpstreamPolicy::from_str(policy.as_str()).unwrap(), policy);
        }
        // Decision 07 ships the read-through proxy on by default; an org opts *out*.
        assert_eq!(UpstreamPolicy::default(), UpstreamPolicy::Allow);
        assert!(UpstreamPolicy::Allow.allows_upstream());
        assert!(!UpstreamPolicy::Block.allows_upstream());
        assert_eq!(UpstreamPolicy::from_str("delay").unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn upstream_policy_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&UpstreamPolicy::Block).unwrap(), "\"block\"");
        assert_eq!(serde_json::from_str::<UpstreamPolicy>("\"allow\"").unwrap(), UpstreamPolicy::Allow);
    }
}
