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
    /// Whether this org's registry may fall through to the upstream proxy (decision 01).
    pub upstream_policy: UpstreamPolicy,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Last update time (UTC).
    pub updated_at: DateTime<Utc>,
}

/// Payload for creating an org (id and timestamps are assigned by the repo; the creator
/// becomes Owner in the same transaction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewOrg {
    /// Display name.
    pub name: String,
    /// URL slug; must be unique on the instance (case-insensitive).
    pub slug: String,
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
