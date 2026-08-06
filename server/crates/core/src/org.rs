//! Organizations, memberships, and invitations (decision 19).
//!
//! A membership carries a cumulative [`RoleLevel`]; every org keeps at least one Owner — the
//! invariant is enforced inside the repository implementations, transactionally, so no
//! sequence of role updates or removals can strand an org.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{InvitationId, OrgId, RoleLevel, UserId};

/// An organization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    /// Entity id (UUID v7).
    pub id: OrgId,
    /// Human-readable display name.
    pub name: String,
    /// URL slug used in virtual registry bases (`/o/{slug}/pub`); unique case-insensitively.
    pub slug: String,
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
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn new_invitation_defaults_to_read_role() {
        let expires = Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0).unwrap();
        let inv = NewInvitation::new(OrgId::new(), "dev@corp.com", UserId::new(), "hash", expires);
        assert_eq!(inv.role, RoleLevel::READ);
        assert_eq!(inv.expires_at, expires);
    }
}
