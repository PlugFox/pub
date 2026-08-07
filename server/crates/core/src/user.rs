//! User accounts: profile and lifecycle status.
//!
//! Identity credentials (OIDC, email OTP, TOTP, …) live in [`crate::credential`]; a user row
//! carries only the profile. Account deletion keeps an anonymized row (S-29) — versions the
//! user published must stay attributable to *something* for supply-chain integrity.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, UserId};

/// Lifecycle status of a user account.
///
/// Stored and serialized as a lowercase string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// Normal, usable account.
    Active,
    /// Sign-in disabled by an admin; data intact.
    Suspended,
    /// Deleted/anonymized (S-29): profile erased, row kept as an attribution tombstone.
    Deleted,
}

impl UserStatus {
    /// Canonical lowercase name as stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UserStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "deleted" => Ok(Self::Deleted),
            other => Err(Error::Invalid { message: format!("unknown user status: {other}") }),
        }
    }
}

/// A user account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Entity id (UUID v7).
    pub id: UserId,
    /// Email address; `None` after anonymization. Unique case-insensitively across accounts.
    pub email: Option<String>,
    /// Whether the email was verified (OIDC `email_verified=true` or a completed OTP).
    /// Only verified emails participate in lookups and account linking (S-01/S-02).
    pub email_verified: bool,
    /// Display name shown in UIs; blanked on anonymization.
    pub display_name: String,
    /// Lifecycle status.
    pub status: UserStatus,
    /// Whether this account administers the **instance** (not an org role — decision 19's
    /// ladder and this flag are orthogonal planes; see [`crate::authorize`]).
    ///
    /// Lives on the row rather than in the access token on purpose: the admin routes read it
    /// per request, so a demotion is effective immediately and [S-07](../../../docs/security.md)
    /// keeps claims to `sub`/`sid`/org levels/timestamps.
    pub is_instance_admin: bool,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Last profile/status update time (UTC).
    pub updated_at: DateTime<Utc>,
}

/// Instance-wide account counts for the admin dashboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCounts {
    /// Every account row, anonymized tombstones included.
    pub total: i64,
    /// Accounts that can sign in.
    pub active: i64,
    /// Accounts an admin has suspended.
    pub suspended: i64,
    /// Anonymized deletion tombstones (S-29).
    pub deleted: i64,
    /// Accounts carrying the instance-admin flag.
    pub admins: i64,
}

/// Filters for the admin user listing; fields combine with AND.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserFilter {
    /// Case-insensitive substring of the email or display name.
    pub query: Option<String>,
    /// Only accounts in this lifecycle status.
    pub status: Option<UserStatus>,
    /// Only accounts carrying the instance-admin flag.
    pub admins_only: bool,
}

/// Payload for creating a user account (id, status, and timestamps are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewUser {
    /// Email address, if known at creation time.
    pub email: Option<String>,
    /// Whether the email arrives already verified (e.g. from OIDC with `email_verified=true`).
    pub email_verified: bool,
    /// Initial display name.
    pub display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_from_str() {
        for status in [UserStatus::Active, UserStatus::Suspended, UserStatus::Deleted] {
            assert_eq!(status.as_str().parse::<UserStatus>().unwrap(), status);
        }
    }

    #[test]
    fn unknown_status_is_invalid() {
        assert_eq!("gone".parse::<UserStatus>().unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn serde_uses_lowercase() {
        assert_eq!(serde_json::to_string(&UserStatus::Deleted).unwrap(), "\"deleted\"");
        assert_eq!(serde_json::from_str::<UserStatus>("\"active\"").unwrap(), UserStatus::Active);
    }
}
