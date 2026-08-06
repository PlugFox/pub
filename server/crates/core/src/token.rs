//! CLI/API tokens (decision 13, S-13): the second credential plane, fully separate from web
//! sessions.
//!
//! Tokens are opaque `<prefix>_…` strings; only the SHA-256 hash and a first-8-chars display
//! hint are stored. Scopes are the fine-grained, non-linear permission plane next to the
//! linear org role ladder (decision 19).

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, OrgId, TokenId, UserId};

/// Token scope. Stored and serialized as a lowercase string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    /// Resolve and download packages.
    Read,
    /// Publish new versions.
    Publish,
    /// Retract / unretract versions.
    Retract,
    /// Org administration through the REST API (CI automation).
    Admin,
}

impl TokenScope {
    /// Canonical lowercase name as stored and used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Publish => "publish",
            Self::Retract => "retract",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenScope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "publish" => Ok(Self::Publish),
            "retract" => Ok(Self::Retract),
            "admin" => Ok(Self::Admin),
            other => Err(Error::Invalid { message: format!("unknown token scope: {other}") }),
        }
    }
}

/// A CLI/API token. The hash is deliberately not exposed on the domain struct — lookups go
/// through hash-keyed repository methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// Entity id (UUID v7).
    pub id: TokenId,
    /// User the token acts as.
    pub user_id: UserId,
    /// Org the token is bound to (S-13: tokens are org-bound).
    pub org_id: OrgId,
    /// User-chosen label ("CI deploy", …).
    pub name: String,
    /// First 8 characters of the plaintext, for the token list UI (S-13 display hint).
    pub display_hint: String,
    /// Granted scopes; never empty.
    pub scopes: Vec<TokenScope>,
    /// Optional package-name patterns narrowing the token further; empty = every package the
    /// org binding allows.
    pub package_patterns: Vec<String>,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Expiry (UTC); `None` = non-expiring (allowed only for pure-`read` tokens — S-13,
    /// enforced by the token-mint flow, not the repo).
    pub expires_at: Option<DateTime<Utc>>,
    /// Last use (UTC), write-throttled (S-13).
    pub last_used_at: Option<DateTime<Utc>>,
    /// IP of the last use, write-throttled together with `last_used_at`.
    pub last_used_ip: Option<String>,
    /// Revocation time; revoked tokens never authenticate again.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Payload for minting a token (id and `created_at` are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewToken {
    /// User the token acts as.
    pub user_id: UserId,
    /// Org binding.
    pub org_id: OrgId,
    /// User-chosen label.
    pub name: String,
    /// SHA-256 hex of the plaintext token (S-13; plaintext is shown once and never stored).
    pub token_hash: String,
    /// First 8 characters of the plaintext.
    pub display_hint: String,
    /// Granted scopes; must not be empty.
    pub scopes: Vec<TokenScope>,
    /// Optional package-name patterns; empty = no narrowing.
    pub package_patterns: Vec<String>,
    /// Expiry (UTC), if any.
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_round_trips_through_from_str() {
        for scope in [TokenScope::Read, TokenScope::Publish, TokenScope::Retract, TokenScope::Admin] {
            assert_eq!(scope.as_str().parse::<TokenScope>().unwrap(), scope);
        }
    }

    #[test]
    fn unknown_scope_is_invalid() {
        assert_eq!("delete".parse::<TokenScope>().unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn serde_uses_lowercase() {
        assert_eq!(
            serde_json::to_string(&vec![TokenScope::Read, TokenScope::Publish]).unwrap(),
            r#"["read","publish"]"#
        );
    }
}
