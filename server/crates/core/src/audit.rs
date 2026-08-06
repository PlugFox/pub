//! Append-only audit log types (S-22, S-23).
//!
//! Events carry ULID ids (docs/rules/rust.md): time-ordered, lexicographically sortable text —
//! which makes the id itself the keyset-pagination cursor, stable even across events sharing a
//! timestamp. Ids are minted from UUID v7 bytes (48-bit ms timestamp + random) re-encoded as
//! Crockford base32, so no extra dependency is needed and ordering matches the other entity ids.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, OrgId, TokenId, UserId};

/// Crockford base32 alphabet (ULID spec): no I, L, O, U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// ULID identifier of an audit event: 26 Crockford-base32 chars over 128 bits.
///
/// Lexicographic order equals numeric order equals (millisecond) time order — the audit list
/// is sorted and paginated by this id alone.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditId(String);

impl AuditId {
    /// Mints a fresh time-ordered id (UUID v7 bits, ULID encoding).
    pub fn generate() -> Self {
        let n = u128::from_be_bytes(*uuid::Uuid::now_v7().as_bytes());
        let mut out = [0u8; 26];
        let mut rest = n;
        for slot in out.iter_mut().rev() {
            *slot = CROCKFORD[(rest & 0x1F) as usize];
            rest >>= 5;
        }
        // 26 chars hold 130 bits; the top 2 bits of a 128-bit value are always zero, so the
        // loop above consumed everything.
        Self(String::from_utf8(out.to_vec()).expect("Crockford alphabet is ASCII"))
    }

    /// The id as its canonical 26-char uppercase string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AuditId {
    type Err = Error;

    /// Parses and canonicalizes (uppercases) a ULID string; rejects wrong length, characters
    /// outside the Crockford alphabet, and values that overflow 128 bits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || Error::Invalid { message: format!("invalid ULID: {s}") };
        if s.len() != 26 {
            return Err(invalid());
        }
        let canonical: String = s.to_ascii_uppercase();
        let mut n: u128 = 0;
        for byte in canonical.bytes() {
            let value = CROCKFORD.iter().position(|&c| c == byte).ok_or_else(invalid)? as u128;
            if n >> 123 != 0 {
                // The next shift would push significant bits past 128.
                return Err(invalid());
            }
            n = (n << 5) | value;
        }
        Ok(Self(canonical))
    }
}

/// Who performed an audited action (S-22: user | token | system).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum AuditActor {
    /// An authenticated user (web session plane).
    User(UserId),
    /// A CLI/API token (token plane).
    Token(TokenId),
    /// The system itself (background jobs, startup tasks).
    System,
}

impl AuditActor {
    /// Storage discriminator: `user` | `token` | `system`.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Token(_) => "token",
            Self::System => "system",
        }
    }

    /// Storage id column value; `None` for the system actor.
    pub fn id_string(&self) -> Option<String> {
        match self {
            Self::User(id) => Some(id.to_string()),
            Self::Token(id) => Some(id.to_string()),
            Self::System => None,
        }
    }
}

/// Outcome of an audited action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    /// The action succeeded.
    Success,
    /// The action failed (auth failure, throttle trip, rejected invariant, …).
    Failure,
}

impl AuditResult {
    /// Canonical lowercase name as stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

impl FromStr for AuditResult {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            other => Err(Error::Invalid { message: format!("unknown audit result: {other}") }),
        }
    }
}

/// A recorded audit event. Never contains secrets, full tokens, or OTP codes (S-22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ULID id — also the pagination cursor.
    pub id: AuditId,
    /// Event time (UTC).
    pub created_at: DateTime<Utc>,
    /// Acting principal.
    pub actor: AuditActor,
    /// Client IP, when the action came from a request.
    pub ip: Option<String>,
    /// Coarse user agent, when the action came from a request.
    pub user_agent: Option<String>,
    /// Org context, when the action is org-scoped.
    pub org_id: Option<OrgId>,
    /// Dot-namespaced action, e.g. `org.member.add`, `auth.login.otp`.
    pub action: String,
    /// Target of the action (entity id, package name, …).
    pub target: Option<String>,
    /// Outcome.
    pub result: AuditResult,
    /// Structured before/after context.
    pub metadata: Option<serde_json::Value>,
}

/// Payload for appending an audit event (id is minted by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAuditEvent {
    /// Acting principal.
    pub actor: AuditActor,
    /// Client IP.
    pub ip: Option<String>,
    /// Coarse user agent.
    pub user_agent: Option<String>,
    /// Org context.
    pub org_id: Option<OrgId>,
    /// Dot-namespaced action.
    pub action: String,
    /// Target of the action.
    pub target: Option<String>,
    /// Outcome.
    pub result: AuditResult,
    /// Structured before/after context.
    pub metadata: Option<serde_json::Value>,
}

impl NewAuditEvent {
    /// Minimal successful event: actor + action; the optional context defaults to empty.
    pub fn new(actor: AuditActor, action: impl Into<String>) -> Self {
        Self {
            actor,
            ip: None,
            user_agent: None,
            org_id: None,
            action: action.into(),
            target: None,
            result: AuditResult::Success,
            metadata: None,
        }
    }
}

/// Filters for listing audit events; every field is optional and they combine with AND.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Only events in this org.
    pub org: Option<OrgId>,
    /// Only events whose action starts with this prefix (e.g. `org.member.`).
    pub action_prefix: Option<String>,
    /// Only events by this exact actor.
    pub actor: Option<AuditActor>,
    /// Only events at or after this time (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Only events before this time (exclusive) — half-open `[from, until)`.
    pub until: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_valid_sortable_ulids() {
        let a = AuditId::generate();
        let b = AuditId::generate();
        assert_eq!(a.as_str().len(), 26);
        assert!(a.as_str().bytes().all(|c| CROCKFORD.contains(&c)));
        assert_ne!(a, b);
        // UUID v7 ms-timestamp prefix: later ids never sort before earlier ones.
        assert!(a <= b);
        // Round trip through parsing.
        assert_eq!(a.as_str().parse::<AuditId>().unwrap(), a);
    }

    #[test]
    fn parse_canonicalizes_lowercase() {
        let id = AuditId::generate();
        let parsed: AuditId = id.as_str().to_ascii_lowercase().parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in ["", "short", "0123456789012345678901234!", &"8".repeat(26), &"z".repeat(27)] {
            assert!(bad.parse::<AuditId>().is_err(), "accepted {bad:?}");
        }
        // First char `8` would need 131 bits — overflow (max valid first char is `7`).
        assert!("8ZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<AuditId>().is_err());
        // All-`7` is the 128-bit maximum and parses fine.
        assert!("7ZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<AuditId>().is_ok());
    }

    #[test]
    fn actor_kind_and_id_map_to_storage_columns() {
        let user = UserId::new();
        assert_eq!(AuditActor::User(user).kind(), "user");
        assert_eq!(AuditActor::User(user).id_string(), Some(user.to_string()));
        assert_eq!(AuditActor::System.kind(), "system");
        assert_eq!(AuditActor::System.id_string(), None);
    }
}
