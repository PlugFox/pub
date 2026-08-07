//! Domain entity identifiers — UUID v7 newtypes (docs/rules/rust.md: UUID v7 for entities,
//! ULID for audit and stream events).
//!
//! Newtypes keep ids from different entities from being mixed up at compile time. The ULID
//! codec lives here too ([`ulid_generate`], [`ulid_canonical`]) because two id families need
//! it — [`crate::audit::AuditId`] and [`crate::event::EventId`] — and two copies of a base32
//! encoder is how their orderings would eventually disagree.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;

/// Crockford base32 alphabet (ULID spec): no I, L, O, U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Mints a fresh ULID string: UUID v7 bits (48-bit ms timestamp + random) in Crockford
/// base32, so lexicographic order equals numeric order equals millisecond time order.
///
/// That property is what makes a ULID usable as a keyset cursor *and* as an SSE
/// `Last-Event-ID`: ids minted on different instances still compare in time order.
pub fn ulid_generate() -> String {
    let n = u128::from_be_bytes(*Uuid::now_v7().as_bytes());
    let mut out = [0u8; 26];
    let mut rest = n;
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(rest & 0x1F) as usize];
        rest >>= 5;
    }
    // 26 chars hold 130 bits; the top 2 bits of a 128-bit value are always zero, so the loop
    // above consumed everything.
    String::from_utf8(out.to_vec()).expect("Crockford alphabet is ASCII")
}

/// Validates and canonicalizes (uppercases) a ULID string.
///
/// Rejects the wrong length, characters outside the Crockford alphabet, and values that would
/// overflow 128 bits. `what` names the id family in the error message.
pub fn ulid_canonical(raw: &str, what: &str) -> Result<String, Error> {
    let invalid = || Error::Invalid { message: format!("invalid {what}: {raw}") };
    if raw.len() != 26 {
        return Err(invalid());
    }
    let canonical: String = raw.to_ascii_uppercase();
    let mut n: u128 = 0;
    for byte in canonical.bytes() {
        let value = CROCKFORD.iter().position(|&c| c == byte).ok_or_else(invalid)? as u128;
        if n >> 123 != 0 {
            // The next shift would push significant bits past 128.
            return Err(invalid());
        }
        n = (n << 5) | value;
    }
    Ok(canonical)
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a fresh time-ordered (UUID v7) identifier.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID (e.g. loaded from storage).
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self).map_err(|err| Error::Invalid {
                    message: format!(concat!("invalid ", stringify!($name), ": {}"), err),
                })
            }
        }
    };
}

define_id!(
    /// Identifier of a user account.
    UserId
);
define_id!(
    /// Identifier of an organization.
    OrgId
);
define_id!(
    /// Identifier of a package — unique per `(format, name)` per instance.
    PackageId
);
define_id!(
    /// Identifier of an immutable published version.
    VersionId
);
define_id!(
    /// Identifier of a CLI/API token (the credential itself is stored only as a hash).
    TokenId
);
define_id!(
    /// Identifier of a web refresh session.
    SessionId
);
define_id!(
    /// Identifier of a credential row (polymorphic over [`crate::credential::CredentialType`]).
    CredentialId
);
define_id!(
    /// Identifier of an org invitation.
    InvitationId
);
define_id!(
    /// Identifier of one stored notification (decision 20 notification center).
    NotificationId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_uuid_v7() {
        assert_eq!(UserId::new().as_uuid().get_version_num(), 7);
        assert_eq!(PackageId::new().as_uuid().get_version_num(), 7);
    }

    #[test]
    fn ids_are_unique_and_time_ordered() {
        let a = OrgId::new();
        let b = OrgId::new();
        assert_ne!(a, b);
        // UUID v7 embeds a millisecond timestamp prefix: later ids never sort before earlier ones.
        assert!(a <= b);
    }

    #[test]
    fn display_parse_round_trip() {
        let id = SessionId::new();
        let parsed: SessionId = id.to_string().parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn garbage_input_is_invalid() {
        let err = "not-a-uuid".parse::<TokenId>().unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[test]
    fn serde_is_transparent() {
        let id = VersionId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<VersionId>(&json).unwrap(), id);
    }

    #[test]
    fn ulids_are_26_chars_and_time_ordered() {
        let first = ulid_generate();
        let second = ulid_generate();
        assert_eq!(first.len(), 26);
        assert!(first <= second, "{first} must not sort after {second}");
        assert_eq!(ulid_canonical(&first, "EventId").unwrap(), first);
    }

    #[test]
    fn ulid_parsing_rejects_every_malformed_shape() {
        for raw in ["", "short", &"Z".repeat(27), &"I".repeat(26), &"Z".repeat(26)] {
            assert!(ulid_canonical(raw, "EventId").is_err(), "accepted {raw:?}");
        }
        // Lowercase input canonicalizes rather than failing.
        let id = ulid_generate();
        assert_eq!(ulid_canonical(&id.to_lowercase(), "EventId").unwrap(), id);
    }
}
