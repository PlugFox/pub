//! Domain entity identifiers — UUID v7 newtypes (docs/rules/rust.md: UUID v7 for entities,
//! ULID for audit events).
//!
//! Newtypes keep ids from different entities from being mixed up at compile time.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;

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
}
