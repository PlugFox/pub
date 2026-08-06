//! Credentials: one polymorphic table over every way a user can prove identity
//! (docs/architecture.md data model; decision 12).
//!
//! The type enum is modeled in full now — `totp`, `recovery`, and `webauthn` rows arrive with
//! their auth flows; only `oidc` and `email` have repository methods in this phase. Secret
//! material (encrypted TOTP seeds, hashed recovery codes) is a storage concern of the
//! implementation crates and is never exposed on the domain struct.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{CredentialId, Error, UserId};

/// Kind of credential. Stored and serialized as a lowercase string.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// OIDC identity, keyed by `(issuer, subject)` — never by email (S-01).
    Oidc,
    /// Email identity used by the OTP sign-in path.
    Email,
    /// TOTP authenticator-app second factor (S-05); seed encrypted with the env KEK.
    Totp,
    /// Single-use recovery code (argon2id hash at rest).
    Recovery,
    /// WebAuthn/passkey (schema-prepared; targeted at v1.1).
    Webauthn,
}

impl CredentialType {
    /// Canonical lowercase name as stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Email => "email",
            Self::Totp => "totp",
            Self::Recovery => "recovery",
            Self::Webauthn => "webauthn",
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CredentialType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(Self::Oidc),
            "email" => Ok(Self::Email),
            "totp" => Ok(Self::Totp),
            "recovery" => Ok(Self::Recovery),
            "webauthn" => Ok(Self::Webauthn),
            other => Err(Error::Invalid { message: format!("unknown credential type: {other}") }),
        }
    }
}

/// A credential row. Which optional fields are set depends on [`Credential::credential_type`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Entity id (UUID v7).
    pub id: CredentialId,
    /// Owning user.
    pub user_id: UserId,
    /// Discriminator for the polymorphic fields.
    pub credential_type: CredentialType,
    /// OIDC issuer URL (`oidc` only).
    pub issuer: Option<String>,
    /// OIDC subject claim (`oidc` only).
    pub subject: Option<String>,
    /// Email address this identity is bound to (`email` only).
    pub email: Option<String>,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Last update time (UTC) — e.g. refreshed on every OIDC sign-in.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_round_trips_through_from_str() {
        for ty in [
            CredentialType::Oidc,
            CredentialType::Email,
            CredentialType::Totp,
            CredentialType::Recovery,
            CredentialType::Webauthn,
        ] {
            assert_eq!(ty.as_str().parse::<CredentialType>().unwrap(), ty);
        }
    }

    #[test]
    fn unknown_type_is_invalid() {
        assert_eq!("password".parse::<CredentialType>().unwrap_err().code(), "invalid_argument");
    }
}
