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

/// The stored second-factor material of an active TOTP enrollment (S-05).
///
/// This is the one struct that carries `secret_enc` out of the repository — the seed sealed
/// with the env KEK (AES-GCM), never plaintext. [`Debug`] is hand-written so even the
/// ciphertext stays out of log lines (S-25: secret-bearing structs redact by type).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCredential {
    /// Credential row id.
    pub id: CredentialId,
    /// Owning user.
    pub user_id: UserId,
    /// KEK-sealed TOTP seed (nonce-prefixed AES-256-GCM ciphertext).
    pub secret_enc: Vec<u8>,
    /// Highest time-step a code was ever accepted at — replay floor (S-05).
    pub last_step: Option<i64>,
}

impl std::fmt::Debug for TotpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCredential")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("secret_enc", &"<redacted>")
            .field("last_step", &self.last_step)
            .finish()
    }
}

/// One stored recovery-code hash (S-05): the argon2id PHC string plus the row id used to
/// consume it atomically on successful use.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCodeHash {
    /// Credential row id (deleted when the code is spent — single-use).
    pub id: CredentialId,
    /// argon2id PHC string of the plaintext code.
    pub phc: String,
}

impl std::fmt::Debug for RecoveryCodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The PHC hash is not directly reversible, but it is still offline-attackable
        // material — keep it out of logs like every other credential secret (S-25).
        f.debug_struct("RecoveryCodeHash").field("id", &self.id).field("phc", &"<redacted>").finish()
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
