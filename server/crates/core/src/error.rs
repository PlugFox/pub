//! Top-level domain error (decision 16).
//!
//! Every error carries a stable machine-readable [`Error::code`]; HTTP mapping lives in the
//! `api` crate via `IntoResponse`. Never match on error message strings.

/// Top-level error type shared across the workspace.
///
/// Infrastructure crates map their native errors into these variants at the boundary, so
/// consumers only ever see domain errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid or inconsistent configuration.
    #[error("configuration error: {message}")]
    Config { message: String },
    /// Invalid input supplied by a caller (bad identifier, unknown format, malformed value).
    #[error("invalid argument: {message}")]
    Invalid { message: String },
    /// The requested resource does not exist (or is not visible to the caller — decision 05).
    #[error("not found: {what}")]
    NotFound { what: String },
    /// State or unique-constraint conflict: duplicate email/slug/hash, double-accepted
    /// invitation, membership that already exists.
    #[error("conflict: {message}")]
    Conflict { message: String },
    /// The actor lacks the required role or scope on a resource it can see (decision 19).
    /// The API layer decides whether this surfaces as 403 or 404 (decision 05 ladder).
    #[error("forbidden: {message}")]
    Forbidden { message: String },
    /// The resource exists but its validity window has passed (invitation, session, token).
    #[error("expired: {what}")]
    Expired { what: String },
    /// The operation would leave the org without any Owner — every org keeps at least one
    /// Owner (decision 19 invariant, enforced repo-side).
    #[error("operation would leave org {org} without an owner")]
    LastOwner { org: crate::OrgId },
    /// A rotated-out refresh hash was presented again — possible token theft (S-08).
    /// The caller must revoke the whole session family.
    #[error("refresh token reuse detected for session {session}")]
    RefreshReused { session: crate::SessionId },
    /// Database backend failure.
    #[error("database error: {message}")]
    Database { message: String },
    /// Blob storage backend failure.
    #[error("blob storage error: {message}")]
    Blob { message: String },
    /// Key-value / broker backend failure.
    #[error("kv error: {message}")]
    Kv { message: String },
    /// Functionality that is declared but not implemented yet (skeleton phase).
    #[error("unimplemented: {what}")]
    Unimplemented { what: String },
    /// Genuine server fault; the only variant that maps to a 5xx.
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl Error {
    /// Stable machine-readable error code used in the API envelope (`error.code`).
    ///
    /// Codes are part of the public contract: existing values never change.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config { .. } => "config_invalid",
            Self::Invalid { .. } => "invalid_argument",
            Self::NotFound { .. } => "not_found",
            Self::Conflict { .. } => "conflict",
            Self::Forbidden { .. } => "forbidden",
            Self::Expired { .. } => "expired",
            Self::LastOwner { .. } => "last_owner",
            Self::RefreshReused { .. } => "refresh_reused",
            Self::Database { .. } => "database_error",
            Self::Blob { .. } => "blob_error",
            Self::Kv { .. } => "kv_error",
            Self::Unimplemented { .. } => "unimplemented",
            Self::Internal { .. } => "internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Error> {
        vec![
            Error::Config { message: "m".into() },
            Error::Invalid { message: "m".into() },
            Error::NotFound { what: "w".into() },
            Error::Conflict { message: "m".into() },
            Error::Forbidden { message: "m".into() },
            Error::Expired { what: "w".into() },
            Error::LastOwner { org: crate::OrgId::new() },
            Error::RefreshReused { session: crate::SessionId::new() },
            Error::Database { message: "m".into() },
            Error::Blob { message: "m".into() },
            Error::Kv { message: "m".into() },
            Error::Unimplemented { what: "w".into() },
            Error::Internal { message: "m".into() },
        ]
    }

    #[test]
    fn codes_are_stable() {
        let codes: Vec<&str> = all().iter().map(Error::code).collect();
        assert_eq!(
            codes,
            vec![
                "config_invalid",
                "invalid_argument",
                "not_found",
                "conflict",
                "forbidden",
                "expired",
                "last_owner",
                "refresh_reused",
                "database_error",
                "blob_error",
                "kv_error",
                "unimplemented",
                "internal",
            ]
        );
    }

    #[test]
    fn codes_are_unique() {
        let mut codes: Vec<&str> = all().iter().map(Error::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all().len());
    }

    #[test]
    fn display_contains_context() {
        let err = Error::NotFound { what: "package acme".into() };
        assert!(err.to_string().contains("package acme"));
    }
}
