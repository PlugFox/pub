//! Web refresh sessions (decision 03, S-08..S-10).
//!
//! A session row is the server-side half of the refresh token: the opaque token itself lives
//! client-side and only its SHA-256 hash is stored. Rotation swaps the hash on every refresh
//! and keeps the rotated-out hash for reuse detection; presenting a rotated-out hash is a
//! theft signal ([`crate::Error::RefreshReused`]) and the caller revokes the whole session.
//!
//! Idle/absolute windows are *parameters* ([`SessionLimits`]) — they are instance-configurable
//! runtime settings, so the repository never hardcodes them.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{SessionId, UserId};

/// A web refresh session. The refresh hash is deliberately not exposed on the domain struct —
/// lookups go through hash-keyed repository methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Entity id (UUID v7); mirrored into JWT `sid` claims.
    pub id: SessionId,
    /// Owning user.
    pub user_id: UserId,
    /// Coarse user-agent string captured at sign-in (session list UI — S-10).
    pub user_agent: Option<String>,
    /// IP captured at sign-in (session list UI — S-10).
    pub ip: Option<String>,
    /// Creation time (UTC); anchor of the absolute cap.
    pub created_at: DateTime<Utc>,
    /// Last activity (UTC), write-throttled; anchor of the sliding idle window.
    pub last_seen_at: DateTime<Utc>,
    /// Revocation time; a revoked session never validates again (S-09 durable truth).
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Payload for creating a session (id and timestamps are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSession {
    /// Owning user.
    pub user_id: UserId,
    /// SHA-256 hex of the opaque refresh token (≥128-bit CSPRNG — S-08).
    pub refresh_hash: String,
    /// Coarse user-agent string.
    pub user_agent: Option<String>,
    /// Client IP.
    pub ip: Option<String>,
}

/// Instance-configured session validity windows (decision 03 defaults: idle 30 d, absolute
/// 90 d), passed into every hash lookup so the query itself enforces them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    /// Sliding idle timeout: a session whose `last_seen_at` is older than this is invalid.
    pub idle_timeout: Duration,
    /// Absolute cap: a session older than this (by `created_at`) is invalid regardless of
    /// activity.
    pub absolute_cap: Duration,
}

impl SessionLimits {
    /// Decision 03 defaults: 30-day sliding idle timeout, 90-day absolute cap.
    pub const DEFAULT: Self =
        Self { idle_timeout: Duration::from_secs(30 * 24 * 3600), absolute_cap: Duration::from_secs(90 * 24 * 3600) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_decision_03() {
        assert_eq!(SessionLimits::DEFAULT.idle_timeout, Duration::from_secs(2_592_000));
        assert_eq!(SessionLimits::DEFAULT.absolute_cap, Duration::from_secs(7_776_000));
    }
}
