//! Wire DTOs for the app API — separate from domain types by rule (docs/rules/api.md), with
//! `From` conversions. Ids travel as strings; role levels travel as names (decision 19).

use chrono::{DateTime, Utc};
use pub_auth::flows::LoginSuccess;
use pub_core::org::{Org, OrgMembership};
use pub_core::session::Session;
use pub_core::token::Token;
use pub_core::user::User;
use pub_core::{RoleLevel, SessionId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// --- request bodies ---

/// Body of `POST /api/v1/auth/otp/request`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OtpRequestBody {
    /// Email to send the sign-in code to.
    pub email: String,
}

/// Body of `POST /api/v1/auth/otp/verify`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OtpVerifyBody {
    /// Opaque pending-auth id from the request step (S-03 binding).
    pub pending_id: String,
    /// The email the code was requested for.
    pub email: String,
    /// The 8-digit code from the email.
    pub code: String,
}

/// Body of `POST /api/v1/auth/refresh`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshBody {
    /// The refresh token issued by verify/refresh.
    pub refresh_token: String,
}

/// Body of `POST /api/v1/tokens`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenCreateBody {
    /// Optional label shown in the token list.
    pub label: Option<String>,
    /// Org the token is bound to (S-13).
    pub org_id: String,
    /// Requested scopes: `read` | `publish` | `retract` | `admin`.
    pub scopes: Vec<String>,
    /// Lifetime in days; defaults to 90 (S-13).
    pub expires_days: Option<i64>,
}

/// Body of `POST /api/v1/orgs`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OrgCreateBody {
    /// Display name.
    pub name: String,
    /// URL slug, unique per instance.
    pub slug: String,
}

// --- responses ---

/// Cursor-paginated list envelope (docs/rules/api.md: cursor pagination only).
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDto<T> {
    /// Items of this page.
    pub items: Vec<T>,
    /// Opaque continuation cursor; `null` on the last page.
    pub cursor: Option<String>,
    /// Whether more items exist.
    pub has_more: bool,
}

impl<T> ListDto<T> {
    /// A single-page listing (the identity/session/org lists are small by construction).
    pub fn single_page(items: Vec<T>) -> Self {
        Self { items, cursor: None, has_more: false }
    }
}

/// Response of `POST /api/v1/auth/otp/request` — deliberately shape-identical for every
/// outcome (S-04).
#[derive(Debug, Serialize, ToSchema)]
pub struct PendingDto {
    /// Opaque pending-auth id to present at the verify step.
    pub pending_id: String,
}

/// Public user profile.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserDto {
    /// User id.
    pub id: String,
    /// Email, when set and not anonymized.
    pub email: Option<String>,
    /// Whether the email is verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: String,
    /// Account creation time.
    pub created_at: DateTime<Utc>,
}

impl From<&User> for UserDto {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.to_string(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            display_name: user.display_name.clone(),
            created_at: user.created_at,
        }
    }
}

/// Response of a successful sign-in or refresh: the token pair plus the profile.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginDto {
    /// Short-lived access JWT (S-07).
    pub access_token: String,
    /// Opaque refresh token — rotates on every refresh (S-08).
    pub refresh_token: String,
    /// Session id backing the pair.
    pub session_id: String,
    /// The authenticated user.
    pub user: UserDto,
}

impl From<LoginSuccess> for LoginDto {
    fn from(login: LoginSuccess) -> Self {
        Self {
            access_token: login.access_token,
            refresh_token: login.refresh_token,
            session_id: login.session_id.to_string(),
            user: UserDto::from(&login.user),
        }
    }
}

/// One row of the session list UI (S-10).
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionDto {
    /// Session id.
    pub id: String,
    /// Sign-in time.
    pub created_at: DateTime<Utc>,
    /// Last activity (write-throttled).
    pub last_seen_at: DateTime<Utc>,
    /// IP captured at sign-in.
    pub ip: Option<String>,
    /// Coarse user agent captured at sign-in.
    pub user_agent: Option<String>,
    /// Whether this row is the session making the request.
    pub current: bool,
}

impl SessionDto {
    /// Converts a domain session, marking it current when it matches `current_sid`.
    pub fn from_session(session: &Session, current_sid: SessionId) -> Self {
        Self {
            id: session.id.to_string(),
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            ip: session.ip.clone(),
            user_agent: session.user_agent.clone(),
            current: session.id == current_sid,
        }
    }
}

/// Token metadata for the token list UI — the secret never appears here (S-13).
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenDto {
    /// Token id.
    pub id: String,
    /// Org the token is bound to.
    pub org_id: String,
    /// User-chosen label.
    pub name: String,
    /// First 8 characters of the secret (S-13 display hint).
    pub display_hint: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry, if any.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last use (write-throttled), if any.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&Token> for TokenDto {
    fn from(token: &Token) -> Self {
        Self {
            id: token.id.to_string(),
            org_id: token.org_id.to_string(),
            name: token.name.clone(),
            display_hint: token.display_hint.clone(),
            scopes: token.scopes.iter().map(|scope| scope.as_str().to_owned()).collect(),
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// Response of `POST /api/v1/tokens`: metadata plus the show-once secret (S-13).
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenCreatedDto {
    /// The plaintext secret — shown exactly once, never retrievable again.
    pub secret: String,
    /// Stored metadata.
    pub token: TokenDto,
}

/// An organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgDto {
    /// Org id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// URL slug.
    pub slug: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

impl From<&Org> for OrgDto {
    fn from(org: &Org) -> Self {
        Self { id: org.id.to_string(), name: org.name.clone(), slug: org.slug.clone(), created_at: org.created_at }
    }
}

/// An org together with the caller's role in it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgMembershipDto {
    /// The org.
    pub org: OrgDto,
    /// The caller's role name (`read`/`write`/`admin`/`owner`; raw level for future roles).
    pub role: String,
}

impl From<&OrgMembership> for OrgMembershipDto {
    fn from(membership: &OrgMembership) -> Self {
        Self { org: OrgDto::from(&membership.org), role: role_name(membership.role) }
    }
}

/// Result of a revocation endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedDto {
    /// How many credentials were revoked.
    pub revoked: u64,
}

/// Wire name of a role level (decision 19: names on the wire, numbers in storage).
fn role_name(role: RoleLevel) -> String {
    role.name().map(str::to_owned).unwrap_or_else(|| role.level().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_follow_decision_19() {
        assert_eq!(role_name(RoleLevel::OWNER), "owner");
        assert_eq!(role_name(RoleLevel::READ), "read");
        // Unknown intermediate levels fall back to the raw number instead of lying.
        assert_eq!(role_name(RoleLevel::new(150)), "150");
    }
}
