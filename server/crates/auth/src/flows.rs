//! Auth flow orchestrations over the core traits (S-03, S-04, S-08, S-09, S-24, S-31).
//!
//! [`AuthService`] owns no clock and no HTTP types: every entry point takes
//! `now: DateTime<Utc>` plus [`ClientMeta`], and speaks only [`pub_core`] traits — the API
//! layer maps results onto the envelope, tests drive it deterministically.
//!
//! Design invariants:
//! - **Anti-enumeration** (S-04/S-31): `request_otp` performs the same crypto and KV work and
//!   returns the same shape whether the email is known, unknown, or domain-blocked; only the
//!   audit trail records the real reason. `verify_otp` collapses every failure into
//!   [`Error::InvalidCode`].
//! - **Revocation** (S-09): durable truth is `sessions.revoked_at`; every revocation *also*
//!   writes the sid into the KV blocklist with TTL = access TTL, the fast path checked per
//!   request.
//! - OIDC plugs in next slice as additional entry points producing the same
//!   [`LoginSuccess`]; nothing here assumes the email-OTP shape beyond its own functions.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Duration, Utc};
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::authorize::{Action, ActorContext, Resource, authorize};
use pub_core::session::{NewSession, Session, SessionLimits};
use pub_core::token::{NewToken, Token, TokenScope};
use pub_core::traits::{Kv, Mailer, Repositories};
use pub_core::user::{NewUser, User, UserStatus};
use pub_core::{Error, OrgId, Result, SessionId, TokenId, UserId};

use crate::jwt::{Claims, Keyring};
use crate::random::RandomSource;
use crate::{otp, ratelimit, token};

/// Default CLI-token lifetime when the caller does not pick one (S-13).
pub const DEFAULT_TOKEN_EXPIRY_DAYS: i64 = 90;

/// Upper bound on a caller-chosen token lifetime (10 years — effectively "long", still finite).
pub const MAX_TOKEN_EXPIRY_DAYS: i64 = 3650;

/// Instance auth policy, resolved from boot config (and later from runtime settings — the
/// registration/domain knobs are instance settings per S-31; they live here so the flows
/// need no settings plumbing yet).
#[derive(Clone, Debug)]
pub struct AuthPolicy {
    /// Access-JWT TTL (S-07: ≤ 15 min); also the KV blocklist TTL (S-09).
    pub access_ttl: StdDuration,
    /// Refresh-session idle/absolute windows (decision 03).
    pub session_limits: SessionLimits,
    /// Server pepper for OTP HMACs (S-03/S-25).
    pub otp_pepper: Vec<u8>,
    /// CLI token prefix incl. the underscore, e.g. `pub_` (decision 17).
    pub token_prefix: String,
    /// Whether a successful first OTP login may create an account.
    pub allow_registration: bool,
    /// Sign-in email-domain allowlist, lowercase; empty = every domain allowed (S-31).
    pub allowed_email_domains: Vec<String>,
    /// OTP requests per email per hour (S-24: 5).
    pub otp_per_email_hour: u32,
    /// OTP requests per IP per hour (S-24: 20) — enforced by the API rate-limit layer.
    pub otp_per_ip_hour: u32,
}

/// Request context captured by the API layer (audit + session metadata).
#[derive(Clone, Debug, Default)]
pub struct ClientMeta {
    /// Client IP, when known.
    pub ip: Option<String>,
    /// Coarse user-agent string, when known.
    pub user_agent: Option<String>,
}

/// A completed sign-in or refresh: the token pair plus the authenticated identity.
#[derive(Clone, Debug)]
pub struct LoginSuccess {
    /// The authenticated user.
    pub user: User,
    /// The web session backing the pair.
    pub session_id: SessionId,
    /// Short-lived access JWT.
    pub access_token: String,
    /// Opaque rotated refresh token (the plaintext; only its hash is stored).
    pub refresh_token: String,
}

/// Auth orchestration facade: OTP sign-in, session lifecycle, CLI-token plane.
pub struct AuthService {
    repos: Repositories,
    kv: Arc<dyn Kv>,
    mailer: Arc<dyn Mailer>,
    keyring: Keyring,
    policy: AuthPolicy,
    rng: Arc<dyn RandomSource>,
}

impl AuthService {
    /// Bundles the dependencies. All backends arrive as trait handles (decision 09).
    pub fn new(
        repos: Repositories,
        kv: Arc<dyn Kv>,
        mailer: Arc<dyn Mailer>,
        keyring: Keyring,
        policy: AuthPolicy,
        rng: Arc<dyn RandomSource>,
    ) -> Self {
        Self { repos, kv, mailer, keyring, policy, rng }
    }

    /// The effective auth policy (the API layer reads rate-limit numbers from here).
    pub fn policy(&self) -> &AuthPolicy {
        &self.policy
    }

    // --- OTP sign-in (S-03) ---

    /// Issues an OTP for `email` and returns the opaque pending-auth id.
    ///
    /// The response is uniform for known, unknown, and policy-rejected emails (S-04/S-31):
    /// the same work happens and the same shape returns; only whether mail is sent differs,
    /// and the audit log records the real reason.
    pub async fn request_otp(&self, email: &str, meta: &ClientMeta, now: DateTime<Utc>) -> Result<String> {
        let email = normalize_email(email)?;

        // S-24: 5/h per email. The per-IP cap is enforced a layer above (API middleware).
        let email_limit = ratelimit::hit(
            self.kv.as_ref(),
            &format!("rl:otp:email:{email}"),
            self.policy.otp_per_email_hour,
            Duration::hours(1),
            now,
        )
        .await?;
        if let ratelimit::Decision::Limited { retry_after_secs } = email_limit {
            self.audit_throttled(&email, meta, "otp_per_email", now).await;
            return Err(Error::RateLimited { retry_after_secs });
        }

        // S-03 resend policy: ≥ 60 s between requests per email; a resend invalidates the
        // prior pending record so only one live code exists per email at a time.
        let last_key = otp::last_request_key(&email);
        let mut resend_of = None;
        if let Some((prior_id, issued_at)) = self.kv.get(&last_key).await?.and_then(|raw| parse_last_request(&raw)) {
            let elapsed = now - issued_at;
            if elapsed < otp::RESEND_INTERVAL {
                self.audit_throttled(&email, meta, "otp_resend", now).await;
                let retry_after_secs = (otp::RESEND_INTERVAL - elapsed).num_seconds().max(1) as u64;
                return Err(Error::RateLimited { retry_after_secs });
            }
            self.kv.del(&otp::pending_key(&prior_id)).await?;
            resend_of = Some(prior_id);
        }

        // Uniform work for every outcome (S-04): code, record, and KV writes always happen.
        let code = otp::generate_code(self.rng.as_ref());
        let pending_id = otp::generate_pending_id(self.rng.as_ref());
        let record = otp::PendingAuth {
            email: email.clone(),
            code_hmac: otp::code_hmac(&code, &self.policy.otp_pepper),
            attempts: 0,
            created_at: now,
            resend_of: resend_of.clone(),
        };
        let record_json = serde_json::to_string(&record)
            .map_err(|err| Error::Internal { message: format!("pending-auth serialization failed: {err}") })?;
        let ttl = otp::PENDING_TTL.to_std().expect("PENDING_TTL is positive");
        self.kv.set_ttl(&otp::pending_key(&pending_id), &record_json, ttl).await?;
        self.kv.set_ttl(&last_key, &format!("{pending_id}:{}", now.timestamp()), ttl).await?;

        // Silent policy gate (S-31): rejected emails still got the full flow above — they
        // just never receive mail, so the code cannot be redeemed.
        let rejection = if !self.domain_allowed(&email) {
            Some("domain_blocked")
        } else if !self.policy.allow_registration && self.repos.users.find_by_email(&email).await?.is_none() {
            Some("registration_closed")
        } else {
            None
        };

        let mut metadata = serde_json::json!({ "resend": resend_of.is_some() });
        match rejection {
            Some(reason) => {
                metadata["reason"] = reason.into();
                self.audit(&email, meta, "auth.otp.requested", AuditResult::Failure, metadata, now).await;
            }
            None => {
                let rendered = pub_mail::render_otp_email(&code, meta.ip.as_deref(), otp::PENDING_TTL.num_minutes())?;
                self.mailer.send_multipart(&email, &rendered.subject, &rendered.text, &rendered.html).await?;
                self.audit(&email, meta, "auth.otp.requested", AuditResult::Success, metadata, now).await;
            }
        }
        Ok(pending_id)
    }

    /// Redeems an OTP against its pending-auth record and opens a session.
    ///
    /// Every failure — unknown pending id, expired record, wrong code, exhausted attempts,
    /// email mismatch, closed registration — surfaces as [`Error::InvalidCode`] (S-04).
    pub async fn verify_otp(
        &self,
        pending_id: &str,
        email: &str,
        code: &str,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<LoginSuccess> {
        let Ok(email) = normalize_email(email) else {
            return Err(self.login_failure(email, meta, "malformed_email", now).await);
        };

        let key = otp::pending_key(pending_id);
        let Some(raw) = self.kv.get(&key).await? else {
            return Err(self.login_failure(&email, meta, "unknown_pending", now).await);
        };
        let Ok(mut record) = serde_json::from_str::<otp::PendingAuth>(&raw) else {
            self.kv.del(&key).await?;
            return Err(self.login_failure(&email, meta, "corrupt_pending", now).await);
        };

        // The KV TTL is only the garbage collector; this comparison is the authority (S-03).
        let expires_at = record.created_at + otp::PENDING_TTL;
        if now >= expires_at {
            self.kv.del(&key).await?;
            return Err(self.login_failure(&email, meta, "expired", now).await);
        }
        if record.attempts >= otp::MAX_ATTEMPTS {
            self.kv.del(&key).await?;
            return Err(self.login_failure(&email, meta, "attempts_exhausted", now).await);
        }

        let email_bound = record.email == email;
        let code_ok = otp::verify_code(code, &self.policy.otp_pepper, &record.code_hmac);
        if !email_bound || !code_ok {
            record.attempts += 1;
            if record.attempts >= otp::MAX_ATTEMPTS {
                // The code dies, never the account (S-03).
                self.kv.del(&key).await?;
            } else {
                let remaining = (expires_at - now).num_seconds().max(1) as u64;
                let json = serde_json::to_string(&record)
                    .map_err(|err| Error::Internal { message: format!("pending-auth update failed: {err}") })?;
                self.kv.set_ttl(&key, &json, StdDuration::from_secs(remaining)).await?;
            }
            let reason = if email_bound { "wrong_code" } else { "email_mismatch" };
            return Err(self.login_failure(&email, meta, reason, now).await);
        }

        // Single-use (S-03): destroy the record before any success side effects.
        self.kv.del(&key).await?;
        self.kv.del(&otp::last_request_key(&email)).await?;

        let mut registered = false;
        let user = match self.repos.users.find_by_email(&email).await? {
            Some(user) if user.status == UserStatus::Active => user,
            Some(_) => return Err(self.login_failure(&email, meta, "account_disabled", now).await),
            None => {
                // First login creates the account — behind the instance policy gates (S-31).
                if !self.policy.allow_registration || !self.domain_allowed(&email) {
                    return Err(self.login_failure(&email, meta, "registration_denied", now).await);
                }
                let display_name = email.split('@').next().unwrap_or("user").to_owned();
                let new_user = NewUser { email: Some(email.clone()), email_verified: true, display_name };
                let user = match self.repos.users.create(new_user, now).await {
                    Ok(user) => user,
                    // e.g. an unverified duplicate holds the address — uniform failure.
                    Err(Error::Conflict { .. }) => {
                        return Err(self.login_failure(&email, meta, "email_conflict", now).await);
                    }
                    Err(other) => return Err(other),
                };
                self.repos.credentials.create_email_identity(user.id, &email, now).await?;
                registered = true;
                user
            }
        };

        let login = self.open_session(user, meta, now).await?;
        self.audit_as(
            AuditActor::User(login.user.id),
            meta,
            "auth.login.success",
            Some(email),
            AuditResult::Success,
            serde_json::json!({ "method": "otp", "registered": registered }),
            now,
        )
        .await;
        Ok(login)
    }

    // --- Session lifecycle (S-08, S-09) ---

    /// Rotates a refresh token into a fresh pair (S-08).
    ///
    /// Reuse of a rotated-out token revokes the whole session family (DB + KV blocklist) and
    /// surfaces as [`Error::RefreshReused`]; unknown/expired refresh tokens collapse into
    /// [`Error::Unauthorized`].
    pub async fn refresh(&self, refresh_token: &str, meta: &ClientMeta, now: DateTime<Utc>) -> Result<LoginSuccess> {
        let old_hash = token::sha256_hex(refresh_token);
        let new_secret = self.generate_refresh_secret();
        let new_hash = token::sha256_hex(&new_secret);
        match self.repos.sessions.rotate(&old_hash, &new_hash, &self.policy.session_limits, now).await {
            Ok(session) => {
                let user = self
                    .repos
                    .users
                    .get(session.user_id)
                    .await?
                    .filter(|user| user.status == UserStatus::Active)
                    .ok_or_else(|| Error::Unauthorized { message: "account unavailable".into() })?;
                let access_token = self.issue_access_token(user.id, session.id, now).await?;
                Ok(LoginSuccess { user, session_id: session.id, access_token, refresh_token: new_secret })
            }
            Err(Error::RefreshReused { session }) => {
                // Theft signal (S-08): kill the family durably and on the fast path.
                self.repos.sessions.revoke(session, now).await?;
                self.blocklist_sid(session).await?;
                self.audit_as(
                    AuditActor::System,
                    meta,
                    "session.revoked",
                    Some(session.to_string()),
                    AuditResult::Failure,
                    serde_json::json!({ "reason": "refresh_reused" }),
                    now,
                )
                .await;
                Err(Error::RefreshReused { session })
            }
            Err(Error::NotFound { .. } | Error::Expired { .. }) => {
                self.audit_as(
                    AuditActor::System,
                    meta,
                    "auth.login.failure",
                    None,
                    AuditResult::Failure,
                    serde_json::json!({ "method": "refresh", "reason": "invalid_refresh" }),
                    now,
                )
                .await;
                Err(Error::Unauthorized { message: "invalid refresh token".into() })
            }
            Err(other) => Err(other),
        }
    }

    /// Revokes the caller's current session (S-09): DB truth plus KV blocklist. Idempotent.
    pub async fn logout(&self, user: UserId, sid: SessionId, meta: &ClientMeta, now: DateTime<Utc>) -> Result<()> {
        match self.repos.sessions.revoke(sid, now).await {
            Ok(()) | Err(Error::NotFound { .. }) => {}
            Err(other) => return Err(other),
        }
        self.blocklist_sid(sid).await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "session.revoked",
            Some(sid.to_string()),
            AuditResult::Success,
            serde_json::json!({ "reason": "logout" }),
            now,
        )
        .await;
        Ok(())
    }

    /// Revokes one of the user's sessions from the session list UI (S-10).
    /// A sid the user does not own is `NotFound` — indistinguishable from a nonexistent one.
    pub async fn revoke_session(
        &self,
        user: UserId,
        sid: SessionId,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let owned = self.repos.sessions.list_for_user(user).await?.iter().any(|s| s.id == sid);
        if !owned {
            return Err(Error::NotFound { what: format!("session {sid}") });
        }
        self.repos.sessions.revoke(sid, now).await?;
        self.blocklist_sid(sid).await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "session.revoked",
            Some(sid.to_string()),
            AuditResult::Success,
            serde_json::json!({ "reason": "manual" }),
            now,
        )
        .await;
        Ok(())
    }

    /// Revokes every live session of the user (S-09 revoke-all); returns the count.
    pub async fn revoke_all_sessions(&self, user: UserId, meta: &ClientMeta, now: DateTime<Utc>) -> Result<u64> {
        let live: Vec<SessionId> = self.repos.sessions.list_for_user(user).await?.iter().map(|s| s.id).collect();
        let count = self.repos.sessions.revoke_all_for_user(user, now).await?;
        for sid in live {
            self.blocklist_sid(sid).await?;
        }
        self.audit_as(
            AuditActor::User(user),
            meta,
            "session.revoked",
            None,
            AuditResult::Success,
            serde_json::json!({ "reason": "revoke_all", "count": count }),
            now,
        )
        .await;
        Ok(count)
    }

    /// The user's non-revoked sessions for the session list UI (S-10).
    pub async fn list_sessions(&self, user: UserId) -> Result<Vec<Session>> {
        self.repos.sessions.list_for_user(user).await
    }

    // --- Access-token plane (S-07, S-09) ---

    /// Verifies an access JWT against the boot keyring.
    pub fn verify_access(&self, token: &str, now: DateTime<Utc>) -> Result<Claims> {
        self.keyring.verify(token, now)
    }

    /// Whether this sid sits on the KV revocation blocklist (S-09 fast path).
    /// A KV failure propagates — the API layer fails closed on it.
    pub async fn is_sid_revoked(&self, sid: SessionId) -> Result<bool> {
        Ok(self.kv.get(&blocklist_key(sid)).await?.is_some())
    }

    // --- CLI token plane (S-13) ---

    /// Mints a CLI/API token bound to `org`. Returns the stored row plus the show-once
    /// plaintext secret. Requires the org role matching each requested scope (decision 19).
    pub async fn mint_token(
        &self,
        user: UserId,
        org: OrgId,
        label: Option<String>,
        scopes: Vec<TokenScope>,
        expires_days: Option<i64>,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<(Token, String)> {
        if scopes.is_empty() {
            return Err(Error::Invalid { message: "at least one scope is required".into() });
        }
        if let Some(days) = expires_days
            && !(1..=MAX_TOKEN_EXPIRY_DAYS).contains(&days)
        {
            return Err(Error::Invalid {
                message: format!("expires_days must be between 1 and {MAX_TOKEN_EXPIRY_DAYS}"),
            });
        }

        // Role check against the durable membership (claims may be older than a just-created
        // org). A non-member cannot see the org: uniform NotFound (S-04).
        let Some(member) = self.repos.orgs.get_member(org, user).await? else {
            return Err(Error::NotFound { what: format!("org {org}") });
        };
        let actor = ActorContext::user(user, BTreeMap::from([(org, member.role)]));
        for scope in &scopes {
            authorize(&actor, action_for_scope(*scope), &Resource::Org(org))?;
        }

        let minted = token::mint(&self.policy.token_prefix, self.rng.as_ref());
        let expires_at = Some(now + Duration::days(expires_days.unwrap_or(DEFAULT_TOKEN_EXPIRY_DAYS)));
        let stored = self
            .repos
            .tokens
            .create(
                NewToken {
                    user_id: user,
                    org_id: org,
                    name: label.unwrap_or_else(|| "api token".to_owned()),
                    token_hash: minted.hash,
                    display_hint: minted.display_hint,
                    scopes: scopes.clone(),
                    package_patterns: Vec::new(),
                    expires_at,
                },
                now,
            )
            .await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "token.created",
            Some(stored.id.to_string()),
            AuditResult::Success,
            serde_json::json!({
                "org": org.to_string(),
                "scopes": scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            }),
            now,
        )
        .await;
        Ok((stored, minted.secret))
    }

    /// The user's tokens for the token list UI (S-13: hints and metadata only).
    pub async fn list_tokens(&self, user: UserId) -> Result<Vec<Token>> {
        self.repos.tokens.list_for_user(user).await
    }

    /// Revokes one of the user's tokens. A foreign or unknown id is `NotFound` (S-04).
    pub async fn revoke_token(
        &self,
        user: UserId,
        token_id: TokenId,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let owned = self.repos.tokens.list_for_user(user).await?.iter().any(|t| t.id == token_id);
        if !owned {
            return Err(Error::NotFound { what: format!("token {token_id}") });
        }
        self.repos.tokens.revoke(token_id, now).await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "token.revoked",
            Some(token_id.to_string()),
            AuditResult::Success,
            serde_json::json!({}),
            now,
        )
        .await;
        Ok(())
    }

    // --- internals ---

    /// Opens a session for `user`: refresh secret + row + access JWT.
    async fn open_session(&self, user: User, meta: &ClientMeta, now: DateTime<Utc>) -> Result<LoginSuccess> {
        let refresh_secret = self.generate_refresh_secret();
        let session = self
            .repos
            .sessions
            .create(
                NewSession {
                    user_id: user.id,
                    refresh_hash: token::sha256_hex(&refresh_secret),
                    user_agent: meta.user_agent.clone(),
                    ip: meta.ip.clone(),
                },
                now,
            )
            .await?;
        let access_token = self.issue_access_token(user.id, session.id, now).await?;
        Ok(LoginSuccess { user, session_id: session.id, access_token, refresh_token: refresh_secret })
    }

    /// Signs an access JWT for `(user, sid)` with the current org role levels (decision 03).
    async fn issue_access_token(&self, user: UserId, sid: SessionId, now: DateTime<Utc>) -> Result<String> {
        let orgs: BTreeMap<OrgId, u8> = self
            .repos
            .orgs
            .list_for_user(user)
            .await?
            .into_iter()
            .map(|membership| (membership.org.id, membership.role.level()))
            .collect();
        let access_ttl = Duration::from_std(self.policy.access_ttl)
            .map_err(|_| Error::Config { message: "auth.access_ttl is out of range".into() })?;
        let claims = Claims { sub: user, sid, orgs, iat: now.timestamp(), exp: (now + access_ttl).timestamp() };
        self.keyring.sign(&claims)
    }

    /// Opaque ≥128-bit refresh secret (S-08): 32 CSPRNG bytes, base64url.
    fn generate_refresh_secret(&self) -> String {
        let mut buf = [0u8; 32];
        self.rng.fill(&mut buf);
        B64URL.encode(buf)
    }

    /// Writes the sid onto the KV revocation blocklist with TTL = access TTL (S-09).
    async fn blocklist_sid(&self, sid: SessionId) -> Result<()> {
        self.kv.set_ttl(&blocklist_key(sid), "1", self.policy.access_ttl).await
    }

    /// S-31 gate: is this (normalized) email's domain allowed to sign in?
    fn domain_allowed(&self, email: &str) -> bool {
        if self.policy.allowed_email_domains.is_empty() {
            return true;
        }
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        self.policy.allowed_email_domains.iter().any(|allowed| allowed.eq_ignore_ascii_case(domain))
    }

    /// Audits a login failure and returns the uniform error (S-04). The reason lives only in
    /// the audit metadata — the caller-facing error carries nothing.
    async fn login_failure(&self, email: &str, meta: &ClientMeta, reason: &str, now: DateTime<Utc>) -> Error {
        self.audit(
            email,
            meta,
            "auth.login.failure",
            AuditResult::Failure,
            serde_json::json!({ "method": "otp", "reason": reason }),
            now,
        )
        .await;
        Error::InvalidCode
    }

    /// Audits a throttle trip (S-24 requires them logged).
    async fn audit_throttled(&self, email: &str, meta: &ClientMeta, limit: &str, now: DateTime<Utc>) {
        self.audit(email, meta, "auth.throttled", AuditResult::Failure, serde_json::json!({ "limit": limit }), now)
            .await;
    }

    /// System-actor audit event targeting an email (pre-authentication flows).
    async fn audit(
        &self,
        email: &str,
        meta: &ClientMeta,
        action: &str,
        result: AuditResult,
        metadata: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        self.audit_as(AuditActor::System, meta, action, Some(email.to_owned()), result, metadata, now).await;
    }

    /// Appends an audit event. Failures are logged, never propagated — an audit outage must
    /// not take authentication down with it (the tracing record preserves the signal).
    async fn audit_as(
        &self,
        actor: AuditActor,
        meta: &ClientMeta,
        action: &str,
        target: Option<String>,
        result: AuditResult,
        metadata: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        let event = NewAuditEvent {
            actor,
            ip: meta.ip.clone(),
            user_agent: meta.user_agent.clone(),
            org_id: None,
            action: action.to_owned(),
            target,
            result,
            metadata: Some(metadata),
        };
        if let Err(err) = self.repos.audit.append(event, now).await {
            tracing::error!(action, error = %err, "audit append failed");
        }
    }
}

/// Maps a token scope onto the org-role action it requires (decision 19 chokepoint).
fn action_for_scope(scope: TokenScope) -> Action {
    match scope {
        TokenScope::Read => Action::ReadPackages,
        // Retract manages own versions — Write level, like publishing (S-06 step-up for the
        // dangerous variants arrives with the TOTP slice).
        TokenScope::Publish | TokenScope::Retract => Action::PublishPackages,
        TokenScope::Admin => Action::ManageMembers,
    }
}

/// Normalizes an email for lookups and KV keys: trim + lowercase, minimal shape check.
fn normalize_email(raw: &str) -> Result<String> {
    let email = raw.trim().to_ascii_lowercase();
    let invalid = || Error::Invalid { message: "invalid email address".into() };
    if email.is_empty() || email.len() > 254 {
        return Err(invalid());
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid());
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(invalid());
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(invalid());
    }
    Ok(email)
}

/// Parses the `otp:last:{email}` value: `"{pending_id}:{issued_unix}"`.
fn parse_last_request(raw: &str) -> Option<(String, DateTime<Utc>)> {
    let (id, issued) = raw.rsplit_once(':')?;
    let issued = DateTime::from_timestamp(issued.parse().ok()?, 0)?;
    Some((id.to_owned(), issued))
}

/// KV key of the revoked-sid blocklist entry (S-09).
fn blocklist_key(sid: SessionId) -> String {
    format!("session:revoked:{sid}")
}

#[cfg(test)]
mod tests {
    use pub_core::RoleLevel;

    use super::*;

    #[test]
    fn normalize_email_lowercases_and_trims() {
        assert_eq!(normalize_email("  Dev@Corp.COM ").unwrap(), "dev@corp.com");
    }

    #[test]
    fn normalize_email_rejects_garbage() {
        for bad in ["", "no-at-sign", "@corp.com", "dev@", "a@b@c", "dev @corp.com", &"x".repeat(255)] {
            assert!(normalize_email(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parse_last_request_round_trips() {
        let (id, issued) = parse_last_request("abcdef:1754481600").unwrap();
        assert_eq!(id, "abcdef");
        assert_eq!(issued.timestamp(), 1_754_481_600);
        assert!(parse_last_request("garbage").is_none());
        assert!(parse_last_request("id:notanumber").is_none());
    }

    #[test]
    fn scope_role_mapping_matches_decision_19() {
        assert_eq!(action_for_scope(TokenScope::Read).required_level(), RoleLevel::READ);
        assert_eq!(action_for_scope(TokenScope::Publish).required_level(), RoleLevel::WRITE);
        assert_eq!(action_for_scope(TokenScope::Retract).required_level(), RoleLevel::WRITE);
        assert_eq!(action_for_scope(TokenScope::Admin).required_level(), RoleLevel::ADMIN);
    }
}
