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
use pub_core::authorize::{ActorContext, Resource, authorize};
use pub_core::session::{NewSession, Session, SessionLimits};
use pub_core::settings::{RegistrationMode, RuntimeSettings, SettingsCache};
use pub_core::token::{NewToken, Token, TokenScope};
use pub_core::traits::{Kv, Mailer, Repositories};
use pub_core::user::{NewUser, User, UserStatus};
use pub_core::{Error, OrgId, Result, RoleLevel, SessionId, TokenId, UserId};

use serde::{Deserialize, Serialize};

use crate::jwt::{Claims, Keyring};
use crate::oidc::{OidcClient, ProviderConfig, StartedFlow};
use crate::random::RandomSource;
use crate::{otp, ratelimit, token, totp};

/// Default CLI-token lifetime when the caller does not pick one (S-13).
pub const DEFAULT_TOKEN_EXPIRY_DAYS: i64 = 90;

/// Upper bound on a caller-chosen token lifetime (10 years — effectively "long", still finite).
pub const MAX_TOKEN_EXPIRY_DAYS: i64 = 3650;

/// How stale `tokens.last_used_at` may get before another write happens (S-13 "write-throttled").
/// The pub client authenticates on every resolve and download; without a throttle a single
/// `pub get` would issue dozens of writes to one row.
const TOKEN_LAST_USED_THROTTLE: StdDuration = StdDuration::from_secs(5 * 60);

/// Instance auth policy, resolved from **boot** configuration only.
///
/// Everything an administrator may change at runtime — the registration mode, the S-31 domain
/// allowlist, and every S-24 rate-limit number — lives in [`SettingsCache`] instead, and is
/// read per request. What stays here is what S-25 makes boot-only (the pepper, the KEK, the
/// signing plane's TTLs) plus [`AuthPolicy::instance_admins`], the administration bootstrap,
/// which must not be editable by the surface it grants access to.
///
/// [`Debug`] is hand-written: this struct carries the OTP pepper, and a stray `{:?}` on it
/// (config dump, `#[instrument]` field, panic message) would put that secret in a log line
/// (S-25).
#[derive(Clone)]
pub struct AuthPolicy {
    /// Access-JWT TTL (S-07: ≤ 15 min); also the KV blocklist TTL (S-09).
    pub access_ttl: StdDuration,
    /// Refresh-session idle/absolute windows (decision 03).
    pub session_limits: SessionLimits,
    /// Server pepper for OTP HMACs (S-03/S-25).
    pub otp_pepper: Vec<u8>,
    /// CLI token prefix incl. the underscore, e.g. `pub_` (decision 17).
    pub token_prefix: String,
    /// Email addresses promoted to instance administrator at startup and at registration
    /// (decision 09 bootstrap), lowercase.
    ///
    /// Boot config, deliberately: the admin surface is what grants and revokes every other
    /// runtime setting, so a list that lived *in* the settings table would let one compromised
    /// admin session make itself permanent. The other bootstrap path — "the first account on
    /// an instance with no admin" — needs no configuration at all.
    pub instance_admins: Vec<String>,
    /// 32-byte key-encryption key sealing TOTP seeds at rest (S-05/S-25).
    pub kek: Vec<u8>,
    /// How long a step-up (fresh second factor / fresh login) stays valid (S-06; default
    /// 15 minutes).
    pub step_up_window: StdDuration,
    /// Issuer label embedded in `otpauth://` provisioning URLs (instance branding).
    pub totp_issuer: String,
}

impl std::fmt::Debug for AuthPolicy {
    /// Everything except the pepper (S-25: secrets never reach a log line).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthPolicy")
            .field("access_ttl", &self.access_ttl)
            .field("session_limits", &self.session_limits)
            .field("otp_pepper", &"<redacted>")
            .field("token_prefix", &self.token_prefix)
            .field("instance_admins", &self.instance_admins)
            .field("kek", &"<redacted>")
            .field("step_up_window", &self.step_up_window)
            .field("totp_issuer", &self.totp_issuer)
            .finish()
    }
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
///
/// [`Debug`] is hand-written: this is the one struct that holds *both* live credentials in
/// plaintext, and the refresh token is the long-lived half (S-08). It must never be printable.
#[derive(Clone)]
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

impl std::fmt::Debug for LoginSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginSuccess")
            .field("user", &self.user.id)
            .field("session_id", &self.session_id)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// Outcome of a first-factor sign-in (OTP or OIDC): either a full session, or — when the
/// account has an active TOTP second factor — a pending-MFA handle the client must redeem
/// at `totp/verify` (S-05).
#[derive(Debug)]
pub enum LoginOutcome {
    /// No second factor enrolled: the session pair is ready.
    Complete(LoginSuccess),
    /// TOTP is active: no tokens yet; present `mfa_token` + a TOTP or recovery code.
    MfaRequired {
        /// Opaque single-use handle of the half-finished login (short TTL).
        mfa_token: String,
    },
}

/// Server-side record of a half-finished login (first factor passed, TOTP outstanding),
/// stored in KV under [`totp::mfa_pending_key`].
#[derive(Serialize, Deserialize)]
struct MfaPending {
    user_id: UserId,
    created_at: DateTime<Utc>,
    /// First-factor method, recorded in the completion audit (`otp` / `oidc:{provider}`).
    method: String,
}

/// Auth orchestration facade: OTP + OIDC sign-in, TOTP second factor, step-up, session
/// lifecycle, CLI-token plane.
pub struct AuthService {
    repos: Repositories,
    kv: Arc<dyn Kv>,
    mailer: Arc<dyn Mailer>,
    keyring: Keyring,
    policy: AuthPolicy,
    /// Runtime settings (decision 09): registration mode, S-31 domain allowlist, S-24 limits.
    runtime: Arc<SettingsCache>,
    rng: Arc<dyn RandomSource>,
    oidc: OidcClient,
}

impl AuthService {
    /// Bundles the dependencies. All backends arrive as trait handles (decision 09).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repos: Repositories,
        kv: Arc<dyn Kv>,
        mailer: Arc<dyn Mailer>,
        keyring: Keyring,
        policy: AuthPolicy,
        runtime: Arc<SettingsCache>,
        rng: Arc<dyn RandomSource>,
        oidc: OidcClient,
    ) -> Self {
        Self { repos, kv, mailer, keyring, policy, runtime, rng, oidc }
    }

    /// The boot-only half of the auth policy (TTLs, pepper, KEK, token prefix).
    pub fn policy(&self) -> &AuthPolicy {
        &self.policy
    }

    /// The current runtime-settings snapshot (decision 09).
    pub fn settings(&self) -> Arc<RuntimeSettings> {
        self.runtime.current()
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
            self.settings().rate_limits.otp_per_email_hour,
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
            created_at: now,
            resend_of: resend_of.clone(),
        };
        let record_json = serde_json::to_string(&record)
            .map_err(|err| Error::Internal { message: format!("pending-auth serialization failed: {err}") })?;
        let ttl = otp::PENDING_TTL.to_std().expect("PENDING_TTL is positive");
        self.kv.set_ttl(&otp::pending_key(&pending_id), &record_json, ttl).await?;
        self.kv.set_ttl(&last_key, &format!("{pending_id}:{}", now.timestamp()), ttl).await?;

        // Silent policy gate (S-31/S-04). Both the account lookup and the template render run
        // for *every* address, known or not, allowed or not: branching on them would turn the
        // response latency into an existence oracle. Only the SMTP hand-off is conditional —
        // a blocked address must never actually receive a redeemable code.
        let known_account = self.repos.users.find_by_email(&email).await?.is_some();
        let rendered = pub_mail::render_otp_email(&code, meta.ip.as_deref(), otp::PENDING_TTL.num_minutes())?;
        // The registration probe runs for every address too, so an open-registration
        // instance and an invite-only one do the same work per request (S-04.a).
        let may_register = self.registration_allowed(&email, now).await?;
        let rejection = if !self.domain_allowed(&email) {
            Some("domain_blocked")
        } else if !may_register && !known_account {
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
                self.mailer.send_multipart(&email, &rendered.subject, &rendered.text, &rendered.html).await?;
                self.audit(&email, meta, "auth.otp.requested", AuditResult::Success, metadata, now).await;
            }
        }
        Ok(pending_id)
    }

    /// Redeems an OTP against its pending-auth record: opens a session, or hands back a
    /// pending-MFA token when the account has an active TOTP second factor (S-05).
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
    ) -> Result<LoginOutcome> {
        let Ok(email) = normalize_email(email) else {
            return Err(self.login_failure(email, meta, "malformed_email", now).await);
        };

        let key = otp::pending_key(pending_id);
        let attempts = otp::attempt_key(pending_id);
        let Some(raw) = self.kv.get(&key).await? else {
            return Err(self.login_failure(&email, meta, "unknown_pending", now).await);
        };
        let Ok(record) = serde_json::from_str::<otp::PendingAuth>(&raw) else {
            self.kv.del(&key).await?;
            return Err(self.login_failure(&email, meta, "corrupt_pending", now).await);
        };

        // The KV TTL is only the garbage collector; this comparison is the authority (S-03).
        let expires_at = record.created_at + otp::PENDING_TTL;
        if now >= expires_at {
            self.kv.del(&key).await?;
            self.kv.del(&attempts).await?;
            return Err(self.login_failure(&email, meta, "expired", now).await);
        }

        // S-03 budget: spend an attempt **atomically and before comparing**, so N parallel
        // guesses cost N attempts. A read-modify-write here would let a burst of concurrent
        // verifications all observe the same counter and share a single increment.
        let remaining_ttl = StdDuration::from_secs((expires_at - now).num_seconds().max(1) as u64);
        let spent = self.kv.incr(&attempts, remaining_ttl).await?;
        if spent > u64::from(otp::MAX_ATTEMPTS) {
            // The code dies, never the account (S-03).
            self.kv.del(&key).await?;
            return Err(self.login_failure(&email, meta, "attempts_exhausted", now).await);
        }

        let email_bound = record.email == email;
        let code_ok = otp::verify_code(code, &self.policy.otp_pepper, &record.code_hmac);
        if !email_bound || !code_ok {
            if spent >= u64::from(otp::MAX_ATTEMPTS) {
                self.kv.del(&key).await?;
            }
            let reason = if email_bound { "wrong_code" } else { "email_mismatch" };
            return Err(self.login_failure(&email, meta, reason, now).await);
        }

        // Single-use (S-03): destroy the record before any success side effects.
        self.kv.del(&key).await?;
        self.kv.del(&attempts).await?;
        self.kv.del(&otp::last_request_key(&email)).await?;

        // S-31 is evaluated at *sign-in*, not only at registration: an account whose domain
        // left the allowlist can no longer authenticate, even holding a valid code.
        if !self.domain_allowed(&email) {
            return Err(self.login_failure(&email, meta, "domain_blocked", now).await);
        }

        let mut registered = false;
        let user = match self.repos.users.find_by_email(&email).await? {
            Some(user) if user.status == UserStatus::Active => user,
            Some(_) => return Err(self.login_failure(&email, meta, "account_disabled", now).await),
            None => {
                // First login creates the account — behind the instance registration gate
                // (decision 09 runtime setting: open / invite-only / closed).
                if !self.registration_allowed(&email, now).await? {
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
                self.bootstrap_instance_admin(user.id, &email, meta, now).await;
                registered = true;
                user
            }
        };

        self.finish_login(
            user,
            "otp",
            "auth.login.success",
            serde_json::json!({ "method": "otp", "registered": registered }),
            meta,
            now,
        )
        .await
    }

    // --- OIDC sign-in (S-01, S-02, S-31) ---

    /// The configured OIDC providers for the login screen (may be empty — OIDC is optional).
    pub fn oidc_providers(&self) -> &[ProviderConfig] {
        self.oidc.providers()
    }

    /// Starts an OIDC flow: server-side state/nonce/PKCE under an opaque flow id (S-01).
    /// Unknown providers are `NotFound` (404).
    pub async fn oidc_start(&self, provider_id: &str, now: DateTime<Utc>) -> Result<StartedFlow> {
        self.oidc.start(self.kv.as_ref(), self.rng.as_ref(), provider_id, now).await
    }

    /// Finishes an OIDC flow: validates state/code/id_token, resolves the account by
    /// `(issuer, subject)`, applies the S-02 linking policy and the S-31 domain gate, and
    /// opens a session (or hands back a pending-MFA token, S-05).
    ///
    /// Every authentication failure collapses into one uniform `Unauthorized`; the real
    /// reason lives only in the audit trail (S-04). Unknown providers stay `NotFound`.
    pub async fn oidc_login(
        &self,
        provider_id: &str,
        flow_id: &str,
        state: &str,
        code: &str,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<LoginOutcome> {
        let provider = self.oidc.provider(provider_id)?;
        let provider_id = provider.id.clone();
        let provider_label = provider.display_name.clone();

        let identity = match self.oidc.callback(self.kv.as_ref(), &provider_id, flow_id, state, code, now).await {
            Ok(identity) => identity,
            Err(Error::Unauthorized { message }) => {
                return Err(self.oidc_failure(&provider_id, None, meta, &message, now).await);
            }
            // Infrastructure failures (KV outage etc.) propagate — the API fails closed.
            Err(other) => return Err(other),
        };

        let existing = self.repos.credentials.find_oidc(&identity.issuer, &identity.subject).await?;
        let (user, linked, registered) = match existing {
            Some(credential) => {
                // Known identity: the every-sign-in path (S-01 key is (iss, sub)).
                let Some(user) =
                    self.repos.users.get(credential.user_id).await?.filter(|u| u.status == UserStatus::Active)
                else {
                    return Err(self
                        .oidc_failure(&provider_id, identity.email, meta, "account_unavailable", now)
                        .await);
                };
                // S-31 is a sign-in gate, not only a registration gate: an account whose
                // domain left the allowlist stops authenticating.
                if let Some(email) = &user.email
                    && !self.domain_allowed(email)
                {
                    return Err(self.oidc_failure(&provider_id, user.email.clone(), meta, "domain_blocked", now).await);
                }
                self.repos.credentials.upsert_oidc(user.id, &identity.issuer, &identity.subject, now).await?;
                (user, false, false)
            }
            None => {
                // New identity. Linking or registering requires a **verified** email from
                // the IdP (S-02) — without one there is nothing trustworthy to key on.
                let verified_email = identity.email.clone().filter(|_| identity.email_verified);
                let Some(email) = verified_email else {
                    return Err(self.oidc_failure(&provider_id, identity.email, meta, "unverified_email", now).await);
                };
                if !self.domain_allowed(&email) {
                    return Err(self.oidc_failure(&provider_id, Some(email), meta, "domain_blocked", now).await);
                }
                match self.repos.users.find_by_email(&email).await? {
                    // find_by_email matches only *verified* local emails, so both sides of
                    // the S-02 equation are verified here — auto-link.
                    Some(user) if user.status == UserStatus::Active => {
                        if self
                            .repos
                            .credentials
                            .upsert_oidc(user.id, &identity.issuer, &identity.subject, now)
                            .await
                            .is_err()
                        {
                            // Raced against another link of the same identity — uniform failure.
                            return Err(self.oidc_failure(&provider_id, Some(email), meta, "link_conflict", now).await);
                        }
                        self.audit_as(
                            AuditActor::User(user.id),
                            meta,
                            "credential.linked",
                            Some(email.clone()),
                            AuditResult::Success,
                            serde_json::json!({ "type": "oidc", "provider": provider_id }),
                            now,
                        )
                        .await;
                        // S-02: linking notifies the user by email. Delivery failures must
                        // not undo an already-recorded link — log and continue.
                        let body = format!(
                            "A new sign-in method ({provider_label}) was just linked to your account.\n\n\
                             If this was not you, revoke your sessions and contact your administrator.",
                        );
                        if let Err(err) = self.mailer.send(&email, "New sign-in method linked", &body).await {
                            tracing::error!(error = %err, "linking notification mail failed");
                        }
                        (user, true, false)
                    }
                    Some(_) => {
                        return Err(self.oidc_failure(&provider_id, Some(email), meta, "account_disabled", now).await);
                    }
                    None => {
                        if !self.registration_allowed(&email, now).await? {
                            return Err(self
                                .oidc_failure(&provider_id, Some(email), meta, "registration_denied", now)
                                .await);
                        }
                        let display_name = email.split('@').next().unwrap_or("user").to_owned();
                        let new_user = NewUser { email: Some(email.clone()), email_verified: true, display_name };
                        let user = match self.repos.users.create(new_user, now).await {
                            Ok(user) => user,
                            // An unverified local holder of this address exists: it can never
                            // claim the account and the account can never claim it (S-02).
                            Err(Error::Conflict { .. }) => {
                                return Err(self
                                    .oidc_failure(&provider_id, Some(email), meta, "email_conflict", now)
                                    .await);
                            }
                            Err(other) => return Err(other),
                        };
                        self.repos.credentials.create_email_identity(user.id, &email, now).await?;
                        self.repos.credentials.upsert_oidc(user.id, &identity.issuer, &identity.subject, now).await?;
                        self.bootstrap_instance_admin(user.id, &email, meta, now).await;
                        (user, false, true)
                    }
                }
            }
        };

        self.finish_login(
            user,
            &format!("oidc:{provider_id}"),
            "auth.oidc.login.success",
            serde_json::json!({ "provider": provider_id, "registered": registered, "linked": linked }),
            meta,
            now,
        )
        .await
    }

    // --- TOTP second factor (S-05) ---

    /// Starts a TOTP enrollment: fresh 160-bit seed, sealed with the KEK into a short-TTL
    /// KV record; nothing touches the database until the code is confirmed. Returns the
    /// base32 secret and the `otpauth://` URL. An active enrollment is a `Conflict`.
    pub async fn enroll_totp(&self, user: UserId, _now: DateTime<Utc>) -> Result<(String, String)> {
        if self.repos.credentials.find_totp(user).await?.is_some() {
            return Err(Error::Conflict { message: "totp is already enrolled; disable it first".into() });
        }
        let account = self.repos.users.get(user).await?.and_then(|u| u.email).unwrap_or_else(|| user.to_string());
        let seed = totp::generate_secret(self.rng.as_ref());
        let sealed = totp::seal(&self.policy.kek, self.rng.as_ref(), &seed)?;
        let ttl = totp::ENROLL_TTL.to_std().expect("ENROLL_TTL is positive");
        self.kv.set_ttl(&totp::enroll_key(user), &B64URL.encode(&sealed), ttl).await?;
        Ok((totp::base32_encode(&seed), totp::otpauth_url(&self.policy.totp_issuer, &account, &seed)))
    }

    /// Confirms a pending enrollment with a live code: activates the second factor and
    /// returns the ten single-use recovery codes — shown exactly once (S-05).
    pub async fn confirm_totp(
        &self,
        user: UserId,
        code: &str,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let key = totp::enroll_key(user);
        let Some(raw) = self.kv.get(&key).await? else {
            return Err(Error::Invalid { message: "no totp enrollment in progress".into() });
        };
        let sealed =
            B64URL.decode(&raw).map_err(|_| Error::Internal { message: "corrupt pending enrollment".into() })?;
        let seed = totp::open(&self.policy.kek, &sealed)?;

        let scope = format!("enroll:{user}");
        self.mfa_backoff_gate(&scope, now).await?;
        let Some(step) = totp::verify_at(&seed, code, now, None) else {
            self.mfa_failure(&scope, meta, "totp_confirm", now).await;
            return Err(Error::InvalidCode);
        };

        // Activate with the confirmation step as the replay floor: the code the user just
        // typed can never be replayed at login (S-05).
        self.repos.credentials.create_totp(user, &sealed, step, now).await?;
        let codes: Vec<String> =
            (0..totp::RECOVERY_CODES).map(|_| totp::generate_recovery_code(self.rng.as_ref())).collect();
        let hashes =
            codes.iter().map(|code| totp::hash_recovery_code(code, self.rng.as_ref())).collect::<Result<Vec<_>>>()?;
        self.repos.credentials.replace_recovery_codes(user, &hashes, now).await?;

        self.kv.del(&key).await?;
        self.clear_mfa_counters(&scope).await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "auth.totp.enrolled",
            None,
            AuditResult::Success,
            serde_json::json!({ "recovery_codes": codes.len() }),
            now,
        )
        .await;
        Ok(codes)
    }

    /// Disables the second factor: removes the TOTP enrollment and every remaining recovery
    /// code. Step-up enforcement happens at the API layer (S-06).
    pub async fn disable_totp(&self, user: UserId, meta: &ClientMeta, now: DateTime<Utc>) -> Result<()> {
        let removed = self.repos.credentials.delete_second_factor(user).await?;
        if removed == 0 {
            return Err(Error::NotFound { what: "totp enrollment".into() });
        }
        self.audit_as(
            AuditActor::User(user),
            meta,
            "auth.totp.disabled",
            None,
            AuditResult::Success,
            serde_json::json!({}),
            now,
        )
        .await;
        Ok(())
    }

    /// Whether the user has an active TOTP second factor.
    pub async fn totp_enrolled(&self, user: UserId) -> Result<bool> {
        Ok(self.repos.credentials.find_totp(user).await?.is_some())
    }

    /// Completes a pending-MFA login with a TOTP or recovery code (S-05).
    ///
    /// The pending handle survives failed attempts (the budget is the ≤5-then-backoff
    /// counter, not the record), and is consumed on success.
    pub async fn verify_mfa(
        &self,
        mfa_token: &str,
        code: Option<&str>,
        recovery_code: Option<&str>,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<LoginSuccess> {
        let key = totp::mfa_pending_key(mfa_token);
        let Some(raw) = self.kv.get(&key).await? else {
            return Err(self.mfa_login_failure(None, meta, "unknown_mfa_token", now).await);
        };
        let Ok(pending) = serde_json::from_str::<MfaPending>(&raw) else {
            self.kv.del(&key).await?;
            return Err(self.mfa_login_failure(None, meta, "corrupt_mfa_pending", now).await);
        };
        // The record's own timestamp is the authority; the KV TTL only garbage-collects.
        if now >= pending.created_at + totp::MFA_PENDING_TTL {
            self.kv.del(&key).await?;
            return Err(self.mfa_login_failure(Some(pending.user_id), meta, "mfa_expired", now).await);
        }

        let scope = format!("login:{mfa_token}");
        self.mfa_backoff_gate(&scope, now).await?;

        let Some(user) = self.repos.users.get(pending.user_id).await?.filter(|u| u.status == UserStatus::Active) else {
            return Err(self.mfa_login_failure(Some(pending.user_id), meta, "account_unavailable", now).await);
        };

        let Some(second_factor) = self.verify_second_factor(user.id, code, recovery_code, now).await? else {
            self.mfa_failure(&scope, meta, "mfa_login", now).await;
            return Err(self.mfa_login_failure(Some(user.id), meta, "wrong_second_factor", now).await);
        };

        // Success: the pending handle is single-use.
        self.kv.del(&key).await?;
        self.clear_mfa_counters(&scope).await?;
        let login = self.open_session(user, meta, now).await?;
        self.audit_as(
            AuditActor::User(login.user.id),
            meta,
            "auth.login.success",
            login.user.email.clone(),
            AuditResult::Success,
            serde_json::json!({ "method": pending.method, "second_factor": second_factor }),
            now,
        )
        .await;
        Ok(login)
    }

    // --- Step-up ("sudo mode", S-06) ---

    /// Marks the caller's session step-up-fresh after a live TOTP/recovery verification.
    /// Returns until when the mark holds. Accounts without an enrolled second factor cannot
    /// use this endpoint — their re-auth path is a fresh login (see [`Self::step_up_satisfied`]).
    pub async fn step_up(
        &self,
        user: UserId,
        sid: SessionId,
        code: Option<&str>,
        recovery_code: Option<&str>,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>> {
        if self.repos.credentials.find_totp(user).await?.is_none() {
            return Err(Error::Invalid { message: "no second factor enrolled; sign in again instead".into() });
        }
        let scope = format!("stepup:{sid}");
        self.mfa_backoff_gate(&scope, now).await?;
        let Some(second_factor) = self.verify_second_factor(user, code, recovery_code, now).await? else {
            self.mfa_failure(&scope, meta, "step_up", now).await;
            self.audit_as(
                AuditActor::User(user),
                meta,
                "auth.step_up.failure",
                Some(sid.to_string()),
                AuditResult::Failure,
                serde_json::json!({}),
                now,
            )
            .await;
            return Err(Error::InvalidCode);
        };
        self.clear_mfa_counters(&scope).await?;
        self.kv.set_ttl(&totp::step_up_key(sid), &now.timestamp().to_string(), self.policy.step_up_window).await?;
        self.audit_as(
            AuditActor::User(user),
            meta,
            "auth.step_up.success",
            Some(sid.to_string()),
            AuditResult::Success,
            serde_json::json!({ "second_factor": second_factor }),
            now,
        )
        .await;
        let window = Duration::from_std(self.policy.step_up_window)
            .map_err(|_| Error::Config { message: "auth.step_up_window is out of range".into() })?;
        Ok(now + window)
    }

    /// Whether the session currently satisfies S-06 step-up:
    ///
    /// 1. a **fresh login** — the session was created within the step-up window (a login
    ///    already ran the strongest factor chain the account has, TOTP included); or
    /// 2. an explicit [`Self::step_up`] verification within the window.
    ///
    /// A KV failure propagates — the API layer fails closed (denies the gated action).
    pub async fn step_up_satisfied(&self, user: UserId, sid: SessionId, now: DateTime<Utc>) -> Result<bool> {
        let window = Duration::from_std(self.policy.step_up_window)
            .map_err(|_| Error::Config { message: "auth.step_up_window is out of range".into() })?;
        let fresh_login = self
            .repos
            .sessions
            .list_for_user(user)
            .await?
            .iter()
            .any(|session| session.id == sid && now < session.created_at + window);
        if fresh_login {
            return Ok(true);
        }
        let mark = self.kv.get(&totp::step_up_key(sid)).await?;
        Ok(mark
            .and_then(|raw| raw.parse::<i64>().ok())
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
            .is_some_and(|marked_at| now < marked_at + window))
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
        self.revoke_all_for(user, AuditActor::User(user), "revoke_all", meta, now).await
    }

    /// Revokes every live session of a user whose **authority just changed** (S-09).
    ///
    /// The distinct entry point exists so the reason reaches the audit log and so the actor is
    /// the *system* rather than the affected user — the person losing their sessions is not
    /// the person who acted. Callers: the org membership service (role change, removal) and
    /// the admin user surface (suspension, admin-flag change). See
    /// [S-09.a](../../../../docs/security.md) for which changes must revoke and why.
    pub async fn revoke_sessions_after_authority_change(
        &self,
        user: UserId,
        reason: &str,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        self.revoke_all_for(user, AuditActor::System, reason, meta, now).await
    }

    /// The one implementation behind both revoke-everything paths: durable revocation first,
    /// KV blocklist second (S-09 fast path), audit last.
    async fn revoke_all_for(
        &self,
        user: UserId,
        actor: AuditActor,
        reason: &str,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let live: Vec<SessionId> = self.repos.sessions.list_for_user(user).await?.iter().map(|s| s.id).collect();
        let count = self.repos.sessions.revoke_all_for_user(user, now).await?;
        for sid in live {
            self.blocklist_sid(sid).await?;
        }
        self.audit_as(
            actor,
            meta,
            "session.revoked",
            Some(user.to_string()),
            AuditResult::Success,
            serde_json::json!({ "reason": reason, "count": count }),
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
            authorize(&actor, scope.required_action(), &Resource::Org(org))?;
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

    // --- CLI token authentication (S-13, S-14, S-24) ---

    /// Authenticates a presented CLI token secret — the pub protocol's whole credential check.
    ///
    /// The order is the security property. The **offline** checks (prefix, length, charset,
    /// CRC32 — decision 13) run first, so a fabricated, truncated, or foreign-prefixed string
    /// never reaches the database; a browser access JWT fails them structurally, which is how
    /// the two credential planes stay unmixed (decision 03) without a special case. Only then
    /// is the SHA-256 looked up, and only tokens active *at `now`* come back — unknown,
    /// revoked, and expired are deliberately indistinguishable (uniform 401, S-14).
    ///
    /// Failures spend an S-24 budget keyed on the client IP; once it is gone the error becomes
    /// [`Error::RateLimited`] instead of [`Error::Unauthorized`], which also stops a brute
    /// force from destroying a bystander's stored credential (the pub client deletes its token
    /// on 401 — docs/protocol.md sharp edge 1).
    pub async fn authenticate_cli_token(&self, secret: &str, meta: &ClientMeta, now: DateTime<Utc>) -> Result<Token> {
        if token::validate(secret, &self.policy.token_prefix).is_err() {
            return Err(self.token_auth_failure(meta, "malformed", now).await);
        }
        let hash = token::sha256_hex(secret);
        match self.repos.tokens.find_active_by_hash(&hash, now).await? {
            Some(token) => Ok(token),
            None => Err(self.token_auth_failure(meta, "unknown_revoked_or_expired", now).await),
        }
    }

    /// The token's principal for the [`authorize`] chokepoint (decision 19).
    ///
    /// The role is read from the **durable** membership, not from any cached claim: a token
    /// outlives role changes by design, so its authority has to be re-derived per request.
    /// A user who has left the org holds [`RoleLevel::NONE`] and the token authenticates but
    /// authorizes nothing.
    pub async fn token_actor(&self, token: &Token) -> Result<ActorContext> {
        let role = self
            .repos
            .orgs
            .get_member(token.org_id, token.user_id)
            .await?
            .map(|member| member.role)
            .unwrap_or(RoleLevel::NONE);
        Ok(ActorContext::user(token.user_id, BTreeMap::from([(token.org_id, role)])))
    }

    /// Write-throttled last-used/last-IP tracking (S-13).
    ///
    /// Best-effort by contract: the pub client authenticates on *every* resolve and download,
    /// so a bookkeeping failure must never fail the request it is bookkeeping for.
    pub async fn touch_cli_token(&self, token: &Token, ip: Option<&str>, now: DateTime<Utc>) {
        if let Err(err) = self.repos.tokens.touch_last_used(token.id, ip, TOKEN_LAST_USED_THROTTLE, now).await {
            tracing::warn!(error = %err, "token last-used tracking failed");
        }
    }

    /// Spends one S-24 token-auth failure budget unit and returns the caller-facing error.
    ///
    /// A KV outage here degrades to a plain denial rather than propagating: the request has
    /// *already* failed authentication, so failing closed and failing open coincide, and a
    /// 503 would only teach an attacker that the throttle is down.
    async fn token_auth_failure(&self, meta: &ClientMeta, reason: &str, now: DateTime<Utc>) -> Error {
        let ip = meta.ip.as_deref().unwrap_or("unknown");
        let key = format!("rl:token_auth:ip:{ip}");
        let window = Duration::minutes(1);
        let limit = self.settings().rate_limits.token_auth_fail_per_ip_minute;
        match ratelimit::hit(self.kv.as_ref(), &key, limit, window, now).await {
            Ok(ratelimit::Decision::Allowed) => {}
            Ok(ratelimit::Decision::Limited { retry_after_secs }) => {
                self.audit_as(
                    AuditActor::System,
                    meta,
                    "auth.throttled",
                    None,
                    AuditResult::Failure,
                    serde_json::json!({ "limit": "token_auth_per_ip" }),
                    now,
                )
                .await;
                return Error::RateLimited { retry_after_secs };
            }
            Err(err) => tracing::error!(error = %err, "token-auth throttle accounting failed"),
        }
        self.audit_as(
            AuditActor::System,
            meta,
            "auth.token.failure",
            None,
            AuditResult::Failure,
            serde_json::json!({ "reason": reason }),
            now,
        )
        .await;
        Error::Unauthorized { message: "invalid or expired token".into() }
    }

    // --- internals ---

    /// Completes a passed first factor: either opens the session (auditing
    /// `success_action`), or parks the login behind a pending-MFA handle when the account
    /// has an active TOTP second factor (S-05).
    async fn finish_login(
        &self,
        user: User,
        method: &str,
        success_action: &str,
        metadata: serde_json::Value,
        meta: &ClientMeta,
        now: DateTime<Utc>,
    ) -> Result<LoginOutcome> {
        if self.repos.credentials.find_totp(user.id).await?.is_some() {
            let mfa_token = otp::generate_pending_id(self.rng.as_ref());
            let pending = MfaPending { user_id: user.id, created_at: now, method: method.to_owned() };
            let json = serde_json::to_string(&pending)
                .map_err(|err| Error::Internal { message: format!("mfa-pending serialization failed: {err}") })?;
            let ttl = totp::MFA_PENDING_TTL.to_std().expect("MFA_PENDING_TTL is positive");
            self.kv.set_ttl(&totp::mfa_pending_key(&mfa_token), &json, ttl).await?;
            self.audit_as(
                AuditActor::User(user.id),
                meta,
                "auth.mfa.challenge",
                user.email.clone(),
                AuditResult::Success,
                serde_json::json!({ "method": method }),
                now,
            )
            .await;
            return Ok(LoginOutcome::MfaRequired { mfa_token });
        }
        let login = self.open_session(user, meta, now).await?;
        self.audit_as(
            AuditActor::User(login.user.id),
            meta,
            success_action,
            login.user.email.clone(),
            AuditResult::Success,
            metadata,
            now,
        )
        .await;
        Ok(LoginOutcome::Complete(login))
    }

    /// Verifies exactly one of TOTP code / recovery code for `user`.
    ///
    /// `Ok(Some("totp" | "recovery"))` on success; `Ok(None)` on any credential mismatch
    /// (uniform for the caller); `Err(Invalid)` when the request shape is wrong. Successful
    /// TOTP verification commits the replay floor atomically — a lost race is a failure.
    async fn verify_second_factor(
        &self,
        user: UserId,
        code: Option<&str>,
        recovery_code: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<&'static str>> {
        match (code, recovery_code) {
            (Some(code), None) => {
                let Some(credential) = self.repos.credentials.find_totp(user).await? else {
                    return Ok(None);
                };
                let seed = totp::open(&self.policy.kek, &credential.secret_enc)?;
                match totp::verify_at(&seed, code, now, credential.last_step) {
                    Some(step) => {
                        Ok(self.repos.credentials.commit_totp_step(credential.id, step, now).await?.then_some("totp"))
                    }
                    None => Ok(None),
                }
            }
            (None, Some(recovery)) => {
                // ≤10 stored hashes; every row is checked so timing does not reveal which
                // (if any) code was close. Single-use is the atomic consume (S-05).
                let mut matched = None;
                for row in self.repos.credentials.list_recovery_codes(user).await? {
                    if totp::verify_recovery_code(recovery, &row.phc) && matched.is_none() {
                        matched = Some(row.id);
                    }
                }
                match matched {
                    Some(id) => Ok(self.repos.credentials.consume_recovery_code(id).await?.then_some("recovery")),
                    None => Ok(None),
                }
            }
            _ => Err(Error::Invalid { message: "provide exactly one of code or recovery_code".into() }),
        }
    }

    /// Refuses MFA verifications while the scope is inside an exponential-backoff window
    /// (S-05: ≤5 failures, then backoff on the MFA step only).
    async fn mfa_backoff_gate(&self, scope: &str, now: DateTime<Utc>) -> Result<()> {
        let Some(raw) = self.kv.get(&totp::mfa_backoff_key(scope)).await? else {
            return Ok(());
        };
        let not_before = raw.parse::<i64>().ok().and_then(|ts| DateTime::from_timestamp(ts, 0));
        match not_before {
            Some(not_before) if now < not_before => {
                let retry_after_secs = (not_before - now).num_seconds().max(1) as u64;
                Err(Error::RateLimited { retry_after_secs })
            }
            _ => Ok(()),
        }
    }

    /// Registers one failed MFA verification: spends the attempt atomically and arms the
    /// exponential backoff once the budget is gone, audit-logging the throttle trip (S-24).
    async fn mfa_failure(&self, scope: &str, meta: &ClientMeta, limit: &str, now: DateTime<Utc>) {
        let result: Result<()> = async {
            let failures = self.kv.incr(&totp::mfa_attempt_key(scope), StdDuration::from_secs(15 * 60)).await?;
            if let Some(delay) = totp::backoff_after(failures) {
                let not_before = now + Duration::seconds(delay as i64);
                self.kv
                    .set_ttl(
                        &totp::mfa_backoff_key(scope),
                        &not_before.timestamp().to_string(),
                        StdDuration::from_secs(delay),
                    )
                    .await?;
                self.audit_as(
                    AuditActor::System,
                    meta,
                    "auth.throttled",
                    None,
                    AuditResult::Failure,
                    serde_json::json!({ "limit": limit, "failures": failures, "backoff_secs": delay }),
                    now,
                )
                .await;
            }
            Ok(())
        }
        .await;
        if let Err(err) = result {
            // Counter bookkeeping failed (KV outage): the verification itself already
            // failed, so the caller still gets a denial — log the degraded throttle.
            tracing::error!(error = %err, scope, "mfa failure accounting failed");
        }
    }

    /// Clears the failed-attempt state of an MFA scope after a success.
    async fn clear_mfa_counters(&self, scope: &str) -> Result<()> {
        self.kv.del(&totp::mfa_attempt_key(scope)).await?;
        self.kv.del(&totp::mfa_backoff_key(scope)).await
    }

    /// Audits a failed pending-MFA completion and returns the uniform error (S-04).
    async fn mfa_login_failure(
        &self,
        user: Option<UserId>,
        meta: &ClientMeta,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Error {
        let actor = user.map(AuditActor::User).unwrap_or(AuditActor::System);
        self.audit_as(
            actor,
            meta,
            "auth.login.failure",
            None,
            AuditResult::Failure,
            serde_json::json!({ "method": "mfa", "reason": reason }),
            now,
        )
        .await;
        Error::InvalidCode
    }

    /// Audits a failed OIDC sign-in and returns the uniform error (S-04): the reason —
    /// including every internal id_token diagnostic — reaches the audit log only.
    async fn oidc_failure(
        &self,
        provider: &str,
        email: Option<String>,
        meta: &ClientMeta,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Error {
        self.audit_as(
            AuditActor::System,
            meta,
            "auth.oidc.login.failure",
            email,
            AuditResult::Failure,
            serde_json::json!({ "provider": provider, "reason": reason }),
            now,
        )
        .await;
        Error::Unauthorized { message: "sign-in failed".into() }
    }

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
    ///
    /// Read from the **runtime** settings on every call, so an admin tightening the allowlist
    /// takes effect on the next sign-in rather than on the next restart.
    fn domain_allowed(&self, email: &str) -> bool {
        self.settings().registration.domain_allowed(email)
    }

    /// Whether an account may be **created** for `email` right now (decision 09 registration
    /// mode, evaluated on top of the already-checked S-31 domain gate).
    ///
    /// `Open` admits anyone; `Invite` admits only an address holding a live invitation, which
    /// is what makes "invite-only instance" a real posture rather than a label; `Closed`
    /// admits nobody. Existing accounts sign in in every mode — this gate is about creation.
    async fn registration_allowed(&self, email: &str, now: DateTime<Utc>) -> Result<bool> {
        match self.settings().registration.mode {
            RegistrationMode::Open => Ok(true),
            RegistrationMode::Invite => self.repos.orgs.has_pending_invitation(email, now).await,
            // A mode this build does not know is treated as the most restrictive one: a
            // rolling upgrade must never widen registration by accident.
            RegistrationMode::Closed | _ => Ok(false),
        }
    }

    /// Applies the instance-admin bootstrap to a freshly created account (decision 09).
    ///
    /// Two paths, in order: the configured email list, then "the first account on an instance
    /// that has no administrator yet" — the latter atomically, so two concurrent first
    /// registrations cannot both win it. Best-effort: a bootstrap failure must not fail a
    /// sign-in that has otherwise succeeded, and the next registration retries the claim.
    async fn bootstrap_instance_admin(&self, user: UserId, email: &str, meta: &ClientMeta, now: DateTime<Utc>) {
        let configured = self.policy.instance_admins.iter().any(|listed| listed.eq_ignore_ascii_case(email));
        let promoted = if configured {
            self.repos.users.set_instance_admin(user, true, now).await.map(|_| true)
        } else {
            self.repos.users.claim_first_admin(user, now).await
        };
        match promoted {
            Ok(true) => {
                let reason = if configured { "configured" } else { "first_account" };
                tracing::info!(user = %user, reason, "granted instance administrator rights");
                self.audit_as(
                    AuditActor::System,
                    meta,
                    "admin.granted",
                    Some(user.to_string()),
                    AuditResult::Success,
                    serde_json::json!({ "reason": reason }),
                    now,
                )
                .await;
            }
            Ok(false) => {}
            Err(err) => tracing::error!(user = %user, error = %err, "instance-admin bootstrap failed"),
        }
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
}
