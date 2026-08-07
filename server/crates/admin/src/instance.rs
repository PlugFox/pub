//! Instance administration: runtime settings, user and org moderation, the audit viewer,
//! instance statistics, and manual job runs.
//!
//! **Settings propagation** is the part with a shape worth stating. A write goes
//! repository → version bump → broker publish → local reload, in that order:
//!
//! ```text
//!   PATCH ──► SettingsRepo::upsert(section)      durable truth, per-key version +1
//!         ──► SettingsCache::reload(repo)        this instance is current immediately
//!         ──► Kv::publish(SETTINGS_TOPIC)        peers reload now
//!               ⋮
//!         ◄── SettingsCache::refresh_if_changed  the 30–60 s reconciliation poll catches
//!                                                whatever a reconnect dropped
//! ```
//!
//! The broker message is a *hint* — it carries the new version and nothing else, and losing it
//! costs one poll interval, never correctness. That is why the poll exists at all: Redis
//! pub/sub has no delivery guarantee across a reconnect, and "the rate limit an admin lowered
//! is still the old one on instance 3" is not a failure anybody would notice from outside.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use pub_auth::flows::{AuthService, ClientMeta};
use pub_auth::random::RandomSource;
use pub_auth::secretbox;
use pub_core::audit::{AuditActor, AuditEvent, AuditFilter, AuditResult, NewAuditEvent};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::jobs::JobState;
use pub_core::org::OrgOverview;
use pub_core::package::{QuarantineEntry, RegistryStats, ShadowingAlarm, UpstreamCacheStats};
use pub_core::settings::{
    BrandingSettings, RateLimitSettings, RegistrationSettings, RuntimeSettings, SETTINGS_TOPIC, SettingsCache,
    UpstreamSettings, keys,
};
use pub_core::traits::{JobTrigger, Kv, Repositories};
use pub_core::user::{User, UserCounts, UserFilter, UserStatus};
use pub_core::{Error, Format, Page, Result, UserId};
use pub_registry::ActorMeta;
use serde::{Deserialize, Serialize};

/// How many quarantine and shadowing rows the stats payload carries.
const REGISTER_SAMPLE: u32 = 20;

/// Largest SMTP password the admin surface accepts, in bytes.
const MAX_SMTP_PASSWORD: usize = 512;

/// The SMTP section as it is **read back**: everything except the credential.
///
/// A distinct type, not a filtered serialization of [`pub_core::settings::SmtpSettings`]:
/// "never returned" (S-26) is a property worth making impossible to lose to a future
/// `#[derive(Serialize)]` on the storage struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpView {
    /// SMTP hostname; `None` = not configured at runtime.
    pub host: Option<String>,
    /// SMTP port.
    pub port: u16,
    /// Login user.
    pub username: Option<String>,
    /// `From:` mailbox.
    pub from: String,
    /// Transport security: `tls` | `starttls` | `none`.
    pub security: String,
    /// Whether a password is stored. The value itself never leaves the database unsealed.
    pub password_set: bool,
}

/// The whole runtime-settings document as an administrator sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsView {
    /// Instance settings version — the number the reconciliation poll compares.
    pub version: i64,
    /// Registration policy.
    pub registration: RegistrationSettings,
    /// Rate-limit numbers.
    pub rate_limits: RateLimitSettings,
    /// Outbound SMTP, credential-free.
    pub smtp: SmtpView,
    /// Instance identity.
    pub branding: BrandingSettings,
    /// Upstream proxy defaults.
    pub upstream: UpstreamSettings,
}

/// The SMTP section on a write.
///
/// [`Debug`] is hand-written: this struct carries a live credential in plaintext for the
/// length of one request, and a derived one would put it in any `#[instrument]` field, panic
/// message, or error format that ever touches it (S-25).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SmtpPatch {
    /// SMTP hostname; `None` disables runtime SMTP.
    pub host: Option<String>,
    /// SMTP port.
    pub port: u16,
    /// Login user.
    pub username: Option<String>,
    /// `From:` mailbox.
    pub from: String,
    /// Transport security: `tls` | `starttls` | `none`.
    pub security: String,
    /// New password. `None` keeps whatever is stored; `Some("")` clears it. Sealed under the
    /// env KEK before it reaches the database (S-26) and never read back out by this surface.
    pub password: Option<String>,
}

impl std::fmt::Debug for SmtpPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpPatch")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("from", &self.from)
            .field("security", &self.security)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A settings write: any subset of sections, each replaced wholesale.
///
/// Section-at-a-time rather than field-at-a-time because a section is the unit the cache and
/// the storage row already work in — a field-level patch would need a merge rule per field and
/// would still race the same way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsPatch {
    /// Registration policy.
    pub registration: Option<RegistrationSettings>,
    /// Rate-limit numbers.
    pub rate_limits: Option<RateLimitSettings>,
    /// Outbound SMTP.
    pub smtp: Option<SmtpPatch>,
    /// Instance identity.
    pub branding: Option<BrandingSettings>,
    /// Upstream proxy defaults.
    pub upstream: Option<UpstreamSettings>,
}

impl SettingsPatch {
    /// Whether the patch changes anything.
    pub fn is_empty(&self) -> bool {
        self.registration.is_none()
            && self.rate_limits.is_none()
            && self.smtp.is_none()
            && self.branding.is_none()
            && self.upstream.is_none()
    }
}

/// The admin dashboard's numbers (decision 23 domain counters, read straight from the stores).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceStats {
    /// Account counts.
    pub users: UserCounts,
    /// How many orgs exist.
    pub orgs: i64,
    /// Packages, versions, and the storage those versions account for.
    pub registry: RegistryStats,
    /// Proxy-cache size (decision 07).
    pub upstream_cache: UpstreamCacheStats,
    /// The most recent quarantine records (S-19).
    pub quarantine: Vec<QuarantineEntry>,
    /// The most recent shadowing alarms (S-17).
    pub shadowing: Vec<ShadowingAlarm>,
    /// How many of those alarms are still unacknowledged.
    pub shadowing_active: i64,
    /// Durable state of every background job that has ever run — including the mirror's
    /// last success, which is what `upstream_sync_lag_seconds` is derived from.
    pub jobs: Vec<JobState>,
    /// Jobs this instance can run on demand.
    pub runnable_jobs: Vec<String>,
    /// The instance settings version this instance is serving.
    pub settings_version: i64,
}

/// The instance-administration service.
pub struct AdminService {
    repos: Repositories,
    kv: Arc<dyn Kv>,
    cache: Arc<SettingsCache>,
    auth: Arc<AuthService>,
    events: Arc<dyn EventSink>,
    jobs: Arc<dyn JobTrigger>,
    rng: Arc<dyn RandomSource>,
    kek: Vec<u8>,
}

impl std::fmt::Debug for AdminService {
    /// The KEK never reaches a log line (S-25).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService").field("kek", &"<redacted>").finish_non_exhaustive()
    }
}

impl AdminService {
    /// Builds the service over the configured backends.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repos: Repositories,
        kv: Arc<dyn Kv>,
        cache: Arc<SettingsCache>,
        auth: Arc<AuthService>,
        events: Arc<dyn EventSink>,
        jobs: Arc<dyn JobTrigger>,
        rng: Arc<dyn RandomSource>,
        kek: Vec<u8>,
    ) -> Self {
        Self { repos, kv, cache, auth, events, jobs, rng, kek }
    }

    // ----------------------------------------------------------------------------- settings

    /// The effective settings document, credential-free.
    pub fn settings(&self) -> SettingsView {
        let current = self.cache.current();
        Self::view(&current, self.cache.version())
    }

    /// Applies a settings patch: durable write, local reload, cross-instance invalidation.
    ///
    /// Returns the new view. An empty patch is [`Error::Invalid`] rather than a no-op that
    /// bumps a version and pages every instance for nothing.
    pub async fn update_settings(
        &self,
        patch: SettingsPatch,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<SettingsView> {
        if patch.is_empty() {
            return Err(Error::Invalid { message: "no settings sections were supplied".to_owned() });
        }
        let before = self.cache.current();
        let mut written: Vec<&'static str> = Vec::new();

        if let Some(registration) = &patch.registration {
            let registration = normalize_registration(registration)?;
            self.write(keys::REGISTRATION, &registration, now).await?;
            written.push(keys::REGISTRATION);
        }
        if let Some(limits) = &patch.rate_limits {
            validate_rate_limits(limits)?;
            self.write(keys::RATE_LIMITS, limits, now).await?;
            written.push(keys::RATE_LIMITS);
        }
        if let Some(smtp) = &patch.smtp {
            let sealed = self.seal_smtp_password(smtp, before.smtp.password_sealed.clone())?;
            let section = pub_core::settings::SmtpSettings {
                host: smtp.host.clone().map(|host| host.trim().to_owned()).filter(|host| !host.is_empty()),
                port: smtp.port,
                username: smtp.username.clone().filter(|user| !user.is_empty()),
                from: smtp.from.clone(),
                security: validate_security(&smtp.security)?,
                password_sealed: sealed,
            };
            if section.port == 0 {
                return Err(Error::Invalid { message: "smtp.port must be greater than 0".to_owned() });
            }
            self.write(keys::SMTP, &section, now).await?;
            written.push(keys::SMTP);
        }
        if let Some(branding) = &patch.branding {
            if branding.name.trim().is_empty() {
                return Err(Error::Invalid { message: "branding.name must not be empty".to_owned() });
            }
            self.write(keys::BRANDING, branding, now).await?;
            written.push(keys::BRANDING);
        }
        if let Some(upstream) = &patch.upstream {
            self.write(keys::UPSTREAM, upstream, now).await?;
            written.push(keys::UPSTREAM);
        }

        // Reload from the durable rows rather than from the patch: whatever another instance
        // wrote concurrently is part of the truth this one now serves.
        let version = self.cache.reload(self.repos.settings.as_ref()).await?;
        // Best-effort fan-out. A broker outage costs one poll interval on the peers, so it is
        // logged rather than failing a write that is already durable.
        if let Err(err) = self.kv.publish(SETTINGS_TOPIC, &version.to_string()).await {
            tracing::warn!(error = %err, "settings invalidation broadcast failed; peers reconcile on the next poll");
        }

        self.audit(
            actor,
            "admin.settings",
            None,
            AuditResult::Success,
            // The before/after payload names the sections, never their values: one of those
            // values is a sealed SMTP password (S-22 "never log secrets").
            serde_json::json!({ "sections": written, "version": version }),
            now,
        )
        .await;
        self.events
            .emit(DomainEvent::InstanceSettingsChanged {
                keys: written.iter().map(|key| (*key).to_owned()).collect(),
                version,
                at: now,
            })
            .await;

        Ok(self.settings())
    }

    /// Seals a new SMTP password, or carries the stored one forward.
    fn seal_smtp_password(&self, patch: &SmtpPatch, stored: Option<String>) -> Result<Option<String>> {
        use base64::Engine as _;

        match patch.password.as_deref() {
            // Absent: keep whatever is stored. This is what makes the field write-only —
            // a round-trip of the returned view cannot blank the credential.
            None => Ok(stored),
            // Empty: an explicit clear.
            Some("") => Ok(None),
            Some(password) => {
                if password.len() > MAX_SMTP_PASSWORD {
                    return Err(Error::Invalid {
                        message: format!("smtp password must be at most {MAX_SMTP_PASSWORD} bytes"),
                    });
                }
                let sealed = secretbox::seal(&self.kek, self.rng.as_ref(), password.as_bytes())?;
                Ok(Some(base64::engine::general_purpose::STANDARD.encode(sealed)))
            }
        }
    }

    /// Writes one settings section.
    async fn write<T: Serialize>(&self, key: &str, value: &T, now: DateTime<Utc>) -> Result<()> {
        let json = serde_json::to_value(value)
            .map_err(|err| Error::Internal { message: format!("settings serialization failed: {err}") })?;
        self.repos.settings.upsert(key, &json, now).await?;
        Ok(())
    }

    /// Projects a snapshot onto the credential-free view.
    fn view(current: &RuntimeSettings, version: i64) -> SettingsView {
        SettingsView {
            version,
            registration: current.registration.clone(),
            rate_limits: current.rate_limits,
            smtp: SmtpView {
                host: current.smtp.host.clone(),
                port: current.smtp.port,
                username: current.smtp.username.clone(),
                from: current.smtp.from.clone(),
                security: current.smtp.security.clone(),
                password_set: current.smtp.password_sealed.is_some(),
            },
            branding: current.branding.clone(),
            upstream: current.upstream,
        }
    }

    // -------------------------------------------------------------------------------- users

    /// The admin user listing.
    pub async fn list_users(&self, filter: &UserFilter, cursor: Option<&str>, limit: u32) -> Result<Page<User>> {
        self.repos.users.list(filter, cursor, limit).await
    }

    /// Suspends or reinstates an account.
    ///
    /// Suspension revokes every session (S-09): the account's authority just went to zero, and
    /// an access token minted a minute ago would otherwise keep working for up to one TTL.
    /// Reinstatement does not — there is nothing stale to withdraw.
    ///
    /// An account cannot suspend itself: an instance with one administrator would lock itself
    /// out of its own admin surface with no way back that does not involve the database.
    pub async fn set_user_suspended(
        &self,
        target: UserId,
        suspended: bool,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<User> {
        if target == actor.user_id && suspended {
            return Err(Error::Invalid { message: "an administrator cannot suspend their own account".to_owned() });
        }
        let user =
            self.repos.users.get(target).await?.ok_or_else(|| Error::NotFound { what: format!("user {target}") })?;
        if user.status == UserStatus::Deleted {
            return Err(Error::Conflict { message: "the account is deleted".to_owned() });
        }
        let status = if suspended { UserStatus::Suspended } else { UserStatus::Active };
        let updated = self.repos.users.update_status(target, status, now).await?;

        let mut revoked = 0;
        if suspended {
            let meta = ClientMeta { ip: actor.ip.clone(), user_agent: actor.user_agent.clone() };
            revoked = self.auth.revoke_sessions_after_authority_change(target, "account_suspended", &meta, now).await?;
        }
        self.audit(
            actor,
            if suspended { "admin.user.suspend" } else { "admin.user.unsuspend" },
            Some(target.to_string()),
            AuditResult::Success,
            serde_json::json!({ "before": user.status.as_str(), "after": status.as_str(), "sessions_revoked": revoked }),
            now,
        )
        .await;
        Ok(updated)
    }

    // --------------------------------------------------------------------------------- orgs

    /// Every org with its member and package counts.
    pub async fn list_orgs(&self, cursor: Option<&str>, limit: u32) -> Result<Page<OrgOverview>> {
        self.repos.orgs.list_all(cursor, limit).await
    }

    // -------------------------------------------------------------------------------- audit

    /// The audit viewer (S-22/S-23), newest first.
    pub async fn list_audit(&self, filter: &AuditFilter, cursor: Option<&str>, limit: u32) -> Result<Page<AuditEvent>> {
        self.repos.audit.list(filter, cursor, limit).await
    }

    // -------------------------------------------------------------------------------- stats

    /// The dashboard numbers.
    pub async fn stats(&self, now: DateTime<Utc>) -> Result<InstanceStats> {
        let _ = now;
        let quarantine = self.repos.upstream.list_quarantine(REGISTER_SAMPLE).await?;
        let shadowing = self.repos.upstream.list_shadowing(false, REGISTER_SAMPLE).await?;
        let shadowing_active = shadowing.iter().filter(|alarm| alarm.is_active()).count() as i64;
        Ok(InstanceStats {
            users: self.repos.users.counts().await?,
            orgs: self.repos.orgs.count().await?,
            registry: self.repos.packages.stats().await?,
            upstream_cache: self.repos.upstream.cache_stats(Format::Pub).await?,
            quarantine,
            shadowing,
            shadowing_active,
            jobs: self.repos.jobs.list().await?,
            runnable_jobs: self.jobs.names(),
            settings_version: self.cache.version(),
        })
    }

    // --------------------------------------------------------------------------------- jobs

    /// Runs a background job now (`POST /api/v1/admin/jobs/{job}/run`).
    ///
    /// Audited on both outcomes: a manual sweep is an operator action with real cost — a
    /// mirror pass fetches from upstream, a GC pass deletes bytes — and "who pressed it" is
    /// exactly the question asked afterwards.
    pub async fn run_job(&self, name: &str, actor: &ActorMeta, now: DateTime<Utc>) -> Result<serde_json::Value> {
        match self.jobs.run_now(name, now).await {
            Ok(summary) => {
                self.audit(
                    actor,
                    "admin.job.run",
                    Some(name.to_owned()),
                    AuditResult::Success,
                    serde_json::json!({ "summary": summary }),
                    now,
                )
                .await;
                Ok(summary)
            }
            Err(err) => {
                self.audit(
                    actor,
                    "admin.job.run",
                    Some(name.to_owned()),
                    AuditResult::Failure,
                    serde_json::json!({ "error": err.code() }),
                    now,
                )
                .await;
                Err(err)
            }
        }
    }

    /// Appends an audit event; failures are logged, never propagated.
    async fn audit(
        &self,
        actor: &ActorMeta,
        action: &str,
        target: Option<String>,
        result: AuditResult,
        metadata: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        let event = NewAuditEvent {
            actor: AuditActor::User(actor.user_id),
            ip: actor.ip.clone(),
            user_agent: actor.user_agent.clone(),
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

/// Runs the reconciliation poll once (decision 09): reload iff the durable version moved.
///
/// A free function rather than a method so the jobs crate can schedule it without depending on
/// the admin service, and so a test can drive one tick deterministically instead of waiting.
pub async fn poll_settings(cache: &SettingsCache, repos: &Repositories) -> Result<bool> {
    cache.refresh_if_changed(repos.settings.as_ref()).await
}

/// Default interval for the reconciliation poll (decision 09: 30–60 s).
pub const SETTINGS_POLL_INTERVAL: Duration = Duration::seconds(45);

/// Lowercases and de-blanks the domain allowlist, and rejects entries that are not domains.
fn normalize_registration(input: &RegistrationSettings) -> Result<RegistrationSettings> {
    let mut domains = Vec::with_capacity(input.allowed_email_domains.len());
    for raw in &input.allowed_email_domains {
        let domain = raw.trim().trim_start_matches('@').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        // A domain with an `@` or whitespace inside it would silently match nothing and turn
        // the allowlist into a lockout (S-31 changes are admin-only and audited, so a typo
        // here is a support ticket at best).
        if domain.contains('@') || domain.contains(char::is_whitespace) || !domain.contains('.') {
            return Err(Error::Invalid { message: format!("{raw:?} is not an email domain") });
        }
        domains.push(domain);
    }
    domains.sort();
    domains.dedup();
    Ok(RegistrationSettings { mode: input.mode, allowed_email_domains: domains })
}

/// Every rate limit must be positive: a zero would lock the instance out of its own sign-in.
fn validate_rate_limits(limits: &RateLimitSettings) -> Result<()> {
    let zeroes: Vec<&str> = [
        ("otp_per_email_hour", limits.otp_per_email_hour),
        ("otp_per_ip_hour", limits.otp_per_ip_hour),
        ("login_per_ip_minute", limits.login_per_ip_minute),
        ("token_auth_fail_per_ip_minute", limits.token_auth_fail_per_ip_minute),
        ("publish_per_hour_org", limits.publish_per_hour_org),
    ]
    .into_iter()
    .filter(|(_, value)| *value == 0)
    .map(|(name, _)| name)
    .collect();
    if zeroes.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid { message: format!("rate limits must be greater than 0: {}", zeroes.join(", ")) })
    }
}

/// Accepts only the three transport modes the mailer knows.
fn validate_security(raw: &str) -> Result<String> {
    match raw {
        "tls" | "starttls" | "none" => Ok(raw.to_owned()),
        other => {
            Err(Error::Invalid { message: format!("unknown smtp security {other:?}: use tls, starttls, or none") })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_allowlist_is_normalized_and_typos_are_refused() {
        let input = RegistrationSettings {
            mode: pub_core::settings::RegistrationMode::Open,
            allowed_email_domains: vec![" @CORP.com ".to_owned(), "corp.com".to_owned(), String::new()],
        };
        let normalized = normalize_registration(&input).unwrap();
        assert_eq!(normalized.allowed_email_domains, vec!["corp.com".to_owned()]);

        for bad in ["dev@corp.com", "corp com", "localhost"] {
            let input = RegistrationSettings {
                mode: pub_core::settings::RegistrationMode::Open,
                allowed_email_domains: vec![bad.to_owned()],
            };
            assert_eq!(normalize_registration(&input).unwrap_err().code(), "invalid_argument", "accepted {bad:?}");
        }
    }

    #[test]
    fn a_zero_rate_limit_is_refused_because_it_would_lock_the_instance_out() {
        let mut limits = RateLimitSettings::default();
        assert!(validate_rate_limits(&limits).is_ok());
        limits.login_per_ip_minute = 0;
        let err = validate_rate_limits(&limits).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(err.to_string().contains("login_per_ip_minute"));
    }

    #[test]
    fn smtp_security_is_an_enum_not_a_free_string() {
        assert_eq!(validate_security("starttls").unwrap(), "starttls");
        assert_eq!(validate_security("plaintext").unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn the_view_reports_only_whether_a_password_exists() {
        let mut settings = RuntimeSettings::default();
        settings.smtp.password_sealed = Some("c2VhbGVk".to_owned());
        let view = AdminService::view(&settings, 3);
        assert!(view.smtp.password_set);
        // Structural: there is no field on the view that could carry it.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json["smtp"].get("password").is_none());
        assert!(json["smtp"].get("password_sealed").is_none());
        assert!(!serde_json::to_string(&json).unwrap().contains("c2VhbGVk"));
    }

    #[test]
    fn an_empty_patch_changes_nothing_and_says_so() {
        assert!(SettingsPatch::default().is_empty());
        let patch = SettingsPatch { branding: Some(BrandingSettings::default()), ..SettingsPatch::default() };
        assert!(!patch.is_empty());
    }

    #[test]
    fn a_patched_password_never_reaches_a_debug_line() {
        let patch = SmtpPatch { password: Some("hunter2".to_owned()), ..SmtpPatch::default() };
        // Through the whole containing patch, which is what a handler would actually log.
        let rendered = format!("{:?}", SettingsPatch { smtp: Some(patch), ..SettingsPatch::default() });
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("hunter2"));
    }
}
