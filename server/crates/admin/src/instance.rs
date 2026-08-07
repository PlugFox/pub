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
    BrandingSettings, RateLimitSettings, RegistrationSettings, RegistrySettings, RuntimeSettings, SETTINGS_TOPIC,
    SettingsCache, SmtpSettings, UpstreamSettings, keys,
};
use pub_core::traits::{JobTrigger, Kv, Mailer, Repositories};
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
    /// Registry-plane policy.
    pub registry: RegistrySettings,
}

/// The outcome of `POST /api/v1/admin/settings/smtp/test`.
///
/// Carries the diagnosis an operator needs and nothing else: a write-only credential behind a
/// lazily-rebuilt transport is otherwise undiagnosable, and there is no field here a password
/// could hide in (S-26.a).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestMailReport {
    /// Whether the mailer accepted the message.
    pub delivered: bool,
    /// Effective SMTP host; `None` = none configured, so nothing was delivered anywhere.
    pub host: Option<String>,
    /// Effective transport security.
    pub security: String,
    /// Whether the transport presented credentials.
    pub credentialed: bool,
    /// The diagnosis, not a status: the SMTP failure text on a refusal, and on an instance with
    /// no SMTP host the notice that the message went to the in-memory outbox.
    pub detail: Option<String>,
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
    /// Registry-plane policy.
    pub registry: Option<RegistrySettings>,
}

impl SettingsPatch {
    /// Whether the patch changes anything.
    pub fn is_empty(&self) -> bool {
        self.registration.is_none()
            && self.rate_limits.is_none()
            && self.smtp.is_none()
            && self.branding.is_none()
            && self.upstream.is_none()
            && self.registry.is_none()
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
    mailer: Arc<dyn Mailer>,
    /// Whether boot config carries `[smtp].password`. The value itself never reaches this
    /// service — the mailer holds it — but whether it exists decides two things here: whether a
    /// runtime `username` is credentialed, and whether the pairing rule below is satisfied.
    boot_smtp_password: bool,
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
        mailer: Arc<dyn Mailer>,
        boot_smtp_password: bool,
    ) -> Self {
        Self { repos, kv, cache, auth, events, jobs, rng, kek, mailer, boot_smtp_password }
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

        // **Every section is validated before any section is written.** Six independent upserts
        // with an early return between them meant a refused PATCH had already committed the
        // sections ahead of the refusal, and the web form always submits all six: an SMTP typo
        // silently dropped the `registry` anonymous-read flag the administrator had just ticked
        // while the 400 named only SMTP. A 400 from here means nothing changed.
        let registration = patch.registration.as_ref().map(normalize_registration).transpose()?;
        if let Some(limits) = &patch.rate_limits {
            validate_rate_limits(limits)?;
        }
        let smtp = patch.smtp.as_ref().map(|smtp| self.validated_smtp(smtp, &before)).transpose()?;
        if let Some(branding) = &patch.branding
            && branding.name.trim().is_empty()
        {
            return Err(Error::Invalid { message: "branding.name must not be empty".to_owned() });
        }

        let mut written: Vec<&'static str> = Vec::new();
        if let Err(error) = self.write_sections(&patch, registration, smtp, now, &mut written).await {
            // Nothing here is a validation failure any more — this is the database itself. A
            // section that did land is durable, so the cache must not keep serving the
            // pre-PATCH document beside it (an S-24 divergence that outlives the request).
            if let Err(error) = self.cache.reload(self.repos.settings.as_ref()).await {
                tracing::error!(%error, "settings cache reload after a failed write failed");
            }
            return Err(error);
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

    /// Validates one SMTP patch into the section that would be stored.
    ///
    /// Every rule the boot validator applies, plus one the boot plane does not need: the section
    /// must be one the transport can actually be *built* from. That check matters more here than
    /// at boot, because a stored section the mailer cannot build is not refused on the send path
    /// — it is either unapplied (the previous transport keeps delivering to an endpoint this row
    /// no longer names) or unusable (every message retries and then dead-letters). The write is
    /// the last moment a human is attached to answer (decision 09 amendment).
    fn validated_smtp(&self, patch: &SmtpPatch, before: &RuntimeSettings) -> Result<SmtpSettings> {
        let section = SmtpSettings {
            host: patch.host.clone().map(|host| host.trim().to_owned()).filter(|host| !host.is_empty()),
            port: patch.port,
            username: patch.username.clone().filter(|user| !user.is_empty()),
            from: patch.from.clone(),
            security: validate_security(&patch.security)?,
            password_sealed: self.seal_smtp_password(patch, before.smtp.password_sealed.clone())?,
        };
        if section.port == 0 {
            return Err(Error::Invalid { message: "smtp.port must be greater than 0".to_owned() });
        }
        if section.host.is_some() && section.from.trim().is_empty() {
            return Err(Error::Invalid { message: "smtp.from must be set when smtp.host is set".to_owned() });
        }
        validate_smtp_credentials(section.username.as_deref(), self.smtp_password_available(&section))?;
        if let Err(err) = pub_mail::validate_section(&section) {
            // The mailer's text already names the offending field; the *code* becomes
            // `invalid_argument` because this is a caller's bad input, not the process's own
            // configuration — the API ladder maps the two to different statuses.
            let message = match err {
                Error::Config { message } => message,
                other => other.to_string(),
            };
            return Err(Error::Invalid { message });
        }
        Ok(section)
    }

    /// Writes the validated sections, in a fixed order.
    ///
    /// Every value reaching this point has passed its validator, so the only failure left is the
    /// database. `written` accumulates in place because the caller needs the list even when a
    /// later write fails — that is what tells it the cache is now behind the durable rows.
    async fn write_sections(
        &self,
        patch: &SettingsPatch,
        registration: Option<RegistrationSettings>,
        smtp: Option<SmtpSettings>,
        now: DateTime<Utc>,
        written: &mut Vec<&'static str>,
    ) -> Result<()> {
        if let Some(registration) = &registration {
            self.write(keys::REGISTRATION, registration, now).await?;
            written.push(keys::REGISTRATION);
        }
        if let Some(limits) = &patch.rate_limits {
            self.write(keys::RATE_LIMITS, limits, now).await?;
            written.push(keys::RATE_LIMITS);
        }
        if let Some(smtp) = &smtp {
            self.write(keys::SMTP, smtp, now).await?;
            written.push(keys::SMTP);
        }
        if let Some(branding) = &patch.branding {
            self.write(keys::BRANDING, branding, now).await?;
            written.push(keys::BRANDING);
        }
        if let Some(upstream) = &patch.upstream {
            self.write(keys::UPSTREAM, upstream, now).await?;
            written.push(keys::UPSTREAM);
        }
        if let Some(registry) = &patch.registry {
            self.write(keys::REGISTRY, registry, now).await?;
            written.push(keys::REGISTRY);
        }
        Ok(())
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

    /// Whether the mailer will find a password for this section.
    ///
    /// The endpoint rule lives on [`SmtpSettings::same_endpoint`] and is shared with the mailer;
    /// this composes it with the one fact the settings table never carries — whether boot config
    /// has an `[smtp].password` at all (S-26.a).
    fn smtp_password_available(&self, section: &SmtpSettings) -> bool {
        if section.password_sealed.is_some() {
            return true;
        }
        let boot = &self.cache.defaults().smtp;
        self.boot_smtp_password
            && section.same_endpoint(boot.host.as_deref(), boot.port, boot.username.as_deref(), &boot.security)
    }

    /// Sends a test message to the acting administrator's **own** verified address.
    ///
    /// No recipient field, deliberately: an operator-triggered mailer aimed at an arbitrary
    /// address is a mail-bomb primitive, and pinning it to the caller removes the vector
    /// entirely instead of rate-limiting it. A delivery failure is a successful diagnosis and
    /// returns `Ok` with `delivered: false` — a wrong SMTP configuration is not a server fault,
    /// and a 5xx would replace the operator's answer with a generic error. Audited on **both**
    /// outcomes, never with a credential (S-22/S-26.a).
    pub async fn send_test_email(&self, actor: &ActorMeta, now: DateTime<Utc>) -> Result<TestMailReport> {
        let user = self
            .repos
            .users
            .get(actor.user_id)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("user {}", actor.user_id) })?;
        let to = user.email.filter(|_| user.email_verified).ok_or_else(|| Error::Invalid {
            message: "the acting administrator has no verified email address to send a test to".to_owned(),
        })?;

        let current = self.cache.current();
        let host = current.smtp.host.clone().filter(|host| !host.trim().is_empty());
        let credentialed =
            host.is_some() && current.smtp.username.is_some() && self.smtp_password_available(&current.smtp);
        let subject = format!("{} SMTP test", current.branding.name);
        let body = format!(
            "This is a test message from {}.\n\nIf you are reading it, outbound mail works.\n",
            current.branding.name
        );

        // The verdict describes the transport that actually ran, which is not the same question
        // as "did a mailer accept the message". A stored section the resolver could not build is
        // either not in force — a memoized transport keeps delivering to an endpoint this row no
        // longer names — or not usable at all, and answering `delivered: true` next to the host
        // an administrator typed in is the one lie this action exists to prevent. No message is
        // sent in that case: there is nothing to learn from it that the resolution has not said.
        let (delivered, error_code, detail) = match self.mailer.resolution() {
            Err(err) => (false, Some(err.code()), Some(sanitize_detail(&err.to_string()))),
            Ok(()) => match self.mailer.send(&to, &subject, &body).await {
                Ok(()) if host.is_none() => (
                    true,
                    None,
                    Some(
                        "no smtp host is configured — the message was written to the in-memory outbox and delivered \
                         nowhere"
                            .to_owned(),
                    ),
                ),
                Ok(()) => (true, None, None),
                Err(err) => (false, Some(err.code()), Some(sanitize_detail(&err.to_string()))),
            },
        };
        self.audit(
            actor,
            "admin.smtp.test",
            Some(to.clone()),
            if delivered { AuditResult::Success } else { AuditResult::Failure },
            // Everything an operator needs to correlate the attempt, and nothing that could be
            // a credential: `credentialed` is a boolean, never the password behind it.
            serde_json::json!({
                "to": to,
                "host": host,
                "security": current.smtp.security,
                "credentialed": credentialed,
                "error_code": error_code,
            }),
            now,
        )
        .await;
        Ok(TestMailReport { delivered, host, security: current.smtp.security.clone(), credentialed, detail })
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
            registry: current.registry,
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

/// Mirrors the boot validator's SMTP pairing rule on the runtime plane.
///
/// Without it the settings table can hold a half-credential the transport silently drops, while
/// the surface reports `password_set: false` next to a filled-in username — an instance that
/// authenticates as nobody and says so nowhere. `password_available` accounts for the boot
/// fallback, so an administrator who keeps the boot endpoint need not re-enter the password.
fn validate_smtp_credentials(username: Option<&str>, password_available: bool) -> Result<()> {
    if username.is_some() && !password_available {
        return Err(Error::Invalid {
            message: "smtp.username needs a password: supply smtp.password, or clear the username".to_owned(),
        });
    }
    Ok(())
}

/// How much of an SMTP error text reaches the operator.
///
/// The server's response is the whole point of the test action, so it is surfaced — but bounded
/// and stripped of control characters, because it is attacker-influenced text (the remote end
/// chooses it) that lands in a log line, an audit row, and a UI.
fn sanitize_detail(raw: &str) -> String {
    const MAX_DETAIL: usize = 400;

    let cleaned: String =
        raw.chars().map(|ch| if ch.is_control() { ' ' } else { ch }).take(MAX_DETAIL).collect::<String>();
    cleaned.trim().to_owned()
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
    fn a_username_without_a_password_is_refused_like_the_boot_validator_refuses_it() {
        assert!(validate_smtp_credentials(None, false).is_ok(), "no username, no requirement");
        assert!(validate_smtp_credentials(Some("mailer"), true).is_ok());
        let err = validate_smtp_credentials(Some("mailer"), false).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert!(err.to_string().contains("smtp.username"));
    }

    #[test]
    fn an_smtp_error_detail_is_bounded_and_stripped_of_control_characters() {
        // The remote end chooses this text, and it lands in a log line, an audit row, and a UI.
        assert_eq!(sanitize_detail("535 auth\r\nfailed"), "535 auth  failed");
        assert_eq!(sanitize_detail(&"x".repeat(1000)).len(), 400);
    }

    #[test]
    fn the_view_reports_the_registry_section() {
        let settings = RuntimeSettings {
            registry: pub_core::settings::RegistrySettings { require_auth_for_read: true },
            ..RuntimeSettings::default()
        };
        let view = AdminService::view(&settings, 9);
        assert!(view.registry.require_auth_for_read);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["registry"]["require_auth_for_read"], true);
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
