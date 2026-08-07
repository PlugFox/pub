//! Runtime-changeable instance settings (decision 09): the typed document, and the per-instance
//! cache that keeps it hot.
//!
//! Three layers, each with one job:
//!
//! 1. [`SettingsRepo`](crate::traits::SettingsRepo) — durable truth, one row per **section**
//!    (`registration`, `rate_limits`, `smtp`, `branding`, `upstream`) with a per-key version.
//!    Sections rather than one blob so a `PATCH` that touches SMTP cannot clobber a concurrent
//!    branding change, and so an unknown future section is ignored instead of dropped.
//! 2. [`SettingsCache`] — the `ArcSwap` snapshot every request reads. It is *always* readable:
//!    a section that is absent, corrupt, or of an unknown shape falls back to the boot-config
//!    default rather than failing the read. Settings gate registration and rate limits, and a
//!    settings outage that closed sign-in instance-wide would be a worse failure than serving
//!    the operator's boot configuration.
//! 3. Invalidation — a broker publish on [`SETTINGS_TOPIC`] for the fast path, plus the
//!    reconciliation version-poll ([`SettingsCache::refresh_if_changed`]) for messages missed
//!    across a reconnect. `SettingsRepo::get_version` is the sum of the per-key versions, so it
//!    strictly increases on every write and one comparison decides whether a reload is needed.
//!
//! **Secrets.** Boot-only material (DB URL, KEK, OTP pepper, JWT keyring, OIDC client secret,
//! public base URL) never appears here — [S-25](../../../docs/security.md). The one credential
//! that *is* runtime-changeable is the SMTP password, and it is stored envelope-encrypted under
//! the env KEK (S-26) in [`SmtpSettings::password_sealed`]; the admin API accepts it on write
//! and never returns it.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::org::UpstreamPolicy;
use crate::traits::SettingsRepo;

/// Broker topic carrying settings-invalidation notices across instances (decision 09).
pub const SETTINGS_TOPIC: &str = "settings.changed";

/// The settings keys this version understands. A key outside this set is left alone by the
/// cache and by the admin API — forward compatibility during a rolling upgrade.
pub mod keys {
    /// Registration mode + sign-in domain allowlist (S-31).
    pub const REGISTRATION: &str = "registration";
    /// Rate-limit numbers (S-24).
    pub const RATE_LIMITS: &str = "rate_limits";
    /// Outbound SMTP (password sealed — S-26).
    pub const SMTP: &str = "smtp";
    /// White-label instance identity (decision 17).
    pub const BRANDING: &str = "branding";
    /// Upstream proxy defaults (decision 07).
    pub const UPSTREAM: &str = "upstream";

    /// Every known key, in a stable order.
    pub const ALL: [&str; 5] = [REGISTRATION, RATE_LIMITS, SMTP, BRANDING, UPSTREAM];
}

/// One entry of the durable settings table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingEntry {
    /// Setting key, e.g. `smtp`, `rate_limits`.
    pub key: String,
    /// JSON value.
    pub value: serde_json::Value,
    /// Per-key version: 1 on first write, +1 per subsequent upsert.
    pub version: i64,
}

/// Who may create an account on this instance (S-31 applies on top, always).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// Any address that passes the domain allowlist may register on first sign-in.
    #[default]
    Open,
    /// Only an address holding a pending, unexpired invitation may register.
    Invite,
    /// Nobody registers; only existing accounts sign in.
    Closed,
}

impl RegistrationMode {
    /// Canonical wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite => "invite",
            Self::Closed => "closed",
        }
    }
}

impl std::fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RegistrationMode {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "invite" => Ok(Self::Invite),
            "closed" => Ok(Self::Closed),
            other => Err(crate::Error::Invalid {
                message: format!("unknown registration mode {other:?}: use open, invite, or closed"),
            }),
        }
    }
}

/// Registration policy (decision 12, S-31).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrationSettings {
    /// Who may create an account.
    pub mode: RegistrationMode,
    /// Sign-in email-domain allowlist, lowercase; empty = every domain (S-31).
    pub allowed_email_domains: Vec<String>,
}

impl RegistrationSettings {
    /// Whether `domain` (already lowercase, no `@`) passes the S-31 allowlist.
    pub fn domain_allowed(&self, email: &str) -> bool {
        if self.allowed_email_domains.is_empty() {
            return true;
        }
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        self.allowed_email_domains.iter().any(|allowed| allowed.eq_ignore_ascii_case(domain))
    }
}

/// Rate-limit numbers (S-24). Zero is rejected by the admin API — a limit of zero would lock
/// the instance out of its own sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitSettings {
    /// OTP requests per email per hour.
    pub otp_per_email_hour: u32,
    /// OTP requests per IP per hour.
    pub otp_per_ip_hour: u32,
    /// Credential redemptions per IP per minute.
    pub login_per_ip_minute: u32,
    /// Failed CLI-token authentications per IP per minute.
    pub token_auth_fail_per_ip_minute: u32,
    /// Publish uploads per org per hour (S-24.c).
    pub publish_per_hour_org: u32,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            otp_per_email_hour: 5,
            otp_per_ip_hour: 20,
            login_per_ip_minute: 10,
            token_auth_fail_per_ip_minute: 30,
            publish_per_hour_org: 30,
        }
    }
}

/// Outbound SMTP (S-26: the password is envelope-encrypted at rest and never returned).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpSettings {
    /// SMTP hostname; `None` = no SMTP configured at runtime (boot config decides).
    pub host: Option<String>,
    /// SMTP port.
    pub port: u16,
    /// Optional login user.
    pub username: Option<String>,
    /// `From:` mailbox.
    pub from: String,
    /// Transport security: `tls` | `starttls` | `none`.
    pub security: String,
    /// The SMTP password, sealed under the env KEK and base64-encoded (S-26).
    ///
    /// Write-only from the API's perspective: the admin surface accepts a plaintext password,
    /// seals it here, and reports only whether one is set. Nothing ever serializes this field
    /// onto the wire — the DTO does not carry it.
    pub password_sealed: Option<String>,
}

/// White-label instance identity (decision 17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BrandingSettings {
    /// Instance name shown in the UI.
    pub name: String,
    /// One-line description; empty = none.
    pub tagline: String,
    /// Absolute logo URL; empty = the UI's own mark.
    pub logo_url: String,
    /// Accent colour as a CSS colour string; empty = the theme default.
    pub primary_color: String,
}

impl Default for BrandingSettings {
    fn default() -> Self {
        Self { name: "Pub".to_owned(), tagline: String::new(), logo_url: String::new(), primary_color: String::new() }
    }
}

/// Upstream proxy defaults (decision 07).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamSettings {
    /// Instance-wide proxy switch. `false` removes step 3 of the resolution order everywhere,
    /// exactly like `[upstream].enabled = false` at boot — this is the runtime half of the
    /// same gate, so an operator can stop egress without a restart.
    pub enabled: bool,
    /// The upstream policy a **newly created** org starts with (existing orgs keep theirs).
    pub default_org_policy: UpstreamPolicy,
}

/// The whole runtime-settings document, as one immutable snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeSettings {
    /// Registration policy.
    pub registration: RegistrationSettings,
    /// Rate-limit numbers.
    pub rate_limits: RateLimitSettings,
    /// Outbound SMTP.
    pub smtp: SmtpSettings,
    /// Instance identity.
    pub branding: BrandingSettings,
    /// Upstream proxy defaults.
    pub upstream: UpstreamSettings,
}

impl RuntimeSettings {
    /// Overlays one stored section onto this document. Unknown keys and values whose shape
    /// does not parse are **ignored with a warning** rather than propagated: see the module
    /// docs on why the cache must always be readable.
    fn overlay(&mut self, entry: &SettingEntry) {
        fn parse<T: for<'de> Deserialize<'de>>(entry: &SettingEntry, slot: &mut T) {
            match serde_json::from_value::<T>(entry.value.clone()) {
                Ok(value) => *slot = value,
                Err(err) => tracing_warn(&entry.key, &err),
            }
        }

        match entry.key.as_str() {
            keys::REGISTRATION => parse(entry, &mut self.registration),
            keys::RATE_LIMITS => parse(entry, &mut self.rate_limits),
            keys::SMTP => parse(entry, &mut self.smtp),
            keys::BRANDING => parse(entry, &mut self.branding),
            keys::UPSTREAM => parse(entry, &mut self.upstream),
            _ => {}
        }
    }
}

/// Logging hook kept out of [`RuntimeSettings::overlay`]'s generic body so the `tracing`
/// call site is one line and easy to grep.
fn tracing_warn(key: &str, err: &serde_json::Error) {
    tracing::warn!(setting = key, error = %err, "stored setting could not be parsed; keeping the boot default");
}

/// The per-instance runtime-settings cache (decision 09).
///
/// Reads are lock-free (`ArcSwap`); writes happen only on a reload. The cache owns the boot
/// **defaults**, which is what makes every read total: a section nobody has ever written, or
/// one that fails to parse, resolves to the operator's configured value.
#[derive(Debug)]
pub struct SettingsCache {
    defaults: RuntimeSettings,
    current: ArcSwap<RuntimeSettings>,
    version: AtomicI64,
}

/// Version stored before the first successful load — below any value `get_version` can return,
/// so the first [`SettingsCache::refresh_if_changed`] always reloads.
const NEVER_LOADED: i64 = -1;

impl SettingsCache {
    /// A cache serving `defaults` until something is loaded over it.
    pub fn new(defaults: RuntimeSettings) -> Self {
        Self { current: ArcSwap::from_pointee(defaults.clone()), defaults, version: AtomicI64::new(NEVER_LOADED) }
    }

    /// The current snapshot. Cheap enough to call per request.
    pub fn current(&self) -> Arc<RuntimeSettings> {
        self.current.load_full()
    }

    /// The boot-config defaults every unset section falls back to.
    pub fn defaults(&self) -> &RuntimeSettings {
        &self.defaults
    }

    /// The instance settings version this snapshot was built from; `-1` before the first load.
    pub fn version(&self) -> i64 {
        self.version.load(Ordering::Acquire)
    }

    /// Replaces the snapshot with `defaults + entries` at `version`.
    pub fn apply(&self, entries: &[SettingEntry], version: i64) {
        let mut merged = self.defaults.clone();
        for entry in entries {
            merged.overlay(entry);
        }
        self.current.store(Arc::new(merged));
        self.version.store(version, Ordering::Release);
    }

    /// Unconditionally reloads from the repository; returns the version now cached.
    pub async fn reload(&self, repo: &dyn SettingsRepo) -> Result<i64> {
        // Version first, entries second: a write landing between the two makes the cache one
        // version *older* than its content, so the next poll reloads. The other order would
        // record a version newer than the content and then never reload — a stale cache that
        // believes it is current is the failure mode worth designing against.
        let version = repo.get_version().await?;
        let entries = repo.get_all().await?;
        self.apply(&entries, version);
        Ok(version)
    }

    /// The reconciliation poll: reloads only when the durable version moved. Returns whether
    /// a reload happened.
    pub async fn refresh_if_changed(&self, repo: &dyn SettingsRepo) -> Result<bool> {
        let version = repo.get_version().await?;
        if version == self.version() {
            return Ok(false);
        }
        self.reload(repo).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    fn entry(key: &str, value: serde_json::Value) -> SettingEntry {
        SettingEntry { key: key.to_owned(), value, version: 1 }
    }

    #[test]
    fn an_unwritten_section_serves_the_boot_default() {
        let mut defaults = RuntimeSettings::default();
        defaults.branding.name = "Acme Registry".to_owned();
        let cache = SettingsCache::new(defaults);
        assert_eq!(cache.version(), NEVER_LOADED);
        assert_eq!(cache.current().branding.name, "Acme Registry");

        // Writing a *different* section must not disturb the untouched one.
        cache.apply(&[entry(keys::REGISTRATION, serde_json::json!({ "mode": "closed" }))], 1);
        assert_eq!(cache.current().branding.name, "Acme Registry");
        assert_eq!(cache.current().registration.mode, RegistrationMode::Closed);
        assert_eq!(cache.version(), 1);
    }

    #[test]
    fn a_corrupt_or_unknown_section_never_breaks_the_snapshot() {
        let cache = SettingsCache::new(RuntimeSettings::default());
        cache.apply(
            &[
                entry(keys::RATE_LIMITS, serde_json::json!("not an object")),
                entry("something_from_a_newer_release", serde_json::json!({ "x": 1 })),
                entry(keys::BRANDING, serde_json::json!({ "name": "Kept" })),
            ],
            7,
        );
        let current = cache.current();
        // The unparseable section fell back to the default rather than poisoning the load.
        assert_eq!(current.rate_limits, RateLimitSettings::default());
        assert_eq!(current.branding.name, "Kept");
        assert_eq!(cache.version(), 7);
    }

    #[test]
    fn a_partial_section_document_fills_the_rest_from_defaults() {
        // `#[serde(default)]` on every section: a stored document written by an older release
        // must not blank the fields it never knew about.
        let cache = SettingsCache::new(RuntimeSettings::default());
        cache.apply(&[entry(keys::RATE_LIMITS, serde_json::json!({ "login_per_ip_minute": 3 }))], 2);
        let limits = cache.current().rate_limits;
        assert_eq!(limits.login_per_ip_minute, 3);
        assert_eq!(limits.otp_per_email_hour, RateLimitSettings::default().otp_per_email_hour);
    }

    #[test]
    fn domain_allowlist_is_case_insensitive_and_empty_means_everything() {
        let mut registration = RegistrationSettings::default();
        assert!(registration.domain_allowed("someone@anywhere.example"));
        registration.allowed_email_domains = vec!["corp.com".to_owned()];
        assert!(registration.domain_allowed("dev@CORP.com"));
        assert!(!registration.domain_allowed("dev@evil.example"));
        // An address with no domain part can never match an allowlist.
        assert!(!registration.domain_allowed("nodomain"));
    }

    #[test]
    fn registration_mode_round_trips_and_rejects_junk() {
        for mode in [RegistrationMode::Open, RegistrationMode::Invite, RegistrationMode::Closed] {
            assert_eq!(RegistrationMode::from_str(mode.as_str()).unwrap(), mode);
        }
        assert_eq!(RegistrationMode::from_str("maybe").unwrap_err().code(), "invalid_argument");
        assert_eq!(serde_json::to_string(&RegistrationMode::Invite).unwrap(), "\"invite\"");
    }

    #[test]
    fn the_sealed_smtp_password_is_a_field_of_the_document_and_not_of_the_wire() {
        // The stored document carries it (sealed, S-26); nothing in this module hands it out
        // unsealed, and the API DTO has no field for it at all.
        let smtp = SmtpSettings { password_sealed: Some("c2VhbGVk".to_owned()), ..SmtpSettings::default() };
        let json = serde_json::to_value(&smtp).unwrap();
        assert_eq!(json["password_sealed"], "c2VhbGVk");
        let round_tripped: SmtpSettings = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.password_sealed.as_deref(), Some("c2VhbGVk"));
    }
}
