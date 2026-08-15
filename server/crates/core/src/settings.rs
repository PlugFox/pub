//! Runtime-changeable instance settings (decision 09): the typed document, and the per-instance
//! cache that keeps it hot.
//!
//! Three layers, each with one job:
//!
//! 1. [`SettingsRepo`](crate::traits::SettingsRepo) — durable truth, one row per **section**
//!    (`registration`, `rate_limits`, `smtp`, `branding`, `upstream`, `registry`) with a
//!    per-key version.
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
    /// Registry-plane policy: anonymous-read gating (decision 05).
    pub const REGISTRY: &str = "registry";

    /// Every known key, in a stable order.
    pub const ALL: [&str; 6] = [REGISTRATION, RATE_LIMITS, SMTP, BRANDING, UPSTREAM, REGISTRY];
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
    /// Reads per minute for a request with **no** identity — bucketed on the client IP
    /// (S-24.f). Anonymous browsing and anonymous `dart pub` traffic land here.
    pub read_per_ip_minute: u32,
    /// Reads per minute for a request that carries one — a CLI token or a verified session
    /// (S-24.f, S-13.b). Deliberately far above the anonymous number: a CI fleet behind one
    /// NAT is one IP and many tokens, so the per-IP value cannot serve both.
    pub read_per_identity_minute: u32,
    /// App-API **mutations** per minute for a request with no identity — bucketed on the client
    /// IP (S-24.g). An order of magnitude below the read number, because writes are that much
    /// rarer in every legitimate shape.
    pub write_per_ip_minute: u32,
    /// App-API **mutations** per minute for a request that carries an identity (S-24.g). The
    /// pub protocol is excluded — its one write spends the S-24.c publish budget instead — and
    /// so are the six credential endpoints, which spend their own fail-closed buckets.
    pub write_per_identity_minute: u32,
    /// Invitations one org may send per rolling 24 hours (S-24.h).
    ///
    /// Not a KV bucket: an exact `COUNT(*)` over `invitations`, so the window genuinely rolls
    /// and the number survives a KV outage — on the one mutation whose cost is mail delivered to
    /// a third party. It lives in this section because it is a limit an administrator changes,
    /// not because it shares the buckets' mechanism.
    pub invitations_per_day_org: u32,
    /// Invitations one member may send per rolling 24 hours **within one org** (S-24.h), the
    /// per-actor half of the same cap: the org cap bounds the org, this one stops a single
    /// member spending it all.
    pub invitations_per_day_actor: u32,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            otp_per_email_hour: 5,
            otp_per_ip_hour: 20,
            login_per_ip_minute: 10,
            token_auth_fail_per_ip_minute: 30,
            publish_per_hour_org: 30,
            read_per_ip_minute: 600,
            read_per_identity_minute: 3000,
            write_per_ip_minute: 60,
            write_per_identity_minute: 300,
            invitations_per_day_org: 20,
            invitations_per_day_actor: 10,
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

impl SmtpSettings {
    /// Whether this section points at exactly the endpoint described by `host`/`port`/
    /// `username`/`security` — the host comparison is ASCII-case-insensitive because DNS is.
    ///
    /// This is the gate on the boot `[smtp]` password (decision 09 amendment, S-26.a). The boot
    /// credential is the *default* of the runtime one, but a default that followed the section
    /// wherever an administrator repointed it would hand the operator's SMTP password to a
    /// server of the administrator's choosing. One rule, two compositions: the mailer pairs it
    /// with the password itself, the admin surface pairs it with the password's mere presence.
    ///
    /// **Transport security is part of the endpoint.** Comparing only host, port and username
    /// left an instance administrator who never held the credential a one-field escalation:
    /// flip `security` to `none`, leave the other three alone, and the next send puts
    /// `AUTH PLAIN` with the operator's password on the wire in the clear for anyone with a
    /// network position. A downgrade is as effective a redirection as a new hostname, so the
    /// match is on all four fields — including an *upgrade*, because "equal to boot" is the only
    /// comparison that needs no ordering between modes to be safe.
    pub fn same_endpoint(&self, host: Option<&str>, port: u16, username: Option<&str>, security: &str) -> bool {
        let same_host = match (self.host.as_deref(), host) {
            (Some(mine), Some(theirs)) => mine.eq_ignore_ascii_case(theirs),
            (None, None) => true,
            _ => false,
        };
        same_host && self.port == port && self.username.as_deref() == username && self.security == security
    }
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

/// Registry-plane policy (decision 05).
///
/// The first *security* flag to enter this always-readable cache, which changes what the
/// module's fallback stance means here: a corrupt `registry` row restores the operator's boot
/// value rather than the most restrictive one. That is defensible — the fallback is the
/// operator's own configured intent — but it is the opposite of the "unknown ⇒ deny" instinct,
/// so it is stated rather than left to be inferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrySettings {
    /// Whether every pub-protocol read demands a CLI token (S-04.c's named mitigation).
    pub require_auth_for_read: bool,
    /// Default per-org storage quota in bytes; **`0` = unlimited** (S-20.b, decision 32).
    ///
    /// The effective limit for one org is its own `storage_quota_bytes` override when it has one
    /// ([`crate::org::Org::storage_quota_bytes`]) and this number otherwise — the override
    /// **wins**, and it is writable only by an instance admin.
    pub storage_quota_bytes: u64,
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
    /// Registry-plane policy.
    pub registry: RegistrySettings,
}

impl RuntimeSettings {
    /// Overlays one stored section onto this document. Unknown keys and values whose shape
    /// does not parse are **ignored with a warning** rather than propagated: see the module
    /// docs on why the cache must always be readable.
    ///
    /// The overlay is **per field, not per section**. See [`merge_section`] for why replacing
    /// the slot wholesale silently blanked the operator's boot values.
    fn overlay(&mut self, entry: &SettingEntry) {
        fn parse<T: Serialize + for<'de> Deserialize<'de>>(entry: &SettingEntry, slot: &mut T) {
            match merge_section(&entry.value, slot) {
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
            keys::REGISTRY => parse(entry, &mut self.registry),
            _ => {}
        }
    }
}

/// Merges one stored section document **onto the boot value** it is overlaying: a key present in
/// the stored object wins, a key absent from it keeps whatever `boot` holds.
///
/// This is not a stylistic choice, it is the whole correctness of a rolling upgrade. Every
/// section carries `#[serde(default)]`, so deserializing the stored document on its own resolves
/// an absent field to the **struct** default — never to the boot value the operator configured
/// and that [`SettingsCache::apply`] has just cloned into the slot. A stored section written by
/// an older release therefore *blanked* every field that release did not know about, cleanly and
/// with nothing logged, because there was no parse error to warn about. Concretely: an instance
/// that had ever changed a rate limit, upgraded, and set `read_per_ip_minute` in its boot config
/// would silently keep enforcing 600.
///
/// Failure keeps the module's contract exactly as it was — **warn and keep the boot value**:
///
/// - a stored value that is not a JSON object at all (`"nope"`, `7`, `[]`, `null`) is refused
///   here, which is the same refusal `serde_json::from_value` used to produce for the same
///   input;
/// - a stored key whose *type* is wrong fails the deserialize below and takes the whole section
///   with it, again as before. Salvaging the other keys of a section somebody corrupted would
///   mean serving half a document nobody wrote.
///
/// Unknown keys survive the merge into the intermediate object and are dropped by the
/// deserialize, which is what keeps a newer release's field harmless to an older replica.
fn merge_section<T: Serialize + for<'de> Deserialize<'de>>(stored: &serde_json::Value, boot: &T) -> SectionResult<T> {
    use serde::de::Error as _;

    let serde_json::Value::Object(stored) = stored else {
        return Err(serde_json::Error::custom(format!(
            "invalid type: {}, expected a settings section object",
            match stored {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "sequence",
                serde_json::Value::Object(_) => unreachable!("matched above"),
            }
        )));
    };
    let mut merged = serde_json::to_value(boot)?;
    // Every section is a struct, so its serialization is an object; the guard is here because
    // "unreachable" and "panics in production" are one refactor apart.
    let serde_json::Value::Object(fields) = &mut merged else {
        return Err(serde_json::Error::custom("a settings section must serialize to an object"));
    };
    for (key, value) in stored {
        fields.insert(key.clone(), value.clone());
    }
    serde_json::from_value(merged)
}

/// Result of one section merge; the error is only ever handed to [`tracing_warn`].
type SectionResult<T> = std::result::Result<T, serde_json::Error>;

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

    /// A boot document in which **every field of every section differs from that section's
    /// struct default**, so a test that asserts "the boot value survived" cannot pass by
    /// accident when the implementation actually produced the struct default.
    ///
    /// **Sections must stay flat**, because [`RuntimeSettings::overlay`] merges stored keys over
    /// the boot document **one level deep**.
    ///
    /// That depth is what fixes the defect this module's guard exists for: a stored section
    /// written by an older release must not blank the fields it never knew about. A *nested*
    /// field would reintroduce it one level down and just as silently — a stored
    /// `{"outer": {"a": 1}}` replaces the whole `outer` object, so every sibling of `a` reverts
    /// to the struct default, parses cleanly, and logs nothing. Today every field of every
    /// section is a scalar, an `Option<scalar>`, a `Vec<String>` or a string-serialized enum, so
    /// the merge is total; this asserts that rather than trusting the next author to know it.
    #[test]
    fn every_settings_section_is_flat_so_the_one_level_merge_is_total() {
        let document = serde_json::to_value(boot_document_unlike_every_struct_default()).expect("serialize");
        let sections = document.as_object().expect("the document is an object");
        assert_eq!(sections.len(), keys::ALL.len(), "one key per section");
        for (section, body) in sections {
            for (field, value) in body.as_object().expect("a section is an object") {
                assert!(
                    !value.is_object(),
                    "{section}.{field} is nested; overlay() merges one level, so a stored document \
                     omitting one of its inner fields would silently reset that field to the struct \
                     default. Flatten it, or make the merge recursive."
                );
                if let Some(items) = value.as_array() {
                    assert!(
                        items.iter().all(|item| !item.is_object()),
                        "{section}.{field} holds objects; same problem, one level down"
                    );
                }
            }
        }
    }

    /// This is the fixture the previous version of the partial-section guard was missing: it
    /// built its cache from `RuntimeSettings::default()`, where the two coincide.
    fn boot_document_unlike_every_struct_default() -> RuntimeSettings {
        let boot = RuntimeSettings {
            registration: RegistrationSettings {
                mode: RegistrationMode::Invite,
                allowed_email_domains: vec!["corp.example".to_owned()],
            },
            rate_limits: RateLimitSettings {
                otp_per_email_hour: 51,
                otp_per_ip_hour: 52,
                login_per_ip_minute: 53,
                token_auth_fail_per_ip_minute: 54,
                publish_per_hour_org: 55,
                read_per_ip_minute: 56,
                read_per_identity_minute: 57,
                write_per_ip_minute: 58,
                write_per_identity_minute: 59,
                invitations_per_day_org: 60,
                invitations_per_day_actor: 61,
            },
            smtp: SmtpSettings {
                host: Some("smtp.corp.example".to_owned()),
                port: 2525,
                username: Some("mailer".to_owned()),
                from: "pub@corp.example".to_owned(),
                security: "starttls".to_owned(),
                password_sealed: Some("c2VhbGVk".to_owned()),
            },
            branding: BrandingSettings {
                name: "Acme Registry".to_owned(),
                tagline: "internal packages".to_owned(),
                logo_url: "https://corp.example/logo.svg".to_owned(),
                primary_color: "#123456".to_owned(),
            },
            upstream: UpstreamSettings { enabled: true, default_org_policy: UpstreamPolicy::Block },
            registry: RegistrySettings { require_auth_for_read: true, storage_quota_bytes: 10 * 1024 * 1024 * 1024 },
        };

        // The fixture's own guard: if a new field is added to a section and not given a
        // non-default value here, the section below stops discriminating and nobody notices.
        let defaults = RuntimeSettings::default();
        for (key, boot_section, default_section) in [
            (keys::REGISTRATION, json(&boot.registration), json(&defaults.registration)),
            (keys::RATE_LIMITS, json(&boot.rate_limits), json(&defaults.rate_limits)),
            (keys::SMTP, json(&boot.smtp), json(&defaults.smtp)),
            (keys::BRANDING, json(&boot.branding), json(&defaults.branding)),
            (keys::UPSTREAM, json(&boot.upstream), json(&defaults.upstream)),
            (keys::REGISTRY, json(&boot.registry), json(&defaults.registry)),
        ] {
            let boot_fields = boot_section.as_object().expect("a section is an object");
            let default_fields = default_section.as_object().expect("a section is an object");
            for (field, value) in boot_fields {
                assert_ne!(
                    Some(value),
                    default_fields.get(field),
                    "{key}.{field} equals its struct default, so it cannot discriminate a merge from a replace"
                );
            }
        }
        boot
    }

    fn json<T: Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).expect("a settings section serializes")
    }

    /// A stored section is merged onto the **boot** value per field: a key the stored document
    /// carries wins, a key it omits keeps what the operator configured — never the struct
    /// default.
    ///
    /// This is the rolling-upgrade property, and it is per **section**, so every section is
    /// exercised: an older release wrote `{"require_auth_for_read": true}`, this one knows
    /// `storage_quota_bytes` as well, and the operator's boot quota must survive the overlay.
    /// The old `*slot = value` implementation failed this silently — a freshly deserialized
    /// section resolves its absent fields to `#[serde(default)]`, which parses cleanly, so the
    /// warn-and-keep path never fired and nothing was logged.
    #[test]
    fn a_partial_section_document_keeps_the_boot_value_of_every_field_it_omits() {
        let boot = boot_document_unlike_every_struct_default();

        // One stored key per section, and the rest of that section must survive untouched.
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (keys::REGISTRATION, serde_json::json!({ "mode": "closed" })),
            (keys::RATE_LIMITS, serde_json::json!({ "login_per_ip_minute": 3 })),
            (keys::SMTP, serde_json::json!({ "port": 465 })),
            (keys::BRANDING, serde_json::json!({ "name": "Renamed" })),
            (keys::UPSTREAM, serde_json::json!({ "enabled": false })),
            // The wave-4 shape, exactly: an instance that stored the `registry` section before
            // the quota field existed, then configured a quota at boot.
            (keys::REGISTRY, serde_json::json!({ "require_auth_for_read": true })),
        ];

        for (key, stored) in cases {
            let cache = SettingsCache::new(boot.clone());
            cache.apply(&[entry(key, stored.clone())], 9);
            let current = cache.current();

            // What the boot document would look like with only the stored keys applied.
            let mut expected = json(&boot);
            let section = expected.get_mut(key).expect("a known section").as_object_mut().expect("an object");
            for (field, value) in stored.as_object().expect("a stored section object") {
                section.insert(field.clone(), value.clone());
            }
            let expected: RuntimeSettings = serde_json::from_value(expected).expect("the expected document");
            assert_eq!(*current, expected, "{key}: a stored key must win and an absent one must keep the boot value");
        }
    }

    /// The concrete regression [S-20.b](../../../docs/security.md) made consequential: an
    /// instance that stored `registry` before `storage_quota_bytes` existed, upgraded, and set
    /// the quota in its boot config.
    ///
    /// Under `*slot = value` the stored section deserialized to `storage_quota_bytes: 0`, `0`
    /// means **unlimited**, and the quota was never enforced — with nothing in the log, because
    /// the document parsed cleanly.
    #[test]
    fn s20_b_a_stored_registry_section_from_an_older_release_cannot_blank_the_boot_quota() {
        const QUOTA: u64 = 10 * 1024 * 1024 * 1024;
        let boot = RuntimeSettings {
            registry: RegistrySettings { require_auth_for_read: false, storage_quota_bytes: QUOTA },
            ..RuntimeSettings::default()
        };
        let cache = SettingsCache::new(boot);
        cache.apply(&[entry(keys::REGISTRY, serde_json::json!({ "require_auth_for_read": true }))], 4);
        let registry = cache.current().registry;
        assert!(registry.require_auth_for_read, "the stored key wins");
        assert_eq!(registry.storage_quota_bytes, QUOTA, "an absent key must not silently disable the quota");
    }

    /// The same failure on the section an operator changes most often: four numbers were added
    /// to `rate_limits` in this wave, and an instance that had ever changed a rate limit stored
    /// a document without them.
    #[test]
    fn s24_g_a_stored_rate_limit_section_from_an_older_release_keeps_the_new_boot_numbers() {
        let mut boot = RuntimeSettings::default();
        boot.rate_limits.write_per_ip_minute = 7;
        boot.rate_limits.write_per_identity_minute = 11;
        boot.rate_limits.invitations_per_day_org = 3;
        boot.rate_limits.invitations_per_day_actor = 2;
        let cache = SettingsCache::new(boot);
        // Exactly the seven keys the release before this wave knew.
        cache.apply(
            &[entry(
                keys::RATE_LIMITS,
                serde_json::json!({
                    "otp_per_email_hour": 5, "otp_per_ip_hour": 20, "login_per_ip_minute": 9,
                    "token_auth_fail_per_ip_minute": 30, "publish_per_hour_org": 30,
                    "read_per_ip_minute": 600, "read_per_identity_minute": 3000
                }),
            )],
            2,
        );
        let limits = cache.current().rate_limits;
        assert_eq!(limits.login_per_ip_minute, 9, "the stored numbers still win");
        assert_eq!(
            (limits.write_per_ip_minute, limits.write_per_identity_minute),
            (7, 11),
            "the boot write buckets survive a section that predates them"
        );
        assert_eq!((limits.invitations_per_day_org, limits.invitations_per_day_actor), (3, 2));
    }

    /// A stored section that is not an object at all keeps the whole boot section, warns, and
    /// never panics — the contract this module has always had, restated against the merge.
    #[test]
    fn a_stored_section_of_the_wrong_json_shape_keeps_the_boot_section_whole() {
        let boot = boot_document_unlike_every_struct_default();
        for shape in [
            serde_json::json!("not an object"),
            serde_json::json!(7),
            serde_json::json!(null),
            serde_json::json!([{ "port": 1 }]),
            serde_json::json!(true),
            // A key of the right name and the wrong type takes its own section down with it,
            // rather than half-applying a document nobody wrote.
            serde_json::json!({ "port": "not a number" }),
        ] {
            let cache = SettingsCache::new(boot.clone());
            cache.apply(&[entry(keys::SMTP, shape.clone())], 1);
            assert_eq!(cache.current().smtp, boot.smtp, "{shape}: a bad shape keeps the boot section");
        }
    }

    /// **S-24.g / S-24.h / S-20.b.** The four numbers decision 32 makes runtime-changeable, and
    /// the quota it makes runtime-changeable, actually survive the storage round trip.
    ///
    /// The failure this discriminates is silent: a stored section whose field names do not match
    /// the struct's is *ignored per field* by `#[serde(default)]`, so an instance being spammed
    /// would keep enforcing the boot numbers while the admin surface reported the new ones.
    #[test]
    fn the_wave_4_limits_round_trip_through_a_stored_section() {
        let defaults = RateLimitSettings::default();
        assert_eq!((defaults.write_per_ip_minute, defaults.write_per_identity_minute), (60, 300), "S-24.g defaults");
        assert_eq!(
            (defaults.invitations_per_day_org, defaults.invitations_per_day_actor),
            (20, 10),
            "S-24.h: the org cap preserves the compile-time constant it replaced"
        );

        let cache = SettingsCache::new(RuntimeSettings::default());
        cache.apply(
            &[
                entry(
                    keys::RATE_LIMITS,
                    serde_json::json!({
                        "write_per_ip_minute": 7, "write_per_identity_minute": 11,
                        "invitations_per_day_org": 3, "invitations_per_day_actor": 2
                    }),
                ),
                // 0 is a *value* here, not an unset field: unlimited (S-20.b).
                entry(keys::REGISTRY, serde_json::json!({ "storage_quota_bytes": 4096 })),
            ],
            5,
        );
        let current = cache.current();
        assert_eq!(current.rate_limits.write_per_ip_minute, 7);
        assert_eq!(current.rate_limits.write_per_identity_minute, 11);
        assert_eq!(current.rate_limits.invitations_per_day_org, 3);
        assert_eq!(current.rate_limits.invitations_per_day_actor, 2);
        assert_eq!(current.registry.storage_quota_bytes, 4096);
        // The untouched neighbours of each section are still the defaults they were.
        assert_eq!(current.rate_limits.read_per_ip_minute, defaults.read_per_ip_minute);
        assert!(!current.registry.require_auth_for_read);
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
    fn the_registry_section_falls_back_to_the_boot_flag_when_absent_or_corrupt() {
        // Decision 05 amendment: boot config is the *default* of the flag, and this cache's
        // always-readable stance means a mangled row restores that default rather than failing
        // the read — the one place where "unknown" resolves to the operator's value and not to
        // the most restrictive one.
        let defaults = RuntimeSettings {
            registry: RegistrySettings { require_auth_for_read: true, storage_quota_bytes: 0 },
            ..RuntimeSettings::default()
        };
        let cache = SettingsCache::new(defaults);
        assert!(cache.current().registry.require_auth_for_read, "an unwritten section serves the boot flag");

        cache.apply(&[entry(keys::REGISTRY, serde_json::json!("not an object"))], 1);
        assert!(cache.current().registry.require_auth_for_read, "a corrupt section keeps the boot flag");

        cache.apply(&[entry(keys::REGISTRY, serde_json::json!({ "require_auth_for_read": false }))], 2);
        assert!(!cache.current().registry.require_auth_for_read, "a stored section wins");
    }

    #[test]
    fn an_older_build_ignores_the_registry_section() {
        // The forward-compatibility half: this build ignores a key it does not know, which is
        // exactly what an older replica does with `registry` during a rolling upgrade — it
        // keeps enforcing its own boot flag.
        let cache = SettingsCache::new(RuntimeSettings::default());
        cache.apply(
            &[
                entry("registry_v2_from_a_newer_release", serde_json::json!({ "require_auth_for_read": true })),
                entry(keys::REGISTRY, serde_json::json!({ "require_auth_for_read": true })),
            ],
            3,
        );
        assert!(cache.current().registry.require_auth_for_read);
        assert_eq!(keys::ALL.len(), 6, "every known key is in ALL, or the admin surface cannot write it");
    }

    #[test]
    fn s26_a_the_boot_smtp_credential_only_matches_its_own_endpoint() {
        // S-26.a: repointing the host must not carry the operator's boot password along.
        let boot = SmtpSettings {
            host: Some("smtp.corp.com".to_owned()),
            port: 587,
            username: Some("mailer".to_owned()),
            security: "tls".to_owned(),
            ..SmtpSettings::default()
        };
        let same = |section: &SmtpSettings| {
            section.same_endpoint(boot.host.as_deref(), boot.port, boot.username.as_deref(), &boot.security)
        };
        assert!(same(&boot));
        // DNS is case-insensitive, so a case variant is the same server.
        assert!(same(&SmtpSettings { host: Some("SMTP.Corp.COM".to_owned()), ..boot.clone() }));
        assert!(!same(&SmtpSettings { host: Some("smtp.attacker.example".to_owned()), ..boot.clone() }));
        assert!(!same(&SmtpSettings { port: 2525, ..boot.clone() }));
        assert!(!same(&SmtpSettings { username: Some("someone-else".to_owned()), ..boot.clone() }));
        assert!(!same(&SmtpSettings { host: None, ..boot.clone() }));
        // The security flip: same host, same port, same login user — and the operator's
        // credential would have gone out in `AUTH PLAIN` over an unencrypted connection. A
        // downgrade is a redirection, so it fails the match exactly like a new hostname does.
        assert!(!same(&SmtpSettings { security: "none".to_owned(), ..boot.clone() }));
        assert!(!same(&SmtpSettings { security: "starttls".to_owned(), ..boot.clone() }));
        // Both unset is still "the same endpoint" — an instance with no SMTP at all.
        assert!(SmtpSettings::default().same_endpoint(None, 0, None, ""));
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
