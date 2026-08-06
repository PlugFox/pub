//! Layered boot configuration (decision 09).
//!
//! Precedence, lowest to highest: built-in defaults → optional TOML file (`--config PATH`) →
//! environment (`PUB_` prefix, `__` nesting separator, e.g. `PUB_DATABASE__URL`) → CLI flags.
//! Validation is fail-fast at startup, and [`Settings::summary`] renders the effective
//! configuration with secrets masked.
//!
//! Runtime-changeable settings (SMTP, rate limits, banners, …) do **not** live here — they
//! belong to the DB `settings` table and arrive in a later roadmap step.

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

mod validate;

/// Errors produced while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A source failed to load or deserialize (bad TOML, unknown enum kind, type mismatch).
    #[error("failed to load configuration: {0}")]
    Source(#[from] config::ConfigError),
    /// The merged configuration is semantically invalid.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl From<ConfigError> for pub_core::Error {
    fn from(err: ConfigError) -> Self {
        pub_core::Error::Config { message: err.to_string() }
    }
}

/// Command-line flags — the highest-precedence configuration layer.
#[derive(Debug, Clone, Default, clap::Parser)]
#[command(name = "pubd", about = "Pub — self-hosted package registry", disable_version_flag = true)]
pub struct CliArgs {
    /// Path to a TOML configuration file.
    #[arg(long, value_name = "PATH", env = "PUB_CONFIG")]
    pub config: Option<PathBuf>,

    /// Socket address to listen on (overrides `server.listen`).
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,

    /// Public base URL of this instance (overrides `server.public_url`).
    #[arg(long, value_name = "URL")]
    pub public_url: Option<String>,

    /// Number of app replicas sharing this configuration (overrides `cluster.replicas`).
    #[arg(long, value_name = "N")]
    pub replicas: Option<u32>,
}

/// Root of the effective boot configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// Database backend selection and connection settings.
    pub database: DatabaseConfig,
    /// Blob storage backend selection and settings.
    pub blob: BlobConfig,
    /// Key-value store / broker backend selection and settings.
    pub kv: KvConfig,
    /// Observability exports (off by default — decision 23).
    pub telemetry: TelemetryConfig,
    /// Multi-instance topology.
    pub cluster: ClusterConfig,
    /// Authentication: JWT keyring, OTP pepper, session windows, rate limits.
    pub auth: AuthConfig,
    /// Outbound SMTP; unset host = the in-memory dev mailer.
    pub smtp: SmtpConfig,
}

/// Deployment mode: gates the dev-only secret fallbacks (S-25).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    /// Local development: missing auth secrets fall back to loud ephemeral values.
    #[default]
    Dev,
    /// Production-like: missing pepper/signing key is a startup error.
    Production,
}

impl RunMode {
    /// Canonical lowercase name as used in config files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Production => "production",
        }
    }
}

/// Authentication section (S-03, S-07, S-08, S-24, S-25, S-31; decisions 03/13/17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Access-JWT TTL in minutes; must stay ≤ 15 (S-07).
    pub access_ttl_minutes: u64,
    /// Refresh-session sliding idle timeout in days (decision 03 default: 30).
    pub refresh_idle_days: u64,
    /// Refresh-session absolute cap in days (decision 03 default: 90).
    pub refresh_absolute_days: u64,
    /// Server pepper for OTP HMACs (secret — S-25). Required in production mode; dev mode
    /// falls back to an ephemeral value with a loud warning.
    pub otp_pepper: Option<String>,
    /// CLI token prefix incl. the trailing underscore (decision 17 default: `pub_`).
    pub token_prefix: String,
    /// Whether a successful first OTP login may create an account.
    pub allow_registration: bool,
    /// Sign-in email-domain allowlist; empty = every domain allowed (S-31).
    pub allowed_email_domains: Vec<String>,
    /// Ed25519 signing/verify keyring (S-07/S-27).
    pub jwt: JwtConfig,
    /// Auth-plane rate limits (S-24 defaults).
    pub rate_limit: AuthRateLimitConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_ttl_minutes: 15,
            refresh_idle_days: 30,
            refresh_absolute_days: 90,
            otp_pepper: None,
            token_prefix: "pub_".to_owned(),
            allow_registration: true,
            allowed_email_domains: Vec::new(),
            jwt: JwtConfig::default(),
            rate_limit: AuthRateLimitConfig::default(),
        }
    }
}

/// Ed25519 access-token keyring (S-07): one signing key, N verify keys, rotated by `kid`
/// overlap (S-27). Seeds are base64-encoded 32-byte values (secrets — S-25).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    /// `kid` of the signing key. Required whenever `signing_key` is set.
    pub kid: Option<String>,
    /// Base64-encoded 32-byte Ed25519 seed used for signing (secret). Required in production
    /// mode; dev mode falls back to an ephemeral keyring with a loud warning.
    pub signing_key: Option<String>,
    /// Previous-generation verify keys kept during rotation overlap.
    pub verify_keys: Vec<JwtVerifyKey>,
}

/// One retired-but-still-verifying key (S-27 rotation overlap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtVerifyKey {
    /// Key id embedded in tokens signed by this key.
    pub kid: String,
    /// Base64-encoded 32-byte Ed25519 seed (secret).
    pub key: String,
}

/// Auth-plane rate limits (S-24). Only the OTP-request knobs exist in this slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthRateLimitConfig {
    /// OTP requests per email per hour (S-24: 5).
    pub otp_per_email_hour: u32,
    /// OTP requests per IP per hour (S-24: 20).
    pub otp_per_ip_hour: u32,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self { otp_per_email_hour: 5, otp_per_ip_hour: 20 }
    }
}

/// SMTP transport security mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurityMode {
    /// Implicit TLS from the first byte (usually port 465).
    Tls,
    /// Plaintext upgraded via STARTTLS (usually port 587) — the default.
    #[default]
    Starttls,
    /// No transport security — local relays and tests only.
    None,
}

impl SmtpSecurityMode {
    /// Canonical lowercase name as used in config files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Starttls => "starttls",
            Self::None => "none",
        }
    }
}

/// Outbound SMTP settings. `host` unset selects the in-memory mailer (dev/test).
///
/// The password is boot-config/env only for now; it moves into runtime settings
/// envelope-encrypted with the env KEK later (S-26).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// SMTP server hostname; unset = no SMTP, use the in-memory mailer.
    pub host: Option<String>,
    /// SMTP server port.
    pub port: u16,
    /// Optional login user.
    pub username: Option<String>,
    /// Password for `username` (secret — always masked in the startup summary).
    pub password: Option<String>,
    /// `From:` mailbox, e.g. `Pub <noreply@pub.example>`.
    pub from: String,
    /// Transport security: `tls` | `starttls` | `none`.
    pub security: SmtpSecurityMode,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: None,
            port: 587,
            username: None,
            password: None,
            from: "Pub <noreply@localhost>".to_owned(),
            security: SmtpSecurityMode::Starttls,
        }
    }
}

/// HTTP server settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Socket address the server binds to.
    pub listen: String,
    /// Public base URL clients use to reach this instance (used in `PUB_HOSTED_URL` snippets).
    pub public_url: String,
    /// Deployment mode: `dev` (default) allows ephemeral auth-secret fallbacks; `production`
    /// makes missing secrets a startup error (S-25).
    pub mode: RunMode,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { listen: "0.0.0.0:8080".to_owned(), public_url: "http://localhost:8080".to_owned(), mode: RunMode::Dev }
    }
}

/// Database backend kind (decision 02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    /// Embedded SQLite — the zero-infrastructure default.
    Sqlite,
    /// PostgreSQL.
    Postgres,
}

impl DatabaseKind {
    /// Canonical lowercase name as used in config files and `/healthz`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Database backend selection and connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Which database backend to use: `sqlite` | `postgres`.
    pub kind: DatabaseKind,
    /// Connection URL — required for `postgres` (e.g. `postgres://user:pass@host/db`).
    pub url: Option<String>,
    /// Database file path for `sqlite` (`:memory:` for an in-memory database).
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { kind: DatabaseKind::Sqlite, url: None, path: "data/pub.sqlite3".to_owned() }
    }
}

/// Blob storage backend kind (decision 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobKind {
    /// Local filesystem under `blob.path`.
    Fs,
    /// S3-compatible object storage (AWS S3, MinIO, …).
    S3,
    /// In-memory store — tests and throwaway instances only.
    Memory,
}

impl BlobKind {
    /// Canonical lowercase name as used in config files and `/healthz`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::S3 => "s3",
            Self::Memory => "memory",
        }
    }
}

/// Blob storage backend selection and settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlobConfig {
    /// Which blob backend to use: `fs` | `s3` | `memory`.
    pub kind: BlobKind,
    /// Root directory for the `fs` backend.
    pub path: String,
    /// Bucket name — required for `s3`.
    pub bucket: Option<String>,
    /// Custom endpoint URL for S3-compatible stores (MinIO); AWS default when unset.
    pub endpoint: Option<String>,
    /// S3 region; defaults to `us-east-1` when unset.
    pub region: Option<String>,
    /// S3 access key id; falls back to the ambient AWS credential chain when unset.
    pub access_key: Option<String>,
    /// S3 secret access key (secret — always masked in the startup summary).
    pub secret_key: Option<String>,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            kind: BlobKind::Fs,
            path: "data/blobs".to_owned(),
            bucket: None,
            endpoint: None,
            region: None,
            access_key: None,
            secret_key: None,
        }
    }
}

/// Key-value / broker backend kind (decision 03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KvKind {
    /// In-process store + broker — valid for a single replica only.
    Memory,
    /// Redis-compatible store + pub/sub broker — mandatory for `replicas > 1`.
    Redis,
}

impl KvKind {
    /// Canonical lowercase name as used in config files and `/healthz`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Redis => "redis",
        }
    }
}

/// Key-value store / broker backend selection and settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KvConfig {
    /// Which KV backend to use: `memory` | `redis`.
    pub kind: KvKind,
    /// Connection URL — required for `redis` (e.g. `redis://host:6379`).
    pub url: Option<String>,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self { kind: KvKind::Memory, url: None }
    }
}

/// Observability exports — each is opt-in and off by default (decision 23).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable the Prometheus metrics recorder/exporter.
    pub prometheus: bool,
    /// Enable OTLP trace export.
    pub otlp: bool,
}

/// Multi-instance topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterConfig {
    /// Number of app replicas sharing the same backends. `> 1` requires the Redis KV backend.
    pub replicas: u32,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self { replicas: 1 }
    }
}

/// Loads the effective configuration from all layers and validates it.
pub fn load(cli: &CliArgs) -> Result<Settings, ConfigError> {
    load_from(cli, None)
}

/// [`load`] with an explicit environment map instead of the process environment.
///
/// Exists so tests (and embedders) can exercise the exact same layering without mutating
/// process-global env vars.
pub fn load_from(cli: &CliArgs, env_override: Option<config::Map<String, String>>) -> Result<Settings, ConfigError> {
    // Layer 1: built-in defaults, derived from the `Default` impls so they can never drift.
    let defaults = config::Config::try_from(&Settings::default())?;
    let mut builder = config::Config::builder().add_source(defaults);

    // Layer 2: optional TOML file. A missing file that was explicitly requested is an error.
    if let Some(path) = &cli.config {
        builder = builder.add_source(config::File::from(path.as_path()));
    }

    // Layer 3: environment — `PUB_` prefix, `__` separates nesting: PUB_DATABASE__URL.
    let mut env_source =
        config::Environment::with_prefix("PUB").prefix_separator("_").separator("__").try_parsing(true);
    if let Some(map) = env_override {
        env_source = env_source.source(Some(map));
    }
    builder = builder.add_source(env_source);

    let mut settings: Settings = builder.build()?.try_deserialize()?;

    // Layer 4: CLI flags override everything.
    if let Some(listen) = &cli.listen {
        settings.server.listen = listen.clone();
    }
    if let Some(public_url) = &cli.public_url {
        settings.server.public_url = public_url.clone();
    }
    if let Some(replicas) = cli.replicas {
        settings.cluster.replicas = replicas;
    }

    settings.validate()?;
    Ok(settings)
}

impl Settings {
    /// Multi-line effective-config summary for startup logs, with secrets masked.
    pub fn summary(&self) -> String {
        let mut out = String::from("effective configuration:\n");
        let _ = writeln!(out, "  server.listen        = {}", self.server.listen);
        let _ = writeln!(out, "  server.public_url    = {}", self.server.public_url);
        let _ = writeln!(out, "  server.mode          = {}", self.server.mode.as_str());
        let _ = writeln!(out, "  database.kind        = {}", self.database.kind.as_str());
        match self.database.kind {
            DatabaseKind::Sqlite => {
                let _ = writeln!(out, "  database.path        = {}", self.database.path);
            }
            DatabaseKind::Postgres => {
                let url = self.database.url.as_deref().map(mask_url).unwrap_or_else(|| "<unset>".to_owned());
                let _ = writeln!(out, "  database.url         = {url}");
            }
        }
        let _ = writeln!(out, "  blob.kind            = {}", self.blob.kind.as_str());
        match self.blob.kind {
            BlobKind::Fs => {
                let _ = writeln!(out, "  blob.path            = {}", self.blob.path);
            }
            BlobKind::S3 => {
                let _ = writeln!(out, "  blob.bucket          = {}", opt(&self.blob.bucket));
                let _ = writeln!(out, "  blob.endpoint        = {}", opt(&self.blob.endpoint));
                let _ = writeln!(out, "  blob.region          = {}", opt(&self.blob.region));
                let _ = writeln!(out, "  blob.access_key      = {}", mask_opt(&self.blob.access_key));
                let _ = writeln!(out, "  blob.secret_key      = {}", mask_opt(&self.blob.secret_key));
            }
            BlobKind::Memory => {}
        }
        let _ = writeln!(out, "  kv.kind              = {}", self.kv.kind.as_str());
        if self.kv.kind == KvKind::Redis {
            let url = self.kv.url.as_deref().map(mask_url).unwrap_or_else(|| "<unset>".to_owned());
            let _ = writeln!(out, "  kv.url               = {url}");
        }
        let _ = writeln!(out, "  telemetry.prometheus = {}", self.telemetry.prometheus);
        let _ = writeln!(out, "  telemetry.otlp       = {}", self.telemetry.otlp);
        let _ = writeln!(out, "  cluster.replicas     = {}", self.cluster.replicas);

        // Auth: secrets masked (S-25); kids are public metadata and are listed for rotation
        // sanity checks.
        let _ = writeln!(out, "  auth.access_ttl      = {} min", self.auth.access_ttl_minutes);
        let _ = writeln!(
            out,
            "  auth.refresh         = idle {} d / absolute {} d",
            self.auth.refresh_idle_days, self.auth.refresh_absolute_days
        );
        let _ = writeln!(out, "  auth.otp_pepper      = {}", mask_opt(&self.auth.otp_pepper));
        let _ = writeln!(out, "  auth.token_prefix    = {}", self.auth.token_prefix);
        let _ = writeln!(out, "  auth.registration    = {}", self.auth.allow_registration);
        let domains = if self.auth.allowed_email_domains.is_empty() {
            "<all>".to_owned()
        } else {
            self.auth.allowed_email_domains.join(", ")
        };
        let _ = writeln!(out, "  auth.email_domains   = {domains}");
        let _ = writeln!(out, "  auth.jwt.kid         = {}", opt(&self.auth.jwt.kid));
        let _ = writeln!(out, "  auth.jwt.signing_key = {}", mask_opt(&self.auth.jwt.signing_key));
        let verify_kids: Vec<&str> = self.auth.jwt.verify_keys.iter().map(|k| k.kid.as_str()).collect();
        let _ = writeln!(
            out,
            "  auth.jwt.verify_kids = {}",
            if verify_kids.is_empty() { "<none>".to_owned() } else { verify_kids.join(", ") }
        );
        let _ = writeln!(
            out,
            "  auth.rate_limit      = otp {}/h/email, {}/h/ip",
            self.auth.rate_limit.otp_per_email_hour, self.auth.rate_limit.otp_per_ip_hour
        );

        match &self.smtp.host {
            Some(host) => {
                let _ = writeln!(out, "  smtp.host            = {host}");
                let _ = writeln!(out, "  smtp.port            = {}", self.smtp.port);
                let _ = writeln!(out, "  smtp.security        = {}", self.smtp.security.as_str());
                let _ = writeln!(out, "  smtp.username        = {}", opt(&self.smtp.username));
                let _ = writeln!(out, "  smtp.password        = {}", mask_opt(&self.smtp.password));
                let _ = writeln!(out, "  smtp.from            = {}", self.smtp.from);
            }
            None => {
                let _ = writeln!(out, "  smtp                 = <unset — in-memory mailer>");
            }
        }
        out
    }
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<unset>".to_owned())
}

fn mask_opt(value: &Option<String>) -> String {
    match value {
        Some(_) => "***".to_owned(),
        None => "<unset>".to_owned(),
    }
}

/// Masks the password component of a connection URL; never echoes unparsable URLs verbatim.
fn mask_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                // Setting the password can only fail for URL schemes that cannot carry one —
                // in that case there was no password to leak in the first place.
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => "<unparsable url — hidden>".to_owned(),
    }
}

#[cfg(test)]
mod tests;
