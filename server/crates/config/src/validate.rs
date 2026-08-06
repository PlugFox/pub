//! Fail-fast semantic validation of the merged configuration (decision 09).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::{BlobKind, ConfigError, DatabaseKind, KvKind, RunMode, Settings};

impl Settings {
    /// Validates cross-field invariants. Called by [`crate::load`] after merging all layers.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.listen.parse::<std::net::SocketAddr>().map_err(|err| {
            invalid(format!("server.listen '{}' is not a valid socket address: {err}", self.server.listen))
        })?;

        if self.database.kind == DatabaseKind::Postgres && self.database.url.is_none() {
            return Err(invalid("database.kind = postgres requires database.url"));
        }
        if self.database.kind == DatabaseKind::Sqlite && self.database.path.is_empty() {
            return Err(invalid("database.kind = sqlite requires a non-empty database.path"));
        }

        if self.blob.kind == BlobKind::S3 && self.blob.bucket.is_none() {
            return Err(invalid("blob.kind = s3 requires blob.bucket"));
        }
        if self.blob.kind == BlobKind::Fs && self.blob.path.is_empty() {
            return Err(invalid("blob.kind = fs requires a non-empty blob.path"));
        }

        if self.kv.kind == KvKind::Redis && self.kv.url.is_none() {
            return Err(invalid("kv.kind = redis requires kv.url"));
        }

        if self.cluster.replicas == 0 {
            return Err(invalid("cluster.replicas must be at least 1"));
        }
        // Decision 03: the in-memory KV cannot share revocations, locks, or invalidations
        // across instances — a Redis-compatible store + broker gates any scale-out.
        if self.cluster.replicas > 1 && self.kv.kind == KvKind::Memory {
            return Err(invalid(format!(
                "cluster.replicas = {} requires kv.kind = redis (decision 03): \
                 the in-memory KV backend is only correct for a single instance",
                self.cluster.replicas
            )));
        }

        self.validate_auth()?;
        self.validate_smtp()?;
        Ok(())
    }

    /// Auth invariants (S-07/S-25 + decisions 13/17).
    fn validate_auth(&self) -> Result<(), ConfigError> {
        let auth = &self.auth;

        // S-07: the access TTL is normatively capped at 15 minutes.
        if auth.access_ttl_minutes == 0 || auth.access_ttl_minutes > 15 {
            return Err(invalid(format!(
                "auth.access_ttl_minutes = {} must be between 1 and 15 (S-07)",
                auth.access_ttl_minutes
            )));
        }
        if auth.refresh_idle_days == 0 || auth.refresh_absolute_days == 0 {
            return Err(invalid("auth.refresh_idle_days and auth.refresh_absolute_days must be at least 1"));
        }
        if auth.refresh_absolute_days < auth.refresh_idle_days {
            return Err(invalid(format!(
                "auth.refresh_absolute_days ({}) must not be below auth.refresh_idle_days ({})",
                auth.refresh_absolute_days, auth.refresh_idle_days
            )));
        }

        // Decision 13/17 format: `<prefix>_<base62×30><crc32×6>` — the prefix carries its
        // own trailing underscore and stays scanner-friendly.
        let prefix = &auth.token_prefix;
        let body_ok = prefix
            .strip_suffix('_')
            .is_some_and(|body| !body.is_empty() && body.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        if !body_ok {
            return Err(invalid(format!(
                "auth.token_prefix '{prefix}' must be lowercase alphanumerics ending in '_' (e.g. pub_)"
            )));
        }

        // S-25: production boots refuse to run without real secrets; dev mode falls back to
        // loud ephemeral values at startup instead.
        if self.server.mode == RunMode::Production {
            if auth.otp_pepper.as_deref().is_none_or(str::is_empty) {
                return Err(invalid("server.mode = production requires auth.otp_pepper (S-25)"));
            }
            if auth.jwt.signing_key.as_deref().is_none_or(str::is_empty) {
                return Err(invalid("server.mode = production requires auth.jwt.signing_key (S-25)"));
            }
        }

        // Whenever keys are present they must be well-formed, regardless of mode.
        if auth.jwt.signing_key.is_some() && auth.jwt.kid.as_deref().is_none_or(str::is_empty) {
            return Err(invalid("auth.jwt.signing_key requires auth.jwt.kid"));
        }
        if let Some(key) = &auth.jwt.signing_key {
            validate_seed("auth.jwt.signing_key", key)?;
        }
        let mut kids: Vec<&str> = auth.jwt.kid.as_deref().into_iter().collect();
        for verify in &auth.jwt.verify_keys {
            if verify.kid.is_empty() {
                return Err(invalid("auth.jwt.verify_keys entries need a non-empty kid"));
            }
            validate_seed(&format!("auth.jwt.verify_keys[{}]", verify.kid), &verify.key)?;
            kids.push(&verify.kid);
        }
        kids.sort_unstable();
        if kids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("auth.jwt kids must be unique across signing and verify keys"));
        }

        if auth.rate_limit.otp_per_email_hour == 0 || auth.rate_limit.otp_per_ip_hour == 0 {
            return Err(invalid("auth.rate_limit values must be at least 1 (S-24)"));
        }
        Ok(())
    }

    /// SMTP invariants: a configured host needs a sane mailbox and port.
    fn validate_smtp(&self) -> Result<(), ConfigError> {
        if self.smtp.host.is_some() {
            if self.smtp.port == 0 {
                return Err(invalid("smtp.port must be non-zero when smtp.host is set"));
            }
            if self.smtp.from.is_empty() {
                return Err(invalid("smtp.from must be set when smtp.host is set"));
            }
            if self.smtp.username.is_some() != self.smtp.password.is_some() {
                return Err(invalid("smtp.username and smtp.password must be set together"));
            }
        }
        Ok(())
    }
}

/// Checks that a configured JWT key is base64 of exactly 32 bytes (an Ed25519 seed).
fn validate_seed(field: &str, value: &str) -> Result<(), ConfigError> {
    match B64.decode(value) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(bytes) => Err(invalid(format!("{field} must decode to 32 bytes, got {}", bytes.len()))),
        Err(_) => Err(invalid(format!("{field} is not valid base64"))),
    }
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}
