//! Fail-fast semantic validation of the merged configuration (decision 09).

use crate::{BlobKind, ConfigError, DatabaseKind, KvKind, Settings};

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

        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}
