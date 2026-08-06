//! Redis-backed [`Kv`] implementation (decision 03) — the mandatory backend for
//! `cluster.replicas > 1`.
//!
//! Skeleton status: constructor + full method set implemented, exercised by the CI backend
//! matrix (testcontainers) rather than local unit tests.

use std::time::Duration;

use async_trait::async_trait;
use deadpool_redis::redis;
use futures::StreamExt;
use pub_config::{KvConfig, KvKind};
use pub_core::traits::{Kv, KvMessage, MessageStream};
use pub_core::{Error, Result};

/// Redis store + pub/sub broker.
pub struct RedisKv {
    pool: deadpool_redis::Pool,
    /// Dedicated client for pub/sub: subscriptions need their own connection outside the pool.
    client: redis::Client,
}

impl std::fmt::Debug for RedisKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pool type has no Debug impl and the URL may carry credentials — keep it opaque.
        f.debug_struct("RedisKv").finish_non_exhaustive()
    }
}

impl RedisKv {
    /// Builds the connection pool and pub/sub client from configuration. No I/O happens
    /// here — connections are established on first use.
    pub fn from_config(cfg: &KvConfig) -> Result<Self> {
        if cfg.kind != KvKind::Redis {
            return Err(Error::Config {
                message: format!("RedisKv::from_config called with kv.kind = {}", cfg.kind.as_str()),
            });
        }
        let url = cfg
            .url
            .as_deref()
            .ok_or_else(|| Error::Config { message: "kv.kind = redis requires kv.url".to_owned() })?;

        let pool = deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|err| Error::Kv { message: format!("failed to create redis pool: {err}") })?;
        let client =
            redis::Client::open(url).map_err(|err| Error::Kv { message: format!("invalid redis url: {err}") })?;

        Ok(Self { pool, client })
    }

    async fn conn(&self) -> Result<deadpool_redis::Connection> {
        self.pool.get().await.map_err(|err| Error::Kv { message: format!("failed to get redis connection: {err}") })
    }
}

#[async_trait]
impl Kv for RedisKv {
    async fn ping(&self) -> Result<()> {
        let mut conn = self.conn().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await.map_err(kv_err)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn().await?;
        let value: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await.map_err(kv_err)?;
        Ok(value)
    }

    async fn set_ttl(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        let mut conn = self.conn().await?;
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
        let _: () =
            redis::cmd("SET").arg(key).arg(value).arg("PX").arg(ttl_ms).query_async(&mut conn).await.map_err(kv_err)?;
        Ok(())
    }

    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64> {
        let mut conn = self.conn().await?;
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
        // INCR is atomic server-side; the pipeline re-arms the TTL in the same round trip so a
        // crash between the two can never leave an immortal counter.
        let (value,): (u64,) = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(key)
            .cmd("PEXPIRE")
            .arg(key)
            .arg(ttl_ms)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(kv_err)?;
        Ok(value)
    }

    async fn del(&self, key: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let _: () = redis::cmd("DEL").arg(key).query_async(&mut conn).await.map_err(kv_err)?;
        Ok(())
    }

    async fn publish(&self, topic: &str, payload: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let _: () = redis::cmd("PUBLISH").arg(topic).arg(payload).query_async(&mut conn).await.map_err(kv_err)?;
        Ok(())
    }

    async fn subscribe(&self, topic: &str) -> Result<MessageStream> {
        let mut pubsub = self.client.get_async_pubsub().await.map_err(kv_err)?;
        pubsub.subscribe(topic).await.map_err(kv_err)?;
        let stream = pubsub.into_on_message().map(|msg| {
            let payload: String = msg.get_payload().unwrap_or_default();
            KvMessage { topic: msg.get_channel_name().to_owned(), payload }
        });
        Ok(stream.boxed())
    }
}

fn kv_err(err: redis::RedisError) -> Error {
    Error::Kv { message: err.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_requires_url() {
        let cfg = KvConfig { kind: KvKind::Redis, url: None };
        let err = RedisKv::from_config(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn from_config_rejects_wrong_kind() {
        let cfg = KvConfig { kind: KvKind::Memory, url: None };
        let err = RedisKv::from_config(&cfg).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn from_config_builds_without_io() {
        let cfg = KvConfig { kind: KvKind::Redis, url: Some("redis://127.0.0.1:1".to_owned()) };
        // Port 1 is never reachable — lazy construction must still succeed.
        RedisKv::from_config(&cfg).unwrap();
    }
}
