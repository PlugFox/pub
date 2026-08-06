//! In-process [`Kv`] implementation: moka cache with per-entry TTL + broadcast broker.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use pub_core::Result;
use pub_core::traits::{Kv, KvMessage, MessageStream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

/// Value stored in the cache together with its requested TTL.
type Entry = (String, Duration);

/// Per-entry TTL policy: every entry expires `entry.1` after creation/update.
struct PerEntryTtl;

impl moka::Expiry<String, Entry> for PerEntryTtl {
    fn expire_after_create(&self, _key: &String, value: &Entry, _created_at: Instant) -> Option<Duration> {
        Some(value.1)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Entry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.1)
    }
}

/// In-process KV store and broker. Cheap to clone via internal sharing is not needed —
/// consumers hold it behind `Arc<dyn Kv>`.
pub struct MemoryKv {
    cache: moka::future::Cache<String, Entry>,
    topics: Mutex<HashMap<String, broadcast::Sender<KvMessage>>>,
}

/// Capacity of each topic's broadcast channel; laggards lose oldest messages (hint channel).
const TOPIC_CAPACITY: usize = 256;

impl MemoryKv {
    /// Creates an empty store.
    pub fn new() -> Self {
        let cache = moka::future::Cache::builder().max_capacity(1_000_000).expire_after(PerEntryTtl).build();
        Self { cache, topics: Mutex::new(HashMap::new()) }
    }

    fn sender(&self, topic: &str) -> broadcast::Sender<KvMessage> {
        let mut topics = self.topics.lock().expect("topics mutex poisoned");
        topics.entry(topic.to_owned()).or_insert_with(|| broadcast::channel(TOPIC_CAPACITY).0).clone()
    }
}

impl Default for MemoryKv {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Kv for MemoryKv {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.cache.get(key).await.map(|(value, _ttl)| value))
    }

    async fn set_ttl(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        self.cache.insert(key.to_owned(), (value.to_owned(), ttl)).await;
        Ok(())
    }

    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64> {
        // moka's entry API holds a per-key lock across the closure, so two concurrent tasks
        // on the same key never observe the same "current" value (the S-03 budget contract).
        let entry = self
            .cache
            .entry(key.to_owned())
            .and_upsert_with(|current| {
                let next =
                    current.and_then(|entry| entry.into_value().0.parse::<u64>().ok()).unwrap_or(0).saturating_add(1);
                std::future::ready((next.to_string(), ttl))
            })
            .await;
        entry
            .into_value()
            .0
            .parse::<u64>()
            .map_err(|err| pub_core::Error::Kv { message: format!("counter at {key} is not an integer: {err}") })
    }

    async fn del(&self, key: &str) -> Result<()> {
        self.cache.invalidate(key).await;
        Ok(())
    }

    async fn publish(&self, topic: &str, payload: &str) -> Result<()> {
        // send() errors only when there are no subscribers — fire-and-forget by contract.
        let _ = self.sender(topic).send(KvMessage { topic: topic.to_owned(), payload: payload.to_owned() });
        Ok(())
    }

    async fn subscribe(&self, topic: &str) -> Result<MessageStream> {
        let receiver = self.sender(topic).subscribe();
        // Lagged receivers yield errors; the broker is a hint channel, so drop them silently.
        let stream = BroadcastStream::new(receiver).filter_map(|msg| futures::future::ready(msg.ok()));
        Ok(stream.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(80);
    const LONG: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn get_returns_what_was_set() {
        let kv = MemoryKv::new();
        kv.set_ttl("k", "v", LONG).await.unwrap();
        assert_eq!(kv.get("k").await.unwrap().as_deref(), Some("v"));
    }

    #[tokio::test]
    async fn absent_key_is_none() {
        let kv = MemoryKv::new();
        assert_eq!(kv.get("missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn entries_expire_after_ttl() {
        let kv = MemoryKv::new();
        kv.set_ttl("session:revoked", "1", SHORT).await.unwrap();
        assert!(kv.get("session:revoked").await.unwrap().is_some());
        tokio::time::sleep(SHORT * 2).await;
        assert_eq!(kv.get("session:revoked").await.unwrap(), None, "entry must expire after its TTL");
    }

    #[tokio::test]
    async fn overwrite_refreshes_value_and_ttl() {
        let kv = MemoryKv::new();
        kv.set_ttl("k", "old", SHORT).await.unwrap();
        kv.set_ttl("k", "new", LONG).await.unwrap();
        tokio::time::sleep(SHORT * 2).await;
        assert_eq!(kv.get("k").await.unwrap().as_deref(), Some("new"), "update must reset the TTL");
    }

    #[tokio::test]
    async fn incr_counts_from_one_and_expires() {
        let kv = MemoryKv::new();
        assert_eq!(kv.incr("c", LONG).await.unwrap(), 1);
        assert_eq!(kv.incr("c", LONG).await.unwrap(), 2);
        assert_eq!(kv.get("c").await.unwrap().as_deref(), Some("2"));
        kv.set_ttl("short", "0", SHORT).await.unwrap();
        assert_eq!(kv.incr("short", SHORT).await.unwrap(), 1);
        tokio::time::sleep(SHORT * 2).await;
        assert_eq!(kv.incr("short", SHORT).await.unwrap(), 1, "an expired counter restarts");
    }

    #[tokio::test]
    async fn incr_is_atomic_under_concurrency() {
        // The S-03 attempt budget is decided by this return value: 64 concurrent increments
        // must yield the 64 distinct values 1..=64, never a shared one.
        let kv = std::sync::Arc::new(MemoryKv::new());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let kv = std::sync::Arc::clone(&kv);
            tasks.spawn(async move { kv.incr("burst", LONG).await.unwrap() });
        }
        let mut seen: Vec<u64> = tasks.join_all().await;
        seen.sort_unstable();
        assert_eq!(seen, (1..=64).collect::<Vec<u64>>());
    }

    #[tokio::test]
    async fn incr_over_a_corrupt_value_restarts_at_one() {
        let kv = MemoryKv::new();
        kv.set_ttl("junk", "not-a-number", LONG).await.unwrap();
        assert_eq!(kv.incr("junk", LONG).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn del_removes_the_key() {
        let kv = MemoryKv::new();
        kv.set_ttl("k", "v", LONG).await.unwrap();
        kv.del("k").await.unwrap();
        assert_eq!(kv.get("k").await.unwrap(), None);
        // Deleting an absent key is not an error.
        kv.del("k").await.unwrap();
    }

    #[tokio::test]
    async fn pub_sub_round_trip() {
        let kv = MemoryKv::new();
        let mut sub = kv.subscribe("settings").await.unwrap();
        kv.publish("settings", "changed:v2").await.unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(1), sub.next()).await.unwrap().unwrap();
        assert_eq!(msg, KvMessage { topic: "settings".to_owned(), payload: "changed:v2".to_owned() });
    }

    #[tokio::test]
    async fn all_subscribers_receive_each_message() {
        let kv = MemoryKv::new();
        let mut first = kv.subscribe("events").await.unwrap();
        let mut second = kv.subscribe("events").await.unwrap();
        kv.publish("events", "hello").await.unwrap();
        for sub in [&mut first, &mut second] {
            let msg = tokio::time::timeout(Duration::from_secs(1), sub.next()).await.unwrap().unwrap();
            assert_eq!(msg.payload, "hello");
        }
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_fire_and_forget() {
        let kv = MemoryKv::new();
        kv.publish("nobody-listens", "hello").await.unwrap();
    }

    #[tokio::test]
    async fn topics_are_isolated() {
        let kv = MemoryKv::new();
        let mut other = kv.subscribe("topic-b").await.unwrap();
        kv.publish("topic-a", "for-a").await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(100), other.next()).await;
        assert!(result.is_err(), "subscriber of topic-b must not see topic-a messages");
    }
}
