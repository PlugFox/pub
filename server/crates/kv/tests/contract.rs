//! The [`Kv`] contract, run against **every** implementation
//! ([decision 35](../../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)).
//!
//! Same shape as the repository contract suite: one set of backend-agnostic functions, one
//! test per property per backend, so a failure names the property rather than the backend.
//! The memory leg runs on every `cargo test`; the Redis leg runs when `PUB_TEST_REDIS_URL`
//! is exported and **panics** when neither it nor `PUB_TEST_NO_REDIS` is set.
//!
//! This file is the first automated execution `RedisKv` has ever had. It was written, wired
//! and documented in the first slice, the config validator has been pointing multi-instance
//! deployments at it since, and until now nothing in this workspace opened a socket to it —
//! while the module's own header claimed it was "exercised by the CI backend matrix".
//!
//! The properties here are not a survey of the API. They are the ones other subsystems are
//! *built on*, each named with what depends on it: the atomic increment the S-03 attempt
//! budget and every S-24 window decide on, the TTL re-arm that forced the rate-limit window
//! into the key, and the after-subscription delivery guarantee the event bus's peer bridge
//! assumes when it fans a domain event to another replica's SSE stream.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use pub_config::{KvConfig, KvKind};
use pub_core::traits::Kv;
use pub_kv::{MemoryKv, RedisKv};
use pub_test_support::{Gate, REDIS};

/// Long enough that nothing under test expires by accident.
const LONG: Duration = Duration::from_secs(60);
/// Short enough to wait out, wide enough that scheduling jitter on a loaded CI runner is not
/// mistaken for an expiry. Redis stores TTLs in milliseconds, so this is exact on both sides.
const SHORT: Duration = Duration::from_millis(400);

/// Keys are namespaced per test run because the Redis leg shares one database with every
/// other test in this binary *and* with whatever ran before it. The memory leg does not need
/// this; using the same helper for both is what keeps the two legs the same code.
fn ns(name: &str) -> String {
    format!("contract:{}:{name}", pub_core::UserId::new())
}

// -------------------------------------------------------------------------- the contract

/// Values round-trip, overwrite in place, and disappear when their TTL is spent.
async fn store(kv: &dyn Kv) {
    let key = ns("store");
    assert_eq!(kv.get(&key).await.unwrap(), None, "an absent key is None, never an empty string");

    kv.set_ttl(&key, "value", LONG).await.unwrap();
    assert_eq!(kv.get(&key).await.unwrap().as_deref(), Some("value"));

    kv.set_ttl(&key, "replaced", LONG).await.unwrap();
    assert_eq!(kv.get(&key).await.unwrap().as_deref(), Some("replaced"), "a second set replaces the value");

    let short = ns("store-short");
    kv.set_ttl(&short, "1", SHORT).await.unwrap();
    assert!(kv.get(&short).await.unwrap().is_some(), "the entry must be readable before its TTL");
    tokio::time::sleep(SHORT * 2).await;
    assert_eq!(kv.get(&short).await.unwrap(), None, "an entry must expire after its TTL");

    // An overwrite re-arms the TTL — the property `set_ttl` exists to have, and what makes a
    // revoked-session entry survive as long as the access token it is blocking (S-09).
    let rearm = ns("store-rearm");
    kv.set_ttl(&rearm, "old", SHORT).await.unwrap();
    kv.set_ttl(&rearm, "new", LONG).await.unwrap();
    tokio::time::sleep(SHORT * 2).await;
    assert_eq!(kv.get(&rearm).await.unwrap().as_deref(), Some("new"), "an update must reset the TTL");
}

/// Counters start at one, return the value the caller decides on, and restart once expired.
async fn counters(kv: &dyn Kv) {
    let key = ns("counter");
    assert_eq!(kv.incr(&key, LONG).await.unwrap(), 1, "the first increment creates the counter at 1");
    assert_eq!(kv.incr(&key, LONG).await.unwrap(), 2);
    assert_eq!(kv.get(&key).await.unwrap().as_deref(), Some("2"), "the counter is readable as its decimal value");

    let short = ns("counter-short");
    assert_eq!(kv.incr(&short, SHORT).await.unwrap(), 1);
    tokio::time::sleep(SHORT * 2).await;
    assert_eq!(kv.incr(&short, SHORT).await.unwrap(), 1, "an expired counter restarts rather than resuming");
}

/// **S-24.d.** Every increment re-arms the TTL, so a counter under sustained traffic never
/// expires — which is why a rate-limit window cannot be carried by the TTL and lives in the
/// key instead. If this ever becomes "arm on create only", the limiter's design is back open.
async fn counters_rearm_their_ttl(kv: &dyn Kv) {
    let key = ns("hot");
    let step = SHORT / 4;
    let mut counts = vec![kv.incr(&key, SHORT).await.unwrap()];
    for _ in 0..5 {
        tokio::time::sleep(step).await;
        counts.push(kv.incr(&key, SHORT).await.unwrap());
    }
    // Six increments spanning 5 × (SHORT/4) — past the TTL each one supplied.
    assert_eq!(counts, vec![1, 2, 3, 4, 5, 6], "every increment must slide the expiry forward");
}

/// **S-03 / S-24.d.** The whole reason `incr` is on the trait rather than composed from
/// `get` + `set_ttl`: 64 concurrent increments must produce the 64 *distinct* values 1..=64.
/// A shared "current" anywhere in the implementation shows up here as a duplicate, and a
/// duplicate is one OTP guess that cost no budget.
async fn counters_are_atomic_under_concurrency(kv: Arc<dyn Kv>) {
    let key = ns("burst");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let (kv, key) = (Arc::clone(&kv), key.clone());
        tasks.spawn(async move { kv.incr(&key, LONG).await.unwrap() });
    }
    let mut seen: Vec<u64> = tasks.join_all().await;
    seen.sort_unstable();
    assert_eq!(seen, (1..=64).collect::<Vec<u64>>(), "every concurrent increment must see its own value");
}

/// Deletion is idempotent — a retried revocation or a sweep over a half-cleaned store must
/// not fail on the second pass.
async fn deletion(kv: &dyn Kv) {
    let key = ns("del");
    kv.set_ttl(&key, "v", LONG).await.unwrap();
    kv.del(&key).await.unwrap();
    assert_eq!(kv.get(&key).await.unwrap(), None);
    kv.del(&key).await.unwrap();
    kv.del(&ns("never-existed")).await.unwrap();
}

/// The broker: fire-and-forget publishing, delivery of everything published *after* a
/// subscription, and one topic never seeing another's traffic.
///
/// The event bus depends on exactly this and on nothing more (`events/src/lib.rs`): a peer
/// instance feeds a received event to its SSE stream, missed messages are never correctness
/// bugs, so what must hold is delivery-after-subscribe and topic isolation.
async fn broker(kv: &dyn Kv) {
    let topic = ns("topic");
    let other = ns("topic-other");

    // Publishing into the void is not an error — every emitter does it on a single-replica
    // instance, where nothing is subscribed at all.
    kv.publish(&topic, "nobody-is-listening").await.unwrap();

    let mut stream = kv.subscribe(&topic).await.unwrap();
    kv.publish(&other, "wrong-topic").await.unwrap();
    kv.publish(&topic, "payload").await.unwrap();

    let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("a message published after subscribing must arrive")
        .expect("the stream must not end while the subscription is alive");
    assert_eq!(message.payload, "payload", "a subscriber must not receive another topic's traffic");
    assert_eq!(message.topic, topic);
}

// -------------------------------------------------------------------------- memory leg

fn memory() -> Arc<dyn Kv> {
    Arc::new(MemoryKv::new())
}

#[tokio::test]
async fn memory_store() {
    store(memory().as_ref()).await;
}

#[tokio::test]
async fn memory_counters() {
    counters(memory().as_ref()).await;
}

#[tokio::test]
async fn memory_counters_rearm_their_ttl() {
    counters_rearm_their_ttl(memory().as_ref()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_counters_are_atomic_under_concurrency() {
    counters_are_atomic_under_concurrency(memory()).await;
}

#[tokio::test]
async fn memory_deletion() {
    deletion(memory().as_ref()).await;
}

#[tokio::test]
async fn memory_broker() {
    broker(memory().as_ref()).await;
}

// -------------------------------------------------------------------------- redis leg

/// A lazily-connected `RedisKv` against the gated URL; `None` when the operator opted out.
fn redis(test: &str) -> Option<Arc<dyn Kv>> {
    let url = match REDIS.gate(test) {
        Gate::Run(url) => url,
        Gate::Skipped => return None,
    };
    let cfg = KvConfig { kind: KvKind::Redis, url: Some(url) };
    Some(Arc::new(RedisKv::from_config(&cfg).expect("build the redis client")))
}

#[tokio::test]
async fn redis_ping_reaches_the_server() {
    // First, so a Redis that is configured but unreachable fails on a one-line assertion
    // rather than inside a contract function's third property.
    let Some(kv) = redis("redis_ping_reaches_the_server") else { return };
    kv.ping().await.expect("PING must reach the server named by PUB_TEST_REDIS_URL");
}

#[tokio::test]
async fn redis_store() {
    let Some(kv) = redis("redis_store") else { return };
    store(kv.as_ref()).await;
}

#[tokio::test]
async fn redis_counters() {
    let Some(kv) = redis("redis_counters") else { return };
    counters(kv.as_ref()).await;
}

#[tokio::test]
async fn redis_counters_rearm_their_ttl() {
    let Some(kv) = redis("redis_counters_rearm_their_ttl") else { return };
    counters_rearm_their_ttl(kv.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_counters_are_atomic_under_concurrency() {
    let Some(kv) = redis("redis_counters_are_atomic_under_concurrency") else { return };
    counters_are_atomic_under_concurrency(kv).await;
}

#[tokio::test]
async fn redis_deletion() {
    let Some(kv) = redis("redis_deletion") else { return };
    deletion(kv.as_ref()).await;
}

#[tokio::test]
async fn redis_broker() {
    let Some(kv) = redis("redis_broker") else { return };
    broker(kv.as_ref()).await;
}
