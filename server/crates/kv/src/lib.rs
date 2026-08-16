//! Key-value store + pub/sub broker implementations (decision 03).
//!
//! - [`MemoryKv`]: in-process moka cache with per-entry TTL plus a `tokio::sync::broadcast`
//!   broker. Correct for a single replica only — the config validator refuses
//!   `cluster.replicas > 1` with this backend.
//! - [`RedisKv`]: deadpool-redis store + Redis pub/sub broker — the backend a multi-replica
//!   deployment runs on. Both implementations are held to one contract suite in
//!   `tests/contract.rs`; its Redis leg is gated by `PUB_TEST_REDIS_URL` and fails closed
//!   when neither that nor `PUB_TEST_NO_REDIS` is set
//!   ([decision 35](../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)).

mod memory;
mod redis_kv;

pub use memory::MemoryKv;
pub use redis_kv::RedisKv;
