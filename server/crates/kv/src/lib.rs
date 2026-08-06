//! Key-value store + pub/sub broker implementations (decision 03).
//!
//! - [`MemoryKv`]: in-process moka cache with per-entry TTL plus a `tokio::sync::broadcast`
//!   broker. Correct for a single replica only — the config validator refuses
//!   `cluster.replicas > 1` with this backend.
//! - [`RedisKv`]: deadpool-redis store + Redis pub/sub broker. Skeleton implementation;
//!   exercised by the CI backend matrix, not by local tests.

mod memory;
mod redis_kv;

pub use memory::MemoryKv;
pub use redis_kv::RedisKv;
