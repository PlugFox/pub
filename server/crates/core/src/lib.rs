//! Domain types, errors, and backend trait contracts for the Pub registry.
//!
//! This crate is the dependency root of the workspace: every other crate sees the domain
//! through the types and traits defined here. It deliberately depends on **no**
//! infrastructure crates (no sqlx, object_store, redis, axum) — implementations live in
//! their own crates (`db-sqlite`, `db-postgres`, `blob`, `kv`, …) and are selected at
//! runtime from configuration (decision 09).

pub mod error;
pub mod format;
pub mod id;
pub mod role;
pub mod traits;

pub use error::Error;
pub use format::Format;
pub use id::{OrgId, PackageId, SessionId, TokenId, UserId, VersionId};
pub use role::RoleLevel;

/// Crate-wide result alias defaulting to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
