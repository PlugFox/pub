//! Domain types, errors, and backend trait contracts for the Pub registry.
//!
//! This crate is the dependency root of the workspace: every other crate sees the domain
//! through the types and traits defined here. It deliberately depends on **no**
//! infrastructure crates (no sqlx, object_store, redis, axum) — implementations live in
//! their own crates (`db-sqlite`, `db-postgres`, `blob`, `kv`, …) and are selected at
//! runtime from configuration (decision 09).

pub mod audit;
pub mod authorize;
pub mod credential;
pub mod error;
pub mod event;
pub mod format;
pub mod id;
pub mod jobs;
pub mod notification;
pub mod org;
pub mod package;
pub mod page;
pub mod role;
pub mod search;
pub mod semver;
pub mod session;
pub mod settings;
pub mod stats;
pub mod token;
pub mod traits;
pub mod user;
pub mod version;

pub use error::Error;
pub use event::DomainEvent;
pub use format::Format;
pub use id::{CredentialId, InvitationId, NotificationId, OrgId, PackageId, SessionId, TokenId, UserId, VersionId};
pub use page::Page;
pub use role::RoleLevel;
pub use semver::SemVer;

/// Crate-wide result alias defaulting to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
