//! Backend trait contracts (decisions 02, 09, 10).
//!
//! Every infrastructure concern is expressed as a trait here and implemented in a dedicated
//! crate (`db-sqlite`, `db-postgres`, `blob`, `kv`, `mail`, …). `AppState` holds `Arc<dyn …>`
//! handles constructed once at startup from configuration — backend selection is runtime
//! polymorphism, never cargo features.
//!
//! Skeleton phase: each trait starts with a health probe plus one representative method so the
//! shapes are locked in; the full method sets land with their roadmap steps.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Format, OrgId, PackageId, Result, RoleLevel, SessionId, TokenId, UserId};

/// Stream of archive bytes, e.g. a package tarball body.
pub type ByteStream = BoxStream<'static, Result<Bytes>>;

/// Stream of broker messages delivered to a [`Kv`] subscriber.
pub type MessageStream = BoxStream<'static, KvMessage>;

/// How a blob download is served (decision 10) — decided per request.
pub enum DownloadPlan {
    /// Redirect (HTTP 307) to a presigned URL; used by backends that support signing (S3).
    Redirect(Url),
    /// Stream the bytes through the app tier; used by fs and in-memory backends.
    Stream(ByteStream),
}

impl std::fmt::Debug for DownloadPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redirect(url) => f.debug_tuple("Redirect").field(url).finish(),
            Self::Stream(_) => f.debug_tuple("Stream").field(&"<byte stream>").finish(),
        }
    }
}

/// Message published on a [`Kv`] broker topic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvMessage {
    /// Topic the message was published on.
    pub topic: String,
    /// Opaque payload; producers and consumers agree on the encoding per topic.
    pub payload: String,
}

/// Minimal audit event shape (append-only log; ULID ids and rich metadata come later).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Dot-namespaced action, e.g. `package.publish`.
    pub action: String,
    /// Acting user, if the action was performed by an authenticated principal.
    pub actor: Option<UserId>,
}

/// Package metadata persistence — packages are unique per `(format, name)` per instance
/// (decision 21).
#[async_trait]
pub trait PackageRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Whether a package with this `(format, name)` exists on the instance (claim lookup).
    async fn exists(&self, format: Format, name: &str) -> Result<bool>;
}

/// User account persistence.
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Whether the user account exists.
    async fn exists(&self, id: UserId) -> Result<bool>;
}

/// Organization and membership persistence (decision 19).
#[async_trait]
pub trait OrgRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// The user's cumulative role level in the org; [`RoleLevel::NONE`] when not a member.
    async fn role_of(&self, org: OrgId, user: UserId) -> Result<RoleLevel>;
}

/// CLI/API token persistence — tokens are stored as SHA-256 hashes, never plaintext
/// (decision 13).
#[async_trait]
pub trait TokenRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Looks a token up by the SHA-256 hash of its plaintext; `None` when unknown or revoked.
    async fn find_by_hash(&self, sha256_hex: &str) -> Result<Option<TokenId>>;
}

/// Web refresh-session persistence (decision 03).
#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Marks a session revoked; the KV revocation fast path is maintained by the caller.
    async fn revoke(&self, id: SessionId) -> Result<()>;
}

/// Append-only audit log (S-22): events are only ever inserted, never updated or deleted.
#[async_trait]
pub trait AuditRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Appends one event to the audit log.
    async fn append(&self, event: AuditEvent) -> Result<()>;
}

/// Runtime-changeable instance settings, key → JSON (decision 09; cache/invalidation on top).
#[async_trait]
pub trait SettingsRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Raw JSON value for a settings key; `None` when unset.
    async fn get(&self, key: &str) -> Result<Option<String>>;

    /// Stores the raw JSON value for a settings key.
    async fn set(&self, key: &str, value_json: &str) -> Result<()>;
}

/// Content-addressed blob storage (decision 10). Keys are derived from the content sha256;
/// stored bytes are immutable and served verbatim forever.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Stores a blob under `key`, overwriting silently (content-addressed keys make
    /// overwrites idempotent).
    async fn put(&self, key: &str, bytes: Bytes) -> Result<()>;

    /// Plans a download for `key`: presigned redirect where supported, streamed bytes
    /// otherwise. [`crate::Error::NotFound`] when the key does not exist.
    async fn download(&self, key: &str) -> Result<DownloadPlan>;
}

/// Key-value store **and** pub/sub broker (decision 03) — one seam for revocation fast paths,
/// rate counters, locks, and cross-instance invalidation. The in-memory implementation is
/// valid for a single replica only; Redis is mandatory for `replicas > 1`.
#[async_trait]
pub trait Kv: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// The current value for `key`; `None` when absent or expired.
    async fn get(&self, key: &str) -> Result<Option<String>>;

    /// Sets `key` to `value` with a time-to-live; the entry expires after `ttl`.
    async fn set_ttl(&self, key: &str, value: &str, ttl: Duration) -> Result<()>;

    /// Removes `key`; removing an absent key is not an error.
    async fn del(&self, key: &str) -> Result<()>;

    /// Publishes a message on a broker topic. Publishing to a topic without subscribers is
    /// not an error (fire-and-forget semantics).
    async fn publish(&self, topic: &str, payload: &str) -> Result<()>;

    /// Subscribes to a broker topic; the stream yields messages published *after* the
    /// subscription was established. The broker is a hint channel — consumers reconcile
    /// through the source of truth, so missed messages are never correctness bugs.
    async fn subscribe(&self, topic: &str) -> Result<MessageStream>;
}

/// Full-text package search (decision 11): PG tsvector+pg_trgm or SQLite FTS5.
#[async_trait]
pub trait PackageSearch: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Searches package names in the given format; returns matching package ids.
    async fn search(&self, format: Format, query: &str) -> Result<Vec<PackageId>>;
}

/// Outbound email delivery (OTP codes, invitations, notifications).
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Cheap connectivity probe used by `/healthz` (e.g. SMTP NOOP or config check).
    async fn ping(&self) -> Result<()>;

    /// Sends a plain-text email. Templated multipart mail arrives with the `mail` crate
    /// build-out.
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()>;
}

/// Leader-election lock guarding single-instance background jobs (PG advisory lock / Redis
/// lock / trivial in-process lock for a single node).
#[async_trait]
pub trait JobLock: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Tries to acquire the named lock for at most `ttl`; returns `true` when this caller
    /// now holds the lock. The TTL bounds how long a crashed holder can block others.
    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<bool>;

    /// Releases the named lock. Releasing a lock that is not held is not an error.
    async fn release(&self, name: &str) -> Result<()>;
}
