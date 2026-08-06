//! Backend trait contracts (decisions 02, 09, 10).
//!
//! Every infrastructure concern is expressed as a trait here and implemented in a dedicated
//! crate (`db-sqlite`, `db-postgres`, `blob`, `kv`, `mail`, …). `AppState` holds `Arc<dyn …>`
//! handles constructed once at startup from configuration — backend selection is runtime
//! polymorphism, never cargo features.
//!
//! The identity & access repositories (`UserRepo`, `CredentialRepo`, `OrgRepo`, `SessionRepo`,
//! `TokenRepo`, `AuditRepo`, `SettingsRepo`) carry their full method sets; the remaining
//! traits are still skeleton-phase (health probe + one representative method) and grow with
//! their roadmap steps.
//!
//! Time is always a parameter (`now: DateTime<Utc>`): repositories never read the clock, so
//! expiry, throttling, and validity windows are deterministic under test.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::audit::{AuditEvent, AuditFilter, NewAuditEvent};
use crate::credential::Credential;
use crate::org::{Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership};
use crate::page::Page;
use crate::session::{NewSession, Session, SessionLimits};
use crate::settings::SettingEntry;
use crate::token::{NewToken, Token};
use crate::user::{NewUser, User, UserStatus};
use crate::{CredentialId, Format, InvitationId, OrgId, PackageId, Result, RoleLevel, SessionId, TokenId, UserId};

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

    /// Creates a user account with status [`UserStatus::Active`].
    ///
    /// Emails are unique case-insensitively across all accounts (verified or not);
    /// a duplicate is [`crate::Error::Conflict`].
    async fn create(&self, new: NewUser, now: DateTime<Utc>) -> Result<User>;

    /// The user with this id; `None` when unknown.
    async fn get(&self, id: UserId) -> Result<Option<User>>;

    /// The user holding this email **verified** (S-01: unverified emails never identify an
    /// account); matching is case-insensitive. `None` when no verified match exists.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;

    /// Updates the lifecycle status.
    ///
    /// Transitioning to [`UserStatus::Deleted`] anonymizes the row (S-29): email is cleared
    /// (freeing it for re-registration) and the display name is blanked; the row itself
    /// survives as the attribution tombstone for published versions.
    async fn update_status(&self, id: UserId, status: UserStatus, now: DateTime<Utc>) -> Result<User>;
}

/// Credential persistence — one polymorphic table over every identity proof (decision 12).
///
/// `oidc`, `email`, `totp`, and `recovery` types have methods; `webauthn` rows arrive with
/// their auth flows (v1.1).
#[async_trait]
pub trait CredentialRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Creates or refreshes the OIDC identity `(issuer, subject)` for `user`.
    ///
    /// Refreshing (`updated_at` bump) is the every-sign-in path. The identity key is unique
    /// instance-wide: if it is already linked to a *different* user, this is
    /// [`crate::Error::Conflict`] — re-linking is an explicit account-linking flow (S-02),
    /// never an upsert side effect.
    async fn upsert_oidc(&self, user: UserId, issuer: &str, subject: &str, now: DateTime<Utc>) -> Result<Credential>;

    /// The OIDC credential for `(issuer, subject)`; `None` when unknown. This is the sign-in
    /// lookup (S-01: identity key is `(iss, sub)`, never email).
    async fn find_oidc(&self, issuer: &str, subject: &str) -> Result<Option<Credential>>;

    /// Creates an `email` identity for `user`. One identity per `(user, email)` pair
    /// (case-insensitive); a duplicate is [`crate::Error::Conflict`].
    async fn create_email_identity(&self, user: UserId, email: &str, now: DateTime<Utc>) -> Result<Credential>;

    /// Every credential of the user, oldest first (account security UI).
    async fn list_for_user(&self, user: UserId) -> Result<Vec<Credential>>;

    /// Activates a TOTP enrollment (S-05): stores the KEK-sealed seed with the step the
    /// confirmation code was accepted at (so that exact code can never be replayed at login).
    /// A second active enrollment for the same user is [`crate::Error::Conflict`].
    async fn create_totp(
        &self,
        user: UserId,
        secret_enc: &[u8],
        last_step: i64,
        now: DateTime<Utc>,
    ) -> Result<Credential>;

    /// The user's active TOTP enrollment with its sealed seed and replay floor; `None` when
    /// the user has no TOTP second factor.
    async fn find_totp(&self, user: UserId) -> Result<Option<crate::credential::TotpCredential>>;

    /// **Atomically** advances the replay floor to `step`, returning whether it moved.
    ///
    /// `false` means `step` is not strictly greater than the stored floor — i.e. a replayed
    /// or older code; the caller must treat that as a failed verification (S-05). The
    /// compare-and-set semantics are the contract: two concurrent verifications of the same
    /// step must not both succeed.
    async fn commit_totp_step(&self, id: CredentialId, step: i64, now: DateTime<Utc>) -> Result<bool>;

    /// Stores the freshly generated recovery-code hashes (argon2id PHC strings, S-05),
    /// replacing any codes the user still had.
    async fn replace_recovery_codes(&self, user: UserId, phc_hashes: &[String], now: DateTime<Utc>) -> Result<()>;

    /// The user's unspent recovery-code hashes (verification iterates over them — ≤10 rows).
    async fn list_recovery_codes(&self, user: UserId) -> Result<Vec<crate::credential::RecoveryCodeHash>>;

    /// **Atomically** consumes one recovery code (single-use, S-05): deletes the row and
    /// returns whether this call deleted it. `false` means someone else spent it first —
    /// a failed verification for this caller.
    async fn consume_recovery_code(&self, id: CredentialId) -> Result<bool>;

    /// Removes the user's whole second factor: the TOTP enrollment plus every remaining
    /// recovery code. Returns how many rows were deleted (0 = nothing was enrolled).
    async fn delete_second_factor(&self, user: UserId) -> Result<u64>;
}

/// Organization, membership, and invitation persistence (decision 19).
///
/// The ≥1-Owner invariant is enforced *here*, transactionally: `update_member_role` and
/// `remove_member` fail with [`crate::Error::LastOwner`] when they would strand the org —
/// regardless of what `authorize()` already allowed (see [`crate::authorize`] module docs).
#[async_trait]
pub trait OrgRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Creates an org and, in the same transaction, makes `creator` its Owner — an org can
    /// never exist without one. A duplicate slug is [`crate::Error::Conflict`].
    async fn create(&self, new: NewOrg, creator: UserId, now: DateTime<Utc>) -> Result<Org>;

    /// The org with this id; `None` when unknown.
    async fn get(&self, id: OrgId) -> Result<Option<Org>>;

    /// The org with this slug (case-insensitive); `None` when unknown.
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Org>>;

    /// Every org the user is a member of, with the user's role, oldest org first.
    async fn list_for_user(&self, user: UserId) -> Result<Vec<OrgMembership>>;

    /// The membership row for `(org, user)` incl. role level; `None` when not a member.
    async fn get_member(&self, org: OrgId, user: UserId) -> Result<Option<OrgMember>>;

    /// Adds a member with the given role (must be `> 0`; level 0 is "not a member").
    /// An existing membership is [`crate::Error::Conflict`] — use `update_member_role`.
    async fn add_member(&self, org: OrgId, user: UserId, role: RoleLevel, now: DateTime<Utc>) -> Result<OrgMember>;

    /// Changes a member's role. Demoting the last Owner is [`crate::Error::LastOwner`].
    async fn update_member_role(
        &self,
        org: OrgId,
        user: UserId,
        role: RoleLevel,
        now: DateTime<Utc>,
    ) -> Result<OrgMember>;

    /// Removes a member. Removing the last Owner is [`crate::Error::LastOwner`].
    async fn remove_member(&self, org: OrgId, user: UserId) -> Result<()>;

    /// Records an invitation (hashed single-use token, email-bound, expiring — S-06 defaults
    /// the role to Read via [`NewInvitation::new`]). A duplicate token hash is
    /// [`crate::Error::Conflict`].
    async fn create_invitation(&self, new: NewInvitation, now: DateTime<Utc>) -> Result<Invitation>;

    /// The invitation whose single-use token hashes to `token_hash`, in any lifecycle state;
    /// `None` when unknown.
    async fn find_invitation_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>>;

    /// Atomically consumes the invitation and adds `user` as a member (one transaction —
    /// no window where the invitation is spent but the membership missing).
    ///
    /// Errors: unknown hash → `NotFound`; already accepted or revoked → `Conflict` (an
    /// invitation is single-use); past `expires_at` → `Expired`; `user` lacking the exact
    /// invited email in verified state → `Forbidden` (the invitation is email-bound).
    /// If `user` is already a member, the membership keeps the higher of the two role levels
    /// (an invitation can raise, never lower).
    async fn accept_invitation(&self, token_hash: &str, user: UserId, now: DateTime<Utc>) -> Result<Invitation>;

    /// Revokes a pending invitation. Already accepted/revoked → [`crate::Error::Conflict`].
    async fn revoke_invitation(&self, id: InvitationId, now: DateTime<Utc>) -> Result<Invitation>;

    /// Every invitation of the org (all lifecycle states — the UI shows pending/expired/
    /// accepted/revoked), newest first.
    async fn list_invitations(&self, org: OrgId) -> Result<Vec<Invitation>>;
}

/// Web refresh-session persistence (decision 03, S-08..S-10).
///
/// Idle/absolute windows arrive as [`SessionLimits`] parameters on every validating lookup —
/// they are runtime-configurable, so the queries enforce whatever the instance currently
/// mandates. The KV revoked-`sid` fast path is maintained by the caller (S-09); this
/// repository is the durable truth.
#[async_trait]
pub trait SessionRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Creates a session from a fresh refresh-token hash plus device metadata.
    async fn create(&self, new: NewSession, now: DateTime<Utc>) -> Result<Session>;

    /// The live session whose **current** refresh hash matches: not revoked, within the idle
    /// window and the absolute cap at `now`. `None` otherwise (including rotated-out hashes —
    /// reuse detection happens in [`SessionRepo::rotate`]).
    async fn find_by_refresh_hash(
        &self,
        refresh_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>>;

    /// Atomically swaps `old_hash` for `new_hash` (the every-refresh rotation, S-08) and
    /// slides the idle window (`last_seen_at = now`).
    ///
    /// Reuse detection: presenting a hash that was already rotated out returns
    /// [`crate::Error::RefreshReused`] carrying the session id, so the caller can revoke the
    /// family and alert. A revoked session behaves as unknown (`NotFound`); a session outside
    /// its idle/absolute window is `Expired`.
    async fn rotate(
        &self,
        old_hash: &str,
        new_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Session>;

    /// Write-throttled activity bump: sets `last_seen_at = now` only when the current value
    /// is older than `now - throttle`. Returns whether a write happened. Unknown or revoked
    /// sessions return `false` (touching is best-effort, never an error path).
    async fn touch(&self, id: SessionId, throttle: Duration, now: DateTime<Utc>) -> Result<bool>;

    /// Marks the session revoked (S-09 durable truth). Idempotent: re-revoking keeps the
    /// original `revoked_at`. Unknown id → `NotFound`.
    async fn revoke(&self, id: SessionId, now: DateTime<Utc>) -> Result<()>;

    /// Revokes every live session of the user (logout-everywhere, permission change — S-09).
    /// Returns how many sessions were revoked.
    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64>;

    /// The user's non-revoked sessions, most recently seen first (session list UI — S-10).
    /// Idle/absolute filtering is the UI's concern; stale-but-unrevoked sessions still show.
    async fn list_for_user(&self, user: UserId) -> Result<Vec<Session>>;
}

/// CLI/API token persistence — tokens are stored as SHA-256 hashes, never plaintext
/// (decision 13, S-13).
#[async_trait]
pub trait TokenRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Mints a token row. Empty scopes are [`crate::Error::Invalid`]; a duplicate hash is
    /// [`crate::Error::Conflict`].
    async fn create(&self, new: NewToken, now: DateTime<Utc>) -> Result<Token>;

    /// The token whose plaintext hashes to `token_hash`, iff it is active at `now`: not
    /// revoked and not expired. `None` otherwise — the auth path cannot distinguish unknown,
    /// revoked, and expired (uniform 401, S-14).
    async fn find_active_by_hash(&self, token_hash: &str, now: DateTime<Utc>) -> Result<Option<Token>>;

    /// Write-throttled usage tracking (S-13): sets `last_used_at = now` (and the IP) only
    /// when the current value is absent or older than `now - throttle`. Returns whether a
    /// write happened; unknown or revoked tokens return `false`.
    async fn touch_last_used(
        &self,
        id: TokenId,
        ip: Option<&str>,
        throttle: Duration,
        now: DateTime<Utc>,
    ) -> Result<bool>;

    /// Revokes the token (effective within ≤60 s everywhere — S-13 caps caching above this
    /// repo). Idempotent: re-revoking keeps the original `revoked_at`. Unknown id → `NotFound`.
    async fn revoke(&self, id: TokenId, now: DateTime<Utc>) -> Result<()>;

    /// The user's non-revoked tokens (incl. expired ones — the UI shows them as expired),
    /// newest first.
    async fn list_for_user(&self, user: UserId) -> Result<Vec<Token>>;

    /// The org's non-revoked tokens, newest first (org admin surface).
    async fn list_for_org(&self, org: OrgId) -> Result<Vec<Token>>;
}

/// Append-only audit log (S-22).
///
/// The trait deliberately exposes **no update and no delete** — append and read are the whole
/// contract. Retention trimming (S-23) is a future privileged maintenance job, not a repo
/// capability. On Postgres the DB role is additionally INSERT-only (defense in depth); SQLite
/// has no roles, so this trait boundary *is* the enforcement there.
#[async_trait]
pub trait AuditRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Appends one event, minting its ULID id; returns the stored event.
    async fn append(&self, event: NewAuditEvent, now: DateTime<Utc>) -> Result<AuditEvent>;

    /// Lists events newest-first with keyset pagination over the ULID id.
    ///
    /// `cursor` is the opaque cursor from the previous [`Page`] (`None` for the first page);
    /// a malformed cursor is [`crate::Error::Invalid`]. `limit` is clamped to a sane range.
    /// Filters combine with AND; see [`AuditFilter`].
    async fn list(&self, filter: &AuditFilter, cursor: Option<&str>, limit: u32) -> Result<Page<AuditEvent>>;
}

/// Runtime-changeable instance settings, key → JSON with versions (decision 09;
/// cache/invalidation live above this repo). See [`crate::settings`] for version semantics.
#[async_trait]
pub trait SettingsRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Every settings entry (key, JSON value, per-key version), ordered by key.
    async fn get_all(&self) -> Result<Vec<SettingEntry>>;

    /// Creates or replaces the value under `key`, bumping its version (1 on first write).
    /// Returns the entry's new version.
    async fn upsert(&self, key: &str, value: &serde_json::Value, now: DateTime<Utc>) -> Result<i64>;

    /// The instance settings version: sum of all per-key versions — a monotonic change
    /// counter for the reconciliation version-poll. `0` when no settings exist.
    async fn get_version(&self) -> Result<i64>;
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

    /// **Atomically** increments the integer counter at `key` and returns the new value,
    /// creating it at `1` when absent and (re-)arming its `ttl`.
    ///
    /// Atomicity is the contract, not an optimization: budget counters that gate
    /// authentication attempts (S-03 ≤5 verifies per code) are decided by this return value,
    /// so a read-modify-write built from [`Kv::get`] + [`Kv::set_ttl`] would let concurrent
    /// requests share one increment and spend the budget many times over.
    async fn incr(&self, key: &str, ttl: Duration) -> Result<u64>;

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

    /// Sends a plain-text email.
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()>;

    /// Sends a two-part (text + HTML alternative) email. The default falls back to the
    /// plain-text path so simple implementations stay one method.
    async fn send_multipart(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<()> {
        let _ = html;
        self.send(to, subject, text).await
    }
}

/// The full set of identity & access repository handles, as one cloneable bundle.
///
/// Constructed once at startup by the selected database crate (`SqliteDb::repositories()` /
/// `PostgresDb::repositories()`) and carried in `AppState`; the contract test suite runs
/// against this bundle, so every backend is exercised through the same trait surface.
#[derive(Clone)]
pub struct Repositories {
    /// User accounts.
    pub users: Arc<dyn UserRepo>,
    /// Identity credentials.
    pub credentials: Arc<dyn CredentialRepo>,
    /// Orgs, memberships, invitations.
    pub orgs: Arc<dyn OrgRepo>,
    /// Web refresh sessions.
    pub sessions: Arc<dyn SessionRepo>,
    /// CLI/API tokens.
    pub tokens: Arc<dyn TokenRepo>,
    /// Append-only audit log.
    pub audit: Arc<dyn AuditRepo>,
    /// Runtime settings.
    pub settings: Arc<dyn SettingsRepo>,
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
