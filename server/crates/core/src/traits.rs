//! Backend trait contracts (decisions 02, 09, 10).
//!
//! Every infrastructure concern is expressed as a trait here and implemented in a dedicated
//! crate (`db-sqlite`, `db-postgres`, `blob`, `kv`, `mail`, …). `AppState` holds `Arc<dyn …>`
//! handles constructed once at startup from configuration — backend selection is runtime
//! polymorphism, never cargo features.
//!
//! The identity & access repositories (`UserRepo`, `CredentialRepo`, `OrgRepo`, `SessionRepo`,
//! `TokenRepo`, `AuditRepo`, `SettingsRepo`) and the registry repository (`PackageRepo`) carry
//! their full method sets; the remaining traits are still skeleton-phase (health probe + one
//! representative method) and grow with their roadmap steps.
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
use crate::authorize::{Action, ActorContext, Resource, authorize};
use crate::credential::Credential;
use crate::jobs::{JobOutcome, JobProgress, JobState};
use crate::org::{Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership, UpstreamPolicy};
use crate::package::{
    BaseScope, NameClaim, NewPackage, NewQuarantineEntry, NewShadowingAlarm, NewVersion, Package, PackageOptions,
    PublishedVersion, QuarantineEntry, Resolution, ShadowingAlarm, UpstreamCacheEntry, UpstreamPackage,
    UpstreamSnapshot, UpstreamVersion, Version, Visibility,
};
use crate::page::Page;
use crate::semver::SemVer;
use crate::session::{NewSession, Session, SessionLimits};
use crate::settings::SettingEntry;
use crate::token::{NewToken, Token};
use crate::user::{NewUser, User, UserStatus};
use crate::{
    CredentialId, Format, InvitationId, OrgId, PackageId, Result, RoleLevel, SessionId, TokenId, UserId, VersionId,
};

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

/// Registry persistence: packages, immutable versions, and name claims — all keyed by
/// `(format, name)` instance-wide (decisions 01, 06, 21).
///
/// Three contracts are load-bearing and are asserted by the shared contract suite against
/// every backend:
///
/// 1. **Publishing is one transaction.** [`PackageRepo::create_version`] checks the name
///    claim, creates the claim + package row on a first publish, and inserts the version — or
///    changes nothing. There is no window in which a claim exists without its package, or a
///    version without its claim.
/// 2. **Version numbers are never reusable** (decision 06, S-18). The `(package, version)`
///    uniqueness covers tombstoned rows too, so a hard-deleted number stays burned forever.
/// 3. **Ordering is semver precedence**, carried by [`crate::SemVer::sort_key`] in a
///    bytewise-collated column — never by the version text, under which `1.0.0-beta.11` would
///    precede `1.0.0-beta.2`.
#[async_trait]
pub trait PackageRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Creates a package row without publishing anything (explicit name reservation).
    ///
    /// The `(format, name)` name claim is created in the same transaction. A name already
    /// claimed — by any org — is [`crate::Error::Conflict`].
    async fn create_package(&self, new: NewPackage, now: DateTime<Utc>) -> Result<Package>;

    /// The package with this id; `None` when unknown.
    async fn get_package(&self, id: PackageId) -> Result<Option<Package>>;

    /// The package with this `(format, name)`; `None` when the name has no package row (it
    /// may still be claimed — see [`PackageRepo::lookup_claim`]).
    async fn get_by_name(&self, format: Format, name: &str) -> Result<Option<Package>>;

    /// The org's packages ordered by name, keyset-paginated over `(name, id)`.
    ///
    /// Includes unlisted and discontinued packages: this is the owner-facing listing, and
    /// hiding rows here would make them unmanageable. `limit` is clamped to a sane range; a
    /// malformed `cursor` is [`crate::Error::Invalid`].
    async fn list_for_org(&self, org: OrgId, cursor: Option<&str>, limit: u32) -> Result<Page<Package>>;

    /// Replaces the package's mutable options (visibility, discontinued, replaced_by,
    /// unlisted) and bumps `updated_at`. Unknown id → `NotFound`.
    async fn set_options(&self, id: PackageId, options: &PackageOptions, now: DateTime<Utc>) -> Result<Package>;

    /// Publishes a version — atomically, per contract 1 above.
    ///
    /// Errors: the name is claimed by another org → [`crate::Error::Forbidden`]; the version
    /// already exists (**including as a tombstone**) → [`crate::Error::Conflict`]; a
    /// concurrent first publish of the same name losing the race → `Conflict`.
    async fn create_version(&self, new: NewVersion, now: DateTime<Utc>) -> Result<PublishedVersion>;

    /// The package's row for exactly this version (tombstones included, so callers can tell
    /// "never existed" from "burned"); `None` when unknown.
    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<Version>>;

    /// The package's live versions in ascending semver precedence order, keyset-paginated
    /// over `(sort key, id)`.
    ///
    /// Retracted versions are **included and flagged** ([`Version::is_retracted`]) — they stay
    /// downloadable for lockfile-pinned builds (docs/protocol.md sharp edge 9). Tombstoned
    /// versions are excluded: their metadata and bytes are gone.
    async fn list_versions(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>>;

    /// Sets or clears the retraction flag; returns the updated row. Idempotent — retracting a
    /// retracted version keeps the original `retracted_at`. Unknown id → `NotFound`; a
    /// tombstoned version → `Conflict` (there is nothing left to retract).
    ///
    /// The *policy* around restoring (the window in which un-retraction is allowed) lives in
    /// the service layer; the repository only records the flag.
    async fn set_retracted(&self, id: VersionId, retracted: bool, now: DateTime<Utc>) -> Result<Version>;

    /// Hard-deletes a version (decision 06): clears the metadata document and rendered HTML
    /// and marks the row a tombstone, so the number can never be reused (S-18).
    ///
    /// Returns the tombstone row. Unknown id → `NotFound`; an already-tombstoned version →
    /// `Conflict`. Removing the archive bytes is the caller's job — the blob may be shared
    /// with other versions (identical content hashes).
    ///
    /// Takes no `now`: the row keeps its original timestamps, and *when* the deletion happened
    /// is recorded where it belongs — the audit log (S-22).
    async fn hard_delete_version(&self, id: VersionId) -> Result<Version>;

    /// How many **live** (non-tombstone) versions reference this content hash.
    ///
    /// Content addressing means one blob can back several versions; this is the check that
    /// keeps a hard delete from erasing bytes another version still serves (byte stability,
    /// docs/protocol.md sharp edge 3).
    async fn count_versions_with_sha256(&self, sha256: &str) -> Result<u64>;

    /// Claims `(format, name)` for `org` (decision 01).
    ///
    /// Idempotent for the holder: re-claiming a name the org already holds returns the
    /// existing claim. A name held by another org is [`crate::Error::Conflict`] — claims are
    /// never silently transferred.
    async fn claim_name(&self, format: Format, name: &str, org: OrgId, now: DateTime<Utc>) -> Result<NameClaim>;

    /// The claim on `(format, name)`; `None` when the name is unclaimed on this instance —
    /// which is the *only* condition under which the proxy may serve it (S-16).
    async fn lookup_claim(&self, format: Format, name: &str) -> Result<Option<NameClaim>>;

    /// Resolves `(format, name)` for a principal: who owns the name, and may this actor read
    /// it (decision 01 resolution order, decision 05 / S-04 visibility ladder).
    ///
    /// Provided, not implemented per backend: visibility is *policy*, and a second copy of it
    /// in a second SQL dialect is how the two backends drift apart. Backends supply the two
    /// lookups; the rule lives here and runs through the [`crate::authorize`] chokepoint.
    ///
    /// Callers must map both [`Resolution::Restricted`] and [`Resolution::Unclaimed`] to the
    /// same 404 on read paths (S-04 anti-enumeration).
    async fn resolve(&self, format: Format, name: &str, actor: &ActorContext) -> Result<Resolution> {
        if let Some(package) = self.get_by_name(format, name).await? {
            let readable = match package.visibility {
                Visibility::Public => true,
                Visibility::Private => authorize(actor, Action::ReadPackages, &Resource::Org(package.org_id)).is_ok(),
            };
            return Ok(if readable {
                Resolution::Readable(package)
            } else {
                Resolution::Restricted { owner: package.org_id }
            });
        }
        // A claim without a package row is still local: the name is burned here and must
        // never fall through to upstream (S-16 "local always wins").
        Ok(match self.lookup_claim(format, name).await? {
            Some(claim) => Resolution::Restricted { owner: claim.org_id },
            None => Resolution::Unclaimed,
        })
    }

    /// Resolves `(format, name)` **as seen from a virtual registry base** — decision 01's
    /// resolution order in code: org-owned → instance-public → (upstream, iff unclaimed).
    ///
    /// This is the only resolution the pub protocol routes are allowed to call, and it is a
    /// *provided* method for the same reason [`PackageRepo::resolve`] is: the policy exists
    /// once, above both SQL dialects, and runs through the [`crate::authorize`] chokepoint.
    ///
    /// **Local always wins** (S-16) is structural here rather than conventional:
    /// [`Resolution::Unclaimed`] — the sole value that permits an upstream lookup — is
    /// produced on exactly one path, after [`PackageRepo::lookup_claim`] came back empty. A
    /// locally claimed name can only ever yield `Readable` or `Restricted`, so no caller can
    /// reach upstream for it, whatever it does with the result. Both non-readable outcomes
    /// (`Restricted` and, for a base with no proxy, `Unclaimed`) must map to the **same 404**
    /// (S-04 anti-enumeration).
    ///
    /// Differences from [`PackageRepo::resolve`], which answers the instance-wide question
    /// the web UI asks:
    ///
    /// - Under [`BaseScope::Org`], another org's **private** package is invisible even to a
    ///   principal who is a member of that other org — it is not in this base's resolution
    ///   order at all (see [`BaseScope`]).
    /// - Under [`BaseScope::PublicRoot`], nothing private resolves, not even the caller's own.
    async fn resolve_in_base(
        &self,
        format: Format,
        name: &str,
        base: BaseScope,
        actor: &ActorContext,
    ) -> Result<Resolution> {
        if let Some(package) = self.get_by_name(format, name).await? {
            let readable = match (base, package.visibility) {
                // Step 1: the base's own org — public and private alike, the latter behind
                // the role gate.
                (BaseScope::Org(org), visibility) if org == package.org_id => {
                    visibility == Visibility::Public
                        || authorize(actor, Action::ReadPackages, &Resource::Org(package.org_id)).is_ok()
                }
                // Step 2: instance-public packages owned by other orgs.
                (_, Visibility::Public) => true,
                // Another org's private package: not part of this base's namespace.
                (_, Visibility::Private) => false,
            };
            return Ok(if readable {
                Resolution::Readable(package)
            } else {
                Resolution::Restricted { owner: package.org_id }
            });
        }
        // Step 3 is only reachable when the name is claimed nowhere on this instance.
        Ok(match self.lookup_claim(format, name).await? {
            Some(claim) => Resolution::Restricted { owner: claim.org_id },
            None => Resolution::Unclaimed,
        })
    }
}

/// Proxy-cache persistence: upstream listing snapshots and the per-version rows behind them
/// (decision 07, S-19).
///
/// This repository is deliberately **not** part of [`PackageRepo`]: an upstream row is not a
/// package we own. It has no org, no claim, no publisher, and no lifecycle of its own — it is
/// a cached copy of somebody else's truth, and keeping it in a separate trait is what stops a
/// resolution path from confusing the two (S-16 "local always wins" is only meaningful while
/// the two sets are distinguishable).
///
/// Two contracts are load-bearing and are asserted by the shared contract suite against every
/// backend:
///
/// 1. **A snapshot never deletes.** [`UpstreamRepo::save_snapshot`] upserts; versions missing
///    from the new listing keep their rows, because we may already hold their bytes and a
///    hash in somebody's `pubspec.lock` has to keep resolving.
/// 2. **A cached version's hash and size are immutable** (S-19 byte-drift). Once
///    [`UpstreamVersion::cached`] is set, `save_snapshot` keeps the recorded
///    `archive_sha256` even when upstream now advertises a different one — and the
///    `archive_size` measured while caching, since a later claim must not make the served
///    `Content-Length` disagree with the bytes. The service layer detects and alarms on the
///    drift; this rule makes overwriting impossible even if it did not.
#[async_trait]
pub trait UpstreamRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// The cached snapshot row for `(format, name)`; `None` when the name was never fetched.
    async fn get_package(&self, format: Format, name: &str) -> Result<Option<UpstreamPackage>>;

    /// Every cached version of an upstream package, ascending by semver precedence.
    async fn list_versions(&self, package: PackageId) -> Result<Vec<UpstreamVersion>>;

    /// One cached upstream version by exact number; `None` when unknown.
    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<UpstreamVersion>>;

    /// Writes a listing snapshot (upsert, per contract 1 and 2 above) and returns the stored
    /// package row.
    async fn save_snapshot(&self, snapshot: UpstreamSnapshot, now: DateTime<Utc>) -> Result<UpstreamPackage>;

    /// Records that the archive bytes for this version are now in our blob store, under the
    /// content-addressed key derived from `sha256`, and how many bytes they are.
    ///
    /// The hash is passed and matched rather than trusted from the row: the caller verified it
    /// against the bytes it just stored (S-19), and a row whose hash moved underneath a
    /// concurrent snapshot must not be marked cached for the wrong content. Returns whether a
    /// row was updated. Unknown id → `false`, never an error: the cache is best-effort.
    ///
    /// `size` is recorded because upstream listings do not carry one and the served response
    /// needs a `Content-Length`; a later snapshot must not erase it (see
    /// [`UpstreamRepo::save_snapshot`]).
    async fn mark_cached(&self, id: VersionId, sha256: &str, size: i64, now: DateTime<Utc>) -> Result<bool>;

    /// Snapshots older than `before`, **oldest first**, capped at `limit` — the mirror
    /// worker's steady-state work queue (decision 07 mirror mode).
    ///
    /// No cursor: refreshing a snapshot updates its `fetched_at`, which moves it to the back of
    /// this ordering, so repeated calls walk the whole cache without one. That is also what
    /// makes the job idempotent — an interrupted pass simply re-reads the packages it had not
    /// reached yet.
    async fn list_stale(&self, format: Format, before: DateTime<Utc>, limit: u32) -> Result<Vec<UpstreamPackage>>;

    /// The admin-facing cache inventory: one aggregated row per cached upstream package,
    /// keyset-paginated over the name.
    async fn list_cached(&self, format: Format, cursor: Option<&str>, limit: u32) -> Result<Page<UpstreamCacheEntry>>;

    /// How many **cached** upstream versions reference this content hash.
    ///
    /// The proxy stores its archives under the same content-addressed keys a local publish
    /// uses, so unreferenced-blob GC has to ask both this and
    /// [`PackageRepo::count_versions_with_sha256`] before it deletes anything. Missing this
    /// half would delete bytes a `pubspec.lock` pins through the proxy (S-18).
    async fn count_cached_with_sha256(&self, sha256: &str) -> Result<u64>;

    /// Records a refused archive (S-19 hash mismatch). Repeated observations of one
    /// `(format, name, version)` collapse onto one row: `occurrences` increments and
    /// `last_seen_at` advances.
    async fn record_quarantine(&self, entry: NewQuarantineEntry, now: DateTime<Utc>) -> Result<QuarantineEntry>;

    /// Quarantined items, most recently observed first.
    async fn list_quarantine(&self, limit: u32) -> Result<Vec<QuarantineEntry>>;

    /// Records that a locally claimed name was observed upstream (S-17).
    ///
    /// Returns the row and whether this call **raised** the alarm — either the first-ever
    /// observation, or the first one after an admin acknowledged it. Only a raise is worth an
    /// audit event, a notification, and a page; every subsequent sighting is a counter, or the
    /// mirror worker would re-alert on every sweep for as long as the condition holds.
    async fn record_shadowing(&self, alarm: NewShadowingAlarm, now: DateTime<Utc>) -> Result<(ShadowingAlarm, bool)>;

    /// Shadowing alarms, newest observation first. `active_only` hides acknowledged ones.
    async fn list_shadowing(&self, active_only: bool, limit: u32) -> Result<Vec<ShadowingAlarm>>;

    /// Acknowledges a shadowing alarm; returns whether an active alarm was acknowledged.
    ///
    /// Acknowledging is bookkeeping, never policy: the local package wins before and after,
    /// because the alternative would make an admin click a button to keep their own package.
    async fn acknowledge_shadowing(&self, format: Format, name: &str, now: DateTime<Utc>) -> Result<bool>;
}

/// Durable background-job state (decision 03 leader-locked scheduler; see [`crate::jobs`]).
///
/// Separate from [`JobLock`] on purpose: the lock answers "may I run right now" and lives
/// wherever leader election does (KV, PG advisory locks), while this answers "where did I get
/// to" and has to be durable across every restart and every leader change. One instance
/// acquiring the lock must resume the cursor the *previous* leader wrote.
#[async_trait]
pub trait JobRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// The job's state; `None` when it has never run.
    async fn get(&self, name: &str) -> Result<Option<JobState>>;

    /// Every job's state, ordered by name — the admin surface's job table.
    async fn list(&self) -> Result<Vec<JobState>>;

    /// Stamps the start of a run (creating the row on first use) and returns the state to
    /// **resume from**, cursor included. Increments `runs`.
    async fn begin_run(&self, name: &str, now: DateTime<Utc>) -> Result<JobState>;

    /// Records mid-run progress: sets `cursor`/`phase` and *adds* the reported counters
    /// ([`JobProgress`]). Safe to call as often as the job checkpoints.
    async fn checkpoint(&self, name: &str, progress: &JobProgress, now: DateTime<Utc>) -> Result<JobState>;

    /// Records how the run ended (see [`JobOutcome`]). A failure keeps the cursor, so the next
    /// run continues rather than starting over.
    async fn finish_run(&self, name: &str, outcome: JobOutcome, now: DateTime<Utc>) -> Result<JobState>;
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

    /// Sets the org's upstream-proxy policy (decision 01, S-16) and bumps `updated_at`.
    /// Unknown id → `NotFound`.
    ///
    /// A dedicated setter rather than a general "update org" patch: this field is a
    /// *resolution* policy — flipping it changes which packages an entire team can install —
    /// so it gets its own audited call site instead of riding along with a rename.
    async fn set_upstream_policy(&self, id: OrgId, policy: UpstreamPolicy, now: DateTime<Utc>) -> Result<Org>;

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

    /// Reads a blob's bytes into this process.
    ///
    /// Deliberately distinct from [`BlobStore::download`]: that one *plans a client response*
    /// and may hand back a presigned redirect, which is useless to the server itself. Internal
    /// consumers — the publish finalizer picking up a staged upload, the proxy re-verifying a
    /// cached archive's sha256 (S-19) — need the bytes here.
    ///
    /// The default drains a streamed plan, which is correct for every backend that never
    /// redirects; a signing backend must override it with a direct read.
    async fn get(&self, key: &str) -> Result<Bytes> {
        match self.download(key).await? {
            DownloadPlan::Stream(mut stream) => {
                use futures::StreamExt as _;

                let mut buf = Vec::new();
                while let Some(chunk) = stream.next().await {
                    buf.extend_from_slice(&chunk?);
                }
                Ok(Bytes::from(buf))
            }
            DownloadPlan::Redirect(_) => Err(crate::Error::Blob {
                message: format!("blob backend cannot read {key} in-process: it only plans redirects"),
            }),
        }
    }

    /// Removes a blob. Deleting an absent key is **not** an error — the operation is
    /// idempotent so a retried hard delete or a GC sweep over a partially cleaned store
    /// cannot fail (decision 06 hard delete, unreferenced-blob GC).
    ///
    /// Callers must check that no live version still references the content hash: blobs are
    /// content-addressed, so identical uploads share one object (docs/protocol.md sharp
    /// edge 3 — served bytes are stable forever).
    async fn delete(&self, key: &str) -> Result<()>;

    /// Every object under `prefix`, with its size and last-modified time.
    ///
    /// Exists for one caller — the unreferenced-blob GC job — and the last-modified time is
    /// what makes that job safe: the publish pipeline writes bytes *before* the version row
    /// (an interrupted publish must leave garbage, never a row pointing at nothing), so a
    /// freshly written blob is legitimately unreferenced for the width of one transaction.
    /// GC therefore refuses to touch anything younger than its grace period, and a backend
    /// that cannot report an age cannot be swept.
    ///
    /// The default is [`crate::Error::Unimplemented`]: a store that cannot enumerate is not a
    /// broken store, it just cannot be garbage-collected, and the job reports that as a job
    /// failure rather than silently deleting on incomplete information.
    async fn list(&self, prefix: &str) -> Result<Vec<BlobObject>> {
        let _ = prefix;
        Err(crate::Error::Unimplemented { what: "this blob backend cannot enumerate objects".to_owned() })
    }
}

/// One stored object, as [`BlobStore::list`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobObject {
    /// Storage key.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// Last modification time, when the backend reports one.
    pub last_modified: Option<DateTime<Utc>>,
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

/// The full set of repository handles, as one cloneable bundle.
///
/// Constructed once at startup by the selected database crate (`SqliteDb::repositories()` /
/// `PostgresDb::repositories()`) and carried in `AppState`; the contract test suite runs
/// against this bundle, so every backend is exercised through the same trait surface.
#[derive(Clone)]
pub struct Repositories {
    /// Packages, versions, and name claims.
    pub packages: Arc<dyn PackageRepo>,
    /// Upstream proxy cache (decision 07).
    pub upstream: Arc<dyn UpstreamRepo>,
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
    /// Durable background-job state (decision 03, decision 07 mirror).
    pub jobs: Arc<dyn JobRepo>,
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
