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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::audit::{AuditEvent, AuditFilter, NewAuditEvent};
use crate::authorize::{Action, ActorContext, Resource, authorize};
use crate::credential::Credential;
use crate::jobs::{JobOutcome, JobProgress, JobState};
use crate::notification::{NewNotification, Notification, NotificationCategory, NotificationPreference};
use crate::org::{
    Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership, OrgOverview, OrgProfile, UpstreamPolicy,
};
use crate::package::{
    BaseScope, NameClaim, NewPackage, NewQuarantineEntry, NewShadowingAlarm, NewVersion, Package, PackageOptions,
    PublishedVersion, QuarantineEntry, RegistryStats, Resolution, ShadowingAlarm, UpstreamCacheEntry,
    UpstreamCacheStats, UpstreamPackage, UpstreamSnapshot, UpstreamVersion, Version, Visibility,
};
use crate::page::Page;
use crate::queue::{
    JobKind, NewQueuedJob, QueueOutcome, QueuePurged, QueueRetention, QueueState, QueuedJob, QueuedJobId,
};
use crate::search::{InstanceCounters, SearchDocument, SearchFacets, SearchHit, SearchQuery, SearchView};
use crate::semver::SemVer;
use crate::session::{NewSession, Session, SessionLimits};
use crate::settings::SettingEntry;
use crate::stats::{DownloadDelta, DownloadTotals, PackageDownloads};
use crate::token::{NewToken, Token};
use crate::user::{NewUser, User, UserCounts, UserFilter, UserStatus};
use crate::{
    CredentialId, Format, InvitationId, NotificationId, OrgId, PackageId, Result, RoleLevel, SessionId, TokenId,
    UserId, VersionId,
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

    /// Every package on the instance, ordered by `(format, name)` and keyset-paginated over
    /// that pair — the reindex job's work queue.
    ///
    /// Deliberately unfiltered by visibility, org, or listing state: the search index must be
    /// rebuildable in full from this walk, and a filtered enumeration would silently make some
    /// packages unindexable. Callers other than the indexer should not exist.
    async fn list_all(&self, cursor: Option<&str>, limit: u32) -> Result<Page<Package>>;

    /// Replaces the package's mutable options (visibility, discontinued, replaced_by,
    /// unlisted) and bumps `updated_at`. Unknown id → `NotFound`.
    async fn set_options(&self, id: PackageId, options: &PackageOptions, now: DateTime<Utc>) -> Result<Package>;

    /// Moves a package to another org — the package row **and its name claim**, in one
    /// transaction.
    ///
    /// Both or neither: a claim left pointing at the old org would make the new owner unable
    /// to publish the name they now hold, and the shadowing alarm would page the wrong
    /// admins (S-17). Unknown id → `NotFound`; an unknown target org → `NotFound`; moving a
    /// package to the org that already owns it is a no-op that returns the row.
    async fn transfer(&self, id: PackageId, to_org: OrgId, now: DateTime<Utc>) -> Result<Package>;

    /// How many packages the org owns, any visibility — the org-deletion guard.
    async fn count_for_org(&self, org: OrgId) -> Result<i64>;

    /// Instance-wide registry totals for the admin dashboard.
    async fn stats(&self) -> Result<RegistryStats>;

    /// Publishes a version — atomically, per contract 1 above.
    ///
    /// Errors: the name is claimed by another org → [`crate::Error::Forbidden`]; the version
    /// already exists (**including as a tombstone**) → [`crate::Error::Conflict`]; a
    /// concurrent first publish of the same name losing the race → `Conflict`.
    async fn create_version(&self, new: NewVersion, now: DateTime<Utc>) -> Result<PublishedVersion>;

    /// The package's row for exactly this version (tombstones included, so callers can tell
    /// "never existed" from "burned"); `None` when unknown.
    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<Version>>;

    /// How many **live** (non-tombstone) versions the package has.
    ///
    /// Exists so the package page can report `versions_count` without walking the listing: a
    /// package with thousands of versions would otherwise cost one query per hundred on an
    /// anonymous-reachable route.
    async fn count_versions(&self, package: PackageId) -> Result<i64>;

    /// The package's live versions in ascending semver precedence order, keyset-paginated
    /// over `(sort key, id)`.
    ///
    /// Retracted versions are **included and flagged** ([`Version::is_retracted`]) — they stay
    /// downloadable for lockfile-pinned builds (docs/protocol.md sharp edge 9). Tombstoned
    /// versions are excluded: their metadata and bytes are gone.
    async fn list_versions(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>>;

    /// The same listing in **descending** precedence order — newest first.
    ///
    /// A separate method rather than a flag because the two have different callers with
    /// different needs: the pub protocol re-emits the whole listing ascending (the spec's
    /// order, and the order `latest` is derived from), while the web UI shows the newest
    /// release first and pages backwards from there. Reversing a page in the API layer would
    /// give newest-first *within* a page while paging from the oldest, which is worse than
    /// either order.
    async fn list_versions_desc(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>>;

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

    /// Instance-wide proxy-cache totals for the admin dashboard: how many upstream packages
    /// and versions are known, how many are held as bytes, and how much that costs.
    async fn cache_stats(&self, format: Format) -> Result<UpstreamCacheStats>;

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

/// The durable work queue (decision 26; see [`crate::queue`]).
///
/// Distinct from [`JobRepo`] on purpose: that one answers "where did this sweep get to" with
/// one row per job name, this one holds **work items** — one row per thing to do, each with
/// its own attempts, backoff and dead-letter state. It is in the database rather than behind
/// [`Kv`] because that seam deliberately has no key enumeration, so nothing could ever find
/// the items again to drain them (the same reason the download-stats buffer is not a KV
/// counter — see `registry/src/stats.rs`).
///
/// Three properties every implementation must carry, because the worker relies on them rather
/// than re-checking:
///
/// 1. **A claim is exclusive for the length of its lease.** Two concurrent claims never return
///    the same item, whatever the backend's concurrency model (`FOR UPDATE SKIP LOCKED` on
///    Postgres, the single writer on SQLite). Without this, one publish notifies everybody
///    twice and one sign-in sends two codes.
/// 2. **[`QueueState::Suppressed`] is a dead end.** No method here may move a row out of it —
///    not [`JobQueueRepo::claim`], not [`JobQueueRepo::complete`], not
///    [`JobQueueRepo::reap_expired_leases`]. That is S-04.a and S-31 expressed in the storage
///    layer: a policy-rejected address files a row so the two branches cost the same, and that
///    row must never become a deliverable message.
/// 3. **Attempts are spent at claim time**, so an item that kills its handler mid-run still
///    converges on the dead letter instead of retrying forever.
///
/// Retry policy — how many attempts, how long the backoff — lives in the worker, never here:
/// a repository that deadlettered on its own count would be policy in the schema.
#[async_trait]
pub trait JobQueueRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Files one work item and returns the stored row.
    ///
    /// `Ok(None)` when the item carries a `dedupe_key` that is already present — a retried
    /// enqueue is a no-op, not a second copy. A [`NewQueuedJob`] whose state is not
    /// [`QueueState::is_admissible`] is [`crate::Error::Invalid`]: `done` and `dead` are
    /// outcomes a worker records, and `running` is a lease nobody holds.
    async fn enqueue(&self, new: &NewQueuedJob, now: DateTime<Utc>) -> Result<Option<QueuedJob>>;

    /// One item by id; `None` when unknown or already purged.
    ///
    /// The drain worker never needs this — it works from what [`JobQueueRepo::claim`] handed
    /// back — but the admin dead-letter view does, and so does every test that asserts a state
    /// transition: a queue whose rows can only be observed by claiming them cannot be checked
    /// without mutating what is being checked.
    async fn get(&self, id: QueuedJobId) -> Result<Option<QueuedJob>>;

    /// Leases up to `limit` runnable items of these `kinds` — **lowest priority value first,
    /// oldest id within a priority** — marking each `running` until `now + lease` and
    /// incrementing its attempt count.
    ///
    /// The priority half of that order is what keeps a sign-in code from being claimed behind
    /// a broadcast filed minutes earlier (decision 26's amendment); the id half is what makes
    /// arrival order claim order inside one class of work.
    ///
    /// Runnable means `pending` **and** `run_after <= now`. Empty `kinds` or `limit == 0`
    /// returns an empty batch and performs no query. The returned rows carry their post-claim
    /// state, so the caller reads `attempts` to decide whether this run is the last one.
    async fn claim(&self, kinds: &[JobKind], limit: u32, lease: Duration, now: DateTime<Utc>)
    -> Result<Vec<QueuedJob>>;

    /// Records how one claimed item ended (see [`QueueOutcome`]). `backoff` is consumed only
    /// by [`QueueOutcome::Retry`], which re-arms `run_after = now + backoff`.
    ///
    /// Applies **only to a row that is still `running`**. A worker whose lease already expired
    /// and was reaped therefore reports into the void rather than clobbering the state of
    /// whoever holds the item now — and, decisively, a `Retry` can never resurrect a
    /// suppressed or dead-lettered row into something claimable.
    async fn complete(
        &self,
        id: QueuedJobId,
        outcome: QueueOutcome,
        backoff: Duration,
        now: DateTime<Utc>,
    ) -> Result<()>;

    /// Returns every item whose lease expired — a worker died mid-run — to `pending`, and
    /// reports how many. The attempt those items already spent is **not** given back.
    async fn reap_expired_leases(&self, now: DateTime<Utc>) -> Result<u64>;

    /// Deletes the rows of every terminal state that are older than that state's cutoff
    /// ([`QueueRetention`]), and reports how many of each ([`QueuePurged`]).
    ///
    /// Every state a row can settle in has a bound, because a queue with retention for one of
    /// them still grows forever: `suppressed` rows are filed by an unauthenticated endpoint and
    /// have no reader after that request, and `dead` rows are the operator's record — kept
    /// long, deleted eventually, never silently (decision 26; the drain warns when it takes
    /// one). `pending` and `running` rows are work, not history, and are never retention's.
    async fn purge(&self, retention: &QueueRetention) -> Result<QueuePurged>;

    /// Per-`(kind, state)` item counts for `/metrics` and the admin job table, ordered by kind
    /// then state. Combinations with no rows are absent rather than reported as zero.
    async fn depth(&self) -> Result<Vec<(JobKind, QueueState, i64)>>;
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

    /// The users with these ids, in **unspecified** order, unknown ids simply absent.
    ///
    /// The batch form exists to kill N+1 reads in listings that show a person per row (org
    /// members, a package's version history). Callers index the result by id rather than by
    /// position — a missing account is a deleted one, not an error. An empty input is an empty
    /// result and performs no query.
    async fn get_many(&self, ids: &[UserId]) -> Result<Vec<User>>;

    /// The user holding this email **verified** (S-01: unverified emails never identify an
    /// account); matching is case-insensitive. `None` when no verified match exists.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;

    /// Updates the lifecycle status.
    ///
    /// Transitioning to [`UserStatus::Deleted`] anonymizes the row (S-29): email is cleared
    /// (freeing it for re-registration) and the display name is blanked; the row itself
    /// survives as the attribution tombstone for published versions.
    async fn update_status(&self, id: UserId, status: UserStatus, now: DateTime<Utc>) -> Result<User>;

    /// The admin user listing, **newest account first**, keyset-paginated over the UUID v7 id
    /// (which is time-ordered, so the id alone is the cursor). Filters combine with AND.
    async fn list(&self, filter: &UserFilter, cursor: Option<&str>, limit: u32) -> Result<Page<User>>;

    /// Account counts for the admin dashboard.
    async fn counts(&self) -> Result<UserCounts>;

    /// Sets or clears the instance-admin flag. Unknown id → `NotFound`.
    ///
    /// Deliberately separate from [`UserRepo::update_status`]: promoting an administrator and
    /// suspending an account are different privileges with different audit actions, and a
    /// combined "update user" call is how one of them rides along with the other by accident.
    async fn set_instance_admin(&self, id: UserId, is_admin: bool, now: DateTime<Utc>) -> Result<User>;

    /// **Atomically** makes `id` an instance admin *iff the instance currently has none*;
    /// returns whether this call promoted them (decision 09 bootstrap).
    ///
    /// The condition is checked inside the same statement, so two accounts registering at the
    /// same moment on two instances cannot both become the first admin. `false` means somebody
    /// already holds the flag — including the caller themselves, which makes the call
    /// idempotent.
    async fn claim_first_admin(&self, id: UserId, now: DateTime<Utc>) -> Result<bool>;
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

    /// Replaces the org's mutable profile (name, description, upstream policy) and bumps
    /// `updated_at`. Unknown id → `NotFound`.
    ///
    /// The slug is **not** in the payload: it is the org's virtual registry base
    /// (`/o/{slug}/pub`), so renaming it would silently break every `PUB_HOSTED_URL`, every
    /// `pubspec.yaml` that names it, and every stored `archive_url` (decision 01).
    async fn update_profile(&self, id: OrgId, profile: &OrgProfile, now: DateTime<Utc>) -> Result<Org>;

    /// Sets the org's upstream-proxy policy (decision 01, S-16) and bumps `updated_at`.
    /// Unknown id → `NotFound`.
    ///
    /// A dedicated setter rather than a general "update org" patch: this field is a
    /// *resolution* policy — flipping it changes which packages an entire team can install —
    /// so it gets its own audited call site instead of riding along with a rename.
    async fn set_upstream_policy(&self, id: OrgId, policy: UpstreamPolicy, now: DateTime<Utc>) -> Result<Org>;

    /// Every org on the instance with its member and package counts, ordered by slug and
    /// keyset-paginated over it — the instance-admin org table.
    async fn list_all(&self, cursor: Option<&str>, limit: u32) -> Result<Page<OrgOverview>>;

    /// How many orgs exist (archived ones included).
    async fn count(&self) -> Result<i64>;

    /// Erases the org and everything that exists only to describe it: memberships,
    /// invitations, and org-bound CLI tokens, in one transaction.
    ///
    /// Refuses with [`crate::Error::Conflict`] when anything **durable** still references the
    /// org — a package row or a name claim — because decision 06 and S-18 keep those forever
    /// and an org row is what they hang from. The caller's escape hatch for that case is
    /// [`OrgRepo::archive`], not a cascade.
    async fn delete(&self, id: OrgId) -> Result<()>;

    /// Archives an org that cannot be erased: stamps `archived_at` and, in the same
    /// transaction, removes every membership and invitation and revokes every org-bound token.
    ///
    /// Idempotent — re-archiving keeps the original `archived_at`. Unknown id → `NotFound`.
    /// Making the org's packages unreachable is the service layer's job (they go private +
    /// unlisted + discontinued through the registry service, so the search index follows).
    async fn archive(&self, id: OrgId, now: DateTime<Utc>) -> Result<Org>;

    /// Every org the user is a member of, with the user's role, oldest org first.
    async fn list_for_user(&self, user: UserId) -> Result<Vec<OrgMembership>>;

    /// The membership row for `(org, user)` incl. role level; `None` when not a member.
    async fn get_member(&self, org: OrgId, user: UserId) -> Result<Option<OrgMember>>;

    /// Every member of the org, highest role first then oldest membership — the members table.
    async fn list_members(&self, org: OrgId) -> Result<Vec<OrgMember>>;

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

    /// Whether `email` holds at least one invitation that is still redeemable at `now`
    /// (pending, not revoked, not expired) — the `invite`-only registration gate
    /// ([`crate::settings::RegistrationMode::Invite`], S-31).
    ///
    /// Matching is case-insensitive, like every other email lookup.
    async fn has_pending_invitation(&self, email: &str, now: DateTime<Utc>) -> Result<bool>;

    /// How many invitations the org sent inside `[since, now]` — the S-24 per-org invitation
    /// budget (≤20/day/org).
    async fn count_invitations_since(&self, org: OrgId, since: DateTime<Utc>) -> Result<i64>;
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
    /// revoked, not expired, **and held by a user whose status is `active`** — suspension
    /// gates the credential plane here at the repository (decision 13 addendum, D37), so a
    /// suspended account's tokens stop authenticating within the S-13 bound and resume on
    /// reinstatement with no re-mint. `None` otherwise — the auth path cannot distinguish
    /// unknown, revoked, expired, and suspended (uniform 401, S-14).
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

/// The notification center's persistence (decision 20): a per-user feed plus per-category
/// delivery preferences.
///
/// Two contracts are load-bearing and are asserted by the shared contract suite against every
/// backend:
///
/// 1. **Every read and every write is scoped to one user.** There is no method that can return
///    or touch another account's notification — the `user` parameter is not a filter the caller
///    may omit, and [`NotificationRepo::mark_read`] silently ignores ids belonging to somebody
///    else rather than reporting them (which would be an existence oracle).
/// 2. **Marking read is idempotent and monotonic.** Re-marking a read notification keeps the
///    original `read_at`, so the returned count is "how many this call changed", which is what
///    an unread badge needs.
#[async_trait]
pub trait NotificationRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Files one notification and returns the stored row.
    async fn create(&self, new: NewNotification, now: DateTime<Utc>) -> Result<Notification>;

    /// Files a batch of notifications and returns **the rows this call created**, in input
    /// order.
    ///
    /// The batch form exists because fan-out writes one row per recipient: an org event with
    /// two hundred members would otherwise be two hundred statements on one worker tick. Bounded
    /// like [`NotificationRepo::stored_preferences`] — an oversized batch is
    /// [`crate::Error::Invalid`], an empty one is an empty result and performs no query.
    ///
    /// Ids are minted in input order, which is what makes the returned order meaningful: a
    /// user's feed is ordered by notification id, so recipients handed over in audience order
    /// read their rows back in that order too.
    ///
    /// **An item whose `(user_id, event_id)` is already filed is skipped, not an error, and is
    /// absent from the result** — that is the exactly-once guarantee decision 26's amendment
    /// moved from a cross-table transaction to a uniqueness constraint. A re-run after a crash
    /// therefore reports only what it actually added, which is what a caller publishing "you
    /// have a new notification" hints off the result needs to know.
    async fn create_many(&self, new: &[NewNotification], now: DateTime<Utc>) -> Result<Vec<Notification>>;

    /// Unread counts for a batch of users, as `(user, count)` pairs in **unspecified** order.
    ///
    /// The batch counterpart of [`NotificationRepo::unread_count`], for the same reason the
    /// batched preference lookup exists: the fan-out needs one badge number per recipient to
    /// put on its `UserNotified` events. Users with nothing unread are **absent** rather than
    /// reported as zero — the same shape a `GROUP BY` produces — so callers default a missing
    /// entry to zero. Bounded and empty-safe like the other batch reads.
    async fn unread_counts(&self, users: &[UserId]) -> Result<Vec<(UserId, i64)>>;

    /// The user's feed, newest first, keyset-paginated over the UUID v7 id (time-ordered, so
    /// the id alone is the cursor). `unread_only` narrows to unread rows.
    ///
    /// A malformed cursor is [`crate::Error::Invalid`]; `limit` is clamped to a sane range.
    async fn list(
        &self,
        user: UserId,
        unread_only: bool,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Notification>>;

    /// How many of the user's notifications are unread.
    async fn unread_count(&self, user: UserId) -> Result<i64>;

    /// Marks the listed notifications read; returns how many rows this call changed. Ids the
    /// user does not own, unknown ids, and already-read ids are all no-ops (contract 1 and 2).
    async fn mark_read(&self, user: UserId, ids: &[NotificationId], now: DateTime<Utc>) -> Result<u64>;

    /// Marks every unread notification of the user read; returns how many rows changed.
    async fn mark_all_read(&self, user: UserId, now: DateTime<Utc>) -> Result<u64>;

    /// The user's stored preference rows — categories they never touched are absent, and
    /// [`crate::notification::NotificationPreferences::from_rows`] fills them in.
    async fn preferences(&self, user: UserId) -> Result<Vec<NotificationPreference>>;

    /// The **stored** preference for one category across a batch of users, as
    /// `(user, preference)` pairs; users with no row for that category are simply absent and
    /// take the default.
    ///
    /// The batch form exists because fan-out asks this question once per recipient: an org
    /// event with two hundred members would otherwise be two hundred queries before the first
    /// notification is written.
    async fn stored_preferences(
        &self,
        users: &[UserId],
        category: NotificationCategory,
    ) -> Result<Vec<(UserId, NotificationPreference)>>;

    /// Upserts the given preference rows (one per category) and returns the full stored set.
    async fn set_preferences(
        &self,
        user: UserId,
        prefs: &[NotificationPreference],
        now: DateTime<Utc>,
    ) -> Result<Vec<NotificationPreference>>;
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

/// Full-text package search and the public read model over it (decision 11): PG
/// `tsvector` + GIN + `pg_trgm`, or SQLite FTS5 with sync triggers.
///
/// The index is **derived data**: every document can be rebuilt from `packages` + `versions`
/// by the reindex job, which is why an indexing failure is logged rather than propagated into
/// a publish. Three contracts are load-bearing and are asserted by the shared contract suite
/// against every backend:
///
/// 1. **Visibility is enforced inside the implementation.** Every read here takes a
///    [`SearchView`] and must apply `visibility = 'public' OR org_id ∈ view` as a *mandatory*
///    predicate — no query text, filter, or cursor may widen it. The view is built through the
///    [`crate::authorize`] chokepoint, so this is the same policy resolution uses rather than a
///    second copy of it (S-04: a principal must never learn that a private package exists).
///    `unlisted` packages additionally never leave their own org, because "hidden from
///    discovery" is what the flag means.
/// 2. **A document exists only while the package has a live version.** Publishing creates or
///    refreshes it; retraction, hard delete, and option changes refresh it; losing the last
///    live version removes it. A search result therefore always carries a version.
/// 3. **Cursors are ordering-bound.** A cursor produced under one [`SearchSort`](crate::search::SearchSort) is
///    [`crate::Error::Invalid`] under another — the sort key it carries means nothing there,
///    and silently reshuffling the page would skip results.
#[async_trait]
pub trait PackageSearch: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Creates or replaces one package's search document (contract 2).
    async fn index(&self, document: &SearchDocument) -> Result<()>;

    /// Removes a package from the index; removing an absent package is not an error.
    async fn remove(&self, package: PackageId) -> Result<()>;

    /// Runs a search, keyset-paginated in [`SearchQuery::effective_sort`] order.
    ///
    /// A malformed cursor — or one produced under a different ordering — is
    /// [`crate::Error::Invalid`]; `limit` is clamped to a sane range.
    async fn search(
        &self,
        query: &SearchQuery,
        view: &SearchView,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SearchHit>>;

    /// Aggregates over the **same** filtered set [`PackageSearch::search`] would return: total
    /// match count plus the top owning orgs, capped at `facet_limit` buckets.
    async fn facets(&self, query: &SearchQuery, view: &SearchView, facet_limit: u32) -> Result<SearchFacets>;

    /// Instance counters for the landing dashboard, scoped to the caller's view.
    async fn counters(&self, view: &SearchView) -> Result<InstanceCounters>;

    /// Writes back the download totals the rollup job computed, so `sort:downloads` reads one
    /// indexed column instead of an aggregate join on the hot path. Unknown package → no-op.
    async fn set_downloads(&self, package: PackageId, totals: DownloadTotals) -> Result<()>;
}

/// Daily download rollups (docs/architecture.md `download_stats`; see [`crate::stats`]).
///
/// Two contracts:
///
/// 1. **`add_downloads` is additive** per `(package, version, date)`. Every instance flushes
///    its own counts, so a write that *set* the value would make the last flush win and
///    silently discard its peers'.
/// 2. **Reads are bounded aggregates.** Per-package totals are one indexed scan, and the job's
///    write-back onto the search index keeps them off the search path entirely.
#[async_trait]
pub trait StatsRepo: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Folds a batch of deltas into the daily rollup (contract 1). Returns how many rows were
    /// inserted or updated; an empty batch is a no-op.
    async fn add_downloads(&self, deltas: &[DownloadDelta]) -> Result<u64>;

    /// All-time and trailing-window totals for one package (`since` inclusive).
    async fn package_totals(&self, package: PackageId, since: NaiveDate) -> Result<DownloadTotals>;

    /// The same totals for a bounded set of packages — the rollup job's write-back input.
    /// Packages with nothing recorded are omitted.
    async fn totals_for(&self, packages: &[PackageId], since: NaiveDate) -> Result<Vec<PackageDownloads>>;
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

    /// Whether the transport that would run right now is the one the settings document names.
    ///
    /// The diagnostic seam behind `POST /api/v1/admin/settings/smtp/test`. A mailer that
    /// resolves its transport from runtime settings keeps the *previous* transport when a
    /// rebuild fails (decision 09), which means a successful `send` proves only that *some*
    /// endpoint accepted the message — not the one the stored section describes. An action whose
    /// entire purpose is diagnosing SMTP has to be able to tell those apart, or it answers
    /// `delivered: true` for a host it never contacted in exactly the case it exists for.
    ///
    /// Defaulted to `Ok(())`: a transport with nothing to resolve — the SMTP transport itself,
    /// the in-memory outbox, every test double — is always the one in force.
    fn resolution(&self) -> Result<()> {
        Ok(())
    }
}

/// The full set of repository handles, as one cloneable bundle.
///
/// Constructed once at startup by the selected database crate (`SqliteDb::repositories()` /
/// `PostgresDb::repositories()`) and carried in `AppState`; the contract test suite runs
/// against this bundle, so every backend is exercised through the same trait surface.
///
/// [`Repositories::search`] rides along even though decision 11 leaves room for a search
/// implementation that is *not* the database (tantivy, Meilisearch): today both implementations
/// are SQL over the same pool, and bundling them keeps every consumer — the publish pipeline,
/// the read-model routes, the reindex job, the contract suite — on one handle. A future
/// non-SQL implementation replaces this one field after the bundle is built.
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
    /// The durable work queue behind asynchronous fan-out and outbound mail (decision 26).
    pub queue: Arc<dyn JobQueueRepo>,
    /// Package search index and the read model over it (decision 11).
    pub search: Arc<dyn PackageSearch>,
    /// Daily download rollups.
    pub stats: Arc<dyn StatsRepo>,
    /// The notification center's feed and preferences (decision 20).
    pub notifications: Arc<dyn NotificationRepo>,
}

/// Manual, out-of-schedule execution of a background job (`POST /api/v1/admin/jobs/{job}/run`).
///
/// The seam lives in `core` so the API crate can offer the button without depending on the
/// jobs crate, and so a deployment that registered no jobs has a real implementation
/// ([`NoJobs`]) rather than an `Option` every handler has to unwrap.
///
/// Implementations must take the same [`JobLock`] the scheduler uses: a manual run that
/// overlapped a scheduled tick would have two writers on one durable cursor.
#[async_trait]
pub trait JobTrigger: Send + Sync {
    /// The jobs that can be triggered right now, sorted. A job the operator disabled is
    /// **not** listed — the admin UI shows what exists on this instance, not what could.
    fn names(&self) -> Vec<String>;

    /// Runs `name` once, now, and returns the job's own summary document.
    ///
    /// Unknown or disabled job → [`crate::Error::NotFound`]; a run that could not take the
    /// leader lock → [`crate::Error::Conflict`], because "somebody else is already running it"
    /// is a state the operator should see rather than a silent no-op.
    async fn run_now(&self, name: &str, now: DateTime<Utc>) -> Result<serde_json::Value>;
}

/// The trigger for an instance with no registered jobs: nothing to list, nothing to run.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoJobs;

#[async_trait]
impl JobTrigger for NoJobs {
    fn names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn run_now(&self, name: &str, _now: DateTime<Utc>) -> Result<serde_json::Value> {
        Err(crate::Error::NotFound { what: format!("job {name}") })
    }
}

/// Proof of *which* acquisition of a lock a holder is talking about.
///
/// A lock with a TTL is a lock that can be lost while its holder still believes it has it: the
/// TTL expires, somebody else acquires, and then the original holder finishes and releases —
/// freeing a lock it no longer owns and letting a third worker in alongside the second. That is
/// not hypothetical for the queue drain, whose overrun is exactly what decision 26's amendment
/// bounds; the token is the other half of that fix. Opaque and unforgeable by construction: a
/// fresh UUID per acquisition, compared by the implementation and by nobody else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LockToken(uuid::Uuid);

impl LockToken {
    /// Mints a token for one acquisition. Called by [`JobLock`] implementations only.
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }
}

impl Default for LockToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LockToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Leader-election lock guarding single-instance background jobs (PG advisory lock / Redis
/// lock / trivial in-process lock for a single node).
#[async_trait]
pub trait JobLock: Send + Sync {
    /// Cheap connectivity probe used by `/healthz`.
    async fn ping(&self) -> Result<()>;

    /// Tries to acquire the named lock for at most `ttl`; `Some(token)` when this caller now
    /// holds it, `None` when somebody else does. The TTL bounds how long a crashed holder can
    /// block others.
    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<Option<LockToken>>;

    /// Releases the named lock **only if `token` is still the acquisition that holds it**.
    ///
    /// A holder whose TTL expired while it was still working must therefore not be able to
    /// free the lock the next holder took. Releasing a lock that is not held, or that is held
    /// by a later acquisition, is a no-op rather than an error.
    async fn release(&self, name: &str, token: LockToken) -> Result<()>;
}
