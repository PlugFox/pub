//! The publish pipeline and the version lifecycle services (decisions 01/06, S-18..S-21).
//!
//! One service, three entry points — [`RegistryService::publish`],
//! [`RegistryService::set_retracted`], [`RegistryService::hard_delete`] — each of which owns
//! the *whole* domain step: validation, storage, database, audit event, domain event. No HTTP
//! here; the pub protocol routes call in with an already-authenticated principal.
//!
//! The publish order is not arbitrary:
//!
//! 1. **Cheap size gate** on the compressed upload, before any CPU is spent (S-20).
//! 2. **Hash, validate, parse, render** on a blocking worker — sha256 over the *exact*
//!    uploaded bytes, tar/gzip validation, pubspec parsing, README/CHANGELOG sanitizing.
//! 3. **Per-name lock** ([`JobLock`]) so two concurrent publishes of one package serialize
//!    instead of racing through the read-then-write below. The lock is an optimization for
//!    clean errors; correctness rests on the database's unique indexes, which is why the lock
//!    being unavailable is a conflict, never a bypass.
//! 4. **Duplicate pre-check**, then **blob write**, then **the transactional DB insert**.
//!    Bytes go in before metadata on purpose: an interrupted publish leaves an unreferenced
//!    blob (GC's problem) rather than a version row pointing at bytes that do not exist —
//!    which would be an unfixable 404 on a hash a client has already pinned
//!    (docs/protocol.md sharp edge 3).
//!
//! The uploaded bytes are stored verbatim and are **never re-compressed or re-tarred**: the
//! sha256 in a user's `pubspec.lock` is computed over exactly what they uploaded.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::package::{NewVersion, Package, PackageOptions, Publisher, Version, Visibility};
use pub_core::token::patterns_allow;
use pub_core::traits::{BlobStore, JobLock, Repositories};
use pub_core::{Error, Format, OrgId, Result, SemVer, TokenId, UserId};
use sha2::{Digest as _, Sha256};

use crate::archive::{ArchiveContents, ArchiveError, ArchiveLimits, validate_archive};
use crate::index::PackageIndexer;
use crate::markdown;
use crate::pubspec::Pubspec;

/// Default window in which a retracted version may still be restored (pub.dev's rule).
pub const DEFAULT_UNRETRACT_WINDOW_DAYS: i64 = 7;

/// Default TTL of the per-name publish lock — long enough to cover a slow blob write, short
/// enough that a crashed publisher does not block the name for long.
pub const DEFAULT_PUBLISH_LOCK_TTL_SECS: u64 = 120;

/// Instance policy for the registry services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryPolicy {
    /// Archive ingest limits (S-20).
    pub archive: ArchiveLimits,
    /// How long after retraction a version may be restored (decision 06).
    pub unretract_window: Duration,
    /// TTL of the per-name publish lock.
    pub publish_lock_ttl: StdDuration,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        Self {
            archive: ArchiveLimits::default(),
            unretract_window: Duration::days(DEFAULT_UNRETRACT_WINDOW_DAYS),
            publish_lock_ttl: StdDuration::from_secs(DEFAULT_PUBLISH_LOCK_TTL_SECS),
        }
    }
}

/// Who is acting, and from where (S-21 provenance, S-22 audit context).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorMeta {
    /// The user the action acts as.
    pub user_id: UserId,
    /// The CLI token used, when the action came from the token plane.
    pub token_id: Option<TokenId>,
    /// Client IP as resolved by the API layer (S-24.a — never a raw header).
    pub ip: Option<String>,
    /// Coarse user agent.
    pub user_agent: Option<String>,
}

impl ActorMeta {
    /// Minimal actor: a user with no request context (tests, internal callers).
    pub fn user(user_id: UserId) -> Self {
        Self { user_id, token_id: None, ip: None, user_agent: None }
    }

    /// The audit actor: the token when the action came through the CLI plane, the user
    /// otherwise — the two credential planes stay distinguishable in the log (S-22).
    fn audit_actor(&self) -> AuditActor {
        match self.token_id {
            Some(token) => AuditActor::Token(token),
            None => AuditActor::User(self.user_id),
        }
    }
}

/// A publish request: an org, a principal, and the uploaded bytes.
#[derive(Clone, Debug)]
pub struct PublishRequest {
    /// Artifact format (decision 21).
    pub format: Format,
    /// Publishing org; must own the name claim.
    pub org_id: OrgId,
    /// Visibility applied only if this publish creates the package.
    pub visibility: Visibility,
    /// Publisher.
    pub actor: ActorMeta,
    /// The uploaded archive, byte-for-byte as received.
    pub archive: Bytes,
    /// The package name the upload was authorized for, when the caller pinned one (token
    /// package pattern, upload session). The pubspec must agree with it (S-20).
    pub expected_name: Option<String>,
    /// The presenting token's package-pattern narrowing (S-13); empty = unrestricted.
    ///
    /// Enforced *here*, at finalize, because that is the first moment the package name exists:
    /// step 1 of the publish flow carries no name at all (docs/protocol.md endpoint 2), so a
    /// pattern-scoped token has to be admitted through the door and stopped at the desk.
    pub package_patterns: Vec<String>,
}

/// What a successful publish produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishOutcome {
    /// The package (created by this publish when `package_created`).
    pub package: Package,
    /// The stored version.
    pub version: Version,
    /// Whether the package row and its name claim were created here.
    pub package_created: bool,
    /// Content-addressed blob key holding the archive.
    pub blob_key: String,
}

/// A retraction or restoration request.
#[derive(Clone, Debug)]
pub struct RetractRequest {
    /// Artifact format.
    pub format: Format,
    /// Org the package must belong to.
    pub org_id: OrgId,
    /// Package name.
    pub name: String,
    /// Affected version.
    pub version: SemVer,
    /// `true` = retract, `false` = restore (subject to the restore window).
    pub retracted: bool,
    /// Actor.
    pub actor: ActorMeta,
}

/// A hard-delete request (decision 06: org admin + step-up, enforced by the API layer).
#[derive(Clone, Debug)]
pub struct HardDeleteRequest {
    /// Artifact format.
    pub format: Format,
    /// Org the package must belong to.
    pub org_id: OrgId,
    /// Package name.
    pub name: String,
    /// Version to delete.
    pub version: SemVer,
    /// Why the bytes are being destroyed — recorded in the audit event (S-22).
    ///
    /// Required by the API layer rather than optional here: hard delete is the one operation
    /// that removes something the ecosystem may already depend on, and "who did it" without
    /// "why" is not an answer anybody can act on months later.
    pub reason: Option<String>,
    /// Actor.
    pub actor: ActorMeta,
}

/// A package-transfer request (decision 19 danger zone: Owner of both orgs + step-up,
/// enforced by the API layer).
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// Artifact format.
    pub format: Format,
    /// The org that currently owns the package.
    pub from_org: OrgId,
    /// The org that will own it.
    pub to_org: OrgId,
    /// Package name.
    pub name: String,
    /// Actor.
    pub actor: ActorMeta,
}

/// What a hard delete produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardDeleteOutcome {
    /// The tombstone row; the version number stays burned (S-18).
    pub version: Version,
    /// Whether the archive bytes were removed. `false` means another live version still
    /// references the same content hash, so the blob had to stay.
    pub blob_removed: bool,
}

/// The everything-but-HTTP half of the registry.
pub struct RegistryService {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    lock: Arc<dyn JobLock>,
    events: Arc<dyn EventSink>,
    indexer: PackageIndexer,
    policy: RegistryPolicy,
}

impl std::fmt::Debug for RegistryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryService").field("policy", &self.policy).finish_non_exhaustive()
    }
}

/// Everything the blocking stage produces from the uploaded bytes.
struct Prepared {
    sha256: String,
    size: i64,
    pubspec: Pubspec,
    readme_html: Option<String>,
    changelog_html: Option<String>,
    contents: ArchiveContents,
}

impl RegistryService {
    /// Builds the service over the configured backends.
    pub fn new(
        repos: Repositories,
        blob: Arc<dyn BlobStore>,
        lock: Arc<dyn JobLock>,
        events: Arc<dyn EventSink>,
        policy: RegistryPolicy,
    ) -> Self {
        let indexer = PackageIndexer::new(repos.clone());
        Self { repos, blob, lock, events, indexer, policy }
    }

    /// The active policy (limits surfaced by the protocol layer, e.g. upload size checks).
    pub fn policy(&self) -> &RegistryPolicy {
        &self.policy
    }

    /// Content-addressed blob key: `<format>/<sha[0..2]>/<sha>.tar.gz`.
    ///
    /// The two-character shard keeps directory fan-out sane on filesystem backends; the format
    /// prefix keeps future formats from sharing a namespace even though the hash alone would
    /// already be unique.
    pub fn blob_key(format: Format, sha256: &str) -> String {
        let shard = &sha256[..2.min(sha256.len())];
        format!("{}/{shard}/{sha256}.tar.gz", format.as_str())
    }

    /// Publishes a version (see the module docs for the ordering and why).
    pub async fn publish(&self, request: PublishRequest, now: DateTime<Utc>) -> Result<PublishOutcome> {
        let actor = request.actor.clone();
        let org = request.org_id;
        // Before the pubspec is parsed the only name we have is the one the caller pinned —
        // and the pub protocol pins none (step 1 carries no name). So the pipeline reports the
        // name back as soon as it learns it: a rejected-publish audit trail with an empty
        // target tells an operator that *something* was refused and nothing more (S-22).
        let target = request.expected_name.clone();
        let mut observed: Option<String> = None;
        match self.publish_inner(request, now, &mut observed).await {
            Ok(outcome) => Ok(outcome),
            Err(err) => {
                let target = observed.or(target);
                // Failed publishes are audited too (S-22): a stream of rejected uploads is
                // exactly the signal an operator wants, and the reason lives in the log
                // rather than only in the CLI's error message.
                self.audit(
                    &actor,
                    Some(org),
                    "package.publish",
                    target,
                    AuditResult::Failure,
                    serde_json::json!({ "error": err.code(), "reason": err.to_string() }),
                    now,
                )
                .await;
                Err(err)
            }
        }
    }

    async fn publish_inner(
        &self,
        request: PublishRequest,
        now: DateTime<Utc>,
        observed: &mut Option<String>,
    ) -> Result<PublishOutcome> {
        // 1. Cheap gate first: no CPU is spent on an upload that is already too big (S-20).
        let size = request.archive.len() as u64;
        if size > self.policy.archive.max_archive_bytes {
            return Err(ArchiveError::ArchiveTooLarge { size, limit: self.policy.archive.max_archive_bytes }.into());
        }

        // 2. Hashing, decompression, parsing, and markdown rendering are CPU-bound
        // (docs/rules/rust.md: off the async worker).
        let prepared = self.prepare(request.archive.clone()).await?;
        // From here on every rejection can name what was rejected.
        *observed = Some(format!("{}@{}", prepared.pubspec.name, prepared.pubspec.version));
        if let Some(expected) = &request.expected_name {
            prepared.pubspec.require_name(expected)?;
        }
        // S-13 narrowing, checked before the lock, the blob write, and the claim: a token
        // scoped to `acme_*` must not be able to create a claim on `evil_pkg`.
        if !patterns_allow(&request.package_patterns, &prepared.pubspec.name) {
            return Err(Error::Forbidden {
                message: format!(
                    "this token is limited to package patterns [{}] and may not publish {:?}",
                    request.package_patterns.join(", "),
                    prepared.pubspec.name
                ),
            });
        }
        let name = prepared.pubspec.name.clone();
        let version = prepared.pubspec.version.clone();

        // 3. Per-name lock: concurrent publishes of one package serialize here. `Busy`, not
        // `Conflict`: the holder may be this very client's timed-out first attempt, so the
        // failure is transient and the API layer must be able to keep the staged upload
        // finalizable instead of burning it (a duplicate version, by contrast, is permanent).
        let lock_key = format!("publish:{}:{name}", request.format);
        let Some(token) = self.lock.try_acquire(&lock_key, self.policy.publish_lock_ttl).await? else {
            return Err(Error::Busy { message: format!("another publish of {name} is already in progress") });
        };
        let result = self.publish_locked(&request, prepared, now).await;
        // With the token: a publish that outlived its TTL must not free the lock the publish
        // that replaced it is holding.
        if let Err(err) = self.lock.release(&lock_key, token).await {
            // A leaked lock expires on its own TTL; failing the publish over it would be worse.
            tracing::warn!(package = %name, version = %version, error = %err, "failed to release publish lock");
        }
        result
    }

    /// The critical section: duplicate pre-check → blob write → transactional insert.
    async fn publish_locked(
        &self,
        request: &PublishRequest,
        prepared: Prepared,
        now: DateTime<Utc>,
    ) -> Result<PublishOutcome> {
        let name = &prepared.pubspec.name;
        let version = &prepared.pubspec.version;

        // Pre-check so the common "already published" case does not write a blob first. The
        // database's unique index (which covers tombstones) remains the actual guarantee.
        if let Some(package) = self.repos.packages.get_by_name(request.format, name).await? {
            // **Ownership is decided before existence.** `create_version` would refuse a
            // foreign claim anyway, but answering "version 1.0.0 already exists" first tells a
            // caller who does not own the name which versions of somebody else's — possibly
            // private — package exist (S-04). The wording is the claim path's, so both routes
            // to this denial say the same thing and neither names the holder (decision 01).
            if package.org_id != request.org_id {
                return Err(Error::Forbidden {
                    message: format!("package name {name:?} is claimed by another organization"),
                });
            }
            if self.repos.packages.get_version(package.id, version).await?.is_some() {
                return Err(Error::Conflict { message: format!("version {version} of {name} already exists") });
            }
        }

        let blob_key = Self::blob_key(request.format, &prepared.sha256);
        // The exact uploaded bytes, never re-compressed (docs/protocol.md sharp edge 3).
        self.blob.put(&blob_key, request.archive.clone()).await?;

        let published = self
            .repos
            .packages
            .create_version(
                NewVersion {
                    format: request.format,
                    package_name: name.clone(),
                    org_id: request.org_id,
                    visibility: request.visibility,
                    version: version.clone(),
                    pubspec: prepared.pubspec.json.clone(),
                    archive_sha256: prepared.sha256.clone(),
                    archive_size: prepared.size,
                    published_by: Publisher { user_id: request.actor.user_id, token_id: request.actor.token_id },
                    readme_html: prepared.readme_html.clone(),
                    changelog_html: prepared.changelog_html.clone(),
                },
                now,
            )
            .await?;

        self.audit(
            &request.actor,
            Some(request.org_id),
            "package.publish",
            Some(format!("{name}@{version}")),
            AuditResult::Success,
            serde_json::json!({
                "format": request.format.as_str(),
                "package": name,
                "version": version.to_string(),
                "sha256": prepared.sha256,
                "size": prepared.size,
                "entries": prepared.contents.entries,
                "uncompressed_size": prepared.contents.uncompressed_bytes,
                "package_created": published.package_created,
            }),
            now,
        )
        .await;

        // Catalogued since the observability plane was designed and emitted nowhere until now
        // (decision 28). Here, after the bytes and the row are durable: a counter that includes
        // publishes that failed halfway is not a count of publishes.
        metrics::counter!("publishes_total", "format" => request.format.as_str()).increment(1);

        self.events
            .emit(DomainEvent::PackagePublished {
                format: request.format,
                org_id: request.org_id,
                package_id: published.package.id,
                name: name.clone(),
                version: version.to_string(),
                version_id: published.version.id,
                package_created: published.package_created,
                at: now,
            })
            .await;

        // S-17: the name became locally claimed just now. If we already proxy a package under
        // it, the shadowing condition exists from this moment — and the publish path is the
        // only place that arrival order can be seen, because the read path never asks upstream
        // about a claimed name (S-16). One indexed read on a first publish; nothing at all on
        // every subsequent version.
        if published.package_created {
            self.observe_shadowing(request.format, name, now).await;
        }

        self.reindex(&published.package).await;

        Ok(PublishOutcome {
            package: published.package,
            version: published.version,
            package_created: published.package_created,
            blob_key,
        })
    }

    /// Rebuilds the package's search document after a lifecycle change (decision 11).
    ///
    /// **Best-effort, deliberately.** The index is a projection of `packages` + `versions`
    /// (see [`crate::index`]), so a failure here costs discoverability until the reindex job
    /// runs — while propagating it would fail a publish whose bytes, row, and audit record are
    /// already committed, and there is nothing to roll back to. Loud in the log instead.
    async fn reindex(&self, package: &Package) {
        if let Err(err) = self.indexer.refresh(package).await {
            tracing::error!(package = %package.name, error = %err, "search index update failed");
        }
    }

    /// Raises an S-17 alarm when the freshly claimed name is one the proxy already caches.
    ///
    /// Best-effort by construction: the publish has already committed, the local package
    /// already wins, and failing a successful publish because an alarm could not be filed
    /// would be the wrong trade. Failures are loud in the log instead.
    async fn observe_shadowing(&self, format: Format, name: &str, now: DateTime<Utc>) {
        let snapshot = match self.repos.upstream.get_package(format, name).await {
            Ok(Some(snapshot)) => snapshot,
            // No upstream snapshot: nothing has been observed upstream under this name, so
            // there is nothing to alarm about yet. The mirror worker covers the other order.
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(package = name, error = %err, "shadowing check could not read the upstream cache");
                return;
            }
        };
        let upstream_version = match self.repos.upstream.list_versions(snapshot.id).await {
            // `list_versions` is ascending by semver precedence, so the tail is the highest.
            Ok(versions) => versions.last().map(|version| version.version.to_string()),
            Err(err) => {
                tracing::warn!(package = name, error = %err, "shadowing check could not read upstream versions");
                None
            }
        };
        let observation =
            crate::shadow::ShadowObservation { format, name, upstream: &snapshot.upstream, upstream_version };
        if let Err(err) = crate::shadow::observe(&self.repos, self.events.as_ref(), observation, now).await {
            tracing::error!(package = name, error = %err, "failed to record a shadowing alarm");
        }
    }

    /// Hash + validate + parse + render, on a blocking worker.
    async fn prepare(&self, archive: Bytes) -> Result<Prepared> {
        let limits = self.policy.archive;
        tokio::task::spawn_blocking(move || {
            let sha256 = hex_sha256(&archive);
            let contents = validate_archive(&archive, &limits)?;
            let pubspec = Pubspec::parse(&contents.pubspec.content)?;
            let readme_html = contents.readme.as_ref().and_then(|file| markdown::render(&file.content));
            let changelog_html = contents.changelog.as_ref().and_then(|file| markdown::render(&file.content));
            Ok::<_, Error>(Prepared {
                sha256,
                size: archive.len() as i64,
                pubspec,
                readme_html,
                changelog_html,
                contents,
            })
        })
        .await
        .map_err(|err| Error::Internal { message: format!("archive validation task failed: {err}") })?
    }

    /// Retracts or restores a version (decision 06).
    ///
    /// Retraction is always allowed; **restoring** is only allowed inside
    /// [`RegistryPolicy::unretract_window`] — the flag is a resolution-visibility signal that
    /// downstream caches and lockfiles react to, so flipping it back long afterwards would
    /// resurrect a version people have already routed around.
    pub async fn set_retracted(&self, request: RetractRequest, now: DateTime<Utc>) -> Result<Version> {
        let package = self.owned_package(request.format, &request.name, request.org_id).await?;
        let current = self
            .repos
            .packages
            .get_version(package.id, &request.version)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("version {} of {}", request.version, request.name) })?;

        if !request.retracted {
            let retracted_at = current
                .retracted_at
                .ok_or_else(|| Error::Conflict { message: format!("version {} is not retracted", request.version) })?;
            if now - retracted_at > self.policy.unretract_window {
                return Err(Error::Conflict {
                    message: format!(
                        "version {} can no longer be restored: the {}-day window has passed",
                        request.version,
                        self.policy.unretract_window.num_days()
                    ),
                });
            }
        }

        let version = self.repos.packages.set_retracted(current.id, request.retracted, now).await?;

        self.audit(
            &request.actor,
            Some(request.org_id),
            "package.retract",
            Some(format!("{}@{}", request.name, request.version)),
            AuditResult::Success,
            serde_json::json!({
                "format": request.format.as_str(),
                "package": request.name,
                "version": request.version.to_string(),
                "retracted": request.retracted,
            }),
            now,
        )
        .await;

        self.events
            .emit(DomainEvent::PackageRetracted {
                format: request.format,
                org_id: request.org_id,
                package_id: package.id,
                name: request.name.clone(),
                version: request.version.to_string(),
                version_id: version.id,
                retracted: request.retracted,
                at: now,
            })
            .await;

        // Retraction moves `latest` and flips `is:retracted-latest`, so the document has to be
        // rebuilt even though no version was added or removed.
        self.reindex(&package).await;

        Ok(version)
    }

    /// Replaces a package's mutable options (visibility, discontinued/replaced-by, unlisted)
    /// and rebuilds its search document.
    ///
    /// The index refresh is the reason this is a service method rather than a repository call
    /// from a handler: all four flags are *search* facets — flipping a package to private has
    /// to remove it from everybody else's results in the same breath, and an admin UI that
    /// wrote the row directly would leave the index advertising it.
    ///
    /// Authorization (org Admin — decision 19) belongs to the API layer; ownership is checked
    /// here, and a package owned elsewhere is `NotFound`, never `Forbidden` (S-04).
    pub async fn set_options(
        &self,
        format: Format,
        org: OrgId,
        name: &str,
        options: &PackageOptions,
        actor: &ActorMeta,
        now: DateTime<Utc>,
    ) -> Result<Package> {
        let current = self.owned_package(format, name, org).await?;
        let before = PackageOptions::from(&current);
        let package = self.repos.packages.set_options(current.id, options, now).await?;

        self.audit(
            actor,
            Some(org),
            "package.options",
            Some(name.to_owned()),
            AuditResult::Success,
            serde_json::json!({
                "format": format.as_str(),
                "package": name,
                "before": before,
                "after": options,
            }),
            now,
        )
        .await;

        self.events
            .emit(DomainEvent::PackageOptionsChanged {
                format,
                org_id: org,
                package_id: package.id,
                name: name.to_owned(),
                visibility: package.visibility.as_str().to_owned(),
                discontinued: package.discontinued,
                unlisted: package.unlisted,
                at: now,
            })
            .await;

        self.reindex(&package).await;
        Ok(package)
    }

    /// Hard-deletes a version: tombstone the row, then remove the bytes **iff** no live
    /// version still references them (decision 06, S-18).
    ///
    /// Authorization (org admin + step-up, S-06) belongs to the API layer; what belongs here
    /// is the content-addressing hazard: several versions — even in different packages — can
    /// share one blob when their uploads are byte-identical, and erasing shared bytes would
    /// break a hash somebody has pinned.
    pub async fn hard_delete(&self, request: HardDeleteRequest, now: DateTime<Utc>) -> Result<HardDeleteOutcome> {
        let package = self.owned_package(request.format, &request.name, request.org_id).await?;
        let current = self
            .repos
            .packages
            .get_version(package.id, &request.version)
            .await?
            .ok_or_else(|| Error::NotFound { what: format!("version {} of {}", request.version, request.name) })?;

        let tombstone = self.repos.packages.hard_delete_version(current.id).await?;

        let still_referenced = self.repos.packages.count_versions_with_sha256(&tombstone.archive_sha256).await? > 0;
        let blob_removed = if still_referenced {
            tracing::info!(
                package = %request.name,
                version = %request.version,
                "archive bytes kept: another live version shares the content hash"
            );
            false
        } else {
            self.blob.delete(&Self::blob_key(request.format, &tombstone.archive_sha256)).await?;
            true
        };

        self.audit(
            &request.actor,
            Some(request.org_id),
            "package.hard_delete",
            Some(format!("{}@{}", request.name, request.version)),
            AuditResult::Success,
            serde_json::json!({
                "format": request.format.as_str(),
                "package": request.name,
                "version": request.version.to_string(),
                "sha256": tombstone.archive_sha256,
                "blob_removed": blob_removed,
                "reason": request.reason,
            }),
            now,
        )
        .await;

        self.events
            .emit(DomainEvent::PackageVersionDeleted {
                format: request.format,
                org_id: request.org_id,
                package_id: package.id,
                name: request.name.clone(),
                version: request.version.to_string(),
                version_id: tombstone.id,
                blob_removed,
                at: now,
            })
            .await;

        // A hard delete can remove the last live version, in which case the document goes away
        // entirely — `refresh` handles both cases.
        self.reindex(&package).await;

        Ok(HardDeleteOutcome { version: tombstone, blob_removed })
    }

    /// Moves a package (and its name claim) to another org.
    ///
    /// Authorization — Owner in **both** orgs plus step-up (S-06) — belongs to the API layer.
    /// What belongs here is everything that has to move with the row: the claim (so the new
    /// owner can publish the name and the S-17 alarm pages the right admins) and the search
    /// document (whose `org` field is a filter dimension and a facet bucket).
    ///
    /// The package keeps its visibility. Flipping a private package public because it changed
    /// hands, or public private, would be a disclosure decision made by a side effect.
    pub async fn transfer(&self, request: TransferRequest, now: DateTime<Utc>) -> Result<Package> {
        let current = self.owned_package(request.format, &request.name, request.from_org).await?;
        if request.from_org == request.to_org {
            return Err(Error::Invalid { message: "the package already belongs to that organization".to_owned() });
        }
        let package = self.repos.packages.transfer(current.id, request.to_org, now).await?;

        self.audit(
            &request.actor,
            Some(request.from_org),
            "package.transfer",
            Some(request.name.clone()),
            AuditResult::Success,
            serde_json::json!({
                "format": request.format.as_str(),
                "package": request.name,
                "from_org": request.from_org.to_string(),
                "to_org": request.to_org.to_string(),
            }),
            now,
        )
        .await;

        self.events
            .emit(DomainEvent::PackageTransferred {
                format: request.format,
                from_org_id: request.from_org,
                to_org_id: request.to_org,
                package_id: package.id,
                name: request.name.clone(),
                at: now,
            })
            .await;

        self.reindex(&package).await;
        Ok(package)
    }

    /// Loads a package and asserts it belongs to `org`.
    ///
    /// A package owned by somebody else is [`Error::NotFound`], not `Forbidden`: the caller
    /// may not learn that the name exists elsewhere (S-04 anti-enumeration, decision 05).
    async fn owned_package(&self, format: Format, name: &str, org: OrgId) -> Result<Package> {
        let package = self
            .repos
            .packages
            .get_by_name(format, name)
            .await?
            .filter(|package| package.org_id == org)
            .ok_or_else(|| Error::NotFound { what: format!("package {name}") })?;
        Ok(package)
    }

    /// Appends an audit event. Failures are logged, never propagated — an audit outage must
    /// not take publishing down with it (same stance as the auth flows).
    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        actor: &ActorMeta,
        org: Option<OrgId>,
        action: &str,
        target: Option<String>,
        result: AuditResult,
        metadata: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        let event = NewAuditEvent {
            actor: actor.audit_actor(),
            ip: actor.ip.clone(),
            user_agent: actor.user_agent.clone(),
            org_id: org,
            action: action.to_owned(),
            target,
            result,
            metadata: Some(metadata),
        };
        if let Err(err) = self.repos.audit.append(event, now).await {
            tracing::error!(action, error = %err, "audit append failed");
        }
    }
}

/// Lowercase hex SHA-256 — the form stored on the version row and served in listings
/// (docs/protocol.md sharp edge 10: exactly 64 hex characters).
pub fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    digest.iter().fold(String::with_capacity(64), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_64_lowercase_hex_chars() {
        let hash = hex_sha256(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn blob_key_is_content_addressed_and_sharded() {
        let sha = "ab".to_owned() + &"c".repeat(62);
        assert_eq!(RegistryService::blob_key(Format::Pub, &sha), format!("pub/ab/{sha}.tar.gz"));
    }

    #[test]
    fn default_policy_matches_the_documented_defaults() {
        let policy = RegistryPolicy::default();
        assert_eq!(policy.archive.max_archive_bytes, 100 * 1024 * 1024);
        assert_eq!(policy.unretract_window, Duration::days(7));
    }

    #[test]
    fn audit_actor_prefers_the_token_plane() {
        let user = UserId::new();
        let token = TokenId::new();
        assert_eq!(ActorMeta::user(user).audit_actor(), AuditActor::User(user));
        let with_token = ActorMeta { token_id: Some(token), ..ActorMeta::user(user) };
        assert_eq!(with_token.audit_actor(), AuditActor::Token(token));
    }
}
