//! Unreferenced-blob garbage collection.
//!
//! The registry writes bytes that nothing ends up pointing at, by design:
//!
//! - a hard delete tombstones a version and removes its archive **only** when no live version
//!   shares the content hash (decision 06) — the shared case leaves the blob behind on purpose,
//!   and it becomes collectable later when the last sharer goes;
//! - the publish pipeline stores the archive *before* the version row, so an interrupted
//!   publish leaves an orphan rather than a row pointing at bytes that do not exist
//!   (docs/protocol.md sharp edge 3 makes the second failure unfixable);
//! - a staged upload that is never finalized keeps its bytes after its KV record expires
//!   ([S-20.a](../../../docs/security.md#4-supply-chain--registry-integrity)).
//!
//! What makes this job safe is the rule it must not get wrong: **content addressing means a
//! blob can be referenced by things that never met each other.** Two byte-identical uploads in
//! different orgs share one object, and so does a proxied upstream archive that happens to
//! match. So a key is collectable only when *both* registers agree nothing live points at it —
//! `versions` (tombstones excluded, which is exactly "live") and cached `upstream_versions`.
//! Deleting bytes on a partial check would break a hash somebody already pinned in a
//! `pubspec.lock`, which is the one failure this system cannot repair (S-18).
//!
//! The second safety rule is the grace period. An object younger than `min_age` is never
//! touched, because "unreferenced" is the normal state of a blob for the width of the publish
//! transaction — and because a staged upload is finalizable for an hour after it is written.
//! A backend that cannot report an object's age therefore cannot be swept at all.
//!
//! `dry_run` reports exactly what a real pass would delete without deleting it: this job
//! removes bytes permanently, so the first thing an operator wants is to see the list.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::{BlobObject, BlobStore, Repositories};
use pub_core::{Format, Result};

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const BLOB_GC_JOB: &str = "blob-gc";

/// Blob-key prefix holding staged, not-yet-finalized uploads (`uploads/<format>/<session>`).
const STAGING_PREFIX: &str = "uploads/";

/// Blob-GC policy (projected from the `[jobs.blob_gc]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcPolicy {
    /// Whether the job runs at all.
    pub enabled: bool,
    /// How often a pass fires.
    pub interval: StdDuration,
    /// Report what would be deleted, delete nothing. The safe first setting.
    pub dry_run: bool,
    /// Objects younger than this are never collected. Must comfortably exceed both the publish
    /// transaction window and the staged-upload TTL (1 hour), because an upload is finalizable
    /// — and its bytes therefore *live* — for that whole hour without any row referencing them.
    pub min_age: Duration,
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self { enabled: false, interval: StdDuration::from_secs(6 * 3600), dry_run: true, min_age: Duration::hours(24) }
    }
}

/// What one [`BlobGc::run_once`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Objects examined.
    pub scanned: usize,
    /// Objects deleted (or, in dry-run mode, that would have been).
    pub deleted: usize,
    /// Bytes reclaimed (or that would have been).
    pub bytes: u64,
    /// Objects kept because a live version or a cached upstream version still references them.
    pub referenced: usize,
    /// Objects kept because they are inside the grace period.
    pub too_young: usize,
    /// Abandoned staged uploads deleted (counted in `deleted` too).
    pub staged: usize,
    /// Keys that are not content-addressed archive keys — left strictly alone.
    pub unrecognized: usize,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// Unreferenced-blob garbage collector.
pub struct BlobGc {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    formats: Vec<Format>,
    policy: GcPolicy,
}

impl std::fmt::Debug for BlobGc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobGc").field("formats", &self.formats).field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl BlobGc {
    /// Builds the collector over the configured backends.
    pub fn new(repos: Repositories, blob: Arc<dyn BlobStore>, formats: Vec<Format>, policy: GcPolicy) -> Self {
        Self { repos, blob, formats, policy }
    }

    /// The configured policy.
    pub fn policy(&self) -> &GcPolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last GC" (never-run jobs included).
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(BLOB_GC_JOB).await?.unwrap_or_else(|| JobState::fresh(BLOB_GC_JOB, now)))
    }

    /// Runs one sweep over every configured format's key space plus the staging area.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<GcReport> {
        self.repos.jobs.begin_run(BLOB_GC_JOB, now).await?;
        let outcome = self.sweep(now).await;
        let report = match outcome {
            Ok(report) => {
                self.repos.jobs.finish_run(BLOB_GC_JOB, JobOutcome::Success, now).await?;
                report
            }
            Err(err) => {
                self.repos.jobs.finish_run(BLOB_GC_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        let progress = JobProgress {
            cursor: None,
            phase: if report.dry_run { "dry-run".to_owned() } else { "sweep".to_owned() },
            processed: report.scanned as u64,
            failed: 0,
        };
        self.repos.jobs.checkpoint(BLOB_GC_JOB, &progress, now).await?;

        metrics::counter!("blob_gc_scanned_total").increment(report.scanned as u64);
        metrics::counter!("blob_gc_deleted_total").increment(report.deleted as u64);
        metrics::counter!("blob_gc_bytes_total").increment(report.bytes);
        tracing::info!(
            job = BLOB_GC_JOB,
            dry_run = report.dry_run,
            scanned = report.scanned,
            deleted = report.deleted,
            bytes = report.bytes,
            referenced = report.referenced,
            too_young = report.too_young,
            staged = report.staged,
            "blob gc pass finished"
        );
        Ok(report)
    }

    async fn sweep(&self, now: DateTime<Utc>) -> Result<GcReport> {
        let mut report = GcReport { dry_run: self.policy.dry_run, ..GcReport::default() };
        let cutoff = now - self.policy.min_age;

        for format in &self.formats {
            let prefix = format!("{}/", format.as_str());
            for object in self.blob.list(&prefix).await? {
                report.scanned += 1;
                let Some(sha256) = archive_sha256(*format, &object.key) else {
                    // Not a content-addressed archive key. Something else put it here and this
                    // job has no idea what references it; leaving it is the only safe answer.
                    report.unrecognized += 1;
                    tracing::warn!(key = %object.key, "blob gc skipped an unrecognized key");
                    continue;
                };
                if self.is_referenced(&sha256).await? {
                    report.referenced += 1;
                    continue;
                }
                if !self.collectable(&object, cutoff) {
                    report.too_young += 1;
                    continue;
                }
                self.collect(&object, &mut report).await?;
            }
        }

        // Staged uploads are keyed by session, not by content, so the reference check above
        // cannot apply: their liveness is the KV record, which expires an hour after the
        // upload. The grace period (documented as ≫ that TTL) is therefore the whole test —
        // a staged blob older than it can no longer be finalized by anybody.
        for object in self.blob.list(STAGING_PREFIX).await? {
            report.scanned += 1;
            if !self.collectable(&object, cutoff) {
                report.too_young += 1;
                continue;
            }
            report.staged += 1;
            self.collect(&object, &mut report).await?;
        }

        Ok(report)
    }

    /// Whether anything live still points at this content hash — **both** registers, because
    /// content addressing lets a local publish and a proxied upstream archive share one object.
    async fn is_referenced(&self, sha256: &str) -> Result<bool> {
        if self.repos.packages.count_versions_with_sha256(sha256).await? > 0 {
            return Ok(true);
        }
        Ok(self.repos.upstream.count_cached_with_sha256(sha256).await? > 0)
    }

    /// Whether an object is old enough to touch. An object whose age the backend cannot report
    /// is never collected: "unknown age" and "old enough" are not the same answer.
    fn collectable(&self, object: &BlobObject, cutoff: DateTime<Utc>) -> bool {
        object.last_modified.is_some_and(|modified| modified < cutoff)
    }

    async fn collect(&self, object: &BlobObject, report: &mut GcReport) -> Result<()> {
        if self.policy.dry_run {
            tracing::info!(key = %object.key, size = object.size, "blob gc (dry run) would delete an unreferenced blob");
        } else {
            self.blob.delete(&object.key).await?;
            tracing::info!(key = %object.key, size = object.size, "blob gc deleted an unreferenced blob");
        }
        report.deleted += 1;
        report.bytes += object.size;
        Ok(())
    }
}

/// Extracts the content hash from `<format>/<shard>/<sha256>.tar.gz`, or `None` when the key is
/// not one of ours.
///
/// Strict on purpose: this function decides what may be deleted, so anything it does not fully
/// recognize — a wrong shard, a short hash, an unexpected extension, an extra path segment —
/// is left alone rather than guessed at.
fn archive_sha256(format: Format, key: &str) -> Option<String> {
    let rest = key.strip_prefix(&format!("{}/", format.as_str()))?;
    let (shard, file) = rest.split_once('/')?;
    let sha256 = file.strip_suffix(".tar.gz")?;
    if !pub_registry::upstream::is_sha256_hex(sha256) || shard.len() != 2 || !sha256.starts_with(shard) {
        return None;
    }
    Some(sha256.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_well_formed_content_addressed_keys_are_collectable() {
        let sha = format!("ab{}", "c".repeat(62));
        assert_eq!(archive_sha256(Format::Pub, &format!("pub/ab/{sha}.tar.gz")), Some(sha.clone()));

        for bogus in [
            format!("pub/ab/{sha}.zip"),           // not our extension
            format!("pub/zz/{sha}.tar.gz"),        // shard disagrees with the hash
            format!("pub/ab/nested/{sha}.tar.gz"), // an extra path segment
            "pub/ab/short.tar.gz".to_owned(),      // not a sha256
            format!("npm/ab/{sha}.tar.gz"),        // another format's key space
            format!("uploads/pub/{sha}.tar.gz"),   // the staging namespace
        ] {
            assert_eq!(archive_sha256(Format::Pub, &bogus), None, "{bogus} must not be recognized");
        }
    }

    #[test]
    fn the_default_policy_is_off_and_dry_run() {
        // Deleting bytes permanently is not something a default should do on somebody's behalf.
        let policy = GcPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.dry_run);
        // The grace period must outlive the staged-upload TTL (1 hour) by a wide margin.
        assert!(policy.min_age >= Duration::hours(2));
    }
}
