//! Unreferenced-blob garbage collection.
//!
//! The registry writes bytes that nothing ends up pointing at, by design:
//!
//! - a hard delete tombstones a version and removes its archive **only** when no live version
//!   shares the content hash (decision 06) — the shared case leaves the blob behind on purpose,
//!   and it becomes collectable later when the last sharer goes;
//! - the publish pipeline stores the archive *before* the version row, so an interrupted
//!   publish leaves an orphan rather than a row pointing at bytes that do not exist
//!   (docs/protocol.md sharp edge 3 makes the second failure unfixable).
//!
//! Abandoned *staged* uploads are not this job's work any more: they live in a namespace of
//! their own, they can be collected by age with no database question at all, and that is why
//! they are swept by [`crate::staging`] on a default install while this job — which deletes
//! bytes somebody may have pinned — stays off until an operator turns it on
//! ([decision 31](../../../../docs/decisions.md)).
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
//! transaction. A backend that cannot report an object's age therefore cannot be swept — and
//! the age is re-read immediately before the delete, because `put` on a content-addressed key
//! is an idempotent overwrite: a republish of identical bytes makes an object young again while
//! this pass is holding a listing that called it old.
//!
//! **How a pass is bounded**, since the alternative was a job that could not be turned on:
//! archive keys are sharded (`pub/ab/<sha>.tar.gz`), so the unit of work is a shard. A pass
//! asks the store which shards exist, sorts them *itself* — `object_store` guarantees nothing
//! about listing order, which is why the cursor cannot be "the last key I saw" — walks from its
//! durable cursor onwards, streams each shard rather than materializing it, and resolves
//! references one batch at a time (two queries per batch, not per object). When the wall-clock
//! budget runs out the cursor names the shard to resume at, so coverage rotates instead of
//! always collecting the head of the key space and never the tail.
//!
//! `dry_run` reports exactly what a real pass would delete without deleting it — including the
//! re-read, so the report cannot promise a deletion the real pass would skip.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use futures::StreamExt as _;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::{BlobObject, BlobStore, Repositories};
use pub_core::{Format, Result};
use tokio::time::Instant;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const BLOB_GC_JOB: &str = "blob-gc";

/// Blob-GC policy (projected from the `[jobs.blob_gc]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcPolicy {
    /// Whether the job runs at all.
    pub enabled: bool,
    /// How often a pass fires.
    pub interval: StdDuration,
    /// Report what would be deleted, delete nothing. The safe first setting.
    pub dry_run: bool,
    /// Objects younger than this are never collected. Must comfortably exceed the publish
    /// transaction window, because the archive is written before the row that references it.
    pub min_age: Duration,
    /// Collectable keys resolved per pair of reference queries.
    ///
    /// The cost model of the whole job: before this existed every object cost two round trips,
    /// which is what kept the collector off on any instance large enough to need it.
    pub batch: u32,
    /// Wall-clock bound on one pass. Checked between shards and between batches, so a pass is
    /// always slightly longer than its budget — which is why the lock TTL doubles it.
    pub budget: StdDuration,
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: StdDuration::from_secs(6 * 3600),
            dry_run: true,
            min_age: Duration::hours(24),
            batch: 256,
            budget: StdDuration::from_secs(300),
        }
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
    /// Objects that were collectable when listed and were **not** deleted, because the re-read
    /// before the delete found them rewritten (a concurrent republish of identical bytes) or
    /// already gone. Steady state is zero.
    pub contested: usize,
    /// Keys — and prefixes — that are not content-addressed archive locations, left strictly
    /// alone. A prefix counted here is one the pass did not walk at all.
    pub unrecognized: usize,
    /// Shards swept to the end in this pass.
    pub shards: usize,
    /// Whether the pass reached the end of the key space. `false` means the budget ran out with
    /// work left, and [`GcReport::cursor`] says where the next one resumes.
    pub converged: bool,
    /// Where the next pass resumes; `None` after a converged pass — the next one starts over.
    pub cursor: Option<String>,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// One key the sweep found collectable, pending its reference check.
struct Candidate {
    key: String,
    sha256: String,
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
    ///
    /// The formats are sorted, and that is load-bearing rather than tidy: the durable cursor is
    /// a `(format, shard)` pair compared as text, so "everything before the cursor is already
    /// done" is only true if passes visit formats in that same order.
    pub fn new(repos: Repositories, blob: Arc<dyn BlobStore>, formats: Vec<Format>, policy: GcPolicy) -> Self {
        let mut formats = formats;
        formats.sort_by_key(|format| format.as_str());
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

    /// Runs one sweep, resuming from the durable cursor.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<GcReport> {
        let state = self.repos.jobs.begin_run(BLOB_GC_JOB, now).await?;
        let started = Instant::now();
        let report = match self.sweep(state.cursor.as_deref(), now, started).await {
            Ok(report) => {
                self.repos.jobs.finish_run(BLOB_GC_JOB, JobOutcome::Success, now).await?;
                report
            }
            Err(err) => {
                // The cursor is left untouched, so the next pass retries from the same shard.
                self.repos.jobs.finish_run(BLOB_GC_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        let progress = JobProgress {
            cursor: report.cursor.clone(),
            phase: phase(&report),
            processed: report.scanned as u64,
            failed: 0,
        };
        self.repos.jobs.checkpoint(BLOB_GC_JOB, &progress, now).await?;

        metrics::counter!("blob_gc_scanned_total").increment(report.scanned as u64);
        metrics::counter!("blob_gc_deleted_total").increment(report.deleted as u64);
        metrics::counter!("blob_gc_bytes_total").increment(report.bytes);
        metrics::counter!("blob_gc_shards_total").increment(report.shards as u64);
        metrics::gauge!("blob_gc_sweep_converged").set(u8::from(report.converged));
        tracing::info!(
            job = BLOB_GC_JOB,
            dry_run = report.dry_run,
            scanned = report.scanned,
            deleted = report.deleted,
            bytes = report.bytes,
            referenced = report.referenced,
            too_young = report.too_young,
            contested = report.contested,
            shards = report.shards,
            converged = report.converged,
            "blob gc pass finished"
        );
        Ok(report)
    }

    async fn sweep(&self, resume: Option<&str>, now: DateTime<Utc>, started: Instant) -> Result<GcReport> {
        let mut report = GcReport { dry_run: self.policy.dry_run, converged: true, ..GcReport::default() };
        let cutoff = now - self.policy.min_age;
        // A cursor this build cannot parse restarts the rotation rather than failing the pass:
        // an unreadable resume point must never be the reason bytes stop being collected.
        let resume = resume.and_then(parse_cursor);

        for format in &self.formats {
            if let Some((from_format, _)) = &resume
                && format.as_str() < from_format.as_str()
            {
                continue;
            }
            let root = format!("{}/", format.as_str());
            for shard in self.shards(&root, &mut report).await? {
                if let Some((from_format, from_shard)) = &resume
                    && format.as_str() == from_format
                    && shard.as_str() < from_shard.as_str()
                {
                    continue;
                }
                if started.elapsed() >= self.policy.budget {
                    report.converged = false;
                    report.cursor = Some(cursor(*format, &shard));
                    return Ok(report);
                }
                if !self.sweep_shard(*format, &root, &shard, cutoff, started, &mut report).await? {
                    // The budget expired inside the shard. Resuming re-lists it, which is
                    // cheaper than it looks — whatever this pass deleted is already gone.
                    report.converged = false;
                    report.cursor = Some(cursor(*format, &shard));
                    return Ok(report);
                }
                report.shards += 1;
            }
        }
        Ok(report)
    }

    /// The shard prefixes under one format root, in the order this job chooses.
    ///
    /// Also the pass's only look at what lives *outside* the shards: an object at the root, or a
    /// prefix that is not a two-hex shard, is reported and left — never walked, never deleted.
    async fn shards(&self, root: &str, report: &mut GcReport) -> Result<Vec<String>> {
        let listing = self.blob.list_prefixes(root).await?;
        for object in &listing.objects {
            report.scanned += 1;
            report.unrecognized += 1;
            tracing::warn!(key = %object.key, "blob gc found an object outside every shard; leaving it alone");
        }

        let mut shards = Vec::with_capacity(listing.prefixes.len());
        for prefix in &listing.prefixes {
            match prefix.strip_prefix(root).and_then(|rest| rest.strip_suffix('/')) {
                Some(shard) if is_shard(shard) => shards.push(shard.to_owned()),
                _ => {
                    report.unrecognized += 1;
                    tracing::warn!(prefix = %prefix, "blob gc found a prefix that is not an archive shard; not walking it");
                }
            }
        }
        // Our order, not the backend's: `object_store` guarantees none, and a cursor over an
        // unordered walk would skip keys permanently rather than late.
        shards.sort();
        Ok(shards)
    }

    /// Streams one shard. `Ok(false)` means the budget expired with the shard unfinished.
    async fn sweep_shard(
        &self,
        format: Format,
        root: &str,
        shard: &str,
        cutoff: DateTime<Utc>,
        started: Instant,
        report: &mut GcReport,
    ) -> Result<bool> {
        let batch_size = self.policy.batch.max(1) as usize;
        let mut batch: Vec<Candidate> = Vec::with_capacity(batch_size);
        let prefix = format!("{root}{shard}/");
        let mut objects = self.blob.list_stream(&prefix);

        while let Some(object) = objects.next().await {
            // Per object, not per batch. A shard whose keys are all too young, or all foreign,
            // never fills a batch — and a budget that is only consulted when a batch flushes is
            // no budget at all on exactly the key space that is expensive to walk.
            if started.elapsed() >= self.policy.budget {
                self.resolve(&mut batch, cutoff, report).await?;
                return Ok(false);
            }
            let object = object?;
            report.scanned += 1;
            let Some(sha256) = archive_sha256(format, &object.key) else {
                // Not a content-addressed archive key. Something else put it here and this
                // job has no idea what references it; leaving it is the only safe answer.
                report.unrecognized += 1;
                tracing::warn!(key = %object.key, "blob gc skipped an unrecognized key");
                continue;
            };
            if !collectable(&object, cutoff) {
                report.too_young += 1;
                continue;
            }
            batch.push(Candidate { key: object.key, sha256 });
            if batch.len() >= batch_size {
                self.resolve(&mut batch, cutoff, report).await?;
            }
        }
        self.resolve(&mut batch, cutoff, report).await?;
        Ok(true)
    }

    /// Decides one batch: two queries, then a delete per key neither register named.
    ///
    /// Both registers stay mandatory — a local publish and a proxied archive can share one
    /// object — but the second is asked only about the hashes the first did not already claim,
    /// so a batch that is entirely referenced costs one query.
    async fn resolve(&self, batch: &mut Vec<Candidate>, cutoff: DateTime<Utc>, report: &mut GcReport) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut hashes: Vec<String> = batch.iter().map(|candidate| candidate.sha256.clone()).collect();
        hashes.sort();
        hashes.dedup();

        let live = self.repos.packages.live_sha256s(&hashes).await?;
        let unclaimed: Vec<String> = hashes.into_iter().filter(|hash| !live.contains(hash)).collect();
        let cached = self.repos.upstream.cached_sha256s(&unclaimed).await?;

        for candidate in batch.drain(..) {
            if live.contains(&candidate.sha256) || cached.contains(&candidate.sha256) {
                report.referenced += 1;
                continue;
            }
            self.collect(&candidate, cutoff, report).await?;
        }
        Ok(())
    }

    async fn collect(&self, candidate: &Candidate, cutoff: DateTime<Utc>, report: &mut GcReport) -> Result<()> {
        // Re-read before deleting. The listing that found this key may be minutes old, and in
        // that window a republish of byte-identical content can have rewritten the object —
        // `put` on a content-addressed key is an idempotent overwrite — and committed the row
        // that references it. The refreshed timestamp is what makes that visible here.
        let Some(current) = self.blob.head(&candidate.key).await? else {
            report.contested += 1;
            return Ok(());
        };
        if !collectable(&current, cutoff) {
            report.contested += 1;
            tracing::info!(key = %candidate.key, "blob gc left a key that was rewritten while the sweep ran");
            return Ok(());
        }

        if self.policy.dry_run {
            tracing::info!(key = %candidate.key, size = current.size, "blob gc (dry run) would delete an unreferenced blob");
        } else {
            self.blob.delete(&candidate.key).await?;
            tracing::info!(key = %candidate.key, size = current.size, "blob gc deleted an unreferenced blob");
        }
        report.deleted += 1;
        report.bytes += current.size;
        Ok(())
    }
}

/// Whether an object is old enough to touch. An object whose age the backend cannot report is
/// never collected: "unknown age" and "old enough" are not the same answer.
fn collectable(object: &BlobObject, cutoff: DateTime<Utc>) -> bool {
    object.last_modified.is_some_and(|modified| modified < cutoff)
}

/// The durable resume point: the `(format, shard)` a pass stopped at.
fn cursor(format: Format, shard: &str) -> String {
    format!("{}:{shard}", format.as_str())
}

/// Reads a cursor back. Anything malformed is `None` — "start over", never an error.
fn parse_cursor(raw: &str) -> Option<(String, String)> {
    let (format, shard) = raw.split_once(':')?;
    if format.is_empty() || !is_shard(shard) {
        return None;
    }
    Some((format.to_owned(), shard.to_owned()))
}

/// The admin surface's **State** column: what happened, and where it resumes.
fn phase(report: &GcReport) -> String {
    let what = if report.dry_run { "dry-run" } else { "swept" };
    match &report.cursor {
        Some(cursor) => format!("{what}, resumes at {cursor}"),
        None => what.to_owned(),
    }
}

/// Whether `name` is an archive shard — the first two hex characters of a content hash.
fn is_shard(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn only_two_hex_characters_name_a_shard() {
        // A prefix this rejects is one the pass will not walk, so the rule has to match exactly
        // what `blob_key` writes — lowercase hex, two characters, nothing else.
        assert!(is_shard("ab"));
        assert!(is_shard("00"));
        assert!(is_shard("9f"));
        for bogus in ["", "a", "abc", "AB", "zz", "a-", "g0", "0 "] {
            assert!(!is_shard(bogus), "{bogus:?} must not be treated as a shard");
        }
    }

    #[test]
    fn the_cursor_round_trips_and_refuses_nonsense() {
        assert_eq!(parse_cursor(&cursor(Format::Pub, "3f")), Some(("pub".to_owned(), "3f".to_owned())));
        // A cursor from another build, a truncated write, or a hand-edited row must restart the
        // rotation rather than fail a pass or, worse, be read as a shard name.
        for bogus in ["", "pub", "pub:", ":3f", "pub:zzz", "pub:ZZ", "pub:3f:extra"] {
            assert_eq!(parse_cursor(bogus), None, "{bogus:?} must not parse");
        }
    }

    #[test]
    fn the_default_policy_is_off_and_dry_run() {
        // Deleting bytes permanently is not something a default should do on somebody's behalf.
        let policy = GcPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.dry_run);
        assert!(policy.min_age >= Duration::hours(2), "the grace period must outlive a publish by a wide margin");
        assert!(policy.batch > 1, "a batch of one is the per-object cost model this job exists to leave");
        assert!(!policy.budget.is_zero(), "an unbounded pass is a lock held for a whole sweep");
    }

    #[test]
    fn the_phase_names_the_resume_point() {
        let converged = GcReport { dry_run: true, converged: true, ..GcReport::default() };
        assert_eq!(phase(&converged), "dry-run");
        let backlog = GcReport { cursor: Some("pub:3f".to_owned()), ..GcReport::default() };
        assert_eq!(phase(&backlog), "swept, resumes at pub:3f");
    }
}
