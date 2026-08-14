//! Abandoned staged uploads: the sweep that runs on a default install
//! ([decision 31](../../../../docs/decisions.md),
//! [S-20.a](../../../../docs/security.md#4-supply-chain--registry-integrity)).
//!
//! Publishing is three steps, and the middle one stores bytes: `newUpload` writes the archive to
//! `uploads/<format>/<session>.tar.gz` and files a KV record that expires in an hour, then
//! `newUploadFinish` picks both up. Every publish that is never finished — a cancelled `dart pub
//! publish`, a client that lost the connection, a rejected archive the client never retried —
//! leaves those bytes behind. They are not referenced by anything, and after the record expires
//! they are not *reachable* by anything either: finalize answers "this upload has expired or was
//! already finalized" and there is no second door.
//!
//! So the sweep's whole test is age, and that is deliberate:
//!
//! - **Not the KV record.** Asking whether the session still exists would couple this job to a
//!   key format owned by the protocol module, and it is the weaker test anyway — a record can
//!   vanish early (an evicted in-memory KV, a Redis restart) while the bytes are still
//!   finalizable. Age answers the question the deletion actually depends on.
//! - **Not a reference check.** Staged keys are named by session, never by content, so no
//!   version row and no cached upstream version can ever point at one. This job asks the
//!   database nothing at all, which is also why it can be on by default while the
//!   unreferenced-archive collector ([`crate::gc`]) stays off: that one deletes bytes a
//!   `pubspec.lock` may pin, and this one deletes bytes nobody can reach.
//!
//! Two rules bound the damage a bug here could do. The key shape is checked strictly — only
//! `uploads/<format>/<32 lowercase hex>.tar.gz` is ever a deletion candidate, everything else
//! under the prefix is reported and left — and the age is re-read immediately before the delete,
//! so an object written between the listing and the collection is skipped rather than removed
//! out from under the client that is still uploading it.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use futures::StreamExt as _;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::{BlobObject, BlobStore, Repositories};
use pub_core::{Format, Result};
use tokio::time::Instant;

/// Job name — also the [`pub_core::traits::JobLock`] key.
pub const STAGING_SWEEP_JOB: &str = "staging-sweep";

/// Blob-key prefix holding staged, not-yet-finalized uploads (`uploads/<format>/<session>`).
const STAGING_PREFIX: &str = "uploads";

/// Length of a session id in hex characters (128 bits, `pub_v2::new_session_id`).
const SESSION_HEX: usize = 32;

/// Staged-upload sweep policy (projected from the `[jobs.staging]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagingPolicy {
    /// Whether the job runs at all. **On by default**: a default install that never collects
    /// abandoned uploads has no bound on them but the publish rate limit.
    pub enabled: bool,
    /// How often a pass fires.
    pub interval: StdDuration,
    /// Report what would be deleted, delete nothing.
    pub dry_run: bool,
    /// Staged objects younger than this are never collected. Must exceed the upload TTL: an
    /// upload is finalizable — and therefore live — for that whole hour with nothing
    /// referencing it.
    pub min_age: Duration,
    /// Wall-clock bound on one pass.
    pub budget: StdDuration,
}

impl Default for StagingPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: StdDuration::from_secs(3600),
            dry_run: false,
            min_age: Duration::hours(2),
            budget: StdDuration::from_secs(60),
        }
    }
}

/// What one [`StagingSweeper::run_once`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StagingReport {
    /// Objects examined.
    pub scanned: usize,
    /// Objects deleted (or, in dry-run mode, that would have been).
    pub deleted: usize,
    /// Bytes reclaimed (or that would have been).
    pub bytes: u64,
    /// Objects kept because they are inside the grace period — an upload that may still be
    /// finalized.
    pub too_young: usize,
    /// Objects that were collectable when listed and were not deleted, because the re-read
    /// found them rewritten or already gone.
    pub contested: usize,
    /// Keys under the staging prefix that are not staged uploads, left strictly alone.
    pub unrecognized: usize,
    /// Whether the pass reached the end of the namespace.
    pub converged: bool,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// The abandoned-staged-upload collector.
pub struct StagingSweeper {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    formats: Vec<Format>,
    policy: StagingPolicy,
}

impl std::fmt::Debug for StagingSweeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingSweeper")
            .field("formats", &self.formats)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl StagingSweeper {
    /// Builds the sweeper over the configured backends.
    pub fn new(repos: Repositories, blob: Arc<dyn BlobStore>, formats: Vec<Format>, policy: StagingPolicy) -> Self {
        Self { repos, blob, formats, policy }
    }

    /// The configured policy.
    pub fn policy(&self) -> &StagingPolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "last staging sweep".
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(STAGING_SWEEP_JOB).await?.unwrap_or_else(|| JobState::fresh(STAGING_SWEEP_JOB, now)))
    }

    /// Runs one sweep over every configured format's staging namespace.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<StagingReport> {
        self.repos.jobs.begin_run(STAGING_SWEEP_JOB, now).await?;
        let started = Instant::now();
        let report = match self.sweep(now, started).await {
            Ok(report) => {
                self.repos.jobs.finish_run(STAGING_SWEEP_JOB, JobOutcome::Success, now).await?;
                report
            }
            Err(err) => {
                self.repos.jobs.finish_run(STAGING_SWEEP_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        // No cursor, unlike the archive collector: everything this pass collects *leaves* the
        // namespace, so a pass that ran out of budget makes the next one's work strictly
        // smaller. There is no tail here that repeated passes could starve.
        let progress = JobProgress { cursor: None, phase: phase(&report), processed: report.scanned as u64, failed: 0 };
        self.repos.jobs.checkpoint(STAGING_SWEEP_JOB, &progress, now).await?;

        metrics::counter!("staging_sweep_scanned_total").increment(report.scanned as u64);
        metrics::counter!("staging_sweep_deleted_total").increment(report.deleted as u64);
        metrics::counter!("staging_sweep_bytes_total").increment(report.bytes);
        tracing::info!(
            job = STAGING_SWEEP_JOB,
            dry_run = report.dry_run,
            scanned = report.scanned,
            deleted = report.deleted,
            bytes = report.bytes,
            too_young = report.too_young,
            contested = report.contested,
            converged = report.converged,
            "staged-upload sweep finished"
        );
        Ok(report)
    }

    async fn sweep(&self, now: DateTime<Utc>, started: Instant) -> Result<StagingReport> {
        let mut report = StagingReport { dry_run: self.policy.dry_run, converged: true, ..StagingReport::default() };
        let cutoff = now - self.policy.min_age;

        for format in &self.formats {
            let prefix = format!("{STAGING_PREFIX}/{}/", format.as_str());
            let mut objects = self.blob.list_stream(&prefix);
            while let Some(object) = objects.next().await {
                // Checked per object rather than per deletion: a staging area full of keys this
                // job does not recognize, or of uploads still inside their grace period, deletes
                // nothing at all — and a budget consulted only after a deletion would let that
                // walk run unbounded under the job's lock.
                if started.elapsed() >= self.policy.budget {
                    report.converged = false;
                    return Ok(report);
                }
                let object = object?;
                report.scanned += 1;
                if !is_staged_upload(&prefix, &object.key) {
                    report.unrecognized += 1;
                    tracing::warn!(key = %object.key, "staging sweep found a key that is not a staged upload; leaving it alone");
                    continue;
                }
                if !collectable(&object, cutoff) {
                    report.too_young += 1;
                    continue;
                }
                self.collect(&object.key, cutoff, &mut report).await?;
            }
        }
        Ok(report)
    }

    async fn collect(&self, key: &str, cutoff: DateTime<Utc>, report: &mut StagingReport) -> Result<()> {
        // Re-read before deleting, for the same reason the archive collector does: the listing
        // is a snapshot, and a session id could in principle be reused by a store that was
        // restored underneath us. A key that is no longer old is a key somebody is using.
        let Some(current) = self.blob.head(key).await? else {
            report.contested += 1;
            return Ok(());
        };
        if !collectable(&current, cutoff) {
            report.contested += 1;
            tracing::info!(key = %key, "staging sweep left a key that was rewritten while the pass ran");
            return Ok(());
        }

        if self.policy.dry_run {
            tracing::info!(key = %key, size = current.size, "staging sweep (dry run) would delete an abandoned upload");
        } else {
            self.blob.delete(key).await?;
            tracing::info!(key = %key, size = current.size, "staging sweep deleted an abandoned upload");
        }
        report.deleted += 1;
        report.bytes += current.size;
        Ok(())
    }
}

/// Whether an object is old enough to touch; an unknown age is never old enough.
fn collectable(object: &BlobObject, cutoff: DateTime<Utc>) -> bool {
    object.last_modified.is_some_and(|modified| modified < cutoff)
}

/// The admin surface's **State** column.
fn phase(report: &StagingReport) -> String {
    let what = if report.dry_run { "dry-run" } else { "swept" };
    if report.converged { what.to_owned() } else { format!("{what}, budget spent") }
}

/// Whether `key` is a staged upload under `prefix` — `<prefix><32 lowercase hex>.tar.gz`.
///
/// As strict as the archive side's key check and for the same reason: this decides what may be
/// deleted. A nested path, a different extension, a session id that is not one this server could
/// have minted — none of them are ours, so none of them are collected.
fn is_staged_upload(prefix: &str, key: &str) -> bool {
    let Some(rest) = key.strip_prefix(prefix) else { return false };
    let Some(session) = rest.strip_suffix(".tar.gz") else { return false };
    session.len() == SESSION_HEX && session.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "uploads/pub/";

    #[test]
    fn only_well_formed_session_keys_are_collectable() {
        let session = "0123456789abcdef0123456789abcdef";
        assert!(is_staged_upload(PREFIX, &format!("{PREFIX}{session}.tar.gz")));

        for bogus in [
            format!("{PREFIX}{session}.zip"),                     // not our extension
            format!("{PREFIX}nested/{session}.tar.gz"),           // an extra path segment
            format!("{PREFIX}{}.tar.gz", &session[..31]),         // too short to be a session id
            format!("{PREFIX}{session}0.tar.gz"),                 // too long
            format!("{PREFIX}{}.tar.gz", session.to_uppercase()), // not the case we mint
            format!("uploads/npm/{session}.tar.gz"),              // another format's namespace
            format!("pub/ab/{session}.tar.gz"),                   // the archive namespace
        ] {
            assert!(!is_staged_upload(PREFIX, &bogus), "{bogus} must not be recognized");
        }
    }

    #[test]
    fn the_default_policy_is_on_and_deletes() {
        // This is the whole point of the job: staged uploads have to be collected on an
        // instance whose operator never read a configuration reference (D22).
        let policy = StagingPolicy::default();
        assert!(policy.enabled);
        assert!(!policy.dry_run);
        // The grace period must outlive the one-hour upload TTL with room for clock skew.
        assert!(policy.min_age > Duration::hours(1));
        assert!(!policy.budget.is_zero());
    }

    #[test]
    fn the_phase_says_whether_the_pass_finished() {
        let done = StagingReport { converged: true, ..StagingReport::default() };
        assert_eq!(phase(&done), "swept");
        let cut = StagingReport { dry_run: true, converged: false, ..StagingReport::default() };
        assert_eq!(phase(&cut), "dry-run, budget spent");
    }
}
