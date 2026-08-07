//! Mirror sync — decision 07's second half.
//!
//! Mirror mode is **read-through warmed by a worker**, not a second implementation. Everything
//! this file does to a package goes through [`UpstreamService::refresh`], which is the same
//! pipeline a cache miss takes: same pubspec validator (S-20), same hash-before-store rule
//! (S-19), same byte-drift freeze, same snapshot writer, same circuit breaker, same
//! per-upstream semaphore, same single-flight guard. What the worker adds is *when*.
//!
//! ```text
//!   mode = full                                   mode = recent
//!   ───────────                                   ─────────────
//!   phase "sweep"                                 phase "recent"
//!   /api/package-names, page by page              upstream_packages ORDER BY fetched_at
//!         │  cursor = {page, offset}                     │  (refreshing moves a package to
//!         ▼  ← survives a restart                        ▼   the back: no cursor needed)
//!   chunk of N names, `concurrency` in flight ────┴─► UpstreamService::refresh
//!         │                                                     │
//!    claimed here? ──yes──► S-17 alarm, never mirrored     ingest pipeline
//!         │no                                                   │
//!    refresh (+ archives when configured) ◄────────────────────┘
//!         │
//!   page exhausted ─► next page ─► …no next page ─► phase "recent" forever after
//! ```
//!
//! Three properties are load-bearing:
//!
//! - **A restart resumes.** The sweep cursor is durable (`jobs.cursor`), so a pod rescheduled
//!   30 000 names into pub.dev's index continues at 30 000 rather than at zero. The in-process
//!   page cache is an optimization on top; losing it costs one index fetch, never progress.
//! - **Every pass is idempotent.** `refresh` takes a freshness floor and answers
//!   [`RefreshOutcome::Fresh`] without asking upstream, so re-walking names an interrupted run
//!   already covered costs one indexed read each.
//! - **A claimed name is observed, never mirrored** (S-16/S-17). Finding one on the sweep is
//!   the *only* way this instance can notice upstream shadowing, because the read path
//!   structurally never asks upstream about a claimed name — and caching it would be storing
//!   bytes resolution can never serve.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use futures::StreamExt as _;
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::Repositories;
use pub_core::{Format, Result};
use pub_registry::{RefreshOutcome, UpstreamService};
use serde::{Deserialize, Serialize};

/// Job name — also the [`pub_core::traits::JobLock`] key, so exactly one instance sweeps.
pub const MIRROR_JOB: &str = "mirror-sync";

/// Phase while the initial full enumeration is still running.
const PHASE_SWEEP: &str = "sweep";
/// Phase once enumeration is done (or when the mode never asked for one).
const PHASE_RECENT: &str = "recent";

/// How much of upstream this instance keeps warm (decision 07, `[upstream.mirror] mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MirrorMode {
    /// No worker at all: the cache is filled by traffic alone (pure read-through). The default,
    /// because a mirror is a deliberate decision about egress and storage.
    #[default]
    Off,
    /// Keep what we already cache fresh: re-poll cached packages oldest-snapshot-first, which
    /// is what picks up new upstream versions and retractions ahead of the TTL.
    Recent,
    /// One initial sweep over upstream's whole package-name list, then `recent` forever after.
    /// The air-gap-adjacent and regional-mirror mode.
    Full,
}

impl MirrorMode {
    /// Canonical lowercase name as used in config files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Recent => "recent",
            Self::Full => "full",
        }
    }

    /// Whether a worker should be scheduled at all.
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Mirror worker policy (projected from the `[upstream.mirror]` config section).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorPolicy {
    /// What to keep warm.
    pub mode: MirrorMode,
    /// How often a tick fires.
    pub interval: StdDuration,
    /// Packages processed per tick. The bound on how much one tick can cost — an unbounded
    /// pass over 60 000 names would hold the leader lock for hours.
    pub chunk: usize,
    /// Packages refreshed simultaneously. Independent of, and normally larger than, the
    /// upstream semaphore: excess refreshes queue on the service's permits instead of on the
    /// network, so this knob controls *our* concurrency and the service still controls
    /// upstream's.
    pub concurrency: usize,
    /// A snapshot younger than this is left alone. It is both the mirror's freshness target
    /// and its throttle — with `refresh_after` at an hour a sweep re-visiting a package costs
    /// one indexed read, not a fetch.
    pub refresh_after: Duration,
    /// Whether to pull archive **bytes**, not just metadata. Off by default: metadata mirroring
    /// keeps resolution fast and leaves bytes to the read-through path, while an air-gapped
    /// instance needs the bytes and pays for them.
    pub archives: bool,
    /// When `archives` is set, how many of a package's newest versions to warm per pass. Whole
    /// histories are usually not what a mirror wants — and always fetching all of them would
    /// make one tick unbounded again.
    pub archive_versions: usize,
    /// In `full` mode, how long after a completed sweep the next enumeration starts.
    ///
    /// A sweep is not a one-off: decision 07 calls it "initial sweep **and drift repair**". It
    /// is also the only way this instance ever learns that upstream has *started* carrying a
    /// name we claim — the read path structurally never asks upstream about a claimed name
    /// (S-16) — so a mirror that enumerated exactly once would go permanently blind to new
    /// S-17 shadowing.
    pub resweep_after: Duration,
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        Self {
            mode: MirrorMode::Off,
            interval: StdDuration::from_secs(300),
            chunk: 200,
            concurrency: 4,
            refresh_after: Duration::hours(1),
            archives: false,
            archive_versions: 1,
            resweep_after: Duration::hours(24),
        }
    }
}

/// What one [`MirrorWorker::run_once`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MirrorReport {
    /// The phase the tick ran in (`sweep` | `recent`).
    pub phase: String,
    /// Packages whose snapshot was refreshed from upstream.
    pub refreshed: usize,
    /// Packages already fresh enough to skip (no upstream request).
    pub skipped: usize,
    /// Packages upstream could not answer for.
    pub unavailable: usize,
    /// Names claimed on this instance — observed as S-17 alarms, never mirrored.
    pub shadowed: usize,
    /// Alarms this tick actually raised (a first sighting, or one after an acknowledgement).
    pub alarms_raised: usize,
    /// Archives fetched and stored.
    pub archives_cached: usize,
    /// Whether this tick finished the initial full enumeration.
    pub sweep_complete: bool,
}

/// The durable sweep position: which page of upstream's name index, and how far into it.
///
/// Stored as JSON in `jobs.cursor` because it is genuinely two values and a delimiter-joined
/// string would be a parser waiting to be got wrong. Resuming re-fetches the page and skips
/// `offset` entries — upstream's index order is not promised to be stable, but re-processing or
/// missing a handful of names across a restart is a *mirror completeness* question that the
/// next sweep settles, not a correctness one: nothing here decides what a client resolves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SweepCursor {
    /// Continuation token of the page being processed; `None` = the first page.
    page: Option<String>,
    /// How many names of that page are done.
    offset: usize,
    /// When the last enumeration finished — what [`MirrorPolicy::resweep_after`] is measured
    /// from. Kept in the cursor rather than in a column of its own because it is the same
    /// thing: the sweep's position, and "done" is a position.
    #[serde(default)]
    completed_at: Option<DateTime<Utc>>,
}

/// Mirror sync worker (decision 07).
pub struct MirrorWorker {
    repos: Repositories,
    upstream: Arc<UpstreamService>,
    format: Format,
    policy: MirrorPolicy,
    /// The name page the sweep is currently walking, kept across ticks so a chunked sweep does
    /// not re-download a multi-megabyte index every tick. Pure optimization: the durable cursor
    /// is what makes progress survive, and a cold process simply fetches once.
    page_cache: tokio::sync::Mutex<Option<CachedPage>>,
}

/// One fetched index page, cached across ticks (see [`MirrorWorker::page_cache`]).
#[derive(Clone)]
struct CachedPage {
    /// The token this page was fetched with (`None` = the first page).
    token: Option<String>,
    /// The names it carried.
    names: Arc<Vec<String>>,
    /// The token of the page after it, if any.
    next: Option<String>,
}

impl std::fmt::Debug for MirrorWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirrorWorker")
            .field("format", &self.format)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl MirrorWorker {
    /// Builds a worker over the proxy pipeline it warms.
    pub fn new(repos: Repositories, upstream: Arc<UpstreamService>, format: Format, policy: MirrorPolicy) -> Self {
        Self { repos, upstream, format, policy, page_cache: tokio::sync::Mutex::new(None) }
    }

    /// The configured policy.
    pub fn policy(&self) -> &MirrorPolicy {
        &self.policy
    }

    /// The job's durable state — the admin surface's "mirror status" (never-run jobs included).
    pub async fn status(&self, now: DateTime<Utc>) -> Result<JobState> {
        Ok(self.repos.jobs.get(MIRROR_JOB).await?.unwrap_or_else(|| JobState::fresh(MIRROR_JOB, now)))
    }

    /// Runs one tick: resume, process a chunk, checkpoint, record the outcome.
    ///
    /// Errors are returned *after* the failure has been recorded on the job row, so a caller
    /// that only logs them still leaves an operator able to see what happened.
    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<MirrorReport> {
        if !self.policy.mode.is_enabled() {
            return Ok(MirrorReport::default());
        }
        let state = self.repos.jobs.begin_run(MIRROR_JOB, now).await?;

        // A dead upstream is skipped whole: feeding a chunk into an open circuit spends the one
        // half-open probe on the first name and answers `Unavailable` for the rest, which would
        // turn the breaker into a slow retry loop and the counters into noise.
        if self.upstream.circuit_open(now) {
            tracing::warn!(job = MIRROR_JOB, "upstream circuit is open; skipping this mirror tick");
            self.repos
                .jobs
                .finish_run(MIRROR_JOB, JobOutcome::Failure("upstream circuit open".to_owned()), now)
                .await?;
            return Ok(MirrorReport { phase: state.phase, ..MirrorReport::default() });
        }

        let cursor: SweepCursor =
            state.cursor.as_deref().and_then(|raw| serde_json::from_str(raw).ok()).unwrap_or_default();
        // Full mode sweeps when it has never finished one, when it was interrupted mid-sweep,
        // or when the last one has aged out — the "drift repair" half of decision 07, and the
        // only channel through which newly appearing upstream shadowing can be noticed at all.
        let resweep_due =
            cursor.completed_at.is_none_or(|at| now.signed_duration_since(at) >= self.policy.resweep_after);
        let sweeping = self.policy.mode == MirrorMode::Full && (state.phase != PHASE_RECENT || resweep_due);
        // A sweep that starts from the steady-state phase is a *new* enumeration, so it begins
        // at the first page rather than at a position left over from the previous one.
        let resume = if state.phase == PHASE_RECENT { SweepCursor::default() } else { cursor };

        let outcome = if sweeping { self.sweep(resume, now).await } else { self.recent(resume, now).await };

        let report = match outcome {
            Ok(report) => {
                self.repos.jobs.finish_run(MIRROR_JOB, JobOutcome::Success, now).await?;
                report
            }
            Err(err) => {
                // The cursor written by the last checkpoint stays: a failed tick resumes where
                // it stopped rather than restarting the sweep.
                self.repos.jobs.finish_run(MIRROR_JOB, JobOutcome::Failure(err.to_string()), now).await?;
                return Err(err);
            }
        };

        if let Some(lag) = self.status(now).await?.lag_seconds(now) {
            metrics::gauge!("upstream_sync_lag_seconds").set(lag as f64);
        }
        tracing::info!(
            job = MIRROR_JOB,
            phase = %report.phase,
            refreshed = report.refreshed,
            skipped = report.skipped,
            unavailable = report.unavailable,
            shadowed = report.shadowed,
            archives = report.archives_cached,
            "mirror tick finished"
        );
        Ok(report)
    }

    // ------------------------------------------------------------------------- full sweep

    /// One chunk of an enumeration, resuming from the durable cursor.
    async fn sweep(&self, cursor: SweepCursor, now: DateTime<Utc>) -> Result<MirrorReport> {
        let page = match self.page(cursor.page.as_deref()).await {
            Some(page) => page,
            None => {
                // No enumeration endpoint (or upstream could not answer): the full mode cannot
                // start, but the packages we already hold still deserve refreshing, so the tick
                // degrades into a `recent` pass instead of doing nothing.
                tracing::warn!(
                    job = MIRROR_JOB,
                    "upstream package-name index unavailable; falling back to a recent pass"
                );
                return self.recent(cursor, now).await;
            }
        };

        let end = (cursor.offset + self.policy.chunk).min(page.names.len());
        let slice: Vec<String> = page.names.get(cursor.offset..end).unwrap_or_default().to_vec();
        let mut report = self.process(&slice, now).await?;
        report.phase = PHASE_SWEEP.to_owned();

        // Page exhausted → advance to the next one; no next page → the sweep is done and the
        // job switches to the steady-state phase for good.
        let (next_cursor, phase) = if end < page.names.len() {
            (SweepCursor { page: cursor.page.clone(), offset: end, completed_at: cursor.completed_at }, PHASE_SWEEP)
        } else {
            match page.next {
                Some(next) => {
                    (SweepCursor { page: Some(next), offset: 0, completed_at: cursor.completed_at }, PHASE_SWEEP)
                }
                None => {
                    report.sweep_complete = true;
                    (SweepCursor { page: None, offset: 0, completed_at: Some(now) }, PHASE_RECENT)
                }
            }
        };

        self.checkpoint(Some(&next_cursor), phase, &report, now).await?;
        if report.sweep_complete {
            tracing::info!(job = MIRROR_JOB, "initial mirror sweep complete; switching to incremental refresh");
        }
        Ok(report)
    }

    /// One index page, from the in-process cache when it is the page we are already walking.
    async fn page(&self, token: Option<&str>) -> Option<CachedPage> {
        let mut cache = self.page_cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.token.as_deref() == token
        {
            return Some(cached.clone());
        }
        match self.upstream.package_names(token).await {
            Ok(fetched) => {
                let page =
                    CachedPage { token: token.map(str::to_owned), names: Arc::new(fetched.names), next: fetched.next };
                *cache = Some(page.clone());
                Some(page)
            }
            Err(err) => {
                tracing::warn!(job = MIRROR_JOB, error = %err, "failed to fetch the upstream package-name index");
                None
            }
        }
    }

    // --------------------------------------------------------------------- incremental pass

    /// One chunk of the steady-state pass: the oldest snapshots we hold.
    ///
    /// No cursor, by construction: a refresh moves a package to the back of the
    /// `ORDER BY fetched_at` queue, so repeated ticks walk the whole cache and an interrupted
    /// tick simply re-reads the packages it had not reached.
    async fn recent(&self, cursor: SweepCursor, now: DateTime<Utc>) -> Result<MirrorReport> {
        let stale_before = now - self.policy.refresh_after;
        let packages = self.upstream.stale_packages(self.format, stale_before, self.policy.chunk as u32).await?;
        let names: Vec<String> = packages.into_iter().map(|package| package.name).collect();

        let mut report = self.process(&names, now).await?;
        report.phase = PHASE_RECENT.to_owned();
        // The cursor is written back rather than cleared: it carries when the last enumeration
        // finished, and dropping that would make the next full tick re-sweep immediately.
        self.checkpoint(Some(&cursor), PHASE_RECENT, &report, now).await?;
        Ok(report)
    }

    // ------------------------------------------------------------------------- shared work

    /// Refreshes a batch of names with bounded concurrency, observing shadowing as it goes.
    async fn process(&self, names: &[String], now: DateTime<Utc>) -> Result<MirrorReport> {
        let stale_before = now - self.policy.refresh_after;
        let refreshed = AtomicUsize::new(0);
        let skipped = AtomicUsize::new(0);
        let unavailable = AtomicUsize::new(0);
        let shadowed = AtomicUsize::new(0);
        let alarms = AtomicUsize::new(0);
        let archives = AtomicUsize::new(0);

        futures::stream::iter(names.iter())
            .for_each_concurrent(self.policy.concurrency.max(1), |name| {
                let (refreshed, skipped, unavailable) = (&refreshed, &skipped, &unavailable);
                let (shadowed, alarms, archives) = (&shadowed, &alarms, &archives);
                async move {
                    // The breaker may open mid-chunk; the rest of the chunk then costs nothing
                    // instead of a permit and a timeout each.
                    if self.upstream.circuit_open(now) {
                        unavailable.fetch_add(1, Ordering::Relaxed);
                        return;
                    }

                    // S-17 first: a name claimed here is observed and then left alone. Mirroring
                    // it would store bytes resolution can never serve (S-16, "local wins").
                    match self.upstream.observe_shadowing(self.format, name, None, now).await {
                        Ok(Some(outcome)) => {
                            shadowed.fetch_add(1, Ordering::Relaxed);
                            if outcome.raised {
                                alarms.fetch_add(1, Ordering::Relaxed);
                            }
                            return;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(package = %name, error = %err, "shadowing check failed during a mirror pass");
                            return;
                        }
                    }

                    match self.upstream.refresh(self.format, name, stale_before, now).await {
                        Ok(RefreshOutcome::Fresh) => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(RefreshOutcome::Updated(listing)) => {
                            refreshed.fetch_add(1, Ordering::Relaxed);
                            archives.fetch_add(self.warm_archives(&listing, now).await, Ordering::Relaxed);
                        }
                        Ok(RefreshOutcome::Unavailable) => {
                            unavailable.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(err) => {
                            // A single package must never abort a pass over thousands.
                            tracing::warn!(package = %name, error = %err, "mirror refresh failed");
                            unavailable.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .await;

        Ok(MirrorReport {
            phase: String::new(),
            refreshed: refreshed.into_inner(),
            skipped: skipped.into_inner(),
            unavailable: unavailable.into_inner(),
            shadowed: shadowed.into_inner(),
            alarms_raised: alarms.into_inner(),
            archives_cached: archives.into_inner(),
            sweep_complete: false,
        })
    }

    /// Pulls the newest live versions' bytes when the policy asks for a byte-level mirror.
    ///
    /// Retracted versions are skipped: they are excluded from new resolutions, so pre-fetching
    /// them spends bandwidth on archives nobody will ask for. They stay available through the
    /// read-through path for a lockfile that pins one.
    async fn warm_archives(&self, listing: &pub_registry::ProxiedListing, now: DateTime<Utc>) -> usize {
        if !self.policy.archives {
            return 0;
        }
        let mut cached = 0;
        for version in listing.versions.iter().rev().filter(|v| !v.retracted).take(self.policy.archive_versions) {
            match self.upstream.archive(self.format, &listing.name, &version.version, now).await {
                Ok(Some(archive)) if !archive.from_cache => cached += 1,
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(
                        package = %listing.name,
                        version = %version.version,
                        error = %err,
                        "mirror archive warm-up failed"
                    );
                }
            }
        }
        cached
    }

    /// Writes the resume point and the tick's counters.
    async fn checkpoint(
        &self,
        cursor: Option<&SweepCursor>,
        phase: &str,
        report: &MirrorReport,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let cursor = match cursor {
            Some(cursor) => Some(serde_json::to_string(cursor).map_err(|err| pub_core::Error::Internal {
                message: format!("failed to encode the mirror cursor: {err}"),
            })?),
            None => None,
        };
        let progress = JobProgress {
            cursor,
            phase: phase.to_owned(),
            processed: (report.refreshed + report.skipped + report.shadowed) as u64,
            failed: report.unavailable as u64,
        };
        self.repos.jobs.checkpoint(MIRROR_JOB, &progress, now).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_round_trip_their_config_names_and_gate_scheduling() {
        assert_eq!(MirrorMode::default(), MirrorMode::Off);
        assert!(!MirrorMode::Off.is_enabled());
        assert!(MirrorMode::Recent.is_enabled());
        assert!(MirrorMode::Full.is_enabled());
        assert_eq!(MirrorMode::Full.as_str(), "full");
    }

    #[test]
    fn the_sweep_cursor_round_trips_through_json() {
        let cursor = SweepCursor {
            page: Some("https://pub.dev/api/package-names?page=2".to_owned()),
            offset: 400,
            completed_at: Some(chrono::Utc::now()),
        };
        let encoded = serde_json::to_string(&cursor).unwrap();
        assert_eq!(serde_json::from_str::<SweepCursor>(&encoded).unwrap(), cursor);
        // A cursor written by an older build (or corrupted) restarts the sweep rather than
        // wedging the job — `run_once` decodes with `unwrap_or_default`.
        assert!(serde_json::from_str::<SweepCursor>("not json").is_err());
        assert_eq!(
            serde_json::from_str::<SweepCursor>("{\"page\":null,\"offset\":7}").unwrap().offset,
            7,
            "a cursor from before resweep tracking still parses"
        );
        assert_eq!(SweepCursor::default(), SweepCursor { page: None, offset: 0, completed_at: None });
    }
}
