//! The download counter's write path (docs/architecture.md `download_stats`).
//!
//! # Why an in-process buffer and not a database write per download
//!
//! An archive download is the hottest path in a registry, and counting it must not cost a
//! round trip. Three shapes were on the table:
//!
//! - **A row upsert per download.** Correct and durable, but it serializes every download of a
//!   popular package on one row's lock and puts a write on the read path.
//! - **A KV counter flushed by the job.** The natural fit for the [`Kv`](pub_core::traits::Kv)
//!   seam — except that trait deliberately has no key enumeration (`SCAN` is a foot-gun on a
//!   shared Redis), so nothing could ever find the counters again to flush them.
//! - **An in-process map flushed by the job** — this. A download costs one mutex-guarded
//!   `HashMap` increment and no I/O at all; the rollup job drains the map on its interval and
//!   folds the deltas into `download_stats` with an *additive* upsert, so several instances
//!   flushing the same day sum correctly.
//!
//! **The trade-off, stated plainly:** a process that dies between flushes loses up to one
//! flush interval of counts on that instance. That is the right trade for a statistic — it is
//! a product feature, not an audit record (S-22 covers what may not be lost) — and it is the
//! reason nothing in the system may ever make a decision from these numbers.
//!
//! Two more properties the buffer has to carry:
//!
//! - **`HEAD` never counts.** The pub client `HEAD`s an archive before every `GET` to check its
//!   cache, so counting both would roughly double every number. The rule is enforced at the
//!   HTTP edge, because that is the only layer that knows the method.
//! - **The map is bounded.** A flood across many distinct packages must not grow it without
//!   limit; past [`DownloadRecorder`]'s capacity, increments to *known* keys still land and new
//!   keys are dropped with a warning. Losing counts beats losing the process.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, NaiveDate, Utc};
use pub_core::stats::DownloadDelta;
use pub_core::traits::StatsRepo;
use pub_core::{PackageId, Result, VersionId};

/// Default number of distinct `(package, version, day)` buckets held between flushes.
///
/// One bucket is ~40 bytes, so the default is well under a megabyte — and an instance seeing
/// more than 50 000 distinct package-versions inside one flush interval is a mirror under a
/// full sweep, not a team installing dependencies.
pub const DEFAULT_BUFFER_CAPACITY: usize = 50_000;

/// Buffered download counts awaiting the next rollup.
#[derive(Debug)]
pub struct DownloadRecorder {
    buffer: Mutex<HashMap<(PackageId, VersionId, NaiveDate), i64>>,
    capacity: usize,
}

impl Default for DownloadRecorder {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_CAPACITY)
    }
}

impl DownloadRecorder {
    /// A recorder holding at most `capacity` distinct buckets between flushes.
    pub fn new(capacity: usize) -> Self {
        Self { buffer: Mutex::new(HashMap::new()), capacity: capacity.max(1) }
    }

    /// Counts one served archive download.
    ///
    /// Infallible and non-blocking by contract: this runs inside the download response path,
    /// and a statistic must never be able to fail a download. A poisoned mutex (another thread
    /// panicked mid-increment) drops the count rather than propagating the panic.
    pub fn record(&self, package: PackageId, version: VersionId, at: DateTime<Utc>) {
        let key = (package, version, at.date_naive());
        let Ok(mut buffer) = self.buffer.lock() else {
            tracing::warn!("download counter buffer is poisoned; dropping a count");
            return;
        };
        let at_capacity = buffer.len() >= self.capacity;
        match buffer.get_mut(&key) {
            Some(count) => *count += 1,
            None if at_capacity => tracing::warn!(
                capacity = self.capacity,
                "download counter buffer is full; dropping counts until the next rollup"
            ),
            None => {
                buffer.insert(key, 1);
            }
        }
    }

    /// How many buckets are waiting (diagnostics and tests).
    pub fn pending(&self) -> usize {
        self.buffer.lock().map(|buffer| buffer.len()).unwrap_or(0)
    }

    /// Drains the buffer into a sorted delta list.
    ///
    /// Sorted so a flush issues its statements in a deterministic order: two instances writing
    /// overlapping rows in the same order cannot deadlock each other on Postgres.
    pub fn drain(&self) -> Vec<DownloadDelta> {
        let Ok(mut buffer) = self.buffer.lock() else {
            tracing::warn!("download counter buffer is poisoned; dropping the pending counts");
            return Vec::new();
        };
        let mut deltas: Vec<DownloadDelta> = buffer
            .drain()
            .map(|((package_id, version_id, date), count)| DownloadDelta { package_id, version_id, date, count })
            .collect();
        deltas.sort_unstable();
        deltas
    }

    /// Puts drained deltas back after a failed write, so a database blip costs a delay rather
    /// than the counts.
    fn restore(&self, deltas: Vec<DownloadDelta>) {
        let Ok(mut buffer) = self.buffer.lock() else { return };
        for delta in deltas {
            if buffer.len() >= self.capacity && !buffer.contains_key(&(delta.package_id, delta.version_id, delta.date))
            {
                continue;
            }
            *buffer.entry((delta.package_id, delta.version_id, delta.date)).or_insert(0) += delta.count;
        }
    }

    /// Drains the buffer into the rollup table and reports which packages were touched.
    ///
    /// The package list is the job's write-back input: only those rows need their denormalized
    /// totals refreshed on the search index.
    pub async fn flush(&self, stats: &dyn StatsRepo) -> Result<FlushReport> {
        let deltas = self.drain();
        if deltas.is_empty() {
            return Ok(FlushReport::default());
        }
        let downloads: i64 = deltas.iter().map(|delta| delta.count).sum();
        let mut packages: Vec<PackageId> = deltas.iter().map(|delta| delta.package_id).collect();
        packages.dedup();

        match stats.add_downloads(&deltas).await {
            Ok(rows) => Ok(FlushReport { rows, downloads, packages }),
            Err(err) => {
                self.restore(deltas);
                Err(err)
            }
        }
    }
}

/// What one [`DownloadRecorder::flush`] wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Rollup rows inserted or updated.
    pub rows: u64,
    /// Downloads folded in.
    pub downloads: i64,
    /// Packages whose totals changed, deduplicated and sorted.
    pub packages: Vec<PackageId>,
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::TimeZone as _;
    use pub_core::Error;
    use pub_core::stats::{DownloadTotals, PackageDownloads};

    use super::*;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, hour, 0, 0).unwrap()
    }

    /// Records what it was handed; optionally fails once.
    #[derive(Default)]
    struct SpyStats {
        written: Mutex<Vec<DownloadDelta>>,
        fail: bool,
    }

    #[async_trait]
    impl StatsRepo for SpyStats {
        async fn ping(&self) -> Result<()> {
            Ok(())
        }

        async fn add_downloads(&self, deltas: &[DownloadDelta]) -> Result<u64> {
            if self.fail {
                return Err(Error::Database { message: "down".into() });
            }
            self.written.lock().unwrap().extend_from_slice(deltas);
            Ok(deltas.len() as u64)
        }

        async fn package_totals(&self, _package: PackageId, _since: NaiveDate) -> Result<DownloadTotals> {
            Ok(DownloadTotals::default())
        }

        async fn totals_for(&self, _packages: &[PackageId], _since: NaiveDate) -> Result<Vec<PackageDownloads>> {
            Ok(Vec::new())
        }

        async fn purge_before(&self, _cutoff: NaiveDate, _batch: u32) -> Result<u64> {
            unimplemented!("the rollup never spends download-stats retention")
        }
    }

    #[tokio::test]
    async fn counts_collapse_per_package_version_and_day() {
        let package = PackageId::new();
        let version = VersionId::new();
        let recorder = DownloadRecorder::default();
        recorder.record(package, version, at(6, 1));
        recorder.record(package, version, at(6, 23));
        recorder.record(package, version, at(7, 0));
        assert_eq!(recorder.pending(), 2, "two days, one bucket each");

        let stats = SpyStats::default();
        let report = recorder.flush(&stats).await.unwrap();
        assert_eq!(report.downloads, 3);
        assert_eq!(report.packages, vec![package]);
        let written = stats.written.lock().unwrap().clone();
        assert_eq!(written.iter().map(|d| d.count).sum::<i64>(), 3);
        assert_eq!(recorder.pending(), 0, "a successful flush drains the buffer");
    }

    #[tokio::test]
    async fn a_failed_flush_keeps_the_counts() {
        let recorder = DownloadRecorder::default();
        recorder.record(PackageId::new(), VersionId::new(), at(6, 1));
        let stats = SpyStats { fail: true, ..SpyStats::default() };
        assert!(recorder.flush(&stats).await.is_err());
        assert_eq!(recorder.pending(), 1, "a database blip must cost a delay, not the counts");
    }

    #[tokio::test]
    async fn an_empty_flush_writes_nothing() {
        let stats = SpyStats::default();
        let report = DownloadRecorder::default().flush(&stats).await.unwrap();
        assert_eq!(report, FlushReport::default());
        assert!(stats.written.lock().unwrap().is_empty());
    }

    #[test]
    fn the_buffer_is_bounded_but_keeps_counting_known_keys() {
        let recorder = DownloadRecorder::new(2);
        let known = PackageId::new();
        let version = VersionId::new();
        recorder.record(known, version, at(6, 1));
        recorder.record(PackageId::new(), VersionId::new(), at(6, 1));
        // Third distinct key is refused …
        recorder.record(PackageId::new(), VersionId::new(), at(6, 1));
        assert_eq!(recorder.pending(), 2);
        // … but the keys already inside keep accumulating.
        recorder.record(known, version, at(6, 2));
        let deltas = recorder.drain();
        assert_eq!(deltas.iter().find(|d| d.package_id == known).unwrap().count, 2);
    }

    #[test]
    fn drained_deltas_are_sorted() {
        let recorder = DownloadRecorder::default();
        for _ in 0..20 {
            recorder.record(PackageId::new(), VersionId::new(), at(6, 1));
        }
        let deltas = recorder.drain();
        let mut sorted = deltas.clone();
        sorted.sort_unstable();
        assert_eq!(deltas, sorted, "a flush must issue its statements in a deterministic order");
    }
}
