//! Download statistics: the daily-rollup shapes behind [`StatsRepo`](crate::traits::StatsRepo).
//!
//! The registry counts **archive GETs**, once per served download, into a per-day bucket keyed
//! by `(package, version, date)` — the `download_stats` table of docs/architecture.md. Three
//! properties shape the types:
//!
//! - **HEAD never counts.** The pub client issues a `HEAD` before every archive `GET` to decide
//!   whether its cache is current; counting both would roughly double every number. The rule is
//!   enforced at the HTTP edge (the archive handler inspects the method), not here.
//! - **Writes are deltas, never absolutes.** Every instance in a cluster flushes its own
//!   counts, so the repository adds to the stored row instead of setting it. Two instances
//!   flushing the same day concurrently produce the sum, which is the only correct answer.
//! - **The counter is best-effort.** Statistics are a product feature, not an audit trail
//!   (S-22 covers what must not be lost). Losing one flush interval on a crash is acceptable;
//!   making a download slower or failing one because a counter could not be written is not.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::{PackageId, VersionId};

/// One increment to fold into the daily rollup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DownloadDelta {
    /// Package downloaded.
    pub package_id: PackageId,
    /// Version downloaded.
    pub version_id: VersionId,
    /// UTC day the downloads happened on.
    pub date: NaiveDate,
    /// How many downloads to add.
    pub count: i64,
}

/// Download totals for one package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadTotals {
    /// All-time downloads.
    pub total: i64,
    /// Downloads inside the trailing window the caller asked for.
    pub recent: i64,
}

/// Per-package totals as the rollup job reads them back to denormalize onto the search index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageDownloads {
    /// The package.
    pub package_id: PackageId,
    /// Its totals.
    pub totals: DownloadTotals,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn deltas_order_by_package_then_version_then_date() {
        // Ordering exists so a flush produces a deterministic statement sequence — two
        // instances writing the same rows in the same order cannot deadlock each other.
        let package = PackageId::new();
        let version = VersionId::new();
        let day = |d: u32| chrono::Utc.with_ymd_and_hms(2026, 8, d, 0, 0, 0).unwrap().date_naive();
        let earlier = DownloadDelta { package_id: package, version_id: version, date: day(1), count: 1 };
        let later = DownloadDelta { date: day(2), ..earlier };
        assert!(earlier < later);
    }

    #[test]
    fn totals_default_to_zero() {
        assert_eq!(DownloadTotals::default(), DownloadTotals { total: 0, recent: 0 });
    }
}
