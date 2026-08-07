//! Background jobs: interval scheduler guarded by [`JobLock`] leader election.
//!
//! Two jobs ship here today, both single-instance by construction — the scheduler acquires the
//! job's lock before every run, so in a cluster exactly one replica executes a given tick and
//! the others skip it:
//!
//! - [`mirror`] — decision 07's mirror sync. Warms the *same* ingest pipeline the read-through
//!   proxy uses, with a durable cursor so a full sweep resumes across restarts, and raises the
//!   S-17 shadowing alarm for names upstream carries that this instance claims.
//! - [`gc`] — unreferenced-blob collection. Content addressing means a blob can be shared by
//!   things that never met, so a key is collectable only when both the local version register
//!   and the proxy cache agree nothing live points at it.
//!
//! - [`reindex`] — search-index rebuild. The index is a projection maintained best-effort by
//!   the publish path, so something has to close the gap; this is also how an existing instance
//!   gets an index at all after migration 0007.
//! - [`downloads`] — download-statistics rollup. Drains the in-process counter buffer into the
//!   daily table and writes the totals back onto the search index. The only job that is **on**
//!   by default: disabling it does not reduce statistics, it fills a buffer until it drops.
//!
//! Still to come with their own roadmap steps: expired session/OTP/invitation purge, audit
//! retention, webhook delivery.
//!
//! [`JobRegistry`] is the same set seen from the admin surface: it takes the scheduler's own
//! [`JobLock`] before a manually triggered run, so an operator pressing "run now" can never
//! overlap a scheduled tick on one durable cursor.
//!
//! Every job must be idempotent and safe to rerun: a tick can be interrupted at any point,
//! and the next one — possibly on another instance — picks up from the durable state in
//! [`pub_core::traits::JobRepo`] rather than from anything held in this process.

pub mod downloads;
pub mod gc;
mod lock;
pub mod mirror;
pub mod registry;
pub mod reindex;
mod scheduler;

pub use downloads::{DOWNLOAD_ROLLUP_JOB, DownloadRollup, DownloadRollupPolicy, RollupReport};
pub use gc::{BLOB_GC_JOB, BlobGc, GcPolicy, GcReport};
pub use lock::InMemoryJobLock;
pub use mirror::{MIRROR_JOB, MirrorMode, MirrorPolicy, MirrorReport, MirrorWorker};
pub use registry::JobRegistry;
pub use reindex::{REINDEX_JOB, ReindexPolicy, ReindexReport, Reindexer};
pub use scheduler::{Scheduler, SchedulerHandle};

pub use pub_core::traits::JobLock;
