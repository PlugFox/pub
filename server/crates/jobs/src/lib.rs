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
//!   and the proxy cache agree nothing live points at it. Off by default, and it streams its
//!   key space one shard at a time from a durable cursor, because it deletes bytes a
//!   `pubspec.lock` may pin (decision 31).
//! - [`staging`] — abandoned staged uploads, the *other* byte collector and the one that is
//!   **on by default**: an unfinished publish leaves an archive that no row and no session can
//!   ever reach again, so age alone decides it and no database is consulted (decision 31).
//!
//! - [`reindex`] — search-index rebuild. The index is a projection maintained best-effort by
//!   the publish path, so something has to close the gap; this is also how an existing instance
//!   gets an index at all after migration 0007.
//! - [`downloads`] — download-statistics rollup. Drains the in-process counter buffer into the
//!   daily table and writes the totals back onto the search index. On by default: disabling it
//!   does not reduce statistics, it fills a buffer until it drops.
//! - [`queue`] — the durable work queue's drain (decision 26), with [`fanout`] and [`mail`] as
//!   its two handlers. The only job with **no** `enabled` key at all: sign-in mail rides this
//!   queue, so an operator who switched it off could not sign in to switch it back on.
//! - [`lifecycle`] — S-23 retention (decision 30), and **the only job in the instance that deletes
//!   rows**. On by default, because a default install that grows forever is not a default. It also
//!   owns the queue's own retention, which used to run as three unbounded `DELETE`s on the drain's
//!   five-second tick: this job deletes, that one delivers.
//!
//! Webhook delivery (S-33) is not an open mechanism question — it is one more
//! [`pub_core::queue::JobKind`] and one more [`queue::JobHandler`], with the retry, backoff and
//! dead-letter machinery already built and already tested.
//!
//! [`JobRegistry`] is the same set seen from the admin surface: it takes the scheduler's own
//! [`JobLock`] before a manually triggered run, so an operator pressing "run now" can never
//! overlap a scheduled tick on one durable cursor.
//!
//! Every job must be idempotent and safe to rerun: a tick can be interrupted at any point,
//! and the next one — possibly on another instance — picks up from the durable state in
//! [`pub_core::traits::JobRepo`] rather than from anything held in this process.

pub mod downloads;
pub mod fanout;
pub mod gc;
pub mod lifecycle;
mod lock;
pub mod mail;
pub mod mirror;
pub mod queue;
pub mod registry;
pub mod reindex;
mod scheduler;
pub mod staging;

pub use downloads::{DOWNLOAD_ROLLUP_JOB, DownloadRollup, DownloadRollupPolicy, RollupReport};
pub use fanout::FanoutHandler;
pub use gc::{BLOB_GC_JOB, BlobGc, GcPolicy, GcReport};
pub use lifecycle::{LIFECYCLE_JOB, LifecyclePolicy, LifecycleWorker};
pub use lock::{InMemoryJobLock, JobLockTtls};
pub use mail::MailHandler;
pub use mirror::{MIRROR_JOB, MirrorMode, MirrorPolicy, MirrorReport, MirrorWorker};
pub use queue::{HandlerReport, JobHandler, QUEUE_JOB, QueuePolicy, QueueReport, QueueWorker};
pub use registry::JobRegistry;
pub use reindex::{REINDEX_JOB, ReindexPolicy, ReindexReport, Reindexer};
pub use scheduler::{Scheduler, SchedulerHandle};
pub use staging::{STAGING_SWEEP_JOB, StagingPolicy, StagingReport, StagingSweeper};

pub use pub_core::traits::JobLock;
