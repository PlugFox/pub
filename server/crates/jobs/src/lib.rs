//! Background jobs: interval scheduler guarded by [`JobLock`] leader election.
//!
//! Planned jobs (docs/architecture.md): mirror sync, unreferenced-blob GC, expired
//! session/OTP/invitation purge, audit retention, search reindex, webhook delivery.
//! Every job must be idempotent and safe to rerun; jobs that must run on a single instance
//! are guarded by a [`JobLock`] (PG advisory lock / Redis lock / in-memory for one node).
//!
//! Skeleton: the scheduler and the in-memory lock are real and tested; concrete jobs land
//! with their roadmap steps.

mod lock;
mod scheduler;

pub use lock::InMemoryJobLock;
pub use scheduler::{Scheduler, SchedulerHandle};

pub use pub_core::traits::JobLock;
