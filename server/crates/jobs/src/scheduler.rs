//! Interval scheduler: each registered job ticks on its own interval and runs only while
//! holding its [`JobLock`] — one instance in a cluster executes it per tick.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;
use pub_core::traits::JobLock;
use tokio::time::MissedTickBehavior;

/// Boxed job body: a factory producing one future per tick.
type JobFn = Arc<dyn Fn() -> BoxFuture<'static, pub_core::Result<()>> + Send + Sync>;

struct Job {
    name: &'static str,
    interval: Duration,
    run: JobFn,
}

/// Interval scheduler guarded by a [`JobLock`].
///
/// Register jobs with [`Scheduler::add`], then call [`Scheduler::spawn`]. Every job gets its
/// own tokio task; missed ticks are skipped (`MissedTickBehavior::Skip` —
/// docs/rules/rust.md), so a slow run never causes a burst of catch-up runs.
pub struct Scheduler {
    lock: Arc<dyn JobLock>,
    lock_ttl: Duration,
    jobs: Vec<Job>,
}

impl Scheduler {
    /// Default TTL for per-run lock acquisitions; bounds how long a crashed instance can
    /// block a job cluster-wide.
    pub const DEFAULT_LOCK_TTL: Duration = Duration::from_secs(300);

    /// Creates a scheduler using `lock` for leader election.
    pub fn new(lock: Arc<dyn JobLock>) -> Self {
        Self { lock, lock_ttl: Self::DEFAULT_LOCK_TTL, jobs: Vec::new() }
    }

    /// Overrides the per-run lock TTL (mainly for tests and fast jobs).
    pub fn with_lock_ttl(mut self, ttl: Duration) -> Self {
        self.lock_ttl = ttl;
        self
    }

    /// Registers a job to run every `interval` (first run fires immediately after spawn).
    pub fn add<F, Fut>(&mut self, name: &'static str, interval: Duration, job: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = pub_core::Result<()>> + Send + 'static,
    {
        self.jobs.push(Job { name, interval, run: Arc::new(move || job().boxed()) });
    }

    /// Spawns one tokio task per registered job and returns a handle that aborts them all
    /// on [`SchedulerHandle::shutdown`] or drop.
    pub fn spawn(self) -> SchedulerHandle {
        let handles = self
            .jobs
            .into_iter()
            .map(|job| {
                let lock = Arc::clone(&self.lock);
                let lock_ttl = self.lock_ttl;
                tokio::spawn(run_job_loop(job, lock, lock_ttl))
            })
            .collect();
        SchedulerHandle { handles }
    }
}

async fn run_job_loop(job: Job, lock: Arc<dyn JobLock>, lock_ttl: Duration) {
    let mut interval = tokio::time::interval(job.interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match lock.try_acquire(job.name, lock_ttl).await {
            Ok(Some(token)) => {
                if let Err(error) = (job.run)().await {
                    tracing::warn!(job = job.name, %error, "background job failed; will retry next tick");
                }
                // With the token, never bare: a run that outlived its TTL is releasing a lock
                // somebody else now holds, and the implementation is what refuses that.
                if let Err(error) = lock.release(job.name, token).await {
                    tracing::warn!(job = job.name, %error, "failed to release job lock; TTL will expire it");
                }
            }
            Ok(None) => {
                tracing::debug!(job = job.name, "job lock held elsewhere; skipping this tick");
            }
            Err(error) => {
                tracing::warn!(job = job.name, %error, "job lock backend failed; skipping this tick");
            }
        }
    }
}

/// Owns the spawned job tasks; aborts them when shut down or dropped.
pub struct SchedulerHandle {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl SchedulerHandle {
    /// Stops all job loops.
    pub fn shutdown(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::InMemoryJobLock;

    #[tokio::test(start_paused = true)]
    async fn job_runs_on_its_interval() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);

        let mut scheduler = Scheduler::new(lock).with_lock_ttl(Duration::from_millis(10));
        scheduler.add("counter", Duration::from_millis(100), move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let handle = scheduler.spawn();

        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.shutdown();
        let count = runs.load(Ordering::SeqCst);
        // Immediate first tick + one per 100ms elapsed.
        assert!((2..=5).contains(&count), "expected steady ticking, got {count} runs");
    }

    #[tokio::test(start_paused = true)]
    async fn job_respects_a_lock_held_elsewhere() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        // Simulate another instance holding the leader lock for this job.
        let token = lock.try_acquire("guarded", Duration::from_secs(3600)).await.unwrap().expect("free");

        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);
        let mut scheduler = Scheduler::new(Arc::clone(&lock)).with_lock_ttl(Duration::from_millis(10));
        scheduler.add("guarded", Duration::from_millis(50), move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let handle = scheduler.spawn();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 0, "job must not run while the lock is held elsewhere");

        // The other instance releases the lock — the job starts running on later ticks.
        lock.release("guarded", token).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.shutdown();
        assert!(runs.load(Ordering::SeqCst) >= 1, "job must run after the lock is released");
    }

    #[tokio::test(start_paused = true)]
    async fn failing_job_keeps_ticking_and_releases_the_lock() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);
        let mut scheduler = Scheduler::new(Arc::clone(&lock)).with_lock_ttl(Duration::from_secs(3600));
        scheduler.add("flaky", Duration::from_millis(50), move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Err(pub_core::Error::Internal { message: "boom".into() })
            }
        });
        let handle = scheduler.spawn();

        tokio::time::sleep(Duration::from_millis(280)).await;
        handle.shutdown();
        // Despite a huge lock TTL, release-after-run lets every tick execute.
        assert!(runs.load(Ordering::SeqCst) >= 3, "failures must not wedge the schedule");
    }
}
