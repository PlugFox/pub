//! Interval scheduler: each registered job ticks on its own interval and runs only while
//! holding its [`JobLock`] — one instance in a cluster executes it per tick.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;
use pub_core::traits::JobLock;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::lock::JobLockTtls;

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
    ttls: JobLockTtls,
    jobs: Vec<Job>,
}

impl Scheduler {
    /// Creates a scheduler using `lock` for leader election and `ttls` for lock lifetimes.
    ///
    /// The TTL table is passed in rather than built here because the manual-run registry
    /// ([`crate::JobRegistry`]) takes the same one: both paths acquire the same lock under the same
    /// name, so a per-job lifetime that differed between them would make the invariant that name
    /// carries — one holder per job — false (D48).
    pub fn new(lock: Arc<dyn JobLock>, ttls: JobLockTtls) -> Self {
        Self { lock, ttls, jobs: Vec::new() }
    }

    /// Registers a job to run every `interval` (first run fires immediately after spawn).
    pub fn add<F, Fut>(&mut self, name: &'static str, interval: Duration, job: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = pub_core::Result<()>> + Send + 'static,
    {
        self.jobs.push(Job { name, interval, run: Arc::new(move || job().boxed()) });
    }

    /// The lock lifetime this scheduler would use for `job` — the same table the manual-run
    /// registry reads, exposed so the pairing is assertable rather than assumed (D48).
    #[must_use]
    pub fn lock_ttl(&self, job: &str) -> Duration {
        self.ttls.get(job)
    }

    /// Spawns one tokio task per registered job and returns a handle that stops them —
    /// gracefully through [`SchedulerHandle::stop_and_release`], by abort on
    /// [`SchedulerHandle::shutdown`] or drop.
    pub fn spawn(self) -> SchedulerHandle {
        let (stop, _) = watch::channel(false);
        let handles = self
            .jobs
            .into_iter()
            .map(|job| {
                let lock = Arc::clone(&self.lock);
                let lock_ttl = self.ttls.get(job.name);
                tokio::spawn(run_job_loop(job, lock, lock_ttl, stop.subscribe()))
            })
            .collect();
        SchedulerHandle { stop, handles }
    }
}

async fn run_job_loop(job: Job, lock: Arc<dyn JobLock>, lock_ttl: Duration, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(job.interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        // Waiting on the stop signal *beside* the tick is what keeps a shutdown from costing a
        // lease. Since decision 36 a Postgres deployment's locks live in a table, so a loop
        // aborted while holding one blocks that job on every replica until the TTL expires —
        // for the queue drain, the sign-in mail plane through a rolling restart.
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            _ = interval.tick() => {}
        }
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
                // A stop that arrived mid-run: the run finished, the lease is back, and this is
                // the point at which leaving costs nothing.
                if *stop.borrow() {
                    return;
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
    stop: watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl SchedulerHandle {
    /// How long [`SchedulerHandle::stop_and_release`] waits for the loops before aborting them.
    ///
    /// A bound rather than "however long the longest job takes": a shutdown that hangs on a job
    /// is a container the orchestrator kills anyway, and then the lease is leaked *and* the stop
    /// took the grace period with it. Long enough for a drain to finish its current item.
    pub const STOP_TIMEOUT: Duration = Duration::from_secs(20);

    /// Stops all job loops **immediately**, by abort.
    ///
    /// A loop aborted while it holds its lock leaves that lock to expire on its TTL, which is
    /// free for the in-process implementation and costs a stall for the database one — see
    /// [`Self::stop_and_release`], which is what `pubd` calls.
    pub fn shutdown(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }

    /// Asks every loop to finish what it is doing, release its lock, and exit; waits up to
    /// [`Self::STOP_TIMEOUT`] and then aborts whatever is left.
    ///
    /// This is the half of leader election that only matters once the lock outlives the process
    /// ([decision 36](../../../../docs/decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check)):
    /// the TTL is what bounds a *crash*, and a planned stop should not have to be paid for at
    /// the same price.
    pub async fn stop_and_release(mut self) {
        // A send with no receivers is not a failure here — it means every loop has already
        // exited, which is the state this method is trying to reach.
        let _ = self.stop.send(true);
        let handles = &mut self.handles;
        let waited = tokio::time::timeout(Self::STOP_TIMEOUT, async move {
            for handle in handles.iter_mut() {
                // The loops return rather than fail; a join error is an abort or a panic, and
                // either way there is nothing left to wait for.
                let _ = handle.await;
            }
        })
        .await;
        if waited.is_err() {
            tracing::warn!(
                timeout_secs = Self::STOP_TIMEOUT.as_secs(),
                "background jobs did not stop in time; aborting — their locks will expire on their TTL"
            );
            self.shutdown();
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

        let mut scheduler = Scheduler::new(lock, JobLockTtls::with_default(Duration::from_millis(10)));
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
        let mut scheduler = Scheduler::new(Arc::clone(&lock), JobLockTtls::with_default(Duration::from_millis(10)));
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

    /// The pair that shows what the graceful stop buys, against the abort that does not buy it.
    ///
    /// With the in-process lock a leaked lease costs nothing, so this asserts the mechanism
    /// rather than the damage — but the mechanism is the one a Postgres deployment's `job_locks`
    /// row depends on: a loop aborted mid-run leaves that row until its TTL, on every replica
    /// (decision 36).
    #[tokio::test(start_paused = true)]
    async fn a_graceful_stop_returns_the_lock_and_an_abort_does_not() {
        async fn spawn_slow_job(lock: &Arc<InMemoryJobLock>) -> SchedulerHandle {
            let mut scheduler =
                Scheduler::new(Arc::clone(lock) as Arc<dyn JobLock>, JobLockTtls::with_default(Duration::from_secs(1)));
            scheduler.add("slow", Duration::from_millis(50), || async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            });
            let handle = scheduler.spawn();
            // Long enough for the first tick to take the lock and be inside the run.
            tokio::time::sleep(Duration::from_millis(10)).await;
            handle
        }

        let aborted = Arc::new(InMemoryJobLock::new());
        let handle = spawn_slow_job(&aborted).await;
        handle.shutdown();
        assert!(
            aborted.try_acquire("slow", Duration::from_secs(3600)).await.unwrap().is_none(),
            "an abort mid-run leaves the lock to its TTL — this is the cost the graceful path avoids"
        );

        let released = Arc::new(InMemoryJobLock::new());
        let handle = spawn_slow_job(&released).await;
        handle.stop_and_release().await;
        assert!(
            released.try_acquire("slow", Duration::from_secs(3600)).await.unwrap().is_some(),
            "a graceful stop finishes the run in flight and hands the lock back"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failing_job_keeps_ticking_and_releases_the_lock() {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let runs = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&runs);
        let mut scheduler = Scheduler::new(Arc::clone(&lock), JobLockTtls::with_default(Duration::from_secs(3600)));
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
