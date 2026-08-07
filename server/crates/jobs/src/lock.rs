//! In-memory [`JobLock`] — trivial leader election for a single-instance deployment.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use pub_core::Result;
use pub_core::traits::{JobLock, LockToken};
use tokio::time::Instant;

/// Named locks with expiry, held in process memory. Only correct for a single instance —
/// multi-instance deployments use the Redis or PG advisory lock implementations (later).
#[derive(Debug, Default)]
pub struct InMemoryJobLock {
    /// Lock name → the acquisition holding it and the deadline it holds it until.
    held: Mutex<HashMap<String, (LockToken, Instant)>>,
}

impl InMemoryJobLock {
    /// Creates an empty lock table.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl JobLock for InMemoryJobLock {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<Option<LockToken>> {
        let mut held = self.held.lock().expect("lock table mutex poisoned");
        let now = Instant::now();
        match held.get(name) {
            Some((_, deadline)) if *deadline > now => Ok(None),
            _ => {
                let token = LockToken::new();
                held.insert(name.to_owned(), (token, now + ttl));
                Ok(Some(token))
            }
        }
    }

    async fn release(&self, name: &str, token: LockToken) -> Result<()> {
        // The ownership check is the point (decision 26's amendment): a holder that overran its
        // TTL must not be able to free the lock the *next* holder took, because that lets a
        // third worker in alongside the one still running — two drains over one queue, each
        // reaping the other's leases.
        let mut held = self.held.lock().expect("lock table mutex poisoned");
        if held.get(name).is_some_and(|(held_by, _)| *held_by == token) {
            held.remove(name);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn acquire_is_exclusive_until_release() {
        let lock = InMemoryJobLock::new();
        let token = lock.try_acquire("gc", TTL).await.unwrap().expect("free");
        assert!(lock.try_acquire("gc", TTL).await.unwrap().is_none(), "second acquire must fail while held");
        lock.release("gc", token).await.unwrap();
        assert!(lock.try_acquire("gc", TTL).await.unwrap().is_some(), "release must free the lock");
    }

    #[tokio::test]
    async fn different_names_do_not_contend() {
        let lock = InMemoryJobLock::new();
        assert!(lock.try_acquire("gc", TTL).await.unwrap().is_some());
        assert!(lock.try_acquire("reindex", TTL).await.unwrap().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_lock_can_be_reacquired() {
        let lock = InMemoryJobLock::new();
        assert!(lock.try_acquire("gc", Duration::from_millis(50)).await.unwrap().is_some());
        assert!(lock.try_acquire("gc", TTL).await.unwrap().is_none());
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(lock.try_acquire("gc", TTL).await.unwrap().is_some(), "a crashed holder's TTL must free the lock");
    }

    #[tokio::test(start_paused = true)]
    async fn an_overrunning_holder_cannot_release_the_next_holders_lock() {
        // The queue drain is why this matters: a drain that runs past its lock TTL finds a
        // second drain already holding the lock, and its own `release` at the end used to hand
        // the lock to a third — so three drains ran over one queue, reaping and re-sending each
        // other's in-flight messages.
        let lock = InMemoryJobLock::new();
        let overrunning = lock.try_acquire("job-queue", Duration::from_millis(50)).await.unwrap().expect("free");
        tokio::time::advance(Duration::from_millis(60)).await;
        let successor = lock.try_acquire("job-queue", TTL).await.unwrap().expect("the TTL expired");
        assert_ne!(overrunning, successor, "a second acquisition is a second token");

        lock.release("job-queue", overrunning).await.unwrap();
        assert!(
            lock.try_acquire("job-queue", TTL).await.unwrap().is_none(),
            "the stale holder's release must not free the lock its successor holds"
        );
        lock.release("job-queue", successor).await.unwrap();
        assert!(lock.try_acquire("job-queue", TTL).await.unwrap().is_some(), "the holder itself still releases it");
    }

    #[tokio::test]
    async fn releasing_an_unheld_lock_is_not_an_error() {
        let lock = InMemoryJobLock::new();
        lock.release("never-held", LockToken::new()).await.unwrap();
    }
}
