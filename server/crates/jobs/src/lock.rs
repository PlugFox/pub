//! In-memory [`JobLock`] — trivial leader election for a single-instance deployment.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use pub_core::Result;
use pub_core::traits::JobLock;
use tokio::time::Instant;

/// Named locks with expiry, held in process memory. Only correct for a single instance —
/// multi-instance deployments use the Redis or PG advisory lock implementations (later).
#[derive(Debug, Default)]
pub struct InMemoryJobLock {
    /// Lock name → deadline until which the lock is considered held.
    held: Mutex<HashMap<String, Instant>>,
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

    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<bool> {
        let mut held = self.held.lock().expect("lock table mutex poisoned");
        let now = Instant::now();
        match held.get(name) {
            Some(deadline) if *deadline > now => Ok(false),
            _ => {
                held.insert(name.to_owned(), now + ttl);
                Ok(true)
            }
        }
    }

    async fn release(&self, name: &str) -> Result<()> {
        self.held.lock().expect("lock table mutex poisoned").remove(name);
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
        assert!(lock.try_acquire("gc", TTL).await.unwrap());
        assert!(!lock.try_acquire("gc", TTL).await.unwrap(), "second acquire must fail while held");
        lock.release("gc").await.unwrap();
        assert!(lock.try_acquire("gc", TTL).await.unwrap(), "release must free the lock");
    }

    #[tokio::test]
    async fn different_names_do_not_contend() {
        let lock = InMemoryJobLock::new();
        assert!(lock.try_acquire("gc", TTL).await.unwrap());
        assert!(lock.try_acquire("reindex", TTL).await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_lock_can_be_reacquired() {
        let lock = InMemoryJobLock::new();
        assert!(lock.try_acquire("gc", Duration::from_millis(50)).await.unwrap());
        assert!(!lock.try_acquire("gc", TTL).await.unwrap());
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(lock.try_acquire("gc", TTL).await.unwrap(), "a crashed holder's TTL must free the lock");
    }

    #[tokio::test]
    async fn releasing_an_unheld_lock_is_not_an_error() {
        let lock = InMemoryJobLock::new();
        lock.release("never-held").await.unwrap();
    }
}
