//! `JobLock` over SQLite's `job_locks` table — leader election that leaves the process
//! ([decision 36](../../../../docs/decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check)).
//!
//! A SQLite *deployment* does not use this: it is single-instance by construction and takes the
//! in-process lock, which a restart clears. This implementation exists so the lock's properties
//! are asserted by the same contract functions on both dialects rather than only on the one that
//! is harder to run.
//!
//! Two things are the same as in the Postgres sibling, deliberately. Acquisition is **one
//! statement**, so there is no read-then-write window for two callers to interleave; and expiry
//! is written from the **database's** clock, never the caller's, because a lock whose lifetime
//! depends on which process asked is a lock two processes can hold.

use std::time::Duration;

use async_trait::async_trait;
use pub_core::Result;
use pub_core::traits::{JobLock, LockToken};
use sqlx::SqlitePool;

use super::{db_err, q};

/// The database's own `now`, in this schema's fixed-width RFC3339 UTC shape.
///
/// `%f` renders `SS.mmm`; the trailing `000` pads the fraction to the six digits every
/// timestamp column in this schema carries, so string comparison stays time comparison.
const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')";

/// SQLite-backed [`JobLock`].
#[derive(Debug, Clone)]
pub struct SqliteJobLock {
    pool: SqlitePool,
}

impl SqliteJobLock {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl JobLock for SqliteJobLock {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<Option<LockToken>> {
        let token = LockToken::new();
        // `±NNN.NNNN seconds` is the finest modifier SQLite's date functions accept — there is
        // no `milliseconds` unit, and asking for one returns NULL rather than an error.
        let ttl_secs = format!("+{:.3} seconds", ttl.as_secs_f64().max(0.001));
        // One statement, and the `WHERE` on the conflict branch is the whole of the mutual
        // exclusion: either this call's row wins (free name, or a lease that has expired) or
        // nothing is written at all. `RETURNING token` is how the caller learns which happened
        // without a second read — an unheld name and a name held by *this very token* would
        // otherwise be indistinguishable.
        let held: Option<String> =
            sqlx::query_scalar(q!("INSERT INTO job_locks (name, token, expires_at, acquired_at) \
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%f000Z', 'now', ?3), {NOW}) \
             ON CONFLICT (name) DO UPDATE SET \
                 token = excluded.token, expires_at = excluded.expires_at, acquired_at = excluded.acquired_at \
             WHERE job_locks.expires_at <= {NOW} \
             RETURNING token"))
            .bind(name)
            .bind(token.to_string())
            .bind(ttl_secs)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(held.map(|_| token))
    }

    async fn release(&self, name: &str, token: LockToken) -> Result<()> {
        // The token in the predicate is the ownership check the trait promises: a holder whose
        // TTL expired while it was still working deletes nothing, because the row it would free
        // now carries its successor's token.
        sqlx::query("DELETE FROM job_locks WHERE name = ?1 AND token = ?2")
            .bind(name)
            .bind(token.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}
