//! `JobLock` over the `job_locks` table — the lock every Postgres deployment runs on
//! ([decision 36](../../../../docs/decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check)).
//!
//! Deliberately **not** `pg_try_advisory_lock`. An advisory lock is held by the session that
//! took it, so an implementation over a pool has to pin one connection for as long as the lock
//! is held — and the per-name publish lock is keyed on the package, so the number of held locks
//! is the number of simultaneous publishes. A pooled implementation that does *not* pin is
//! worse: two acquisitions that land on the same session are re-entrant and both succeed.
//! Advisory locks also have no TTL, which is the whole of this trait's ownership model.
//!
//! Two properties carry the implementation, and both are in the SQL rather than in Rust:
//!
//! 1. **Acquisition is one statement.** The conditional `ON CONFLICT … DO UPDATE … WHERE` either
//!    writes this call's token or writes nothing; there is no read-then-write for two callers to
//!    interleave, and no transaction to hold open across the caller's work.
//! 2. **Expiry is stamped by the database's clock.** `now()` here is the transaction's start
//!    time on the server every replica already shares. Two instances with skewed clocks
//!    computing their own `expires_at` is precisely the double-holder bug this table removes.

use std::time::Duration;

use async_trait::async_trait;
use pub_core::Result;
use pub_core::traits::{JobLock, LockToken};
use sqlx::PgPool;
use uuid::Uuid;

use super::db_err;

/// Postgres-backed [`JobLock`].
#[derive(Debug, Clone)]
pub struct PgJobLock {
    pool: PgPool,
}

impl PgJobLock {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl JobLock for PgJobLock {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn try_acquire(&self, name: &str, ttl: Duration) -> Result<Option<LockToken>> {
        let token = LockToken::new();
        // `make_interval` rather than string concatenation: the TTL is a number, and a number
        // that has to be rendered into SQL text is a number that can carry something else.
        let ttl_secs = ttl.as_secs_f64().max(0.001);
        // `RETURNING token` distinguishes "this call took the lock" from "somebody else holds a
        // live lease" — the conflict branch writes nothing when the `WHERE` fails, so no row
        // comes back at all.
        let held: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO job_locks (name, token, expires_at, acquired_at) \
             VALUES ($1, $2, now() + make_interval(secs => $3), now()) \
             ON CONFLICT (name) DO UPDATE SET \
                 token = excluded.token, expires_at = excluded.expires_at, acquired_at = excluded.acquired_at \
             WHERE job_locks.expires_at <= now() \
             RETURNING token",
        )
        .bind(name)
        .bind(token.as_uuid())
        .bind(ttl_secs)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(held.map(|_| token))
    }

    async fn release(&self, name: &str, token: LockToken) -> Result<()> {
        // The token in the predicate is the ownership check the trait promises: a holder that
        // overran its TTL frees nothing, because the row now carries its successor's token.
        sqlx::query("DELETE FROM job_locks WHERE name = $1 AND token = $2")
            .bind(name)
            .bind(token.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}
