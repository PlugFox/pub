//! `JobQueueRepo` over Postgres: the durable work queue (decision 26).
//!
//! The one substantive difference from the SQLite sibling is the claim. SQLite gets
//! exclusivity from its single writer; here concurrent drains are a real shape, so the claim
//! selects its batch `FOR UPDATE SKIP LOCKED` — a claimer walks past rows another transaction
//! already holds instead of blocking on them or, worse, leasing them twice. That is written
//! now, before multi-instance deployment exists, because it is what makes the queue correct the
//! moment a second replica drains, and retrofitting a claim strategy onto a table that is
//! already carrying sign-in mail is a change to a live path.
//!
//! Every write carries a state predicate: `complete` touches only a row that is still
//! `running`, which is what keeps a `suppressed` row (S-04.a/S-31) from being resurrected into
//! something deliverable by a late `Retry`.
//!
//! On this dialect that guard was never enough on its own, and the header said otherwise
//! ([D45](../../../../docs/roadmap.md)): with concurrent drains a running row may be running
//! under *another* worker's lease. Since [decision 36](../../../../docs/decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check)
//! the claim's `attempts` fences the completion, and the statement reports whether it applied.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone as _, Utc};
use pub_core::queue::{
    JobKind, NewQueuedJob, QueueOutcome, QueuePurged, QueueRetention, QueueState, QueuedJob, QueuedJobId,
};
use pub_core::traits::JobQueueRepo;
use pub_core::{Error, Result};
use sqlx::PgPool;
use uuid::Uuid;

use super::{db_err, parse_col, q};

/// Largest batch one [`JobQueueRepo::claim`] hands back; larger requests are clamped.
///
/// A batch is held in memory and dispatched item by item, so an over-eager configured batch
/// size should cost a shorter tick, not an error the operator has to decode.
const MAX_CLAIM_BATCH: u32 = 500;

/// All queue columns, in [`QueueRow`] order (`JSONB` reads back as text).
const COLS: &str = "id, kind, priority, payload::text AS payload, state, attempts, run_after, locked_until, \
                    dedupe_key, last_error, created_at, updated_at";

/// Postgres-backed [`JobQueueRepo`].
#[derive(Debug, Clone)]
pub struct PgJobQueueRepo {
    pool: PgPool,
}

impl PgJobQueueRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Leases up to `limit` runnable items of one lane, oldest-runnable first.
    ///
    /// The predicate is exactly the claim index's prefix — `kind`, `priority`, `run_after` —
    /// and the `ORDER BY` is the rest of it, so the statement is an index scan that stops at
    /// `limit` instead of one over the whole lane. `SKIP LOCKED` so a concurrent drain takes
    /// the next rows instead of blocking on these.
    async fn claim_lane(
        &self,
        names: &[String],
        priority: i32,
        limit: u32,
        lease: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<QueuedJob>> {
        let rows: Vec<QueueRow> = sqlx::query_as(q!(
            "UPDATE job_queue SET state = 'running', attempts = attempts + 1, locked_until = $1, updated_at = $2 \
             WHERE id IN (SELECT id FROM job_queue WHERE state = 'pending' AND priority = $3 AND run_after <= $2 \
             AND kind = ANY($4) ORDER BY run_after, id LIMIT $5 FOR UPDATE SKIP LOCKED) RETURNING {COLS}"
        ))
        .bind(deadline(now, lease))
        .bind(now)
        .bind(priority)
        .bind(names)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let mut claimed: Vec<QueuedJob> = rows.into_iter().map(TryInto::try_into).collect::<Result<_>>()?;
        // `RETURNING` makes no ordering promise; the caller was promised the claim order.
        claimed.sort_by_key(|job| (job.run_after, job.id));
        Ok(claimed)
    }
}

#[derive(sqlx::FromRow)]
struct QueueRow {
    id: Uuid,
    kind: String,
    priority: i32,
    payload: String,
    state: String,
    attempts: i64,
    run_after: DateTime<Utc>,
    locked_until: Option<DateTime<Utc>>,
    dedupe_key: Option<String>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<QueueRow> for QueuedJob {
    type Error = Error;

    fn try_from(row: QueueRow) -> Result<Self> {
        Ok(QueuedJob {
            id: QueuedJobId::from_uuid(row.id),
            kind: parse_col::<JobKind>(&row.kind)?,
            priority: row.priority,
            payload: serde_json::from_str(&row.payload)
                .map_err(|err| Error::Database { message: format!("corrupt queue payload: {err}") })?,
            state: parse_col::<QueueState>(&row.state)?,
            attempts: row.attempts,
            run_after: row.run_after,
            locked_until: row.locked_until,
            dedupe_key: row.dedupe_key,
            last_error: row.last_error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct DepthRow {
    kind: String,
    state: String,
    count: i64,
}

/// The instant an absurd lease or backoff saturates to — chrono's `MAX_UTC` is not
/// representable in `TIMESTAMPTZ`, the same reason [`super::window_floor`] exists.
fn horizon() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(9999, 12, 31, 23, 59, 59).single().expect("the end of year 9999 is a valid UTC instant")
}

/// `now + delta`, saturating at [`horizon`].
fn deadline(now: DateTime<Utc>, delta: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(delta).ok().and_then(|delta| now.checked_add_signed(delta)).unwrap_or_else(horizon)
}

#[async_trait]
impl JobQueueRepo for PgJobQueueRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn enqueue(&self, new: &NewQueuedJob, now: DateTime<Utc>) -> Result<Option<QueuedJob>> {
        if !new.state.is_admissible() {
            return Err(Error::Invalid { message: format!("cannot enqueue a job in state {}", new.state) });
        }
        // The claim drains one lane at a time, so a row outside the lane set is a row nothing
        // will ever claim — invisible work, which is worse than a refused enqueue.
        if !NewQueuedJob::is_claimable_priority(new.priority) {
            return Err(Error::Invalid {
                message: format!("priority {} is not a claim lane {:?}", new.priority, NewQueuedJob::LEVELS),
            });
        }
        let payload = serde_json::to_string(&new.payload)
            .map_err(|err| Error::Internal { message: format!("failed to encode queue payload: {err}") })?;
        // DO NOTHING rather than DO UPDATE: a retried enqueue must not disturb the item that is
        // already there — it may be running, or already done. The index predicate is repeated in
        // the conflict target because that is how a partial unique index is inferred.
        let row: Option<QueueRow> = sqlx::query_as(q!(
            "INSERT INTO job_queue (id, kind, priority, payload, state, attempts, run_after, locked_until, \
             dedupe_key, last_error, created_at, updated_at) \
             VALUES ($1, $2, $3, $4::jsonb, $5, 0, $6, NULL, $7, NULL, $8, $8) \
             ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING RETURNING {COLS}"
        ))
        .bind(*QueuedJobId::new().as_uuid())
        .bind(new.kind.as_str())
        .bind(new.priority)
        .bind(payload)
        .bind(new.state.as_str())
        .bind(new.run_after.unwrap_or(now))
        .bind(new.dedupe_key.as_deref())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get(&self, id: QueuedJobId) -> Result<Option<QueuedJob>> {
        let row: Option<QueueRow> = sqlx::query_as(q!("SELECT {COLS} FROM job_queue WHERE id = $1"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn claim(
        &self,
        kinds: &[JobKind],
        limit: u32,
        lease: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<QueuedJob>> {
        if kinds.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let names: Vec<String> = kinds.iter().map(|kind| kind.as_str().to_owned()).collect();
        let mut remaining = limit.min(MAX_CLAIM_BATCH);
        let mut claimed: Vec<QueuedJob> = Vec::new();
        // One statement per lane, drained in order, instead of one statement ordering by
        // priority — the same shape and the same reason as the SQLite sibling. The **equality**
        // on `priority` is what lets `job_queue_claim_prio_idx (kind, priority, run_after, id)`
        // use `run_after` as a scan bound; with `priority` unconstrained the index degrades to
        // its `kind` prefix and every claim reads the whole pending partition of each kind.
        // Draining a lane before the next one is looked at is also strictly stronger than
        // ordering inside one batch: interactive work is exhausted before bulk is leased.
        for level in NewQueuedJob::LEVELS {
            if remaining == 0 {
                break;
            }
            let batch = self.claim_lane(&names, level, remaining, lease, now).await?;
            remaining = remaining.saturating_sub(u32::try_from(batch.len()).unwrap_or(u32::MAX));
            claimed.extend(batch);
        }
        Ok(claimed)
    }

    async fn complete(
        &self,
        id: QueuedJobId,
        attempts: i64,
        outcome: QueueOutcome,
        backoff: Duration,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        // A success clears the previous error for the same reason `JobRepo::finish_run` does:
        // leaving it would show the admin surface a failure that has been recovered from.
        let (state, run_after) = match &outcome {
            QueueOutcome::Done => (QueueState::Done, None),
            QueueOutcome::Retry(_) => (QueueState::Pending, Some(deadline(now, backoff))),
            QueueOutcome::Dead(_) => (QueueState::Dead, None),
        };
        // `attempts` fences the claim (D45, decision 36). This is the dialect where two drains
        // are a real shape: a worker whose lease expired, was reaped, and whose item was
        // re-claimed by another instance would otherwise mark that row `done` mid-delivery,
        // clear the lease and erase the `last_error` the operator would have seen.
        let result = sqlx::query(
            "UPDATE job_queue SET state = $1, run_after = COALESCE($2::timestamptz, run_after), locked_until = NULL, \
             last_error = $3, updated_at = $4 WHERE id = $5 AND state = 'running' AND attempts = $6",
        )
        .bind(state.as_str())
        .bind(run_after)
        .bind(outcome.message())
        .bind(now)
        .bind(*id.as_uuid())
        .bind(attempts)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn reap_expired_leases(&self, now: DateTime<Utc>) -> Result<u64> {
        // `attempts` is left where it is: the attempt was spent when the lease was taken, and
        // refunding it is how an item that kills its worker retries forever.
        let result = sqlx::query(
            "UPDATE job_queue SET state = 'pending', locked_until = NULL, updated_at = $1 \
             WHERE state = 'running' AND locked_until <= $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn purge(&self, retention: &QueueRetention, batch: u32) -> Result<QueuePurged> {
        // `suppressed` first, deliberately: those rows are filed by an unauthenticated endpoint,
        // one per policy-rejected sign-in, each carrying the attempted address in the clear
        // (S-04.a), and they have the shortest window in the product. If one of these statements
        // fails, the caller stops the pass — so the order decides which lane loses a pass to an
        // error, and it must not be that one.
        //
        // One statement per state rather than one `OR`-ed DELETE, and the state as a **literal**
        // rather than a bound parameter: each state has its own partial retention index, and the
        // planner can only use one when the statement's predicate visibly implies the index's.
        // The caller reports the dead-letter count separately, because that deletion is the one
        // that destroys a record an operator may still need.
        //
        // The `id IN (SELECT … LIMIT $2)` shape is decision 30's batch bound. It matters less here
        // than on SQLite — Postgres readers are not blocked by a writer — and it is kept identical
        // across both dialects on purpose: a retention pass that converges in a different number
        // of statements per backend is one the contract suite cannot assert the same way.
        let mut purged = QueuePurged::default();
        for (sql, before, counter) in [
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'suppressed' AND updated_at < $1 LIMIT $2)",
                retention.suppressed_before,
                &mut purged.suppressed,
            ),
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'done' AND updated_at < $1 LIMIT $2)",
                retention.done_before,
                &mut purged.done,
            ),
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'dead' AND updated_at < $1 LIMIT $2)",
                retention.dead_before,
                &mut purged.dead,
            ),
        ] {
            let result =
                sqlx::query(sql).bind(before).bind(i64::from(batch)).execute(&self.pool).await.map_err(db_err)?;
            *counter = result.rows_affected();
        }
        Ok(purged)
    }

    async fn depth(&self) -> Result<Vec<(JobKind, QueueState, i64)>> {
        let rows: Vec<DepthRow> = sqlx::query_as(
            "SELECT kind, state, COUNT(*) AS count FROM job_queue GROUP BY kind, state ORDER BY kind, state",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter()
            .map(|row| Ok((parse_col::<JobKind>(&row.kind)?, parse_col::<QueueState>(&row.state)?, row.count)))
            .collect()
    }
}
