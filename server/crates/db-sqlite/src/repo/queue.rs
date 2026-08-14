//! `JobQueueRepo` over SQLite: the durable work queue (decision 26).
//!
//! Exclusivity of a claim comes from the engine here rather than from a locking clause: SQLite
//! serializes writers, so the claim's `UPDATE … WHERE id IN (SELECT … LIMIT ?) RETURNING` is
//! atomic against every other claimer by construction and needs no `SKIP LOCKED` (the Postgres
//! sibling does, and has one). What that buys is the property the worker relies on without
//! re-checking: two drains never receive the same item, so one publish never notifies everybody
//! twice and one sign-in never sends two codes.
//!
//! Every write here also carries a state predicate, because the states are not interchangeable:
//! `complete` touches only a row that is still `running`, which is what keeps a `suppressed`
//! row (S-04.a/S-31) from being resurrected into something deliverable by a late `Retry`.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone as _, Utc};
use pub_core::queue::{
    JobKind, NewQueuedJob, QueueOutcome, QueuePurged, QueueRetention, QueueState, QueuedJob, QueuedJobId,
};
use pub_core::traits::JobQueueRepo;
use pub_core::{Error, Result};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use super::{db_err, parse_col, parse_ts, parse_ts_opt, q};

/// Largest batch one [`JobQueueRepo::claim`] hands back; larger requests are clamped.
///
/// A batch is held in memory and dispatched item by item, so an over-eager configured batch
/// size should cost a shorter tick, not an error the operator has to decode.
const MAX_CLAIM_BATCH: u32 = 500;

/// All queue columns, in [`QueueRow`] order.
const COLS: &str = "id, kind, priority, payload, state, attempts, run_after, locked_until, dedupe_key, last_error, \
                    created_at, updated_at";

/// SQLite-backed [`JobQueueRepo`].
#[derive(Debug, Clone)]
pub struct SqliteJobQueueRepo {
    pool: SqlitePool,
}

impl SqliteJobQueueRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Leases up to `limit` runnable items of one lane, oldest-runnable first.
    ///
    /// The predicate is exactly the claim index's prefix — `kind`, `priority`, `run_after` —
    /// and the `ORDER BY` is the rest of it, so the statement is a seek that stops at `limit`
    /// instead of a scan of the lane. The `state` literal is what lets the partial index be
    /// inferred, the same reason retention spells its states out.
    async fn claim_lane(
        &self,
        kinds: &[JobKind],
        priority: i32,
        limit: u32,
        lease: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<QueuedJob>> {
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new("UPDATE job_queue SET state = 'running', attempts = attempts + 1, locked_until = ");
        query.push_bind(super::ts(deadline(now, lease)));
        query.push(", updated_at = ").push_bind(super::ts(now));
        query.push(" WHERE id IN (SELECT id FROM job_queue WHERE state = 'pending' AND priority = ");
        query.push_bind(priority);
        query.push(" AND run_after <= ").push_bind(super::ts(now));
        query.push(" AND kind IN (");
        let mut separated = query.separated(", ");
        for kind in kinds {
            separated.push_bind(kind.as_str());
        }
        query.push(") ORDER BY run_after, id LIMIT ").push_bind(i64::from(limit));
        query.push(") RETURNING ").push(COLS);

        let rows: Vec<QueueRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let mut claimed: Vec<QueuedJob> = rows.into_iter().map(TryInto::try_into).collect::<Result<_>>()?;
        // `RETURNING` makes no ordering promise; the caller was promised the claim order.
        claimed.sort_by_key(|job| (job.run_after, job.id));
        Ok(claimed)
    }
}

#[derive(sqlx::FromRow)]
struct QueueRow {
    id: String,
    kind: String,
    priority: i32,
    payload: String,
    state: String,
    attempts: i64,
    run_after: String,
    locked_until: Option<String>,
    dedupe_key: Option<String>,
    last_error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<QueueRow> for QueuedJob {
    type Error = Error;

    fn try_from(row: QueueRow) -> Result<Self> {
        Ok(QueuedJob {
            id: parse_col(&row.id)?,
            kind: parse_col::<JobKind>(&row.kind)?,
            priority: row.priority,
            payload: serde_json::from_str(&row.payload)
                .map_err(|err| Error::Database { message: format!("corrupt queue payload: {err}") })?,
            state: parse_col::<QueueState>(&row.state)?,
            attempts: row.attempts,
            run_after: parse_ts(&row.run_after)?,
            locked_until: parse_ts_opt(row.locked_until.as_deref())?,
            dedupe_key: row.dedupe_key,
            last_error: row.last_error,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct DepthRow {
    kind: String,
    state: String,
    count: i64,
}

/// The instant an absurd lease or backoff saturates to.
///
/// Deliberately not `DateTime::<Utc>::MAX_UTC`: a six-digit year formats with a leading `+`,
/// which sorts *before* every real timestamp in the TEXT comparison this schema's ordering
/// rests on — a saturated deadline would land in the past.
fn horizon() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(9999, 12, 31, 23, 59, 59).single().expect("the end of year 9999 is a valid UTC instant")
}

/// `now + delta`, saturating at [`horizon`].
fn deadline(now: DateTime<Utc>, delta: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(delta).ok().and_then(|delta| now.checked_add_signed(delta)).unwrap_or_else(horizon)
}

#[async_trait]
impl JobQueueRepo for SqliteJobQueueRepo {
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
        let stamp = super::ts(now);
        // DO NOTHING rather than DO UPDATE: a retried enqueue must not disturb the item that is
        // already there — it may be running, or already done. The partial index's predicate is
        // repeated in the conflict target because that is how SQLite infers a partial index.
        let row: Option<QueueRow> = sqlx::query_as(q!(
            "INSERT INTO job_queue (id, kind, priority, payload, state, attempts, run_after, locked_until, \
             dedupe_key, last_error, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 0, ?, NULL, ?, NULL, ?, ?) \
             ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING RETURNING {COLS}"
        ))
        .bind(QueuedJobId::new().to_string())
        .bind(new.kind.as_str())
        .bind(new.priority)
        .bind(payload)
        .bind(new.state.as_str())
        .bind(super::ts(new.run_after.unwrap_or(now)))
        .bind(new.dedupe_key.as_deref())
        .bind(&stamp)
        .bind(&stamp)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get(&self, id: QueuedJobId) -> Result<Option<QueuedJob>> {
        let row: Option<QueueRow> = sqlx::query_as(q!("SELECT {COLS} FROM job_queue WHERE id = ?"))
            .bind(id.to_string())
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
        let mut remaining = limit.min(MAX_CLAIM_BATCH);
        let mut claimed: Vec<QueuedJob> = Vec::new();
        // One statement per lane, drained in order, instead of one statement ordering by
        // priority. Two things come out of it. The **equality** on `priority` is what lets
        // `job_queue_claim_prio_idx (kind, priority, run_after, id)` use `run_after` as a seek
        // bound: with `priority` unconstrained the engine can only scan every pending entry of
        // each kind and filter, which measured 6.3 ms against 0.007 ms on a 200k-row backlog a
        // relay outage had backed off into the future — inside a write statement that holds
        // SQLite's single writer, up to 64 times per tick. And draining a lane before looking
        // at the next is strictly stronger than ordering one batch: interactive work is
        // exhausted before any bulk item is leased.
        for level in NewQueuedJob::LEVELS {
            if remaining == 0 {
                break;
            }
            let batch = self.claim_lane(kinds, level, remaining, lease, now).await?;
            remaining = remaining.saturating_sub(u32::try_from(batch.len()).unwrap_or(u32::MAX));
            claimed.extend(batch);
        }
        Ok(claimed)
    }

    async fn complete(
        &self,
        id: QueuedJobId,
        outcome: QueueOutcome,
        backoff: Duration,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // A success clears the previous error for the same reason `JobRepo::finish_run` does:
        // leaving it would show the admin surface a failure that has been recovered from.
        let (state, run_after) = match &outcome {
            QueueOutcome::Done => (QueueState::Done, None),
            QueueOutcome::Retry(_) => (QueueState::Pending, Some(super::ts(deadline(now, backoff)))),
            QueueOutcome::Dead(_) => (QueueState::Dead, None),
        };
        sqlx::query(
            "UPDATE job_queue SET state = ?, run_after = COALESCE(?, run_after), locked_until = NULL, \
             last_error = ?, updated_at = ? WHERE id = ? AND state = 'running'",
        )
        .bind(state.as_str())
        .bind(run_after)
        .bind(outcome.message())
        .bind(super::ts(now))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn reap_expired_leases(&self, now: DateTime<Utc>) -> Result<u64> {
        // `attempts` is left where it is: the attempt was spent when the lease was taken, and
        // refunding it is how an item that kills its worker retries forever.
        let result = sqlx::query(
            "UPDATE job_queue SET state = 'pending', locked_until = NULL, updated_at = ? \
             WHERE state = 'running' AND locked_until <= ?",
        )
        .bind(super::ts(now))
        .bind(super::ts(now))
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
        // rather than a bound parameter: each state has its own partial retention index, and
        // SQLite can only use one when the statement's predicate visibly implies the index's.
        // That matters here more than anywhere else in this file — a delete is a write, and an
        // unindexed one holds the single write lock against every concurrent publish and
        // sign-in for the length of its scan, on a table that only grows.
        //
        // The `id IN (SELECT … LIMIT ?)` shape is the bound, and it is a subquery rather than
        // `DELETE … LIMIT` because the latter needs `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`, which is
        // not a default build option (decision 30). The inner SELECT keeps the state literal, so
        // the partial index still serves it.
        let mut purged = QueuePurged::default();
        for (sql, before, counter) in [
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'suppressed' AND updated_at < ? LIMIT ?)",
                retention.suppressed_before,
                &mut purged.suppressed,
            ),
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'done' AND updated_at < ? LIMIT ?)",
                retention.done_before,
                &mut purged.done,
            ),
            (
                "DELETE FROM job_queue WHERE id IN \
                 (SELECT id FROM job_queue WHERE state = 'dead' AND updated_at < ? LIMIT ?)",
                retention.dead_before,
                &mut purged.dead,
            ),
        ] {
            let result = sqlx::query(sql)
                .bind(super::ts(before))
                .bind(i64::from(batch))
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
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
