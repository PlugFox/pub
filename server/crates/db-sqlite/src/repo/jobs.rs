//! `JobRepo` over SQLite: durable background-job state (decision 03, decision 07 mirror).
//!
//! Everything here is written as an **upsert with additive counters**, never a read-then-write.
//! A job checkpoints while it runs, and the run may die between two checkpoints; `processed =
//! processed + ?` records what actually happened, whereas `processed = ?` would need the caller
//! to hold a total it may have read before another leader's write.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::JobRepo;
use pub_core::{Error, Result};
use sqlx::SqlitePool;

use super::{db_err, parse_ts, parse_ts_opt, q};

/// All job columns, in [`JobRow`] order.
const COLS: &str = "name, cursor, phase, last_run_at, last_success_at, last_error, runs, processed, failures, \
                    updated_at";

/// SQLite-backed [`JobRepo`].
#[derive(Debug, Clone)]
pub struct SqliteJobRepo {
    pool: SqlitePool,
}

impl SqliteJobRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct JobRow {
    name: String,
    cursor: Option<String>,
    phase: String,
    last_run_at: Option<String>,
    last_success_at: Option<String>,
    last_error: Option<String>,
    runs: i64,
    processed: i64,
    failures: i64,
    updated_at: String,
}

impl TryFrom<JobRow> for JobState {
    type Error = Error;

    fn try_from(row: JobRow) -> Result<Self> {
        Ok(JobState {
            name: row.name,
            cursor: row.cursor,
            phase: row.phase,
            last_run_at: parse_ts_opt(row.last_run_at.as_deref())?,
            last_success_at: parse_ts_opt(row.last_success_at.as_deref())?,
            last_error: row.last_error,
            runs: row.runs,
            processed: row.processed,
            failures: row.failures,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[async_trait]
impl JobRepo for SqliteJobRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<JobState>> {
        let row: Option<JobRow> = sqlx::query_as(q!("SELECT {COLS} FROM jobs WHERE name = ?"))
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self) -> Result<Vec<JobState>> {
        let rows: Vec<JobRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM jobs ORDER BY name")).fetch_all(&self.pool).await.map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn begin_run(&self, name: &str, now: DateTime<Utc>) -> Result<JobState> {
        let stamp = super::ts(now);
        // Creates the row on first use. Nothing but `runs`, `last_run_at`, and `updated_at`
        // moves: the cursor is what the caller is about to *read* in order to resume.
        let row: JobRow = sqlx::query_as(q!(
            "INSERT INTO jobs (name, cursor, phase, last_run_at, runs, processed, failures, updated_at) \
             VALUES (?, NULL, '', ?, 1, 0, 0, ?) \
             ON CONFLICT (name) DO UPDATE SET runs = jobs.runs + 1, last_run_at = excluded.last_run_at, \
             updated_at = excluded.updated_at RETURNING {COLS}"
        ))
        .bind(name)
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_into()
    }

    async fn checkpoint(&self, name: &str, progress: &JobProgress, now: DateTime<Utc>) -> Result<JobState> {
        let stamp = super::ts(now);
        let row: JobRow =
            sqlx::query_as(q!("INSERT INTO jobs (name, cursor, phase, runs, processed, failures, updated_at) \
             VALUES (?, ?, ?, 0, ?, ?, ?) \
             ON CONFLICT (name) DO UPDATE SET cursor = excluded.cursor, phase = excluded.phase, \
             processed = jobs.processed + excluded.processed, failures = jobs.failures + excluded.failures, \
             updated_at = excluded.updated_at RETURNING {COLS}"))
            .bind(name)
            .bind(progress.cursor.as_deref())
            .bind(&progress.phase)
            .bind(progress.processed as i64)
            .bind(progress.failed as i64)
            .bind(&stamp)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        row.try_into()
    }

    async fn finish_run(&self, name: &str, outcome: JobOutcome, now: DateTime<Utc>) -> Result<JobState> {
        let stamp = super::ts(now);
        let (success_at, error) = match &outcome {
            // A success clears the previous failure; leaving it would make the admin surface
            // show an error that has already been recovered from.
            JobOutcome::Success => (Some(stamp.clone()), None),
            JobOutcome::Failure(message) => (None, Some(message.as_str())),
        };
        let row: Option<JobRow> = sqlx::query_as(q!(
            "UPDATE jobs SET last_success_at = COALESCE(?, last_success_at), last_error = ?, updated_at = ? \
             WHERE name = ? RETURNING {COLS}"
        ))
        .bind(success_at)
        .bind(error)
        .bind(&stamp)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("job {name}") })?.try_into()
    }
}
