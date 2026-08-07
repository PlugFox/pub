//! `JobRepo` over Postgres: durable background-job state (decision 03, decision 07 mirror).
//!
//! Everything here is written as an **upsert with additive counters**, never a read-then-write.
//! A job checkpoints while it runs, and the run may die between two checkpoints; `processed =
//! jobs.processed + excluded.processed` records what actually happened, whereas an absolute
//! write would need the caller to hold a total it may have read before another leader's write.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::jobs::{JobOutcome, JobProgress, JobState};
use pub_core::traits::JobRepo;
use pub_core::{Error, Result};
use sqlx::PgPool;

use super::{db_err, q};

/// All job columns, in [`JobRow`] order.
const COLS: &str = "name, cursor, phase, last_run_at, last_success_at, last_error, runs, processed, failures, \
                    updated_at";

/// Postgres-backed [`JobRepo`].
#[derive(Debug, Clone)]
pub struct PgJobRepo {
    pool: PgPool,
}

impl PgJobRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct JobRow {
    name: String,
    cursor: Option<String>,
    phase: String,
    last_run_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    runs: i64,
    processed: i64,
    failures: i64,
    updated_at: DateTime<Utc>,
}

impl From<JobRow> for JobState {
    fn from(row: JobRow) -> Self {
        JobState {
            name: row.name,
            cursor: row.cursor,
            phase: row.phase,
            last_run_at: row.last_run_at,
            last_success_at: row.last_success_at,
            last_error: row.last_error,
            runs: row.runs,
            processed: row.processed,
            failures: row.failures,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl JobRepo for PgJobRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<JobState>> {
        let row: Option<JobRow> = sqlx::query_as(q!("SELECT {COLS} FROM jobs WHERE name = $1"))
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list(&self) -> Result<Vec<JobState>> {
        let rows: Vec<JobRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM jobs ORDER BY name")).fetch_all(&self.pool).await.map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn begin_run(&self, name: &str, now: DateTime<Utc>) -> Result<JobState> {
        // Creates the row on first use. Nothing but `runs`, `last_run_at`, and `updated_at`
        // moves: the cursor is what the caller is about to *read* in order to resume.
        let row: JobRow = sqlx::query_as(q!(
            "INSERT INTO jobs (name, cursor, phase, last_run_at, runs, processed, failures, updated_at) \
             VALUES ($1, NULL, '', $2, 1, 0, 0, $2) \
             ON CONFLICT (name) DO UPDATE SET runs = jobs.runs + 1, last_run_at = excluded.last_run_at, \
             updated_at = excluded.updated_at RETURNING {COLS}"
        ))
        .bind(name)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.into())
    }

    async fn checkpoint(&self, name: &str, progress: &JobProgress, now: DateTime<Utc>) -> Result<JobState> {
        let row: JobRow =
            sqlx::query_as(q!("INSERT INTO jobs (name, cursor, phase, runs, processed, failures, updated_at) \
             VALUES ($1, $2, $3, 0, $4, $5, $6) \
             ON CONFLICT (name) DO UPDATE SET cursor = excluded.cursor, phase = excluded.phase, \
             processed = jobs.processed + excluded.processed, failures = jobs.failures + excluded.failures, \
             updated_at = excluded.updated_at RETURNING {COLS}"))
            .bind(name)
            .bind(progress.cursor.as_deref())
            .bind(&progress.phase)
            .bind(progress.processed as i64)
            .bind(progress.failed as i64)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.into())
    }

    async fn finish_run(&self, name: &str, outcome: JobOutcome, now: DateTime<Utc>) -> Result<JobState> {
        let (success_at, error) = match &outcome {
            // A success clears the previous failure; leaving it would make the admin surface
            // show an error that has already been recovered from.
            JobOutcome::Success => (Some(now), None),
            JobOutcome::Failure(message) => (None, Some(message.as_str())),
        };
        let row: Option<JobRow> = sqlx::query_as(q!(
            "UPDATE jobs SET last_success_at = COALESCE($1, last_success_at), last_error = $2, updated_at = $3 \
             WHERE name = $4 RETURNING {COLS}"
        ))
        .bind(success_at)
        .bind(error)
        .bind(now)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.ok_or_else(|| Error::NotFound { what: format!("job {name}") })?.into())
    }
}
