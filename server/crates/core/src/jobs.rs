//! Durable background-job state (decision 03 leader-locked scheduler, decision 07 mirror).
//!
//! A job is identified by its **name** — the same string the [`crate::traits::JobLock`] leader
//! election uses — and owns one row holding where it got to and how it has been doing. The row
//! exists so that a restart *resumes* rather than restarts: a full mirror sweep over 60 000
//! upstream package names cannot afford to begin again every time a pod is rescheduled.
//!
//! Three properties shape the type:
//!
//! - **The cursor is opaque to everybody but the job.** It is whatever the job needs to resume
//!   — a package name, an upstream page token, a timestamp — and the repository never
//!   interprets it. Storing a typed cursor per job would put job logic in the schema.
//! - **Counters are monotonic deltas, never absolute writes.** A run reports "I processed 40
//!   more"; the repository adds. Two checkpoints from one run can therefore never lose work,
//!   and a crashed run leaves its partial progress recorded rather than rolled back.
//! - **A run is bracketed.** [`crate::traits::JobRepo::begin_run`] hands back the state to
//!   resume from and stamps the attempt; [`crate::traits::JobRepo::finish_run`] records the
//!   outcome. The pair is what makes "when did this last actually succeed" answerable — the
//!   question an operator asks about a mirror, and the one `upstream_sync_lag_seconds` is
//!   derived from.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Durable state of one background job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobState {
    /// Job name — also the [`crate::traits::JobLock`] key, so the lock and the state row can
    /// never drift apart.
    pub name: String,
    /// Where the job resumes from; `None` means "from the beginning". Opaque to the repository.
    pub cursor: Option<String>,
    /// Job-defined phase (the mirror uses `sweep` / `recent` / `idle`), so a multi-stage job
    /// can tell which stage its cursor belongs to after a restart.
    pub phase: String,
    /// When a run last started.
    pub last_run_at: Option<DateTime<Utc>>,
    /// When a run last completed successfully — the freshness an operator actually watches.
    pub last_success_at: Option<DateTime<Utc>>,
    /// The last failure's message; cleared by the next success.
    pub last_error: Option<String>,
    /// How many runs have started.
    pub runs: i64,
    /// How many work items the job has processed in total.
    pub processed: i64,
    /// How many work items the job has failed on in total.
    pub failures: i64,
    /// Last write (UTC).
    pub updated_at: DateTime<Utc>,
}

impl JobState {
    /// A never-run job's state, as [`crate::traits::JobRepo::get`] would report it before the
    /// first tick.
    pub fn fresh(name: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            name: name.into(),
            cursor: None,
            phase: String::new(),
            last_run_at: None,
            last_success_at: None,
            last_error: None,
            runs: 0,
            processed: 0,
            failures: 0,
            updated_at: now,
        }
    }

    /// Seconds since the job last succeeded; `None` when it never has.
    ///
    /// This is the mirror's sync lag: how far behind upstream this instance's cache may be. A
    /// job that has never succeeded deliberately reports `None` rather than "infinitely
    /// behind" — the two are different alarms.
    pub fn lag_seconds(&self, now: DateTime<Utc>) -> Option<i64> {
        self.last_success_at.map(|at| now.signed_duration_since(at).num_seconds().max(0))
    }
}

/// One mid-run progress report (see the module docs on why counters are deltas).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobProgress {
    /// The new resume point, written verbatim. `None` clears it — "start from the beginning
    /// next time", which is how a completed sweep hands over to the steady-state phase.
    pub cursor: Option<String>,
    /// The phase the cursor belongs to.
    pub phase: String,
    /// Work items completed since the previous checkpoint.
    pub processed: u64,
    /// Work items that failed since the previous checkpoint.
    pub failed: u64,
}

/// How a run ended (see [`crate::traits::JobRepo::finish_run`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    /// The run completed; `last_success_at` advances and `last_error` is cleared.
    Success,
    /// The run failed; the message is kept for the admin surface and the next run still
    /// resumes from the recorded cursor.
    Failure(String),
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
    }

    #[test]
    fn a_fresh_job_has_no_cursor_and_no_lag() {
        let state = JobState::fresh("mirror-sync", t0());
        assert_eq!(state.cursor, None);
        assert_eq!(state.runs, 0);
        // Never succeeded is not "infinitely behind": an operator alarms on them differently.
        assert_eq!(state.lag_seconds(t0()), None);
    }

    #[test]
    fn lag_is_seconds_since_the_last_success_and_never_negative() {
        let mut state = JobState::fresh("mirror-sync", t0());
        state.last_success_at = Some(t0());
        assert_eq!(state.lag_seconds(t0() + chrono::Duration::minutes(5)), Some(300));
        // Clock skew between instances must not produce a negative lag on a gauge.
        assert_eq!(state.lag_seconds(t0() - chrono::Duration::minutes(5)), Some(0));
    }
}
