//! Retention windows, the batch bound every delete carries, and what one pass removed
//! ([decision 30](../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)).
//!
//! Four properties shape the types here, and each of them is a defect this module exists to
//! make unrepresentable:
//!
//! - **A window is `Option<Duration>`, not a number with a magic zero.** `0` in the config
//!   means "keep forever", and a `0` that survived into a `Duration` would be a cutoff of
//!   `now` — a retention setting that means "keep nothing". The conversion happens once, at the
//!   config boundary, and every consumer below it reads an absent window as absent.
//! - **Every delete is bounded and every bounded delete needs a loop.** [`RetentionPolicy`]
//!   carries the batch size and the wall-clock budget together, because a batch bound without a
//!   convergence loop is a table that never drains and a loop without a budget is a job that
//!   never ends. The loop lives in the lifecycle job; the repositories only ever delete at most
//!   one batch and report how many rows that was.
//! - **"Nothing left" and "ran out of time" are different answers.** [`TableOutcome::Swept`]
//!   carries `converged` so an operator reading the job's report can tell a drained table from
//!   a backlog still in progress, and so a test can assert that a released backlog takes
//!   several passes instead of one statement.
//! - **A refusal is an outcome, not an error.** On a Postgres provisioned per the hardened
//!   template the audit prune can be refused at the database
//!   ([S-22.a](../../../docs/security.md#5-audit--abuse)); that must disable one table loudly,
//!   never abort the pass that still has five other tables to sweep.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};

/// How long settled rows are kept, per table, plus the bounds on one sweep.
///
/// Every field is a window measured back from the pass's `now`; `None` is "keep forever" and is
/// the documented default for `download_stats`, whose per-version daily rows are chart data
/// that cannot be reconstructed once deleted (the correct bound there is a monthly roll-up,
/// which is a feature and not a purge).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Audit-log window — uniform across actions, unlike S-23's original three
    /// ([S-23.a](../../../docs/security.md#5-audit--abuse)).
    pub audit: Option<Duration>,
    /// Session window, aged from `last_seen_at`.
    pub sessions: Option<Duration>,
    /// Invitation window, aged from whenever the invitation *settled*.
    pub invitations: Option<Duration>,
    /// Notification-feed window, aged from `created_at`.
    pub notifications: Option<Duration>,
    /// Daily download-rollup window. `None` by default, deliberately.
    pub download_stats: Option<Duration>,
    /// Rows one statement may delete. Bounds the write-lock hold, which on SQLite is the whole
    /// point: one unbounded `DELETE` holds the process's single writer for its full duration,
    /// and a hold past the busy timeout turns a concurrent publish or sign-in into
    /// `SQLITE_BUSY` instead of a wait.
    pub batch: u32,
    /// Wall-clock budget for one pass across all tables. A released backlog is drained over
    /// several ticks rather than in one long transaction.
    pub budget: StdDuration,
}

impl RetentionPolicy {
    /// The floor under the audit window, mirrored by the Postgres `pub_audit_prune` function
    /// (which raises above it) and by the config validator (which refuses to configure it).
    ///
    /// Evidence of an attack is recent. The floor is what makes the app's reachable capability
    /// "delete audit rows older than a month" rather than "delete audit rows", which is the
    /// property [S-22](../../../docs/security.md#5-audit--abuse) is defending and the reason the
    /// app role still holds no `DELETE` on that table.
    pub const AUDIT_FLOOR: Duration = Duration::days(30);

    /// The cutoff instant for a window, or `None` when the window is "keep forever".
    ///
    /// Saturating, not panicking. `now - window` panics on out-of-range, the validator bounds every
    /// window only from *below*, and a panic here happens inside a spawned scheduler task — so a
    /// mistyped `retain_notifications_days = 100000000` would kill the retention loop for the life
    /// of the process, leaving the durable job state stuck at "running" and the leader lock to
    /// expire on its TTL. Saturating to the minimum instant means an absurd window behaves as the
    /// operator wrote it: keep everything. The same shape the SQLite repository already uses for
    /// its own cutoffs.
    #[must_use]
    pub fn cutoff(window: Option<Duration>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        window.map(|window| now.checked_sub_signed(window).unwrap_or(DateTime::<Utc>::MIN_UTC))
    }

    /// Whether an audit cutoff respects [`Self::AUDIT_FLOOR`].
    ///
    /// Checked in the repository layer as well as at the database, because on SQLite there is no
    /// database layer to check it: the trait surface is the whole enforcement there, exactly as
    /// it is for the absence of an update.
    #[must_use]
    pub fn audit_cutoff_is_allowed(cutoff: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        cutoff <= now - Self::AUDIT_FLOOR
    }
}

/// What retention did to one table during one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableOutcome {
    /// The window is "keep forever" — nothing was attempted.
    Disabled,
    /// The pass's budget was already spent when this table's turn came, so it was never touched.
    ///
    /// Distinct from `Swept { converged: false }` on purpose. Both mean "there may be more", but
    /// only one of them means the job *tried*: a table that is never reached, pass after pass,
    /// because the tables ahead of it exhaust the budget is a table with no retention at all, and
    /// it must not be reported in the same words as one that is working through a backlog.
    Skipped,
    /// Rows were considered. `converged` is `false` when the pass's budget ran out with a full
    /// batch still coming back, i.e. there is more to delete on the next tick.
    Swept {
        /// Rows deleted across every batch of this pass.
        deleted: u64,
        /// Statements issued — `1` on an idle instance, more when a backlog was released.
        passes: u32,
        /// Whether the table is drained (a pass deleted fewer rows than the batch).
        converged: bool,
    },
    /// The database refused the delete. The audit-log case on a hardened Postgres
    /// ([S-22.a](../../../docs/security.md#5-audit--abuse)); carries the message so the log line
    /// and the durable job state can name the missing grant instead of a generic failure.
    Refused {
        /// The database's own message, forwarded verbatim.
        reason: String,
    },
}

impl TableOutcome {
    /// Rows deleted, `0` for every non-sweeping outcome.
    #[must_use]
    pub fn deleted(&self) -> u64 {
        match self {
            Self::Swept { deleted, .. } => *deleted,
            Self::Disabled | Self::Skipped | Self::Refused { .. } => 0,
        }
    }

    /// Whether this table needs attention rather than just reporting.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

/// One table's line in the lifecycle job's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableReport {
    /// The table the line is about, as it appears in the schema — the name an operator would
    /// grep for, and the metric label.
    pub table: &'static str,
    /// What happened to it.
    pub outcome: TableOutcome,
}

/// What one lifecycle pass removed, table by table, in the order it swept them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// One line per table the pass considered, including the disabled ones — a table missing
    /// from this list is a table the job forgot, which is exactly the failure a report of only
    /// non-zero counts would hide.
    pub tables: Vec<TableReport>,
}

impl RetentionReport {
    /// Records one table's outcome.
    pub fn record(&mut self, table: &'static str, outcome: TableOutcome) {
        self.tables.push(TableReport { table, outcome });
    }

    /// Rows deleted across every table.
    #[must_use]
    pub fn deleted_total(&self) -> u64 {
        self.tables.iter().map(|line| line.outcome.deleted()).sum()
    }

    /// Whether any table was refused by the database.
    #[must_use]
    pub fn any_refused(&self) -> bool {
        self.tables.iter().any(|line| line.outcome.is_refused())
    }

    /// The tables whose backlog outlived the pass's budget, plus the ones it never reached.
    ///
    /// Both belong in the operator-facing backlog signal — the difference between them matters when
    /// reading *which* table, which is why the report keeps them as separate outcomes.
    #[must_use]
    pub fn unconverged(&self) -> Vec<&'static str> {
        self.tables
            .iter()
            .filter(|line| matches!(line.outcome, TableOutcome::Swept { converged: false, .. } | TableOutcome::Skipped))
            .map(|line| line.table)
            .collect()
    }

    /// Tables the pass never reached because its budget was already spent.
    #[must_use]
    pub fn skipped(&self) -> Vec<&'static str> {
        self.tables.iter().filter(|line| matches!(line.outcome, TableOutcome::Skipped)).map(|line| line.table).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            audit: Some(Duration::days(730)),
            sessions: Some(Duration::days(30)),
            invitations: Some(Duration::days(30)),
            notifications: Some(Duration::days(180)),
            download_stats: None,
            batch: 1_000,
            budget: StdDuration::from_secs(60),
        }
    }

    #[test]
    fn an_absurd_window_saturates_instead_of_panicking() {
        // The validator bounds windows from below only, so this is a reachable configuration. A
        // panic here would be permanent: it happens inside the scheduler's spawned task.
        let now = Utc::now();
        let cutoff = RetentionPolicy::cutoff(Some(Duration::days(100_000_000)), now);
        assert_eq!(cutoff, Some(DateTime::<Utc>::MIN_UTC));
        // And it means what the operator wrote — nothing is old enough to delete.
        assert!(cutoff.expect("saturated") < now - Duration::days(365 * 100));
    }

    #[test]
    fn keep_forever_has_no_cutoff() {
        let now = Utc::now();
        // The whole reason the type is `Option`: a zero-day window must not become "delete
        // everything up to this instant".
        assert_eq!(RetentionPolicy::cutoff(policy().download_stats, now), None);
        assert_eq!(RetentionPolicy::cutoff(policy().audit, now), Some(now - Duration::days(730)));
    }

    #[test]
    fn the_audit_floor_refuses_a_recent_cutoff() {
        let now = Utc::now();
        assert!(RetentionPolicy::audit_cutoff_is_allowed(now - Duration::days(730), now));
        assert!(RetentionPolicy::audit_cutoff_is_allowed(now - Duration::days(30), now));
        // One day inside the floor is refused: this is the backstop that keeps the reachable
        // capability away from the rows an attacker would want gone.
        assert!(!RetentionPolicy::audit_cutoff_is_allowed(now - Duration::days(29), now));
        assert!(!RetentionPolicy::audit_cutoff_is_allowed(now, now));
    }

    #[test]
    fn a_report_distinguishes_drained_from_out_of_time_from_refused() {
        let mut report = RetentionReport::default();
        report.record("sessions", TableOutcome::Swept { deleted: 40, passes: 1, converged: true });
        report.record("notifications", TableOutcome::Swept { deleted: 2_000, passes: 2, converged: false });
        report.record("audit_log", TableOutcome::Refused { reason: "permission denied".to_owned() });
        report.record("download_stats", TableOutcome::Disabled);

        assert_eq!(report.deleted_total(), 2_040);
        assert!(report.any_refused());
        assert_eq!(report.unconverged(), vec!["notifications"]);
        // Disabled tables stay in the report: a line that is absent reads as a table the job
        // forgot, and that is precisely the bug a non-zero-only report would hide.
        assert_eq!(report.tables.len(), 4);
    }
}
