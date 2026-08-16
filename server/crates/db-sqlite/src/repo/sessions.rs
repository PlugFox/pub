//! `SessionRepo` over SQLite: rotating refresh sessions with reuse detection (S-08/S-09).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::session::{NewSession, Session, SessionLimits};
use pub_core::traits::SessionRepo;
use pub_core::{Error, Result, SessionId, UserId};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, SqlitePool};

use super::{cutoff, db_err, parse_col, parse_ts, parse_ts_opt, q, write_err};

/// All session columns exposed to the domain, in [`SessionRow`] order (hashes stay internal).
const COLS: &str = "id, user_id, user_agent, ip, created_at, last_seen_at, revoked_at";

/// SQLite-backed [`SessionRepo`].
#[derive(Debug, Clone)]
pub struct SqliteSessionRepo {
    pool: SqlitePool,
}

impl SqliteSessionRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    user_id: String,
    user_agent: Option<String>,
    ip: Option<String>,
    created_at: String,
    last_seen_at: String,
    revoked_at: Option<String>,
}

impl TryFrom<SessionRow> for Session {
    type Error = Error;

    fn try_from(row: SessionRow) -> Result<Self> {
        Ok(Session {
            id: parse_col(&row.id)?,
            user_id: parse_col(&row.user_id)?,
            user_agent: row.user_agent,
            ip: row.ip,
            created_at: parse_ts(&row.created_at)?,
            last_seen_at: parse_ts(&row.last_seen_at)?,
            revoked_at: parse_ts_opt(row.revoked_at.as_deref())?,
        })
    }
}

#[async_trait]
impl SessionRepo for SqliteSessionRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewSession, now: DateTime<Utc>) -> Result<Session> {
        let stamp = super::ts(now);
        let row: SessionRow = sqlx::query_as(q!(
            "INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, created_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING {COLS}"
        ))
        .bind(SessionId::new().to_string())
        .bind(new.user_id.to_string())
        .bind(&new.refresh_hash)
        .bind(&new.user_agent)
        .bind(&new.ip)
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "refresh hash already exists", "user"))?;
        row.try_into()
    }

    async fn find_by_refresh_hash(
        &self,
        refresh_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>> {
        // Idle/absolute windows are query predicates: the row must be live at `now`.
        let row: Option<SessionRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE refresh_hash = ? AND revoked_at IS NULL \
             AND last_seen_at >= ? AND created_at >= ?"))
            .bind(refresh_hash)
            .bind(super::ts(cutoff(now, limits.idle_timeout)))
            .bind(super::ts(cutoff(now, limits.absolute_cap)))
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    /// **The swap is one conditional statement, and that is what decides the race (S-08).**
    ///
    /// It used to be `SELECT` the row, check it in Rust, then `UPDATE … WHERE id = ?`, inside a
    /// transaction — with a comment calling the result an atomic swap. It was not one. SQLite's
    /// transactions are deferred: the `SELECT` takes a read snapshot without a write lock, so
    /// two rotations of the same token both read the live row, and the second one's `UPDATE`
    /// finds another writer has committed since its snapshot. That is `SQLITE_BUSY_SNAPSHOT`,
    /// which the busy timeout deliberately does **not** wait out (waiting cannot resolve a
    /// conflict that has already happened), so the loser of the race got `database is locked` —
    /// a 500 on the endpoint every signed-in browser calls, where the auth layer can neither
    /// tell it apart from a store that fell over nor act on it: no family revocation, no
    /// cleared session, and a client that retries.
    ///
    /// Making the predicate part of the write removes the read that created the conflict. A
    /// statement whose transaction has not read anything simply waits for the write lock —
    /// which is what the busy timeout is for — and then matches zero rows, because the hash it
    /// is looking for is no longer the current one. The loser lands in the ordinary
    /// reuse-detection path below and gets the answer S-08 asks for.
    ///
    /// The Postgres sibling reaches the same property differently and correctly:
    /// `SELECT … FOR UPDATE` blocks the second reader until the first commits, and under READ
    /// COMMITTED the predicate is then re-evaluated against the updated row, which no longer
    /// matches. Both dialects are held to `session_rotation_is_single_winner` in the contract
    /// suite, which races 25 rounds behind a barrier — one attempt does not reliably overlap.
    async fn rotate(
        &self,
        old_hash: &str,
        new_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Session> {
        // Every condition the old code checked in Rust, moved into the statement: the hash must
        // still be the current one, the session must be live, and both windows must hold.
        let swapped: Option<SessionRow> = sqlx::query_as(q!(
            "UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = ?, last_seen_at = ? \
             WHERE refresh_hash = ? AND revoked_at IS NULL AND last_seen_at >= ? AND created_at >= ? \
             RETURNING {COLS}"
        ))
        .bind(new_hash)
        .bind(super::ts(now))
        .bind(old_hash)
        .bind(super::ts(cutoff(now, limits.idle_timeout)))
        .bind(super::ts(cutoff(now, limits.absolute_cap)))
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| write_err(err, "refresh hash already exists", "session"))?;
        if let Some(row) = swapped {
            return row.try_into();
        }

        // Nothing matched, so this call is refused; the reads below only decide *which* refusal,
        // in the same order the pre-conditional code used — current hash first, reuse slot
        // second. They run outside any transaction because they change nothing: the refusal has
        // already happened, and the worst a concurrent rotation can do to them is pick a
        // different one of two refusals.
        let current: Option<SessionRow> = sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE refresh_hash = ?"))
            .bind(old_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if let Some(current) = current {
            // Revoked sessions behave as unknown — no oracle for stolen hashes.
            if current.revoked_at.is_some() {
                return Err(Error::NotFound { what: "session".to_owned() });
            }
            if parse_ts(&current.last_seen_at)? < cutoff(now, limits.idle_timeout)
                || parse_ts(&current.created_at)? < cutoff(now, limits.absolute_cap)
            {
                return Err(Error::Expired { what: "session".to_owned() });
            }
            // The row is live and still carries this hash, yet the swap matched nothing: the
            // only way there is a rotation that committed and moved it on between the two
            // statements. Answering "unknown" is the safe read of a hash we cannot claim.
            return Err(Error::NotFound { what: "session".to_owned() });
        }

        // Not the current hash of any session — was it rotated out? (S-08 reuse detection)
        let reused: Option<SqliteRow> = sqlx::query("SELECT id FROM sessions WHERE prev_refresh_hash = ?")
            .bind(old_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        match reused {
            Some(row) => {
                let sid: String = row.get("id");
                Err(Error::RefreshReused { session: parse_col(&sid)? })
            }
            None => Err(Error::NotFound { what: "session".to_owned() }),
        }
    }

    async fn touch(&self, id: SessionId, throttle: Duration, now: DateTime<Utc>) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL AND last_seen_at < ?",
        )
        .bind(super::ts(now))
        .bind(id.to_string())
        .bind(super::ts(cutoff(now, throttle)))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke(&self, id: SessionId, now: DateTime<Utc>) -> Result<()> {
        let result = sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(super::ts(now))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        if result.rows_affected() > 0 {
            return Ok(());
        }
        // Idempotent for already-revoked sessions; NotFound for unknown ids.
        let exists: Option<SqliteRow> = sqlx::query("SELECT id FROM sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if exists.is_some() { Ok(()) } else { Err(Error::NotFound { what: format!("session {id}") }) }
    }

    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
            .bind(super::ts(now))
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<Session>> {
        let rows: Vec<SessionRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE user_id = ? AND revoked_at IS NULL \
             ORDER BY last_seen_at DESC, id DESC"))
            .bind(user.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn purge_before(&self, cutoff: DateTime<Utc>, batch: u32) -> Result<u64> {
        // `last_seen_at` is the only anchor that makes this safe without a second condition: a row
        // older than the idle window cannot authenticate, and a revoked row's `last_seen_at` has
        // already stopped advancing. `sessions_last_seen_idx` (migration 0012) serves the seek;
        // the `id IN (SELECT … LIMIT ?)` shape is the batch bound, because `DELETE … LIMIT` needs a
        // non-default SQLite build option.
        let result = sqlx::query(
            "DELETE FROM sessions WHERE id IN \
             (SELECT id FROM sessions WHERE last_seen_at < ? ORDER BY last_seen_at LIMIT ?)",
        )
        .bind(super::ts(cutoff))
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
