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

    async fn rotate(
        &self,
        old_hash: &str,
        new_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Session> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let current: Option<SessionRow> = sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE refresh_hash = ?"))
            .bind(old_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;

        let Some(current) = current else {
            // Not the current hash of any session — was it rotated out? (S-08 reuse detection)
            let reused: Option<SqliteRow> = sqlx::query("SELECT id FROM sessions WHERE prev_refresh_hash = ?")
                .bind(old_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            return match reused {
                Some(row) => {
                    let sid: String = row.get("id");
                    Err(Error::RefreshReused { session: parse_col(&sid)? })
                }
                None => Err(Error::NotFound { what: "session".to_owned() }),
            };
        };

        if current.revoked_at.is_some() {
            // Revoked sessions behave as unknown — no oracle for stolen hashes.
            return Err(Error::NotFound { what: "session".to_owned() });
        }
        if parse_ts(&current.last_seen_at)? < cutoff(now, limits.idle_timeout)
            || parse_ts(&current.created_at)? < cutoff(now, limits.absolute_cap)
        {
            return Err(Error::Expired { what: "session".to_owned() });
        }

        // Atomic swap: the old hash moves to the reuse-detection slot, activity slides.
        let row: SessionRow = sqlx::query_as(q!(
            "UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = ?, last_seen_at = ? \
             WHERE id = ? RETURNING {COLS}"
        ))
        .bind(new_hash)
        .bind(super::ts(now))
        .bind(&current.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "refresh hash already exists", "session"))?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
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
