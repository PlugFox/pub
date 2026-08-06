//! `SessionRepo` over Postgres: rotating refresh sessions with reuse detection (S-08/S-09).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::session::{NewSession, Session, SessionLimits};
use pub_core::traits::SessionRepo;
use pub_core::{Error, Result, SessionId, UserId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::{cutoff, db_err, q, write_err};

/// All session columns exposed to the domain, in [`SessionRow`] order (hashes stay internal;
/// `INET` reads back via `host()` — a bare `::text` cast would append `/32`).
const COLS: &str = "id, user_id, user_agent, host(ip) AS ip, created_at, last_seen_at, revoked_at";

/// Postgres-backed [`SessionRepo`].
#[derive(Debug, Clone)]
pub struct PgSessionRepo {
    pool: PgPool,
}

impl PgSessionRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    user_agent: Option<String>,
    ip: Option<String>,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Session {
            id: SessionId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            user_agent: row.user_agent,
            ip: row.ip,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[async_trait]
impl SessionRepo for PgSessionRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewSession, now: DateTime<Utc>) -> Result<Session> {
        let row: SessionRow = sqlx::query_as(q!(
            "INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, created_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5::inet, $6, $7) RETURNING {COLS}"
        ))
        .bind(*SessionId::new().as_uuid())
        .bind(*new.user_id.as_uuid())
        .bind(&new.refresh_hash)
        .bind(&new.user_agent)
        .bind(&new.ip)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "refresh hash already exists", "user"))?;
        Ok(row.into())
    }

    async fn find_by_refresh_hash(
        &self,
        refresh_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>> {
        // Idle/absolute windows are query predicates: the row must be live at `now`.
        let row: Option<SessionRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE refresh_hash = $1 AND revoked_at IS NULL \
             AND last_seen_at >= $2 AND created_at >= $3"))
            .bind(refresh_hash)
            .bind(cutoff(now, limits.idle_timeout))
            .bind(cutoff(now, limits.absolute_cap))
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn rotate(
        &self,
        old_hash: &str,
        new_hash: &str,
        limits: &SessionLimits,
        now: DateTime<Utc>,
    ) -> Result<Session> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // FOR UPDATE: two concurrent rotations of the same hash must serialize — the loser
        // then sees the rotated-out hash and reports reuse instead of double-swapping.
        let current: Option<SessionRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE refresh_hash = $1 FOR UPDATE"))
                .bind(old_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;

        let Some(current) = current else {
            // Not the current hash of any session — was it rotated out? (S-08 reuse detection)
            let reused: Option<PgRow> = sqlx::query("SELECT id FROM sessions WHERE prev_refresh_hash = $1")
                .bind(old_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            return match reused {
                Some(row) => Err(Error::RefreshReused { session: SessionId::from_uuid(row.get("id")) }),
                None => Err(Error::NotFound { what: "session".to_owned() }),
            };
        };

        if current.revoked_at.is_some() {
            // Revoked sessions behave as unknown — no oracle for stolen hashes.
            return Err(Error::NotFound { what: "session".to_owned() });
        }
        if current.last_seen_at < cutoff(now, limits.idle_timeout)
            || current.created_at < cutoff(now, limits.absolute_cap)
        {
            return Err(Error::Expired { what: "session".to_owned() });
        }

        // Atomic swap: the old hash moves to the reuse-detection slot, activity slides.
        let row: SessionRow = sqlx::query_as(q!(
            "UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = $1, last_seen_at = $2 \
             WHERE id = $3 RETURNING {COLS}"
        ))
        .bind(new_hash)
        .bind(now)
        .bind(current.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "refresh hash already exists", "session"))?;
        tx.commit().await.map_err(db_err)?;
        Ok(row.into())
    }

    async fn touch(&self, id: SessionId, throttle: Duration, now: DateTime<Utc>) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE sessions SET last_seen_at = $1 WHERE id = $2 AND revoked_at IS NULL AND last_seen_at < $3",
        )
        .bind(now)
        .bind(*id.as_uuid())
        .bind(cutoff(now, throttle))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke(&self, id: SessionId, now: DateTime<Utc>) -> Result<()> {
        let result = sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(*id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        if result.rows_affected() > 0 {
            return Ok(());
        }
        // Idempotent for already-revoked sessions; NotFound for unknown ids.
        let exists: Option<PgRow> = sqlx::query("SELECT id FROM sessions WHERE id = $1")
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if exists.is_some() { Ok(()) } else { Err(Error::NotFound { what: format!("session {id}") }) }
    }

    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(*user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<Session>> {
        let rows: Vec<SessionRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM sessions WHERE user_id = $1 AND revoked_at IS NULL \
             ORDER BY last_seen_at DESC, id DESC"))
            .bind(*user.as_uuid())
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
