//! `UserRepo` over Postgres.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::traits::UserRepo;
use pub_core::user::{NewUser, User, UserStatus};
use pub_core::{Error, Result, UserId};
use sqlx::PgPool;
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// All user columns, in [`UserRow`] order.
const COLS: &str = "id, email, email_verified, display_name, status, created_at, updated_at";

/// Postgres-backed [`UserRepo`].
#[derive(Debug, Clone)]
pub struct PgUserRepo {
    pool: PgPool,
}

impl PgUserRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: Option<String>,
    email_verified: bool,
    display_name: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for User {
    type Error = Error;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(User {
            id: UserId::from_uuid(row.id),
            email: row.email,
            email_verified: row.email_verified,
            display_name: row.display_name,
            status: parse_col::<UserStatus>(&row.status)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[async_trait]
impl UserRepo for PgUserRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewUser, now: DateTime<Utc>) -> Result<User> {
        let id = UserId::new();
        let row: UserRow = sqlx::query_as(q!(
            "INSERT INTO users (id, email, email_verified, display_name, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'active', $5, $6) RETURNING {COLS}"
        ))
        .bind(*id.as_uuid())
        .bind(&new.email)
        .bind(new.email_verified)
        .bind(&new.display_name)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "email already in use", "user"))?;
        row.try_into()
    }

    async fn get(&self, id: UserId) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(q!("SELECT {COLS} FROM users WHERE id = $1"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        // Case-insensitive match, aligned with the lower() unique index.
        let row: Option<UserRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM users WHERE lower(email) = lower($1) AND email_verified"))
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn update_status(&self, id: UserId, status: UserStatus, now: DateTime<Utc>) -> Result<User> {
        let row: Option<UserRow> = if status == UserStatus::Deleted {
            // Anonymization (S-29): erase the profile, free the email slot, keep the row as
            // the attribution tombstone.
            sqlx::query_as(q!("UPDATE users SET status = 'deleted', email = NULL, email_verified = FALSE, \
                 display_name = 'deleted user', updated_at = $1 WHERE id = $2 RETURNING {COLS}"))
            .bind(now)
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?
        } else {
            sqlx::query_as(q!("UPDATE users SET status = $1, updated_at = $2 WHERE id = $3 RETURNING {COLS}"))
                .bind(status.as_str())
                .bind(now)
                .bind(*id.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
        };
        row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()
    }
}
