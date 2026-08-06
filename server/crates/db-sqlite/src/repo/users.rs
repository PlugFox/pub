//! `UserRepo` over SQLite.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::traits::UserRepo;
use pub_core::user::{NewUser, User, UserStatus};
use pub_core::{Error, Result, UserId};
use sqlx::SqlitePool;

use super::{db_err, parse_col, parse_ts, q, write_err};

/// All user columns, in [`UserRow`] order.
const COLS: &str = "id, email, email_verified, display_name, status, created_at, updated_at";

/// SQLite-backed [`UserRepo`].
#[derive(Debug, Clone)]
pub struct SqliteUserRepo {
    pool: SqlitePool,
}

impl SqliteUserRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    email: Option<String>,
    email_verified: bool,
    display_name: String,
    status: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<UserRow> for User {
    type Error = Error;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(User {
            id: parse_col(&row.id)?,
            email: row.email,
            email_verified: row.email_verified,
            display_name: row.display_name,
            status: parse_col::<UserStatus>(&row.status)?,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[async_trait]
impl UserRepo for SqliteUserRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewUser, now: DateTime<Utc>) -> Result<User> {
        let id = UserId::new();
        let stamp = super::ts(now);
        let row: UserRow = sqlx::query_as(q!(
            "INSERT INTO users (id, email, email_verified, display_name, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, 'active', ?, ?) RETURNING {COLS}"
        ))
        .bind(id.to_string())
        .bind(&new.email)
        .bind(new.email_verified)
        .bind(&new.display_name)
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "email already in use", "user"))?;
        row.try_into()
    }

    async fn get(&self, id: UserId) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(q!("SELECT {COLS} FROM users WHERE id = ?"))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        // The email column carries COLLATE NOCASE, so `=` matches case-insensitively.
        let row: Option<UserRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM users WHERE email = ? AND email_verified = 1"))
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn update_status(&self, id: UserId, status: UserStatus, now: DateTime<Utc>) -> Result<User> {
        let stamp = super::ts(now);
        let row: Option<UserRow> = if status == UserStatus::Deleted {
            // Anonymization (S-29): erase the profile, free the email slot, keep the row as
            // the attribution tombstone.
            sqlx::query_as(q!("UPDATE users SET status = 'deleted', email = NULL, email_verified = 0, \
                 display_name = 'deleted user', updated_at = ? WHERE id = ? RETURNING {COLS}"))
            .bind(&stamp)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?
        } else {
            sqlx::query_as(q!("UPDATE users SET status = ?, updated_at = ? WHERE id = ? RETURNING {COLS}"))
                .bind(status.as_str())
                .bind(&stamp)
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
        };
        row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()
    }
}
