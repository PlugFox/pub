//! `UserRepo` over Postgres.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::page::{Page, decode_cursor, encode_cursor};
use pub_core::traits::UserRepo;
use pub_core::user::{NewUser, User, UserCounts, UserFilter, UserStatus};
use pub_core::{Error, Result, UserId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// Largest `get_many` batch — a bound on the array a single lookup may carry.
const MAX_BATCH: usize = 500;

/// All user columns, in [`UserRow`] order.
const COLS: &str = "id, email, email_verified, display_name, status, is_instance_admin, created_at, updated_at";

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
    is_instance_admin: bool,
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
            is_instance_admin: row.is_instance_admin,
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

    async fn get_many(&self, ids: &[UserId]) -> Result<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > MAX_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_BATCH} accounts per lookup") });
        }
        let uuids: Vec<uuid::Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let rows: Vec<UserRow> = sqlx::query_as(q!("SELECT {COLS} FROM users WHERE id = ANY($1)"))
            .bind(&uuids)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
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

    async fn list(&self, filter: &UserFilter, cursor: Option<&str>, limit: u32) -> Result<Page<User>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(format!("SELECT {COLS} FROM users WHERE TRUE"));
        if let Some(status) = filter.status {
            query.push(" AND status = ").push_bind(status.as_str().to_owned());
        }
        if filter.admins_only {
            query.push(" AND is_instance_admin");
        }
        if let Some(text) = filter.query.as_ref().map(|q| q.trim()).filter(|q| !q.is_empty()) {
            // ILIKE with the wildcards bound as data: an operator searching for `100%` must
            // not turn their own query into a match-everything pattern.
            let pattern = format!("%{}%", escape_like(text));
            query.push(" AND (email ILIKE ").push_bind(pattern.clone()).push(LIKE_ESCAPE);
            query.push(" OR display_name ILIKE ").push_bind(pattern).push(LIKE_ESCAPE).push(")");
        }
        if let Some(cursor) = cursor {
            // UUID v7 ids are time-ordered, so the id alone is a total order and the cursor.
            let parts = decode_cursor(cursor, 1)?;
            let id: UserId = parts[0].parse().map_err(|_| Error::Invalid { message: "malformed cursor".to_owned() })?;
            query.push(" AND id < ").push_bind(*id.as_uuid());
        }
        query.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

        let rows: Vec<UserRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<User> = rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = has_more.then(|| items.last().map(|user| encode_cursor(&[&user.id.to_string()]))).flatten();
        Ok(Page { items, cursor, has_more })
    }

    async fn counts(&self) -> Result<UserCounts> {
        let row: PgRow = sqlx::query(
            "SELECT COUNT(*) AS total, \
             COUNT(*) FILTER (WHERE status = 'active') AS active, \
             COUNT(*) FILTER (WHERE status = 'suspended') AS suspended, \
             COUNT(*) FILTER (WHERE status = 'deleted') AS deleted, \
             COUNT(*) FILTER (WHERE is_instance_admin) AS admins FROM users",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(UserCounts {
            total: row.get("total"),
            active: row.get("active"),
            suspended: row.get("suspended"),
            deleted: row.get("deleted"),
            admins: row.get("admins"),
        })
    }

    async fn set_instance_admin(&self, id: UserId, is_admin: bool, now: DateTime<Utc>) -> Result<User> {
        let row: Option<UserRow> = sqlx::query_as(q!(
            "UPDATE users SET is_instance_admin = $1, updated_at = $2 WHERE id = $3 RETURNING {COLS}"
        ))
        .bind(is_admin)
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()
    }

    async fn claim_first_admin(&self, id: UserId, now: DateTime<Utc>) -> Result<bool> {
        // The `NOT EXISTS` lives inside the UPDATE, so the check and the write are one
        // statement: two accounts racing for the empty-instance bootstrap cannot both win.
        let result = sqlx::query(
            "UPDATE users SET is_instance_admin = TRUE, updated_at = $1 \
             WHERE id = $2 AND NOT EXISTS (SELECT 1 FROM users WHERE is_instance_admin)",
        )
        .bind(now)
        .bind(*id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}

/// The `ESCAPE` clause pairing with [`escape_like`]; a const so the two can never disagree.
const LIKE_ESCAPE: &str = " ESCAPE '\\'";

/// Escapes the LIKE metacharacters in caller-supplied search text.
fn escape_like(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_metacharacters_in_a_search_are_data() {
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        // The escape character itself has to be escaped first, or `\%` would smuggle a wildcard.
        assert_eq!(escape_like("c:\\%"), "c:\\\\\\%");
    }
}
