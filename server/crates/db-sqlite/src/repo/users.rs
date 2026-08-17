//! `UserRepo` over SQLite.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::page::{Page, decode_cursor, encode_cursor};
use pub_core::traits::UserRepo;
use pub_core::user::{NewUser, User, UserCounts, UserFilter, UserStatus};
use pub_core::{Error, Result, UserId};
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row as _, Sqlite, SqlitePool};

use super::{db_err, parse_col, parse_ts, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// Largest `get_many` batch: the `IN (…)` list is bound one parameter per id, so an unbounded
/// caller would build an unbounded statement.
const MAX_BATCH: usize = 500;

/// All user columns, in [`UserRow`] order.
const COLS: &str = "id, email, email_verified, display_name, status, is_instance_admin, created_at, updated_at";

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
    is_instance_admin: bool,
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
            is_instance_admin: row.is_instance_admin,
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

    async fn get_many(&self, ids: &[UserId]) -> Result<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > MAX_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_BATCH} accounts per lookup") });
        }
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(format!("SELECT {COLS} FROM users WHERE id IN ("));
        let mut separated = query.separated(", ");
        for id in ids {
            separated.push_bind(id.to_string());
        }
        query.push(")");
        let rows: Vec<UserRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
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
            // Anonymization (S-29.a): erase the profile, free the email slot, drop the
            // instance-admin flag, keep the row as the attribution tombstone. The flag goes
            // because `counts` would report tombstones as administrators and `claim_first_admin`
            // asks whether *any* account holds it — a deleted admin would block the bootstrap
            // promotion on an instance with nobody left to promote by hand.
            sqlx::query_as(q!("UPDATE users SET status = 'deleted', email = NULL, email_verified = 0, \
                 display_name = 'deleted user', is_instance_admin = 0, updated_at = ? \
                 WHERE id = ? RETURNING {COLS}"))
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

    async fn update_profile(&self, id: UserId, display_name: &str, now: DateTime<Utc>) -> Result<User> {
        let row: Option<UserRow> =
            sqlx::query_as(q!("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ? RETURNING {COLS}"))
                .bind(display_name)
                .bind(super::ts(now))
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()
    }

    async fn change_email(&self, id: UserId, email: &str, now: DateTime<Utc>) -> Result<User> {
        let stamp = super::ts(now);
        let key = id.to_string();
        // One transaction, because the account's address lives in two places: the user row that
        // `find_by_email` resolves sign-ins through, and the `email` credential row that is the
        // account's own record of which addresses identify it (S-03.b). Half of this applied is
        // an account whose credential inventory names an address that no longer signs in.
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let row: Option<UserRow> = sqlx::query_as(q!(
            "UPDATE users SET email = ?, email_verified = 1, updated_at = ? WHERE id = ? RETURNING {COLS}"
        ))
        .bind(email)
        .bind(&stamp)
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await
        // The unique index is the check. A prior `find_by_email` would be a read another
        // transaction can invalidate before this write lands; the index cannot be raced.
        .map_err(|err| write_err(err, "email already in use", "user"))?;
        let user: User = row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()?;

        // The account may have signed up through OIDC and never held an email identity at all,
        // so this is an update-if-present rather than a required row. `credentials_email_key` is
        // unique on `(user_id, email)`, so a caller who somehow already holds the new address as
        // a second identity collides here rather than silently keeping two.
        sqlx::query("UPDATE credentials SET email = ?, updated_at = ? WHERE user_id = ? AND type = 'email'")
            .bind(email)
            .bind(&stamp)
            .bind(&key)
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "email already in use", "credential"))?;
        tx.commit().await.map_err(db_err)?;
        Ok(user)
    }

    async fn list(&self, filter: &UserFilter, cursor: Option<&str>, limit: u32) -> Result<Page<User>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(format!("SELECT {COLS} FROM users WHERE 1 = 1"));
        if let Some(status) = filter.status {
            query.push(" AND status = ").push_bind(status.as_str());
        }
        if filter.admins_only {
            query.push(" AND is_instance_admin = 1");
        }
        if let Some(text) = filter.query.as_ref().map(|q| q.trim()).filter(|q| !q.is_empty()) {
            // LIKE with the wildcards bound as data: an operator searching for `100%` must not
            // turn their own query into a match-everything pattern.
            let pattern = format!("%{}%", escape_like(text));
            query.push(" AND (email LIKE ").push_bind(pattern.clone()).push(" ESCAPE '\\'");
            query.push(" OR display_name LIKE ").push_bind(pattern).push(" ESCAPE '\\')");
        }
        if let Some(cursor) = cursor {
            // UUID v7 ids are time-ordered, so the id alone is a total order and the cursor.
            let parts = decode_cursor(cursor, 1)?;
            query.push(" AND id < ").push_bind(parts[0].clone());
        }
        query.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

        let rows: Vec<UserRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<User> = rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = has_more.then(|| items.last().map(|user| encode_cursor(&[&user.id.to_string()]))).flatten();
        Ok(Page { items, cursor, has_more })
    }

    async fn counts(&self) -> Result<UserCounts> {
        let row: SqliteRow = sqlx::query(
            "SELECT COUNT(*) AS total, \
             COALESCE(SUM(status = 'active'), 0) AS active, \
             COALESCE(SUM(status = 'suspended'), 0) AS suspended, \
             COALESCE(SUM(status = 'deleted'), 0) AS deleted, \
             COALESCE(SUM(is_instance_admin = 1), 0) AS admins FROM users",
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
        let row: Option<UserRow> =
            sqlx::query_as(q!("UPDATE users SET is_instance_admin = ?, updated_at = ? WHERE id = ? RETURNING {COLS}"))
                .bind(is_admin)
                .bind(super::ts(now))
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("user {id}") })?.try_into()
    }

    async fn claim_first_admin(&self, id: UserId, now: DateTime<Utc>) -> Result<bool> {
        // The `NOT EXISTS` lives inside the UPDATE, so the check and the write are one
        // statement: two accounts racing for the empty-instance bootstrap cannot both win.
        let result = sqlx::query(
            "UPDATE users SET is_instance_admin = 1, updated_at = ? \
             WHERE id = ? AND NOT EXISTS (SELECT 1 FROM users WHERE is_instance_admin = 1)",
        )
        .bind(super::ts(now))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}

/// Escapes the LIKE metacharacters in caller-supplied search text (`ESCAPE '\'`).
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
