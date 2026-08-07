//! `NotificationRepo` over SQLite (decision 20 notification center).
//!
//! Every statement carries `user_id` in its `WHERE` clause — including the ones that take
//! explicit ids. That is the trait's contract 1 in SQL: there is no query here that could
//! return or touch another account's row even if a caller passed a foreign id.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::notification::{NewNotification, Notification, NotificationCategory, NotificationPreference};
use pub_core::page::Page;
use pub_core::traits::NotificationRepo;
use pub_core::{Error, NotificationId, Result, UserId};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use super::{db_err, parse_col, parse_ts, parse_ts_opt, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 100;

/// Largest batch [`NotificationRepo::mark_read`] accepts in one call — the `IN (…)` list is
/// bound parameter by parameter, and an unbounded one would be a statement of unbounded size.
const MAX_MARK_BATCH: usize = 200;

/// Largest recipient batch one fan-out may ask about in a single preference lookup.
const MAX_RECIPIENT_BATCH: usize = 500;

/// All notification columns, in [`NotificationRow`] order.
const COLS: &str = "id, user_id, category, event, title, org_id, payload, created_at, read_at";

/// SQLite-backed [`NotificationRepo`].
#[derive(Debug, Clone)]
pub struct SqliteNotificationRepo {
    pool: SqlitePool,
}

impl SqliteNotificationRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct NotificationRow {
    id: String,
    user_id: String,
    category: String,
    event: String,
    title: String,
    org_id: Option<String>,
    payload: String,
    created_at: String,
    read_at: Option<String>,
}

impl TryFrom<NotificationRow> for Notification {
    type Error = Error;

    fn try_from(row: NotificationRow) -> Result<Self> {
        Ok(Notification {
            id: parse_col(&row.id)?,
            user_id: parse_col(&row.user_id)?,
            category: parse_col::<NotificationCategory>(&row.category)?,
            event: row.event,
            title: row.title,
            org_id: row.org_id.as_deref().map(parse_col).transpose()?,
            payload: serde_json::from_str(&row.payload)
                .map_err(|err| Error::Database { message: format!("corrupt notification payload: {err}") })?,
            created_at: parse_ts(&row.created_at)?,
            read_at: parse_ts_opt(row.read_at.as_deref())?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct UserPrefRow {
    user_id: String,
    category: String,
    in_app: bool,
    email: bool,
}

#[derive(sqlx::FromRow)]
struct PrefRow {
    category: String,
    in_app: bool,
    email: bool,
}

impl TryFrom<PrefRow> for NotificationPreference {
    type Error = Error;

    fn try_from(row: PrefRow) -> Result<Self> {
        Ok(NotificationPreference {
            category: parse_col::<NotificationCategory>(&row.category)?,
            in_app: row.in_app,
            email: row.email,
        })
    }
}

#[async_trait]
impl NotificationRepo for SqliteNotificationRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewNotification, now: DateTime<Utc>) -> Result<Notification> {
        let payload = serde_json::to_string(&new.payload)
            .map_err(|err| Error::Internal { message: format!("failed to encode notification payload: {err}") })?;
        let row: NotificationRow = sqlx::query_as(q!(
            "INSERT INTO notifications (id, user_id, category, event, title, org_id, payload, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING {COLS}"
        ))
        .bind(NotificationId::new().to_string())
        .bind(new.user_id.to_string())
        .bind(new.category.as_str())
        .bind(&new.event)
        .bind(&new.title)
        .bind(new.org_id.map(|org| org.to_string()))
        .bind(payload)
        .bind(super::ts(now))
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "notification already exists", "the recipient or org"))?;
        row.try_into()
    }

    async fn list(
        &self,
        user: UserId,
        unread_only: bool,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Notification>> {
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT {COLS} FROM notifications WHERE user_id = "));
        query.push_bind(user.to_string());
        if unread_only {
            query.push(" AND read_at IS NULL");
        }
        if let Some(cursor) = cursor {
            // Keyset over the UUID v7 id: strictly older than the last-seen row. Ids are
            // unique, so pages stay stable across concurrent inserts.
            let cursor: NotificationId =
                cursor.parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {cursor}") })?;
            query.push(" AND id < ").push_bind(cursor.to_string());
        }
        query.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

        let rows: Vec<NotificationRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<Notification> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more { items.last().map(|item| item.id.to_string()) } else { None };
        Ok(Page { items, cursor, has_more })
    }

    async fn unread_count(&self, user: UserId) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL")
            .bind(user.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(count)
    }

    async fn mark_read(&self, user: UserId, ids: &[NotificationId], now: DateTime<Utc>) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        if ids.len() > MAX_MARK_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_MARK_BATCH} notifications per call") });
        }
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new("UPDATE notifications SET read_at = ");
        query.push_bind(super::ts(now));
        query.push(" WHERE read_at IS NULL AND user_id = ").push_bind(user.to_string());
        query.push(" AND id IN (");
        let mut separated = query.separated(", ");
        for id in ids {
            separated.push_bind(id.to_string());
        }
        query.push(")");
        let result = query.build().execute(&self.pool).await.map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn mark_all_read(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL")
            .bind(super::ts(now))
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn preferences(&self, user: UserId) -> Result<Vec<NotificationPreference>> {
        let rows: Vec<PrefRow> = sqlx::query_as(
            "SELECT category, in_app, email FROM notification_prefs WHERE user_id = ? ORDER BY category",
        )
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn stored_preferences(
        &self,
        users: &[UserId],
        category: NotificationCategory,
    ) -> Result<Vec<(UserId, NotificationPreference)>> {
        if users.is_empty() {
            return Ok(Vec::new());
        }
        if users.len() > MAX_RECIPIENT_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_RECIPIENT_BATCH} recipients per lookup") });
        }
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT user_id, category, in_app, email FROM notification_prefs WHERE category = ");
        query.push_bind(category.as_str());
        query.push(" AND user_id IN (");
        let mut separated = query.separated(", ");
        for user in users {
            separated.push_bind(user.to_string());
        }
        query.push(")");
        let rows: Vec<UserPrefRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    parse_col::<UserId>(&row.user_id)?,
                    NotificationPreference {
                        category: parse_col::<NotificationCategory>(&row.category)?,
                        in_app: row.in_app,
                        email: row.email,
                    },
                ))
            })
            .collect()
    }

    async fn set_preferences(
        &self,
        user: UserId,
        prefs: &[NotificationPreference],
        now: DateTime<Utc>,
    ) -> Result<Vec<NotificationPreference>> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for pref in prefs {
            sqlx::query(
                "INSERT INTO notification_prefs (user_id, category, in_app, email, updated_at) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (user_id, category) DO UPDATE SET in_app = excluded.in_app, \
                 email = excluded.email, updated_at = excluded.updated_at",
            )
            .bind(user.to_string())
            .bind(pref.category.as_str())
            .bind(pref.in_app)
            .bind(pref.email)
            .bind(super::ts(now))
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "preference already exists", "the account"))?;
        }
        let rows: Vec<PrefRow> = sqlx::query_as(q!(
            "SELECT category, in_app, email FROM notification_prefs WHERE user_id = ? ORDER BY category"
        ))
        .bind(user.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
