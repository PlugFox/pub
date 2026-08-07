//! `NotificationRepo` over Postgres (decision 20 notification center).
//!
//! Every statement carries `user_id` in its `WHERE` clause — including the ones that take
//! explicit ids. That is the trait's contract 1 in SQL: there is no query here that could
//! return or touch another account's row even if a caller passed a foreign id.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::event::EventId;
use pub_core::notification::{NewNotification, Notification, NotificationCategory, NotificationPreference};
use pub_core::page::Page;
use pub_core::traits::NotificationRepo;
use pub_core::{Error, NotificationId, Result, UserId};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 100;

/// Largest batch [`NotificationRepo::mark_read`] accepts in one call — the `IN (…)` list is
/// bound parameter by parameter, and an unbounded one would be a statement of unbounded size.
const MAX_MARK_BATCH: usize = 200;

/// Largest recipient batch one fan-out may ask about in a single preference lookup.
const MAX_RECIPIENT_BATCH: usize = 500;

/// All notification columns, in [`NotificationRow`] order (`JSONB` reads back as text).
const COLS: &str = "id, user_id, category, event, title, org_id, payload::text AS payload, created_at, read_at";

/// Postgres-backed [`NotificationRepo`].
#[derive(Debug, Clone)]
pub struct PgNotificationRepo {
    pool: PgPool,
}

impl PgNotificationRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct NotificationRow {
    id: Uuid,
    user_id: Uuid,
    category: String,
    event: String,
    title: String,
    org_id: Option<Uuid>,
    payload: String,
    created_at: DateTime<Utc>,
    read_at: Option<DateTime<Utc>>,
}

impl TryFrom<NotificationRow> for Notification {
    type Error = Error;

    fn try_from(row: NotificationRow) -> Result<Self> {
        Ok(Notification {
            id: NotificationId::from_uuid(row.id),
            user_id: pub_core::UserId::from_uuid(row.user_id),
            category: parse_col::<NotificationCategory>(&row.category)?,
            event: row.event,
            title: row.title,
            org_id: row.org_id.map(pub_core::OrgId::from_uuid),
            payload: serde_json::from_str(&row.payload)
                .map_err(|err| Error::Database { message: format!("corrupt notification payload: {err}") })?,
            created_at: row.created_at,
            read_at: row.read_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct UnreadCountRow {
    user_id: Uuid,
    count: i64,
}

#[derive(sqlx::FromRow)]
struct UserPrefRow {
    user_id: Uuid,
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
impl NotificationRepo for PgNotificationRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewNotification, now: DateTime<Utc>) -> Result<Notification> {
        let payload = serde_json::to_string(&new.payload)
            .map_err(|err| Error::Internal { message: format!("failed to encode notification payload: {err}") })?;
        // No `ON CONFLICT` here, unlike the batched sibling: a single-row caller names one
        // recipient deliberately, so a second row for the same emission is a caller error worth
        // a `Conflict` rather than something to swallow.
        let row: NotificationRow = sqlx::query_as(q!(
            "INSERT INTO notifications (id, user_id, category, event_id, event, title, org_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9) RETURNING {COLS}"
        ))
        .bind(*NotificationId::new().as_uuid())
        .bind(*new.user_id.as_uuid())
        .bind(new.category.as_str())
        .bind(new.event_id.as_ref().map(EventId::as_str))
        .bind(&new.event)
        .bind(&new.title)
        .bind(new.org_id.map(|org| *org.as_uuid()))
        .bind(payload)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "notification already exists", "the recipient or org"))?;
        row.try_into()
    }

    async fn create_many(&self, new: &[NewNotification], now: DateTime<Utc>) -> Result<Vec<Notification>> {
        if new.is_empty() {
            return Ok(Vec::new());
        }
        if new.len() > MAX_RECIPIENT_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_RECIPIENT_BATCH} notifications per batch") });
        }
        // Minted here rather than by the database, in input order: UUID v7 is monotonic within
        // a millisecond, and a user's feed is ordered by this id.
        let ids: Vec<NotificationId> = new.iter().map(|_| NotificationId::new()).collect();
        let id_uuids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let users: Vec<Uuid> = new.iter().map(|item| *item.user_id.as_uuid()).collect();
        let categories: Vec<String> = new.iter().map(|item| item.category.as_str().to_owned()).collect();
        let event_ids: Vec<Option<String>> =
            new.iter().map(|item| item.event_id.as_ref().map(|id| id.as_str().to_owned())).collect();
        let events: Vec<String> = new.iter().map(|item| item.event.clone()).collect();
        let titles: Vec<String> = new.iter().map(|item| item.title.clone()).collect();
        let orgs: Vec<Option<Uuid>> = new.iter().map(|item| item.org_id.map(|org| *org.as_uuid())).collect();
        let payloads: Vec<String> = new
            .iter()
            .map(|item| {
                serde_json::to_string(&item.payload)
                    .map_err(|err| Error::Internal { message: format!("failed to encode notification payload: {err}") })
            })
            .collect::<Result<_>>()?;

        // One statement over parallel arrays rather than a multi-row VALUES list: the bind
        // count stays at nine regardless of the recipient count, so the batch size is bounded
        // by policy (`MAX_RECIPIENT_BATCH`) and never by the protocol's parameter limit.
        //
        // `ON CONFLICT … DO NOTHING` is exactly-once fan-out (decision 26's amendment): a
        // re-run after a crash converges on the rows that are already there instead of filing
        // everybody a second copy. The index predicate is repeated in the conflict target
        // because that is how a partial unique index is inferred.
        let rows: Vec<NotificationRow> = sqlx::query_as(q!(
            "INSERT INTO notifications (id, user_id, category, event_id, event, title, org_id, payload, created_at) \
             SELECT id, user_id, category, event_id, event, title, org_id, payload::jsonb, $9 \
             FROM UNNEST($1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::uuid[], \
             $8::text[]) AS batch (id, user_id, category, event_id, event, title, org_id, payload) \
             ON CONFLICT (user_id, event_id) WHERE event_id IS NOT NULL DO NOTHING RETURNING {COLS}"
        ))
        .bind(&id_uuids)
        .bind(&users)
        .bind(&categories)
        .bind(&event_ids)
        .bind(&events)
        .bind(&titles)
        .bind(&orgs)
        .bind(&payloads)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| write_err(err, "notification already exists", "the recipient or org"))?;

        // `RETURNING` promises no order; the minted id sequence is the input order.
        let mut stored: HashMap<NotificationId, Notification> = HashMap::with_capacity(rows.len());
        for row in rows {
            let notification: Notification = row.try_into()?;
            stored.insert(notification.id, notification);
        }
        // An id that is absent is a row this call did **not** file — the recipient already had
        // one for this emission — and the contract is that those are simply not returned.
        Ok(ids.into_iter().filter_map(|id| stored.remove(&id)).collect())
    }

    async fn list(
        &self,
        user: UserId,
        unread_only: bool,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Notification>> {
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let mut query: QueryBuilder<Postgres> =
            QueryBuilder::new(format!("SELECT {COLS} FROM notifications WHERE user_id = "));
        query.push_bind(*user.as_uuid());
        if unread_only {
            query.push(" AND read_at IS NULL");
        }
        if let Some(cursor) = cursor {
            // Keyset over the UUID v7 id: strictly older than the last-seen row. Ids are
            // unique, so pages stay stable across concurrent inserts.
            let cursor: NotificationId =
                cursor.parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {cursor}") })?;
            query.push(" AND id < ").push_bind(*cursor.as_uuid());
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
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL")
                .bind(*user.as_uuid())
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(count)
    }

    async fn unread_counts(&self, users: &[UserId]) -> Result<Vec<(UserId, i64)>> {
        if users.is_empty() {
            return Ok(Vec::new());
        }
        if users.len() > MAX_RECIPIENT_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_RECIPIENT_BATCH} recipients per lookup") });
        }
        let uuids: Vec<Uuid> = users.iter().map(|user| *user.as_uuid()).collect();
        let rows: Vec<UnreadCountRow> = sqlx::query_as(
            "SELECT user_id, COUNT(*) AS count FROM notifications \
             WHERE read_at IS NULL AND user_id = ANY($1) GROUP BY user_id",
        )
        .bind(&uuids)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(|row| (pub_core::UserId::from_uuid(row.user_id), row.count)).collect())
    }

    async fn mark_read(&self, user: UserId, ids: &[NotificationId], now: DateTime<Utc>) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        if ids.len() > MAX_MARK_BATCH {
            return Err(Error::Invalid { message: format!("at most {MAX_MARK_BATCH} notifications per call") });
        }
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new("UPDATE notifications SET read_at = ");
        query.push_bind(now);
        query.push(" WHERE read_at IS NULL AND user_id = ").push_bind(*user.as_uuid());
        query.push(" AND id IN (");
        let mut separated = query.separated(", ");
        for id in ids {
            separated.push_bind(*id.as_uuid());
        }
        query.push(")");
        let result = query.build().execute(&self.pool).await.map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn mark_all_read(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("UPDATE notifications SET read_at = $1 WHERE user_id = $2 AND read_at IS NULL")
            .bind(now)
            .bind(*user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn preferences(&self, user: UserId) -> Result<Vec<NotificationPreference>> {
        let rows: Vec<PrefRow> = sqlx::query_as(
            "SELECT category, in_app, email FROM notification_prefs WHERE user_id = $1 ORDER BY category",
        )
        .bind(*user.as_uuid())
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
        let uuids: Vec<Uuid> = users.iter().map(|user| *user.as_uuid()).collect();
        let rows: Vec<UserPrefRow> = sqlx::query_as(
            "SELECT user_id, category, in_app, email FROM notification_prefs \
             WHERE category = $1 AND user_id = ANY($2)",
        )
        .bind(category.as_str())
        .bind(&uuids)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    pub_core::UserId::from_uuid(row.user_id),
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
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (user_id, category) DO UPDATE SET in_app = excluded.in_app, \
                 email = excluded.email, updated_at = excluded.updated_at",
            )
            .bind(*user.as_uuid())
            .bind(pref.category.as_str())
            .bind(pref.in_app)
            .bind(pref.email)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "preference already exists", "the account"))?;
        }
        let rows: Vec<PrefRow> = sqlx::query_as(q!(
            "SELECT category, in_app, email FROM notification_prefs WHERE user_id = $1 ORDER BY category"
        ))
        .bind(*user.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
