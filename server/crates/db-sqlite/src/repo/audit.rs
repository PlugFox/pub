//! `AuditRepo` over SQLite (S-22): append, cursor-paginated read, and one floor-guarded prune.
//!
//! SQLite has no roles, so this repository *is* the enforcement — it exposes no update, and its
//! only delete is [`SqliteAuditRepo::prune_before`], which refuses any cutoff newer than
//! [`RetentionPolicy::AUDIT_FLOOR`] and deletes at most one batch per call. On Postgres the same
//! two properties are additionally enforced *below* the application, by a `SECURITY DEFINER`
//! function the app role can execute but whose privileges it does not hold; here there is no
//! below, which is why the guard is written out rather than assumed
//! ([S-22.a](../../../../docs/security.md#5-audit--abuse), [decision 30](../../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::audit::{AuditActor, AuditEvent, AuditFilter, AuditId, AuditResult, NewAuditEvent};
use pub_core::retention::RetentionPolicy;
use pub_core::traits::AuditRepo;
use pub_core::{Error, Page, Result};
use sqlx::SqlitePool;

use super::{db_err, parse_col, parse_ts, q};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All audit columns, in [`AuditRow`] order.
const COLS: &str = "id, created_at, actor_type, actor_id, ip, user_agent, org_id, action, target, result, metadata";

/// SQLite-backed [`AuditRepo`].
#[derive(Debug, Clone)]
pub struct SqliteAuditRepo {
    pool: SqlitePool,
}

impl SqliteAuditRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    created_at: String,
    actor_type: String,
    actor_id: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    org_id: Option<String>,
    action: String,
    target: Option<String>,
    result: String,
    metadata: Option<String>,
}

impl TryFrom<AuditRow> for AuditEvent {
    type Error = Error;

    fn try_from(row: AuditRow) -> Result<Self> {
        let actor = match (row.actor_type.as_str(), row.actor_id.as_deref()) {
            ("user", Some(id)) => AuditActor::User(parse_col(id)?),
            ("token", Some(id)) => AuditActor::Token(parse_col(id)?),
            ("system", None) => AuditActor::System,
            (kind, id) => {
                return Err(Error::Database { message: format!("corrupt audit actor: type={kind}, id={id:?}") });
            }
        };
        let metadata = row
            .metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|err| Error::Database { message: format!("corrupt audit metadata: {err}") })?;
        Ok(AuditEvent {
            id: parse_col::<AuditId>(&row.id)?,
            created_at: parse_ts(&row.created_at)?,
            actor,
            ip: row.ip,
            user_agent: row.user_agent,
            org_id: row.org_id.as_deref().map(parse_col).transpose()?,
            action: row.action,
            target: row.target,
            result: parse_col::<AuditResult>(&row.result)?,
            metadata,
        })
    }
}

/// The audit page statement for one filter shape, with or without its keyset predicate.
///
/// **Exported so the plan test can EXPLAIN the statement production emits instead of a copy of
/// it** — the drift roadmap [D52](../../../../docs/roadmap.md) describes, avoided here rather
/// than repeated. No caller-supplied value enters the text: the filter decides only which
/// predicates are present, and every value travels as a bind.
///
/// Binds, in this order: `org`, the `action` prefix pattern, the actor kind, the actor id (only
/// when the actor carries one — `AuditActor::System` renders `IS NULL` and binds nothing), `from`,
/// `until`, the cursor id when `with_cursor`, and finally the row limit.
///
/// The actor predicate is written as two equalities in the order `audit_actor_idx` (0018) carries
/// them, with the `id` keyset third — so an actor page is a range scan inside one actor rather
/// than a filter over the whole log.
pub fn audit_page_sql(filter: &AuditFilter, with_cursor: bool) -> String {
    let mut sql = format!("SELECT {COLS} FROM audit_log WHERE 1 = 1");
    if filter.org.is_some() {
        sql.push_str(" AND org_id = ?");
    }
    if filter.action_prefix.is_some() {
        sql.push_str(" AND action LIKE ? ESCAPE '\\'");
    }
    if let Some(actor) = &filter.actor {
        sql.push_str(" AND actor_type = ?");
        sql.push_str(if actor.id_string().is_some() { " AND actor_id = ?" } else { " AND actor_id IS NULL" });
    }
    if filter.from.is_some() {
        sql.push_str(" AND created_at >= ?");
    }
    if filter.until.is_some() {
        sql.push_str(" AND created_at < ?");
    }
    if with_cursor {
        sql.push_str(" AND id < ?");
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    sql
}

/// Escapes `%`, `_`, and the escape char itself for a `LIKE … ESCAPE '\'` prefix match.
fn like_prefix(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len() + 1);
    for ch in prefix.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push('%');
    escaped
}

#[async_trait]
impl AuditRepo for SqliteAuditRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn append(&self, event: NewAuditEvent, now: DateTime<Utc>) -> Result<AuditEvent> {
        let metadata = event
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|err| Error::Internal { message: format!("failed to encode audit metadata: {err}") })?;
        let row: AuditRow = sqlx::query_as(q!(
            "INSERT INTO audit_log (id, created_at, actor_type, actor_id, ip, user_agent, org_id, action, target, \
             result, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING {COLS}"
        ))
        .bind(AuditId::generate().to_string())
        .bind(super::ts(now))
        .bind(event.actor.kind())
        .bind(event.actor.id_string())
        .bind(&event.ip)
        .bind(&event.user_agent)
        .bind(event.org_id.map(|org| org.to_string()))
        .bind(&event.action)
        .bind(&event.target)
        .bind(event.result.as_str())
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_into()
    }

    async fn list(&self, filter: &AuditFilter, cursor: Option<&str>, limit: u32) -> Result<Page<AuditEvent>> {
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        // Keyset pagination over the ULID id: strictly older than the last-seen id. The id is
        // unique, so pages are stable even when timestamps collide. Parsed before the statement
        // is built, so a malformed cursor is a 400 rather than a query that returns nothing.
        let cursor: Option<AuditId> = cursor
            .map(|raw| raw.parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {raw}") }))
            .transpose()?;

        // The text comes from [`audit_page_sql`] and the binds follow in the order it documents.
        let mut query = sqlx::query_as::<_, AuditRow>(sqlx::AssertSqlSafe(audit_page_sql(filter, cursor.is_some())));
        if let Some(org) = filter.org {
            query = query.bind(org.to_string());
        }
        if let Some(prefix) = &filter.action_prefix {
            query = query.bind(like_prefix(prefix));
        }
        if let Some(actor) = &filter.actor {
            query = query.bind(actor.kind());
            if let Some(id) = actor.id_string() {
                query = query.bind(id);
            }
        }
        if let Some(from) = filter.from {
            query = query.bind(super::ts(from));
        }
        if let Some(until) = filter.until {
            query = query.bind(super::ts(until));
        }
        if let Some(cursor) = cursor {
            query = query.bind(cursor.to_string());
        }
        query = query.bind(limit + 1);

        let rows: Vec<AuditRow> = query.fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<AuditEvent> =
            rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
        let cursor = if has_more { items.last().map(|event| event.id.to_string()) } else { None };
        Ok(Page { items, cursor, has_more })
    }

    async fn prune_before(&self, cutoff: DateTime<Utc>, now: DateTime<Utc>, batch: u32) -> Result<u64> {
        if !RetentionPolicy::audit_cutoff_is_allowed(cutoff, now) {
            // Refused, not clamped. No legitimate path produces this — the config validator will
            // not accept a window below the floor — so a clamp would turn a caller's mistake into
            // a silent deletion of a month of evidence.
            return Err(Error::Invalid {
                message: format!(
                    "audit retention cutoff {cutoff} is newer than the {} day floor",
                    RetentionPolicy::AUDIT_FLOOR.num_days()
                ),
            });
        }
        // `id IN (SELECT … LIMIT ?)` because `DELETE … LIMIT` needs a non-default SQLite build
        // option; the inner SELECT seeks `audit_created_idx`. `ORDER BY created_at` makes the
        // batch the *oldest* rows rather than an arbitrary subset, so repeated calls converge from
        // the far end instead of nibbling at the middle of the backlog.
        let result = sqlx::query(
            "DELETE FROM audit_log WHERE id IN \
             (SELECT id FROM audit_log WHERE created_at < ? ORDER BY created_at LIMIT ?)",
        )
        .bind(super::ts(cutoff))
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
