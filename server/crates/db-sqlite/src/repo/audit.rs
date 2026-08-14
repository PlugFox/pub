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
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

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
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(format!("SELECT {COLS} FROM audit_log WHERE 1 = 1"));

        if let Some(org) = filter.org {
            query.push(" AND org_id = ").push_bind(org.to_string());
        }
        if let Some(prefix) = &filter.action_prefix {
            query.push(" AND action LIKE ").push_bind(like_prefix(prefix)).push(" ESCAPE '\\'");
        }
        if let Some(actor) = &filter.actor {
            query.push(" AND actor_type = ").push_bind(actor.kind());
            match actor.id_string() {
                Some(id) => {
                    query.push(" AND actor_id = ").push_bind(id);
                }
                None => {
                    query.push(" AND actor_id IS NULL");
                }
            }
        }
        if let Some(from) = filter.from {
            query.push(" AND created_at >= ").push_bind(super::ts(from));
        }
        if let Some(until) = filter.until {
            query.push(" AND created_at < ").push_bind(super::ts(until));
        }
        if let Some(cursor) = cursor {
            // Keyset pagination over the ULID id: strictly older than the last-seen id. The
            // id is unique, so pages are stable even when timestamps collide.
            let cursor: AuditId =
                cursor.parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {cursor}") })?;
            query.push(" AND id < ").push_bind(cursor.to_string());
        }
        query.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

        let rows: Vec<AuditRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
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
