//! `AuditRepo` over Postgres (S-22): append, cursor-paginated read, and one delete this role may
//! not perform itself.
//!
//! Defense in depth: besides this repository exposing no update, the migration file carries the
//! INSERT-only role grant template applied at deploy time (docs/rules/migrations.md) — and
//! [`PgAuditRepo::prune_before`] does **not** weaken it. The template's
//! `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log` stands; retention calls `pub_audit_prune`
//! (migration 0012), a `SECURITY DEFINER` function owned by the migration role, on which the app
//! role holds only `EXECUTE`. So the reachable capability is "delete audit rows older than thirty
//! days, one bounded batch at a time" rather than "delete audit rows"
//! ([S-22.a](../../../../docs/security.md#5-audit--abuse), [decision 30](../../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)).

use std::fmt::Write as _;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::audit::{AuditActor, AuditEvent, AuditFilter, AuditId, AuditResult, NewAuditEvent};
use pub_core::retention::RetentionPolicy;
use pub_core::traits::AuditRepo;
use pub_core::{Error, Page, Result};
use sqlx::PgPool;
use uuid::Uuid;

use super::{db_err, parse_col, q};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All audit columns, in [`AuditRow`] order (`JSONB` reads back as text, `INET` via `host()` —
/// a bare `::text` cast would append `/32`).
const COLS: &str = "id, created_at, actor_type, actor_id, host(ip) AS ip, user_agent, org_id, action, target, \
                    result, metadata::text AS metadata";

/// Postgres-backed [`AuditRepo`].
#[derive(Debug, Clone)]
pub struct PgAuditRepo {
    pool: PgPool,
}

impl PgAuditRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    created_at: DateTime<Utc>,
    actor_type: String,
    actor_id: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    org_id: Option<Uuid>,
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
            created_at: row.created_at,
            actor,
            ip: row.ip,
            user_agent: row.user_agent,
            org_id: row.org_id.map(pub_core::OrgId::from_uuid),
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
/// predicates are present, and every value travels as a numbered bind.
///
/// Binds, in this order: `org`, the `action` prefix pattern, the actor kind, the actor id (only
/// when the actor carries one — `AuditActor::System` renders `IS NULL` and binds nothing), `from`,
/// `until`, the cursor id when `with_cursor`, and finally the row limit.
///
/// The actor predicate is written as two equalities in the order `audit_actor_idx` (0018) carries
/// them, with the `id` keyset third — so an actor page is an index scan inside one actor rather
/// than a filter over the whole log.
pub fn audit_page_sql(filter: &AuditFilter, with_cursor: bool) -> String {
    let mut sql = format!("SELECT {COLS} FROM audit_log WHERE TRUE");
    let mut slot = 0;
    let mut next = move || {
        slot += 1;
        slot
    };
    if filter.org.is_some() {
        let _ = write!(sql, " AND org_id = ${}", next());
    }
    if filter.action_prefix.is_some() {
        let _ = write!(sql, " AND action LIKE ${} ESCAPE '\\'", next());
    }
    if let Some(actor) = &filter.actor {
        let _ = write!(sql, " AND actor_type = ${}", next());
        if actor.id_string().is_some() {
            let _ = write!(sql, " AND actor_id = ${}", next());
        } else {
            sql.push_str(" AND actor_id IS NULL");
        }
    }
    if filter.from.is_some() {
        let _ = write!(sql, " AND created_at >= ${}", next());
    }
    if filter.until.is_some() {
        let _ = write!(sql, " AND created_at < ${}", next());
    }
    if with_cursor {
        let _ = write!(sql, " AND id < ${}", next());
    }
    let _ = write!(sql, " ORDER BY id DESC LIMIT ${}", next());
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
impl AuditRepo for PgAuditRepo {
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
             result, metadata) VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11::jsonb) RETURNING {COLS}"
        ))
        .bind(AuditId::generate().to_string())
        .bind(now)
        .bind(event.actor.kind())
        .bind(event.actor.id_string())
        .bind(&event.ip)
        .bind(&event.user_agent)
        .bind(event.org_id.map(|org| *org.as_uuid()))
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
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        // Keyset pagination over the ULID id: strictly older than the last-seen id. The id is
        // unique, so pages are stable even when timestamps collide. Parsed before the statement
        // is built, so a malformed cursor is a 400 rather than a query that returns nothing.
        let cursor: Option<AuditId> = cursor
            .map(|raw| raw.parse().map_err(|_| Error::Invalid { message: format!("malformed cursor: {raw}") }))
            .transpose()?;

        // The text comes from [`audit_page_sql`] and the binds follow in the order it documents.
        let mut query = sqlx::query_as::<_, AuditRow>(sqlx::AssertSqlSafe(audit_page_sql(filter, cursor.is_some())));
        if let Some(org) = filter.org {
            query = query.bind(*org.as_uuid());
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
            query = query.bind(from);
        }
        if let Some(until) = filter.until {
            query = query.bind(until);
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
            // Checked here as well as inside the function, and checked here *first*, so the
            // contract is identical on both dialects: SQLite has no function to check it in, and a
            // caller must not learn the floor from a Postgres-only error.
            return Err(Error::Invalid {
                message: format!(
                    "audit retention cutoff {cutoff} is newer than the {} day floor",
                    RetentionPolicy::AUDIT_FLOOR.num_days()
                ),
            });
        }
        // No direct DELETE: this role does not have one on `audit_log` and must not be given one.
        // A missing `EXECUTE` grant surfaces as a database error the lifecycle job renders as a
        // refusal naming the grant — never as a generic internal failure, and never as a silent
        // skip.
        let deleted: i64 = sqlx::query_scalar("SELECT pub_audit_prune($1, $2)")
            .bind(cutoff)
            .bind(i32::try_from(batch).unwrap_or(i32::MAX))
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(u64::try_from(deleted).unwrap_or(0))
    }
}
