//! `TokenRepo` over Postgres (decision 13, S-13).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::token::{NewToken, Token, TokenScope};
use pub_core::traits::TokenRepo;
use pub_core::{Error, OrgId, Result, TokenId, UserId};
use sqlx::PgPool;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use super::{cutoff, db_err, q, write_err};

/// All token columns exposed to the domain, in [`TokenRow`] order (the hash stays internal;
/// `JSONB` reads back as text, `INET` via `host()` — a bare `::text` cast would append `/32`).
const COLS: &str = "id, user_id, org_id, name, display_hint, scopes::text AS scopes, \
                    package_patterns::text AS package_patterns, created_at, expires_at, last_used_at, \
                    host(last_used_ip) AS last_used_ip, revoked_at";

/// Postgres-backed [`TokenRepo`].
#[derive(Debug, Clone)]
pub struct PgTokenRepo {
    pool: PgPool,
}

impl PgTokenRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    user_id: Uuid,
    org_id: Uuid,
    name: String,
    display_hint: String,
    scopes: String,
    package_patterns: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    last_used_ip: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<TokenRow> for Token {
    type Error = Error;

    fn try_from(row: TokenRow) -> Result<Self> {
        let scopes: Vec<TokenScope> = serde_json::from_str(&row.scopes)
            .map_err(|err| Error::Database { message: format!("corrupt token scopes {:?}: {err}", row.scopes) })?;
        let package_patterns: Vec<String> = serde_json::from_str(&row.package_patterns).map_err(|err| {
            Error::Database { message: format!("corrupt token patterns {:?}: {err}", row.package_patterns) }
        })?;
        Ok(Token {
            id: TokenId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            org_id: OrgId::from_uuid(row.org_id),
            name: row.name,
            display_hint: row.display_hint,
            scopes,
            package_patterns,
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            last_used_ip: row.last_used_ip,
            revoked_at: row.revoked_at,
        })
    }
}

#[async_trait]
impl TokenRepo for PgTokenRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewToken, now: DateTime<Utc>) -> Result<Token> {
        if new.scopes.is_empty() {
            return Err(Error::Invalid { message: "a token needs at least one scope".to_owned() });
        }
        let scopes = serde_json::to_string(&new.scopes)
            .map_err(|err| Error::Internal { message: format!("failed to encode scopes: {err}") })?;
        let patterns = serde_json::to_string(&new.package_patterns)
            .map_err(|err| Error::Internal { message: format!("failed to encode patterns: {err}") })?;
        let row: TokenRow = sqlx::query_as(q!(
            "INSERT INTO tokens (id, user_id, org_id, name, token_hash, display_hint, scopes, package_patterns, \
             created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10) RETURNING {COLS}"
        ))
        .bind(*TokenId::new().as_uuid())
        .bind(*new.user_id.as_uuid())
        .bind(*new.org_id.as_uuid())
        .bind(&new.name)
        .bind(&new.token_hash)
        .bind(&new.display_hint)
        .bind(&scopes)
        .bind(&patterns)
        .bind(now)
        .bind(new.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "token hash already exists", "user or org"))?;
        row.try_into()
    }

    async fn find_active_by_hash(&self, token_hash: &str, now: DateTime<Utc>) -> Result<Option<Token>> {
        let row: Option<TokenRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM tokens WHERE token_hash = $1 AND revoked_at IS NULL \
             AND (expires_at IS NULL OR expires_at > $2)"))
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn touch_last_used(
        &self,
        id: TokenId,
        ip: Option<&str>,
        throttle: Duration,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE tokens SET last_used_at = $1, last_used_ip = $2::inet WHERE id = $3 AND revoked_at IS NULL \
             AND (last_used_at IS NULL OR last_used_at < $4)",
        )
        .bind(now)
        .bind(ip)
        .bind(*id.as_uuid())
        .bind(cutoff(now, throttle))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke(&self, id: TokenId, now: DateTime<Utc>) -> Result<()> {
        let result = sqlx::query("UPDATE tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(*id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        if result.rows_affected() > 0 {
            return Ok(());
        }
        // Idempotent for already-revoked tokens; NotFound for unknown ids.
        let exists: Option<PgRow> = sqlx::query("SELECT id FROM tokens WHERE id = $1")
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if exists.is_some() { Ok(()) } else { Err(Error::NotFound { what: format!("token {id}") }) }
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<Token>> {
        let rows: Vec<TokenRow> = sqlx::query_as(q!(
            "SELECT {COLS} FROM tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC, id DESC"
        ))
        .bind(*user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_for_org(&self, org: OrgId) -> Result<Vec<Token>> {
        let rows: Vec<TokenRow> = sqlx::query_as(q!(
            "SELECT {COLS} FROM tokens WHERE org_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC, id DESC"
        ))
        .bind(*org.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
