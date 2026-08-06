//! `CredentialRepo` over Postgres.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::credential::{Credential, CredentialType};
use pub_core::traits::CredentialRepo;
use pub_core::{CredentialId, Error, Result, UserId};
use sqlx::PgPool;
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// All credential columns, in [`CredentialRow`] order (`type` aliased — Rust keyword).
const COLS: &str = "id, user_id, type AS credential_type, issuer, subject, email, created_at, updated_at";

/// Postgres-backed [`CredentialRepo`].
#[derive(Debug, Clone)]
pub struct PgCredentialRepo {
    pool: PgPool,
}

impl PgCredentialRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: Uuid,
    user_id: Uuid,
    credential_type: String,
    issuer: Option<String>,
    subject: Option<String>,
    email: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<CredentialRow> for Credential {
    type Error = Error;

    fn try_from(row: CredentialRow) -> Result<Self> {
        Ok(Credential {
            id: CredentialId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            credential_type: parse_col::<CredentialType>(&row.credential_type)?,
            issuer: row.issuer,
            subject: row.subject,
            email: row.email,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[async_trait]
impl CredentialRepo for PgCredentialRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn upsert_oidc(&self, user: UserId, issuer: &str, subject: &str, now: DateTime<Utc>) -> Result<Credential> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // FOR UPDATE: the refresh path must not race a concurrent re-link check.
        let existing: Option<CredentialRow> = sqlx::query_as(q!(
            "SELECT {COLS} FROM credentials WHERE type = 'oidc' AND issuer = $1 AND subject = $2 FOR UPDATE"
        ))
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row: CredentialRow = match existing {
            Some(row) if row.user_id == *user.as_uuid() => {
                // The every-sign-in refresh path.
                sqlx::query_as(q!("UPDATE credentials SET updated_at = $1 WHERE id = $2 RETURNING {COLS}"))
                    .bind(now)
                    .bind(row.id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?
            }
            Some(_) => {
                // Linked to another account: never silently re-bind (S-02).
                return Err(Error::Conflict { message: "oidc identity already linked to another account".to_owned() });
            }
            None => sqlx::query_as(q!(
                "INSERT INTO credentials (id, user_id, type, issuer, subject, created_at, updated_at) \
                 VALUES ($1, $2, 'oidc', $3, $4, $5, $6) RETURNING {COLS}"
            ))
            .bind(*CredentialId::new().as_uuid())
            .bind(*user.as_uuid())
            .bind(issuer)
            .bind(subject)
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| write_err(err, "oidc identity already linked to another account", "user"))?,
        };
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn find_oidc(&self, issuer: &str, subject: &str) -> Result<Option<Credential>> {
        let row: Option<CredentialRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM credentials WHERE type = 'oidc' AND issuer = $1 AND subject = $2"))
                .bind(issuer)
                .bind(subject)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn create_email_identity(&self, user: UserId, email: &str, now: DateTime<Utc>) -> Result<Credential> {
        let row: CredentialRow =
            sqlx::query_as(q!("INSERT INTO credentials (id, user_id, type, email, created_at, updated_at) \
             VALUES ($1, $2, 'email', $3, $4, $5) RETURNING {COLS}"))
            .bind(*CredentialId::new().as_uuid())
            .bind(*user.as_uuid())
            .bind(email)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| write_err(err, "email identity already exists for this user", "user"))?;
        row.try_into()
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<Credential>> {
        let rows: Vec<CredentialRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM credentials WHERE user_id = $1 ORDER BY created_at, id"))
                .bind(*user.as_uuid())
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
