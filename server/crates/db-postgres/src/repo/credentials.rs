//! `CredentialRepo` over Postgres.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::credential::{Credential, CredentialType, RecoveryCodeHash, TotpCredential};
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

    async fn create_totp(
        &self,
        user: UserId,
        secret_enc: &[u8],
        last_step: i64,
        now: DateTime<Utc>,
    ) -> Result<Credential> {
        let row: CredentialRow = sqlx::query_as(q!(
            "INSERT INTO credentials (id, user_id, type, secret_enc, totp_last_step, created_at, updated_at) \
             VALUES ($1, $2, 'totp', $3, $4, $5, $6) RETURNING {COLS}"
        ))
        .bind(*CredentialId::new().as_uuid())
        .bind(*user.as_uuid())
        .bind(secret_enc)
        .bind(last_step)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "totp is already enrolled for this user", "user"))?;
        row.try_into()
    }

    async fn find_totp(&self, user: UserId) -> Result<Option<TotpCredential>> {
        let row: Option<(Uuid, Vec<u8>, Option<i64>)> = sqlx::query_as(
            "SELECT id, secret_enc, totp_last_step FROM credentials WHERE user_id = $1 AND type = 'totp'",
        )
        .bind(*user.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(|(id, secret_enc, last_step)| TotpCredential {
            id: CredentialId::from_uuid(id),
            user_id: user,
            secret_enc,
            last_step,
        }))
    }

    async fn commit_totp_step(&self, id: CredentialId, step: i64, now: DateTime<Utc>) -> Result<bool> {
        // Single-statement compare-and-set: Postgres row locking makes this atomic, and the
        // WHERE clause is the replay gate (S-05) — no read-modify-write window exists.
        let result = sqlx::query(
            "UPDATE credentials SET totp_last_step = $1, updated_at = $2 \
             WHERE id = $3 AND type = 'totp' AND (totp_last_step IS NULL OR totp_last_step < $1)",
        )
        .bind(step)
        .bind(now)
        .bind(*id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_recovery_codes(&self, user: UserId, phc_hashes: &[String], now: DateTime<Utc>) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("DELETE FROM credentials WHERE user_id = $1 AND type = 'recovery'")
            .bind(*user.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        for phc in phc_hashes {
            sqlx::query(
                "INSERT INTO credentials (id, user_id, type, secret_enc, created_at, updated_at) \
                 VALUES ($1, $2, 'recovery', $3, $4, $5)",
            )
            .bind(*CredentialId::new().as_uuid())
            .bind(*user.as_uuid())
            .bind(phc.as_bytes())
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "duplicate recovery code row", "user"))?;
        }
        tx.commit().await.map_err(db_err)
    }

    async fn list_recovery_codes(&self, user: UserId) -> Result<Vec<RecoveryCodeHash>> {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, secret_enc FROM credentials WHERE user_id = $1 AND type = 'recovery' ORDER BY id",
        )
        .bind(*user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter()
            .map(|(id, phc)| {
                let phc = String::from_utf8(phc)
                    .map_err(|_| Error::Database { message: "corrupt recovery-code hash (not UTF-8)".to_owned() })?;
                Ok(RecoveryCodeHash { id: CredentialId::from_uuid(id), phc })
            })
            .collect()
    }

    async fn consume_recovery_code(&self, id: CredentialId) -> Result<bool> {
        // Single-use is decided by this DELETE's row count (S-05): of two racers, exactly one
        // observes rows_affected = 1.
        let result = sqlx::query("DELETE FROM credentials WHERE id = $1 AND type = 'recovery'")
            .bind(*id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_second_factor(&self, user: UserId) -> Result<u64> {
        let result = sqlx::query("DELETE FROM credentials WHERE user_id = $1 AND type IN ('totp', 'recovery')")
            .bind(*user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn delete_all_for_user(&self, user: UserId) -> Result<u64> {
        // No type predicate on purpose: this is account deletion (S-29.a), and a type filter
        // here is a list that silently stops covering `webauthn` the day those rows arrive.
        let result = sqlx::query("DELETE FROM credentials WHERE user_id = $1")
            .bind(*user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
