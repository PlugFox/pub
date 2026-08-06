//! `CredentialRepo` over SQLite.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::credential::{Credential, CredentialType, RecoveryCodeHash, TotpCredential};
use pub_core::traits::CredentialRepo;
use pub_core::{CredentialId, Error, Result, UserId};
use sqlx::SqlitePool;

use super::{db_err, parse_col, parse_ts, q, write_err};

/// All credential columns, in [`CredentialRow`] order (`type` aliased — Rust keyword).
const COLS: &str = "id, user_id, type AS credential_type, issuer, subject, email, created_at, updated_at";

/// SQLite-backed [`CredentialRepo`].
#[derive(Debug, Clone)]
pub struct SqliteCredentialRepo {
    pool: SqlitePool,
}

impl SqliteCredentialRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: String,
    user_id: String,
    credential_type: String,
    issuer: Option<String>,
    subject: Option<String>,
    email: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<CredentialRow> for Credential {
    type Error = Error;

    fn try_from(row: CredentialRow) -> Result<Self> {
        Ok(Credential {
            id: parse_col(&row.id)?,
            user_id: parse_col(&row.user_id)?,
            credential_type: parse_col::<CredentialType>(&row.credential_type)?,
            issuer: row.issuer,
            subject: row.subject,
            email: row.email,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[async_trait]
impl CredentialRepo for SqliteCredentialRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn upsert_oidc(&self, user: UserId, issuer: &str, subject: &str, now: DateTime<Utc>) -> Result<Credential> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let existing: Option<CredentialRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM credentials WHERE type = 'oidc' AND issuer = ? AND subject = ?"))
                .bind(issuer)
                .bind(subject)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;

        let row: CredentialRow = match existing {
            Some(row) if row.user_id == user.to_string() => {
                // The every-sign-in refresh path.
                sqlx::query_as(q!("UPDATE credentials SET updated_at = ? WHERE id = ? RETURNING {COLS}"))
                    .bind(super::ts(now))
                    .bind(&row.id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?
            }
            Some(_) => {
                // Linked to another account: never silently re-bind (S-02).
                return Err(Error::Conflict { message: "oidc identity already linked to another account".to_owned() });
            }
            None => {
                let stamp = super::ts(now);
                sqlx::query_as(q!(
                    "INSERT INTO credentials (id, user_id, type, issuer, subject, created_at, updated_at) \
                     VALUES (?, ?, 'oidc', ?, ?, ?, ?) RETURNING {COLS}"
                ))
                .bind(CredentialId::new().to_string())
                .bind(user.to_string())
                .bind(issuer)
                .bind(subject)
                .bind(&stamp)
                .bind(&stamp)
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| write_err(err, "oidc identity already linked to another account", "user"))?
            }
        };
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn find_oidc(&self, issuer: &str, subject: &str) -> Result<Option<Credential>> {
        let row: Option<CredentialRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM credentials WHERE type = 'oidc' AND issuer = ? AND subject = ?"))
                .bind(issuer)
                .bind(subject)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn create_email_identity(&self, user: UserId, email: &str, now: DateTime<Utc>) -> Result<Credential> {
        let stamp = super::ts(now);
        let row: CredentialRow =
            sqlx::query_as(q!("INSERT INTO credentials (id, user_id, type, email, created_at, updated_at) \
             VALUES (?, ?, 'email', ?, ?, ?) RETURNING {COLS}"))
            .bind(CredentialId::new().to_string())
            .bind(user.to_string())
            .bind(email)
            .bind(&stamp)
            .bind(&stamp)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| write_err(err, "email identity already exists for this user", "user"))?;
        row.try_into()
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<Credential>> {
        let rows: Vec<CredentialRow> =
            sqlx::query_as(q!("SELECT {COLS} FROM credentials WHERE user_id = ? ORDER BY created_at, id"))
                .bind(user.to_string())
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
        let stamp = super::ts(now);
        let row: CredentialRow = sqlx::query_as(q!(
            "INSERT INTO credentials (id, user_id, type, secret_enc, totp_last_step, created_at, updated_at) \
             VALUES (?, ?, 'totp', ?, ?, ?, ?) RETURNING {COLS}"
        ))
        .bind(CredentialId::new().to_string())
        .bind(user.to_string())
        .bind(secret_enc)
        .bind(last_step)
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "totp is already enrolled for this user", "user"))?;
        row.try_into()
    }

    async fn find_totp(&self, user: UserId) -> Result<Option<TotpCredential>> {
        let row: Option<(String, Vec<u8>, Option<i64>)> = sqlx::query_as(
            "SELECT id, secret_enc, totp_last_step FROM credentials WHERE user_id = ? AND type = 'totp'",
        )
        .bind(user.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|(id, secret_enc, last_step)| {
            Ok(TotpCredential { id: parse_col(&id)?, user_id: user, secret_enc, last_step })
        })
        .transpose()
    }

    async fn commit_totp_step(&self, id: CredentialId, step: i64, now: DateTime<Utc>) -> Result<bool> {
        // Single-statement compare-and-set: SQLite's single writer makes this atomic, and the
        // WHERE clause is the replay gate (S-05) — no read-modify-write window exists.
        let result = sqlx::query(
            "UPDATE credentials SET totp_last_step = ?, updated_at = ? \
             WHERE id = ? AND type = 'totp' AND (totp_last_step IS NULL OR totp_last_step < ?)",
        )
        .bind(step)
        .bind(super::ts(now))
        .bind(id.to_string())
        .bind(step)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_recovery_codes(&self, user: UserId, phc_hashes: &[String], now: DateTime<Utc>) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("DELETE FROM credentials WHERE user_id = ? AND type = 'recovery'")
            .bind(user.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let stamp = super::ts(now);
        for phc in phc_hashes {
            sqlx::query(
                "INSERT INTO credentials (id, user_id, type, secret_enc, created_at, updated_at) \
                 VALUES (?, ?, 'recovery', ?, ?, ?)",
            )
            .bind(CredentialId::new().to_string())
            .bind(user.to_string())
            .bind(phc.as_bytes())
            .bind(&stamp)
            .bind(&stamp)
            .execute(&mut *tx)
            .await
            .map_err(|err| write_err(err, "duplicate recovery code row", "user"))?;
        }
        tx.commit().await.map_err(db_err)
    }

    async fn list_recovery_codes(&self, user: UserId) -> Result<Vec<RecoveryCodeHash>> {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, secret_enc FROM credentials WHERE user_id = ? AND type = 'recovery' ORDER BY id",
        )
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter()
            .map(|(id, phc)| {
                let phc = String::from_utf8(phc)
                    .map_err(|_| Error::Database { message: "corrupt recovery-code hash (not UTF-8)".to_owned() })?;
                Ok(RecoveryCodeHash { id: parse_col(&id)?, phc })
            })
            .collect()
    }

    async fn consume_recovery_code(&self, id: CredentialId) -> Result<bool> {
        // Single-use is decided by this DELETE's row count (S-05): of two racers, exactly one
        // observes rows_affected = 1.
        let result = sqlx::query("DELETE FROM credentials WHERE id = ? AND type = 'recovery'")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_second_factor(&self, user: UserId) -> Result<u64> {
        let result = sqlx::query("DELETE FROM credentials WHERE user_id = ? AND type IN ('totp', 'recovery')")
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
