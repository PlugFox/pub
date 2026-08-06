//! `SettingsRepo` over Postgres (decision 09): key → JSON with per-key versions.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::settings::SettingEntry;
use pub_core::traits::SettingsRepo;
use pub_core::{Error, Result};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row as _};

use super::db_err;

/// Postgres-backed [`SettingsRepo`].
#[derive(Debug, Clone)]
pub struct PgSettingsRepo {
    pool: PgPool,
}

impl PgSettingsRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct SettingRow {
    key: String,
    value: String,
    version: i64,
}

impl TryFrom<SettingRow> for SettingEntry {
    type Error = Error;

    fn try_from(row: SettingRow) -> Result<Self> {
        let value = serde_json::from_str(&row.value)
            .map_err(|err| Error::Database { message: format!("corrupt settings value for {:?}: {err}", row.key) })?;
        Ok(SettingEntry { key: row.key, value, version: row.version })
    }
}

#[async_trait]
impl SettingsRepo for PgSettingsRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<SettingEntry>> {
        let rows: Vec<SettingRow> =
            sqlx::query_as("SELECT key, value::text AS value, version FROM settings ORDER BY key")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn upsert(&self, key: &str, value: &serde_json::Value, now: DateTime<Utc>) -> Result<i64> {
        let encoded = value.to_string();
        let row: PgRow = sqlx::query(
            "INSERT INTO settings (key, value, version, updated_at) VALUES ($1, $2::jsonb, 1, $3) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, version = settings.version + 1, \
             updated_at = excluded.updated_at RETURNING version",
        )
        .bind(key)
        .bind(&encoded)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.get("version"))
    }

    async fn get_version(&self) -> Result<i64> {
        // SUM over per-key versions: increases on every upsert (see core::settings docs).
        // SUM(BIGINT) yields NUMERIC in Postgres — cast back to BIGINT for decoding.
        let row: PgRow = sqlx::query("SELECT CAST(COALESCE(SUM(version), 0) AS BIGINT) AS version FROM settings")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.get("version"))
    }
}
