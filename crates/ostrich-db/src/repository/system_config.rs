//! System configuration repository
//!
//! View + upsert for the CAA "System Configuration" surface.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: CM-3 (change control), CM-6, AC-6, SC-28
//! - NIAP PP-CA: FMT_SMF.1, FMT_MTD.1

use crate::{Error, Result, models::SystemConfigRecord};
use sqlx::PgPool;

/// Repository for system configuration settings.
pub struct SystemConfigRepository {
    pool: PgPool,
}

impl SystemConfigRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List every setting, ordered by key.
    pub async fn list(&self) -> Result<Vec<SystemConfigRecord>> {
        sqlx::query_as::<_, SystemConfigRecord>("SELECT * FROM system_config ORDER BY key ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Query(format!("Failed to list config: {}", e)))
    }

    /// Fetch one setting by key.
    pub async fn get(&self, key: &str) -> Result<Option<SystemConfigRecord>> {
        sqlx::query_as::<_, SystemConfigRecord>("SELECT * FROM system_config WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Query(format!("Failed to load config: {}", e)))
    }

    /// Insert or update a setting's value (and optional description), recording
    /// who changed it. Returns the stored row.
    pub async fn upsert(
        &self,
        key: &str,
        value: &str,
        description: Option<&str>,
        updated_by: &str,
    ) -> Result<SystemConfigRecord> {
        sqlx::query_as::<_, SystemConfigRecord>(
            r#"
            INSERT INTO system_config (key, value, description, updated_by, updated_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value,
                description = COALESCE(EXCLUDED.description, system_config.description),
                updated_by = EXCLUDED.updated_by,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(description)
        .bind(updated_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to upsert config: {}", e)))
    }
}
