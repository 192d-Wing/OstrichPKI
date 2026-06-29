//! Namespace / wildcard policy repository
//!
//! CRUD for the CAA "Wildcard Management" surface.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: CM-3 (change control), AC-6, SI-10, SC-28
//! - NIAP PP-CA: FMT_SMF.1, FDP_ACF.1

use crate::{Error, Result, models::NamespaceRecord};
use sqlx::PgPool;
use uuid::Uuid;

/// Repository for certificate namespace / wildcard policy rules.
pub struct NamespaceRepository {
    pool: PgPool,
}

impl NamespaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new namespace rule.
    pub async fn create(&self, rule: &NamespaceRecord) -> Result<NamespaceRecord> {
        sqlx::query_as::<_, NamespaceRecord>(
            r#"
            INSERT INTO namespaces (id, pattern, allow, description, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(rule.id)
        .bind(&rule.pattern)
        .bind(rule.allow)
        .bind(&rule.description)
        .bind(&rule.created_by)
        .bind(rule.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to create namespace: {}", e)))
    }

    /// List all namespace rules, ordered by pattern.
    pub async fn list(&self) -> Result<Vec<NamespaceRecord>> {
        sqlx::query_as::<_, NamespaceRecord>("SELECT * FROM namespaces ORDER BY pattern ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Query(format!("Failed to list namespaces: {}", e)))
    }

    /// Delete a namespace rule by id. Returns false if no such rule.
    pub async fn delete(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM namespaces WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Query(format!("Failed to delete namespace: {}", e)))?;
        Ok(result.rows_affected() > 0)
    }
}
