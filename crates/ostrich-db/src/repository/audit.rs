//! Audit log repository with integrity chain
//!
//! NIST 800-53: AU-2 - Auditable events
//! NIST 800-53: AU-9 - Protection of audit information
//! NIST 800-53: AU-10 - Non-repudiation

use crate::{DatabasePool, Error, Result, models::AuditEvent};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

/// Repository for audit log operations
///
/// Implements append-only audit log with hash chain for integrity
///
/// NIST 800-53: AU-9(3) - Cryptographic protection of audit information
pub struct AuditRepository {
    pool: DatabasePool,
}

impl AuditRepository {
    /// Create a new audit repository
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Append a new audit event to the log
    ///
    /// NIST 800-53: AU-2 - Auditable events
    /// NIST 800-53: AU-3 - Content of audit records
    /// NIST 800-53: AU-10 - Non-repudiation via hash chain
    pub async fn append(&self, event: &AuditEvent) -> Result<AuditEvent> {
        // Get the previous event's hash to create chain
        let prev_hash = self.get_last_hash().await?;

        let created = sqlx::query_as::<_, AuditEvent>(
            r#"
            INSERT INTO audit_events (
                id, event_type, actor, target, action, outcome,
                details, ip_address, user_agent, session_id,
                previous_hash, event_hash, timestamp
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id, event_type, actor, target, action, outcome,
                      details, ip_address, user_agent, session_id,
                      previous_hash, event_hash, timestamp
            "#,
        )
        .bind(event.id)
        .bind(&event.event_type)
        .bind(&event.actor)
        .bind(&event.target)
        .bind(&event.action)
        .bind(&event.outcome)
        .bind(&event.details)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(&event.session_id)
        .bind(&prev_hash)
        .bind(&event.event_hash)
        .bind(event.timestamp)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        tracing::debug!(
            "Audit event recorded: {} - {} {} on {}",
            event.event_type,
            event.actor,
            event.action,
            event.target
        );

        Ok(created)
    }

    /// Get the hash of the last audit event for chain integrity
    ///
    /// NIST 800-53: AU-9(3) - Maintain hash chain
    async fn get_last_hash(&self) -> Result<Option<Vec<u8>>> {
        let result = sqlx::query(
            r#"
            SELECT event_hash
            FROM audit_events
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(result.map(|row| row.get("event_hash")))
    }

    /// Verify the integrity of the audit log chain
    ///
    /// NIST 800-53: AU-9(3) - Verify audit information integrity
    pub async fn verify_chain(&self) -> Result<bool> {
        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            ORDER BY timestamp ASC
            "#,
        )
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        if events.is_empty() {
            return Ok(true);
        }

        let mut prev_hash: Option<Vec<u8>> = None;
        let total_events = events.len();

        for event in &events {
            // Verify the chain link
            if event.previous_hash != prev_hash {
                tracing::error!(
                    "Audit chain integrity violation at event {} (timestamp: {})",
                    event.id,
                    event.timestamp
                );
                return Ok(false);
            }

            // TODO: Verify event_hash by recomputing from event data
            // This requires implementing the hash function in ostrich-audit

            prev_hash = Some(event.event_hash.clone());
        }

        tracing::info!("Audit chain integrity verified ({} events)", total_events);
        Ok(true)
    }

    /// Find events by actor (user/system)
    ///
    /// NIST 800-53: AU-12 - Audit generation for user actions
    pub async fn find_by_actor(
        &self,
        actor: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            WHERE actor = $1
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(actor)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(events)
    }

    /// Find events by type
    pub async fn find_by_type(
        &self,
        event_type: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            WHERE event_type = $1
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(event_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(events)
    }

    /// Find events within a time range
    ///
    /// NIST 800-53: AU-11 - Audit record retention
    pub async fn find_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            WHERE timestamp >= $1 AND timestamp <= $2
            ORDER BY timestamp DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(start)
        .bind(end)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(events)
    }

    /// Find security-relevant events (failures, access violations, etc.)
    ///
    /// NIST 800-53: AU-2 - Security-relevant events
    pub async fn find_security_events(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            WHERE outcome = 'failure'
               OR event_type IN ('authentication', 'authorization', 'access_violation')
            ORDER BY timestamp DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(events)
    }
}

#[async_trait]
impl super::Repository<AuditEvent> for AuditRepository {
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditEvent>> {
        let event = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(event)
    }

    async fn create(&self, event: &AuditEvent) -> Result<AuditEvent> {
        // Use append method for audit events to maintain chain
        self.append(event).await
    }

    async fn update(&self, _event: &AuditEvent) -> Result<AuditEvent> {
        // NIST 800-53: AU-9 - Audit logs are append-only
        Err(Error::ConstraintViolation(
            "Audit events cannot be modified".to_string(),
        ))
    }

    async fn delete(&self, _id: &Uuid) -> Result<()> {
        // NIST 800-53: AU-9 - Audit logs cannot be deleted
        Err(Error::ConstraintViolation(
            "Audit events cannot be deleted".to_string(),
        ))
    }

    async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, event_type, actor, target, action, outcome,
                   details, ip_address, user_agent, session_id,
                   previous_hash, event_hash, timestamp
            FROM audit_events
            ORDER BY timestamp DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok(events)
    }

    async fn count(&self) -> Result<i64> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM audit_events")
            .fetch_one(self.pool.pool())
            .await
            .map_err(|e| Error::Query(e.to_string()))?;

        Ok(result.get("count"))
    }
}
