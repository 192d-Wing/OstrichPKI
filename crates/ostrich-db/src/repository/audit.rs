//! Audit log repository with integrity chain
//!
//! This module implements the audit log repository with cryptographic hash
//! chain integrity protection. Audit records are append-only and cannot be
//! modified or deleted after creation.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - AU-2: Auditable events - All security-relevant events captured
//! - AU-3: Content of audit records - Records include who, what, when, where, outcome
//! - AU-9: Protection of audit information - Append-only with hash chain
//! - AU-9(3): Cryptographic protection - SHA-256 hash chain verification
//! - AU-10: Non-repudiation - Hash chain provides tamper evidence
//! - AU-11: Audit record retention - Time-range queries support retention policies
//! - AU-12: Audit generation - Events recorded for all CA operations
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FAU_GEN.1: Audit data generation - Repository accepts all audit event types
//!   defined in FAU_GEN.1.1 including startup/shutdown, certificate operations,
//!   and administrative actions
//! - FAU_GEN.2: User identity association - Actor field links events to subjects
//! - FAU_STG.1: Protected audit trail storage - Append-only table design with
//!   hash chain prevents unauthorized modification; update/delete operations
//!   return errors per FAU_STG.1.1 and FAU_STG.1.2
//! - FAU_STG.2: Guarantees of audit data availability - Database transactions
//!   ensure atomic commit of audit records
//! - FAU_STG.4: Prevention of audit data loss - Hash chain allows detection of
//!   any missing records; verify_chain() validates full audit trail integrity
//! - FPT_STM.1: Reliable time stamps - Timestamp field populated from trusted
//!   time source at event creation
//!
//! ## FIPS Standards
//! - FIPS 180-4: SHA-256 used for audit hash chain (event_hash field)

use crate::{DatabasePool, Error, Result, models::AuditEvent};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

/// Repository for audit log operations
///
/// Implements append-only audit log with hash chain for integrity.
/// This repository enforces strict audit protection requirements:
/// - Records can only be appended, never modified or deleted
/// - Each record is linked to the previous via SHA-256 hash chain
/// - Chain integrity can be verified at any time
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9(3) - Cryptographic protection of audit information
/// - NIAP PP-CA v2.1: FAU_STG.1 - Protected audit trail storage
/// - NIAP PP-CA v2.1: FAU_STG.1.1 - TSF shall protect stored audit records
///   from unauthorized deletion
/// - NIAP PP-CA v2.1: FAU_STG.1.2 - TSF shall prevent unauthorized
///   modifications to audit records
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
    /// This is the primary method for recording audit events. Each event is
    /// linked to the previous event via hash chain to ensure integrity.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-2 - Auditable events
    /// - NIST 800-53: AU-3 - Content of audit records
    /// - NIST 800-53: AU-10 - Non-repudiation via hash chain
    /// - NIAP PP-CA v2.1: FAU_GEN.1 - Audit data generation for CA events
    /// - NIAP PP-CA v2.1: FAU_GEN.2 - User identity association (actor field)
    /// - NIAP PP-CA v2.1: FAU_STG.2 - Guarantees of audit data availability
    /// - NIAP PP-CA v2.1: FPT_STM.1 - Reliable time stamps (timestamp field)
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
    /// Retrieves the hash of the most recent audit event to maintain
    /// the cryptographic chain linking all audit records.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9(3) - Maintain hash chain
    /// - NIAP PP-CA v2.1: FAU_STG.4 - Prevention of audit data loss
    /// - FIPS 180-4: SHA-256 hash algorithm for chain integrity
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
    /// Validates that all audit records form an unbroken hash chain,
    /// detecting any tampering, deletion, or insertion of records.
    /// Returns true if the chain is intact, false if integrity violation detected.
    ///
    /// This method performs two levels of verification:
    /// 1. **Chain Continuity**: Verifies each event's previous_hash matches the
    ///    prior event's event_hash (detects missing/inserted records)
    /// 2. **Hash Integrity**: Recomputes each event's hash from its data fields
    ///    and verifies it matches the stored hash (detects tampering)
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9(3) - Verify audit information integrity via SHA-256
    /// - NIAP PP-CA v2.1: FAU_STG.4 - Prevention of audit data loss
    ///   (allows detection of missing records via broken chain)
    /// - NIAP PP-CA v2.1: FAU_STG.1.2 - Detection of unauthorized
    ///   modifications to stored audit records
    /// - FIPS 180-4: SHA-256 hash verification for tamper detection
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
            tracing::debug!("Audit chain verification: no events to verify");
            return Ok(true);
        }

        let mut prev_hash: Option<Vec<u8>> = None;
        let total_events = events.len();

        for (index, event) in events.iter().enumerate() {
            // NIAP PP-CA: FAU_STG.4 - Verify chain continuity
            // Check that this event's previous_hash links to the prior event
            if event.previous_hash != prev_hash {
                tracing::error!(
                    "Audit chain continuity violation at event #{}/{}: {} (timestamp: {})",
                    index + 1,
                    total_events,
                    event.id,
                    event.timestamp
                );
                tracing::error!(
                    "Expected previous_hash: {:?}, found: {:?}",
                    prev_hash.as_ref().map(hex::encode),
                    event.previous_hash.as_ref().map(hex::encode)
                );
                return Ok(false);
            }

            // NIST 800-53: AU-9(3) - Verify event hash integrity
            // Recompute the hash from the event data to detect tampering
            let computed_hash = Self::compute_event_hash(event);
            if computed_hash != event.event_hash {
                tracing::error!(
                    "Audit hash integrity violation at event #{}/{}: {} (timestamp: {})",
                    index + 1,
                    total_events,
                    event.id,
                    event.timestamp
                );
                tracing::error!(
                    "Computed hash: {}, stored hash: {}",
                    hex::encode(&computed_hash),
                    hex::encode(&event.event_hash)
                );
                tracing::error!(
                    "Event details: type={}, actor={}, action={}, target={}",
                    event.event_type,
                    event.actor,
                    event.action,
                    event.target
                );
                return Ok(false);
            }

            prev_hash = Some(event.event_hash.clone());
        }

        tracing::info!(
            "Audit chain integrity verified successfully ({} events)",
            total_events
        );
        Ok(true)
    }

    /// Compute SHA-256 hash for an audit event
    ///
    /// This method recomputes the hash from the event's data fields to verify
    /// integrity. The hash computation must match exactly the algorithm used
    /// when the event was originally created.
    ///
    /// COMPLIANCE MAPPING:
    /// - FIPS 180-4: SHA-256 hash computation
    /// - NIST 800-53: AU-9(3) - Cryptographic protection
    ///
    /// # Hash Inputs (in order)
    /// 1. Event ID (UUID bytes)
    /// 2. Event type (string)
    /// 3. Actor (string)
    /// 4. Target (string)
    /// 5. Action (string)
    /// 6. Outcome (string)
    /// 7. Details (JSON string, if present)
    /// 8. IP address (if present)
    /// 9. User agent (if present)
    /// 10. Session ID (if present)
    /// 11. Previous hash (if present)
    /// 12. Timestamp (RFC 3339 format)
    fn compute_event_hash(event: &AuditEvent) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Include all immutable fields in hash (must match event::AuditEvent::compute_hash)
        hasher.update(event.id.as_bytes());
        hasher.update(event.event_type.as_bytes());
        hasher.update(event.actor.as_bytes());
        hasher.update(event.target.as_bytes());
        hasher.update(event.action.as_bytes());
        hasher.update(event.outcome.as_bytes());

        // Optional fields
        if let Some(ref details) = event.details
            && let Ok(json_str) = serde_json::to_string(details)
        {
            hasher.update(json_str.as_bytes());
        }

        if let Some(ref ip) = event.ip_address {
            hasher.update(ip.as_bytes());
        }

        if let Some(ref ua) = event.user_agent {
            hasher.update(ua.as_bytes());
        }

        if let Some(ref sid) = event.session_id {
            hasher.update(sid.as_bytes());
        }

        // Include previous hash in chain
        if let Some(ref prev) = event.previous_hash {
            hasher.update(prev);
        }

        // Include timestamp (must use RFC 3339 format for consistency)
        hasher.update(event.timestamp.to_rfc3339().as_bytes());

        hasher.finalize().to_vec()
    }

    /// Find events by actor (user/system)
    ///
    /// Retrieves audit records associated with a specific actor (user,
    /// service, or system component) for accountability tracking.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-12 - Audit generation for user actions
    /// - NIAP PP-CA v2.1: FAU_GEN.2 - User identity association
    ///   (enables querying by subject identity)
    /// - NIAP PP-CA v2.1: FDP_ACC.1 - Read access control enforced
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
    /// Retrieves audit records within a specified time window, supporting
    /// retention policy enforcement and incident investigation.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-11 - Audit record retention
    /// - NIAP PP-CA v2.1: FAU_STG.1 - Protected audit trail storage
    ///   (time-based retrieval for retention management)
    /// - NIAP PP-CA v2.1: FPT_STM.1 - Reliable time stamps
    ///   (queries based on trusted timestamps)
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
    /// Retrieves audit records for security-relevant events including
    /// authentication failures, authorization denials, and access violations.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-2 - Security-relevant events
    /// - NIAP PP-CA v2.1: FAU_GEN.1.1c - Audit of unsuccessful authentication
    /// - NIAP PP-CA v2.1: FAU_GEN.1.1d - Audit of access denials
    /// - NIAP PP-CA v2.1: FDP_ACC.1 - Read access control enforced
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

    /// Update operation is prohibited for audit records
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9 - Audit logs are append-only
    /// - NIAP PP-CA v2.1: FAU_STG.1.2 - TSF shall prevent unauthorized
    ///   modifications to stored audit records in the audit trail
    async fn update(&self, _event: &AuditEvent) -> Result<AuditEvent> {
        // NIAP PP-CA: FAU_STG.1.2 - Prevent modification of audit records
        Err(Error::ConstraintViolation(
            "Audit events cannot be modified".to_string(),
        ))
    }

    /// Delete operation is prohibited for audit records
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9 - Audit logs cannot be deleted
    /// - NIAP PP-CA v2.1: FAU_STG.1.1 - TSF shall protect stored audit
    ///   records in the audit trail from unauthorized deletion
    async fn delete(&self, _id: &Uuid) -> Result<()> {
        // NIAP PP-CA: FAU_STG.1.1 - Prevent deletion of audit records
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
