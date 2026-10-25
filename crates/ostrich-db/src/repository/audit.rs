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

/// Fixed key of the PostgreSQL advisory lock that serialises audit-chain
/// appends across all services and instances sharing the database
/// ("OSTRICHA" as ASCII, big-endian).
// POAM: POAM-2026-10-23-31 - append serialisation is verified against
// Postgres only by the opt-in test `crates/ostrich-audit/tests/chain_concurrency.rs`
// (OSTRICH_DB_TESTS=1), which CI does not run yet.
pub const AUDIT_CHAIN_LOCK_KEY: i64 = 0x4F53_5452_4943_4841;

/// `lock_timeout` for an audit-chain append transaction: how long a writer
/// waits for [`AUDIT_CHAIN_LOCK_KEY`] before the append fails (closed) instead
/// of blocking behind a stalled holder (AU-5, SC-5).
pub const AUDIT_CHAIN_LOCK_TIMEOUT_MS: u32 = 5_000;

/// `statement_timeout` for each statement of an audit-chain append
/// transaction (head read, insert).
pub const AUDIT_CHAIN_STATEMENT_TIMEOUT_MS: u32 = 10_000;

/// `idle_in_transaction_session_timeout` for an audit-chain append
/// transaction. The record is signed between the head read and the insert,
/// with the transaction idle and the chain lock held. If the client stalls
/// there (a hung HSM call, a stuck process), Postgres terminates the session
/// after this long, which rolls back and releases the advisory lock for the
/// other writers. Kept slightly above the audit sink's sign timeout
/// (`ostrich_audit::sink::AUDIT_SIGN_TIMEOUT`, 5 s) so the client normally
/// gives up first.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5 (Response to Audit Processing Failures), SC-5
pub const AUDIT_CHAIN_IDLE_TIMEOUT_MS: u32 = 7_000;

/// An in-progress, serialised audit-chain append (see
/// [`AuditRepository::begin_append`]). Holds the advisory lock until
/// [`Self::commit`] or drop (rollback).
pub struct AuditAppendTx {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    previous_hash: Option<Vec<u8>>,
    previous_timestamp: Option<DateTime<Utc>>,
}

impl AuditAppendTx {
    /// Hash of the current chain head (`None` for the first record).
    pub fn previous_hash(&self) -> Option<&[u8]> {
        self.previous_hash.as_deref()
    }

    /// Timestamp of the current chain head. Chain order is timestamp order,
    /// so a new record must be strictly later (FPT_STM.1 / AU-9(3)).
    pub fn previous_timestamp(&self) -> Option<DateTime<Utc>> {
        self.previous_timestamp
    }

    /// Insert the record and commit, releasing the lock. The record must link
    /// to [`Self::previous_hash`] and be later than
    /// [`Self::previous_timestamp`].
    pub async fn commit(mut self, event: &AuditEvent) -> Result<AuditEvent> {
        if event.previous_hash.as_deref() != self.previous_hash.as_deref() {
            return Err(Error::ConstraintViolation(
                "audit record does not link to the current chain head".to_string(),
            ));
        }
        if self
            .previous_timestamp
            .is_some_and(|head| event.timestamp <= head)
        {
            return Err(Error::ConstraintViolation(
                "audit record timestamp is not after the current chain head".to_string(),
            ));
        }
        let created = AuditRepository::insert(&mut *self.tx, event).await?;
        self.tx
            .commit()
            .await
            .map_err(|e| Error::Query(e.to_string()))?;
        Ok(created)
    }
}

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

    /// Insert a fully prepared audit record, checked against the chain head.
    ///
    /// This method does NOT build the chain: the caller must already have set
    /// `previous_hash`, `timestamp` and `event_hash` (and the signature) for
    /// the current head. The insert runs under the chain lock (via
    /// [`Self::begin_append`]) and is refused with
    /// [`Error::ConstraintViolation`] if the record does not link to the
    /// current head or is not later than it, so it can never fork the chain.
    /// Writers that need the head to build a record use [`Self::begin_append`]
    /// directly (as `ostrich_audit::DatabaseAuditSink` does).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9(3) - chain linkage verified under the chain lock
    /// - NIAP PP-CA v2.1: FAU_STG.1, FAU_STG.4
    pub async fn append(&self, event: &AuditEvent) -> Result<AuditEvent> {
        // We persist exactly what was hashed/signed; re-deriving the link here
        // would store a link the event_hash never covered.
        let created = self.begin_append().await?.commit(event).await?;

        tracing::debug!(
            "Audit event recorded: {} - {} {} on {}",
            event.event_type,
            event.actor,
            event.action,
            event.target
        );

        Ok(created)
    }

    /// Start an atomic, serialised chain append.
    ///
    /// Opens a transaction, takes the transaction-scoped advisory lock
    /// [`AUDIT_CHAIN_LOCK_KEY`] (shared by every service writing to this
    /// database), and reads the current chain head. The caller links, hashes
    /// and signs its record against [`AuditAppendTx::previous_hash`] and then
    /// calls [`AuditAppendTx::commit`]. Concurrent appenders wait on the lock,
    /// so two records can never link to the same predecessor (forked chain).
    /// Dropping the handle without committing rolls back and releases the
    /// lock.
    ///
    /// The transaction sets `lock_timeout` ([`AUDIT_CHAIN_LOCK_TIMEOUT_MS`]),
    /// `statement_timeout` ([`AUDIT_CHAIN_STATEMENT_TIMEOUT_MS`]) and
    /// `idle_in_transaction_session_timeout` ([`AUDIT_CHAIN_IDLE_TIMEOUT_MS`])
    /// first. Waiting writers fail (closed, nothing inserted) instead of
    /// queueing without bound, and a holder that goes idle mid-append (stuck
    /// signing) has its session killed by the server, which releases the lock.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9 / AU-9(3) - hash chain integrity under concurrency
    /// - NIST 800-53: AU-5 - bounded wait; the failure is reported to the caller
    /// - NIAP PP-CA v2.1: FAU_STG.1, FAU_STG.4, FPT_STM.1 (monotonic order)
    pub async fn begin_append(&self) -> Result<AuditAppendTx> {
        let mut tx = self
            .pool
            .pool()
            .begin()
            .await
            .map_err(|e| Error::Query(e.to_string()))?;
        // Transaction-local (`is_local = true`, i.e. SET LOCAL) timeouts in ms.
        sqlx::query(
            "SELECT set_config('lock_timeout', $1, true), \
                    set_config('statement_timeout', $2, true), \
                    set_config('idle_in_transaction_session_timeout', $3, true)",
        )
        .bind(AUDIT_CHAIN_LOCK_TIMEOUT_MS.to_string())
        .bind(AUDIT_CHAIN_STATEMENT_TIMEOUT_MS.to_string())
        .bind(AUDIT_CHAIN_IDLE_TIMEOUT_MS.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::Query(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(AUDIT_CHAIN_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Query(e.to_string()))?;
        let head = sqlx::query(
            r#"
            SELECT event_hash, timestamp
            FROM audit_events
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Error::Query(e.to_string()))?;
        let (previous_hash, previous_timestamp) = match head {
            Some(row) => (
                Some(row.get::<Vec<u8>, _>("event_hash")),
                Some(row.get::<DateTime<Utc>, _>("timestamp")),
            ),
            None => (None, None),
        };
        Ok(AuditAppendTx {
            tx,
            previous_hash,
            previous_timestamp,
        })
    }

    async fn insert<'c, E>(executor: E, event: &AuditEvent) -> Result<AuditEvent>
    where
        E: sqlx::Executor<'c, Database = sqlx::Postgres>,
    {
        sqlx::query_as::<_, AuditEvent>(
            r#"
            INSERT INTO audit_events (
                id, event_type, actor, target, action, outcome,
                details, ip_address, user_agent, session_id,
                previous_hash, event_hash, timestamp,
                signature, signing_key_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
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
        .bind(&event.previous_hash)
        .bind(&event.event_hash)
        .bind(event.timestamp)
        .bind(&event.signature)
        .bind(&event.signing_key_id)
        .fetch_one(executor)
        .await
        .map_err(|e| Error::Query(e.to_string()))
    }

    /// Hash of the most recent audit event, read WITHOUT the chain lock.
    ///
    /// Informational only (e.g. monitoring): the value can be stale as soon as
    /// it is returned, so it must not be used to link a new record. Appenders
    /// use [`Self::begin_append`], which reads the head under the lock.
    pub async fn get_last_hash(&self) -> Result<Option<Vec<u8>>> {
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

    /// Return all audit events in chain order (oldest first).
    ///
    /// Used by signature verification (AU-10) to check each record's signature.
    pub async fn all_events_ordered(&self) -> Result<Vec<AuditEvent>> {
        sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT *
            FROM audit_events
            ORDER BY timestamp ASC
            "#,
        )
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))
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
            SELECT *
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
            SELECT *
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
            SELECT *
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
            SELECT *
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
            SELECT *
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

    /// List audit records with optional filters (actor substring, exact event
    /// type, exact outcome, time window), newest first, paginated — with
    /// filtering, counting, and pagination all performed in SQL. Returns
    /// `(page rows, total matching count)`.
    ///
    /// Backs the audit-review UI (FAU_SAR.1 / AU-6). `actor` is a
    /// case-insensitive literal substring; the rest are exact matches. All
    /// values are bound — no user input is interpolated.
    ///
    /// - `sort`: API column key (`eventType` | `actor` | `target` | `action` |
    ///   `outcome` | `timestamp`). Anything else (incl. `None`) falls back to the
    ///   default `timestamp DESC`.
    /// - `descending`: direction for a recognized `sort` (ignored by the default).
    #[allow(clippy::too_many_arguments)]
    pub async fn list_filtered(
        &self,
        actor: Option<&str>,
        event_type: Option<&str>,
        outcome: Option<&str>,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        sort: Option<&str>,
        descending: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AuditEvent>, i64)> {
        const PREDICATE: &str = r#"
            ($1::text IS NULL OR POSITION(LOWER($1) IN LOWER(actor)) > 0)
            AND ($2::text IS NULL OR event_type = $2)
            AND ($3::text IS NULL OR outcome = $3)
            AND ($4::timestamptz IS NULL OR timestamp >= $4)
            AND ($5::timestamptz IS NULL OR timestamp <= $5)
        "#;

        // SI-10: the ORDER BY is built only from a closed whitelist (column from a
        // fixed match, direction from a bool) — never from raw user input. A
        // unique `id` tiebreaker keeps pagination deterministic across equal keys.
        let dir = if descending { "DESC" } else { "ASC" };
        let order_by = match sort {
            Some("eventType") => format!("event_type {dir}"),
            Some("actor") => format!("actor {dir}"),
            Some("target") => format!("target {dir}"),
            Some("action") => format!("action {dir}"),
            Some("outcome") => format!("outcome {dir}"),
            Some("timestamp") => format!("timestamp {dir}"),
            _ => "timestamp DESC".to_string(),
        };

        // SI-10: PREDICATE is a fixed fragment with $N placeholders; all filters
        // are bound, not interpolated. AssertSqlSafe (sqlx 0.9) marks it audited.
        let rows = sqlx::query_as::<_, AuditEvent>(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM audit_events WHERE {PREDICATE} ORDER BY {order_by}, id LIMIT $6 OFFSET $7"
        )))
        .bind(actor)
        .bind(event_type)
        .bind(outcome)
        .bind(start)
        .bind(end)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM audit_events WHERE {PREDICATE}"
        )))
        .bind(actor)
        .bind(event_type)
        .bind(outcome)
        .bind(start)
        .bind(end)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|e| Error::Query(e.to_string()))?;

        Ok((rows, total))
    }

    /// Count total audit records and how many carry a signature (AU-10). Used
    /// by the integrity-verification report so operators see signed coverage.
    pub async fn signed_counts(&self) -> Result<(i64, i64)> {
        let row =
            sqlx::query("SELECT COUNT(*) AS total, COUNT(signature) AS signed FROM audit_events")
                .fetch_one(self.pool.pool())
                .await
                .map_err(|e| Error::Query(e.to_string()))?;
        Ok((row.get("total"), row.get("signed")))
    }
}

#[async_trait]
impl super::Repository<AuditEvent> for AuditRepository {
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditEvent>> {
        let event = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT *
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

    /// Same as [`AuditRepository::append`]: a checked insert of a prepared
    /// record under the chain lock; refused unless it links to the head.
    async fn create(&self, event: &AuditEvent) -> Result<AuditEvent> {
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
            SELECT *
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
