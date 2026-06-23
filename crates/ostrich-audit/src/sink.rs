//! Audit event sinks for persistence
//!
//! This module provides audit sink implementations for persisting audit records
//! with integrity protection through cryptographic hash chains.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-9**: Protection of audit information - Secure storage with hash chain
//! - **AU-9(3)**: Cryptographic protection - SHA-256 hash chain for integrity
//! - **AU-10**: Non-repudiation - Tamper-evident audit trail
//! - **AU-4**: Audit storage capacity - Database-backed persistent storage
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FAU_STG.1**: Protected audit trail storage
//!   - Audit trail stored in protected database
//!   - Unauthorized modification prevented through access controls
//! - **FAU_STG.4**: Prevention of audit data loss
//!   - Hash chain enables detection of missing/modified records
//!   - Integrity verification via verify_integrity() method
//!
//! ## Related Standards
//! - FIPS 180-4: SHA-256 for hash chain computation

use crate::{AuditEvent, Error, Result};
use async_trait::async_trait;
use ostrich_db::{DatabasePool, repository::AuditRepository};

/// Trait for audit event sinks
///
/// NIST 800-53: AU-4 - Audit storage capacity
/// NIAP PP-CA: FAU_STG.1 - Protected audit trail storage interface
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record an audit event
    ///
    /// NIST 800-53: AU-2 - Auditable events
    /// NIST 800-53: AU-9(3) - Cryptographic protection via hash chain
    /// NIAP PP-CA: FAU_GEN.1.1 - Store generated audit record
    async fn record(&self, event: &mut AuditEvent) -> Result<()>;

    /// Verify the integrity of the audit log
    ///
    /// NIST 800-53: AU-9(3) - Verify audit information integrity
    /// NIAP PP-CA: FAU_STG.4 - Detect potential audit data loss or modification
    async fn verify_integrity(&self) -> Result<bool>;

    /// Query events by various criteria
    ///
    /// NIAP PP-CA: FAU_STG.1 - Retrieve audit records from protected storage
    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>>;
}

/// Criteria for querying audit events
#[derive(Debug, Clone)]
pub struct QueryCriteria {
    /// Filter by actor
    pub actor: Option<String>,

    /// Filter by event type
    pub event_type: Option<String>,

    /// Filter by time range
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,

    /// Limit number of results
    pub limit: Option<i64>,

    /// Offset for pagination
    pub offset: Option<i64>,
}

impl Default for QueryCriteria {
    fn default() -> Self {
        Self {
            actor: None,
            event_type: None,
            start_time: None,
            end_time: None,
            limit: Some(100),
            offset: None,
        }
    }
}

/// Database-backed audit sink with hash chain integrity
///
/// NIST 800-53: AU-9 - Audit information stored in database
/// NIST 800-53: AU-9(3) - Hash chain for integrity protection
/// NIAP PP-CA: FAU_STG.1 - Protected audit trail storage in database
/// NIAP PP-CA: FAU_STG.4 - Hash chain prevents undetected modification
pub struct DatabaseAuditSink {
    repository: AuditRepository,
    /// Optional record signer (AU-10 non-repudiation). When set, every record's
    /// event_hash is signed at write time; verification then detects tampering
    /// even by an attacker who rewrites the whole SHA-256 chain.
    signer: Option<AuditSigner>,
}

/// Holds the key material used to sign audit records.
struct AuditSigner {
    crypto: std::sync::Arc<dyn ostrich_crypto::CryptoProvider>,
    key_handle: ostrich_crypto::KeyHandle,
    algorithm: ostrich_crypto::Algorithm,
    /// Stored on each record so verifiers know which key to check.
    key_label: String,
}

impl DatabaseAuditSink {
    /// Create a new database audit sink WITHOUT record signing (hash chain
    /// only). Backward-compatible default.
    pub fn new(pool: DatabasePool) -> Self {
        Self {
            repository: AuditRepository::new(pool),
            signer: None,
        }
    }

    /// Create a database audit sink that SIGNS each record's event_hash
    /// (AU-10 non-repudiation). The signing key should be HSM-backed in
    /// production; `key_label` is recorded on each row so verifiers know which
    /// public key to check against.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-10 (Non-repudiation), AU-9(3) (Cryptographic protection)
    /// - NIAP PP-CA: FAU_STG.1.2 / FAU_STG.4 - undetected modification prevented
    pub fn with_signing_key(
        pool: DatabasePool,
        crypto: std::sync::Arc<dyn ostrich_crypto::CryptoProvider>,
        key_handle: ostrich_crypto::KeyHandle,
        algorithm: ostrich_crypto::Algorithm,
        key_label: impl Into<String>,
    ) -> Self {
        Self {
            repository: AuditRepository::new(pool),
            signer: Some(AuditSigner {
                crypto,
                key_handle,
                algorithm,
                key_label: key_label.into(),
            }),
        }
    }

    /// Verify the audit chain AND every signed record's signature against the
    /// given public key (DER SubjectPublicKeyInfo).
    ///
    /// Returns Ok(true) only if the hash chain is intact AND every record that
    /// carries a signature verifies. A record whose contents were modified
    /// fails here even if the attacker recomputed the entire hash chain,
    /// because they cannot forge the signature (AU-10).
    ///
    /// `algorithm` is the signature algorithm of the signing key (e.g. the CA
    /// key's algorithm). The audit signer stores the crypto provider's RAW
    /// signature, so for ECDSA keys this is fixed `r||s` (ecdsa_fixed=true);
    /// RSA/Ed25519 are unaffected.
    pub async fn verify_signed_chain(
        &self,
        signer_public_key_spki: &[u8],
        algorithm: ostrich_crypto::Algorithm,
    ) -> Result<bool> {
        // First the structural checks (continuity + hash recomputation).
        if !self
            .repository
            .verify_chain()
            .await
            .map_err(Error::Database)?
        {
            return Ok(false);
        }

        // Then verify each signed record's signature over its event_hash. A
        // tampered record fails here even after a full hash-chain rewrite,
        // because the attacker cannot forge the signature (AU-10).
        let events = self
            .repository
            .all_events_ordered()
            .await
            .map_err(Error::Database)?;
        for db_event in events {
            let Some(sig) = &db_event.signature else {
                continue; // unsigned record - structural check already covered it
            };
            let ok = ostrich_crypto::verify_with_spki(
                signer_public_key_spki,
                algorithm,
                &db_event.event_hash,
                sig,
                true, // provider emits raw fixed r||s for ECDSA
            )
            .map_err(|e| Error::Signing(format!("Audit signature verify error: {}", e)))?;
            if !ok {
                tracing::error!(
                    event_id = %db_event.id,
                    "Audit record signature verification FAILED (tampering or wrong key)"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Convert database model to audit event
    fn from_db_model(db_event: ostrich_db::models::AuditEvent) -> AuditEvent {
        use crate::{EventOutcome, EventType};

        // Parse event type
        let event_type = match db_event.event_type.as_str() {
            "authentication" => EventType::Authentication,
            "authorization" => EventType::Authorization,
            "certificate_issuance" => EventType::CertificateIssuance,
            "certificate_revocation" => EventType::CertificateRevocation,
            "crl_generation" => EventType::CrlGeneration,
            "key_generation" => EventType::KeyGeneration,
            "key_escrow" => EventType::KeyEscrow,
            "key_recovery" => EventType::KeyRecovery,
            "key_destruction" => EventType::KeyDestruction,
            "configuration_change" => EventType::ConfigurationChange,
            "access_violation" => EventType::AccessViolation,
            "token_lifecycle" => EventType::TokenLifecycle,
            "acme_protocol" => EventType::AcmeProtocol,
            "est_protocol" => EventType::EstProtocol,
            "ocsp_protocol" => EventType::OcspProtocol,
            "tamp_protocol" => EventType::TampProtocol,
            "system" => EventType::System,
            "database" => EventType::Database,
            _ => EventType::Other,
        };

        // Parse outcome
        let outcome = match db_event.outcome.as_str() {
            "success" => EventOutcome::Success,
            "failure" => EventOutcome::Failure,
            _ => EventOutcome::Error,
        };

        AuditEvent {
            id: db_event.id,
            event_type,
            actor: db_event.actor,
            target: db_event.target,
            action: db_event.action,
            outcome,
            details: db_event.details,
            ip_address: db_event.ip_address,
            user_agent: db_event.user_agent,
            session_id: db_event.session_id,
            previous_hash: db_event.previous_hash,
            event_hash: db_event.event_hash,
            timestamp: db_event.timestamp,
            signature: db_event.signature,
            signing_key_id: db_event.signing_key_id,
        }
    }
}

#[async_trait]
impl AuditSink for DatabaseAuditSink {
    // NIAP PP-CA: FAU_STG.1 - Protected audit trail storage implementation

    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        // Truncate to microsecond precision BEFORE hashing. Postgres timestamptz
        // stores microseconds, so a nanosecond-precision Utc::now() would hash to
        // one value here but recompute to a different value after the DB
        // round-trip, breaking verify_chain. Truncating up front makes the stored
        // hash match what the verifier recomputes from the persisted timestamp.
        use chrono::SubsecRound;
        event.timestamp = event.timestamp.trunc_subsecs(6);

        // NIAP PP-CA: FAU_STG.4 - Link to the prior record BEFORE hashing so the
        // chain link is covered by event_hash (and the signature below). The
        // repository persists this previous_hash verbatim; it does not re-derive
        // it. Without this, event_hash would be computed with previous_hash=None
        // while the verifier recomputes with the stored link -> mismatch.
        event.previous_hash = self
            .repository
            .get_last_hash()
            .await
            .map_err(Error::Database)?;

        // NIAP PP-CA: FAU_STG.4 - Compute hash for tamper detection
        // Compute event hash with chain integrity
        event.event_hash = event.compute_hash();

        // AU-10: sign the event_hash so tampering is detectable even if the
        // attacker recomputes the whole hash chain (they cannot forge this).
        if let Some(signer) = &self.signer {
            let signature = signer
                .crypto
                .sign(&signer.key_handle, signer.algorithm, &event.event_hash)
                .await
                .map_err(|e| Error::Signing(format!("Failed to sign audit record: {}", e)))?;
            event.signature = Some(signature);
            event.signing_key_id = Some(signer.key_label.clone());
        }

        // Store in database (repository will handle previous_hash linking)
        let db_event = event.to_db_model();
        self.repository
            .append(&db_event)
            .await
            .map_err(Error::Database)?;

        tracing::debug!(
            "Audit event recorded: {} - {} {} on {}",
            event.event_type.as_str(),
            event.actor,
            event.action,
            event.target
        );

        // Log security-relevant events at info level
        if event.event_type.is_security_relevant() {
            tracing::info!(
                "Security event: {} by {} on {} - {}",
                event.action,
                event.actor,
                event.target,
                event.outcome.as_str()
            );
        }

        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        // NIAP PP-CA: FAU_STG.4 - Verify hash chain to detect tampering or loss
        self.repository
            .verify_chain()
            .await
            .map_err(Error::Database)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let db_events = if let Some(actor) = criteria.actor {
            self.repository
                .find_by_actor(&actor, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let Some(event_type) = criteria.event_type {
            self.repository
                .find_by_type(&event_type, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else if let (Some(start), Some(end)) = (criteria.start_time, criteria.end_time) {
            self.repository
                .find_by_time_range(start, end, criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        } else {
            use ostrich_db::repository::Repository;
            self.repository
                .list(criteria.limit, criteria.offset)
                .await
                .map_err(Error::Database)?
        };

        Ok(db_events.into_iter().map(Self::from_db_model).collect())
    }
}

/// In-memory audit sink for testing
///
/// WARNING: Not suitable for production use - no persistence
/// NOTE: Does not satisfy FAU_STG.1 (protected storage) for production
#[cfg(any(test, feature = "testing"))]
pub struct MemoryAuditSink {
    events: tokio::sync::RwLock<Vec<AuditEvent>>,
}

#[cfg(any(test, feature = "testing"))]
impl Default for MemoryAuditSink {
    fn default() -> Self {
        Self {
            events: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record(&self, event: &mut AuditEvent) -> Result<()> {
        // NIAP PP-CA: FAU_GEN.1.1 - Store audit record (test implementation)
        let mut events = self.events.write().await;

        // NIAP PP-CA: FAU_STG.4 - Link to previous event for chain integrity
        // Get previous hash
        event.previous_hash = events.last().map(|e| e.event_hash.clone());

        // Compute this event's hash
        event.event_hash = event.compute_hash();

        events.push(event.clone());
        Ok(())
    }

    async fn verify_integrity(&self) -> Result<bool> {
        // NIAP PP-CA: FAU_STG.4 - Verify audit trail integrity
        let events = self.events.read().await;

        if events.is_empty() {
            return Ok(true);
        }

        let mut prev_hash: Option<Vec<u8>> = None;

        for event in events.iter() {
            // NIAP PP-CA: FAU_STG.4 - Check chain continuity
            if event.previous_hash != prev_hash {
                return Ok(false);
            }

            // NIAP PP-CA: FAU_STG.4 - Verify hash computation matches stored hash
            // Verify hash computation
            let computed_hash = event.compute_hash();
            if computed_hash != event.event_hash {
                return Ok(false);
            }

            prev_hash = Some(event.event_hash.clone());
        }

        Ok(true)
    }

    async fn query_events(&self, criteria: QueryCriteria) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let mut filtered: Vec<AuditEvent> = events
            .iter()
            .filter(|e| {
                if let Some(ref actor) = criteria.actor
                    && e.actor != *actor
                {
                    return false;
                }
                if let Some(ref event_type) = criteria.event_type
                    && e.event_type.as_str() != event_type
                {
                    return false;
                }
                if let Some(start) = criteria.start_time
                    && e.timestamp < start
                {
                    return false;
                }
                if let Some(end) = criteria.end_time
                    && e.timestamp > end
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Apply limit and offset
        let offset = criteria.offset.unwrap_or(0) as usize;
        let limit = criteria.limit.unwrap_or(100) as usize;

        if offset < filtered.len() {
            filtered = filtered[offset..].to_vec();
        } else {
            filtered.clear();
        }

        if filtered.len() > limit {
            filtered.truncate(limit);
        }

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventBuilder, EventOutcome, EventType};

    #[tokio::test]
    async fn test_memory_sink_chain_integrity() {
        let sink = MemoryAuditSink::new();

        // Record first event
        let mut event1 = AuditEventBuilder::new(
            EventType::Authentication,
            "user1",
            "system",
            "login",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event1).await.unwrap();

        // Record second event
        let mut event2 = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            "ca-service",
            "cert-123",
            "issue",
            EventOutcome::Success,
        )
        .build();

        sink.record(&mut event2).await.unwrap();

        // Verify integrity
        assert!(sink.verify_integrity().await.unwrap());

        // Verify chain link
        assert_eq!(event2.previous_hash, Some(event1.event_hash.clone()));
    }

    #[tokio::test]
    async fn test_memory_sink_query() {
        let sink = MemoryAuditSink::new();

        // Record events
        for i in 0..5 {
            let mut event = AuditEventBuilder::new(
                EventType::Authentication,
                format!("user{}", i),
                "system",
                "login",
                EventOutcome::Success,
            )
            .build();

            sink.record(&mut event).await.unwrap();
        }

        // Query all events
        let criteria = QueryCriteria::default();
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 5);

        // Query by actor
        let criteria = QueryCriteria {
            actor: Some("user2".to_string()),
            ..Default::default()
        };
        let events = sink.query_events(criteria).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user2");
    }
}
