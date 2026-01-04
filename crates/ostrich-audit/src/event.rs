//! Audit event types and builders
//!
//! This module defines the core audit event structures and builder patterns for
//! constructing audit records with all required compliance fields.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-2**: Auditable events - Event type enumeration covers all security-relevant events
//! - **AU-3**: Content of audit records - AuditEvent structure contains all required fields
//! - **AU-9(3)**: Cryptographic protection - SHA-256 hash computation for integrity
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FAU_GEN.1.1**: The TSF shall generate an audit record for auditable events
//!   - Startup/shutdown, certificate operations, key operations, auth events
//! - **FAU_GEN.1.2**: Audit records include date/time, event type, subject identity, outcome
//! - **FAU_GEN.2.1**: Associate user identity with auditable events
//!   - Implemented via the `actor` field in AuditEvent
//!
//! ## Related Standards
//! - RFC 5280: Certificate lifecycle events (issuance, revocation)
//! - FIPS 180-4: SHA-256 for event hash computation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Audit event type categories
///
/// NIST 800-53: AU-2 - Event categories to be audited
/// NIAP PP-CA: FAU_GEN.1.1 - Auditable event types for CA operations
///
/// This enumeration defines all auditable event types as required by FAU_GEN.1.1:
/// - Startup and shutdown of audit functions
/// - Certificate generation, revocation, and renewal
/// - Key generation, destruction, and recovery
/// - Authentication and authorization events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Authentication events (login, logout, failed authentication)
    ///
    /// NIST 800-53: AC-7 - Unsuccessful login attempts
    /// NIAP PP-CA: FAU_GEN.1.1 - Authentication-related audit events
    Authentication,

    /// Authorization events (access granted/denied)
    ///
    /// NIST 800-53: AC-3 - Access enforcement
    Authorization,

    /// Certificate issuance
    ///
    /// RFC 5280 - Certificate lifecycle
    /// NIAP PP-CA: FAU_GEN.1.1 - Certificate generation and issuance events
    CertificateIssuance,

    /// Certificate revocation
    ///
    /// RFC 5280 §5 - Certificate revocation
    /// NIAP PP-CA: FAU_GEN.1.1 - Certificate revocation events
    CertificateRevocation,

    /// CRL generation
    ///
    /// RFC 5280 §5 - CRL issuance
    CrlGeneration,

    /// Key generation
    ///
    /// NIST 800-53: SC-12 - Key generation events
    /// NIAP PP-CA: FAU_GEN.1.1 - Cryptographic key generation events
    KeyGeneration,

    /// Key escrow (KRA)
    ///
    /// NIST 800-53: SC-12 - Key escrow events
    /// NIAP PP-CA: FAU_GEN.1.1 - Key escrow and archival events
    KeyEscrow,

    /// Key recovery (KRA)
    ///
    /// NIST 800-53: SC-12 - Key recovery events
    /// NIAP PP-CA: FAU_GEN.1.1 - Key recovery operations
    KeyRecovery,

    /// Key destruction
    ///
    /// NIST 800-53: SC-12 - Key destruction events
    /// NIAP PP-CA: FAU_GEN.1.1 - Key destruction/zeroization events
    KeyDestruction,

    /// Configuration change
    ///
    /// NIST 800-53: CM-3 - Configuration change control
    ConfigurationChange,

    /// Access violation attempt
    ///
    /// NIST 800-53: AU-2 - Security-relevant events
    AccessViolation,

    /// Token lifecycle event (SCMS)
    TokenLifecycle,

    /// ACME protocol event
    AcmeProtocol,

    /// EST protocol event
    EstProtocol,

    /// OCSP protocol event
    OcspProtocol,

    /// System event (startup, shutdown, etc.)
    ///
    /// NIAP PP-CA: FAU_GEN.1.1 - Startup and shutdown of audit functions
    System,

    /// Database event
    Database,

    /// Other events
    Other,
}

impl EventType {
    /// Check if this event type is security-relevant
    ///
    /// NIST 800-53: AU-2 - Security-relevant events
    /// NIAP PP-CA: FAU_GEN.1.1 - Determines if event requires mandatory auditing
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            EventType::Authentication
                | EventType::Authorization
                | EventType::AccessViolation
                | EventType::KeyGeneration
                | EventType::KeyEscrow
                | EventType::KeyRecovery
                | EventType::KeyDestruction
                | EventType::CertificateRevocation
        )
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Authentication => "authentication",
            EventType::Authorization => "authorization",
            EventType::CertificateIssuance => "certificate_issuance",
            EventType::CertificateRevocation => "certificate_revocation",
            EventType::CrlGeneration => "crl_generation",
            EventType::KeyGeneration => "key_generation",
            EventType::KeyEscrow => "key_escrow",
            EventType::KeyRecovery => "key_recovery",
            EventType::KeyDestruction => "key_destruction",
            EventType::ConfigurationChange => "configuration_change",
            EventType::AccessViolation => "access_violation",
            EventType::TokenLifecycle => "token_lifecycle",
            EventType::AcmeProtocol => "acme_protocol",
            EventType::EstProtocol => "est_protocol",
            EventType::OcspProtocol => "ocsp_protocol",
            EventType::System => "system",
            EventType::Database => "database",
            EventType::Other => "other",
        }
    }
}

/// Audit event outcome
///
/// NIST 800-53: AU-3 - Event outcome indication
/// NIAP PP-CA: FAU_GEN.1.2 - Outcome (success or failure) of the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventOutcome {
    /// Operation succeeded
    Success,

    /// Operation failed
    Failure,

    /// Error occurred during operation
    Error,
}

impl EventOutcome {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            EventOutcome::Success => "success",
            EventOutcome::Failure => "failure",
            EventOutcome::Error => "error",
        }
    }
}

/// Audit event structure
///
/// NIST 800-53: AU-3 - Content of audit records includes:
/// - Event type
/// - Date and time
/// - Outcome (success/failure)
/// - User identity
/// - Location/source
///
/// NIAP PP-CA: FAU_GEN.1.2 - Each audit record contains:
/// - Date and time of the event (timestamp field)
/// - Type of event (event_type field)
/// - Subject identity (actor field)
/// - Outcome (success or failure) of the event (outcome field)
///
/// NIAP PP-CA: FAU_GEN.2.1 - User identity association via actor field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: Uuid,

    /// Event type
    ///
    /// NIST 800-53: AU-2 - Event type identification
    pub event_type: EventType,

    /// Actor (user, system, or service) that triggered the event
    ///
    /// NIST 800-53: AU-3(1) - User identity
    /// NIAP PP-CA: FAU_GEN.2.1 - Identity of the user associated with the event
    pub actor: String,

    /// Target resource (certificate ID, key ID, etc.)
    pub target: String,

    /// Action performed (create, read, update, delete, sign, etc.)
    pub action: String,

    /// Event outcome
    ///
    /// NIST 800-53: AU-3 - Event outcome
    pub outcome: EventOutcome,

    /// Additional event-specific details
    pub details: Option<JsonValue>,

    /// Source IP address
    ///
    /// NIST 800-53: AU-3(1) - Session origin
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Session identifier
    ///
    /// NIST 800-53: AU-3(1) - Session identifier
    pub session_id: Option<String>,

    /// Hash of previous audit event (for chain integrity)
    ///
    /// NIST 800-53: AU-9(3) - Cryptographic protection
    /// NIAP PP-CA: FAU_STG.4 - Prevention of audit data loss through chain verification
    pub previous_hash: Option<Vec<u8>>,

    /// Hash of this event (for chain integrity)
    ///
    /// NIST 800-53: AU-9(3) - Cryptographic protection
    /// NIAP PP-CA: FAU_STG.4 - Tamper-evident hash chain
    pub event_hash: Vec<u8>,

    /// Timestamp of the event
    ///
    /// NIST 800-53: AU-3 - Date and time of event
    /// NIAP PP-CA: FAU_GEN.1.2 - Date and time of the event
    pub timestamp: DateTime<Utc>,
}

impl AuditEvent {
    // NIAP PP-CA: FAU_STG.4 - Hash chain computation for tamper detection

    /// Compute the hash of this event for chain integrity
    ///
    /// NIST 800-53: AU-9(3) - Use SHA-256 for event hashing
    /// NIAP PP-CA: FAU_STG.4 - Cryptographic hash for audit trail integrity
    /// FIPS 180-4: SHA-256 compliant hash algorithm
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // Include all immutable fields in hash
        hasher.update(self.id.as_bytes());
        hasher.update(self.event_type.as_str().as_bytes());
        hasher.update(self.actor.as_bytes());
        hasher.update(self.target.as_bytes());
        hasher.update(self.action.as_bytes());
        hasher.update(self.outcome.as_str().as_bytes());

        if let Some(details) = &self.details
            && let Ok(json_str) = serde_json::to_string(details)
        {
            hasher.update(json_str.as_bytes());
        }

        if let Some(ip) = &self.ip_address {
            hasher.update(ip.as_bytes());
        }

        if let Some(ua) = &self.user_agent {
            hasher.update(ua.as_bytes());
        }

        if let Some(sid) = &self.session_id {
            hasher.update(sid.as_bytes());
        }

        // Include previous hash in chain
        if let Some(prev) = &self.previous_hash {
            hasher.update(prev);
        }

        // Include timestamp
        hasher.update(self.timestamp.to_rfc3339().as_bytes());

        hasher.finalize().to_vec()
    }

    /// Convert to database model
    pub fn to_db_model(&self) -> ostrich_db::models::AuditEvent {
        ostrich_db::models::AuditEvent {
            id: self.id,
            event_type: self.event_type.as_str().to_string(),
            actor: self.actor.clone(),
            target: self.target.clone(),
            action: self.action.clone(),
            outcome: self.outcome.as_str().to_string(),
            details: self.details.clone(),
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            session_id: self.session_id.clone(),
            previous_hash: self.previous_hash.clone(),
            event_hash: self.event_hash.clone(),
            timestamp: self.timestamp,
        }
    }
}

/// Builder for constructing audit events
///
/// NIST 800-53: AU-3 - Ensures all required fields are populated
/// NIAP PP-CA: FAU_GEN.1.2 - Builder ensures all required audit record fields are present
/// NIAP PP-CA: FAU_GEN.2.1 - Requires actor (user identity) to be specified
pub struct AuditEventBuilder {
    event_type: EventType,
    actor: String,
    target: String,
    action: String,
    outcome: EventOutcome,
    details: Option<JsonValue>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    session_id: Option<String>,
}

impl AuditEventBuilder {
    // NIAP PP-CA: FAU_GEN.1.1 - Generate audit record for auditable events

    /// Create a new audit event builder
    ///
    /// NIAP PP-CA: FAU_GEN.2.1 - Actor (user identity) is required parameter
    pub fn new(
        event_type: EventType,
        actor: impl Into<String>,
        target: impl Into<String>,
        action: impl Into<String>,
        outcome: EventOutcome,
    ) -> Self {
        Self {
            event_type,
            actor: actor.into(),
            target: target.into(),
            action: action.into(),
            outcome,
            details: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
        }
    }

    /// Add event details (JSON)
    pub fn with_details(mut self, details: JsonValue) -> Self {
        self.details = Some(details);
        self
    }

    /// Add IP address
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Add user agent
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Add session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Build the audit event (without hash - will be computed by sink)
    ///
    /// NIAP PP-CA: FAU_GEN.1.2 - Generates complete audit record with all required fields
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            event_type: self.event_type,
            actor: self.actor,
            target: self.target,
            action: self.action,
            outcome: self.outcome,
            details: self.details,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            session_id: self.session_id,
            previous_hash: None,    // Will be set by sink
            event_hash: Vec::new(), // Will be computed by sink
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_common::test_constants::test_ipv4;
    use serde_json::json;

    #[test]
    fn test_event_hash_computation() {
        let event = AuditEventBuilder::new(
            EventType::Authentication,
            "user@example.com",
            "system",
            "login",
            EventOutcome::Success,
        )
        .with_ip(test_ipv4::TEST_NET_1) // RFC 5737 TEST-NET-1
        .build();

        let hash = event.compute_hash();
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_event_hash_chain() {
        let event1 = AuditEventBuilder::new(
            EventType::Authentication,
            "user@example.com",
            "system",
            "login",
            EventOutcome::Success,
        )
        .build();

        let hash1 = event1.compute_hash();

        let mut event2 = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            "ca-service",
            "cert-123",
            "issue",
            EventOutcome::Success,
        )
        .build();

        event2.previous_hash = Some(hash1.clone());
        let hash2 = event2.compute_hash();

        // Hash should change when previous_hash is included
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_event_type_security_relevance() {
        assert!(EventType::Authentication.is_security_relevant());
        assert!(EventType::AccessViolation.is_security_relevant());
        assert!(!EventType::System.is_security_relevant());
    }

    #[test]
    fn test_event_builder() {
        let event = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            "ca-service",
            "cert-123",
            "issue",
            EventOutcome::Success,
        )
        .with_details(json!({
            "subject": "CN=Test User",
            "serial": "1234567890"
        }))
        .with_ip(test_ipv4::TEST_NET_2) // RFC 5737 TEST-NET-2
        .with_user_agent("Mozilla/5.0")
        .with_session("session-abc-123")
        .build();

        assert_eq!(event.event_type, EventType::CertificateIssuance);
        assert_eq!(event.actor, "ca-service");
        assert_eq!(event.target, "cert-123");
        assert_eq!(event.action, "issue");
        assert_eq!(event.outcome, EventOutcome::Success);
        assert!(event.details.is_some());
        assert_eq!(event.ip_address, Some(test_ipv4::TEST_NET_2.to_string()));
        assert_eq!(event.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(event.session_id, Some("session-abc-123".to_string()));
    }
}
