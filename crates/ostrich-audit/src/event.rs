//! Audit event types and builders
//!
//! NIST 800-53: AU-2 - Auditable events
//! NIST 800-53: AU-3 - Content of audit records

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Audit event type categories
///
/// NIST 800-53: AU-2 - Event categories to be audited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Authentication events (login, logout, failed authentication)
    ///
    /// NIST 800-53: AC-7 - Unsuccessful login attempts
    Authentication,

    /// Authorization events (access granted/denied)
    ///
    /// NIST 800-53: AC-3 - Access enforcement
    Authorization,

    /// Certificate issuance
    ///
    /// RFC 5280 - Certificate lifecycle
    CertificateIssuance,

    /// Certificate revocation
    ///
    /// RFC 5280 §5 - Certificate revocation
    CertificateRevocation,

    /// CRL generation
    ///
    /// RFC 5280 §5 - CRL issuance
    CrlGeneration,

    /// Key generation
    ///
    /// NIST 800-53: SC-12 - Key generation events
    KeyGeneration,

    /// Key escrow (KRA)
    ///
    /// NIST 800-53: SC-12 - Key escrow events
    KeyEscrow,

    /// Key recovery (KRA)
    ///
    /// NIST 800-53: SC-12 - Key recovery events
    KeyRecovery,

    /// Key destruction
    ///
    /// NIST 800-53: SC-12 - Key destruction events
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

    /// System event (startup, shutdown, etc.)
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
            EventType::System => "system",
            EventType::Database => "database",
            EventType::Other => "other",
        }
    }
}

/// Audit event outcome
///
/// NIST 800-53: AU-3 - Event outcome indication
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
    pub previous_hash: Option<Vec<u8>>,

    /// Hash of this event (for chain integrity)
    ///
    /// NIST 800-53: AU-9(3) - Cryptographic protection
    pub event_hash: Vec<u8>,

    /// Timestamp of the event
    ///
    /// NIST 800-53: AU-3 - Date and time of event
    pub timestamp: DateTime<Utc>,
}

impl AuditEvent {
    /// Compute the hash of this event for chain integrity
    ///
    /// NIST 800-53: AU-9(3) - Use SHA-256 for event hashing
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
    /// Create a new audit event builder
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
        .with_ip("192.168.1.1")
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
        .with_ip("10.0.0.1")
        .with_user_agent("Mozilla/5.0")
        .with_session("session-abc-123")
        .build();

        assert_eq!(event.event_type, EventType::CertificateIssuance);
        assert_eq!(event.actor, "ca-service");
        assert_eq!(event.target, "cert-123");
        assert_eq!(event.action, "issue");
        assert_eq!(event.outcome, EventOutcome::Success);
        assert!(event.details.is_some());
        assert_eq!(event.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(event.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(event.session_id, Some("session-abc-123".to_string()));
    }
}
