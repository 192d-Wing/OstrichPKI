//! Audit event database model
//!
//! NIST 800-53: AU-3 - Content of audit records
//! NIST 800-53: AU-9 - Protection of audit information

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Audit event database model
///
/// NIST 800-53: AU-3 - Audit records contain:
/// - Event type
/// - Time of event
/// - Outcome (success/failure)
/// - Identity of user/subject
/// - Location/source
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditEvent {
    /// Unique identifier
    pub id: Uuid,

    /// Type of event (authentication, authorization, certificate_issuance, etc.)
    ///
    /// NIST 800-53: AU-2 - Event type identification
    pub event_type: String,

    /// Actor (user, system, or service) that triggered the event
    ///
    /// NIST 800-53: AU-3(1) - User identity
    pub actor: String,

    /// Target resource (certificate ID, key ID, etc.)
    pub target: String,

    /// Action performed (create, read, update, delete, sign, etc.)
    pub action: String,

    /// Outcome (success, failure, error)
    ///
    /// NIST 800-53: AU-3 - Event outcome
    pub outcome: String,

    /// Additional details (JSON)
    pub details: Option<serde_json::Value>,

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
    /// Create a new audit event
    pub fn new(
        event_type: String,
        actor: String,
        target: String,
        action: String,
        outcome: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            actor,
            target,
            action,
            outcome,
            details: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
            previous_hash: None,
            event_hash: Vec::new(), // Will be computed by ostrich-audit
            timestamp: Utc::now(),
        }
    }

    /// Add details to the event
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Add IP address
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Add user agent
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Add session ID
    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_new() {
        let event = AuditEvent::new(
            "certificate_issuance".to_string(),
            "admin@example.com".to_string(),
            "cert-12345".to_string(),
            "create".to_string(),
            "success".to_string(),
        );

        assert_eq!(event.event_type, "certificate_issuance");
        assert_eq!(event.actor, "admin@example.com");
        assert_eq!(event.target, "cert-12345");
        assert_eq!(event.action, "create");
        assert_eq!(event.outcome, "success");
        assert!(event.details.is_none());
        assert!(event.ip_address.is_none());
        assert!(event.user_agent.is_none());
        assert!(event.session_id.is_none());
        assert!(event.previous_hash.is_none());
        assert!(event.event_hash.is_empty());
    }

    #[test]
    fn test_audit_event_with_details() {
        let event = AuditEvent::new(
            "authentication".to_string(),
            "user@example.com".to_string(),
            "session".to_string(),
            "login".to_string(),
            "success".to_string(),
        )
        .with_details(serde_json::json!({
            "method": "mTLS",
            "certificate_subject": "CN=user"
        }));

        assert!(event.details.is_some());
        let details = event.details.unwrap();
        assert_eq!(details["method"], "mTLS");
        assert_eq!(details["certificate_subject"], "CN=user");
    }

    #[test]
    fn test_audit_event_with_ip() {
        let event = AuditEvent::new(
            "api_call".to_string(),
            "service".to_string(),
            "endpoint".to_string(),
            "read".to_string(),
            "success".to_string(),
        )
        .with_ip("192.168.1.100".to_string());

        assert_eq!(event.ip_address, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_audit_event_with_user_agent() {
        let event = AuditEvent::new(
            "api_call".to_string(),
            "client".to_string(),
            "resource".to_string(),
            "read".to_string(),
            "success".to_string(),
        )
        .with_user_agent("OstrichPKI-Client/1.0".to_string());

        assert_eq!(
            event.user_agent,
            Some("OstrichPKI-Client/1.0".to_string())
        );
    }

    #[test]
    fn test_audit_event_with_session() {
        let event = AuditEvent::new(
            "authorization".to_string(),
            "user".to_string(),
            "resource".to_string(),
            "access".to_string(),
            "denied".to_string(),
        )
        .with_session("session-abc123".to_string());

        assert_eq!(event.session_id, Some("session-abc123".to_string()));
    }

    #[test]
    fn test_audit_event_builder_chain() {
        let event = AuditEvent::new(
            "key_generation".to_string(),
            "hsm-operator".to_string(),
            "key-uuid-12345".to_string(),
            "create".to_string(),
            "success".to_string(),
        )
        .with_details(serde_json::json!({"algorithm": "ECDSA-P256"}))
        .with_ip("10.0.0.1".to_string())
        .with_user_agent("HSM-Admin/2.0".to_string())
        .with_session("operator-session-789".to_string());

        assert!(event.details.is_some());
        assert_eq!(event.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(event.user_agent, Some("HSM-Admin/2.0".to_string()));
        assert_eq!(event.session_id, Some("operator-session-789".to_string()));
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(
            "revocation".to_string(),
            "ca-admin".to_string(),
            "cert-revoke-target".to_string(),
            "revoke".to_string(),
            "success".to_string(),
        )
        .with_details(serde_json::json!({"reason": "keyCompromise", "reason_code": 1}));

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("revocation"));
        assert!(json.contains("ca-admin"));
        assert!(json.contains("keyCompromise"));

        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.actor, event.actor);
        assert_eq!(deserialized.target, event.target);
    }
}
