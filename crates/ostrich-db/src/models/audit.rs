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
