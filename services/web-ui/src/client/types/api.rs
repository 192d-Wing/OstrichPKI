//! API Types
//!
//! Request and response types for API calls.

use serde::{Deserialize, Serialize};

/// Certificate status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Revoked,
    Expired,
}

/// Certificate summary for list views
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummary {
    pub id: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub status: CertificateStatus,
}

/// Audit event for display
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor: String,
    pub target: String,
    pub action: String,
    pub outcome: String,
    pub details: Option<serde_json::Value>,
}

/// Approval request summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub id: String,
    pub request_type: String,
    pub requestor: String,
    pub subject: String,
    pub status: String,
    pub created_at: String,
}
