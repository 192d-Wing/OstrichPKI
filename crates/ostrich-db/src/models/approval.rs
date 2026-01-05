//! Approval workflow database models
//!
//! # COMPLIANCE MAPPING
//! - NIAP PP-CA: FDP_CER_EXT.2 - Certificate request linkage
//! - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval
//! - NIST 800-53: AU-2 - Auditable events (approval decisions)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Approval request database record
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApprovalRequestRecord {
    pub id: Uuid,
    pub request_type: String,
    pub csr_id: Option<Uuid>,
    pub certificate_id: Option<Uuid>,
    pub requestor_id: Uuid,
    pub requestor_username: String,
    pub requestor_roles: Vec<String>,
    pub status: String,
    pub request_details: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

/// Approval decision database record
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApprovalDecisionRecord {
    pub id: Uuid,
    pub request_id: Uuid,
    pub approver_id: Uuid,
    pub approver_username: String,
    pub approver_roles: Vec<String>,
    pub decision: String,
    pub reason: Option<String>,
    pub justification: Option<String>,
    pub decided_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}
