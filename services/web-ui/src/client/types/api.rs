//! API Types
//!
//! Request and response types for API calls.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-3 (Audit Content) - Audit event structure
//! - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation)
//! - RFC 5280: Certificate data structures

use serde::{Deserialize, Serialize};

// =============================================================================
// Dashboard Types
// =============================================================================

/// Dashboard statistics for overview cards
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStats {
    pub active_certificates: u64,
    pub active_change_percent: f64,
    pub pending_approvals: u64,
    pub pending_change: i64,
    pub expiring_soon: u64,
    pub expiring_days: u32,
    pub revoked_certificates: u64,
    pub revoked_today: u64,
}

/// Recent activity item for dashboard
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityItem {
    pub id: String,
    pub action: String,
    pub subject: String,
    pub actor: String,
    pub timestamp: String,
    pub relative_time: String,
}

/// Dashboard data response combining stats and activity
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardData {
    pub stats: DashboardStats,
    pub recent_activity: Vec<ActivityItem>,
}

// =============================================================================
// Certificate Types
// =============================================================================

/// Certificate status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Revoked,
    Expired,
    Pending,
}

impl std::fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Revoked => write!(f, "Revoked"),
            Self::Expired => write!(f, "Expired"),
            Self::Pending => write!(f, "Pending"),
        }
    }
}

/// Certificate summary for list views
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummary {
    pub id: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub status: CertificateStatus,
    pub key_algorithm: Option<String>,
}

/// Paginated certificate list response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateListResponse {
    pub certificates: Vec<CertificateSummary>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

/// Certificate filter/query parameters
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateFilter {
    pub search: Option<String>,
    pub status: Option<String>,
    pub page: u32,
    pub page_size: u32,
}

/// X.509 Extension information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateExtension {
    pub oid: String,
    pub name: String,
    pub critical: bool,
    pub value: String,
}

/// Subject Alternative Name entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectAltName {
    pub name_type: String,
    pub value: String,
}

/// Full certificate details for detail view
/// COMPLIANCE: RFC 5280 §4.1 - Certificate Structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateDetails {
    // Basic fields
    pub id: String,
    pub serial_number: String,
    pub version: u8,
    pub status: CertificateStatus,

    // Subject/Issuer
    pub subject_dn: String,
    pub issuer_dn: String,

    // Validity
    pub valid_from: String,
    pub valid_to: String,
    pub days_remaining: Option<i64>,

    // Key information
    pub key_algorithm: String,
    pub key_size: u32,
    pub signature_algorithm: String,

    // Fingerprints
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,

    // Extensions
    pub extensions: Vec<CertificateExtension>,
    pub subject_alt_names: Vec<SubjectAltName>,

    // Key usage
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,

    // Authority information
    pub authority_key_id: Option<String>,
    pub subject_key_id: Option<String>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_responder_urls: Vec<String>,

    // Revocation info (if revoked)
    pub revocation_time: Option<String>,
    pub revocation_reason: Option<String>,

    // PEM encoded certificate
    pub pem: String,
}

/// Inventory-wide certificate counts by status (dashboard summary cards).
///
/// Sourced from `GET /api/v1/certificates/stats`, so the cards show true totals
/// independent of the table's status filter and pagination.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateStats {
    pub total: u64,
    pub active: u64,
    pub revoked: u64,
    pub expired: u64,
    pub pending: u64,
}

/// Revocation reason codes per RFC 5280 §5.3.1
///
/// Serialized form is PascalCase to match the CA's `RevocationReason` wire
/// representation (e.g. `"KeyCompromise"`); the revoke endpoint rejects any
/// other casing. This enum is only ever serialized into the revoke request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "Unspecified"),
            Self::KeyCompromise => write!(f, "Key Compromise"),
            Self::CaCompromise => write!(f, "CA Compromise"),
            Self::AffiliationChanged => write!(f, "Affiliation Changed"),
            Self::Superseded => write!(f, "Superseded"),
            Self::CessationOfOperation => write!(f, "Cessation of Operation"),
            Self::CertificateHold => write!(f, "Certificate Hold"),
            Self::RemoveFromCrl => write!(f, "Remove from CRL"),
            Self::PrivilegeWithdrawn => write!(f, "Privilege Withdrawn"),
            Self::AaCompromise => write!(f, "AA Compromise"),
        }
    }
}

/// Revocation request body
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRequest {
    pub reason: RevocationReason,
    pub notes: Option<String>,
}

// =============================================================================
// Audit Types
// =============================================================================

/// Audit event for display
/// COMPLIANCE: NIST 800-53 AU-3 - Content of Audit Records
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor: String,
    pub target: String,
    pub action: String,
    pub outcome: String,
    /// Whether this record carries an AU-10 signature (vs. hash-chain only).
    pub signed: bool,
    pub ip_address: Option<String>,
}

/// Paginated audit-log listing (`GET /ca/api/v1/audit`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResponse {
    pub events: Vec<AuditEvent>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

/// Audit-trail integrity result (`GET /ca/api/v1/audit/verify`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerifyResponse {
    pub intact: bool,
    pub total_records: u64,
    pub signed_records: u64,
    pub verified_at: String,
}

// =============================================================================
// Approval Types
// =============================================================================

/// Approval request summary
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequestSummary {
    pub id: String,
    pub request_type: String,
    pub requestor: String,
    pub subject: String,
    pub status: String,
    pub created_at: String,
}

// =============================================================================
// Generic API Response Types
// =============================================================================

/// Generic API error response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Generic success response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}
