//! EST enrollment types
//!
//! RFC 7030 §4.2: Simple enrollment and re-enrollment

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Enrollment request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// PKCS#10 CSR (DER encoded)
    pub csr: Vec<u8>,

    /// Client certificate serial (for re-enrollment)
    pub client_serial: Option<String>,

    /// Requested subject DN
    pub subject_dn: String,

    /// Requested validity period (days)
    pub validity_days: Option<u32>,
}

/// Enrollment response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// Issued certificate (DER encoded)
    pub certificate: Vec<u8>,

    /// Certificate chain (DER encoded)
    pub chain: Vec<Vec<u8>>,
}

/// Enrollment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EnrollmentStatus {
    /// Pending approval
    Pending,
    /// Approved and certificate issued
    Approved,
    /// Rejected
    Rejected,
    /// Expired
    Expired,
}

/// Enrollment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    /// Enrollment ID
    pub id: Uuid,

    /// Client identifier (from certificate CN or other field)
    pub client_id: String,

    /// CSR (DER encoded)
    pub csr: Vec<u8>,

    /// Enrollment status
    pub status: EnrollmentStatus,

    /// Issued certificate ID (if approved)
    pub certificate_id: Option<Uuid>,

    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,

    /// Approved/rejected timestamp
    pub processed_at: Option<DateTime<Utc>>,
}

impl Enrollment {
    /// Create new pending enrollment
    pub fn new(client_id: String, csr: Vec<u8>) -> Self {
        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            client_id,
            csr,
            status: EnrollmentStatus::Pending,
            certificate_id: None,
            rejection_reason: None,
            created_at: now,
            updated_at: now,
            processed_at: None,
        }
    }

    /// Approve enrollment
    pub fn approve(&mut self, certificate_id: Uuid) {
        self.status = EnrollmentStatus::Approved;
        self.certificate_id = Some(certificate_id);
        self.updated_at = Utc::now();
        self.processed_at = Some(Utc::now());
    }

    /// Reject enrollment
    pub fn reject(&mut self, reason: String) {
        self.status = EnrollmentStatus::Rejected;
        self.rejection_reason = Some(reason);
        self.updated_at = Utc::now();
        self.processed_at = Some(Utc::now());
    }

    /// Mark as expired
    pub fn expire(&mut self) {
        self.status = EnrollmentStatus::Expired;
        self.updated_at = Utc::now();
    }
}

/// CSR attributes response (RFC 7030 §4.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrAttributes {
    /// OIDs of required attributes
    pub required: Vec<String>,

    /// OIDs of optional attributes
    pub optional: Vec<String>,

    /// Challenge password required
    pub challenge_password: bool,
}

impl Default for CsrAttributes {
    fn default() -> Self {
        Self {
            required: vec![
                "2.5.4.3".to_string(),  // CN
                "2.5.4.10".to_string(), // O
            ],
            optional: vec![
                "2.5.4.11".to_string(), // OU
                "2.5.4.6".to_string(),  // C
                "2.5.4.7".to_string(),  // L
                "2.5.4.8".to_string(),  // ST
            ],
            challenge_password: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_creation() {
        let enrollment = Enrollment::new("client-123".to_string(), vec![0x30, 0x82]);

        assert_eq!(enrollment.status, EnrollmentStatus::Pending);
        assert_eq!(enrollment.client_id, "client-123");
        assert!(enrollment.certificate_id.is_none());
        assert!(enrollment.rejection_reason.is_none());
    }

    #[test]
    fn test_enrollment_approval() {
        let mut enrollment = Enrollment::new("client-123".to_string(), vec![0x30, 0x82]);
        let cert_id = Uuid::new_v4();

        enrollment.approve(cert_id);

        assert_eq!(enrollment.status, EnrollmentStatus::Approved);
        assert_eq!(enrollment.certificate_id, Some(cert_id));
        assert!(enrollment.processed_at.is_some());
    }

    #[test]
    fn test_enrollment_rejection() {
        let mut enrollment = Enrollment::new("client-123".to_string(), vec![0x30, 0x82]);

        enrollment.reject("Invalid CSR".to_string());

        assert_eq!(enrollment.status, EnrollmentStatus::Rejected);
        assert_eq!(enrollment.rejection_reason, Some("Invalid CSR".to_string()));
        assert!(enrollment.processed_at.is_some());
    }

    #[test]
    fn test_csr_attributes_default() {
        let attrs = CsrAttributes::default();

        assert_eq!(attrs.required.len(), 2);
        assert_eq!(attrs.optional.len(), 4);
        assert!(!attrs.challenge_password);
    }
}
