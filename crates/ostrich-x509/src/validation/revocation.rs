//! Revocation checking for path validation
//!
//! RFC 5280 - Certificate revocation via OCSP and CRL
//!
//! COMPLIANCE MAPPING:
//! - RFC 6960: OCSP (Online Certificate Status Protocol)
//! - RFC 5280 §5: CRL Profile
//! - NIAP PP-CA FDP_CSI_EXT.1: Certificate Status Information

use super::error::Result;
use crate::parser::ParsedCertificate;
use chrono::{DateTime, Utc};

/// Revocation status of a certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is not revoked
    Good,

    /// Certificate has been revoked
    Revoked {
        /// Revocation reason
        reason: String,

        /// Revocation time
        revoked_at: DateTime<Utc>,
    },

    /// Revocation status unknown (OCSP/CRL unavailable)
    Unknown,
}

/// Revocation checker
///
/// Integrates with OCSP and CRL for revocation status checking
pub struct RevocationChecker {
    /// Maximum CRL download size (10MB per user requirement)
    max_crl_size: usize,
}

impl RevocationChecker {
    /// Create new revocation checker
    pub fn new() -> Self {
        Self {
            max_crl_size: 10 * 1024 * 1024, // 10MB
        }
    }

    /// Set maximum CRL download size
    pub fn with_max_crl_size(mut self, size: usize) -> Self {
        self.max_crl_size = size;
        self
    }

    /// Check certificate revocation status
    ///
    /// RFC 5280 - Revocation checking
    /// User requirement: Try OCSP first, fall back to CRL
    ///
    /// Phase 4: Stub implementation
    /// Future: Integrate with ostrich-ocsp::OcspResponder and CRL fetching
    pub async fn check(
        &self,
        _cert: &ParsedCertificate,
        _issuer: &ParsedCertificate,
    ) -> Result<RevocationStatus> {
        // TODO: Phase 4 - Implement revocation checking
        // 1. Extract OCSP responder URL from AIA extension
        // 2. Query OCSP (if available)
        // 3. If OCSP unavailable, extract CRL DP from certificate
        // 4. Fetch and parse CRL (respect max_crl_size)
        // 5. Check CRL for certificate serial number
        // 6. Return RevocationStatus

        // For now, stub that returns Good
        Ok(RevocationStatus::Good)
    }

    /// Check if OCSP is available for certificate
    ///
    /// RFC 5280 §4.2.2.1 - Authority Information Access
    #[allow(dead_code)]
    fn has_ocsp_responder(_cert: &ParsedCertificate) -> bool {
        // TODO: Parse AIA extension and check for id-ad-ocsp
        false
    }

    /// Check if CRL DP is available for certificate
    ///
    /// RFC 5280 §4.2.1.13 - CRL Distribution Points
    #[allow(dead_code)]
    fn has_crl_dp(_cert: &ParsedCertificate) -> bool {
        // TODO: Parse CRL Distribution Points extension
        false
    }
}

impl Default for RevocationChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cert() -> ParsedCertificate {
        ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=CA".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key: vec![],
            signature: vec![],
            der_encoded: vec![],
        }
    }

    #[test]
    fn test_revocation_checker_new() {
        let checker = RevocationChecker::new();
        assert_eq!(checker.max_crl_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_revocation_checker_with_max_crl_size() {
        let checker = RevocationChecker::new().with_max_crl_size(5 * 1024 * 1024);
        assert_eq!(checker.max_crl_size, 5 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_check_revocation_status() {
        let checker = RevocationChecker::new();
        let cert = create_test_cert();
        let issuer = create_test_cert();

        let result = checker.check(&cert, &issuer).await;
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status, RevocationStatus::Good);
    }

    #[test]
    fn test_revocation_status_good() {
        let status = RevocationStatus::Good;
        assert_eq!(status, RevocationStatus::Good);
    }

    #[test]
    fn test_revocation_status_revoked() {
        let now = Utc::now();
        let status = RevocationStatus::Revoked {
            reason: "keyCompromise".to_string(),
            revoked_at: now,
        };

        match status {
            RevocationStatus::Revoked { reason, .. } => {
                assert_eq!(reason, "keyCompromise");
            }
            _ => panic!("Expected Revoked status"),
        }
    }

    #[test]
    fn test_revocation_status_unknown() {
        let status = RevocationStatus::Unknown;
        assert_eq!(status, RevocationStatus::Unknown);
    }

    #[test]
    fn test_has_ocsp_responder() {
        let cert = create_test_cert();
        assert!(!RevocationChecker::has_ocsp_responder(&cert));
    }

    #[test]
    fn test_has_crl_dp() {
        let cert = create_test_cert();
        assert!(!RevocationChecker::has_crl_dp(&cert));
    }
}
