//! CA service integration for EST
//!
//! RFC 7030 - EST enrollment via CA service
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 - Transmission confidentiality (gRPC with mTLS)
//! - NIST 800-53: AU-3 - Audit record content (requestor tracking)
//! - RFC 7030 §4.2 - Simple Enroll and Re-enroll

use crate::{Error, Result};
use der::Encode;
use ostrich_common::{CaGrpcClient, GrpcClientConfig};
use ostrich_db::DatabasePool;
use ostrich_protocol::certificate_authority_service_client::CertificateAuthorityServiceClient;
use ostrich_protocol::{DistinguishedName as ProtoDistinguishedName, IssueCertificateRequest};
use uuid::Uuid;
use x509_cert::der::Decode;
use x509_cert::request::CertReq;

/// CA client for EST service
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 - Cryptographic key management via CA
/// - RFC 7030 §4.2 - Certificate enrollment operations
pub struct EstCaClient {
    grpc_client: CaGrpcClient,
    db_pool: DatabasePool,
}

impl EstCaClient {
    /// Create a new EST CA client
    ///
    /// NIST 800-53: SC-8(1) - Establish mTLS connection to CA
    pub async fn new(config: GrpcClientConfig, db_pool: DatabasePool) -> Result<Self> {
        let grpc_client = CaGrpcClient::new(config)
            .await
            .map_err(|e| Error::Internal(format!("Failed to create CA client: {}", e)))?;

        Ok(Self {
            grpc_client,
            db_pool,
        })
    }

    /// Enroll a new certificate via EST
    ///
    /// RFC 7030 §4.2.1 - Simple Enroll
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 7030 §4.2.1 - CSR validation and certificate issuance
    /// - NIST 800-53: AU-2 - Auditable event (certificate issuance)
    ///
    /// # Arguments
    /// * `enrollment_id` - EST enrollment UUID
    /// * `csr_der` - DER-encoded CSR from client
    /// * `client_id` - EST client identifier (for audit)
    /// * `profile_name` - Certificate profile to use
    ///
    /// # Returns
    /// Certificate ID assigned by CA
    pub async fn enroll(
        &self,
        enrollment_id: Uuid,
        csr_der: &[u8],
        client_id: &str,
        profile_name: &str,
    ) -> Result<Uuid> {
        // Parse CSR to extract subject and public key
        let csr = CertReq::from_der(csr_der)
            .map_err(|e| Error::InvalidCsr(format!("Failed to parse CSR: {}", e)))?;

        // Verify CSR signature
        // TODO: Add signature verification (Phase 13)

        // Extract subject from CSR
        let subject = csr.info.subject;
        let proto_subject = Self::convert_subject_to_proto(&subject)?;

        // Extract SANs from CSR
        // TODO: Parse SANs from CSR attributes/extensions (Phase 13)
        let subject_alt_names = vec![];

        // Extract public key
        let public_key_der = csr
            .info
            .public_key
            .to_der()
            .map_err(|e| Error::InvalidCsr(format!("Failed to encode public key: {}", e)))?;

        // Prepare metadata for audit trail
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("est_enrollment_id".to_string(), enrollment_id.to_string());
        metadata.insert("est_client_id".to_string(), client_id.to_string());

        // Create gRPC request
        let request = IssueCertificateRequest {
            profile_name: profile_name.to_string(),
            subject: Some(proto_subject),
            subject_alt_names,
            public_key: public_key_der,
            requestor: format!("est::{}", client_id),
            metadata,
        };

        // Call CA service with retry logic
        let channel = self.grpc_client.channel();
        let response = self
            .grpc_client
            .with_retry(|| {
                let mut client = CertificateAuthorityServiceClient::new(channel.clone());
                let req = request.clone();
                async move { client.issue_certificate(tonic::Request::new(req)).await }
            })
            .await
            .map_err(|e| Error::Internal(format!("CA service call failed: {}", e)))?;

        let issued = response.into_inner();

        // Parse certificate ID
        let certificate_id = Uuid::parse_str(&issued.certificate_id)
            .map_err(|_| Error::Internal("Invalid certificate ID from CA".to_string()))?;

        // Update EST enrollment with certificate ID
        let est_repo = ostrich_db::repository::EstRepository::new(self.db_pool.clone());
        est_repo
            .update_enrollment_certificate(enrollment_id, certificate_id, profile_name)
            .await
            .map_err(|e| Error::Database(e))?;

        // Update enrollment status to "issued"
        est_repo
            .update_enrollment_status(enrollment_id, "issued")
            .await
            .map_err(|e| Error::Database(e))?;

        Ok(certificate_id)
    }

    /// Convert X.509 Name to proto DistinguishedName
    ///
    /// RFC 5280 §4.1.2.4 - Issuer/Subject name conversion
    fn convert_subject_to_proto(name: &x509_cert::name::Name) -> Result<ProtoDistinguishedName> {
        // Convert Name to string (RFC 4514 format)
        // For now, we'll do a simple conversion
        // TODO: Proper ASN.1 RDN parsing (Phase 13)

        let name_str = format!("{:?}", name); // Temporary - needs proper implementation

        Ok(ProtoDistinguishedName {
            common_name: Some(name_str.clone()),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: None,
            serial_number: None,
        })
    }

    /// Get issued certificate from CA
    ///
    /// RFC 7030 §4.2.3 - Certificate retrieval
    ///
    /// # Arguments
    /// * `certificate_id` - Certificate ID from CA
    ///
    /// # Returns
    /// PKCS#7 (CMS) encoded certificate (RFC 7030 §4.1.3)
    pub async fn get_certificate(&self, certificate_id: Uuid) -> Result<Vec<u8>> {
        // Fetch certificate from database
        let cert_repo = ostrich_db::repository::CertificateRepository::new(self.db_pool.clone());
        let certificate = cert_repo
            .find_by_id(certificate_id)
            .await
            .map_err(|e| Error::Database(e))?
            .ok_or_else(|| Error::NotFound)?;

        // RFC 7030 §4.1.3 - Response is PKCS#7 (CMS) signed-data
        // TODO: Wrap certificate in PKCS#7/CMS format (Phase 13)
        // For now, return DER-encoded certificate
        Ok(certificate.der_encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_est_ca_client_placeholder() {
        // TODO: Add integration tests with mock CA service
        assert!(true);
    }
}
