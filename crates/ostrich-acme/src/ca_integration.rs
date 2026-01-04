//! CA service integration for ACME
//!
//! RFC 8555 §7.4 - Order finalization and certificate issuance
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 - Transmission confidentiality (gRPC with mTLS)
//! - NIST 800-53: AU-3 - Audit record content (requestor tracking)
//! - RFC 8555 §7.4 - Finalize order after challenges validated

use crate::{Error, Result};
use der::Encode;
use ostrich_common::{CaGrpcClient, GrpcClientConfig};
use ostrich_db::DatabasePool;
use ostrich_protocol::certificate_authority_service_client::CertificateAuthorityServiceClient;
use ostrich_protocol::{DistinguishedName as ProtoDistinguishedName, IssueCertificateRequest};
use uuid::Uuid;
use x509_cert::der::Decode;
use x509_cert::request::CertReq;

/// CA client for ACME service
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 - Cryptographic key management via CA
pub struct AcmeCaClient {
    grpc_client: CaGrpcClient,
    db_pool: DatabasePool,
}

impl AcmeCaClient {
    /// Create a new ACME CA client
    ///
    /// NIST 800-53: SC-8(1) - Establish mTLS connection to CA
    pub async fn new(config: GrpcClientConfig, db_pool: DatabasePool) -> Result<Self> {
        let grpc_client = CaGrpcClient::new(config)
            .await
            .map_err(|e| Error::ServerInternal(format!("Failed to create CA client: {}", e)))?;

        Ok(Self {
            grpc_client,
            db_pool,
        })
    }

    /// Finalize ACME order and issue certificate
    ///
    /// RFC 8555 §7.4 - Order finalization
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 8555 §7.4 - CSR validation and certificate issuance
    /// - NIST 800-53: AU-2 - Auditable event (certificate issuance)
    ///
    /// # Arguments
    /// * `order_id` - ACME order UUID
    /// * `csr_der` - DER-encoded CSR from client
    /// * `account_id` - ACME account identifier (for audit)
    ///
    /// # Returns
    /// Certificate ID assigned by CA
    pub async fn finalize_order(
        &self,
        order_id: Uuid,
        csr_der: &[u8],
        account_id: &str,
    ) -> Result<Uuid> {
        // Parse CSR to extract subject and public key
        let csr = CertReq::from_der(csr_der)
            .map_err(|e| Error::BadCsr(format!("Failed to parse CSR: {}", e)))?;

        // NOTE: CSR signature verification is performed by the REST handler
        // (rest.rs:806-814) before this function is called. This ensures
        // proof-of-possession before forwarding to the CA service.

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
            .map_err(|e| Error::BadCsr(format!("Failed to encode public key: {}", e)))?;

        // Prepare metadata for audit trail
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("acme_order_id".to_string(), order_id.to_string());
        metadata.insert("acme_account_id".to_string(), account_id.to_string());

        // Create gRPC request
        let request = IssueCertificateRequest {
            profile_name: "acme-default".to_string(), // TODO: Make configurable
            subject: Some(proto_subject),
            subject_alt_names,
            public_key: public_key_der,
            requestor: format!("acme::{}", account_id),
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
            .map_err(|e| Error::ServerInternal(format!("CA service call failed: {}", e)))?;

        let issued = response.into_inner();

        // Parse certificate ID
        let certificate_id = Uuid::parse_str(&issued.certificate_id)
            .map_err(|_| Error::ServerInternal("Invalid certificate ID from CA".to_string()))?;

        // Update ACME order with certificate ID
        let acme_repo = ostrich_db::repository::AcmeRepository::new(self.db_pool.clone());
        acme_repo
            .update_order_certificate(order_id, certificate_id, csr_der)
            .await
            .map_err(Error::Database)?;

        // Update order status to "valid"
        acme_repo
            .update_order_status(order_id, "valid")
            .await
            .map_err(Error::Database)?;

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
    /// RFC 8555 §7.4.2 - Download certificate
    ///
    /// # Arguments
    /// * `certificate_id` - Certificate ID from CA
    ///
    /// # Returns
    /// PEM-encoded certificate chain
    pub async fn get_certificate(&self, certificate_id: Uuid) -> Result<String> {
        // Fetch certificate from database
        let cert_repo = ostrich_db::repository::CertificateRepository::new(self.db_pool.clone());
        let certificate = cert_repo
            .find_by_id(certificate_id)
            .await
            .map_err(Error::Database)?
            .ok_or_else(|| Error::NotFound)?;

        // Return PEM-encoded certificate
        // RFC 8555 §7.4.2 - Certificate response format
        Ok(certificate.pem_encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_ca_client_placeholder() {
        // TODO: Add integration tests with mock CA service
        assert!(true);
    }
}
