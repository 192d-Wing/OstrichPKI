//! CA service integration for EST
//!
//! RFC 7030 - EST enrollment via CA service
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - gRPC communication with CA service uses mTLS
//!   - Mutual authentication between EST and CA services
//!
//! - **FCS_COP.1**: Cryptographic operations
//!   - CSR parsing and signature verification
//!   - Certificate encoding (DER/PKCS#7)
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - Enrollment requests logged with requestor identity
//!   - Certificate issuance events tracked
//!
//! - **FMT_SMF.1**: Security management functions
//!   - Certificate enrollment workflow management
//!   - Enrollment status tracking
//!
//! - **FDP_ITC.1**: Import of user data without security attributes
//!   - CSR data imported from EST client
//!   - Subject information extracted for certificate issuance
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-8**: Transmission confidentiality (gRPC with mTLS)
//! - **SC-12**: Cryptographic key establishment and management
//! - **AU-3**: Audit record content (requestor tracking)
//!
//! ## RFC Compliance
//!
//! - **RFC 7030 S4.2**: Simple Enroll and Re-enroll
//! - **RFC 5280**: X.509 certificate profile

use crate::{Error, Result};
use der::Encode;
use ostrich_common::{CaGrpcClient, GrpcClientConfig};
use ostrich_db::DatabasePool;
use ostrich_protocol::certificate_authority_service_client::CertificateAuthorityServiceClient;
use ostrich_protocol::{
    DistinguishedName as ProtoDistinguishedName, IssueCertificateRequest,
    SubjectAltName as ProtoSubjectAltName,
};
use uuid::Uuid;
use x509_cert::der::Decode;
use x509_cert::request::CertReq;
use x509_parser::der_parser::asn1_rs::FromDer;

/// CA client for EST service
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FTP_ITC.1 - Inter-TSF trusted channel (mTLS to CA)
/// - NIAP PP-CA: FMT_SMF.1 - Security management (enrollment workflow)
/// - NIST 800-53: SC-12 - Cryptographic key management via CA
/// - RFC 7030 S4.2 - Certificate enrollment operations
pub struct EstCaClient {
    grpc_client: CaGrpcClient,
    db_pool: DatabasePool,
}

impl EstCaClient {
    /// Create a new EST CA client
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FTP_ITC.1.1 - Initiate trusted channel to CA service
    /// - NIAP PP-CA: FTP_ITC.1.2 - Establish mTLS mutual authentication
    /// - NIST 800-53: SC-8(1) - Establish mTLS connection to CA
    /// - NIST 800-53: SC-23 - Session authenticity
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
    /// RFC 7030 S4.2.1 - Simple Enroll
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (CSR parsing)
    /// - NIAP PP-CA: FDP_ITC.1 - Import user data (CSR subject info)
    /// - NIAP PP-CA: FAU_GEN.1 - Audit data generation (enrollment event)
    /// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (enrollment)
    /// - NIST 800-53: AU-2 - Auditable event (certificate issuance)
    /// - RFC 7030 S4.2.1 - CSR validation and certificate issuance
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

        // NOTE: CSR signature verification is performed by the REST handlers
        // (rest.rs:268-276 for simpleenroll, rest.rs:360-368 for simplereenroll)
        // before this function is called. This ensures proof-of-possession
        // before forwarding to the CA service.

        // Extract subject from CSR
        let subject = csr.info.subject;
        let proto_subject = Self::convert_subject_to_proto(&subject)?;

        // Parse CSR to extract SANs (using the full parser with extension support)
        let parsed_csr = ostrich_x509::parser::parse_csr(csr_der)
            .map_err(|e| Error::InvalidCsr(format!("Failed to parse CSR for SANs: {}", e)))?;

        // Convert SANs to proto format
        let subject_alt_names = Self::convert_sans_to_proto(&parsed_csr.subject_alternative_names)?;

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
            .map_err(Error::Database)?;

        // Update enrollment status to "issued"
        est_repo
            .update_enrollment_status(enrollment_id, "issued")
            .await
            .map_err(Error::Database)?;

        Ok(certificate_id)
    }

    /// Convert X.509 Name to proto DistinguishedName
    ///
    /// RFC 5280 §4.1.2.4 - Issuer/Subject name conversion
    /// RFC 4514 - LDAP DN string representation
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA FDP_ITC.1: Import user data (subject DN)
    /// - RFC 5280 §4.1.2.4: Subject/Issuer name field parsing
    /// - RFC 4514: DN attribute extraction and conversion
    fn convert_subject_to_proto(name: &x509_cert::name::Name) -> Result<ProtoDistinguishedName> {
        // Encode the Name to DER so we can parse it with x509-parser
        use der::Encode;
        let name_der = name
            .to_der()
            .map_err(|e| Error::InvalidCsr(format!("Failed to encode subject DN: {}", e)))?;

        // Parse with x509-parser to use our DN parser
        use x509_parser::x509::X509Name;
        let (_, parsed_name) = X509Name::from_der(&name_der)
            .map_err(|e| Error::InvalidCsr(format!("Failed to parse subject DN: {}", e)))?;

        // Use our DN parser
        let dn = ostrich_x509::parser::parse_distinguished_name(&parsed_name)
            .map_err(|e| Error::InvalidCsr(format!("Failed to extract DN attributes: {}", e)))?;

        Ok(ProtoDistinguishedName {
            common_name: dn.common_name,
            organization: dn.organization,
            organizational_unit: dn.organizational_unit,
            locality: dn.locality,
            state_or_province: dn.state_or_province,
            country: dn.country,
            serial_number: dn.serial_number,
        })
    }

    /// Convert parsed SANs to proto SubjectAltName format
    ///
    /// RFC 5280 §4.2.1.6 - SubjectAltName extension
    /// RFC 7030 §3.5 - EST enrollment with SANs
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.6: SubjectAltName conversion
    /// - RFC 7030 §3.5: EST CSR attribute processing
    /// - NIAP PP-CA FDP_ITC.1: Import user data (SAN extraction)
    fn convert_sans_to_proto(sans: &[String]) -> Result<Vec<ProtoSubjectAltName>> {
        use ostrich_protocol::subject_alt_name::Name;

        let mut proto_sans = Vec::new();

        for san in sans {
            let proto_san = if let Some(dns) = san.strip_prefix("DNS:") {
                ProtoSubjectAltName {
                    name: Some(Name::DnsName(dns.to_string())),
                }
            } else if let Some(email) = san.strip_prefix("email:") {
                ProtoSubjectAltName {
                    name: Some(Name::Rfc822Name(email.to_string())),
                }
            } else if let Some(uri) = san.strip_prefix("URI:") {
                ProtoSubjectAltName {
                    name: Some(Name::Uri(uri.to_string())),
                }
            } else if let Some(ip) = san.strip_prefix("IP:") {
                ProtoSubjectAltName {
                    name: Some(Name::IpAddress(ip.to_string())),
                }
            } else if let Some(dn) = san.strip_prefix("DirName:") {
                ProtoSubjectAltName {
                    name: Some(Name::DirectoryName(dn.to_string())),
                }
            } else {
                // Unknown SAN type, skip
                continue;
            };

            proto_sans.push(proto_san);
        }

        Ok(proto_sans)
    }

    /// Get issued certificate from CA
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (certificate encoding)
    /// - NIAP PP-CA: FDP_ETC.1 - Export of user data (certificate retrieval)
    /// - RFC 7030 S4.2.3 - Certificate retrieval
    /// - RFC 7030 S4.1.3 - PKCS#7/CMS response format
    /// - RFC 5652 S5 - CMS SignedData (degenerate certs-only)
    ///
    /// # Arguments
    /// * `certificate_id` - Certificate ID from CA
    ///
    /// # Returns
    /// PKCS#7 (CMS) encoded certificate (RFC 7030 S4.1.3)
    pub async fn get_certificate(&self, certificate_id: Uuid) -> Result<Vec<u8>> {
        // Fetch certificate from database
        let cert_repo = ostrich_db::repository::CertificateRepository::new(self.db_pool.clone());
        let certificate = cert_repo
            .find_by_id(certificate_id)
            .await
            .map_err(Error::Database)?
            .ok_or_else(|| Error::NotFound)?;

        // RFC 7030 §4.1.3 - Response is PKCS#7 (CMS) signed-data
        // Wrap certificate in PKCS#7 certs-only structure
        let certs = vec![certificate.der_encoded];
        crate::rest::encode_certs_only_pkcs7(&certs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_sans_to_proto() {
        // Test DNS name conversion
        let sans = vec!["DNS:example.com".to_string()];
        let result = EstCaClient::convert_sans_to_proto(&sans).unwrap();
        assert_eq!(result.len(), 1);

        // Test email conversion
        let sans = vec!["email:user@example.com".to_string()];
        let result = EstCaClient::convert_sans_to_proto(&sans).unwrap();
        assert_eq!(result.len(), 1);

        // Test unknown SAN type is skipped
        let sans = vec!["unknown:value".to_string()];
        let result = EstCaClient::convert_sans_to_proto(&sans).unwrap();
        assert_eq!(result.len(), 0);
    }
}
