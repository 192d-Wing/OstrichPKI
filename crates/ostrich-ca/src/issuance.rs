//! Certificate issuance functionality
//!
//! This module handles certificate issuance including CSR validation, certificate
//! building, signing, and storage.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1.1**: Issue certificates - Core certificate issuance functionality
//! - **FCS_COP.1.1**: Perform cryptographic signing using CA private key
//! - **FDP_IFC.1.1**: Enforce certificate policy during issuance
//! - **FDP_ACC.1.1**: Access control for certificate issuance operations
//! - **FAU_GEN.1.1**: Generate audit record for each certificate issuance
//! - **FPT_STM.1.1**: Use reliable time source for notBefore/notAfter fields
//!
//! ## RFC Compliance
//! - RFC 5280 §4.1 - Certificate structure and issuance
//! - RFC 5280 §4.1.2.2 - Serial number requirements
//!
//! ## NIST 800-53 Controls
//! - SC-12: Cryptographic key establishment and management
//! - SC-13: Use of FIPS-validated cryptographic algorithms
//! - AU-2: Audit certificate issuance events

use crate::{
    Error, Result,
    approval::{ApprovalConfig, ApprovalEngine, RequestType},
};
use chrono::{DateTime, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use ostrich_db::{
    DatabasePool,
    models::Certificate,
    repository::{ApprovalRepository, CertificateRepository, Repository},
};
use ostrich_x509::{CertificateBuilder, extensions::SubjectAltName, profile::CertificateProfile};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Certificate issuance request
///
/// RFC 5280 §4.1 - Certificate fields
/// RFC 2986 - PKCS#10 CSR format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// Profile to use for issuance
    pub profile_name: String,

    /// Subject distinguished name
    pub subject: DistinguishedName,

    /// Subject alternative names (optional)
    pub subject_alt_names: Vec<SubjectAltName>,

    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,

    /// Requestor (for audit)
    pub requestor: String,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,

    /// Optional PKCS#10 CSR (DER-encoded)
    /// If provided, the CSR signature will be verified before issuance
    /// to ensure proof-of-possession of the private key
    #[serde(default)]
    pub csr_der: Option<Vec<u8>>,

    /// Optional approval request ID (FDP_CER_EXT.2 linkage)
    ///
    /// If provided, the issuance will link to the approval request.
    /// If approval is required but this is None, issuance will fail.
    #[serde(default)]
    pub approval_request_id: Option<Uuid>,
}

/// Issued certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    /// Certificate ID
    pub certificate_id: Uuid,

    /// Serial number
    pub serial_number: Vec<u8>,

    /// DER-encoded certificate
    pub der_encoded: Vec<u8>,

    /// PEM-encoded certificate
    pub pem_encoded: String,

    /// Validity period
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// Certificate issuer
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function for certificate issuance
/// - NIAP PP-CA: FCS_COP.1.1 - Cryptographic signing operations
/// - NIAP PP-CA: FDP_CER_EXT.2 - Certificate request linkage via approval workflow
/// - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval enforcement
/// - NIST 800-53: SC-12 - Cryptographic key generation and management
pub struct CertificateIssuer {
    /// CA key handle
    ca_key: KeyHandle,

    /// CA certificate
    ca_certificate: Certificate,

    /// Crypto provider (Arc for sharing with validation functions)
    crypto_provider: std::sync::Arc<dyn CryptoProvider>,

    /// Database pool
    db_pool: DatabasePool,

    /// Audit sink
    audit_sink: Box<dyn AuditSink>,

    /// Available profiles
    profiles: std::collections::HashMap<String, CertificateProfile>,

    /// Approval engine (optional - for FDP_CER_EXT.3 compliance)
    #[allow(dead_code)]
    approval_engine: Option<Arc<ApprovalEngine>>,

    /// Approval repository (optional - for FDP_CER_EXT.2 linkage)
    approval_repo: Option<Arc<ApprovalRepository>>,

    /// Approval configuration
    approval_config: ApprovalConfig,
}

impl CertificateIssuer {
    /// Create a new certificate issuer
    pub fn new(
        ca_key: KeyHandle,
        ca_certificate: Certificate,
        crypto_provider: std::sync::Arc<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
    ) -> Self {
        Self {
            ca_key,
            ca_certificate,
            crypto_provider,
            db_pool,
            audit_sink,
            profiles: std::collections::HashMap::new(),
            approval_engine: None,
            approval_repo: None,
            approval_config: ApprovalConfig::default(),
        }
    }

    /// Create a new certificate issuer with approval workflow
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval workflow
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_approval(
        ca_key: KeyHandle,
        ca_certificate: Certificate,
        crypto_provider: std::sync::Arc<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
        approval_engine: Arc<ApprovalEngine>,
        approval_repo: Arc<ApprovalRepository>,
        approval_config: ApprovalConfig,
    ) -> Self {
        Self {
            ca_key,
            ca_certificate,
            crypto_provider,
            db_pool,
            audit_sink,
            profiles: std::collections::HashMap::new(),
            approval_engine: Some(approval_engine),
            approval_repo: Some(approval_repo),
            approval_config,
        }
    }

    /// Add a certificate profile
    pub fn add_profile(&mut self, profile: CertificateProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Issue a certificate
    ///
    /// NIAP PP-CA: FMT_SMF.1.1 - Issue certificate security management function
    /// NIAP PP-CA: FCS_COP.1.1 - Sign certificate using CA private key
    /// NIAP PP-CA: FDP_IFC.1.1 - Enforce certificate profile policy
    /// NIAP PP-CA: FAU_GEN.1.1 - Generate audit record for issuance
    ///
    /// RFC 5280 §4.1 - Certificate generation
    /// NIST 800-53: SC-12 - Cryptographic key generation
    /// NIST 800-53: AU-2 - Auditable event (certificate issuance)
    pub async fn issue(&self, request: IssuanceRequest) -> Result<IssuedCertificate> {
        // NIAP PP-CA: FAU_GEN.1.1 - Generate audit record
        // NIST 800-53: AU-2 - Audit certificate issuance
        let mut audit_event = AuditEventBuilder::new(
            EventType::CertificateIssuance,
            &request.requestor,
            request.subject.to_string_rfc4514(),
            "issue",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "profile": request.profile_name,
            "subject": request.subject.to_string_rfc4514(),
        }))
        .build();

        // NIAP PP-CA: FDP_IFC.1.1 - Retrieve and validate certificate policy (profile)
        let profile = self
            .profiles
            .get(&request.profile_name)
            .ok_or_else(|| Error::ProfileNotFound(request.profile_name.clone()))?;

        // NIAP PP-CA: FDP_IFC.1.1 - Validate policy constraints
        profile.validate()?;

        // COMPLIANCE MAPPING:
        // - NIAP PP-CA: FDP_CER_EXT.2 - Certificate request linkage
        // - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval workflow
        // - NIAP PP-CA: FDP_SEPP.1 - Segregation of duties enforcement
        //
        // Verify approval if required
        let approval_request_id = request.approval_request_id;
        if self.approval_config.require_approval {
            let approval_request_id_val = approval_request_id.ok_or_else(|| {
                Error::InvalidRequest(
                    "Approval request ID is required when approval workflow is enabled".to_string(),
                )
            })?;

            // Get approval repository and request
            let approval_repo = self.approval_repo.as_ref().ok_or_else(|| {
                Error::InvalidRequest("Approval repository not configured".to_string())
            })?;

            let approval_record = approval_repo
                .get_request(&approval_request_id_val)
                .await?
                .ok_or_else(|| {
                    Error::InvalidRequest(format!(
                        "Approval request not found: {}",
                        approval_request_id_val
                    ))
                })?;

            // Convert database record to approval request
            let approval_request = crate::approval::ApprovalRequest::from_record(approval_record);

            // Verify approval status
            if approval_request.status != crate::approval::ApprovalStatus::Approved {
                audit_event.outcome = EventOutcome::Failure;
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                return Err(Error::InvalidRequest(format!(
                    "Approval request must be in Approved status, current status: {:?}",
                    approval_request.status
                )));
            }

            // Verify request type matches
            if approval_request.request_type != RequestType::Issuance {
                audit_event.outcome = EventOutcome::Failure;
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                return Err(Error::InvalidRequest(format!(
                    "Approval request type mismatch: expected Issuance, got {:?}",
                    approval_request.request_type
                )));
            }

            // FDP_CER_EXT.2: Verify approval request hasn't been used already
            if approval_request.certificate_id.is_some() {
                audit_event.outcome = EventOutcome::Failure;
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                return Err(Error::InvalidRequest(
                    "Approval request has already been used to issue a certificate".to_string(),
                ));
            }

            tracing::info!(
                "Approval verified for issuance request: {}",
                approval_request_id_val
            );
        }

        // Validate request
        if profile.subject_alt_name_required && request.subject_alt_names.is_empty() {
            audit_event.outcome = EventOutcome::Failure;
            self.audit_sink
                .record(&mut audit_event)
                .await
                .map_err(Error::Audit)?;

            return Err(Error::InvalidRequest(
                "Subject alternative names are required for this profile".to_string(),
            ));
        }

        // COMPLIANCE MAPPING:
        // - RFC 2986 §4.2 - CSR signature verification
        // - NIST 800-53 SI-10 - Input validation (CSR signature verification)
        // - NIAP PP-CA FDP_ITC.1.1 - Validate imported user data (CSR)
        // - NIST 800-53 SC-8(1) - Cryptographic protection (proof of possession)
        //
        // If CSR is provided, verify signature to ensure proof-of-possession
        // of the private key corresponding to the public key in the request
        if let Some(csr_der) = &request.csr_der {
            // Parse CSR
            let parsed_csr = ostrich_x509::parser::parse_csr(csr_der)
                .map_err(|e| Error::InvalidRequest(format!("Failed to parse CSR: {}", e)))?;

            // Verify CSR signature (proof of possession)
            let signature_valid =
                ostrich_x509::parser::verify_csr_signature(&parsed_csr, &self.crypto_provider)
                    .await
                    .map_err(|e| {
                        Error::InvalidRequest(format!("CSR signature verification failed: {}", e))
                    })?;

            if !signature_valid {
                audit_event.outcome = EventOutcome::Failure;
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                return Err(Error::InvalidRequest(
                    "Invalid CSR signature - proof of possession failed".to_string(),
                ));
            }

            // Verify that the public key in the CSR matches the public key in the request
            if parsed_csr.public_key != request.public_key {
                audit_event.outcome = EventOutcome::Failure;
                self.audit_sink
                    .record(&mut audit_event)
                    .await
                    .map_err(Error::Audit)?;

                return Err(Error::InvalidRequest(
                    "CSR public key does not match request public key".to_string(),
                ));
            }

            tracing::debug!(
                "CSR signature verified for subject: {}",
                request.subject.to_string_rfc4514()
            );
        }

        // Generate serial number
        let serial_number = self.generate_serial_number()?;

        // Build certificate
        let mut builder = CertificateBuilder::from_profile(profile)
            .serial_number(serial_number.clone())
            .subject(request.subject.clone())
            .issuer(
                DistinguishedName::new_cn(&self.ca_certificate.subject_dn), // TODO: Parse from certificate
            )
            .public_key(request.public_key.clone());

        // Add subject alternative names
        for san in request.subject_alt_names {
            builder = builder.add_subject_alt_name(san);
        }

        // Build TBS certificate
        let tbs_cert = builder.build_tbs()?;

        // Encode TBS certificate to DER for signing
        let tbs_der = tbs_cert.to_der()?;

        // NIAP PP-CA: FCS_COP.1.1 - Sign TBS certificate with CA private key
        // Uses FIPS-validated cryptographic algorithm (RSA-PSS with SHA-256)
        // TODO: Determine signature algorithm from CA key type
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, Algorithm::RsaPssSha256, &tbs_der)
            .await?;

        // Construct final signed certificate
        let der_encoded = self.build_signed_certificate(&tbs_der, &signature)?;

        // Convert DER to PEM
        let pem_encoded = self.der_to_pem(&der_encoded)?;

        // Store certificate in database
        let cert_id = Uuid::new_v4();
        let certificate = Certificate {
            id: cert_id,
            ca_id: self.ca_certificate.id,
            serial_number: serial_number.as_bytes().to_vec(),
            subject_dn: request.subject.to_string_rfc4514(),
            issuer_dn: self.ca_certificate.subject_dn.clone(),
            not_before: tbs_cert.not_before,
            not_after: tbs_cert.not_after,
            der_encoded: der_encoded.clone(),
            pem_encoded: pem_encoded.clone(),
            revoked: false,
            revocation_time: None,
            revocation_reason: None,
            issuer_service: Some("CA".to_string()),
            requestor: Some(request.requestor.clone()),
            profile_name: Some(request.profile_name.clone()),
            metadata: request.metadata.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        cert_repo.create(&certificate).await?;

        // COMPLIANCE MAPPING:
        // - NIAP PP-CA: FDP_CER_EXT.2 - Link certificate to approval request
        //
        // Mark approval request as completed and link to certificate
        if let Some(approval_request_id_val) = approval_request_id
            && let Some(approval_repo) = &self.approval_repo
        {
            approval_repo
                .mark_request_completed(&approval_request_id_val, cert_id)
                .await?;

            tracing::info!(
                "Linked certificate {} to approval request {}",
                cert_id,
                approval_request_id_val
            );
        }

        // NIAP PP-CA: FAU_GEN.1.1 - Record successful issuance audit event
        self.audit_sink
            .record(&mut audit_event)
            .await
            .map_err(Error::Audit)?;

        tracing::info!(
            "Certificate issued: {} for {}",
            cert_id,
            request.subject.to_string_rfc4514()
        );

        Ok(IssuedCertificate {
            certificate_id: cert_id,
            serial_number: serial_number.as_bytes().to_vec(),
            der_encoded,
            pem_encoded,
            not_before: tbs_cert.not_before,
            not_after: tbs_cert.not_after,
        })
    }

    /// Build a signed X.509 certificate from TBS and signature
    ///
    /// RFC 5280 §4.1 - Certificate structure
    fn build_signed_certificate(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        use der::{Decode, Encode, asn1::BitString};
        use x509_cert::{Certificate as X509Certificate, TbsCertificate};

        // Parse TBS certificate from DER
        let tbs = TbsCertificate::from_der(tbs_der)
            .map_err(|e| Error::Issuance(format!("Failed to parse TBS certificate: {}", e)))?;

        // Get signature algorithm (same as in TBS)
        let signature_algorithm = tbs.signature.clone();

        // Convert signature bytes to BitString
        let signature_value = BitString::from_bytes(signature)
            .map_err(|e| Error::Issuance(format!("Failed to create signature BitString: {}", e)))?;

        // Build complete certificate
        let certificate = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm,
            signature: signature_value,
        };

        // Encode to DER
        certificate
            .to_der()
            .map_err(|e| Error::Issuance(format!("Failed to encode certificate: {}", e)))
    }

    /// Convert DER-encoded certificate to PEM format
    ///
    /// RFC 7468 - PEM encoding
    fn der_to_pem(&self, der: &[u8]) -> Result<String> {
        use pem_rfc7468::{LineEnding, encode_string};

        const CERTIFICATE_LABEL: &str = "CERTIFICATE";

        encode_string(CERTIFICATE_LABEL, LineEnding::LF, der)
            .map_err(|e| Error::Issuance(format!("Failed to encode PEM: {}", e)))
    }

    /// Generate a cryptographically random serial number
    ///
    /// RFC 5280 §4.1.2.2 - Serial number must be positive and unique
    fn generate_serial_number(&self) -> Result<SerialNumber> {
        use ostrich_common::util::random::secure_random_bytes;

        // Generate 20 random bytes (160 bits) - RFC 5280 maximum
        let mut bytes = secure_random_bytes(20);

        // Ensure positive (clear high bit)
        bytes[0] &= 0x7F;

        SerialNumber::from_bytes(bytes).map_err(Error::Common)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuance_request_serialization() {
        let request = IssuanceRequest {
            profile_name: "tls_server".to_string(),
            subject: DistinguishedName::new_cn("example.com"),
            subject_alt_names: vec![SubjectAltName::dns("example.com")],
            public_key: vec![1, 2, 3],
            requestor: "admin@example.com".to_string(),
            metadata: None,
            csr_der: None,
            approval_request_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IssuanceRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.profile_name, "tls_server");
        assert_eq!(deserialized.requestor, "admin@example.com");
        assert!(deserialized.csr_der.is_none());
        assert!(deserialized.approval_request_id.is_none());
    }
}
