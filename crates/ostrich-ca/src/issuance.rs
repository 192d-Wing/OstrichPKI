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
use ostrich_crypto::{CryptoProvider, KeyHandle};
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

    /// Public CRL distribution URL embedded into issued certificates.
    ///
    /// RFC 5280 §4.2.1.13 - when set, issued leaves carry a CRL Distribution
    /// Points extension pointing relying parties at the public GET CRL endpoint.
    crl_distribution_url: Option<String>,

    /// Public OCSP responder URL embedded into issued certificates.
    ///
    /// RFC 5280 §4.2.2.1 / RFC 6960 - when set, issued leaves carry an Authority
    /// Information Access extension with an `id-ad-ocsp` accessDescription so
    /// relying parties can discover the OCSP responder for revocation checking.
    ocsp_responder_url: Option<String>,

    /// CA Issuers URL embedded into issued certificates' AIA extension.
    ///
    /// RFC 5280 §4.2.2.1 - `id-ad-caIssuers` accessDescription pointing relying
    /// parties at the issuing CA certificate (for chain building).
    ca_issuers_url: Option<String>,
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
            crl_distribution_url: None,
            ocsp_responder_url: None,
            ca_issuers_url: None,
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
            crl_distribution_url: None,
            ocsp_responder_url: None,
            ca_issuers_url: None,
        }
    }

    /// Add a certificate profile
    pub fn add_profile(&mut self, profile: CertificateProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Override the approval configuration.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FDP_CER_EXT.3 - approval workflow is the compliant
    ///   default (`require_approval: true`); disabling it is an explicit,
    ///   audited deployment decision (e.g. ACME issuance where RFC 8555
    ///   challenge validation serves as the automated approval)
    pub fn set_approval_config(&mut self, config: ApprovalConfig) {
        self.approval_config = config;
    }

    /// Wire the approval engine + repository into the issuer.
    ///
    /// Required when `approval_config.require_approval` is true: issuance loads
    /// the referenced approval request from this repository and refuses to
    /// proceed unless it is Approved. Without it, issuance fails closed with
    /// "Approval repository not configured".
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA: FDP_CER_EXT.2 (request linkage) / FDP_CER_EXT.3 (approval)
    pub fn set_approval(
        &mut self,
        engine: Arc<ApprovalEngine>,
        repo: Arc<ApprovalRepository>,
        config: ApprovalConfig,
    ) {
        self.approval_engine = Some(engine);
        self.approval_repo = Some(repo);
        self.approval_config = config;
    }

    /// Set the public CRL distribution URL embedded into issued certificates.
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.1.13 - CRL Distribution Points extension
    /// - NIAP PP-CA: FMT_SMF.1 - CRL distribution configuration
    /// - NIST 800-53: SC-17 - PKI certificate status (points relying parties at
    ///   the public CRL GET endpoint)
    ///
    /// Should be the externally reachable URL of the public CRL GET endpoint
    /// (e.g. `https://ca.example.com/api/v1/crl`).
    pub fn set_crl_distribution_url(&mut self, url: impl Into<String>) {
        self.crl_distribution_url = Some(url.into());
    }

    /// Set the OCSP responder URL embedded into issued certificates (AIA).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.2.1 / RFC 6960 - id-ad-ocsp accessDescription
    /// - NIST 800-53: SC-17 - PKI certificate status (lets relying parties
    ///   discover the OCSP responder for revocation checking)
    ///
    /// Should be the externally reachable URL of the OCSP responder
    /// (e.g. `http://ocsp.example.com`).
    pub fn set_ocsp_responder_url(&mut self, url: impl Into<String>) {
        self.ocsp_responder_url = Some(url.into());
    }

    /// Set the CA Issuers URL embedded into issued certificates (AIA).
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.2.2.1 - id-ad-caIssuers accessDescription (points relying
    ///   parties at the issuing CA certificate for chain building)
    ///
    /// Should be the externally reachable URL serving the CA certificate
    /// (e.g. `http://ca.example.com/api/v1/ca-certificate`).
    pub fn set_ca_issuers_url(&mut self, url: impl Into<String>) {
        self.ca_issuers_url = Some(url.into());
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

        // Build certificate.
        // RFC 5280 §7.1 - the issuer field must be the CA certificate's
        // structured subject DN (parsed from DER), not a CN wrapper around
        // the rendered string, or name chaining fails at validation time.
        let issuer_dn = ostrich_x509::parser::parse_subject_dn(&self.ca_certificate.der_encoded)
            .map_err(|e| {
                Error::Issuance(format!("Failed to parse CA subject DN: {}", e))
            })?;
        // RFC 5280 §4.1.1.2 - choose the signature algorithm from the CA key
        // type so the TBS AlgorithmIdentifier, the outer signatureAlgorithm, and
        // the actual signing call all agree (RSA / ECDSA P-256/P-384 / Ed25519).
        let sig_alg =
            ostrich_x509::signing::recommended_signature_algorithm(self.ca_key.key_type)
                .map_err(|e| {
                    Error::Issuance(format!(
                        "unsupported CA key type for issuance: {}",
                        e
                    ))
                })?;

        let mut builder = CertificateBuilder::from_profile(profile)
            .serial_number(serial_number.clone())
            .subject(request.subject.clone())
            .issuer(issuer_dn)
            .public_key(request.public_key.clone())
            .signature_algorithm(sig_alg);

        // COMPLIANCE MAPPING:
        // - RFC 5280 §4.2.1.2 - Subject Key Identifier: SHA-1 of the leaf's own
        //   subjectPublicKey, so verifiers and downstream issuers can reference
        //   this certificate's key.
        // - NIAP PP-CA: FDP_CER_EXT.1 - certificate field generation
        //
        // Computed from the subject's SPKI (request.public_key). A malformed
        // SPKI would already have failed TBS encoding, so a failure here is a
        // genuine error and is surfaced rather than silently dropped.
        let ski = ostrich_x509::signing::key_identifier(&request.public_key)
            .map_err(|e| Error::Issuance(format!("failed to compute subject key id: {}", e)))?;
        builder = builder.subject_key_id(ski);

        // COMPLIANCE MAPPING:
        // - RFC 5280 §4.2.1.1 - Authority Key Identifier: the issuer's
        //   subjectKeyIdentifier, so this leaf points at the key that signed it
        //   and path builders can chain leaf -> issuer reliably.
        //
        // Derived from the CA certificate's SPKI. Kept robust: if AKI cannot be
        // computed (e.g. an unparseable CA cert), we log and proceed without it
        // rather than failing issuance - AKI is a path-building hint, not a
        // correctness requirement for the signature.
        match Self::ca_subject_public_key_info(&self.ca_certificate.der_encoded)
            .and_then(|spki| {
                ostrich_x509::signing::key_identifier(&spki)
                    .map_err(|e| Error::Issuance(format!("AKI key id: {}", e)))
            }) {
            Ok(aki) => builder = builder.authority_key_id(aki),
            Err(e) => tracing::warn!(
                error = %e,
                "Could not compute Authority Key Identifier from CA certificate; \
                 issuing leaf without AKI"
            ),
        }

        // Add subject alternative names
        for san in request.subject_alt_names {
            builder = builder.add_subject_alt_name(san);
        }

        // COMPLIANCE MAPPING:
        // - RFC 5280 §4.2.1.13 - CRL Distribution Points: point relying parties
        //   at the public CRL GET endpoint so they can fetch revocation status.
        // - NIAP PP-CA: FMT_SMF.1 - CRL distribution
        // - NIST 800-53: SC-17 - PKI certificate status
        //
        // Only emitted when the CA is configured with a public CRL URL.
        if let Some(crl_url) = &self.crl_distribution_url {
            builder = builder.add_crl_distribution_point(
                ostrich_x509::extensions::CrlDistributionPoint::new(crl_url.clone()),
            );
        }

        // COMPLIANCE MAPPING:
        // - RFC 5280 §4.2.2.1 / RFC 6960 - Authority Information Access: point
        //   relying parties at the OCSP responder (id-ad-ocsp) so they can check
        //   revocation status, and at the issuing CA cert (id-ad-caIssuers) for
        //   chain building.
        // - NIST 800-53: SC-17 - PKI certificate status discovery
        //
        // Each accessDescription is emitted only when its URL is configured.
        if let Some(ocsp_url) = &self.ocsp_responder_url {
            builder = builder.add_authority_info_access(
                ostrich_x509::extensions::AuthorityInfoAccess::Ocsp(ocsp_url.clone()),
            );
        }
        if let Some(ca_issuers_url) = &self.ca_issuers_url {
            builder = builder.add_authority_info_access(
                ostrich_x509::extensions::AuthorityInfoAccess::CaIssuers(ca_issuers_url.clone()),
            );
        }

        // Build TBS certificate
        let tbs_cert = builder.build_tbs()?;

        // Encode TBS certificate to DER for signing
        let tbs_der = tbs_cert.to_der()?;

        // NIAP PP-CA: FCS_COP.1.1 - Sign TBS certificate with CA private key
        //
        // The signing algorithm MUST match the AlgorithmIdentifier the builder
        // wrote into the TBS (RFC 5280 §4.1.1.2 requires tbsCertificate.signature
        // and signatureAlgorithm to be identical). Both come from `sig_alg`
        // (the shared signing module), so RSA / ECDSA / Ed25519 CA keys all
        // produce consistent, verifiable certificates.
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, sig_alg, &tbs_der)
            .await?;

        // ECDSA signatures come back as fixed-length r||s from the provider;
        // X.509 requires DER Ecdsa-Sig-Value (RFC 5758 §3.2). RSA/Ed25519 pass
        // through unchanged. The encoded bytes go into the signature BIT STRING.
        let signature = ostrich_x509::signing::encode_x509_signature(sig_alg, signature)
            .map_err(|e| Error::Issuance(format!("failed to encode signature: {}", e)))?;

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

    /// Extract the DER-encoded SubjectPublicKeyInfo from a CA certificate.
    ///
    /// Used to derive the issuer's key identifier for the Authority Key
    /// Identifier extension (RFC 5280 §4.2.1.1) placed on issued leaves.
    fn ca_subject_public_key_info(ca_cert_der: &[u8]) -> Result<Vec<u8>> {
        // ParsedCertificate.public_key is the complete DER SubjectPublicKeyInfo
        // (x509-parser's `public_key().raw`), exactly what key_identifier wants.
        let parsed = ostrich_x509::parser::parse_certificate(ca_cert_der)
            .map_err(|e| Error::Issuance(format!("failed to parse CA certificate for AKI: {}", e)))?;
        Ok(parsed.public_key)
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
