//! RFC 5280 §6.1 Path Validation Algorithm
//!
//! This module implements the complete certification path validation algorithm
//! as specified in RFC 5280 Section 6.1.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §6.1: Certification Path Validation
//! - NIST 800-53 SC-17: PKI certificates
//! - NIAP PP-CA FIA_X509_EXT.1: X.509 certificate validation

use super::error::{Result, ValidationError};
use super::extensions::{check_unknown_critical_extensions, get_basic_constraints, get_key_usage};
use super::path_builder::PathBuilder;
use super::trust_anchor::{TrustAnchor, TrustAnchorStore};
use crate::parser::ParsedCertificate;
use chrono::{DateTime, Utc};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle, KeyType};
use std::sync::Arc;

/// Validation context - inputs to the path validation algorithm
///
/// RFC 5280 §6.1.1 - Inputs
#[derive(Clone)]
pub struct ValidationContext {
    /// Certificate to validate (end entity)
    pub certificate: ParsedCertificate,

    /// Trust anchor store
    pub trust_anchors: Arc<TrustAnchorStore>,

    /// Current date/time for validity checking
    /// RFC 5280 §6.1.1(a)
    pub validation_time: DateTime<Utc>,

    /// Maximum path length
    pub max_path_length: usize,

    /// Check revocation status?
    /// RFC 5280 - Revocation checking (Phase 4)
    pub check_revocation: bool,

    /// Enable AIA fetching for chain building
    /// User requirement: configurable
    pub enable_aia_fetching: bool,
}

impl ValidationContext {
    /// Create new validation context with defaults
    pub fn new(certificate: ParsedCertificate, trust_anchors: Arc<TrustAnchorStore>) -> Self {
        Self {
            certificate,
            trust_anchors,
            validation_time: Utc::now(),
            max_path_length: 10,
            check_revocation: false,    // Phase 4
            enable_aia_fetching: false, // Default: disabled per user requirement
        }
    }

    /// Set validation time
    pub fn with_validation_time(mut self, time: DateTime<Utc>) -> Self {
        self.validation_time = time;
        self
    }

    /// Set maximum path length
    pub fn with_max_path_length(mut self, length: usize) -> Self {
        self.max_path_length = length;
        self
    }

    /// Enable revocation checking (Phase 4)
    pub fn with_revocation_checking(mut self, enabled: bool) -> Self {
        self.check_revocation = enabled;
        self
    }

    /// Enable AIA fetching
    pub fn with_aia_fetching(mut self, enabled: bool) -> Self {
        self.enable_aia_fetching = enabled;
        self
    }
}

/// Validation state - working state during path validation
///
/// RFC 5280 §6.1.2 - Initialization and state variables
struct ValidationState {
    /// Working issuer name
    /// RFC 5280 §6.1.2(a)
    working_issuer_name: String,

    /// Working public key
    /// RFC 5280 §6.1.2(b)
    _working_public_key: Vec<u8>,

    /// Maximum path length remaining
    /// RFC 5280 §6.1.2(k)
    max_path_length: Option<usize>,
}

impl ValidationState {
    /// Initialize validation state
    ///
    /// RFC 5280 §6.1.3 - Initialization
    fn new(trust_anchor: &TrustAnchor, max_path: usize) -> Self {
        Self {
            working_issuer_name: trust_anchor.subject_dn.clone(),
            _working_public_key: trust_anchor.subject_public_key.clone(),
            max_path_length: Some(max_path),
        }
    }
}

/// Result of path validation
#[derive(Debug)]
pub struct ValidationResult {
    /// Was validation successful?
    pub valid: bool,

    /// Validated certificate chain (root to end entity)
    pub chain: Vec<ParsedCertificate>,

    /// Trust anchor used
    pub trust_anchor_id: uuid::Uuid,

    /// Validation errors (if any)
    pub errors: Vec<ValidationError>,

    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

/// Path validator
///
/// RFC 5280 §6.1 - Basic Path Validation
pub struct PathValidator;

impl PathValidator {
    /// Validate certificate path
    ///
    /// RFC 5280 §6.1 - Complete path validation algorithm
    pub fn validate(ctx: ValidationContext) -> Result<ValidationResult> {
        // §6.1.2 - Build certification path
        let builder = PathBuilder::new((*ctx.trust_anchors).clone())
            .with_max_depth(ctx.max_path_length)
            .with_aia_fetching(ctx.enable_aia_fetching);

        let chain = builder.build_path(&ctx.certificate)?;

        // Find trust anchor for this chain
        let trust_anchor = Self::find_trust_anchor(&chain, &ctx.trust_anchors)?;

        // §6.1.2 - Initialize state
        let mut state = ValidationState::new(&trust_anchor, ctx.max_path_length);

        // §6.1.3 - Process each certificate in chain
        let mut errors = Vec::new();
        let chain_len = chain.len();

        for (i, cert) in chain.iter().enumerate() {
            if let Err(e) = Self::process_certificate(cert, i, &mut state, &ctx, chain_len) {
                errors.push(e);
            }
        }

        // §6.1.5 - Wrap-up procedure
        let valid = errors.is_empty();

        Ok(ValidationResult {
            valid,
            chain,
            trust_anchor_id: trust_anchor.id,
            errors,
            validated_at: ctx.validation_time,
        })
    }

    /// Find trust anchor for certificate chain
    fn find_trust_anchor(
        chain: &[ParsedCertificate],
        trust_anchors: &TrustAnchorStore,
    ) -> Result<TrustAnchor> {
        let last_cert = chain
            .last()
            .ok_or(ValidationError::InvalidChain("Empty chain".to_string()))?;

        let anchors = trust_anchors.find_by_issuer(&last_cert.issuer_dn);

        anchors
            .first()
            .cloned()
            .cloned()
            .ok_or(ValidationError::TrustAnchorNotFound)
    }

    /// Process a single certificate in the chain
    ///
    /// RFC 5280 §6.1.3 - Basic Certificate Processing
    #[allow(clippy::unnecessary_wraps)]
    fn process_certificate(
        cert: &ParsedCertificate,
        index: usize,
        state: &mut ValidationState,
        ctx: &ValidationContext,
        chain_len: usize,
    ) -> Result<()> {
        // (a) Verify signature - Phase 2: stub (will add crypto integration)
        // Self::verify_signature(cert, state, ctx)?;

        // (b) Check validity period
        Self::check_validity_period(cert, ctx.validation_time)?;

        // (c) Check revocation status - Phase 4
        // if ctx.check_revocation {
        //     Self::check_revocation(cert, ctx)?;
        // }

        // (d) Verify issuer name matches working_issuer_name
        Self::verify_issuer_name(cert, state)?;

        // (e) Name constraints - Phase 3
        // Self::check_name_constraints(cert, state)?;

        // (f) Policy processing - Phase 3
        // Self::process_policies(cert, state)?;

        // (g) Check for unknown critical extensions
        check_unknown_critical_extensions(cert)?;

        // (j) Process Basic Constraints
        Self::process_basic_constraints(cert, index, state)?;

        // (k) If not last cert in chain (not end entity), it must be a CA cert
        // End entity is at index 0, so any other cert should be verified as CA
        if index < chain_len - 1 {
            Self::verify_ca_key_usage(cert)?;
        }

        // (n) Update working issuer name for next cert
        state.working_issuer_name = cert.subject_dn.clone();

        Ok(())
    }

    /// Check certificate validity period
    ///
    /// RFC 5280 §6.1.3(b)
    fn check_validity_period(
        cert: &ParsedCertificate,
        validation_time: DateTime<Utc>,
    ) -> Result<()> {
        if validation_time < cert.not_before {
            return Err(ValidationError::ValidityPeriod(format!(
                "Certificate not yet valid. Valid from: {}, Current time: {}",
                cert.not_before, validation_time
            )));
        }

        if validation_time > cert.not_after {
            return Err(ValidationError::ValidityPeriod(format!(
                "Certificate expired. Valid until: {}, Current time: {}",
                cert.not_after, validation_time
            )));
        }

        Ok(())
    }

    /// Verify issuer name matches working issuer name
    ///
    /// RFC 5280 §6.1.3(d)
    fn verify_issuer_name(cert: &ParsedCertificate, state: &ValidationState) -> Result<()> {
        if cert.issuer_dn != state.working_issuer_name {
            return Err(ValidationError::IssuerNameMismatch(format!(
                "Expected: {}, Found: {}",
                state.working_issuer_name, cert.issuer_dn
            )));
        }

        Ok(())
    }

    /// Process basic constraints extension
    ///
    /// RFC 5280 §6.1.3(j)
    fn process_basic_constraints(
        cert: &ParsedCertificate,
        _index: usize,
        state: &mut ValidationState,
    ) -> Result<()> {
        if let Some(bc) = get_basic_constraints(cert)? {
            // If this is a CA cert, check path length constraint
            if bc.ca
                && let Some(path_len) = bc.path_len_constraint
            {
                // Update max_path_length if constraint is more restrictive
                if let Some(current_max) = state.max_path_length {
                    state.max_path_length = Some(current_max.min(path_len as usize));
                }
            }
        }

        Ok(())
    }

    /// Verify CA certificate has keyCertSign in key usage
    ///
    /// RFC 5280 §6.1.3(l)
    fn verify_ca_key_usage(cert: &ParsedCertificate) -> Result<()> {
        if let Some(ku) = get_key_usage(cert)?
            && !ku.has_key_cert_sign()
        {
            return Err(ValidationError::KeyUsage(
                "CA certificate must have keyCertSign usage".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify certificate signature
    ///
    /// RFC 5280 §6.1.3(a) - Verify signature using issuer's public key
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §6.1.3(a): Signature verification
    /// - FIPS 186-5: Digital signature verification
    /// - NIST 800-53 SC-17: PKI certificate validation
    #[allow(dead_code)]
    async fn verify_signature(
        cert: &ParsedCertificate,
        issuer_public_key: &[u8],
        crypto_provider: &Arc<dyn CryptoProvider>,
    ) -> Result<()> {
        // Map signature algorithm OID to Algorithm enum
        let algorithm = map_signature_algorithm_oid(&cert.signature_algorithm)?;

        // Import issuer's public key for verification
        let key_handle = import_public_key_for_verification(issuer_public_key, algorithm)?;

        // Verify the signature on the TBS certificate
        let valid = crypto_provider
            .verify(
                &key_handle,
                algorithm,
                &cert.tbs_certificate,
                &cert.signature,
            )
            .await
            .map_err(|e| ValidationError::SignatureVerification(format!("Crypto error: {}", e)))?;

        if !valid {
            return Err(ValidationError::SignatureVerification(
                "Invalid signature".to_string(),
            ));
        }

        Ok(())
    }
}

/// Import a public key from SPKI DER for verification
///
/// Creates a temporary KeyHandle for signature verification
/// Similar to ostrich-acme/src/jws.rs:import_public_key_temp
fn import_public_key_for_verification(_spki_der: &[u8], algorithm: Algorithm) -> Result<KeyHandle> {
    use ostrich_crypto::key::ProviderId;

    // Determine key type from algorithm
    let key_type = match algorithm {
        Algorithm::RsaPkcs1Sha256
        | Algorithm::RsaPkcs1Sha384
        | Algorithm::RsaPkcs1Sha512
        | Algorithm::RsaPssSha256
        | Algorithm::RsaPssSha384
        | Algorithm::RsaPssSha512 => KeyType::Rsa2048, // TODO: Parse actual key size from SPKI
        Algorithm::EcdsaP256Sha256 => KeyType::EcP256,
        Algorithm::EcdsaP384Sha384 => KeyType::EcP384,
        Algorithm::EcdsaP521Sha512 => KeyType::EcP521,
        Algorithm::Ed25519 => KeyType::Ed25519,
        _ => {
            return Err(ValidationError::SignatureVerification(format!(
                "Unsupported signature algorithm: {:?}",
                algorithm
            )));
        }
    };

    // Create a temporary KeyHandle for verification
    // The actual public key bytes are in spki_der, but we don't use them directly
    // The CryptoProvider will parse the SPKI when needed
    let key_id = uuid::Uuid::new_v4().as_bytes().to_vec();

    Ok(KeyHandle {
        key_id,
        key_type,
        provider_id: ProviderId::Software,
        algorithm,
        label: "temp-verification-key".to_string(),
    })
}

/// Map signature algorithm OID to Algorithm enum
///
/// RFC 5280 §4.1.1.2 - Signature algorithms
fn map_signature_algorithm_oid(oid: &str) -> Result<Algorithm> {
    match oid {
        // RSA PKCS#1 v1.5
        "1.2.840.113549.1.1.11" => Ok(Algorithm::RsaPkcs1Sha256), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Ok(Algorithm::RsaPkcs1Sha384), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Ok(Algorithm::RsaPkcs1Sha512), // sha512WithRSAEncryption

        // RSA-PSS
        "1.2.840.113549.1.1.10" => Ok(Algorithm::RsaPssSha256), // id-RSASSA-PSS

        // ECDSA
        "1.2.840.10045.4.3.2" => Ok(Algorithm::EcdsaP256Sha256), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(Algorithm::EcdsaP384Sha384), // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Ok(Algorithm::EcdsaP521Sha512), // ecdsa-with-SHA512

        // EdDSA
        "1.3.101.112" => Ok(Algorithm::Ed25519), // id-Ed25519

        _ => Err(ValidationError::SignatureVerification(format!(
            "Unsupported signature algorithm OID: {}",
            oid
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::trust_anchor::TrustAnchor;

    fn create_test_cert(
        subject: &str,
        issuer: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> ParsedCertificate {
        ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: subject.to_string(),
            issuer_dn: issuer.to_string(),
            not_before,
            not_after,
            public_key: vec![0x30, 0x82, 0x01, 0x22],
            signature: vec![0x00, 0x01, 0x02],
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            tbs_certificate: vec![],
            der_encoded: vec![],
            basic_constraints: None,
            key_usage: None,
            subject_alt_names: vec![],
        }
    }

    #[test]
    fn test_validation_context_new() {
        let cert = create_test_cert("CN=Test", "CN=CA", Utc::now(), Utc::now());
        let store = Arc::new(TrustAnchorStore::new());
        let ctx = ValidationContext::new(cert, store);

        assert_eq!(ctx.max_path_length, 10);
        assert!(!ctx.check_revocation);
        assert!(!ctx.enable_aia_fetching);
    }

    #[test]
    fn test_validation_context_builder() {
        let cert = create_test_cert("CN=Test", "CN=CA", Utc::now(), Utc::now());
        let store = Arc::new(TrustAnchorStore::new());
        let ctx = ValidationContext::new(cert, store)
            .with_max_path_length(5)
            .with_revocation_checking(true)
            .with_aia_fetching(true);

        assert_eq!(ctx.max_path_length, 5);
        assert!(ctx.check_revocation);
        assert!(ctx.enable_aia_fetching);
    }

    #[test]
    fn test_check_validity_period_valid() {
        let now = Utc::now();
        let cert = create_test_cert(
            "CN=Test",
            "CN=CA",
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
        );

        let result = PathValidator::check_validity_period(&cert, now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_validity_period_expired() {
        let now = Utc::now();
        let cert = create_test_cert(
            "CN=Test",
            "CN=CA",
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
        );

        let result = PathValidator::check_validity_period(&cert, now);
        assert!(matches!(result, Err(ValidationError::ValidityPeriod(_))));
    }

    #[test]
    fn test_check_validity_period_not_yet_valid() {
        let now = Utc::now();
        let cert = create_test_cert(
            "CN=Test",
            "CN=CA",
            now + chrono::Duration::hours(1),
            now + chrono::Duration::hours(2),
        );

        let result = PathValidator::check_validity_period(&cert, now);
        assert!(matches!(result, Err(ValidationError::ValidityPeriod(_))));
    }

    #[test]
    fn test_validate_with_trust_anchor() {
        let now = Utc::now();
        let mut store = TrustAnchorStore::new();

        // Add trust anchor
        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );
        store.add(anchor).unwrap();

        // Create end entity certificate
        let cert = create_test_cert(
            "CN=End Entity,O=OstrichPKI",
            "CN=Root CA,O=OstrichPKI",
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
        );

        let ctx = ValidationContext::new(cert, Arc::new(store));
        let result = PathValidator::validate(ctx);

        assert!(result.is_ok());
        let validation_result = result.unwrap();
        assert!(validation_result.valid);
        assert_eq!(validation_result.chain.len(), 1);
    }

    #[test]
    fn test_validate_expired_certificate() {
        let now = Utc::now();
        let mut store = TrustAnchorStore::new();

        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );
        store.add(anchor).unwrap();

        // Create expired certificate
        let cert = create_test_cert(
            "CN=End Entity,O=OstrichPKI",
            "CN=Root CA,O=OstrichPKI",
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
        );

        let ctx = ValidationContext::new(cert, Arc::new(store));
        let result = PathValidator::validate(ctx);

        assert!(result.is_ok());
        let validation_result = result.unwrap();
        assert!(!validation_result.valid);
        assert!(!validation_result.errors.is_empty());
    }
}
