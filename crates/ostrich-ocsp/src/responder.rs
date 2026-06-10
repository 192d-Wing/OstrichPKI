//! OCSP Responder core logic
//!
//! This module implements the core OCSP responder functionality for processing
//! certificate status queries and generating signed OCSP responses.
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - **RFC 6960**: Online Certificate Status Protocol (OCSP)
//!   - Section 4.2.1: BasicOCSPResponse - Response data and signing
//!   - Section 4.2.2: Mandatory/Optional Extensions
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FCS_COP.1(1)**: Cryptographic Operation - Digital signature generation
//!   for OCSP responses using approved algorithms
//! - **FDP_OCSPG_EXT.1**: OCSP Response Generation - Producing properly
//!   formatted OCSP responses per RFC 6960
//! - **FDP_IFC.1**: Information Flow Control - Revocation status queries
//!   allowed without authentication (per PP line 358)
//! - **FAU_GEN.1**: Audit Data Generation - Logging all OCSP operations
//! - **FAU_GEN.2**: User Identity Association - Actor tracking in audit records
//! - **FPT_STM.1**: Reliable Time Stamps - thisUpdate/nextUpdate timestamps
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-2**: Auditable Events - All OCSP operations are logged
//! - **AU-3**: Content of Audit Records - Serial number, status, outcome
//! - **SC-13**: Cryptographic Protection - FIPS-validated signature algorithms

use crate::{
    Result,
    cache::{CacheKey, OcspCache},
    request::OcspRequest,
    response::{self, CertStatus, OcspResponse, SingleResponse},
};
use chrono::{Duration, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle, KeyType};
use ostrich_db::{DatabasePool, repository::CertificateRepository};
use std::sync::Arc;
use uuid::Uuid;

/// OCSP Responder configuration
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FCS_COP.1(1)**: `signing_key` references the real CA signing key in
///   the crypto provider; when absent the responder fails closed
///
/// # NIST 800-53 Rev 5 Controls
/// - **SC-12**: Key material stays in the crypto provider; only the
///   KeyHandle reference is held here
/// - **CM-6**: Secure default - no signing key means no signed responses
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Validity period for responses (in seconds)
    pub response_validity: i64,

    /// CA certificate ID
    pub ca_id: Uuid,

    /// OCSP signing key (the CA key, loaded from the database at bootstrap).
    /// `None` means signing is not configured: the responder fails closed.
    pub signing_key: Option<KeyHandle>,

    /// DER-encoded CA certificate. Used for the responderID (byName: the CA
    /// subject) and included in the certs field of BasicOCSPResponse.
    pub ca_certificate_der: Option<Vec<u8>>,

    /// Whether to include nonce in response
    pub include_nonce: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            response_validity: 3600, // 1 hour
            ca_id: Uuid::nil(),
            signing_key: None,
            ca_certificate_der: None,
            include_nonce: true,
        }
    }
}

/// Select the signature algorithm for the configured signing key.
///
/// Fails closed when no key is configured (NIST 800-53 CM-6: secure default).
///
/// The declared signatureAlgorithm in BasicOCSPResponse is
/// sha256WithRSAEncryption (1.2.840.113549.1.1.11), so RSA keys MUST be
/// signed with PKCS#1 v1.5 / SHA-256 - signing with a different scheme (e.g.
/// RSA-PSS) would make every response unverifiable (RFC 6960 §4.2.1; same
/// pattern as certificate issuance in crates/ostrich-ca/src/issuance.rs).
///
/// # COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (Cryptographic Protection) - declared and actual
///   algorithms must match
/// - NIAP PP-CA: FCS_COP.1(1) - approved signature algorithm selection
/// - RFC 6960 §4.3: responders MUST support sha256WithRSAEncryption
//
// POAM: algorithm agility - ECDSA/EdDSA/ML-DSA OCSP signing requires
// emitting the matching AlgorithmIdentifier in BasicOCSPResponse; until
// then non-RSA keys are rejected rather than producing broken responses.
pub(crate) fn signing_algorithm_for_key(signing_key: Option<&KeyHandle>) -> Result<Algorithm> {
    let key = signing_key
        .ok_or_else(|| crate::Error::SigningError("OCSP signing key not configured".to_string()))?;

    match key.key_type {
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => Ok(Algorithm::RsaPkcs1Sha256),
        other => Err(crate::Error::SigningError(format!(
            "OCSP signing with key type {:?} is not supported yet; only RSA keys \
             (sha256WithRSAEncryption) are implemented (POAM: algorithm agility)",
            other
        ))),
    }
}

/// OCSP Responder
///
/// The main OCSP responder component that processes certificate status requests
/// and generates signed responses.
///
/// # Performance Optimization
///
/// Uses in-memory LRU cache to reduce database load and improve response latency:
/// - Cache hit: <5ms response time (99th percentile)
/// - Cache miss: Database lookup + signing (typical: 20-50ms)
/// - Cache invalidation: Automatic on certificate revocation
///
/// # NIAP PP-CA v2.1 Compliance
/// - **FDP_OCSPG_EXT.1**: This struct implements the OCSP response generation
///   functionality required by the Protection Profile
/// - **FCS_COP.1(1)**: Uses CryptoProvider for response signing operations
/// - **FAU_GEN.1**: All operations emit audit events via AuditSink
pub struct OcspResponder {
    config: OcspConfig,
    #[allow(dead_code)]
    db: DatabasePool,
    crypto: Arc<dyn CryptoProvider>,
    audit: Arc<dyn AuditSink>,
    cert_repo: CertificateRepository,
    /// Response cache for performance optimization
    cache: OcspCache,
}

impl OcspResponder {
    /// Create a new OCSP responder
    pub fn new(
        config: OcspConfig,
        db: DatabasePool,
        crypto: Arc<dyn CryptoProvider>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        let cert_repo = CertificateRepository::new(db.clone());

        Self {
            config,
            db,
            crypto,
            audit,
            cert_repo,
            cache: OcspCache::default(), // 10,000 entry cache
        }
    }

    /// Create a new OCSP responder with custom cache size
    pub fn with_cache_size(
        config: OcspConfig,
        db: DatabasePool,
        crypto: Arc<dyn CryptoProvider>,
        audit: Arc<dyn AuditSink>,
        cache_size: usize,
    ) -> Self {
        let cert_repo = CertificateRepository::new(db.clone());

        Self {
            config,
            db,
            crypto,
            audit,
            cert_repo,
            cache: OcspCache::new(cache_size),
        }
    }

    /// Process an OCSP request
    ///
    /// Looks up the certificate status in the database and generates a signed
    /// OCSP response per RFC 6960.
    ///
    /// # Performance Optimization
    ///
    /// Checks cache before database lookup:
    /// 1. Generate cache key from serial number + hash algorithm
    /// 2. Check cache for valid response
    /// 3. If cache hit: return cached response (< 5ms)
    /// 4. If cache miss: query database, generate response, cache result
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FDP_OCSPG_EXT.1**: Generates OCSP responses per RFC 6960
    /// - **FDP_IFC.1**: Allows unauthenticated status queries (per PP line 358)
    /// - **FAU_GEN.1**: Emits audit events for request processing
    /// - **FPT_STM.1**: Uses reliable timestamps for thisUpdate/nextUpdate
    ///
    /// # RFC 6960 Compliance
    /// - Section 4.2.1: Response format and signing
    /// - Section 2.2: Response status (good, revoked, unknown)
    pub async fn process_request(&self, request: OcspRequest) -> Result<OcspResponse> {
        // Cache key includes the request's hash algorithm: CertIDs computed
        // with different hash algorithms are distinct responses.
        let cache_key = CacheKey::new(
            request.serial_number.clone(),
            request.hash_algorithm.oid().to_string(),
        );

        // RFC 8954 §2.1: a response carrying a nonce must echo the nonce of
        // *this* request - cached (pre-produced) responses cannot satisfy
        // that, so requests with a nonce bypass the cache entirely.
        // NIST 800-53: SC-23 - replay protection takes precedence over caching.
        let cacheable = request.nonce.is_none() || !self.config.include_nonce;

        // Check cache for existing valid response
        if cacheable && let Some(cached_response) = self.cache.get(&cache_key).await {
            // Cache hit - return cached response
            let mut event = AuditEventBuilder::new(
                EventType::OcspProtocol,
                "ocsp-responder",
                "certificate",
                "cache_hit",
                EventOutcome::Success,
            )
            .with_details(serde_json::json!({
                "serial_number": hex::encode(&request.serial_number),
                "cache": "hit",
            }))
            .build();
            self.audit.record(&mut event).await.ok();

            return Ok(cached_response);
        }

        // Cache miss - log the request
        let mut event = AuditEventBuilder::new(
            EventType::OcspProtocol,
            "ocsp-responder",
            "certificate",
            "check_status",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "serial_number": hex::encode(&request.serial_number),
            "cache": "miss",
        }))
        .build();
        self.audit.record(&mut event).await.ok();

        // Look up certificate status
        let cert_opt = self
            .cert_repo
            .find_by_serial(&request.serial_number)
            .await?;

        let cert = match cert_opt {
            Some(c) => c,
            None => {
                // Certificate not found - return unknown status
                return self.create_unknown_response(request).await;
            }
        };

        // Create single response based on certificate status.
        // The CertID fields echo the request exactly (RFC 6960 §4.2.1).
        // Note: expired certificates still return "good" per OCSP spec.
        let cert_status = if cert.revoked {
            CertStatus::Revoked {
                revocation_time: cert.revocation_time.unwrap_or_else(Utc::now),
                revocation_reason: cert.revocation_reason.map(|r| r as u8),
            }
        } else {
            CertStatus::Good
        };

        let single_response = SingleResponse {
            serial_number: request.serial_number.clone(),
            issuer_name_hash: request.issuer_name_hash.clone(),
            issuer_key_hash: request.issuer_key_hash.clone(),
            hash_algorithm: request.hash_algorithm.oid().to_string(),
            cert_status,
            this_update: Utc::now(),
            next_update: Some(Utc::now() + Duration::seconds(self.config.response_validity)),
        };

        // Sign the response
        let response = self
            .sign_response(vec![single_response], request.nonce)
            .await?;

        // Cache the response for future queries (nonce'd responses are
        // request-specific and must not be served to other requesters)
        if cacheable {
            self.cache.insert(cache_key, response.clone()).await;
        }

        // Log successful response
        let mut event = AuditEventBuilder::new(
            EventType::OcspProtocol,
            "ocsp-responder",
            "certificate",
            "generate_response",
            EventOutcome::Success,
        )
        .build();
        self.audit.record(&mut event).await.ok();

        Ok(response)
    }

    /// Invalidate cached responses for a certificate
    ///
    /// Should be called when a certificate is revoked to ensure updated status
    /// is returned on next OCSP query.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FMT_MSA.1.2**: Security attribute changes (revocation) invalidate cache
    /// - **FDP_OCSPG_EXT.1**: Ensures fresh revocation status is returned
    ///
    /// # RFC 6960 Compliance
    /// - Section 2.7: OCSP responses must reflect current certificate status
    pub async fn invalidate_cache(&self, serial_number: &[u8]) {
        self.cache.invalidate(serial_number).await;
    }

    /// Get cache statistics
    ///
    /// Returns (total_entries, valid_entries) for monitoring and diagnostics.
    pub async fn cache_stats(&self) -> (usize, usize) {
        self.cache.stats().await
    }

    /// Create an "unknown" status response
    async fn create_unknown_response(&self, request: OcspRequest) -> Result<OcspResponse> {
        let single_response = SingleResponse {
            serial_number: request.serial_number,
            issuer_name_hash: request.issuer_name_hash,
            issuer_key_hash: request.issuer_key_hash,
            hash_algorithm: request.hash_algorithm.oid().to_string(),
            cert_status: CertStatus::Unknown,
            this_update: Utc::now(),
            next_update: None,
        };

        self.sign_response(vec![single_response], request.nonce)
            .await
    }

    /// Sign an OCSP response
    ///
    /// Encodes the to-be-signed ResponseData exactly once, signs those bytes
    /// with the configured CA key, and stores the same bytes for verbatim
    /// embedding in the BasicOCSPResponse - the signed bytes and the emitted
    /// bytes are guaranteed identical.
    ///
    /// Fails closed when no signing key or CA certificate is configured.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    /// - **FCS_COP.1(1)**: Cryptographic signature operation using approved
    ///   algorithms (RSA PKCS#1 v1.5 with SHA-256)
    /// - **FDP_OCSPG_EXT.1**: Signed OCSP response generation
    /// - **FCO_NRO_EXT.2**: Proof of origin via digital signature
    /// - **FPT_STM.1**: producedAt from reliable time source
    ///
    /// # FIPS Compliance
    /// - FIPS 186-5: RSA signature algorithm
    ///
    /// # NIST 800-53 Rev 5 Controls
    /// - **SC-13**: Declared signatureAlgorithm matches the actual scheme
    /// - **AU-10**: Non-repudiation via CA signature
    ///
    /// # RFC 6960 Section 4.2.1
    /// BasicOCSPResponse ::= SEQUENCE {
    ///    tbsResponseData      ResponseData,
    ///    signatureAlgorithm   AlgorithmIdentifier,
    ///    signature            BIT STRING,
    ///    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    async fn sign_response(
        &self,
        responses: Vec<SingleResponse>,
        nonce: Option<Vec<u8>>,
    ) -> Result<OcspResponse> {
        // Fail closed: no signing key means no responses (NIST 800-53 CM-6)
        let algorithm = signing_algorithm_for_key(self.config.signing_key.as_ref())?;
        let key_handle = self
            .config
            .signing_key
            .as_ref()
            .expect("checked by signing_algorithm_for_key");

        let ca_cert_der = self.config.ca_certificate_der.as_deref().ok_or_else(|| {
            crate::Error::SigningError("OCSP responder CA certificate not configured".to_string())
        })?;

        // ResponderID byName: the CA certificate's subject Name, embedded as
        // raw DER bytes (RFC 6960 §4.2.1 - byName [1] Name)
        let (_, ca_cert) = x509_parser::parse_x509_certificate(ca_cert_der).map_err(|e| {
            crate::Error::SigningError(format!("Failed to parse CA certificate: {}", e))
        })?;
        let responder_name_der = ca_cert.subject().as_raw().to_vec();

        let nonce = if self.config.include_nonce {
            nonce
        } else {
            None
        };

        // Encode the TBS once - these exact bytes are signed and emitted
        let tbs_der = response::encode_tbs_response_data(
            &responder_name_der,
            Utc::now(),
            &responses,
            nonce.as_deref(),
        )?;

        let signature = self
            .crypto
            .sign(key_handle, algorithm, &tbs_der)
            .await
            .map_err(|e| {
                crate::Error::SigningError(format!("Failed to sign OCSP response: {}", e))
            })?;

        Ok(OcspResponse::successful(
            responses,
            tbs_der,
            signature,
            ca_cert_der.to_vec(),
            nonce,
        ))
    }

    /// Get OCSP responder configuration
    pub fn config(&self) -> &OcspConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_default() {
        let config = OcspConfig::default();
        assert_eq!(config.response_validity, 3600);
        assert!(config.include_nonce);
        // Secure defaults: signing not configured -> responder fails closed
        assert!(config.signing_key.is_none());
        assert!(config.ca_certificate_der.is_none());
    }

    /// NIST 800-53 CM-6 - fail closed when no signing key is configured
    #[test]
    fn test_signing_fails_closed_without_key() {
        let result = signing_algorithm_for_key(None);
        match result {
            Err(crate::Error::SigningError(msg)) => {
                assert!(
                    msg.contains("not configured"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected SigningError, got {:?}", other.map(|_| ())),
        }
    }

    /// RFC 6960 §4.2.1 - actual signing scheme must match the declared
    /// sha256WithRSAEncryption AlgorithmIdentifier
    #[test]
    fn test_rsa_keys_use_pkcs1_sha256() {
        for key_type in [KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096] {
            let key = KeyHandle::new(
                ostrich_crypto::key::ProviderId::Software,
                vec![1, 2, 3],
                key_type,
                Algorithm::RsaPkcs1Sha256,
                "ocsp-test".to_string(),
            );
            assert_eq!(
                signing_algorithm_for_key(Some(&key)).unwrap(),
                Algorithm::RsaPkcs1Sha256
            );
        }
    }

    /// POAM: algorithm agility - non-RSA keys are rejected rather than
    /// producing responses whose declared and actual algorithms differ
    #[test]
    fn test_non_rsa_keys_rejected() {
        let key = KeyHandle::new(
            ostrich_crypto::key::ProviderId::Software,
            vec![1, 2, 3],
            KeyType::EcP256,
            Algorithm::EcdsaP256Sha256,
            "ocsp-test".to_string(),
        );
        assert!(matches!(
            signing_algorithm_for_key(Some(&key)),
            Err(crate::Error::SigningError(_))
        ));
    }
}
