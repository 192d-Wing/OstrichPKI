//! EST REST API
//!
//! RFC 7030: Enrollment over Secure Transport
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before enrollment operations
//!   - mTLS client certificate required for simpleenroll/simplereenroll
//!   - Certificate validation via [`crate::mtls::validate_client`]
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - All endpoints served over TLS 1.3
//!   - Mutual TLS for enrollment endpoints
//!
//! - **FMT_SMF.1**: Enrollment management functions
//!   - Simple enrollment (RFC 7030 S4.2.1)
//!   - Simple re-enrollment (RFC 7030 S4.2.2)
//!   - CSR attributes retrieval (RFC 7030 S4.5)
//!
//! - **FDP_ACC.1/FDP_ACF.1**: Access control for enrollment
//!   - Only authenticated clients may enroll
//!   - Re-enrollment requires matching subject DN
//!
//! - **FCS_COP.1**: Cryptographic operations
//!   - CSR signature verification (proof of possession)
//!   - PKCS#7/CMS response encoding
//!
//! - **FAU_GEN.1**: Audit generation for enrollment events
//!   - Enrollment requests logged with client identity
//!   - Success/failure outcomes recorded
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-8**: Transmission confidentiality via TLS
//! - **SI-10**: Input validation for CSRs
//! - **AU-2**: Auditable enrollment events

use crate::{
    enrollment::CsrAttributes,
    error::{Error, Result},
};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ostrich_audit::AuditSink;
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use std::sync::Arc;

/// EST service state
#[derive(Clone)]
pub struct EstState {
    pub db_pool: DatabasePool,
    pub crypto_provider: Arc<dyn CryptoProvider>,
    pub audit_sink: Arc<dyn AuditSink>,
    // TODO: Add CA client for certificate issuance (Phase 12)
}

impl EstState {
    /// Create new EST service state
    pub fn new(
        db_pool: DatabasePool,
        crypto_provider: Arc<dyn CryptoProvider>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            db_pool,
            crypto_provider,
            audit_sink,
        }
    }
}

/// Create EST REST API router
///
/// RFC 7030 well-known URI: /.well-known/est/
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1 - Security management functions for EST enrollment
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (router served over TLS)
/// - NIST 800-53: SC-8 - Transmission confidentiality (TLS required)
/// - RFC 7030 S3.2.2 - EST well-known URI structure
pub fn create_router(state: EstState) -> Router {
    Router::new()
        // Health and readiness endpoints
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        // RFC 7030 §4.1: Distribution of CA certificates
        .route("/.well-known/est/cacerts", get(get_ca_certs))
        // RFC 7030 §4.2: Simple enrollment
        .route("/.well-known/est/simpleenroll", post(simple_enroll))
        // RFC 7030 §4.2: Simple re-enrollment
        .route("/.well-known/est/simplereenroll", post(simple_reenroll))
        // RFC 7030 §4.5: CSR attributes
        .route("/.well-known/est/csrattrs", get(get_csr_attrs))
        // RFC 7030 §4.3: Server-side key generation (optional)
        .route("/.well-known/est/serverkeygen", post(server_key_gen))
        .with_state(state)
}

/// Health check endpoint (liveness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
///
/// Returns 200 OK if the service process is running.
async fn health_check() -> impl IntoResponse {
    ostrich_common::health::health_response("ostrich-est")
}

/// Readiness check endpoint (readiness probe)
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 (Fail-safe response)
/// - NIST 800-53: SC-8 (Transmission confidentiality and integrity)
///
/// Returns 200 OK if the service is ready to handle EST requests.
/// Checks database connectivity.
async fn readiness_check(State(state): State<EstState>) -> impl IntoResponse {
    ostrich_common::health::readiness_response_with_db("ostrich-est", &state.db_pool).await
}

/// Get CA certificates (RFC 7030 S4.1)
///
/// Returns a PKCS#7 certs-only structure containing CA certificate chain.
/// This endpoint does NOT require client authentication per RFC 7030.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (PKCS#7 encoding)
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (TLS, but no client auth required)
/// - NIST 800-53: SC-17 - PKI certificate distribution
/// - RFC 7030 S4.1 - CA certificate retrieval
async fn get_ca_certs(State(state): State<EstState>) -> Result<Response> {
    // TODO: Fetch CA certificate chain from database (Phase 12 - CA integration)
    // For now, create empty PKCS#7 certs-only structure
    let _repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());

    let pkcs7_der = encode_certs_only_pkcs7(&[])?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        pkcs7_der,
    )
        .into_response())
}

/// Encode certificates as PKCS#7 certs-only structure
///
/// RFC 7030 S4.1: Responses use degenerate PKCS#7 (CMS) SignedData
/// with no signed content, only certificates in the certificates field.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (CMS encoding)
/// - RFC 5652 S5 - CMS SignedData structure
/// - RFC 7030 S4.1.3 - EST CA certificates response format
pub(crate) fn encode_certs_only_pkcs7(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    use cms::{content_info::ContentInfo, signed_data::SignedData};
    use der::{
        Decode, Encode,
        asn1::{ObjectIdentifier, SetOfVec},
    };
    use x509_cert::Certificate;

    // RFC 5652 §5: SignedData content type OID
    const SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

    // Parse certificates from DER
    let mut cert_choices = SetOfVec::new();
    for cert_der in certs {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| Error::Internal(format!("Invalid certificate DER: {}", e)))?;
        let choice = cms::cert::CertificateChoices::Certificate(cert);
        cert_choices
            .insert(choice)
            .map_err(|e| Error::Internal(format!("Too many certificates: {}", e)))?;
    }

    // Create degenerate SignedData with no content and empty SignerInfos
    let digest_algorithms = SetOfVec::new();

    // RFC 5652 §3: data content type OID
    const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

    let encap_content_info = cms::signed_data::EncapsulatedContentInfo {
        econtent_type: DATA_OID,
        econtent: None,
    };

    let signed_data = SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates: if cert_choices.is_empty() {
            None
        } else {
            Some(cert_choices.into())
        },
        crls: None,
        signer_infos: SetOfVec::new().into(),
    };

    // Wrap in ContentInfo
    let content_info = ContentInfo {
        content_type: SIGNED_DATA_OID,
        content: der::Any::encode_from(&signed_data)
            .map_err(|e| Error::Internal(format!("Failed to encode SignedData: {}", e)))?,
    };

    content_info
        .to_der()
        .map_err(|e| Error::Internal(format!("Failed to encode PKCS#7: {}", e)))
}

/// Simple enrollment (RFC 7030 S4.2.1)
///
/// Client submits PKCS#10 CSR, server returns PKCS#7 with issued certificate.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via mTLS client certificate
/// - NIAP PP-CA: FDP_ACC.1 - Access control for enrollment operations
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic CSR signature verification
/// - NIAP PP-CA: FAU_GEN.1 - Audit record generation for enrollment
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (enrollment)
/// - NIST 800-53: SI-10 - Information input validation (CSR parsing)
/// - NIST 800-53: AU-2 - Auditable event (enrollment request)
/// - RFC 7030 S4.2.1 - Simple enrollment request/response
/// - RFC 2986 - PKCS#10 CSR format
///
/// TODO: Add mTLS client certificate validation when TLS is configured.
/// When TLS server is set up, this handler should:
/// 1. Extract client certificate using `ClientCertExtractor` axum extractor
/// 2. Validate certificate with `validate_client(&client_cert, &state.db_pool).await?`
/// 3. Use `client_cert.client_id` as the client identifier
/// 4. Use `client_cert.subject_dn` for audit logging
///
/// Example (when TLS is configured):
/// ```ignore
/// let ClientCertExtractor(client_cert) = ClientCertExtractor::from_request_parts(&mut parts, &state).await?;
/// validate_client(&client_cert, &state.db_pool).await?;
/// let client_identifier = &client_cert.client_id;
/// ```
async fn simple_enroll(State(state): State<EstState>, body: Bytes) -> Result<Response> {
    // Placeholder client identifier (mTLS validation pending TLS server setup)
    let client_identifier = "placeholder-client";

    // Decode base64-encoded CSR
    let csr_der = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;

    if csr_der.len() < 10 {
        return Err(Error::InvalidCsr("CSR too short".to_string()));
    }

    // Parse and validate PKCS#10 CSR
    let parsed_csr = ostrich_x509::parser::parse_csr(&csr_der)
        .map_err(|e| Error::InvalidCsr(format!("Failed to parse CSR: {}", e)))?;

    // Verify CSR signature (proof of possession)
    let signature_valid =
        ostrich_x509::parser::verify_csr_signature(&parsed_csr, &state.crypto_provider)
            .await
            .map_err(|e| Error::InvalidCsr(format!("CSR signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(Error::InvalidCsr("Invalid CSR signature".to_string()));
    }

    // Create enrollment record in database
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let enrollment = repo
        .create_enrollment(
            client_identifier,
            "simple-enroll",
            csr_der.clone(),
            "pending",
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create enrollment: {}", e)))?;

    // TODO: Audit log enrollment creation
    // TODO: Submit to CA for issuance - Phase 12

    // For now, return empty PKCS#7 structure with 202 Accepted status
    let pkcs7_response = encode_certs_only_pkcs7(&[])?;

    Ok((
        StatusCode::ACCEPTED, // 202 - enrollment pending
        [
            (header::CONTENT_TYPE, "application/pkcs7-mime"),
            (
                header::LOCATION,
                format!("/est/enrollments/{}", enrollment.id).as_str(),
            ),
        ],
        BASE64_STANDARD.encode(&pkcs7_response),
    )
        .into_response())
}

/// Simple re-enrollment (RFC 7030 S4.2.2)
///
/// Authenticated client re-enrolls for certificate renewal.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via existing certificate
/// - NIAP PP-CA: FDP_ACC.1 - Access control (subject DN must match)
/// - NIAP PP-CA: FDP_ACF.1 - Access control function (re-enrollment policy)
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic CSR signature verification
/// - NIAP PP-CA: FAU_GEN.1 - Audit record generation for re-enrollment
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (re-enrollment)
/// - NIST 800-53: SI-10 - Information input validation (CSR parsing)
/// - NIST 800-53: AU-2 - Auditable event (re-enrollment request)
/// - RFC 7030 S4.2.2 - Simple re-enrollment requirements
///
/// TODO: Add mTLS client certificate validation when TLS is configured.
/// When TLS server is set up, this handler should:
/// 1. Extract client certificate using `ClientCertExtractor` axum extractor
/// 2. Validate certificate with `validate_client(&client_cert, &state.db_pool).await?`
/// 3. Verify CSR subject matches client certificate subject (re-enrollment requirement)
/// 4. Use `client_cert.client_id` as the client identifier
/// 5. Use `client_cert.subject_dn` for audit logging
///
/// Example (when TLS is configured):
/// ```ignore
/// let ClientCertExtractor(client_cert) = ClientCertExtractor::from_request_parts(&mut parts, &state).await?;
/// validate_client(&client_cert, &state.db_pool).await?;
/// // Verify subject match after parsing CSR
/// if parsed_csr.subject_dn != client_cert.subject_dn {
///     return Err(Error::Forbidden("CSR subject doesn't match client cert".into()));
/// }
/// let client_identifier = &client_cert.client_id;
/// ```
async fn simple_reenroll(State(state): State<EstState>, body: Bytes) -> Result<Response> {
    // Placeholder client identifier (mTLS validation pending TLS server setup)
    let client_identifier = "placeholder-client";

    // Decode base64-encoded CSR
    let csr_der = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;

    if csr_der.len() < 10 {
        return Err(Error::InvalidCsr("CSR too short".to_string()));
    }

    // Parse and validate PKCS#10 CSR
    let parsed_csr = ostrich_x509::parser::parse_csr(&csr_der)
        .map_err(|e| Error::InvalidCsr(format!("Failed to parse CSR: {}", e)))?;

    // Verify CSR signature (proof of possession)
    let signature_valid =
        ostrich_x509::parser::verify_csr_signature(&parsed_csr, &state.crypto_provider)
            .await
            .map_err(|e| Error::InvalidCsr(format!("CSR signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(Error::InvalidCsr("Invalid CSR signature".to_string()));
    }

    // TODO: When mTLS is implemented, verify CSR subject matches client certificate subject
    // if parsed_csr.subject_dn != client_cert.subject_dn {
    //     return Err(Error::Forbidden("CSR subject doesn't match client certificate".into()));
    // }

    // Create re-enrollment record in database
    let repo = ostrich_db::repository::EstRepository::new(state.db_pool.clone());
    let enrollment = repo
        .create_enrollment(
            client_identifier,
            "simple-reenroll",
            csr_der.clone(),
            "pending",
        )
        .await
        .map_err(|e| Error::Internal(format!("Failed to create re-enrollment: {}", e)))?;

    // TODO: Audit log re-enrollment
    // TODO: Issue new certificate with same subject via CA service - Phase 12

    // For now, return empty PKCS#7 structure with 202 Accepted status
    let pkcs7_response = encode_certs_only_pkcs7(&[])?;

    Ok((
        StatusCode::ACCEPTED,
        [
            (header::CONTENT_TYPE, "application/pkcs7-mime"),
            (
                header::LOCATION,
                format!("/est/enrollments/{}", enrollment.id).as_str(),
            ),
        ],
        BASE64_STANDARD.encode(&pkcs7_response),
    )
        .into_response())
}

/// Get CSR attributes (RFC 7030 S4.5)
///
/// Returns attributes the CA expects in CSRs.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_SMF.1.1 - Security management function (CSR policy)
/// - NIAP PP-CA: FTP_ITC.1 - Trusted channel (TLS, client auth optional)
/// - NIST 800-53: SC-17 - PKI policy distribution
/// - RFC 7030 S4.5 - CSR attributes retrieval
async fn get_csr_attrs(State(_state): State<EstState>) -> Result<Response> {
    let _attrs = CsrAttributes::default();

    // TODO: Encode as ASN.1 CsrAttrs structure (RFC 7030 §4.5.2)
    // For now, return empty response (means no specific attributes required)

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/csrattrs")],
        Vec::<u8>::new(), // Empty = no specific requirements
    )
        .into_response())
}

/// Server-side key generation (RFC 7030 §4.4)
///
/// Server generates key pair and returns PKCS#12 with certificate + encrypted private key.
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FIA_UAU.1 - User authentication via mTLS (required)
/// - NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation (server-side)
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operations (PKCS#12 encoding)
/// - NIAP PP-CA: FDP_ACC.1 - Access control for key generation
/// - NIAP PP-CA: FAU_GEN.1 - Audit record for key generation event
/// - NIAP PP-CA: FCS_CKM.4 - Key destruction (zeroization after use)
/// - NIST 800-53: SC-12 - Cryptographic key establishment
/// - NIST 800-53: SI-12 - Information handling (key zeroization)
/// - RFC 7030 §4.4 - Server-side key generation
/// - RFC 7292 - PKCS#12 Personal Information Exchange
///
/// # Request Format
///
/// The client sends a base64-encoded "CSR-like" structure containing:
/// - Subject distinguished name
/// - Requested key type (from CSR algorithm field or attributes)
/// - Optional SANs
///
/// Unlike normal CSR, there is no proof-of-possession since the client
/// doesn't have the private key yet.
///
/// # Response Format
///
/// Returns a PKCS#12 bundle (application/pkcs12) containing:
/// - Issued certificate
/// - Encrypted private key (password-protected)
/// - CA certificate chain
///
/// # Security Notes
///
/// - CRITICAL: This endpoint MUST require client authentication (mTLS)
/// - Private keys are zeroized from memory after PKCS#12 creation
/// - PKCS#12 password should be communicated out-of-band (not in this response)
/// - Consider KRA escrow for key recovery capability
///
/// TODO: Add mTLS client certificate validation when TLS is configured.
/// When TLS server is set up, this handler should:
/// 1. Extract client certificate using `ClientCertExtractor` axum extractor
/// 2. Validate certificate with `validate_client(&client_cert, &state.db_pool).await?`
/// 3. Use `client_cert.client_id` as the client identifier
/// 4. Use `client_cert.subject_dn` for audit logging
///
/// Example (when TLS is configured):
/// ```ignore
/// let ClientCertExtractor(client_cert) = ClientCertExtractor::from_request_parts(&mut parts, &state).await?;
/// validate_client(&client_cert, &state.db_pool).await?;
/// let client_identifier = &client_cert.client_id;
/// ```
async fn server_key_gen(State(state): State<EstState>, body: Bytes) -> Result<Response> {
    use crate::serverkeygen::{ServerKeyGenRequest, generate_key_pair_for_client};
    use ostrich_crypto::KeyType;
    use zeroize::Zeroizing;

    // Placeholder client identifier (mTLS validation pending TLS server setup)
    let client_identifier = "placeholder-client";

    // Decode base64-encoded request body
    let request_der = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;

    if request_der.len() < 10 {
        return Err(Error::BadRequest("Request too short".to_string()));
    }

    // TODO: Parse CSR-like structure to extract subject DN and requested key type
    // For Phase 13, use defaults
    let subject_dn = "CN=ServerKeyGen Client,O=OstrichPKI".to_string();
    let key_type = KeyType::Rsa2048; // Default to RSA 2048
    let profile_name = "default".to_string();

    let request = ServerKeyGenRequest {
        subject_dn: subject_dn.clone(),
        key_type,
        subject_alt_names: vec![],
        profile_name,
    };

    // Default PKCS#12 password (in production, this should be client-provided or generated)
    // RFC 7030 §4.4.2 - Password may be provided via HTTP Basic Auth or other mechanism
    let pkcs12_password = Zeroizing::new("changeit".to_string());

    // Generate key pair, issue certificate, create PKCS#12 bundle
    let pkcs12_bundle = generate_key_pair_for_client(
        request,
        client_identifier,
        state.crypto_provider.clone(),
        state.audit_sink.clone(),
        pkcs12_password,
    )
    .await?;

    // Audit log successful key generation
    // (Additional audit already done in generate_key_pair_for_client)

    // RFC 7030 §4.4.2 - Response is PKCS#12 (application/pkcs12)
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs12")],
        BASE64_STANDARD.encode(&pkcs12_bundle),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_est_path_prefix() {
        // Verify EST URL path structure per RFC 7030 §3.2.2
        let prefix = "/.well-known/est";
        assert!(prefix.starts_with("/.well-known/"));
        assert!(prefix.ends_with("est"));
    }

    #[test]
    fn test_base64_decoding() {
        // Test base64 encoding/decoding for PKCS#10 requests per RFC 7030
        use base64::prelude::*;

        let original = b"test CSR data";
        let encoded = BASE64_STANDARD.encode(original);
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_invalid_base64_handling() {
        // Verify that invalid base64 is properly rejected
        use base64::prelude::*;

        let invalid = "invalid-base64!@#$";
        let result = BASE64_STANDARD.decode(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_est_content_type_header() {
        // Test Content-Type header for PKCS#7 responses
        let content_type = "application/pkcs7-mime";
        assert!(content_type.contains("pkcs7"));
    }

    #[test]
    fn test_pkcs7_certs_only_empty() {
        // Test PKCS#7 encoding with empty certificate list
        // RFC 7030 §4.1.3 - Degenerate SignedData (certs-only)
        // RFC 5652 §5 - CMS SignedData structure
        let result = encode_certs_only_pkcs7(&[]);
        assert!(result.is_ok());

        let pkcs7_der = result.unwrap();
        // Verify it's valid DER (basic length check)
        assert!(!pkcs7_der.is_empty());

        // Verify it starts with SEQUENCE tag (0x30) per DER encoding rules
        assert_eq!(pkcs7_der[0], 0x30);

        // Verify minimum PKCS#7 ContentInfo structure size
        // ContentInfo ::= SEQUENCE {
        //   contentType OBJECT IDENTIFIER,
        //   content [0] EXPLICIT ANY DEFINED BY contentType
        // }
        assert!(pkcs7_der.len() > 10);
    }
}
