//! EST REST API
//!
//! RFC 7030: Enrollment over Secure Transport

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
pub fn create_router(state: EstState) -> Router {
    Router::new()
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

/// Get CA certificates (RFC 7030 §4.1)
///
/// Returns a PKCS#7 certs-only structure containing CA certificate chain
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
/// RFC 7030 §4.1: Responses use degenerate PKCS#7 (CMS) SignedData
/// with no signed content, only certificates in the certificates field
fn encode_certs_only_pkcs7(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
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

/// Simple enrollment (RFC 7030 §4.2.1)
///
/// Client submits PKCS#10 CSR, server returns PKCS#7 with issued certificate
///
/// TODO: Add mTLS client certificate validation when TLS is configured.
/// When TLS server is set up, this handler should:
/// 1. Extract client certificate using `extract_client_cert_placeholder()`
/// 2. Validate certificate with `validate_client(&client_cert, &state.db_pool).await?`
/// 3. Use `client_cert.client_id` as the client identifier
/// 4. Use `client_cert.subject_dn` for audit logging
///
/// Example (when TLS is configured):
/// ```ignore
/// let client_cert = extract_client_cert_placeholder()?;
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

/// Simple re-enrollment (RFC 7030 §4.2.2)
///
/// Authenticated client re-enrolls for certificate renewal
///
/// TODO: Add mTLS client certificate validation when TLS is configured.
/// When TLS server is set up, this handler should:
/// 1. Extract client certificate using `extract_client_cert_placeholder()`
/// 2. Validate certificate with `validate_client(&client_cert, &state.db_pool).await?`
/// 3. Verify CSR subject matches client certificate subject (re-enrollment requirement)
/// 4. Use `client_cert.client_id` as the client identifier
/// 5. Use `client_cert.subject_dn` for audit logging
///
/// Example (when TLS is configured):
/// ```ignore
/// let client_cert = extract_client_cert_placeholder()?;
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

/// Get CSR attributes (RFC 7030 §4.5)
///
/// Returns attributes the CA expects in CSRs
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

/// Server-side key generation (RFC 7030 §4.3)
///
/// Server generates key pair and returns certificate + encrypted private key
async fn server_key_gen(State(_state): State<EstState>, _body: Bytes) -> Result<Response> {
    // TODO: Validate client certificate
    // TODO: Parse CSR (without private key, just subject info)
    // TODO: Generate key pair on server
    // TODO: Issue certificate
    // TODO: Encrypt private key for client
    // TODO: Return PKCS#7 with cert + encrypted private key

    // This is an optional feature, return 501 Not Implemented for now
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "Server-side key generation not implemented",
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_ca_certs() {
        let state = EstState::new();
        let response = get_ca_certs(State(state)).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_simple_enroll_invalid_base64() {
        let state = EstState::new();
        let body = Bytes::from("invalid-base64!@#$");
        let result = simple_enroll(State(state), body).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_csr_attrs() {
        let state = EstState::new();
        let response = get_csr_attrs(State(state)).await;
        assert!(response.is_ok());
    }
}
