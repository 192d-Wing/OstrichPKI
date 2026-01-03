//! EST REST API
//!
//! RFC 7030: Enrollment over Secure Transport

use crate::{
    enrollment::{CsrAttributes, Enrollment},
    error::{Error, Result},
};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

/// EST service state
#[derive(Clone)]
pub struct EstState {
    // TODO: Add database pool, crypto provider, audit sink, CA client
}

impl EstState {
    /// Create new EST service state
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for EstState {
    fn default() -> Self {
        Self::new()
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
async fn get_ca_certs(State(_state): State<EstState>) -> Result<Response> {
    // TODO: Fetch CA certificate chain from database
    // TODO: Encode as PKCS#7 certs-only

    // Placeholder PKCS#7 structure
    let pkcs7_placeholder = vec![
        0x30, 0x82, // SEQUENCE
        0x01, 0x00, // length placeholder
    ];

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        pkcs7_placeholder,
    )
        .into_response())
}

/// Simple enrollment (RFC 7030 §4.2.1)
///
/// Client submits PKCS#10 CSR, server returns PKCS#7 with issued certificate
async fn simple_enroll(State(_state): State<EstState>, body: Bytes) -> Result<Response> {
    // TODO: Validate client certificate (mTLS)
    // TODO: Parse PKCS#10 CSR from body
    // TODO: Validate CSR signature
    // TODO: Submit to CA for issuance
    // TODO: Create enrollment record
    // TODO: Audit log

    // Decode base64-encoded CSR
    let csr_der = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;

    if csr_der.len() < 10 {
        return Err(Error::InvalidCsr("CSR too short".to_string()));
    }

    // Create enrollment record
    let _enrollment = Enrollment::new("client-unknown".to_string(), csr_der.clone());

    // Placeholder: Return PKCS#7 with certificate
    let pkcs7_response = vec![
        0x30, 0x82, // SEQUENCE
        0x02, 0x00, // length placeholder
    ];

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
        BASE64_STANDARD.encode(&pkcs7_response),
    )
        .into_response())
}

/// Simple re-enrollment (RFC 7030 §4.2.2)
///
/// Authenticated client re-enrolls for certificate renewal
async fn simple_reenroll(State(_state): State<EstState>, body: Bytes) -> Result<Response> {
    // TODO: Validate client certificate (mTLS required)
    // TODO: Verify client is authorized for re-enrollment
    // TODO: Parse PKCS#10 CSR
    // TODO: Issue new certificate with same subject
    // TODO: Audit log

    // Decode base64-encoded CSR
    let csr_der = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| Error::BadRequest(format!("Invalid base64: {}", e)))?;

    if csr_der.len() < 10 {
        return Err(Error::InvalidCsr("CSR too short".to_string()));
    }

    // Placeholder: Return PKCS#7 with renewed certificate
    let pkcs7_response = vec![
        0x30, 0x82, // SEQUENCE
        0x03, 0x00, // length placeholder
    ];

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pkcs7-mime")],
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
