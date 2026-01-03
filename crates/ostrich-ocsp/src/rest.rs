//! REST API for OCSP Responder
//!
//! RFC 6960 §A.1: OCSP over HTTP

use crate::{Error, OcspResponder, ResponseStatus, request::OcspRequest};
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::sync::Arc;

/// OCSP API state
pub struct OcspApiState {
    responder: Arc<OcspResponder>,
}

impl OcspApiState {
    /// Create new API state
    pub fn new(responder: Arc<OcspResponder>) -> Self {
        Self { responder }
    }
}

/// Create OCSP REST API router
pub fn create_router(responder: Arc<OcspResponder>) -> Router {
    let state = Arc::new(OcspApiState::new(responder));

    Router::new()
        .route("/", post(ocsp_post))
        .route("/", get(ocsp_get))
        .route("/health", get(health_check))
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "ostrich-ocsp"
    }))
}

/// OCSP POST request handler
///
/// RFC 6960 §A.1.1: POST method
async fn ocsp_post(State(state): State<Arc<OcspApiState>>, body: Bytes) -> Result<Response, Error> {
    // Parse OCSP request from DER
    let request = OcspRequest::from_der(&body)?;

    // Process request
    let response = state.responder.process_request(request).await?;

    // Encode response to DER
    let response_der = response
        .to_der()
        .map_err(|e| Error::InternalError(format!("Failed to encode response: {}", e)))?;

    // Return with OCSP response content type
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/ocsp-response")],
        response_der,
    )
        .into_response())
}

/// OCSP GET request handler
///
/// RFC 6960 §A.1.1: GET method with base64-encoded request
#[derive(Deserialize)]
struct OcspGetParams {
    #[serde(rename = "req")]
    request: String,
}

async fn ocsp_get(
    State(state): State<Arc<OcspApiState>>,
    Query(params): Query<OcspGetParams>,
) -> Result<Response, Error> {
    // Decode base64 request
    let request_der = BASE64_URL_SAFE_NO_PAD
        .decode(&params.request)
        .map_err(|_| Error::MalformedRequest)?;

    // Parse OCSP request
    let request = OcspRequest::from_der(&request_der)?;

    // Process request
    let response = state.responder.process_request(request).await?;

    // Encode response to DER
    let response_der = response
        .to_der()
        .map_err(|e| Error::InternalError(format!("Failed to encode response: {}", e)))?;

    // Return with OCSP response content type
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/ocsp-response")],
        response_der,
    )
        .into_response())
}

// Error conversion for Axum responses
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, ocsp_status) = match self {
            Error::InvalidRequest(_) | Error::MalformedRequest => {
                (StatusCode::BAD_REQUEST, ResponseStatus::MalformedRequest)
            }
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, ResponseStatus::Unauthorized),
            Error::InternalError(_)
            | Error::Database(_)
            | Error::Crypto(_)
            | Error::Common(_)
            | Error::DerError(_)
            | Error::SigningError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseStatus::InternalError,
            ),
            Error::CertificateNotFound => {
                // For certificate not found, we still return 200 with "unknown" status
                // This is handled in the responder
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ResponseStatus::InternalError,
                )
            }
        };

        // Create error response
        let error_response = crate::OcspResponse::error(ocsp_status);
        let response_der = error_response.to_der().unwrap_or_default();

        (
            status,
            [(header::CONTENT_TYPE, "application/ocsp-response")],
            response_der,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"test");
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded, b"test");
    }
}
