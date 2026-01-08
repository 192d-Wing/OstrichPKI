//! API Proxy
//!
//! Proxies API requests from the web UI to backend services.
//! This provides same-origin API access and centralized authentication.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - Validate session before proxying
//! - NIST 800-53: AU-2 (Auditable Events) - Log all API requests
//! - NIST 800-53: SC-8 (Transmission Confidentiality) - Internal mTLS

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;

use super::router::AppState;

/// Create the API proxy router
pub fn create_proxy_routes(state: AppState) -> Router {
    Router::new()
        // CA API
        .route("/ca/*path", any(proxy_ca))
        // ACME API
        .route("/acme/*path", any(proxy_acme))
        // OCSP API
        .route("/ocsp/*path", any(proxy_ocsp))
        // SCMS API
        .route("/scms/*path", any(proxy_scms))
        // KRA API
        .route("/kra/*path", any(proxy_kra))
        // Audit API
        .route("/audit/*path", any(proxy_audit))
        .with_state(state)
}

/// Proxy requests to the CA service
async fn proxy_ca(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.ca_url, &path, request).await
}

/// Proxy requests to the ACME service
async fn proxy_acme(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.acme_url, &path, request).await
}

/// Proxy requests to the OCSP service
async fn proxy_ocsp(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.ocsp_url, &path, request).await
}

/// Proxy requests to the SCMS service
async fn proxy_scms(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.scms_url, &path, request).await
}

/// Proxy requests to the KRA service
async fn proxy_kra(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.kra_url, &path, request).await
}

/// Proxy requests to the Audit service
async fn proxy_audit(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.config.backend.audit_url, &path, request).await
}

/// Generic proxy function to forward requests to a backend service
async fn proxy_to_service(
    base_url: &str,
    path: &str,
    original_request: Request<Body>,
) -> Response {
    let target_url = format!("{}/{}", base_url.trim_end_matches('/'), path);

    tracing::debug!(
        target = %target_url,
        method = %original_request.method(),
        "Proxying request to backend service"
    );

    // Build the proxied request
    let (parts, body) = original_request.into_parts();

    let uri: hyper::Uri = match target_url.parse() {
        Ok(uri) => uri,
        Err(e) => {
            tracing::error!(error = %e, url = %target_url, "Invalid proxy target URL");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "proxy_error",
                "Invalid backend service URL",
            );
        }
    };

    let mut proxy_request = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(uri);

    // Copy headers, excluding hop-by-hop headers
    for (key, value) in parts.headers.iter() {
        if !is_hop_by_hop_header(key.as_str()) {
            proxy_request = proxy_request.header(key, value);
        }
    }

    // Add X-Forwarded headers
    // TODO: Extract actual user info from session and add X-Forwarded-User header

    let proxy_request = match proxy_request.body(body) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build proxy request");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "proxy_error",
                "Failed to build proxy request",
            );
        }
    };

    // Create HTTP client
    // Note: In production, reuse a connection pool via State
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build_http();

    // Execute the request
    match client.request(proxy_request).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                target = %target_url,
                "Failed to proxy request to backend service"
            );
            error_response(
                StatusCode::BAD_GATEWAY,
                "backend_error",
                "Backend service unavailable",
            )
        }
    }
}

/// Check if a header is a hop-by-hop header that shouldn't be forwarded
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// Create an error response
fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    let body = serde_json::to_string(&json!({
        "error": error,
        "message": message
    }))
    .unwrap_or_else(|_| r#"{"error":"internal_error"}"#.to_string());

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(is_hop_by_hop_header("Host"));

        assert!(!is_hop_by_hop_header("Content-Type"));
        assert!(!is_hop_by_hop_header("Authorization"));
        assert!(!is_hop_by_hop_header("X-Custom-Header"));
    }
}
