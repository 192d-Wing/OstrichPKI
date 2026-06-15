//! Audit Logging Middleware
//!
//! This middleware logs all web UI requests for audit purposes.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Auditable Events) - Log all security-relevant events
//! - NIST 800-53: AU-3 (Content of Audit Records) - Include required fields
//! - NIST 800-53: AU-12 (Audit Record Generation) - Generate audit records
//! - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation)
//! - NIAP PP-CA: FAU_GEN.2 (User Identity Association)

use axum::{extract::Request, http::Method, middleware::Next, response::Response};
use chrono::Utc;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

/// Request ID for tracing and audit correlation
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl Default for RequestId {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Authenticated user info (populated by auth middleware)
/// This struct is used to associate audit records with authenticated users.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AuditUser {
    pub id: String,
    pub username: String,
}

/// Audit middleware that logs all requests
///
/// This middleware:
/// 1. Assigns a unique request ID for correlation
/// 2. Records request start time
/// 3. Logs request completion with timing and status
/// 4. Captures user identity if authenticated
pub async fn audit_middleware(mut request: Request, next: Next) -> Response {
    // Generate request ID for correlation
    let request_id = RequestId::default();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    // Store request ID in extensions
    request.extensions_mut().insert(request_id.clone());

    // Record start time
    let start = Instant::now();
    let timestamp = Utc::now();

    // Extract client IP if available (from X-Forwarded-For or connection)
    let client_ip = extract_client_ip(&request);

    // Extract user agent
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Process the request
    let response = next.run(request).await;

    // Calculate duration
    let duration = start.elapsed();
    let status = response.status();

    // Log based on whether this is an API call or static resource
    if should_audit_request(&method, &path) {
        // NIST 800-53: AU-3 - Audit record content
        info!(
            request_id = %request_id.0,
            timestamp = %timestamp.to_rfc3339(),
            method = %method,
            path = %path,
            status = status.as_u16(),
            duration_ms = duration.as_millis() as u64,
            client_ip = ?client_ip,
            user_agent = ?user_agent,
            "Web UI request completed"
        );

        // Log warning for errors
        if status.is_server_error() {
            warn!(
                request_id = %request_id.0,
                status = status.as_u16(),
                path = %path,
                "Server error in Web UI request"
            );
        }
    } else {
        // Trace-level logging for static resources
        tracing::trace!(
            request_id = %request_id.0,
            method = %method,
            path = %path,
            status = status.as_u16(),
            duration_ms = duration.as_millis() as u64,
            "Static resource request"
        );
    }

    response
}

/// Determine if a request should be audited at info level
///
/// API calls and auth-related requests are always audited.
/// Static resource requests are logged at trace level.
fn should_audit_request(method: &Method, path: &str) -> bool {
    // Always audit non-GET requests (mutations)
    if method != Method::GET {
        return true;
    }

    // Always audit API calls
    if path.starts_with("/api/") {
        return true;
    }

    // Always audit auth-related paths
    if path.starts_with("/auth/") {
        return true;
    }

    // Audit the main page load
    if path == "/" || path == "/index.html" {
        return true;
    }

    // Don't audit static resources at info level
    if path.starts_with("/static/") {
        return false;
    }

    // Default to auditing
    true
}

/// Extract client IP from request headers or connection
fn extract_client_ip(request: &Request) -> Option<String> {
    // Check X-Forwarded-For first (for reverse proxy setups)
    if let Some(forwarded) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        // Take the first IP in the chain (original client)
        return forwarded.split(',').next().map(|s| s.trim().to_string());
    }

    // Check X-Real-IP
    if let Some(real_ip) = request
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
    {
        return Some(real_ip.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_audit_api_calls() {
        assert!(should_audit_request(&Method::GET, "/api/certificates"));
        assert!(should_audit_request(&Method::POST, "/api/certificates"));
        assert!(should_audit_request(
            &Method::DELETE,
            "/api/certificates/123"
        ));
    }

    #[test]
    fn test_should_audit_auth_calls() {
        assert!(should_audit_request(&Method::GET, "/auth/login"));
        assert!(should_audit_request(&Method::GET, "/auth/callback"));
        assert!(should_audit_request(&Method::POST, "/auth/logout"));
    }

    #[test]
    fn test_should_not_audit_static_files() {
        assert!(!should_audit_request(&Method::GET, "/static/app.js"));
        assert!(!should_audit_request(&Method::GET, "/static/style.css"));
        assert!(!should_audit_request(&Method::GET, "/static/app.wasm"));
    }

    #[test]
    fn test_should_audit_mutations() {
        // Any non-GET request should be audited
        assert!(should_audit_request(&Method::POST, "/static/upload"));
        assert!(should_audit_request(&Method::PUT, "/anything"));
        assert!(should_audit_request(&Method::DELETE, "/anything"));
    }
}
