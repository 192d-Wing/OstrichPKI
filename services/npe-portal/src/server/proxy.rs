//! Allowlisted API proxy.
//!
//! The NPE portal proxies ONLY the CA and EST services (identity-forwarded, RBAC
//! enforced by the backend) plus the public OCSP responder — and only the routes
//! the portal's menus need. This allowlist is the portal's security boundary:
//! even with a valid session, a client cannot reach admin-only services (audit,
//! KRA, user management beyond the CAA surface) through this proxy. The CA/EST
//! services independently enforce RBAC on the session's mapped NPE role; the OCSP
//! path is a public RFC 6960 responder and carries no forwarded identity.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement), SC-7 (Boundary Protection) - the
//!   allowlist (CA, EST, OCSP) is the enumerated portal→backend boundary
//! - NIST 800-53: AC-6 (Least Privilege) - the OCSP path forwards no NPE identity
//! - NIST 800-53: AU-2 (Auditable Events) - proxied requests are logged
//! - RFC 6960 - OCSP request/response passthrough to the responder

use axum::{
    Router,
    body::Body,
    extract::{Extension, Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::json;

use super::router::{AppState, HttpClient};
use super::session::SessionData;

/// Create the allowlisted API proxy router (CA + EST + public OCSP).
pub fn create_proxy_routes(state: AppState) -> Router {
    Router::new()
        .route("/ca/{*path}", any(proxy_ca))
        .route("/est/{*path}", any(proxy_est))
        // OCSP revocation-status checker (RFC 6960). The responder listens at its
        // root and is public; `/ocsp` forwards there. Read-only status data only.
        .route("/ocsp", any(proxy_ocsp))
        .with_state(state)
}

async fn proxy_ca(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.http_client, &state.config.backend.ca_url, &path, Some(&session), request).await
}

async fn proxy_est(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.http_client, &state.config.backend.est_url, &path, Some(&session), request).await
}

/// Forward an OCSP request to the responder's root (RFC 6960 over HTTP). The
/// NPE identity is NOT forwarded: OCSP is a public, no-auth protocol that does
/// not consume the X-Npe-* headers, so attaching the caller's CN/DN/roles would
/// be needless disclosure (least privilege / AC-6).
async fn proxy_ocsp(
    State(state): State<AppState>,
    request: Request<Body>,
) -> impl IntoResponse {
    proxy_to_service(&state.http_client, &state.config.backend.ocsp_url, "", None, request).await
}

/// Forward a request to a backend service, preserving the query string and
/// attaching the authenticated NPE identity so the backend can enforce RBAC.
async fn proxy_to_service(
    client: &HttpClient,
    base_url: &str,
    path: &str,
    session: Option<&SessionData>,
    original_request: Request<Body>,
) -> Response {
    let base = base_url.trim_end_matches('/');
    let target_url = match original_request.uri().query() {
        Some(query) => format!("{base}/{path}?{query}"),
        None => format!("{base}/{path}"),
    };

    tracing::debug!(
        target = %target_url,
        method = %original_request.method(),
        "Proxying NPE request to backend service"
    );

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

    // Copy headers, dropping hop-by-hop headers, any client Authorization (the
    // portal is the sole authority for the upstream credential), and any
    // client-supplied X-Npe-* identity headers — the latter MUST be stripped so
    // a caller cannot spoof the identity we attach below.
    for (key, value) in parts.headers.iter() {
        if is_stripped_inbound_header(key.as_str()) {
            continue;
        }
        proxy_request = proxy_request.header(key, value);
    }

    // Attach the authenticated NPE identity so the backend can enforce per-role
    // and own-scope RBAC (NIST AC-3). These are trusted because the portal
    // stripped any inbound X-Npe-* above and the proxy is the only ingress.
    // The backend MUST only accept these on the portal's mTLS channel. Omitted
    // for identity-agnostic backends (e.g. the public OCSP responder).
    if let Some(session) = session {
        use ostrich_common::auth::{
            HEADER_NPE_ROLES, HEADER_NPE_SESSION, HEADER_NPE_SUBJECT, HEADER_NPE_USER,
        };
        proxy_request = proxy_request
            .header(HEADER_NPE_USER, &session.common_name)
            .header(HEADER_NPE_SUBJECT, &session.subject_dn)
            .header(HEADER_NPE_ROLES, session.roles.join(","))
            .header(HEADER_NPE_SESSION, &session.id);
    }

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

    match client.request(proxy_request).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Err(e) => {
            tracing::error!(error = %e, target = %target_url, "Failed to proxy request");
            error_response(
                StatusCode::BAD_GATEWAY,
                "backend_error",
                "Backend service unavailable",
            )
        }
    }
}

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

/// Whether an inbound (client-supplied) header must be dropped before forwarding
/// to the backend. This is the portal's anti-spoofing boundary: hop-by-hop
/// headers, any client `Authorization` (the portal is the sole authority for the
/// upstream credential), and ALL `X-Npe-*` identity headers are stripped — the
/// proxy re-attaches the authenticated `X-Npe-*` identity itself, so a client can
/// never forge its identity or role by sending those headers (NIST 800-53 AC-3).
fn is_stripped_inbound_header(name: &str) -> bool {
    is_hop_by_hop_header(name)
        || name.eq_ignore_ascii_case("authorization")
        || name.to_ascii_lowercase().starts_with("x-npe-")
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    let body = serde_json::to_string(&json!({ "error": error, "message": message }))
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
        assert!(is_hop_by_hop_header("Host"));
        assert!(!is_hop_by_hop_header("Content-Type"));
    }

    /// Anti-spoofing boundary: a client must not be able to forge its identity or
    /// role by sending X-Npe-* / Authorization headers — they are stripped before
    /// the proxy forwards (and re-attaches the authenticated identity). Legitimate
    /// content headers pass through.
    #[test]
    fn inbound_identity_headers_are_stripped() {
        // Stripped regardless of case.
        for h in [
            "X-Npe-User",
            "x-npe-user",
            "X-Npe-Roles",
            "X-Npe-Subject",
            "X-Npe-Session",
            "Authorization",
            "authorization",
            "Connection",
            "Host",
        ] {
            assert!(is_stripped_inbound_header(h), "{h} must be stripped");
        }
        // Forwarded.
        for h in ["Content-Type", "Accept", "Content-Length", "X-Request-Id"] {
            assert!(!is_stripped_inbound_header(h), "{h} must pass through");
        }
    }
}
