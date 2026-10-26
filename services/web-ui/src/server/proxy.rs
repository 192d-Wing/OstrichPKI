//! API Proxy
//!
//! Proxies API requests from the web UI to backend services.
//! This provides same-origin API access and centralized authentication.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - The upstream credential is the
//!   session-bound backend token only: client-supplied `Authorization`,
//!   `Cookie` and `X-Npe-*` headers are stripped before forwarding. (Session
//!   validation itself is done by `require_session` in `middleware/session.rs`,
//!   layered in `router.rs`.)
//! - NIST 800-53: AU-2 (Event Logging) - Rejected (unsafe-path) proxy requests
//!   are logged as security events. (Per-request API logging is done by
//!   `audit_middleware` in `middleware/audit.rs`, layered in `router.rs`.)
//! - NIST 800-53: SC-8 (Transmission Confidentiality) - Internal mTLS
//! - NIST 800-53: SI-10 (Information Input Validation) - The backend path is
//!   taken from the raw (percent-encoded) request path and refused if it
//!   carries dot segments or encoded delimiters (see `validate_backend_path`)

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::json;

use super::backend_client::HttpClient;
use super::router::AppState;

/// Create the API proxy router
pub fn create_proxy_routes(state: AppState) -> Router {
    Router::new()
        // CA API
        .route("/ca/{*path}", any(proxy_ca))
        // ACME API
        .route("/acme/{*path}", any(proxy_acme))
        // OCSP API
        .route("/ocsp/{*path}", any(proxy_ocsp))
        // SCMS API
        .route("/scms/{*path}", any(proxy_scms))
        // KRA API
        .route("/kra/{*path}", any(proxy_kra))
        // Audit API
        .route("/audit/{*path}", any(proxy_audit))
        // EST API (RFC 7030)
        .route("/est/{*path}", any(proxy_est))
        .with_state(state)
}

/// Proxy requests to the EST service
async fn proxy_est(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.est_url,
        "est",
        request,
    )
    .await
}

/// Proxy requests to the CA service
async fn proxy_ca(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.ca_url,
        "ca",
        request,
    )
    .await
}

/// Proxy requests to the ACME service
async fn proxy_acme(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.acme_url,
        "acme",
        request,
    )
    .await
}

/// Proxy requests to the OCSP service
async fn proxy_ocsp(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.ocsp_url,
        "ocsp",
        request,
    )
    .await
}

/// Proxy requests to the SCMS service
async fn proxy_scms(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.scms_url,
        "scms",
        request,
    )
    .await
}

/// Proxy requests to the KRA service
async fn proxy_kra(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.kra_url,
        "kra",
        request,
    )
    .await
}

/// Proxy requests to the Audit service
async fn proxy_audit(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.ca_client,
        &state.config.backend.audit_url,
        "audit",
        request,
    )
    .await
}

/// Why a proxied request path was refused. The `reason()` strings are stable,
/// non-secret tokens suitable for the audit/security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRejection {
    /// The raw path does not start with `/{svc}/` (or `/api/{svc}/`).
    MissingServicePrefix,
    /// An empty segment (`//`, trailing `/`, or nothing after the prefix).
    EmptySegment,
    /// A `.` or `..` segment, literal or percent-encoded.
    DotSegment,
    /// A `%` not followed by two hex digits.
    MalformedPercentEncoding,
    /// A segment that decodes to `/`, `?`, `#` or `\` (a delimiter that was
    /// smuggled in percent-encoded form).
    EncodedDelimiter,
    /// A segment that decodes to a C0 control character or DEL (incl. NUL).
    ControlCharacter,
}

impl PathRejection {
    fn reason(self) -> &'static str {
        match self {
            Self::MissingServicePrefix => "missing_service_prefix",
            Self::EmptySegment => "empty_segment",
            Self::DotSegment => "dot_segment",
            Self::MalformedPercentEncoding => "malformed_percent_encoding",
            Self::EncodedDelimiter => "encoded_delimiter",
            Self::ControlCharacter => "control_character",
        }
    }
}

/// Strictly percent-decode one path segment (RFC 3986 §2.1). Any `%` not
/// followed by exactly two hex digits is an error rather than being passed
/// through, so ambiguous input cannot be interpreted differently by the backend.
fn percent_decode_segment(segment: &str) -> Result<Vec<u8>, PathRejection> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex);
            let lo = bytes.next().and_then(hex);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                _ => return Err(PathRejection::MalformedPercentEncoding),
            }
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

/// Derive the backend path from the **raw** (still percent-encoded) request
/// path and validate it.
///
/// `raw_path` is `request.uri().path()` as seen inside the proxy router. The
/// router is mounted with `.nest("/api", ...)`, so axum has already stripped
/// `/api` and the path is `/{svc}/...`; `/api/{svc}/...` is accepted too in
/// case the mount changes. On success the remainder after the prefix is
/// returned unchanged (still encoded) so the backend decodes it exactly once,
/// as it would for a direct request.
///
/// Each segment is percent-decoded only for inspection; the request is
/// refused if any segment is empty, is `.`/`..` (literal or encoded), contains
/// a malformed escape, decodes to a delimiter (`/`, `?`, `#`, `\`), or decodes
/// to a control character. This stops an encoded `%2F`/`%3F`/`%2E%2E` from
/// changing which backend resource (or query) the BFF requests on the
/// signed-in admin's behalf.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-10 (Information Input Validation) - canonical, strict
///   path validation at the BFF boundary
/// - NIST 800-53: AC-3 (Access Enforcement) - the proxy cannot be steered to a
///   backend resource other than the one the URL names (confused deputy)
/// - NIST 800-53: AC-4 (Information Flow Enforcement) - requests flow only to
///   the backend resource the URL names
/// - NIAP PP-CA: FDP_ACF.1 (supporting) - ensures the backend's access control
///   decision is made on the object named by the request
/// - RFC 3986 §2.1 (percent-encoding), §3.3 (path segments), §5.2.4 (dot segments)
fn validate_backend_path<'a>(raw_path: &'a str, svc: &str) -> Result<&'a str, PathRejection> {
    let rest = raw_path
        .strip_prefix("/api")
        .filter(|r| r.starts_with('/'))
        .unwrap_or(raw_path);
    let rest = rest
        .strip_prefix('/')
        .and_then(|r| r.strip_prefix(svc))
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(PathRejection::MissingServicePrefix)?;

    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(PathRejection::EmptySegment);
        }
        let decoded = percent_decode_segment(segment)?;
        if decoded == b"." || decoded == b".." {
            return Err(PathRejection::DotSegment);
        }
        for &b in &decoded {
            match b {
                b'/' | b'?' | b'#' | b'\\' => return Err(PathRejection::EncodedDelimiter),
                0x00..=0x1F | 0x7F => return Err(PathRejection::ControlCharacter),
                _ => {}
            }
        }
    }
    Ok(rest)
}

/// Generic proxy function to forward requests to a backend service
async fn proxy_to_service(
    client: &HttpClient,
    base_url: &str,
    svc: &str,
    original_request: Request<Body>,
) -> Response {
    // Build the backend path from the raw request path, never from axum's
    // percent-decoded `{*path}` capture (POAM-2026-10-23-43). Fail closed with
    // 400 before any backend contact.
    let path = match validate_backend_path(original_request.uri().path(), svc) {
        Ok(path) => path.to_owned(),
        Err(rejection) => {
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records)
            // - NIST 800-53: SI-10 (Information Input Validation)
            // AU-3: who (actor), what (method/service/reason), where
            // (client_ip/request_id/path), outcome. The session token and
            // backend bearer token are never logged. `client_ip` uses the same
            // XFF / X-Real-IP source as the audit middleware (correlatable, only
            // as trustworthy as the fronting proxy). AU-9: it is logged only if
            // it parses as an IpAddr, else `-`, so header text cannot forge fields.
            let client_ip = super::middleware::audit::extract_client_ip(&original_request);
            let client_ip = client_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
            let request_id = original_request
                .extensions()
                .get::<super::middleware::audit::RequestId>()
                .map(|r| r.0.as_str())
                .unwrap_or("-");
            let actor = original_request
                .extensions()
                .get::<super::auth::SessionData>()
                .map(|s| s.user_subject.as_str())
                .unwrap_or("anonymous");
            tracing::warn!(
                security_event = "proxy_path_rejected",
                request_id = %request_id,
                actor = %actor,
                client_ip = %client_ip.map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                method = %original_request.method(),
                service = %svc,
                path = ?original_request.uri().path(),
                reason = rejection.reason(),
                outcome = "denied",
                "Rejected proxied request with unsafe path"
            );
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_path",
                "Request path contains disallowed segments or encodings",
            );
        }
    };

    // Preserve the query string (pagination, filters) — the raw path above
    // excludes it, so it must be re-appended or backends see no query at all.
    let base = base_url.trim_end_matches('/');
    let target_url = match original_request.uri().query() {
        Some(query) => format!("{base}/{path}?{query}"),
        None => format!("{base}/{path}"),
    };

    tracing::debug!(
        target = %target_url,
        method = %original_request.method(),
        "Proxying request to backend service"
    );

    // Build the proxied request
    let (parts, body) = original_request.into_parts();

    // Internal-auth mode: the session (injected by `require_session`) carries
    // the CA's own bearer token. Present it upstream so the backend
    // independently authenticates the actual admin, rather than trusting the
    // proxy's network position (closes the confused-deputy gap). Any
    // client-supplied Authorization header is dropped below and replaced.
    let backend_token = parts
        .extensions
        .get::<super::auth::SessionData>()
        .and_then(|s| s.backend_token.clone());

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

    // Copy headers, excluding hop-by-hop headers and any client-supplied
    // credential or identity header (the proxy is the sole authority for the
    // upstream credential). See `is_stripped_inbound_header`.
    for (key, value) in parts.headers.iter() {
        if is_stripped_inbound_header(key.as_str()) {
            continue;
        }
        proxy_request = proxy_request.header(key, value);
    }

    // Attach the session-bound backend credential (internal-auth mode).
    if let Some(token) = backend_token {
        proxy_request = proxy_request.header("authorization", format!("Bearer {token}"));
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

    // Execute the request over the shared, TLS-capable client (built once with
    // the CA trust anchor). The connector is `https_or_http`, so plaintext
    // backends still work through the same pooled client.
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

/// Inbound headers that must never be forwarded to a backend: hop-by-hop
/// headers, plus anything a browser could use to carry a credential or an
/// identity assertion past the BFF.
///
/// - `Authorization`: replaced by the session-bound backend token.
/// - `Cookie`: the web-UI session cookie (and any other browser cookie) is a
///   BFF-only credential; no backend reads it, so forwarding it only widens its
///   exposure.
/// - `X-Npe-*`: NPE identity headers are asserted only by the npe-portal over
///   its trusted-proxy mTLS channel. A console user must not be able to inject
///   them, even if the web-UI's client certificate were (mis)configured as a
///   trusted proxy subject on a backend.
///
/// Mirrors `is_stripped_inbound_header` in `services/npe-portal/src/server/proxy.rs`.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) - backends authorize on the
///   BFF-supplied credential only; client-forged identity headers are dropped
/// - NIST 800-53: SC-23 (Session Authenticity) - the browser session cookie
///   stays within the BFF and is not replayed to backends
fn is_stripped_inbound_header(name: &str) -> bool {
    is_hop_by_hop_header(name)
        || name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.to_ascii_lowercase().starts_with("x-npe-")
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
    use axum::http::Method;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    use crate::server::{auth::SessionManager, backend_client, config::WebUiConfig};

    // ---- validate_backend_path (pure) ----

    #[test]
    fn normal_paths_are_forwarded_verbatim() {
        assert_eq!(
            validate_backend_path("/ca/api/v1/certificates", "ca"),
            Ok("api/v1/certificates")
        );
        assert_eq!(validate_backend_path("/kra/x", "kra"), Ok("x"));
        // Defensive: un-stripped `/api` mount prefix.
        assert_eq!(
            validate_backend_path("/api/ca/api/v1/certificates", "ca"),
            Ok("api/v1/certificates")
        );
        // Single dots inside a segment and dot-prefixed names are fine.
        assert_eq!(
            validate_backend_path("/est/.well-known/est/cacerts", "est"),
            Ok(".well-known/est/cacerts")
        );
        assert_eq!(validate_backend_path("/ca/a/...", "ca"), Ok("a/..."));
        assert_eq!(validate_backend_path("/ca/v1.2/x", "ca"), Ok("v1.2/x"));
    }

    #[test]
    fn legit_encoded_characters_are_forwarded_still_encoded() {
        assert_eq!(
            validate_backend_path("/ca/users/a%20b/x%40example.com", "ca"),
            Ok("users/a%20b/x%40example.com")
        );
        assert_eq!(
            validate_backend_path("/ca/users/caf%C3%A9", "ca"),
            Ok("users/caf%C3%A9")
        );
        // Double-encoding is forwarded raw; the backend decodes once to the
        // literal `%2F`, exactly as for a direct request.
        assert_eq!(validate_backend_path("/ca/a%252Fb", "ca"), Ok("a%252Fb"));
    }

    #[test]
    fn encoded_slash_is_rejected() {
        for p in ["/ca/a%2Fb", "/ca/a%2fb", "/ca/%2F", "/ca/v1/%2F..%2Fadmin"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
    }

    #[test]
    fn encoded_backslash_query_and_fragment_are_rejected() {
        for p in [
            "/ca/a%5Cb",
            "/ca/a%3Fadmin=1",
            "/ca/a%3fb",
            "/ca/a%23frag",
            "/ca/v1%3F",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
    }

    #[test]
    fn literal_and_encoded_dot_segments_are_rejected() {
        for p in [
            "/ca/..",
            "/ca/../admin",
            "/ca/v1/./x",
            "/ca/v1/.",
            "/ca/%2E%2E/admin",
            "/ca/%2e%2e/admin",
            "/ca/.%2E/admin",
            "/ca/%2E./admin",
            "/ca/%2E/admin",
            "/ca/v1/%2e",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::DotSegment),
                "{p}"
            );
        }
    }

    #[test]
    fn empty_segments_are_rejected() {
        for p in ["/ca/", "/ca//x", "/ca/a//b", "/ca/a/"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EmptySegment),
                "{p}"
            );
        }
    }

    #[test]
    fn control_characters_and_malformed_escapes_are_rejected() {
        for p in [
            "/ca/a%00b",
            "/ca/a%0Ab",
            "/ca/a%0d%0aX-Injected:1",
            "/ca/%7F",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::ControlCharacter),
                "{p}"
            );
        }
        for p in ["/ca/a%", "/ca/a%2", "/ca/a%zz", "/ca/a%G0/b"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MalformedPercentEncoding),
                "{p}"
            );
        }
    }

    #[test]
    fn wrong_or_missing_service_prefix_is_rejected() {
        for p in ["/acme/x", "/cax/x", "/ca", "ca/x", "/", ""] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MissingServicePrefix),
                "{p}"
            );
        }
    }

    // ---- handler level, through the axum Router ----

    /// Spawn a local stand-in backend that counts hits and echoes the request
    /// target (path + query) it received.
    async fn spawn_echo_backend() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = Router::new().fallback(move |req: Request<Body>| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let target = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_owned())
                    .unwrap_or_default();
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                format!("{target}|{auth}")
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo backend");
        let addr = listener.local_addr().expect("echo backend addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), hits)
    }

    /// The proxy routes mounted exactly as in `router.rs` (`.nest("/api", ..)`),
    /// without the session middleware, with every backend pointed at `backend`.
    fn bff_router(backend: &str) -> Router {
        let mut config = WebUiConfig::default();
        config.backend.ca_url = backend.to_owned();
        config.backend.acme_url = backend.to_owned();
        config.backend.ocsp_url = backend.to_owned();
        config.backend.scms_url = backend.to_owned();
        config.backend.kra_url = backend.to_owned();
        config.backend.audit_url = backend.to_owned();
        config.backend.est_url = backend.to_owned();
        let ca_client = backend_client::build(&config.backend).expect("backend client");
        let state = AppState {
            config: Arc::new(config),
            oidc_client: None,
            session_manager: Arc::new(SessionManager::new(900, 28_800)),
            ca_client,
        };
        Router::new().nest("/api", create_proxy_routes(state))
    }

    async fn send(router: Router, method: Method, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn router_rejects_unsafe_paths_before_contacting_backend() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);
        for uri in [
            "/api/ca/api/v1/%2E%2E/%2E%2E/admin",
            "/api/ca/api/v1/certificates%2F..%2Fadmin",
            "/api/ca/api/v1/x%3Fadmin=true",
            "/api/ca/api/v1/x%23frag",
            "/api/ca/api/v1/../admin",
            "/api/ca/api/v1/./x",
            "/api/acme/a%5Cb",
            "/api/ocsp/a%00b",
            "/api/scms/a//b",
            "/api/kra/a%zz",
            "/api/audit/%2e%2e",
            "/api/est/.well-known/est/%2F",
        ] {
            let (status, body) = send(router.clone(), Method::GET, uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json error body");
            assert_eq!(json["error"], "invalid_path", "{uri}");
        }
        // Also for state-changing methods.
        let (status, _) = send(router, Method::POST, "/api/ca/api/v1/%2E%2E/revoke").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "backend must not be contacted"
        );
    }

    #[tokio::test]
    async fn router_forwards_raw_path_and_query_verbatim() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);

        let (status, body) = send(
            router.clone(),
            Method::GET,
            "/api/ca/api/v1/certificates?page=2&status=valid",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/api/v1/certificates?page=2&status=valid|");

        let (status, body) = send(
            router.clone(),
            Method::GET,
            "/api/ca/api/v1/users/a%20b%40example.com?q=x%2Fy",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/api/v1/users/a%20b%40example.com?q=x%2Fy|");

        let (status, body) = send(router, Method::GET, "/api/est/.well-known/est/cacerts").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/.well-known/est/cacerts|");

        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    // ---- QA additions (POAM-2026-10-23-43) ----

    #[test]
    fn qa_mixed_case_and_partial_encoded_dot_segments_are_rejected() {
        // Mixed-case hex in a single escape pair and partial encodings; the
        // url crate (WHATWG) and many backends treat all of these as `..`/`.`.
        for p in [
            "/ca/%2e%2E/admin",
            "/ca/%2E%2e/admin",
            "/ca/.%2e/admin",
            "/ca/%2e./admin",
            "/ca/v1/%2e%2E",
            "/ca/v1/.%2E",
        ] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::DotSegment),
                "{p}"
            );
        }
        // Three (or more) dots, encoded or not, are an ordinary segment name in
        // RFC 3986 §5.2.4 and are forwarded raw.
        assert_eq!(
            validate_backend_path("/ca/%2E%2E%2E", "ca"),
            Ok("%2E%2E%2E")
        );
        assert_eq!(validate_backend_path("/ca/..%2e.", "ca"), Ok("..%2e."));
        // A dot-dot followed by other characters is not a dot segment.
        assert_eq!(validate_backend_path("/ca/..a", "ca"), Ok("..a"));
    }

    #[test]
    fn qa_lowercase_and_extra_delimiter_escapes_are_rejected() {
        for p in ["/ca/a%5cb", "/ca/%2f", "/ca/%23", "/ca/x%2F%2F"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::EncodedDelimiter),
                "{p}"
            );
        }
        // A literal backslash (should http::Uri ever accept one) is also
        // refused: WHATWG URL parsers treat `\` as `/` for special schemes.
        assert_eq!(
            validate_backend_path("/ca/a\\..\\admin", "ca"),
            Err(PathRejection::EncodedDelimiter)
        );
        for p in ["/ca/a%09b", "/ca/a%1Fb", "/ca/a%7fb", "/ca/a%0d"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::ControlCharacter),
                "{p}"
            );
        }
        // Malformed: escape split across a `/` boundary, and a non-ASCII hex
        // lookalike after `%`.
        for p in ["/ca/a%2/F", "/ca/a%/2F", "/ca/a%\u{ff10}0"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MalformedPercentEncoding),
                "{p}"
            );
        }
    }

    #[test]
    fn qa_overlong_utf8_slash_and_dot_are_forwarded_raw_not_decoded() {
        // Documented behaviour: overlong UTF-8 encodings of `/` (%C0%AF,
        // %E0%80%AF) and `.` (%C0%AE) are NOT rejected. Their decoded bytes are
        // >= 0x80, never 0x2F/0x2E, so they cannot form a delimiter or dot
        // segment for an RFC 3986 parser; they are forwarded still encoded and
        // a conforming (UTF-8 strict) backend rejects them as invalid UTF-8.
        for (p, want) in [
            ("/ca/a%C0%AFb", "a%C0%AFb"),
            ("/ca/%C0%AF", "%C0%AF"),
            ("/ca/a%E0%80%AFb", "a%E0%80%AFb"),
            ("/ca/%C0%AE%C0%AE/admin", "%C0%AE%C0%AE/admin"),
            ("/ca/%FF%FE", "%FF%FE"),
        ] {
            assert_eq!(validate_backend_path(p, "ca"), Ok(want), "{p}");
        }
    }

    #[test]
    fn qa_trailing_slash_and_service_prefix_edge_cases() {
        // Trailing slash yields an empty final segment and is refused (no
        // console route uses one; see qa-report.md).
        for p in ["/ca/api/v1/certificates/", "/est/.well-known/est/"] {
            let svc = if p.starts_with("/est") { "est" } else { "ca" };
            assert_eq!(
                validate_backend_path(p, svc),
                Err(PathRejection::EmptySegment),
                "{p}"
            );
        }
        // Service prefix match is exact and case-sensitive, and an encoded
        // prefix is not accepted as the prefix.
        for p in ["/CA/x", "/%63a/x", "/api/CA/x", "/apica/x", "/api"] {
            assert_eq!(
                validate_backend_path(p, "ca"),
                Err(PathRejection::MissingServicePrefix),
                "{p}"
            );
        }
        // `/api/` fallback is only taken for a real `/api/` segment.
        assert_eq!(
            validate_backend_path("/api/ca/x", "ca"),
            Ok("x"),
            "defensive /api fallback"
        );
    }

    #[test]
    fn qa_rejection_reason_tokens_are_stable() {
        assert_eq!(
            PathRejection::MissingServicePrefix.reason(),
            "missing_service_prefix"
        );
        assert_eq!(PathRejection::EmptySegment.reason(), "empty_segment");
        assert_eq!(PathRejection::DotSegment.reason(), "dot_segment");
        assert_eq!(
            PathRejection::MalformedPercentEncoding.reason(),
            "malformed_percent_encoding"
        );
        assert_eq!(
            PathRejection::EncodedDelimiter.reason(),
            "encoded_delimiter"
        );
        assert_eq!(
            PathRejection::ControlCharacter.reason(),
            "control_character"
        );
    }

    fn qa_session(backend_token: &str) -> crate::server::auth::SessionData {
        let now = chrono::Utc::now();
        crate::server::auth::SessionData {
            id: "qa-session-id".to_owned(),
            user_subject: "qa-admin@example.test".to_owned(),
            username: Some("qa-admin".to_owned()),
            email: None,
            roles: vec!["admin".to_owned()],
            created_at: now,
            last_activity: now,
            expires_at: now + chrono::Duration::minutes(15),
            locked: false,
            backend_token: Some(backend_token.to_owned()),
        }
    }

    async fn send_with_session(
        router: Router,
        method: Method,
        uri: &str,
        session: Option<crate::server::auth::SessionData>,
        request_id: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer client-supplied-must-be-dropped")
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .body(Body::empty())
            .expect("request");
        if let Some(s) = session {
            request.extensions_mut().insert(s);
        }
        if let Some(id) = request_id {
            request
                .extensions_mut()
                .insert(crate::server::middleware::audit::RequestId(id.to_owned()));
        }
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn qa_router_rejects_mixed_case_and_partial_encodings_without_backend_call() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);
        for (method, uri) in [
            (Method::GET, "/api/ca/api/v1/%2e%2E/%2E%2e/admin"),
            (Method::GET, "/api/ca/api/v1/.%2E/admin"),
            (Method::GET, "/api/ca/api/v1/%2e./admin"),
            (Method::GET, "/api/ca/api/v1/certificates/"),
            (Method::GET, "/api/ca/api/v1/a%2fb?page=1"),
            (Method::PUT, "/api/kra/a%5cb"),
            (Method::DELETE, "/api/scms/%2E%2E"),
            (Method::PATCH, "/api/audit/a%3Fb"),
            (Method::POST, "/api/acme/new-order%23x"),
            (Method::GET, "/api/ocsp/a%0d%0aHost:evil"),
        ] {
            let (status, body) = send(router.clone(), method.clone(), uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json error body");
            assert_eq!(json["error"], "invalid_path", "{uri}");
            assert!(
                !body.contains(uri),
                "error body must not reflect the raw path: {body}"
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "backend must not be contacted"
        );
    }

    #[tokio::test]
    async fn qa_router_forwards_overlong_utf8_and_encoded_query_verbatim() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);

        // Overlong `/` is forwarded raw, still percent-encoded (not decoded
        // into a delimiter by the BFF).
        let (status, body) = send(router.clone(), Method::GET, "/api/ca/a%C0%AFb").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/a%C0%AFb|");

        // Query string is forwarded byte-for-byte, including encoded
        // delimiters and dot sequences, which cannot alter the path because
        // the BFF fixes the `?` position.
        let q = "q=%2E%2E%2F..%2Fadmin&r=%3F%23%26&s=a%20b+c&t=%C3%A9";
        let (status, body) = send(
            router.clone(),
            Method::GET,
            &format!("/api/ca/api/v1/certificates?{q}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("/api/v1/certificates?{q}|"));

        // Empty query (`?` with nothing after) is preserved as-is.
        let (status, body) = send(router, Method::GET, "/api/ca/api/v1/ca/info?").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/api/v1/ca/info?|");

        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn qa_router_session_bearer_forwarded_only_on_valid_path() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);

        // Valid path with a session: the session-bound bearer replaces the
        // client-supplied Authorization header.
        let (status, body) = send_with_session(
            router.clone(),
            Method::GET,
            "/api/ca/api/v1/certificates",
            Some(qa_session("qa-backend-token")),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "/api/v1/certificates|Bearer qa-backend-token");

        // Unsafe path with a session: refused, backend never sees the token.
        let (status, body) = send_with_session(
            router,
            Method::GET,
            "/api/ca/api/v1/%2E%2E/admin",
            Some(qa_session("qa-backend-token")),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.contains("qa-backend-token"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// `MakeWriter` that appends formatted events to a shared buffer, using
    /// only the existing `tracing-subscriber` dependency.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // Current-thread runtime (the `#[tokio::test]` default) so the
    // thread-local default subscriber sees the handler's events.
    #[tokio::test]
    async fn qa_rejection_emits_au3_security_event_without_secrets() {
        // tracing-core uses a "just one dispatcher" fast path while exactly one
        // dispatcher is registered: callsite interest is then computed from
        // whatever thread happens to (re)register, so a parallel test thread
        // with no subscriber can cache this callsite as `never`. Keeping a
        // second (no-op) dispatcher registered for the life of the test binary
        // disables that fast path, so interest is the union over all
        // registered dispatchers and the per-event `enabled` check decides.
        static KEEPALIVE: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        KEEPALIVE
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));

        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (backend, hits) = spawn_echo_backend().await;
        let router = bff_router(&backend);

        // A callsite first registered by another thread in the window around
        // `set_default` can still cache a stale interest. Prime until this
        // thread's subscriber observes the event, rebuilding the interest
        // cache each time, then discard the priming output. This does not
        // weaken the assertions below, which run on a cleared buffer.
        let mut primed = false;
        for _ in 0..50 {
            tracing::callsite::rebuild_interest_cache();
            let (status, _) = send(router.clone(), Method::GET, "/api/ca/prime%2F").await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let seen = String::from_utf8_lossy(&capture.0.lock().expect("capture lock"))
                .contains("proxy_path_rejected");
            if seen {
                primed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            primed,
            "security event was never observed by the subscriber"
        );
        capture.0.lock().expect("capture lock").clear();

        // With session + request id.
        let (status, _) = send_with_session(
            router.clone(),
            Method::DELETE,
            "/api/kra/keys/%2e%2E/escrow",
            Some(qa_session("qa-secret-backend-token")),
            Some("req-qa-0001"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Without session / request id: fallbacks are used.
        let (status, _) = send(router.clone(), Method::GET, "/api/audit/a%2Fb").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // SEC-005: a forged, non-IP X-Forwarded-For hop must not reach the log.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/ca/x%2Fy")
            .header(
                "x-forwarded-for",
                "198.51.100.1 actor=admin outcome=allowed",
            )
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("infallible");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let raw =
            String::from_utf8(capture.0.lock().expect("capture lock").clone()).expect("utf8 log");
        let events: Vec<serde_json::Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("json log line"))
            .filter(|v: &serde_json::Value| v["fields"]["security_event"] == "proxy_path_rejected")
            .collect();
        assert_eq!(events.len(), 3, "one warn event per rejection: {raw}");

        let e = &events[0];
        assert_eq!(e["level"], "WARN");
        assert_eq!(e["fields"]["request_id"], "req-qa-0001");
        assert_eq!(e["fields"]["actor"], "qa-admin@example.test");
        // AU-3 where: first X-Forwarded-For hop, as in the audit middleware.
        assert_eq!(e["fields"]["client_ip"], "203.0.113.7");
        assert_eq!(e["fields"]["method"], "DELETE");
        assert_eq!(e["fields"]["service"], "kra");
        assert_eq!(e["fields"]["reason"], "dot_segment");
        assert_eq!(e["fields"]["outcome"], "denied");
        assert!(
            e["fields"]["path"]
                .as_str()
                .is_some_and(|p| p.contains("/kra/keys/%2e%2E/escrow")),
            "raw path recorded: {e}"
        );
        assert!(e["timestamp"].is_string(), "AU-3 when");

        let e = &events[1];
        assert_eq!(e["fields"]["request_id"], "-");
        assert_eq!(e["fields"]["actor"], "anonymous");
        assert_eq!(e["fields"]["client_ip"], "-");
        assert_eq!(e["fields"]["method"], "GET");
        assert_eq!(e["fields"]["service"], "audit");
        assert_eq!(e["fields"]["reason"], "encoded_delimiter");
        assert_eq!(e["fields"]["outcome"], "denied");

        let e = &events[2];
        assert_eq!(e["fields"]["client_ip"], "-");
        assert_eq!(e["fields"]["service"], "ca");
        assert!(!raw.contains("actor=admin"), "{raw}");
        assert!(!raw.contains("outcome=allowed"), "{raw}");
        assert!(!raw.contains("198.51.100.1"), "{raw}");

        // No credential material in the security log.
        assert!(!raw.contains("qa-secret-backend-token"), "{raw}");
        assert!(!raw.contains("client-supplied-must-be-dropped"), "{raw}");
        assert!(!raw.contains("qa-session-id"), "{raw}");
    }

    #[test]
    fn credential_and_identity_headers_are_stripped_inbound() {
        for h in [
            "Authorization",
            "authorization",
            "Cookie",
            "COOKIE",
            "X-Npe-User",
            "x-npe-subject",
            "X-NPE-ROLES",
            "X-Npe-Session",
            "x-npe-anything-new",
            "Connection",
            "Host",
        ] {
            assert!(is_stripped_inbound_header(h), "{h} must be stripped");
        }
        for h in [
            "Content-Type",
            "Accept",
            "Content-Length",
            "X-Request-Id",
            "X-Npe",
            "X-Forwarded-For",
        ] {
            assert!(!is_stripped_inbound_header(h), "{h} must pass through");
        }
    }

    /// Stand-in backend that echoes the request headers it received as JSON
    /// (`name -> [values]`).
    async fn spawn_header_echo_backend() -> String {
        let app = Router::new().fallback(|req: Request<Body>| async move {
            let mut map = serde_json::Map::new();
            for (name, value) in req.headers() {
                let entry = map
                    .entry(name.as_str().to_owned())
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                if let serde_json::Value::Array(values) = entry {
                    values.push(serde_json::Value::String(
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    ));
                }
            }
            serde_json::Value::Object(map).to_string()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind header echo backend");
        let addr = listener.local_addr().expect("header echo backend addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn router_strips_cookie_and_npe_identity_headers_before_backend() {
        let backend = spawn_header_echo_backend().await;
        let router = bff_router(&backend);

        for session in [None, Some(qa_session("qa-backend-token"))] {
            let with_session = session.is_some();
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/ca/api/v1/certificates")
                .header("cookie", "ostrich_session=browser-session-secret; other=1")
                .header("x-npe-user", "forged-npe")
                .header("X-Npe-Subject", "CN=forged")
                .header("x-npe-roles", "npe_admin")
                .header("x-npe-session", "forged-session")
                .header("authorization", "Bearer client-supplied-must-be-dropped")
                .header("content-type", "application/json")
                .header("x-request-id", "req-strip-1")
                .body(Body::from("{}"))
                .expect("request");
            if let Some(s) = session {
                request.extensions_mut().insert(s);
            }
            let response = router.clone().oneshot(request).await.expect("infallible");
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("body");
            let headers: serde_json::Value =
                serde_json::from_slice(&body).expect("header echo json");
            let obj = headers.as_object().expect("header map");

            assert!(obj.get("cookie").is_none(), "cookie forwarded: {headers}");
            assert!(
                !obj.keys().any(|k| k.starts_with("x-npe-")),
                "x-npe-* forwarded: {headers}"
            );
            let raw = headers.to_string();
            assert!(!raw.contains("browser-session-secret"), "{raw}");
            assert!(!raw.contains("forged"), "{raw}");
            assert!(!raw.contains("client-supplied-must-be-dropped"), "{raw}");

            // Ordinary headers still pass through.
            assert_eq!(headers["content-type"][0], "application/json");
            assert_eq!(headers["x-request-id"][0], "req-strip-1");

            // Only the session-bound credential goes upstream.
            if with_session {
                assert_eq!(headers["authorization"][0], "Bearer qa-backend-token");
            } else {
                assert!(obj.get("authorization").is_none(), "{headers}");
            }
        }
    }

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
