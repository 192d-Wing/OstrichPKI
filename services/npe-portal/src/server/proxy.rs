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
//! - NIST 800-53: AU-2 (Auditable Events) - rejected (unsafe-path) CA/EST
//!   requests are logged as security events and audited as `ostrich_audit`
//!   Authorization/Failure records; successful proxied requests are logged at
//!   DEBUG only and audited by the CA/EST backends
//! - NIST 800-53: SI-10 (Information Input Validation) - the CA/EST backend
//!   path is taken from the raw (percent-encoded) request path and refused if
//!   it carries dot segments or encoded delimiters (see
//!   `ostrich_common::util::proxy_path::validate_backend_path`)
//! - RFC 6960 - OCSP request/response passthrough to the responder

use axum::{
    Router,
    body::Body,
    extract::{Extension, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use ostrich_common::util::proxy_path::{PathRejection, validate_backend_path};
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
    request: Request<Body>,
) -> Response {
    let Ok(path) = checked_backend_path(&request, "ca", &session) else {
        return invalid_path_response();
    };
    proxy_to_service(
        &state.http_client,
        &state.config.backend.ca_url,
        &path,
        Some(&session),
        request,
    )
    .await
}

async fn proxy_est(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    request: Request<Body>,
) -> Response {
    let Ok(path) = checked_backend_path(&request, "est", &session) else {
        return invalid_path_response();
    };
    proxy_to_service(
        &state.http_client,
        &state.config.backend.est_url,
        &path,
        Some(&session),
        request,
    )
    .await
}

/// Derive the CA/EST backend path from the **raw** request path, logging a
/// security event if it is refused. On `Err` the caller must answer with
/// [`invalid_path_response`] (400) and must not contact the backend.
///
/// POAM-2026-10-23-46: never build the backend path from axum's decoded
/// `{*path}` capture. axum percent-decodes it, so `%2F`, `%3F` or `%2E%2E`
/// would steer the backend request while the portal attaches the session's
/// `X-Npe-*` identity over the trusted-proxy mTLS bridge (confused deputy; the
/// session cookie is `SameSite=Lax`, so a cross-site top-level GET carries it).
/// The proxy router is nested under `/api` in `router.rs`, so here
/// `request.uri().path()` is `/{svc}/...`, still percent-encoded. The validated
/// remainder is forwarded still encoded, so the backend decodes it exactly
/// once. On rejection the handler returns before `proxy_to_service`: no
/// backend contact and no identity headers.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-10 (Information Input Validation) - strict raw-path
///   validation at the portal boundary, fail closed with 400 `invalid_path`
/// - NIST 800-53: AC-3 (Access Enforcement), AC-4 (Information Flow
///   Enforcement) - the forwarded NPE identity reaches only the backend
///   resource the URL names
/// - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records),
///   AU-12 (Audit Record Generation) - one `proxy_path_rejected` warn event and
///   one `ostrich_audit` Authorization/Failure record per rejection with
///   who/what/where/outcome and no session id
/// - NIST 800-53: AU-3, SI-10 - `client_ip` is logged only if it parses as an
///   IP address and `actor` / `path` are Debug-escaped, so client- or
///   certificate-controlled text cannot forge log fields (AU-9 supporting)
/// - NIAP PP-CA: FDP_ACF.1 (supporting), FAU_GEN.1.1
/// - RFC 3986 §2.1 (percent-encoding), §3.3 (path segments), §5.2.4 (dot segments)
fn checked_backend_path(
    request: &Request<Body>,
    svc: &'static str,
    session: &SessionData,
) -> Result<String, PathRejection> {
    match validate_backend_path(request.uri().path(), svc) {
        Ok(path) => Ok(path.to_owned()),
        Err(rejection) => {
            // AU-3: who (actor = certificate CN), what (method/service/reason),
            // where (client_ip/path), outcome. The portal has no request-id
            // middleware; `-` keeps the field schema identical to web-ui and an
            // inbound X-Request-Id is not logged because it is client-controlled.
            // The session id / cookie token are never logged.
            let client_ip = super::router::client_ip(request.headers())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .map(|ip| ip.to_string());
            let method = request.method().as_str();
            let raw_path = request.uri().path();
            tracing::warn!(
                security_event = "proxy_path_rejected",
                request_id = "-",
                actor = ?session.common_name,
                client_ip = client_ip.as_deref().unwrap_or("-"),
                method,
                service = svc,
                path = ?raw_path,
                reason = rejection.reason(),
                outcome = "denied",
                "Rejected proxied NPE request with unsafe path"
            );
            // AU-12 / FAU_GEN.1.1: canonical audit record for the AC-3 denial.
            super::audit::proxy_path_rejected(
                &session.common_name,
                svc,
                method,
                raw_path,
                rejection.reason(),
                client_ip.as_deref(),
            );
            Err(rejection)
        }
    }
}

/// Fail-closed 400 for a refused proxy path (SI-10). The body is fixed text
/// and never reflects the request path or session identity (SI-11, Error
/// Handling).
fn invalid_path_response() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_path",
        "Request path contains disallowed segments or encodings",
    )
}

/// Forward an OCSP request to the responder's root (RFC 6960 over HTTP). The
/// NPE identity is NOT forwarded: OCSP is a public, no-auth protocol that does
/// not consume the X-Npe-* headers, so attaching the caller's CN/DN/roles would
/// be needless disclosure (least privilege / AC-6).
async fn proxy_ocsp(State(state): State<AppState>, request: Request<Body>) -> impl IntoResponse {
    proxy_to_service(
        &state.http_client,
        &state.config.backend.ocsp_url,
        "",
        None,
        request,
    )
    .await
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
/// upstream credential), the browser `Cookie` (the portal's opaque session token
/// is a bearer-equivalent secret the CA/EST backends have no need for — do not
/// spread it into backend logs/memory or let a client smuggle a cookie-based
/// session through), and ALL `X-Npe-*` identity headers are stripped — the proxy
/// re-attaches the authenticated `X-Npe-*` identity itself, so a client can never
/// forge its identity or role by sending those headers (NIST 800-53 AC-3).
fn is_stripped_inbound_header(name: &str) -> bool {
    is_hop_by_hop_header(name)
        || name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
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
    use axum::http::Method;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    use crate::server::{backend_client, config::NpePortalConfig, session::SessionManager};

    // ---- handler level, through the axum Router (POAM-2026-10-23-46) ----

    /// Local stand-in backend that counts hits and echoes
    /// `{path_and_query}|{x-npe-user}|{x-npe-subject}|{x-npe-roles}|{x-npe-session-id}|{cookie}`.
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
                let h = |name: &str| {
                    req.headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned()
                };
                format!(
                    "{target}|{}|{}|{}|{}|{}",
                    h("x-npe-user"),
                    h("x-npe-subject"),
                    h("x-npe-roles"),
                    h(ostrich_common::auth::HEADER_NPE_SESSION),
                    h("cookie")
                )
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

    /// The proxy routes mounted as in `router.rs` (`.nest("/api", ..)`),
    /// without `require_session`, with every backend pointed at `backend`.
    fn portal_router(backend: &str) -> Router {
        let mut config = NpePortalConfig::default();
        config.backend.ca_url = backend.to_owned();
        config.backend.est_url = backend.to_owned();
        config.backend.ocsp_url = backend.to_owned();
        let http_client = backend_client::build(&config.backend).expect("backend client");
        let state = AppState {
            config: Arc::new(config),
            session_manager: Arc::new(SessionManager::new(900, 28_800)),
            http_client,
        };
        Router::new().nest("/api", create_proxy_routes(state))
    }

    fn qa_session() -> SessionData {
        let now = chrono::Utc::now();
        SessionData {
            id: "qa-session-id-SECRET".to_owned(),
            common_name: "qa-npe-cn".to_owned(),
            subject_dn: "CN=qa-npe-cn,OU=QA,O=Ostrich".to_owned(),
            roles: vec!["pki_sponsor".to_owned()],
            cert_fingerprint: "00".repeat(32),
            accepted_consent: true,
            created_at: now,
            last_activity: now,
            expires_at: now + chrono::Duration::minutes(15),
            locked: false,
        }
    }

    /// Send one request; the session (if any) is inserted as a request
    /// extension, exactly as `require_session` does.
    async fn send(
        router: Router,
        method: Method,
        uri: &str,
        session: Option<SessionData>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(Body::empty()).expect("request");
        if let Some(s) = session {
            request.extensions_mut().insert(s);
        }
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn rejects_unsafe_paths_before_contacting_backend() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        let unsafe_tails = [
            "a%2Fb", "a%3Fx", "a%23x", "a%5Cb", "..", "%2e%2E", ".", "a//b", "a/", "a%00b", "a%7F",
            "a%G1", "a%2",
        ];
        for svc in ["ca", "est"] {
            for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
                for tail in unsafe_tails {
                    let uri = format!("/api/{svc}/{tail}");
                    let (status, body) = send(
                        router.clone(),
                        method.clone(),
                        &uri,
                        Some(qa_session()),
                        &[],
                    )
                    .await;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
                    let json: serde_json::Value =
                        serde_json::from_str(&body).expect("json error body");
                    assert_eq!(json["error"], "invalid_path", "{method} {uri}");
                }
            }
        }
        // Nothing after the service prefix: axum's `{*path}` does not match an
        // empty remainder, so the router answers 404 without reaching a handler.
        let (status, _) = send(router, Method::GET, "/api/ca/", Some(qa_session()), &[]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "backend must not be contacted"
        );
    }

    #[tokio::test]
    async fn forwards_raw_path_and_query_verbatim() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);

        let (status, body) = send(
            router.clone(),
            Method::GET,
            "/api/ca/api/v1/certificates%20x?page=2&q=a%2Fb",
            Some(qa_session()),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let target = body.split('|').next().unwrap_or_default();
        assert_eq!(target, "/api/v1/certificates%20x?page=2&q=a%2Fb");
        assert!(!target.contains("/api/ca"), "{target}");

        let (status, body) = send(
            router.clone(),
            Method::POST,
            "/api/est/.well-known/est/cacerts",
            Some(qa_session()),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let target = body.split('|').next().unwrap_or_default();
        assert_eq!(target, "/.well-known/est/cacerts");
        assert!(!target.contains("/api/est"), "{target}");

        // Encoded non-delimiters stay encoded (backend decodes once).
        let (status, body) = send(
            router,
            Method::GET,
            "/api/ca/api/v1/users/caf%C3%A9%40example.com",
            Some(qa_session()),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.starts_with("/api/v1/users/caf%C3%A9%40example.com|"),
            "{body}"
        );

        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn identity_attached_only_on_valid_path() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        let forged = [
            ("x-npe-user", "attacker"),
            ("x-npe-roles", "npe_admin"),
            ("cookie", "npe_session=tok-SECRET"),
        ];

        let (status, body) = send(
            router.clone(),
            Method::GET,
            "/api/ca/api/v1/certificates",
            Some(qa_session()),
            &forged,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            "/api/v1/certificates|qa-npe-cn|CN=qa-npe-cn,OU=QA,O=Ostrich|pki_sponsor|qa-session-id-SECRET|"
        );
        assert!(!body.contains("attacker"), "{body}");
        assert!(!body.contains("tok-SECRET"), "{body}");

        // Unsafe path with the same session: refused, the backend never sees
        // the identity, and nothing identifying is reflected in the error.
        let (status, body) = send(
            router,
            Method::GET,
            "/api/ca/api/v1/%2E%2E/admin",
            Some(qa_session()),
            &forged,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.contains("qa-npe-cn"), "{body}");
        assert!(!body.contains("qa-session-id-SECRET"), "{body}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ocsp_route_unchanged() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        let (status, body) = send(
            router,
            Method::POST,
            "/api/ocsp?x=1",
            None,
            &[("x-npe-user", "attacker")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Responder root, query preserved, no identity headers at all.
        assert_eq!(body, "/?x=1|||||");
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
    async fn rejection_emits_au3_security_event_without_secrets() {
        // tracing-core uses a "just one dispatcher" fast path while exactly one
        // dispatcher is registered, so a parallel test thread with no
        // subscriber can cache this callsite as `never`. Keeping a second
        // (no-op) dispatcher registered disables that fast path (same approach
        // as the web-ui proxy tests).
        static KEEPALIVE: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        KEEPALIVE
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));

        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            // INFO so the `ostrich_audit` record (emitted at info) is captured
            // alongside the WARN security event.
            .with_max_level(tracing::Level::INFO)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);

        // Prime until this thread's subscriber observes the event (a callsite
        // registered by another thread around `set_default` can cache a stale
        // interest), then discard the priming output.
        let mut primed = false;
        for _ in 0..50 {
            tracing::callsite::rebuild_interest_cache();
            let (status, _) = send(
                router.clone(),
                Method::GET,
                "/api/ca/prime%2F",
                Some(qa_session()),
                &[],
            )
            .await;
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

        let (status, _) = send(
            router.clone(),
            Method::DELETE,
            "/api/ca/api/v1/%2e%2E/admin",
            Some(qa_session()),
            &[
                ("x-forwarded-for", "203.0.113.7, 10.0.0.1"),
                ("cookie", "npe_session=tok-SECRET"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // AU-9: a forged, non-IP X-Forwarded-For hop must not reach the log.
        let (status, _) = send(
            router,
            Method::POST,
            "/api/est/a%3Fb",
            Some(qa_session()),
            &[(
                "x-forwarded-for",
                "198.51.100.1 actor=admin outcome=allowed",
            )],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let raw =
            String::from_utf8(capture.0.lock().expect("capture lock").clone()).expect("utf8 log");
        let events: Vec<serde_json::Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("json log line"))
            .filter(|v: &serde_json::Value| v["fields"]["security_event"] == "proxy_path_rejected")
            .collect();
        assert_eq!(events.len(), 2, "one warn event per rejection: {raw}");

        let e = &events[0];
        assert_eq!(e["level"], "WARN");
        assert_eq!(e["fields"]["request_id"], "-");
        // Debug-formatted (CWE-117): a CN cannot inject raw log text.
        assert_eq!(e["fields"]["actor"], "\"qa-npe-cn\"");
        assert_eq!(e["fields"]["client_ip"], "203.0.113.7");
        assert_eq!(e["fields"]["method"], "DELETE");
        assert_eq!(e["fields"]["service"], "ca");
        assert_eq!(e["fields"]["reason"], "dot_segment");
        assert_eq!(e["fields"]["outcome"], "denied");
        assert!(
            e["fields"]["path"]
                .as_str()
                .is_some_and(|p| p.contains("/ca/api/v1/%2e%2E/admin")),
            "raw path recorded: {e}"
        );
        assert!(e["timestamp"].is_string(), "AU-3 when");

        let e = &events[1];
        assert_eq!(e["fields"]["request_id"], "-");
        // Debug-formatted (CWE-117): a CN cannot inject raw log text.
        assert_eq!(e["fields"]["actor"], "\"qa-npe-cn\"");
        assert_eq!(e["fields"]["client_ip"], "-");
        assert_eq!(e["fields"]["method"], "POST");
        assert_eq!(e["fields"]["service"], "est");
        assert_eq!(e["fields"]["reason"], "encoded_delimiter");
        assert_eq!(e["fields"]["outcome"], "denied");
        assert!(!raw.contains("actor=admin"), "{raw}");
        assert!(!raw.contains("outcome=allowed"), "{raw}");
        assert!(!raw.contains("198.51.100.1"), "{raw}");

        // NIST-001: exactly one canonical `ostrich_audit` record per
        // rejection, Authorization/Failure, with no session id.
        let audits: Vec<serde_json::Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("json log line"))
            .filter(|v| v["target"] == "ostrich_audit")
            .map(|v| {
                let rec = v["fields"]["audit"]
                    .as_str()
                    .expect("audit field is a string");
                serde_json::from_str(rec).expect("audit record is JSON")
            })
            .collect();
        assert_eq!(
            audits.len(),
            2,
            "one ostrich_audit record per rejection: {raw}"
        );

        let a = &audits[0];
        assert_eq!(a["event_type"], "authorization");
        assert_eq!(a["outcome"], "failure");
        assert_eq!(a["actor"], "qa-npe-cn");
        assert_eq!(a["target"], "npe-portal/ca");
        assert_eq!(a["action"], "proxy_path_rejected");
        assert_eq!(a["ip_address"], "203.0.113.7");
        assert!(a["session_id"].is_null(), "no session id: {a}");
        assert_eq!(a["details"]["method"], "DELETE");
        assert_eq!(a["details"]["reason"], "dot_segment");
        assert_eq!(a["details"]["request_id"], "-");
        assert_eq!(a["details"]["outcome"], "denied");
        assert!(
            a["details"]["path"]
                .as_str()
                .is_some_and(|p| p.contains("/ca/api/v1/%2e%2E/admin")),
            "raw path recorded: {a}"
        );
        assert!(a["timestamp"].is_string(), "AU-3 when");
        assert!(a["event_hash"].is_array(), "integrity digest: {a}");

        let a = &audits[1];
        assert_eq!(a["event_type"], "authorization");
        assert_eq!(a["outcome"], "failure");
        assert_eq!(a["target"], "npe-portal/est");
        assert_eq!(a["details"]["method"], "POST");
        assert_eq!(a["details"]["reason"], "encoded_delimiter");
        assert!(a["ip_address"].is_null(), "forged XFF not recorded: {a}");
        assert!(a["session_id"].is_null(), "no session id: {a}");

        // No session id or cookie token in the security log or audit records.
        assert!(!raw.contains("qa-session-id-SECRET"), "{raw}");
        assert!(!raw.contains("tok-SECRET"), "{raw}");
        assert!(!raw.contains("npe_session"), "{raw}");
    }

    // ---- QA additions (POAM-2026-10-23-46) ----

    const INVALID_PATH_BODY: &str = r#"{"error":"invalid_path","message":"Request path contains disallowed segments or encodings"}"#;

    /// Negative / boundary matrix: mixed-case and partial encodings, malformed
    /// escapes, encoded delimiters and control bytes, every method incl.
    /// PATCH/HEAD/OPTIONS, both services, with and without a query string.
    /// Each must be refused with the fixed 400 body and zero backend hits.
    #[tokio::test]
    async fn qa_unsafe_path_matrix_all_methods_both_services() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        let tails = [
            "%2e%2E",
            "%2E%2e/admin",
            ".%2E/admin",
            "%2e./admin",
            "%2E",
            "v1/%2e%2E/admin",
            "a%2",
            "a%",
            "a%zz",
            "a%2/F",
            "a%5C",
            "a%5cb",
            "a%2f..%2fadmin",
            "a%3F",
            "a%23",
            "a%00",
            "a%0A",
            "a%0d%0aX-Injected:1",
            "a%1F",
            "a%7F",
            "a%7f",
            "v1/certificates/",
            "a//b",
            "../admin",
            "./x",
        ];
        let methods = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ];
        for svc in ["ca", "est"] {
            for method in &methods {
                for tail in tails {
                    for query in ["", "?x=1&y=%2F"] {
                        let uri = format!("/api/{svc}/{tail}{query}");
                        let (status, body) = send(
                            router.clone(),
                            method.clone(),
                            &uri,
                            Some(qa_session()),
                            &[],
                        )
                        .await;
                        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
                        // Fixed body: never reflects the path or the identity.
                        // axum strips the body of a HEAD response.
                        if *method == Method::HEAD {
                            assert!(body.is_empty(), "{method} {uri}");
                        } else {
                            assert_eq!(body, INVALID_PATH_BODY, "{method} {uri}");
                        }
                    }
                }
            }
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "backend must not be contacted"
        );
    }

    /// Mirrors `router.rs`: proxy routes layered with the real `require_session`
    /// and nested under `/api`. A real, consented, certificate-bound session
    /// (cookie + PeerCertificate) is used instead of injecting the extension.
    async fn session_layered_router(backend: &str) -> (Router, String, Vec<u8>) {
        let mut config = NpePortalConfig::default();
        config.backend.ca_url = backend.to_owned();
        config.backend.est_url = backend.to_owned();
        config.backend.ocsp_url = backend.to_owned();
        let http_client = backend_client::build(&config.backend).expect("backend client");
        let state = AppState {
            config: Arc::new(config),
            session_manager: Arc::new(SessionManager::new(900, 28_800)),
            http_client,
        };
        let cert_der = b"qa-not-a-real-certificate".to_vec();
        let (token, _) = state
            .session_manager
            .create_session(
                "qa-layer-cn".to_owned(),
                "CN=qa-layer-cn".to_owned(),
                vec![ostrich_common::auth::Role::PkiSponsor],
                crate::server::oid::fingerprint(&cert_der),
            )
            .await;
        state
            .session_manager
            .accept_consent(&token)
            .await
            .expect("consent");
        let cookie = format!("{}={token}", state.config.session.cookie_name);
        let api = create_proxy_routes(state.clone()).layer(axum::middleware::from_fn_with_state(
            state,
            crate::server::middleware::require_session,
        ));
        (Router::new().nest("/api", api), cookie, cert_der)
    }

    async fn send_with_cert(
        router: Router,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        cert_der: &[u8],
        extra: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        for (n, v) in extra {
            builder = builder.header(*n, *v);
        }
        let mut request = builder.body(Body::empty()).expect("request");
        request
            .extensions_mut()
            .insert(ostrich_common::tls::PeerCertificate(Some(
                cert_der.to_vec(),
            )));
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn qa_through_require_session_layer_rejects_unsafe_and_forwards_safe() {
        let (backend, hits) = spawn_echo_backend().await;
        let (router, cookie, cert) = session_layered_router(&backend).await;

        // Authenticated + consented session, unsafe path: 400, no backend hit.
        for (method, uri) in [
            (Method::GET, "/api/ca/api/v1/%2E%2E/admin"),
            (Method::PATCH, "/api/est/a%2Fb"),
        ] {
            let (status, body) =
                send_with_cert(router.clone(), method, uri, Some(&cookie), &cert, &[]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(body, INVALID_PATH_BODY, "{uri}");
        }
        // No session: authentication is enforced first (401), still no hit.
        let (status, _) = send_with_cert(
            router.clone(),
            Method::GET,
            "/api/ca/%2E%2E/admin",
            None,
            &cert,
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // Valid path through the real layer: identity attached, client
        // cookie and forged X-Npe-* not forwarded.
        let (status, body) = send_with_cert(
            router,
            Method::GET,
            "/api/ca/api/v1/certificates?page=1",
            Some(&cookie),
            &cert,
            &[("x-npe-roles", "npe_admin")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let fields: Vec<&str> = body.split('|').collect();
        assert_eq!(fields[0], "/api/v1/certificates?page=1");
        assert_eq!(fields[1], "qa-layer-cn");
        assert_eq!(fields[2], "CN=qa-layer-cn");
        assert_eq!(fields[3], "pki_sponsor");
        assert!(!fields[4].is_empty(), "session id forwarded upstream");
        assert_eq!(fields[5], "", "cookie must not be forwarded");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// EST + PATCH on a valid path: forged X-Npe-* headers in any case are
    /// still stripped and replaced by the session identity.
    #[tokio::test]
    async fn qa_est_patch_valid_path_strips_forged_identity_headers() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        let (status, body) = send(
            router,
            Method::PATCH,
            "/api/est/.well-known/est/simplereenroll",
            Some(qa_session()),
            &[
                ("X-NPE-USER", "attacker"),
                ("x-npe-subject", "CN=attacker"),
                ("X-Npe-Roles", "npe_admin"),
                ("x-npe-session-id", "forged-session"),
                ("authorization", "Bearer forged"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            "/.well-known/est/simplereenroll|qa-npe-cn|CN=qa-npe-cn,OU=QA,O=Ostrich|pki_sponsor|qa-session-id-SECRET|"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// The query string is never validated or rewritten: dot segments,
    /// encoded delimiters and NUL escapes in the query are passed verbatim,
    /// and an empty query is preserved.
    #[tokio::test]
    async fn qa_query_is_forwarded_byte_for_byte() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        for (uri, want) in [
            (
                "/api/ca/api/v1/x?a=../../admin&b=%2e%2E%2F&c=%00&d=a%3Fb&e=%zz",
                "/api/v1/x?a=../../admin&b=%2e%2E%2F&c=%00&d=a%3Fb&e=%zz",
            ),
            ("/api/est/a/b?", "/a/b?"),
            ("/api/est/a/b?x", "/a/b?x"),
        ] {
            let (status, body) =
                send(router.clone(), Method::GET, uri, Some(qa_session()), &[]).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_eq!(body.split('|').next(), Some(want), "{uri}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    /// A backend base URL with its own path prefix (and trailing slash) is
    /// preserved and joined with exactly one `/`.
    #[tokio::test]
    async fn qa_backend_base_path_prefix_preserved() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&format!("{backend}/prefix/"));
        let (status, body) = send(
            router,
            Method::GET,
            "/api/ca/api/v1/certificates",
            Some(qa_session()),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("/prefix/api/v1/certificates|"), "{body}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// Fail-secure: if the session extension is somehow missing (layer
    /// misconfiguration), the CA/EST handlers never contact the backend.
    #[tokio::test]
    async fn qa_missing_session_extension_fails_closed() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        for uri in [
            "/api/ca/api/v1/certificates",
            "/api/est/.well-known/est/cacerts",
        ] {
            let (status, body) = send(router.clone(), Method::GET, uri, None, &[]).await;
            assert!(!status.is_success(), "{uri}: {status}");
            assert!(!body.contains('|'), "{uri}: echoed backend body {body}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// `/ocsp` is an exact route; sub-paths (incl. traversal attempts) are not
    /// proxied anywhere.
    #[tokio::test]
    async fn qa_ocsp_subpaths_are_not_proxied() {
        let (backend, hits) = spawn_echo_backend().await;
        let router = portal_router(&backend);
        for uri in ["/api/ocsp/x", "/api/ocsp/..%2Fca/admin", "/api/ocsp/%2E%2E"] {
            let (status, _) = send(router.clone(), Method::POST, uri, None, &[]).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

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
