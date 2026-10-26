//! Web UI Router
//!
//! Defines all routes for the Web UI service including:
//! - Health/readiness endpoints
//! - OAuth/OIDC authentication routes
//! - API proxy routes
//! - Static file serving
//! - SPA fallback route
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - Route-level access control
//! - NIST 800-53: AU-2 (Auditable Events) - All routes are audited

use anyhow::Result;
use axum::{
    Router,
    extract::{OriginalUri, Request, State},
    middleware,
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

use super::{
    auth, backend_client,
    backend_client::HttpClient,
    config::{AuthMode, WebUiConfig},
    middleware::{audit_middleware, csp_middleware, require_session},
    proxy, template,
};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WebUiConfig>,
    /// OIDC client, present only in `oidc` auth mode. `None` in `internal`
    /// mode, where authentication goes directly to the CA and no external IdP
    /// is contacted.
    pub oidc_client: Option<Arc<auth::OidcClient>>,
    /// Server-side session store. Sessions are created by the OIDC callback
    /// and validated by `require_session` on every proxied request, so a
    /// session cookie is meaningful only if it maps to a live server session.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: IA-2 - server-validated authentication state
    /// - NIAP PP-CA: FTA_SSL.1/FTA_SSL.3 - inactivity + absolute timeouts
    pub session_manager: Arc<auth::SessionManager>,
    /// Pooled HTTP(S) client for reaching the backend services. Built with the
    /// CA trust anchor so it can dial the CA's TLS 1.3 REST API; also used by
    /// the auth handlers for the CA login/logout calls. Shared (connection
    /// pooling) rather than constructed per request.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-8 (transmission confidentiality)
    pub ca_client: HttpClient,
}

/// Create the main router with all routes
pub async fn create_router(config: WebUiConfig) -> Result<Router> {
    let config = Arc::new(config);

    // Initialize the OIDC client only in OIDC mode. In internal mode no
    // external IdP is contacted; authentication is delegated to the CA's own
    // account store, so we never perform OIDC discovery (which would require a
    // reachable Keycloak).
    let oidc_client = match config.auth_mode {
        AuthMode::Oidc => Some(Arc::new(auth::OidcClient::new(&config.oidc).await?)),
        AuthMode::Internal => {
            tracing::info!(
                "Auth mode: INTERNAL — authenticating against the CA's account store \
                 (POST /api/v1/auth/login); Keycloak/OIDC is disabled"
            );
            None
        }
    };

    // Server-side session manager. Web-UI sessions are ephemeral by design (a
    // stateless BFF; users re-auth via OIDC on restart, and the proxy
    // backend_token cannot be persisted). Storage sits behind WebUiSessionStore,
    // so a durable backend can be supplied via SessionManager::with_store for
    // multi-instance deployments. See auth/session.rs module docs.
    let session_manager = Arc::new(auth::SessionManager::new(
        config.session.inactivity_timeout_secs,
        config.session.absolute_timeout_secs,
    ));

    // Pooled HTTP(S) client for the backends. Built once with the CA trust
    // anchor (config.backend.tls_ca_cert) so it can verify the CA's internal
    // TLS certificate; a failure here is fatal (the console cannot function
    // without a working CA channel).
    let ca_client = backend_client::build(&config.backend)?;

    let state = AppState {
        config: config.clone(),
        oidc_client,
        session_manager,
        ca_client,
    };

    // Health check routes (no auth, no CSP)
    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(state.clone());

    // Auth routes. OIDC login/callback are used in `oidc` mode; internal-login
    // is used in `internal` mode. Both are always mounted (the handlers reject
    // calls that don't match the active mode), so logout/userinfo work in both.
    let auth_routes = Router::new()
        .route("/auth/login", get(auth::handlers::login))
        .route("/auth/callback", get(auth::handlers::callback))
        .route("/auth/internal-login", post(auth::handlers::internal_login))
        // GET so the browser can navigate to it directly (the client triggers
        // logout by setting window.location); the handler clears the session and
        // redirects to /auth/login.
        .route("/auth/logout", get(auth::handlers::logout))
        .route("/auth/logout-all", get(auth::handlers::logout_all))
        .route("/auth/userinfo", get(auth::handlers::userinfo))
        .with_state(state.clone());

    // API proxy routes (require authentication)
    //
    // The require_session middleware rejects any request that does not carry
    // the configured session cookie. The cookie is set by the OIDC callback
    // handler after successful authentication. This prevents unauthenticated
    // clients from using the proxy to reach backend services directly.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3 (Access Enforcement)
    // - NIST 800-53: IA-2 (Identification and Authentication)
    // - NIAP PP-CA: FIA_UAU.1 (User Authentication before TSF-mediated actions)
    let api_routes = proxy::create_proxy_routes(state.clone()).layer(
        middleware::from_fn_with_state(state.clone(), require_session),
    );

    // Static file serving
    let static_routes = Router::new().nest_service(
        &config.static_files.url_prefix,
        ServeDir::new(&config.static_files.directory),
    );

    // Legacy `/next` alias (see `legacy_next_router`).
    let next_redirect = legacy_next_router();

    // SPA fallback — serve the React console index for `/` and all unmatched
    // routes (the client router resolves the path).
    let spa_routes = Router::new()
        .fallback(get(template::serve_index))
        .with_state(state.clone());

    // Combine all routes with middleware
    let app = Router::new()
        // Health routes first (no middleware)
        .merge(health_routes)
        // Auth routes
        .merge(auth_routes)
        // API proxy routes
        .nest("/api", api_routes)
        // Static files
        .merge(static_routes)
        // Legacy /next → / redirect (specific routes, before the catch-all)
        .merge(next_redirect)
        // SPA fallback (must be last)
        .merge(spa_routes)
        // Apply audit middleware to all routes
        .layer(middleware::from_fn(audit_middleware))
        // Apply CSP middleware (generates nonce per request)
        .layer(middleware::from_fn(csp_middleware));

    Ok(app)
}

/// Legacy `/next` alias router.
///
/// The React console moved from `/next` to `/` when the Yew SPA was retired;
/// old links are permanently redirected (preserving the sub-path) so bookmarks
/// and external references keep working. The target is computed by
/// [`legacy_next_target`] from the raw request path.
fn legacy_next_router() -> Router {
    Router::new()
        .route("/next", get(legacy_next_redirect))
        .route("/next/", get(legacy_next_redirect))
        .route("/next/{*rest}", get(legacy_next_redirect))
}

/// Handler for the legacy `/next` routes.
///
/// Uses the raw, still percent-encoded request path (`OriginalUri`) rather
/// than the percent-decoded `Path` capture, so an encoded `/` or `\` in the
/// request can never be decoded into the `Location` header. Any unsafe target
/// is replaced by `/` and logged as a security event.
async fn legacy_next_redirect(request: Request) -> Redirect {
    let raw_path = request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri().path(), |original| original.0.path());
    match legacy_next_target(raw_path) {
        Ok(target) => Redirect::permanent(&target),
        Err(detail) => {
            // COMPLIANCE MAPPING:
            // - NIST 800-53: SI-10 (Information Input Validation)
            // - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records),
            //   SI-4 (System Monitoring) - neutralised redirect probes are
            //   recorded, not only the routine 308 from the audit middleware.
            // AU-9: `path` is Debug-formatted so attacker bytes are escaped;
            // `client_ip` is logged only if it parses as an IpAddr.
            let client_ip = super::middleware::audit::extract_client_ip(&request)
                .and_then(|s| s.parse::<std::net::IpAddr>().ok());
            let request_id = request
                .extensions()
                .get::<super::middleware::audit::RequestId>()
                .map_or("-", |r| r.0.as_str());
            tracing::warn!(
                security_event = "legacy_redirect_rejected",
                request_id = %request_id,
                client_ip = %client_ip.map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                method = %request.method(),
                path = ?raw_path,
                reason = "unsafe legacy redirect target",
                detail = detail,
                outcome = "redirected_to_root",
                "Rejected unsafe legacy /next redirect target"
            );
            Redirect::permanent("/")
        }
    }
}

/// Compute the same-origin redirect target for a legacy `/next/...` request.
///
/// `raw_path` is the raw (not percent-decoded) request path; the query string
/// is not consulted and is dropped. `/next` and `/next/` map to `Ok("/")`.
/// Otherwise the remainder after `/next/` is copied into the target only if
/// it:
/// - consists solely of visible ASCII (0x21..=0x7E),
/// - has no empty segment (no leading `/`, no `//`),
/// - contains no `\` and no encoded `/` or `\` (`%2F`/`%5C`, any case),
/// - has no `.` or `..` segment, raw or percent-encoded (`%2e`, any case).
///
/// Anything else returns `Err(detail)`; the caller fails secure to `/`. A
/// successful result is therefore `/` followed by a visible-ASCII character
/// that is neither `/` nor `\`, and contains no segment a browser could
/// normalise into a scheme-relative (`//host`) path.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-10 (Information Input Validation)
/// - NIAP PP-CA: none (no SFR covers HTTP redirect targets)
/// - CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
/// - Closes POAM-2026-10-23-45 (decoded `Path` capture let `/next/%2Fevil.com`
///   and `/next//evil.com` redirect to `//evil.com`)
fn legacy_next_target(raw_path: &str) -> Result<String, &'static str> {
    let Some(remainder) = raw_path.strip_prefix("/next") else {
        return Err("not a legacy /next path");
    };
    if remainder.is_empty() {
        return Ok("/".to_owned());
    }
    // Only `/next` itself or `/next/...` is a legacy link (not `/nextfoo`).
    let Some(rest) = remainder.strip_prefix('/') else {
        return Err("not a legacy /next path");
    };
    if rest.is_empty() {
        return Ok("/".to_owned());
    }
    if !rest.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err("non-visible-ASCII byte");
    }
    if rest.starts_with('/') || rest.contains("//") {
        return Err("empty path segment");
    }
    let lower = rest.to_ascii_lowercase();
    if rest.contains('\\') || lower.contains("%2f") || lower.contains("%5c") {
        return Err("raw or encoded separator");
    }
    // `lower` decodes only `%2e`, solely to recognise dot segments.
    if lower
        .split('/')
        .map(|segment| segment.replace("%2e", "."))
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("dot segment");
    }
    Ok(format!("/{rest}"))
}

/// Health check endpoint
///
/// Returns 200 OK if the service is running.
/// Used for liveness probes.
async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "ostrich-web-ui",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness check endpoint
///
/// Returns 200 OK if the service is ready to accept traffic.
/// Checks OIDC provider connectivity.
async fn readiness_check(State(state): State<AppState>) -> Response {
    // In internal-auth mode there is no IdP to probe; the service is ready as
    // soon as it is serving. In OIDC mode, readiness reflects IdP reachability.
    match &state.oidc_client {
        None => Json(json!({
            "status": "ready",
            "checks": { "auth": "internal" }
        }))
        .into_response(),
        Some(oidc) if oidc.is_ready().await => Json(json!({
            "status": "ready",
            "checks": { "oidc": "ok" }
        }))
        .into_response(),
        Some(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "checks": { "oidc": "unreachable" }
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Send `GET <uri>` through the real legacy `/next` router and return the
    /// status and `Location` header.
    async fn legacy_next_get(uri: &str) -> (StatusCode, Option<String>) {
        let request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("valid test request");
        let response = legacy_next_router()
            .oneshot(request)
            .await
            .expect("router is infallible");
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .map(|v| v.to_str().expect("ASCII Location").to_string());
        (response.status(), location)
    }

    /// The `Location` the handler would send for `raw_path` (unsafe → `/`).
    fn resolved_target(raw_path: &str) -> String {
        legacy_next_target(raw_path).unwrap_or_else(|_| "/".to_owned())
    }

    async fn assert_legacy_next(uri: &str, expected_location: &str) {
        let (status, location) = legacy_next_get(uri).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT, "status for {uri}");
        assert_eq!(
            location.as_deref(),
            Some(expected_location),
            "Location for {uri}"
        );
    }

    // POAM-2026-10-23-45 / CWE-601: encoded or doubled separators must never
    // produce a scheme-relative (`//host`) or backslash-host Location.
    #[tokio::test]
    async fn test_legacy_next_encoded_slash_fails_secure() {
        assert_legacy_next("/next/%2Fevil.com", "/").await;
        assert_legacy_next("/next/%2fevil.com", "/").await;
    }

    #[tokio::test]
    async fn test_legacy_next_double_slash_fails_secure() {
        assert_legacy_next("/next//evil.com", "/").await;
    }

    #[tokio::test]
    async fn test_legacy_next_encoded_backslash_upper_fails_secure() {
        assert_legacy_next("/next/%5Cevil.com", "/").await;
    }

    #[tokio::test]
    async fn test_legacy_next_encoded_backslash_lower_fails_secure() {
        assert_legacy_next("/next/%5cevil.com", "/").await;
    }

    #[tokio::test]
    async fn test_legacy_next_preserves_deep_link() {
        assert_legacy_next("/next/certificates/abc", "/certificates/abc").await;
    }

    #[tokio::test]
    async fn test_legacy_next_drops_query() {
        assert_legacy_next("/next/certificates/abc?x=//evil.com", "/certificates/abc").await;
        assert_legacy_next("/next?x=//evil.com", "/").await;
    }

    #[tokio::test]
    async fn test_legacy_next_root_redirects_to_root() {
        assert_legacy_next("/next", "/").await;
        assert_legacy_next("/next/", "/").await;
    }

    #[test]
    fn test_legacy_next_target_helper() {
        assert_eq!(resolved_target("/next/a/b"), "/a/b");
        assert_eq!(resolved_target("/next/a%2Fb"), "/");
        assert_eq!(resolved_target("/next/a\\b"), "/");
        assert_eq!(resolved_target("/next/\\evil.com"), "/");
        assert_eq!(resolved_target("/next///evil.com"), "/");
        assert_eq!(resolved_target("/nextfoo"), "/");
        assert_eq!(resolved_target("/other"), "/");
        assert_eq!(resolved_target(""), "/");
        // Non-separator encodings stay percent-encoded (in-origin path).
        assert_eq!(resolved_target("/next/a%20b"), "/a%20b");
        // NIST-001: `/next` and `/next/` are the only `Ok("/")` results; every
        // other fallback is an `Err` that the handler logs.
        assert_eq!(legacy_next_target("/next"), Ok("/".to_owned()));
        assert_eq!(legacy_next_target("/next/"), Ok("/".to_owned()));
        for raw in [
            "/next//evil.com",
            "/next/%2Fevil.com",
            "/next/.//evil.com",
            "/next/a\u{7f}",
            "/nextfoo",
        ] {
            assert!(legacy_next_target(raw).is_err(), "{raw:?} must be Err");
        }
    }

    // ---- QA additions (POAM-2026-10-23-45 / CWE-601 / SI-10) ----

    /// Assert the safety invariant from the fix: `Location` is exactly `/`,
    /// or `/` followed by a byte that is neither `/` nor `\`, and contains no
    /// ASCII control characters (which browsers may strip, e.g. tab).
    fn assert_same_origin_location(uri: &str, location: &str) {
        let bytes = location.as_bytes();
        assert_eq!(
            bytes.first(),
            Some(&b'/'),
            "Location for {uri}: {location:?}"
        );
        if let Some(second) = bytes.get(1) {
            assert!(
                *second != b'/' && *second != b'\\',
                "scheme-relative/backslash Location for {uri}: {location:?}"
            );
        }
        assert!(
            !bytes.iter().any(|b| b.is_ascii_control()),
            "control character in Location for {uri}: {location:?}"
        );
    }

    // Double-encoded separators are not decoded by the server: they remain a
    // literal `%25..` sequence in an origin-relative path.
    #[tokio::test]
    async fn test_legacy_next_double_encoded_separators_stay_in_origin() {
        for (uri, expected) in [
            ("/next/%252Fevil.com", "/%252Fevil.com"),
            ("/next/%252fevil.com", "/%252fevil.com"),
            ("/next/%255Cevil.com", "/%255Cevil.com"),
            ("/next/%252F%252Fevil.com", "/%252F%252Fevil.com"),
        ] {
            assert_legacy_next(uri, expected).await;
            assert_same_origin_location(uri, expected);
        }
    }

    // Encoded separators anywhere in the remainder (not only the first
    // segment), in any case combination, fail secure to `/`.
    #[tokio::test]
    async fn test_legacy_next_mixed_case_encoded_separators_anywhere_fail_secure() {
        for uri in [
            "/next/%2F%2fevil.com",
            "/next/%2f%2Fevil.com",
            "/next/%5C%5cevil.com",
            "/next/%2F%5Cevil.com",
            "/next/%5c%2fevil.com",
            "/next/certificates/%2F%2Fevil.com",
            "/next/certificates%5C..%5Cevil.com",
            "/next/a/b/c%2fd",
        ] {
            assert_legacy_next(uri, "/").await;
        }
    }

    // A literal backslash (accepted by the `http` URI parser) fails secure.
    #[tokio::test]
    async fn test_legacy_next_literal_backslash_fails_secure() {
        assert!("/next/\\evil.com".parse::<axum::http::Uri>().is_ok());
        assert_legacy_next("/next/\\evil.com", "/").await;
        assert_legacy_next("/next/\\\\evil.com", "/").await;
        assert_legacy_next("/next/a/\\evil.com", "/").await;
    }

    // SEC-001: `.`/`..` segments, raw or percent-encoded in any case or mix,
    // fail secure to `/` (browsers normalise `/.//evil.com` to the
    // same-origin path `//evil.com`, a latent scheme-relative sink).
    // Segments that merely contain dots are preserved.
    #[tokio::test]
    async fn test_legacy_next_dot_segments_fail_secure() {
        for uri in [
            "/next/.",
            "/next/..",
            "/next/%2e",
            "/next/%2E",
            "/next/%2e%2e",
            "/next/%2E%2E/",
            "/next/.%2e",
            "/next/%2E.",
            "/next/../evil.com",
            "/next/.//evil.com",
            "/next/%2e//evil.com",
            "/next/%2e%2e/%2e%2e//evil.com",
            "/next/a/./b",
            "/next/a/%2e%2E/b",
            "/next/a/..",
        ] {
            assert_legacy_next(uri, "/").await;
        }
        for (uri, expected) in [
            ("/next/.well-known/x", "/.well-known/x"),
            ("/next/a.b/c..d", "/a.b/c..d"),
            ("/next/...", "/..."),
            ("/next/%2e%2e%2e", "/%2e%2e%2e"),
        ] {
            assert_legacy_next(uri, expected).await;
            assert_same_origin_location(uri, expected);
        }
    }

    // SEC-001: an empty segment (`//`) anywhere in the remainder fails secure.
    #[tokio::test]
    async fn test_legacy_next_inner_double_slash_fails_secure() {
        for uri in [
            "/next/a//evil.com",
            "/next/certificates//evil.com",
            "/next/a/b//",
        ] {
            assert_legacy_next(uri, "/").await;
        }
    }

    // Only the exact `/next` segment is a legacy link: `/nextfoo...` and
    // other-case `/Next`/`/NEXT` do not match this router (they fall through
    // to the SPA fallback in `create_router`), and produce no Location.
    #[tokio::test]
    async fn test_legacy_next_prefix_must_be_exact_segment() {
        for uri in [
            "/nextfoo",
            "/nextfoo//evil.com",
            "/next%2F%2Fevil.com",
            "/Next//evil.com",
            "/NEXT/%2Fevil.com",
        ] {
            let (status, location) = legacy_next_get(uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "status for {uri}");
            assert_eq!(location, None, "Location for {uri}");
        }
    }

    // Tab, CR, LF and space (which browsers strip from or reject in URLs) are
    // refused by the `http` URI parser before routing, so they cannot reach
    // the handler; their percent-encoded forms stay encoded in-origin.
    #[tokio::test]
    async fn test_legacy_next_whitespace_variants() {
        for raw in [
            "/next/\t/evil.com",
            "/next/\n/evil.com",
            "/next/\r/evil.com",
            "/next/ /evil.com",
            "/next/\t\\evil.com",
        ] {
            assert!(
                raw.parse::<axum::http::Uri>().is_err(),
                "URI parser accepted {raw:?}"
            );
        }
        for (uri, expected) in [
            ("/next/%09/evil.com", "/%09/evil.com"),
            ("/next/%0A/evil.com", "/%0A/evil.com"),
            ("/next/%20/evil.com", "/%20/evil.com"),
        ] {
            assert_legacy_next(uri, expected).await;
            assert_same_origin_location(uri, expected);
        }
        // SEC-001: followed by `//`, they fail secure.
        assert_legacy_next("/next/%0d%0a//evil.com", "/").await;
        assert_legacy_next("/next/%20//evil.com", "/").await;
    }

    // The query string never influences the target path (it is dropped),
    // even when it carries separators or an absolute URL; a fragment is not
    // part of the parsed path either.
    #[tokio::test]
    async fn test_legacy_next_query_and_fragment_do_not_influence_path() {
        for (uri, expected) in [
            ("/next/?//evil.com", "/"),
            ("/next?/evil.com", "/"),
            ("/next?%2F%2Fevil.com", "/"),
            ("/next/a?\\evil.com", "/a"),
            ("/next/a?next=https://evil.com", "/a"),
            ("/next/a?%2F%2Fevil.com", "/a"),
            ("/next/a#//evil.com", "/a"),
            ("/next//evil.com?ok", "/"),
        ] {
            assert_legacy_next(uri, expected).await;
        }
    }

    // HEAD is routed by `get` and must take the same fail-secure path; other
    // methods are not redirected at all.
    #[tokio::test]
    async fn test_legacy_next_methods() {
        let head = Request::builder()
            .method(axum::http::Method::HEAD)
            .uri("/next//evil.com")
            .body(Body::empty())
            .expect("valid test request");
        let response = legacy_next_router()
            .oneshot(head)
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(axum::http::header::LOCATION),
            Some(&axum::http::HeaderValue::from_static("/"))
        );

        let post = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/next//evil.com")
            .body(Body::empty())
            .expect("valid test request");
        let response = legacy_next_router()
            .oneshot(post)
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none()
        );
    }

    // QA-001/QA-002: bytes the `http` URI parser accepts but that are not
    // visible ASCII (DEL, raw UTF-8) fail secure to `/` instead of producing
    // a 500 or a non-ASCII Location.
    #[tokio::test]
    async fn test_legacy_next_non_visible_ascii_fails_secure() {
        for uri in [
            "/next/a\u{7f}/evil.com",
            "/next/\u{7f}",
            "/next/\u{e9}",
            "/next/certificates/caf\u{e9}",
        ] {
            assert!(uri.parse::<axum::http::Uri>().is_ok(), "{uri:?}");
            assert_legacy_next(uri, "/").await;
        }
        // Helper-level: bytes the URI parser would reject today are also
        // refused, so the helper does not depend on upstream filtering.
        for raw in [
            "/next/\t/evil.com",
            "/next/a\nb",
            "/next/a b",
            "/next/\u{0}",
        ] {
            assert!(legacy_next_target(raw).is_err(), "{raw:?} must be Err");
        }
    }

    // Helper-level invariant over a corpus of hostile remainders.
    #[test]
    fn test_legacy_next_target_invariant_corpus() {
        for raw in [
            "/next",
            "/next/",
            "/next//",
            "/next///",
            "/next/\\",
            "/next/%2F",
            "/next/%5c",
            "/next/%252F",
            "/next/%2e%2e//evil.com",
            "/next/./%2F/evil.com",
            "/next/a/b/c",
            "/next/https:/evil.com",
            "/next/https://evil.com",
            "/next/javascript:alert(1)",
            "/next/@evil.com",
            "/next/.%2e//evil.com",
            "/next/a\u{7f}",
            "/next/\u{e9}",
        ] {
            let target = resolved_target(raw);
            assert_same_origin_location(raw, &target);
        }
        // Scheme-looking remainders stay path-absolute (`/https:...`).
        assert_eq!(resolved_target("/next/https:/evil.com"), "/https:/evil.com");
        // SEC-001: `//` anywhere fails secure.
        assert_eq!(resolved_target("/next/https://evil.com"), "/");
        assert_eq!(resolved_target("/next//"), "/");
    }

    // SEC-002: through a router assembled like `create_router` (legacy router
    // merged before the SPA fallback, wrapped in `audit_middleware`), an
    // unsafe target still yields 308 `/` and a near-miss reaches the fallback.
    #[tokio::test]
    async fn test_legacy_next_merged_router_fails_secure() {
        let app = Router::new()
            .merge(legacy_next_router())
            .merge(Router::new().fallback(get(|| async { "spa" })))
            .layer(middleware::from_fn(audit_middleware));

        let request = Request::builder()
            .uri("/next//evil.com")
            .body(Body::empty())
            .expect("valid test request");
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(axum::http::header::LOCATION),
            Some(&axum::http::HeaderValue::from_static("/"))
        );

        let request = Request::builder()
            .uri("/next/certificates/abc")
            .body(Body::empty())
            .expect("valid test request");
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(axum::http::header::LOCATION),
            Some(&axum::http::HeaderValue::from_static("/certificates/abc"))
        );

        let request = Request::builder()
            .uri("/nextfoo//evil.com")
            .body(Body::empty())
            .expect("valid test request");
        let response = app.oneshot(request).await.expect("router is infallible");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none()
        );
    }
}
