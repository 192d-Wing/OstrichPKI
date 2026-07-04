//! NPE Portal router.
//!
//! Wires the mTLS auth endpoints, the USG consent gate, the allowlisted API
//! proxy, static assets, and the SPA fallback.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement), IA-2 (Identification & Auth)
//! - NIAP PP-CA: FIA_UAU.1, FTA_SSL.1/FTA_SSL.3

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use ostrich_common::tls::PeerCertificate;
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

use super::{
    audit, backend_client,
    config::NpePortalConfig,
    middleware::{csp_middleware, require_session},
    oid, proxy,
    session::{SessionData, SessionManager},
    template,
};

/// Pooled HTTP(S) client used by the backend proxy (mTLS-capable; see
/// [`backend_client`]).
pub use backend_client::HttpClient;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<NpePortalConfig>,
    pub session_manager: Arc<SessionManager>,
    /// Shared connection-pooling HTTP client for proxying to CA/EST.
    pub http_client: HttpClient,
}

/// Extract the client IP for audit attribution from forwarding headers (the
/// portal terminates TLS behind a load balancer). Falls back to `None`.
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Create the main router.
pub async fn create_router(config: NpePortalConfig) -> Result<Router> {
    let config = Arc::new(config);
    let session_manager = Arc::new(SessionManager::new(
        config.session.inactivity_timeout_secs,
        config.session.absolute_timeout_secs,
    ));
    let http_client = backend_client::build(&config.backend)?;
    let state = AppState {
        config: config.clone(),
        session_manager,
        http_client,
    };

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(state.clone());

    // mTLS auth + consent endpoints.
    let auth_routes = Router::new()
        .route("/auth/login", get(login))
        .route("/auth/consent", post(consent))
        .route("/auth/userinfo", get(userinfo))
        .route("/auth/logout", post(logout))
        .with_state(state.clone());

    // Portal-local API endpoints (handled here, not proxied to a backend) that
    // still require an authenticated session. CSR parsing powers the submit
    // form's CN/SAN preview.
    let local_api_routes = Router::new()
        .route("/v1/parse-csr", post(parse_csr))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // Allowlisted API proxy, gated by the session/consent middleware.
    let api_routes = proxy::create_proxy_routes(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ))
        .merge(local_api_routes);

    let static_routes = Router::new().nest_service(
        &config.static_files.url_prefix,
        ServeDir::new(&config.static_files.directory),
    );

    let spa_routes = Router::new()
        .fallback(get(template::serve_index))
        .with_state(state.clone());

    let app = Router::new()
        .merge(health_routes)
        .merge(auth_routes)
        .nest("/api", api_routes)
        .merge(static_routes)
        .merge(spa_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csp_middleware,
        ));

    Ok(app)
}

/// Build the session cookie with the secure attributes for this deployment.
fn session_cookie(name: &str, value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), value);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie
}

/// JSON view of a session for the SPA.
fn userinfo_json(session: &SessionData) -> serde_json::Value {
    json!({
        "commonName": session.common_name,
        "subjectDn": session.subject_dn,
        "roles": session.roles,
        "consentAccepted": session.accepted_consent,
    })
}

fn presented_fingerprint(peer_cert: Option<&Extension<PeerCertificate>>) -> Option<String> {
    peer_cert
        .and_then(|Extension(p)| p.0.as_deref())
        .map(oid::fingerprint)
}

fn session_matches_presented_cert(
    session: &SessionData,
    peer_cert: Option<&Extension<PeerCertificate>>,
) -> bool {
    presented_fingerprint(peer_cert).as_deref() == Some(session.cert_fingerprint.as_str())
}

/// mTLS login: resolve the verified client certificate's OIDs to an NPE role,
/// mint a session (consent pending), and set the session cookie. If the caller
/// already holds a live session, return it instead of re-minting.
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    peer_cert: Option<Extension<PeerCertificate>>,
) -> Response {
    let ip = client_ip(&headers);
    let cert_der = peer_cert.as_ref().and_then(|Extension(p)| p.0.clone());
    let presented_fp = cert_der.as_deref().map(oid::fingerprint);

    // Existing session fast-path: return it if the cookie is live, not locked,
    // and bound to the certificate on THIS connection (SC-23). Use a passive
    // validation (no inactivity refresh) so SPA session polling doesn't hold the
    // timer open. A fingerprint mismatch falls through to re-authentication.
    if let Some(cookie) = jar.get(&state.config.session.cookie_name)
        && let Some(session) = state
            .session_manager
            .validate_session(cookie.value(), false)
            .await
        && !session.locked
        && presented_fp.as_deref() == Some(session.cert_fingerprint.as_str())
    {
        return Json(userinfo_json(&session)).into_response();
    }

    match oid::authenticate(cert_der.as_deref(), &state.config.oid_mapping) {
        Ok(identity) => {
            let role = identity.role.name().to_string();
            let (token, session) = state
                .session_manager
                .create_session(
                    identity.common_name,
                    identity.subject_dn,
                    vec![identity.role],
                    identity.fingerprint,
                )
                .await;
            audit::login_success(&session.common_name, &role, ip.as_deref(), &session.id);
            let jar = jar.add(session_cookie(
                &state.config.session.cookie_name,
                token,
                state.config.session.secure_cookies,
            ));
            (jar, Json(userinfo_json(&session))).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "NPE mTLS authentication failed");
            audit::login_failed(&e.to_string(), ip.as_deref());
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "authentication_failed", "message": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// Acknowledge the USG consent banner for the current session.
async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    peer_cert: Option<Extension<PeerCertificate>>,
) -> Response {
    let token = match jar.get(&state.config.session.cookie_name) {
        Some(c) if !c.value().is_empty() => c.value().to_string(),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "not_authenticated" })),
            )
                .into_response();
        }
    };
    let current = match state.session_manager.validate_session(&token, false).await {
        Some(session) if session_matches_presented_cert(&session, peer_cert.as_ref()) => session,
        Some(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "certificate_mismatch" })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_session" })),
            )
                .into_response();
        }
    };

    match state.session_manager.accept_consent(&token).await {
        Some(session) => {
            audit::consent_accepted(
                &current.common_name,
                client_ip(&headers).as_deref(),
                &current.id,
            );
            Json(userinfo_json(&session)).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_session" })),
        )
            .into_response(),
    }
}

/// Return the current session's identity, or 401 if there is none. This is a
/// passive probe (no inactivity refresh).
async fn userinfo(
    State(state): State<AppState>,
    jar: CookieJar,
    peer_cert: Option<Extension<PeerCertificate>>,
) -> Response {
    let token = match jar.get(&state.config.session.cookie_name) {
        Some(c) if !c.value().is_empty() => c.value().to_string(),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "not_authenticated" })),
            )
                .into_response();
        }
    };
    match state.session_manager.validate_session(&token, false).await {
        Some(session) if session.locked => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "session_locked" })),
        )
            .into_response(),
        Some(session) if !session_matches_presented_cert(&session, peer_cert.as_ref()) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "certificate_mismatch" })),
        )
            .into_response(),
        Some(session) => Json(userinfo_json(&session)).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_session" })),
        )
            .into_response(),
    }
}

/// Invalidate the current session and clear the cookie.
async fn logout(State(state): State<AppState>, headers: HeaderMap, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(&state.config.session.cookie_name) {
        // Capture identity for the audit record before invalidating.
        if let Some(session) = state
            .session_manager
            .validate_session(cookie.value(), false)
            .await
        {
            audit::logout(
                &session.common_name,
                client_ip(&headers).as_deref(),
                &session.id,
            );
        }
        state
            .session_manager
            .invalidate_session(cookie.value())
            .await;
    }
    let jar = jar.remove(Cookie::from(state.config.session.cookie_name.clone()));
    (jar, Json(json!({ "status": "logged_out" }))).into_response()
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "ostrich-npe-portal",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ready",
        "sessions": state.session_manager.session_count().await,
    }))
}

#[derive(serde::Deserialize)]
struct ParseCsrRequest {
    csr_pem: String,
}

/// Parse a pasted PKCS#10 CSR and return its subject Common Name + Subject
/// Alternative Names for the submit form's preview. Read-only and session-gated;
/// the CA independently re-validates the CSR on submit, so this is a UX aid only.
/// Reuses `ostrich_x509::parser` — the same parser the CA/EST services use.
async fn parse_csr(
    Extension(_session): Extension<SessionData>,
    Json(req): Json<ParseCsrRequest>,
) -> Response {
    let der = match x509_parser::pem::Pem::read(std::io::Cursor::new(req.csr_pem.as_bytes())) {
        Ok((pem, _)) if pem.label == "CERTIFICATE REQUEST" => pem.contents,
        Ok((pem, _)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("expected a CERTIFICATE REQUEST PEM block, found {}", pem.label),
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("not a PEM certificate request: {e}") })),
            )
                .into_response();
        }
    };

    let parsed = match ostrich_x509::parser::parse_csr(&der) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid certificate request: {e}") })),
            )
                .into_response();
        }
    };
    // Structured CN (the rendered subject_dn is RFC 4514 and awkward to split in
    // the client); fall back to None if the subject has no CN.
    let common_name = ostrich_x509::parser::parse_csr_subject_dn(&der)
        .ok()
        .and_then(|dn| dn.common_name);

    (
        StatusCode::OK,
        Json(json!({
            "commonName": common_name,
            "subjectDn": parsed.subject_dn,
            "sans": parsed.subject_alternative_names,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
