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
    extract::{Path, State},
    middleware,
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

use super::{
    auth,
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

    let state = AppState {
        config: config.clone(),
        oidc_client,
        session_manager,
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

    // Legacy `/next` alias. The React console moved from `/next` to `/` when the
    // Yew SPA was retired; permanently redirect old links (preserving the
    // sub-path) so bookmarks and external references keep working.
    let next_redirect = Router::new()
        .route("/next", get(|| async { Redirect::permanent("/") }))
        .route(
            "/next/{*rest}",
            get(|Path(rest): Path<String>| async move {
                Redirect::permanent(&format!("/{rest}"))
            }),
        );

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

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
