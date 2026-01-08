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
    extract::State,
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

use super::{
    auth,
    config::WebUiConfig,
    middleware::{audit_middleware, csp_middleware},
    proxy,
    template,
};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WebUiConfig>,
    pub oidc_client: Arc<auth::OidcClient>,
}

/// Create the main router with all routes
pub async fn create_router(config: WebUiConfig) -> Result<Router> {
    let config = Arc::new(config);

    // Initialize OIDC client
    let oidc_client = Arc::new(auth::OidcClient::new(&config.oidc).await?);

    let state = AppState {
        config: config.clone(),
        oidc_client,
    };

    // Health check routes (no auth, no CSP)
    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(state.clone());

    // Auth routes (OIDC login/callback/logout)
    let auth_routes = Router::new()
        .route("/auth/login", get(auth::handlers::login))
        .route("/auth/callback", get(auth::handlers::callback))
        .route("/auth/logout", post(auth::handlers::logout))
        .route("/auth/userinfo", get(auth::handlers::userinfo))
        .with_state(state.clone());

    // API proxy routes (require authentication)
    let api_routes = proxy::create_proxy_routes(state.clone());

    // Static file serving
    let static_routes = Router::new().nest_service(
        &config.static_files.url_prefix,
        ServeDir::new(&config.static_files.directory),
    );

    // SPA fallback - serve index.html for all unmatched routes
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
    // Check OIDC provider is reachable
    let oidc_ready = state.oidc_client.is_ready().await;

    if oidc_ready {
        Json(json!({
            "status": "ready",
            "checks": {
                "oidc": "ok"
            }
        }))
        .into_response()
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "checks": {
                    "oidc": "unreachable"
                }
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
