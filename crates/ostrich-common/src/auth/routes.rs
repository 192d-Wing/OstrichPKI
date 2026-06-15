//! Authentication REST endpoints (login/logout)
//!
//! Shared router factory so every service exposes the same session API:
//!
//! - `POST /api/v1/auth/login`  `{username, password}` -> `{token, expires_at, user}`
//! - `POST /api/v1/auth/logout` (Bearer token) -> 204
//!
//! Login/logout are necessarily public routes (a client cannot have a session
//! before logging in); brute-force is mitigated by the provider's
//! failed-attempt lockout (FIA_AFL.1) and the DB-side counter.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification and Authentication)
//! - NIST 800-53: IA-5 (Authenticator Management) - password never logged
//! - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - provider lockout
//! - NIAP PP-CA: FIA_UAU.1 / FIA_UID.1 - authentication before TSF actions
//! - NIAP PP-CA: FTA_SSL.4 - user-initiated session termination (logout)

use crate::auth::provider::{AuthError, AuthProvider, Credentials};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Login request body
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Successful login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Bearer token for subsequent requests
    pub token: String,
    /// Session expiration (Unix timestamp)
    pub expires_at: i64,
    /// Authenticated username
    pub username: String,
    /// Assigned roles
    pub roles: Vec<String>,
}

/// Build the auth router. Mount it on the service's public route group.
pub fn auth_routes(provider: Arc<dyn AuthProvider>) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .with_state(provider)
}

/// POST /api/v1/auth/login
///
/// NIST 800-53: IA-2, AC-7 - authenticate and enforce lockout policy.
/// Error responses deliberately do not distinguish "no such user" from
/// "wrong password" (NIST 800-53: SI-11 - no account enumeration).
async fn login(
    State(provider): State<Arc<dyn AuthProvider>>,
    Json(request): Json<LoginRequest>,
) -> Response {
    let credentials = Credentials::password(&request.username, request.password);

    let user = match provider.authenticate(&credentials).await {
        Ok(user) => user,
        Err(e) => {
            // AU-2: log the failure with actor context but never the password
            tracing::warn!(username = %request.username, error = %e, "Login failed");
            let (status, message) = match e {
                AuthError::AccountLocked { until } => (
                    StatusCode::FORBIDDEN,
                    format!("Account locked until {}", until),
                ),
                AuthError::AccountSuspended | AuthError::AccountDisabled => {
                    (StatusCode::FORBIDDEN, "Account unavailable".to_string())
                }
                _ => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            };
            return (status, Json(serde_json::json!({ "error": message }))).into_response();
        }
    };

    let session = match provider.create_session(&user).await {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(username = %user.username, error = %e, "Session creation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Session creation failed" })),
            )
                .into_response();
        }
    };

    tracing::info!(username = %user.username, "Login successful");
    (
        StatusCode::OK,
        Json(LoginResponse {
            token: session.token,
            expires_at: session.expires_at,
            username: user.username,
            roles: user.roles.iter().map(|r| format!("{:?}", r)).collect(),
        }),
    )
        .into_response()
}

/// POST /api/v1/auth/logout
///
/// NIAP PP-CA: FTA_SSL.4 - user-initiated session termination.
/// Always returns 204: terminating an already-invalid session is not an
/// error, and the response must not leak session validity to a third party.
async fn logout(
    State(provider): State<Arc<dyn AuthProvider>>,
    headers: axum::http::HeaderMap,
) -> StatusCode {
    if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        let _ = provider.invalidate_session(token).await;
    }
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::DisabledAuthProvider;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn login_fails_closed_with_disabled_provider() {
        let app = auth_routes(Arc::new(DisabledAuthProvider::new()));
        let response = app
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"username": "a", "password": "b"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_is_idempotent() {
        let app = auth_routes(Arc::new(DisabledAuthProvider::new()));
        let response = app
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header("authorization", "Bearer nonsense")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
