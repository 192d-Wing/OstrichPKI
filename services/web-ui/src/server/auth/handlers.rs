//! OAuth/OIDC HTTP Handlers
//!
//! HTTP handlers for the OAuth/OIDC authentication flow.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification and Authentication)
//! - NIST 800-53: AU-2 (Auditable Events) - Log all auth events
//! - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)
//! - NIAP PP-CA: FAU_GEN.1 (Audit Data Generation)

use axum::{
    debug_handler,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};

use super::super::router::AppState;

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

/// Error response for authentication failures
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
}

/// User info response
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub subject: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub session_locked: bool,
}

/// Login handler - initiates OAuth flow
///
/// Redirects the user to the Keycloak authorization endpoint.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, Response> {
    // Generate authorization URL with PKCE
    let (auth_url, csrf_state) = state
        .oidc_client
        .authorize_url()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to generate authorization URL");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError {
                    error: "auth_error".to_string(),
                    message: "Failed to initiate authentication".to_string(),
                }),
            )
                .into_response()
        })?;

    tracing::info!("Initiating OAuth login flow");

    // Store CSRF state in a secure cookie
    let csrf_cookie = Cookie::build(("oauth_state", csrf_state))
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::minutes(10));

    Ok((jar.add(csrf_cookie), Redirect::to(auth_url.as_str())))
}

/// OAuth callback handler
///
/// Handles the redirect from Keycloak after user authentication.
/// Exchanges the authorization code for tokens and creates a session.
#[debug_handler]
pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Result<impl IntoResponse, Response> {
    // Validate CSRF state
    let csrf_cookie = jar.get("oauth_state").ok_or_else(|| {
        tracing::warn!("OAuth callback missing CSRF cookie");
        (
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_state".to_string(),
                message: "Missing or invalid OAuth state".to_string(),
            }),
        )
            .into_response()
    })?;

    if csrf_cookie.value() != params.state {
        // NIST 800-53: AU-2 - Log authentication failures
        tracing::warn!(
            expected = %params.state,
            "OAuth CSRF state mismatch"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_state".to_string(),
                message: "OAuth state validation failed".to_string(),
            }),
        )
            .into_response());
    }

    // Exchange authorization code for tokens
    let user_info = state
        .oidc_client
        .exchange_code(&params.code, &params.state)
        .await
        .map_err(|e| {
            // NIAP PP-CA: FIA_AFL.1 - Log failed authentication attempts
            tracing::error!(error = %e, "Failed to exchange authorization code");
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "auth_failed".to_string(),
                    message: "Authentication failed".to_string(),
                }),
            )
                .into_response()
        })?;

    // Create session
    // Note: In production, inject a proper SessionManager via State
    let session_token = create_session_token();

    tracing::info!(
        subject = %user_info.subject,
        username = ?user_info.username,
        roles = ?user_info.roles,
        "User authenticated successfully"
    );

    // Set session cookie - clone the cookie name to satisfy 'static lifetime
    let cookie_name = state.config.session.cookie_name.clone();
    let session_cookie = Cookie::build((cookie_name, session_token))
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            state.config.session.absolute_timeout_secs,
        ));

    // Remove CSRF cookie
    let remove_csrf = Cookie::build(("oauth_state", ""))
        .path("/")
        .max_age(cookie::time::Duration::ZERO);

    // Redirect to dashboard
    Ok((
        jar.add(session_cookie).add(remove_csrf),
        Redirect::to("/"),
    ))
}

/// Logout handler
///
/// Invalidates the session and clears the session cookie.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    // Get session token from cookie
    if let Some(_session_cookie) = jar.get(&state.config.session.cookie_name) {
        tracing::info!("User logged out");
        // In production: invalidate session in SessionManager
    }

    // Clear session cookie - clone the cookie name to satisfy 'static lifetime
    let cookie_name = state.config.session.cookie_name.clone();
    let remove_session = Cookie::build((cookie_name, ""))
        .path("/")
        .max_age(cookie::time::Duration::ZERO);

    // Optionally redirect to Keycloak logout
    // For now, just redirect to login page
    (jar.add(remove_session), Redirect::to("/auth/login"))
}

/// User info handler
///
/// Returns information about the currently authenticated user.
pub async fn userinfo(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, Response> {
    // Get session token from cookie
    let _session_cookie = jar.get(&state.config.session.cookie_name).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(AuthError {
            error: "not_authenticated".to_string(),
            message: "No active session".to_string(),
        })).into_response()
    })?;

    // In production: validate session with SessionManager and return actual user info
    // For now, return a placeholder
    Ok(Json(UserInfoResponse {
        subject: "placeholder".to_string(),
        username: Some("user".to_string()),
        email: None,
        roles: vec!["user".to_string()],
        session_locked: false,
    }))
}

/// Generate a session token
/// In production, use the SessionManager
fn create_session_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ostrich_common::util::random::secure_random_bytes;

    let bytes = secure_random_bytes(32);
    URL_SAFE_NO_PAD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_token_generation() {
        let token1 = create_session_token();
        let token2 = create_session_token();

        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
        assert_ne!(token1, token2);
    }
}
