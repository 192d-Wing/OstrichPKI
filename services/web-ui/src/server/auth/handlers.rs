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

/// Response used when an OIDC-only route is hit while running in internal mode.
fn oidc_disabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(AuthError {
            error: "oidc_disabled".to_string(),
            message: "OIDC is disabled; this deployment uses internal CA authentication".to_string(),
        }),
    )
        .into_response()
}

/// Credentials posted to the internal-login endpoint.
#[derive(Debug, Deserialize)]
pub struct InternalLoginRequest {
    pub username: String,
    pub password: String,
}

/// Shape of the CA's `POST /api/v1/auth/login` success response.
#[derive(Debug, Deserialize)]
struct CaLoginResponse {
    token: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// What the web UI returns to the browser after a successful internal login.
#[derive(Debug, Serialize)]
pub struct InternalLoginResponse {
    pub username: Option<String>,
    pub roles: Vec<String>,
}

/// Internal-auth login handler (no external IdP).
///
/// Authenticates the supplied credentials directly against the CA's own account
/// store (`POST {ca_url}/api/v1/auth/login`, argon2id + lockout + RBAC). On
/// success it binds the CA's bearer token to a server-side web session and sets
/// the session cookie; the proxy then presents that token upstream, so the CA
/// independently authenticates every admin action (no confused deputy, no IdP).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-2 (Identification and Authentication) - CA-enforced
/// - NIST 800-53: AC-3 (Access Enforcement) - credential carried end-to-end
/// - NIAP PP-CA: FIA_UAU.1 / FIA_AFL.1 (CA-side authentication + lockout)
pub async fn internal_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<InternalLoginRequest>,
) -> Response {
    if state.config.auth_mode != super::super::config::AuthMode::Internal {
        return oidc_disabled();
    }

    let url = format!(
        "{}/api/v1/auth/login",
        state.config.backend.ca_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "username": req.username, "password": req.password }))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "internal login: CA auth endpoint unreachable");
            return (
                StatusCode::BAD_GATEWAY,
                Json(AuthError {
                    error: "backend_error".to_string(),
                    message: "Authentication service unavailable".to_string(),
                }),
            )
                .into_response();
        }
    };

    if !resp.status().is_success() {
        // NIAP PP-CA: FIA_AFL.1 - failed authentication (lockout enforced CA-side)
        tracing::warn!(status = %resp.status(), user = %req.username, "internal login rejected by CA");
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "auth_failed".to_string(),
                message: "Invalid username or password".to_string(),
            }),
        )
            .into_response();
    }

    let ca: CaLoginResponse = match resp.json().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "internal login: malformed CA login response");
            return (
                StatusCode::BAD_GATEWAY,
                Json(AuthError {
                    error: "backend_error".to_string(),
                    message: "Malformed authentication response".to_string(),
                }),
            )
                .into_response();
        }
    };

    let username = ca.username.or(Some(req.username.clone()));
    let (session_token, _session) = state
        .session_manager
        .create_session_with_token(
            username.clone().unwrap_or_default(),
            username.clone(),
            None,
            ca.roles.clone(),
            Some(ca.token),
        )
        .await;

    tracing::info!(user = ?username, roles = ?ca.roles, "User authenticated via internal CA auth");

    let cookie_name = state.config.session.cookie_name.clone();
    let session_cookie = Cookie::build((cookie_name, session_token))
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure_cookies)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            state.config.session.absolute_timeout_secs,
        ));

    (
        jar.add(session_cookie),
        Json(InternalLoginResponse {
            username,
            roles: ca.roles,
        }),
    )
        .into_response()
}

/// Login handler - initiates OAuth flow
///
/// Redirects the user to the Keycloak authorization endpoint.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, Response> {
    let oidc_client = state.oidc_client.as_ref().ok_or_else(oidc_disabled)?;

    // Generate authorization URL with PKCE
    let (auth_url, csrf_state) = oidc_client
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

    let oidc_client = state.oidc_client.as_ref().ok_or_else(oidc_disabled)?;

    // Exchange authorization code for tokens
    let user_info = oidc_client
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

    // Create a server-side session bound to the OIDC identity. The cookie
    // value is only meaningful because this token now maps to a live session
    // in the SessionManager (require_session validates it server-side).
    // NIST 800-53: IA-2; NIAP PP-CA: FIA_UAU.1
    let (session_token, _session) = state
        .session_manager
        .create_session(
            user_info.subject.clone(),
            user_info.username.clone(),
            user_info.email.clone(),
            user_info.roles.clone(),
        )
        .await;

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
    // Invalidate the server-side session (NIAP PP-CA: FTA_SSL.4 -
    // user-initiated termination). Removing only the cookie would leave the
    // session live and replayable until timeout.
    if let Some(session_cookie) = jar.get(&state.config.session.cookie_name) {
        state
            .session_manager
            .invalidate_session(session_cookie.value())
            .await;
        tracing::info!("User logged out");
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
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "not_authenticated".to_string(),
                message: "No active session".to_string(),
            }),
        )
            .into_response()
    };

    // Validate the session server-side and return the real identity.
    let session_cookie = jar
        .get(&state.config.session.cookie_name)
        .ok_or_else(unauthorized)?;
    let session = state
        .session_manager
        .validate_session(session_cookie.value())
        .await
        .ok_or_else(unauthorized)?;

    Ok(Json(UserInfoResponse {
        subject: session.user_subject,
        username: session.username,
        email: session.email,
        roles: session.roles,
        session_locked: session.locked,
    }))
}

// Session tokens are generated by SessionManager::create_session (the
// previous standalone create_session_token produced cookie values that were
// never stored anywhere, so require_session could only check presence).
