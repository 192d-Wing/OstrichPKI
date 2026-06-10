//! Session Gate Middleware
//!
//! Rejects unauthenticated access to `/api/*` proxy routes. The OIDC callback
//! handler sets a session cookie (name configured via
//! `config.session.cookie_name`) after a successful login. This middleware
//! extracts that cookie on every request and rejects with 401 if it is missing.
//!
//! Note: this is a session *presence* check, not a full session *validity*
//! check. Full server-side session validation against `SessionManager` is a
//! follow-up (the `SessionManager` type already exists in
//! `server::auth::session` but is not wired to AppState yet). Checking presence
//! still meaningfully closes the hole where an unauthenticated client could
//! call the proxy and reach backend services directly; without a valid OIDC
//! login the cookie will not be set.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - deny unauthenticated proxy access
//! - NIST 800-53: IA-2 (Identification and Authentication) - enforce session presence
//! - NIAP PP-CA: FIA_UAU.1 (Authentication before TSF-mediated actions)

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;

use crate::server::router::AppState;

/// Require a session cookie on the incoming request.
///
/// Returns 401 Unauthorized if the configured session cookie is missing. The
/// cookie name is read from `AppState::config::session::cookie_name`.
pub async fn require_session(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let cookie_name = &state.config.session.cookie_name;

    match jar.get(cookie_name) {
        Some(cookie) if !cookie.value().is_empty() => next.run(request).await,
        _ => {
            tracing::warn!(
                path = %request.uri().path(),
                "Proxy request rejected: missing session cookie"
            );
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "not_authenticated",
                    "message": "Active session required"
                })),
            )
                .into_response()
        }
    }
}
