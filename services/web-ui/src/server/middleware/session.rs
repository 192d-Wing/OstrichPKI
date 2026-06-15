//! Session Gate Middleware
//!
//! Rejects unauthenticated access to `/api/*` proxy routes. The OIDC callback
//! handler creates a server-side session (in `AppState::session_manager`) and
//! sets a cookie carrying its token. This middleware validates that token
//! against the session store on every request - it is a full session
//! *validity* check, not a cookie *presence* check: a forged or stale cookie
//! whose token is not a live session is rejected, and the session's
//! inactivity/absolute timeouts (FTA_SSL.1/FTA_SSL.3) are enforced on each
//! call. A session that has locked due to inactivity is also rejected
//! (the user must re-authenticate).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - deny unauthenticated proxy access
//! - NIST 800-53: IA-2 (Identification and Authentication) - server-validated session
//! - NIAP PP-CA: FIA_UAU.1 (Authentication before TSF-mediated actions)
//! - NIAP PP-CA: FTA_SSL.1/FTA_SSL.3 (session timeout enforcement)

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;

use crate::server::router::AppState;

/// Validate the session token cookie against the server-side session store.
///
/// Returns 401 Unauthorized if the cookie is missing, its token is not a live
/// session, the session has expired, or the session is locked due to
/// inactivity.
pub async fn require_session(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    let reject = |path: &str, reason: &str| -> Response {
        tracing::warn!(path = %path, reason = %reason, "Proxy request rejected");
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "not_authenticated",
                "message": "Active session required",
            })),
        )
            .into_response()
    };

    let path = request.uri().path().to_string();

    let token = match jar.get(&state.config.session.cookie_name) {
        Some(cookie) if !cookie.value().is_empty() => cookie.value().to_string(),
        _ => return reject(&path, "missing session cookie"),
    };

    // Server-side validation: token must map to a live, non-expired session.
    match state.session_manager.validate_session(&token).await {
        Some(session) if session.locked => reject(
            &path,
            "session locked (inactivity); re-authentication required",
        ),
        Some(session) => {
            // Make the validated session available to downstream proxy handlers
            // so they can attach the bound backend credential (internal mode).
            request.extensions_mut().insert(session);
            next.run(request).await
        }
        None => reject(&path, "invalid or expired session"),
    }
}
