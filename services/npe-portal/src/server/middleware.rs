//! NPE Portal middleware: CSP nonce generation and the session/consent gate.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - deny un-consented/unauthenticated API
//! - NIST 800-53: IA-2 (server-validated session), SC-18 (Mobile Code, CSP nonce)
//! - NIAP PP-CA: FIA_UAU.1, FTA_SSL.1/FTA_SSL.3

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ostrich_common::tls::PeerCertificate;
use ostrich_common::util::random::secure_random_bytes;
use serde_json::json;

use super::{oid, router::AppState};

/// Per-request CSP nonce, injected into the inline runtime-config script.
#[derive(Clone, Debug)]
pub struct CspNonce(String);

impl CspNonce {
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Generate a per-request CSP nonce, expose it to handlers via an extension, and
/// attach a Content-Security-Policy header to the response. The nonce length is
/// taken from configuration (`csp_nonce_length`).
pub async fn csp_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let nonce = BASE64.encode(secure_random_bytes(state.config.csp_nonce_length));
    request.extensions_mut().insert(CspNonce(nonce.clone()));

    let mut response = next.run(request).await;

    let policy = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; \
         form-action 'self'"
    );
    if let Ok(value) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

/// Gate `/api/*` proxy routes: require a live session whose USG consent has been
/// acknowledged. A valid-but-un-consented session returns 403 `consent_required`
/// so the SPA can show the consent banner before retrying.
pub async fn require_session(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    let reject = |status: StatusCode, error: &str, message: &str| -> Response {
        tracing::warn!(path = %path, error = %error, "NPE proxy request rejected");
        (status, Json(json!({ "error": error, "message": message }))).into_response()
    };

    let token = match jar.get(&state.config.session.cookie_name) {
        Some(cookie) if !cookie.value().is_empty() => cookie.value().to_string(),
        _ => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "not_authenticated",
                "Active session required",
            );
        }
    };

    // Fingerprint of the certificate on THIS connection (None on plain HTTP).
    let presented_fp = request
        .extensions()
        .get::<PeerCertificate>()
        .and_then(|p| p.0.as_deref())
        .map(oid::fingerprint);

    // A proxied API call is genuine user activity, so refresh the inactivity
    // timer (refresh = true).
    match state.session_manager.validate_session(&token, true).await {
        Some(session) if session.locked => reject(
            StatusCode::UNAUTHORIZED,
            "session_locked",
            "Session locked due to inactivity; re-authentication required",
        ),
        // SC-23: the session is bound to the certificate that created it. A
        // cookie replayed under a different (or no) mTLS identity is rejected.
        Some(session) if presented_fp.as_deref() != Some(session.cert_fingerprint.as_str()) => {
            reject(
                StatusCode::UNAUTHORIZED,
                "certificate_mismatch",
                "Session is bound to a different client certificate",
            )
        }
        Some(session) if !session.accepted_consent => reject(
            StatusCode::FORBIDDEN,
            "consent_required",
            "USG consent must be acknowledged before using the portal",
        ),
        Some(session) => {
            request.extensions_mut().insert(session);
            next.run(request).await
        }
        None => reject(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "Invalid or expired session",
        ),
    }
}
