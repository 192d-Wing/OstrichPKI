//! SPA index rendering with CSP-nonce + runtime-config injection.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-18 (Mobile Code) - nonce on the injected inline script
//! - NIST 800-53: SI-10 (Information Input Validation) - JSON-escaped config

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use super::{middleware::CspNonce, router::AppState};

/// Serve the React console index with CSP-nonce + runtime-config injection. The
/// SPA reads `window.__OSTRICH_NPE_CONFIG__` for the classification banner and
/// API base URL; per-session role/identity comes from `/auth/userinfo`.
pub async fn serve_index(
    State(state): State<AppState>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let path = std::path::Path::new(&state.config.static_files.directory).join("index.html");
    let template = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "NPE console index.html not found");
            return (
                StatusCode::NOT_FOUND,
                "NPE portal console not built for this image",
            )
                .into_response();
        }
    };

    let config = serde_json::json!({
        "apiBaseUrl": "/api",
        "appName": "OstrichPKI NPE Portal",
        "classificationBanner": state.config.classification_banner,
        "classificationColor": state.config.classification_color,
        "dodMode": state.config.dod_mode,
        "certProfiles": state.config.cert_profiles,
        "ccsaOptions": state.config.ccsa_options,
        "estBaseUrl": state.config.est_base_url,
        "sessionIdleSeconds": state.config.session.inactivity_timeout_secs,
        "version": env!("CARGO_PKG_VERSION"),
        "basename": "/",
    });
    let config_json = match serde_json::to_string(&config) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize NPE console config");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error").into_response();
        }
    };

    let injected = format!(
        "<script nonce=\"{}\">window.__OSTRICH_NPE_CONFIG__ = {};</script></head>",
        nonce.value(),
        config_json
    );
    let html = template.replacen("</head>", &injected, 1);
    Html(html).into_response()
}
