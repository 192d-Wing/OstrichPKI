//! Template Rendering with CSP Nonce Injection
//!
//! Serves the React (AWS Cloudscape) console's index.html with dynamic CSP-nonce
//! and runtime-config injection. The console is the primary app, mounted at `/`.
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

/// Serve the React console index with CSP-nonce + runtime-config injection.
///
/// The Vite-built `index.html` loads its module script + stylesheet from
/// same-origin `/static/assets/*`, already permitted by the CSP `'self'` source,
/// so ONLY the injected inline config script needs the per-request nonce. The
/// app mounts at `/` (basename `/`); the client router resolves deep links, so
/// this same handler answers `/` and every unmatched path.
pub async fn serve_index(
    State(state): State<AppState>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    // The Vite build's index.html is copied next to the static assets at build
    // time (see services/web-ui/Dockerfile).
    let path = std::path::Path::new(&state.config.static_files.directory).join("index.html");
    let template = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "Console index.html not found");
            return (
                StatusCode::NOT_FOUND,
                "Web console not built for this image",
            )
                .into_response();
        }
    };

    // Runtime config the React app reads from window.__OSTRICH_CONFIG__.
    let config = serde_json::json!({
        "apiBaseUrl": "/api",
        "oidcClientId": state.config.oidc.client_id,
        "oidcAuthUrl": format!(
            "{}/protocol/openid-connect/auth",
            state.config.oidc.issuer_url
        ),
        "appName": "OstrichPKI",
        "version": env!("CARGO_PKG_VERSION"),
        "basename": "/",
    });
    let config_json = match serde_json::to_string(&config) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize console config");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error").into_response();
        }
    };

    // Inject the nonced config script just before </head> so it runs before the
    // deferred module script reads window.__OSTRICH_CONFIG__.
    let injected = format!(
        "<script nonce=\"{}\">window.__OSTRICH_CONFIG__ = {};</script></head>",
        nonce.value(),
        config_json
    );
    let html = template.replacen("</head>", &injected, 1);

    Html(html).into_response()
}
