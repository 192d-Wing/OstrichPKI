//! Template Rendering with CSP Nonce Injection
//!
//! This module handles serving the index.html template with dynamic
//! CSP nonce injection for secure inline scripts and styles.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-18 (Mobile Code) - Safe template injection
//! - NIST 800-53: SI-10 (Information Input Validation) - Template escaping

use axum::{
    extract::{Extension, State},
    response::{Html, IntoResponse, Response},
    http::StatusCode,
};
use serde::Serialize;

use super::{middleware::CspNonce, router::AppState};

/// Client-side configuration passed to the Yew app
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientConfig {
    /// Base URL for API calls
    pub api_base_url: String,

    /// OIDC client ID (for PKCE flow initialization)
    pub oidc_client_id: String,

    /// OIDC authorization endpoint
    pub oidc_auth_url: String,

    /// Application name
    pub app_name: String,

    /// Version
    pub version: String,
}

/// Serve the index.html template with CSP nonce injection
///
/// This handler:
/// 1. Reads the compiled index.html template
/// 2. Injects the CSP nonce into script and style tags
/// 3. Injects client configuration as a JSON object
pub async fn serve_index(
    State(state): State<AppState>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    // In production, this would read from the dist directory
    // For now, use an embedded template
    let template = get_index_template();

    // Build client config
    let client_config = ClientConfig {
        api_base_url: "/api".to_string(),
        oidc_client_id: state.config.oidc.client_id.clone(),
        oidc_auth_url: format!("{}/protocol/openid-connect/auth", state.config.oidc.issuer_url),
        app_name: "OstrichPKI".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Serialize config (escape for safe injection)
    let config_json = match serde_json::to_string(&client_config) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize client config");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error").into_response();
        }
    };

    // Inject nonce and config into template
    let html = template
        .replace("{{CSP_NONCE}}", nonce.value())
        .replace("{{CONFIG_JSON}}", &config_json);

    Html(html).into_response()
}

/// Get the index.html template
///
/// In development, this returns an embedded template.
/// In production, this would read from the dist directory.
fn get_index_template() -> String {
    // This template is designed for Yew WASM applications
    // The CSP nonce ensures only scripts with the nonce can execute
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="OstrichPKI Administration Interface" />
    <title>OstrichPKI Admin</title>

    <!-- Tailwind CSS (compiled) -->
    <link rel="stylesheet" href="/static/output.css" nonce="{{CSP_NONCE}}" />

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg" />
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Loading indicator shown while WASM loads -->
    <div id="loading" class="fixed inset-0 flex items-center justify-center bg-gray-100">
        <div class="text-center">
            <div class="inline-block animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent"></div>
            <p class="mt-4 text-gray-600">Loading OstrichPKI...</p>
        </div>
    </div>

    <!-- Yew app mounts here -->
    <div id="app"></div>

    <!-- Client configuration (injected by server) -->
    <script nonce="{{CSP_NONCE}}">
        window.__OSTRICH_CONFIG__ = {{CONFIG_JSON}};

        // Hide loading indicator when app starts
        window.addEventListener('ostrich:ready', function() {
            document.getElementById('loading').style.display = 'none';
        });
    </script>

    <!-- Yew WASM application -->
    <script type="module" nonce="{{CSP_NONCE}}">
        import init from '/static/ostrich-web-ui.js';

        async function run() {
            try {
                await init('/static/ostrich-web-ui_bg.wasm');
                // Dispatch ready event
                window.dispatchEvent(new Event('ostrich:ready'));
            } catch (e) {
                console.error('Failed to load WASM:', e);
                document.getElementById('loading').innerHTML =
                    '<div class="text-center text-red-600">' +
                    '<p class="text-lg font-semibold">Failed to load application</p>' +
                    '<p class="mt-2">Please refresh the page or contact support.</p>' +
                    '</div>';
            }
        }

        run();
    </script>

    <!-- No-script fallback -->
    <noscript>
        <div class="fixed inset-0 flex items-center justify-center bg-gray-100">
            <div class="text-center p-8 bg-white rounded-lg shadow-lg">
                <h1 class="text-xl font-bold text-gray-900">JavaScript Required</h1>
                <p class="mt-2 text-gray-600">
                    OstrichPKI requires JavaScript to be enabled.
                    Please enable JavaScript in your browser settings.
                </p>
            </div>
        </div>
    </noscript>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_contains_placeholders() {
        let template = get_index_template();
        assert!(template.contains("{{CSP_NONCE}}"));
        assert!(template.contains("{{CONFIG_JSON}}"));
    }

    #[test]
    fn test_template_nonce_replacement() {
        let template = get_index_template();
        let nonce = "test-nonce-12345";
        let result = template.replace("{{CSP_NONCE}}", nonce);

        assert!(result.contains(&format!("nonce=\"{nonce}\"")));
        assert!(!result.contains("{{CSP_NONCE}}"));
    }

    #[test]
    fn test_client_config_serialization() {
        let config = ClientConfig {
            api_base_url: "/api".to_string(),
            oidc_client_id: "test-client".to_string(),
            oidc_auth_url: "https://auth.example.com/auth".to_string(),
            app_name: "OstrichPKI".to_string(),
            version: "0.1.0".to_string(),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("apiBaseUrl"));
        assert!(json.contains("oidcClientId"));
    }
}
