//! Web UI Configuration
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-2 (Baseline Configuration)
//! - NIST 800-53: CM-6 (Configuration Settings)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration for the Web UI service
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebUiConfig {
    /// OIDC/OAuth configuration for Keycloak
    pub oidc: OidcConfig,

    /// Backend service URLs for API proxying
    pub backend: BackendConfig,

    /// Session configuration
    pub session: SessionConfig,

    /// Content Security Policy configuration
    pub csp: CspConfig,

    /// Static file serving configuration
    pub static_files: StaticFilesConfig,
}

/// OAuth/OIDC configuration for Keycloak integration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    /// OIDC Issuer URL (e.g., https://keycloak.example.com/realms/ostrich)
    pub issuer_url: String,

    /// OAuth Client ID
    pub client_id: String,

    /// OAuth Client Secret (optional for public clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Redirect URI for OAuth callback
    pub redirect_uri: String,

    /// OAuth scopes to request
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,

    /// Claim name for extracting roles from ID token
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_roles_claim() -> String {
    "realm_access.roles".to_string()
}

/// Backend service URLs for API proxying
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendConfig {
    /// CA service URL
    pub ca_url: String,

    /// ACME service URL
    pub acme_url: String,

    /// OCSP service URL
    pub ocsp_url: String,

    /// SCMS service URL
    pub scms_url: String,

    /// KRA service URL
    pub kra_url: String,

    /// Audit service URL (or database connection)
    pub audit_url: String,
}

/// Session management configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    /// Session cookie name
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Session inactivity timeout in seconds (default: 15 minutes)
    #[serde(default = "default_inactivity_timeout")]
    pub inactivity_timeout_secs: i64,

    /// Session absolute timeout in seconds (default: 8 hours)
    #[serde(default = "default_absolute_timeout")]
    pub absolute_timeout_secs: i64,

    /// Whether cookies should be marked as secure (HTTPS only)
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
}

fn default_cookie_name() -> String {
    "ostrich_session".to_string()
}

fn default_inactivity_timeout() -> i64 {
    900 // 15 minutes (NIAP PP-CA FTA_SSL.1 requirement)
}

fn default_absolute_timeout() -> i64 {
    28800 // 8 hours
}

fn default_secure_cookies() -> bool {
    true
}

/// Content Security Policy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CspConfig {
    /// Nonce length in bytes (default: 16 = 128 bits)
    #[serde(default = "default_nonce_length")]
    pub nonce_length: usize,

    /// Additional allowed script sources
    #[serde(default)]
    pub additional_script_src: Vec<String>,

    /// Additional allowed style sources
    #[serde(default)]
    pub additional_style_src: Vec<String>,

    /// Additional allowed connect sources (for API calls)
    #[serde(default)]
    pub additional_connect_src: Vec<String>,
}

fn default_nonce_length() -> usize {
    16 // 128 bits
}

impl Default for CspConfig {
    fn default() -> Self {
        Self {
            nonce_length: default_nonce_length(),
            additional_script_src: Vec::new(),
            additional_style_src: Vec::new(),
            additional_connect_src: Vec::new(),
        }
    }
}

/// Static file serving configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticFilesConfig {
    /// Directory containing compiled WASM and static assets
    #[serde(default = "default_static_dir")]
    pub directory: String,

    /// URL path prefix for static files
    #[serde(default = "default_static_prefix")]
    pub url_prefix: String,
}

fn default_static_dir() -> String {
    "dist".to_string()
}

fn default_static_prefix() -> String {
    "/static".to_string()
}

impl Default for StaticFilesConfig {
    fn default() -> Self {
        Self {
            directory: default_static_dir(),
            url_prefix: default_static_prefix(),
        }
    }
}

impl WebUiConfig {
    /// Load configuration from a JSON file
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Check if file exists
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "Configuration file not found, using defaults"
            );
            return Ok(Self::default());
        }

        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            oidc: OidcConfig {
                issuer_url: "http://localhost:8081/realms/ostrich".to_string(),
                client_id: "ostrich-web-ui".to_string(),
                client_secret: None,
                redirect_uri: "http://localhost:8080/auth/callback".to_string(),
                scopes: default_scopes(),
                roles_claim: default_roles_claim(),
            },
            backend: BackendConfig {
                ca_url: "http://localhost:8081".to_string(),
                acme_url: "http://localhost:8082".to_string(),
                ocsp_url: "http://localhost:8083".to_string(),
                scms_url: "http://localhost:8084".to_string(),
                kra_url: "http://localhost:8085".to_string(),
                audit_url: "http://localhost:8086".to_string(),
            },
            session: SessionConfig {
                cookie_name: default_cookie_name(),
                inactivity_timeout_secs: default_inactivity_timeout(),
                absolute_timeout_secs: default_absolute_timeout(),
                secure_cookies: false, // Development default
            },
            csp: CspConfig::default(),
            static_files: StaticFilesConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WebUiConfig::default();
        assert_eq!(config.session.inactivity_timeout_secs, 900);
        assert_eq!(config.csp.nonce_length, 16);
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "oidc": {
                "issuerUrl": "https://keycloak.example.com/realms/ostrich",
                "clientId": "web-ui",
                "redirectUri": "https://pki.example.com/auth/callback"
            },
            "backend": {
                "caUrl": "https://ca.internal:8080",
                "acmeUrl": "https://acme.internal:8080",
                "ocspUrl": "https://ocsp.internal:8080",
                "scmsUrl": "https://scms.internal:8080",
                "kraUrl": "https://kra.internal:8080",
                "auditUrl": "https://audit.internal:8080"
            },
            "session": {
                "cookieName": "session",
                "inactivityTimeoutSecs": 600,
                "absoluteTimeoutSecs": 14400,
                "secureCookies": true
            },
            "csp": {
                "nonceLength": 32
            },
            "staticFiles": {
                "directory": "/var/www/ostrich",
                "urlPrefix": "/static"
            }
        }"#;

        let config: WebUiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.oidc.issuer_url,
            "https://keycloak.example.com/realms/ostrich"
        );
        assert_eq!(config.session.inactivity_timeout_secs, 600);
        assert_eq!(config.csp.nonce_length, 32);
    }
}
