//! NPE Portal configuration.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-2 (Baseline Configuration), CM-6 (Configuration Settings)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration for the NPE Portal service.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpePortalConfig {
    /// Backend service URLs for the allowlisted API proxy.
    pub backend: BackendConfig,

    /// Session configuration (mTLS-minted server-side sessions).
    #[serde(default)]
    pub session: SessionConfig,

    /// Certificate OID -> NPE role mapping.
    #[serde(default)]
    pub oid_mapping: super::oid::OidRoleMapping,

    /// Classification banner shown across the portal (e.g. "CUI").
    #[serde(default = "default_classification")]
    pub classification_banner: String,

    /// Content Security Policy nonce length in bytes.
    #[serde(default = "default_nonce_length")]
    pub csp_nonce_length: usize,

    /// Static file serving configuration.
    #[serde(default)]
    pub static_files: StaticFilesConfig,
}

fn default_classification() -> String {
    "UNCLASSIFIED//FOR OFFICIAL USE ONLY".to_string()
}

fn default_nonce_length() -> usize {
    16 // 128 bits
}

/// Backend service URLs for API proxying.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendConfig {
    /// CA service URL (certificate applications, approvals, CA details).
    pub ca_url: String,

    /// EST service URL (RFC 7030 enrollment, password/token management).
    #[serde(default = "default_est_url")]
    pub est_url: String,
}

fn default_est_url() -> String {
    "http://localhost:8087".to_string()
}

/// Session management configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    /// Session cookie name.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Inactivity timeout in seconds. The NPE portal requirements mandate a
    /// 30-minute inactivity logout (NIAP PP-CA FTA_SSL.1 / NIST AC-12).
    #[serde(default = "default_inactivity_timeout")]
    pub inactivity_timeout_secs: i64,

    /// Absolute session timeout in seconds.
    #[serde(default = "default_absolute_timeout")]
    pub absolute_timeout_secs: i64,

    /// Whether cookies should be marked Secure (HTTPS only).
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
}

fn default_cookie_name() -> String {
    "ostrich_npe_session".to_string()
}

fn default_inactivity_timeout() -> i64 {
    1800 // 30 minutes (NPE portal requirement; NIAP PP-CA FTA_SSL.1)
}

fn default_absolute_timeout() -> i64 {
    28800 // 8 hours
}

fn default_secure_cookies() -> bool {
    true
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: default_cookie_name(),
            inactivity_timeout_secs: default_inactivity_timeout(),
            absolute_timeout_secs: default_absolute_timeout(),
            secure_cookies: default_secure_cookies(),
        }
    }
}

/// Static file serving configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticFilesConfig {
    /// Directory containing the compiled SPA assets.
    #[serde(default = "default_static_dir")]
    pub directory: String,

    /// URL path prefix for static files.
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

impl NpePortalConfig {
    /// Load configuration from a JSON file, falling back to defaults if absent.
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
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

impl Default for NpePortalConfig {
    fn default() -> Self {
        Self {
            backend: BackendConfig {
                ca_url: "http://localhost:8081".to_string(),
                est_url: default_est_url(),
            },
            session: SessionConfig::default(),
            oid_mapping: super::oid::OidRoleMapping::default(),
            classification_banner: default_classification(),
            csp_nonce_length: default_nonce_length(),
            static_files: StaticFilesConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_inactivity_is_30_minutes() {
        let config = NpePortalConfig::default();
        assert_eq!(config.session.inactivity_timeout_secs, 1800);
    }

    #[test]
    fn test_deserialize_minimal_config() {
        let json = r#"{
            "backend": { "caUrl": "https://ca.internal:8081" }
        }"#;
        let config: NpePortalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.backend.ca_url, "https://ca.internal:8081");
        // Defaults applied.
        assert_eq!(config.session.inactivity_timeout_secs, 1800);
        assert_eq!(config.session.cookie_name, "ostrich_npe_session");
    }
}
