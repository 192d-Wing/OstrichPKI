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

    /// Classification banner text shown across the portal (e.g. "CUI",
    /// "SECRET", "TOP SECRET//SCI"). The banner color is derived from this text
    /// per the DoD/IC standard palette unless `classification_color` overrides
    /// it.
    #[serde(default = "default_classification")]
    pub classification_banner: String,

    /// Optional explicit banner background color (CSS color, e.g. "#502b85").
    /// When unset, the color is derived from `classification_banner` using the
    /// standard mapping (CUI=purple, Confidential=blue, Secret=red, Top
    /// Secret=orange, Top Secret//SCI=yellow, Unclassified=green). Set this only
    /// for a non-standard banner whose text the mapping cannot classify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_color: Option<String>,

    /// Content Security Policy nonce length in bytes.
    #[serde(default = "default_nonce_length")]
    pub csp_nonce_length: usize,

    /// Static file serving configuration.
    #[serde(default)]
    pub static_files: StaticFilesConfig,

    /// ACME client: when set, the portal auto-enrolls + renews its own TLS
    /// server certificate (RFC 8555, HTTP-01) instead of using a static
    /// `TLS_CERT_FILE`/`TLS_KEY_FILE`.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,

    /// DoD deployment mode. Enables DoD-specific UI — currently the CC/S/A
    /// (Combatant Command / Service / Agency) selector on the submit form,
    /// which is hidden when this is false.
    #[serde(default)]
    pub dod_mode: bool,

    /// Certificate profiles offered on the submit form. Configurable here so the
    /// catalog is deployment-controlled (this configmap) rather than hardcoded.
    #[serde(default = "default_cert_profiles")]
    pub cert_profiles: Vec<CertProfileConfig>,

    /// CC/S/A option groups for the submit form's selector. Shown only when
    /// `dod_mode` is true. Deployment-controlled (this configmap).
    #[serde(default = "default_ccsa_options")]
    pub ccsa_options: Vec<CcsaGroupConfig>,

    /// Public base URL of the EST server (e.g. `https://est.example.mil`), used
    /// to pre-fill the enrollment commands on the EST catalog page. When unset,
    /// the page derives a best-guess from the browser host (editable there).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est_base_url: Option<String>,
}

/// A selectable certificate profile on the submit form.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertProfileConfig {
    /// Display label.
    pub label: String,
    /// Profile identifier sent to the CA.
    pub value: String,
    /// Server-side key generation flow (EFS): no CSR is required; the server
    /// generates the key and returns a one-time PKCS#12.
    #[serde(default)]
    pub efs: bool,
    /// Carries the id-kp-serverAuth EKU, which drives the 397-day validity
    /// advisory on the form.
    #[serde(default)]
    pub server_auth: bool,
}

/// A CC/S/A option group (e.g. "Military Services").
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CcsaGroupConfig {
    pub label: String,
    pub options: Vec<CcsaOptionConfig>,
}

/// A single CC/S/A option.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CcsaOptionConfig {
    pub label: String,
    pub value: String,
}

fn default_cert_profiles() -> Vec<CertProfileConfig> {
    vec![
        CertProfileConfig {
            label: "TLS Client".into(),
            value: "tls_client".into(),
            efs: false,
            server_auth: false,
        },
        CertProfileConfig {
            label: "TLS Server".into(),
            value: "tls_server".into(),
            efs: false,
            server_auth: true,
        },
        CertProfileConfig {
            label: "TLS Server + Client".into(),
            value: "tls_server_client".into(),
            efs: false,
            server_auth: true,
        },
        CertProfileConfig {
            label: "EFS (File Encryption)".into(),
            value: "efs".into(),
            efs: true,
            server_auth: false,
        },
    ]
}

fn ccsa_group(label: &str, opts: &[(&str, &str)]) -> CcsaGroupConfig {
    CcsaGroupConfig {
        label: label.into(),
        options: opts
            .iter()
            .map(|(l, v)| CcsaOptionConfig { label: (*l).into(), value: (*v).into() })
            .collect(),
    }
}

fn default_ccsa_options() -> Vec<CcsaGroupConfig> {
    vec![
        ccsa_group(
            "Military Services",
            &[
                ("Air Force (USAF)", "USAF"),
                ("Army (USA)", "USA"),
                ("Navy (USN)", "USN"),
                ("Marine Corps (USMC)", "USMC"),
                ("Space Force (USSF)", "USSF"),
                ("Coast Guard (USCG)", "USCG"),
            ],
        ),
        ccsa_group(
            "Combatant Commands",
            &[
                ("AFRICOM", "AFRICOM"),
                ("CENTCOM", "CENTCOM"),
                ("CYBERCOM", "CYBERCOM"),
                ("EUCOM", "EUCOM"),
                ("INDOPACOM", "INDOPACOM"),
                ("NORTHCOM", "NORTHCOM"),
                ("SOCOM", "SOCOM"),
                ("SOUTHCOM", "SOUTHCOM"),
                ("SPACECOM", "SPACECOM"),
                ("STRATCOM", "STRATCOM"),
                ("TRANSCOM", "TRANSCOM"),
            ],
        ),
        ccsa_group(
            "Agencies & Field Activities",
            &[
                ("DISA", "DISA"),
                ("DLA", "DLA"),
                ("DIA", "DIA"),
                ("NSA", "NSA"),
                ("NGA", "NGA"),
                ("DCSA", "DCSA"),
                ("DCMA", "DCMA"),
                ("DFAS", "DFAS"),
                ("DHA", "DHA"),
                ("DTRA", "DTRA"),
                ("MDA", "MDA"),
                ("OSD / WHS", "OSD"),
            ],
        ),
    ]
}

/// ACME client configuration (RFC 8555). The portal obtains its server cert
/// from an ACME directory using the HTTP-01 challenge.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeConfig {
    /// ACME directory URL (e.g. `https://acme.oopl.dev.mil/acme/directory`).
    pub directory_url: String,

    /// Domains to request on the certificate. The first is the primary CN; all
    /// become Subject Alternative Names. Each is validated via HTTP-01.
    pub domains: Vec<String>,

    /// Optional account contact (e.g. `mailto:pki@example.mil`).
    #[serde(default)]
    pub contact: Option<String>,

    /// PEM bundle of CA certificate(s) to trust for the ACME directory's own
    /// HTTPS endpoint (the OstrichPKI ACME server presents a private-CA cert, so
    /// the public web PKI roots would reject it).
    #[serde(default)]
    pub ca_bundle: Option<String>,

    /// Local port the HTTP-01 challenge responder listens on. The ACME server
    /// validates by fetching `http://<domain>:<port>/.well-known/acme-challenge/`.
    #[serde(default = "default_acme_challenge_port")]
    pub challenge_port: u16,

    /// Renew the certificate once it is within this many days of expiry.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: i64,

    /// Directory to cache the issued cert/key (and ACME account) across restarts.
    /// When unset the portal re-enrolls on every start.
    #[serde(default)]
    pub cache_dir: Option<String>,
}

fn default_acme_challenge_port() -> u16 {
    80
}

fn default_renew_before_days() -> i64 {
    30
}

fn default_classification() -> String {
    "CUI".to_string()
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

    /// OCSP responder URL (RFC 6960) for the certificate revocation-status
    /// checker. The responder is public (no auth); the proxy just forwards the
    /// DER OCSP request/response.
    #[serde(default = "default_ocsp_url")]
    pub ocsp_url: String,

    /// Client certificate (PEM) the portal presents to the CA/EST backends so
    /// they can verify it and trust the forwarded X-Npe-* identity (the identity
    /// bridge). When set with `mtls_client_key` + `mtls_ca_cert`, the proxy dials
    /// the backends over mTLS; otherwise it uses plain HTTP (development).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_client_cert: Option<String>,
    /// Client private key (PEM) for the backend mTLS channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_client_key: Option<String>,
    /// CA bundle (PEM) used to verify the CA/EST server certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_ca_cert: Option<String>,
}

fn default_est_url() -> String {
    "http://localhost:8087".to_string()
}

fn default_ocsp_url() -> String {
    "http://localhost:8081".to_string()
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
                ocsp_url: default_ocsp_url(),
                mtls_client_cert: None,
                mtls_client_key: None,
                mtls_ca_cert: None,
            },
            session: SessionConfig::default(),
            oid_mapping: super::oid::OidRoleMapping::default(),
            classification_banner: default_classification(),
            classification_color: None,
            dod_mode: false,
            cert_profiles: default_cert_profiles(),
            ccsa_options: default_ccsa_options(),
            est_base_url: None,
            csp_nonce_length: default_nonce_length(),
            static_files: StaticFilesConfig::default(),
            acme: None,
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
