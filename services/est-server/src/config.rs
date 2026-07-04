//! JSON configuration file support for the EST server.
//!
//! Settings may be supplied via a JSON config file (`--config <path>`), CLI
//! flags, or environment variables. Precedence is: CLI flag / env var > config
//! file > built-in default. The config file is validated against an embedded
//! JSON Schema before use, so a malformed or unknown key fails fast at startup.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-2 (baseline configuration), CM-6 (configuration settings)
//! - NIAP PP-CA: FMT_SMF.1 (security management function)

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::Path;

/// JSON Schema for the EST server config, embedded at compile time.
const EST_CONFIG_SCHEMA: &str = include_str!("../../../config/schema/est-server.schema.json");

/// EST server configuration as read from a JSON file.
///
/// Every field is optional: a field absent from the file falls back to the CLI
/// flag / env var, and finally to the built-in default. Field names are
/// camelCase to match the rest of the OstrichPKI configuration files.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileConfig {
    /// Optional `$schema` reference for editor support (ignored at runtime).
    #[serde(rename = "$schema", default)]
    #[allow(dead_code)]
    pub schema: Option<String>,

    pub bind_address: Option<String>,
    pub mtls_bind_address: Option<String>,
    pub database_url: Option<String>,

    pub ca_grpc_url: Option<String>,
    pub ca_grpc_client_cert: Option<String>,
    pub ca_grpc_client_key: Option<String>,
    pub ca_grpc_ca_cert: Option<String>,
    pub ca_insecure: Option<bool>,

    pub enroll_profile: Option<String>,
    pub enroll_identity_policy: Option<String>,

    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_ca_cert: Option<String>,

    pub allow_basic_auth: Option<bool>,
    pub allow_bearer_auth: Option<bool>,
    pub mtls_token_bootstrap: Option<bool>,

    /// Named CA backends for RFC 7030 §3.2.2 label-routed enrollment.
    pub ca_backends: Option<Vec<CaBackendFileConfig>>,
    /// Label -> CA-backend routing. Enables the `/{label}/...` paths.
    pub label_routing: Option<LabelRoutingFileConfig>,

    pub log_level: Option<String>,
    pub log_json: Option<bool>,
}

/// One named CA backend for label-routed enrollment.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaBackendFileConfig {
    /// Backend name, referenced by `labelRouting`.
    pub name: String,
    /// CA gRPC endpoint for this backend.
    pub grpc_url: String,
    /// mTLS client certificate (PEM path) for this backend's gRPC channel.
    pub client_cert: Option<String>,
    /// mTLS client private key (PEM path).
    pub client_key: Option<String>,
    /// CA certificate (PEM path) verifying this backend's gRPC server.
    pub ca_cert: Option<String>,
    /// UUID of this backend's issuing CA certificate, served by `/{label}/cacerts`.
    pub ca_certificate_id: Option<String>,
}

/// Label -> CA-backend routing.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabelRoutingFileConfig {
    /// Key-algorithm token (`2048`, `P384`) -> backend name.
    #[serde(default)]
    pub algo_backends: std::collections::HashMap<String, String>,
    /// Backend used when a label carries no key-algorithm token.
    pub default_backend: String,
}

impl FileConfig {
    /// Load and schema-validate a JSON config file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        Self::from_json(&contents)
            .with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Parse JSON config text, validating it against the embedded schema first.
    pub fn from_json(json: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(json).context("config is not valid JSON")?;

        let schema: serde_json::Value = serde_json::from_str(EST_CONFIG_SCHEMA)
            .context("embedded EST config schema is invalid")?;
        let validator =
            jsonschema::validator_for(&schema).context("failed to compile EST config schema")?;

        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("{}: {}", e.instance_path(), e))
            .collect();
        if !errors.is_empty() {
            bail!(
                "config failed schema validation:\n  - {}",
                errors.join("\n  - ")
            );
        }

        serde_json::from_value(value).context("failed to deserialize config")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_valid_config() {
        let cfg = FileConfig::from_json(
            r#"{ "bindAddress": "0.0.0.0:8443", "databaseUrl": "postgres://x/y" }"#,
        )
        .unwrap();
        assert_eq!(cfg.bind_address.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://x/y"));
        assert_eq!(cfg.allow_basic_auth, None);
    }

    #[test]
    fn accepts_the_schema_reference_key() {
        let cfg =
            FileConfig::from_json(r#"{ "$schema": "./est-server.schema.json", "logJson": true }"#)
                .unwrap();
        assert_eq!(cfg.log_json, Some(true));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = FileConfig::from_json(r#"{ "bogusKey": 1 }"#).unwrap_err();
        assert!(format!("{err:#}").contains("schema validation"));
    }

    #[test]
    fn rejects_invalid_identity_policy() {
        let err = FileConfig::from_json(r#"{ "enrollIdentityPolicy": "wide-open" }"#).unwrap_err();
        assert!(format!("{err:#}").contains("schema validation"));
    }

    #[test]
    fn rejects_wrong_type() {
        let err = FileConfig::from_json(r#"{ "allowBasicAuth": "yes" }"#).unwrap_err();
        assert!(format!("{err:#}").contains("schema validation"));
    }

    #[test]
    fn parses_multi_ca_backends_and_label_routing() {
        let cfg = FileConfig::from_json(
            r#"{
                "databaseUrl": "postgres://x/y",
                "caBackends": [
                    { "name": "ec",  "grpcUrl": "https://ca-ec:50051" },
                    { "name": "rsa", "grpcUrl": "https://ca-rsa:50051", "caCertificateId": "00000000-0000-0000-0000-000000000001" }
                ],
                "labelRouting": {
                    "algoBackends": { "P384": "ec", "2048": "rsa" },
                    "defaultBackend": "ec"
                }
            }"#,
        )
        .unwrap();
        let backends = cfg.ca_backends.unwrap();
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].name, "ec");
        let lr = cfg.label_routing.unwrap();
        assert_eq!(lr.default_backend, "ec");
        assert_eq!(
            lr.algo_backends.get("2048").map(String::as_str),
            Some("rsa")
        );
    }

    #[test]
    fn rejects_ca_backend_missing_name() {
        let err =
            FileConfig::from_json(r#"{ "caBackends": [ { "grpcUrl": "https://ca:50051" } ] }"#)
                .unwrap_err();
        assert!(format!("{err:#}").contains("schema validation"));
    }

    #[test]
    fn the_example_file_is_valid() {
        let example = include_str!("../../../config/est_server.example.json");
        FileConfig::from_json(example).expect("est_server.example.json must validate");
    }
}
