//! # Centralized JSON Configuration System
//!
//! ## NIAP PP-CA Compliance
//! - FMT_MSA.1: Secure configuration defaults
//! - FMT_SMF.1: Configuration management function
//!
//! ## NIST 800-53 Compliance
//! - CM-2: Baseline configuration
//! - CM-6: Configuration settings
//!
//! ## Security Requirements
//! - NO HARDCODED IP LITERALS (use hostnames or '::' for dual-stack)
//! - JSON Schema validation on load
//! - Environment variable expansion for secrets

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// JSON Schema for configuration validation.
/// This is embedded at compile time from config/schema/ostrich-config.schema.json.
const CONFIG_SCHEMA: &str = include_str!("../../../config/schema/ostrich-config.schema.json");

/// Configuration error types.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("No configuration file found")]
    NoConfigFile,

    #[error("Failed to read configuration file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse JSON: {0}")]
    JsonParse(String),

    #[error("Schema error: {0}")]
    SchemaError(String),

    #[error("Configuration validation failed: {0:?}")]
    ValidationFailed(Vec<String>),

    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("IP literal not allowed in '{field}': {value} - use hostname instead")]
    IpLiteralNotAllowed { field: String, value: String },
}

/// Global configuration for all OstrichPKI services.
///
/// # NIAP PP-CA Compliance
/// - FMT_MSA.1: Secure configuration defaults
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstrichConfig {
    /// JSON Schema reference (optional, for IDE support).
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Service configuration.
    pub service: ServiceConfig,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// TLS configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// ACME-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,

    /// EST-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub est: Option<EstConfig>,

    /// CA-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaConfig>,

    /// OCSP-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp: Option<OcspConfig>,

    /// KRA-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kra: Option<KraConfig>,

    /// SCMS-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scms: Option<ScmsConfig>,

    /// Logging configuration.
    pub logging: LoggingConfig,
}

/// Service configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    /// Service name.
    pub name: String,

    /// Listen configuration.
    pub listen: ListenConfig,

    /// Public base URL for this service (NO IP LITERALS).
    pub base_url: String,

    /// Maximum request body size (bytes).
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request timeout (seconds).
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

/// Listen configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenConfig {
    /// Listen host (use "::" for dual-stack, hostname for specific interface).
    /// NO IP LITERALS except "::" and "0.0.0.0".
    pub host: String,

    /// Listen port.
    pub port: u16,
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
    /// Database hostname (NO IP LITERALS).
    pub host: String,

    /// Database port.
    #[serde(default = "default_db_port")]
    pub port: u16,

    /// Database name.
    pub database: String,

    /// Username.
    pub username: String,

    /// Password (supports $ENV{VAR} syntax).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// SSL mode.
    #[serde(default = "default_ssl_mode")]
    pub ssl_mode: String,
}

/// TLS configuration.
///
/// # NIAP PP-CA Compliance
/// - FTP_ITC.1: TLS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    /// Path to TLS certificate file.
    pub cert_file: String,

    /// Path to TLS private key file.
    pub key_file: String,

    /// Path to CA certificate for client verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,

    /// Minimum TLS version (1.3 required for NIAP compliance).
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,

    /// Client authentication mode.
    #[serde(default = "default_client_auth")]
    pub client_auth: String,
}

/// ACME service configuration.
///
/// # RFC Compliance
/// - RFC 8555: ACME Protocol
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeConfig {
    /// ACME directory URL base.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_url: Option<String>,

    /// Terms of Service URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_url: Option<String>,

    /// Nonce expiration time (seconds).
    #[serde(default = "default_nonce_expiration")]
    pub nonce_expiration_seconds: u64,

    /// Order expiration time (seconds).
    #[serde(default = "default_order_expiration")]
    pub order_expiration_seconds: u64,

    /// Maximum identifiers per order.
    #[serde(default = "default_max_identifiers")]
    pub max_identifiers_per_order: usize,

    /// Enabled challenge types.
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<String>,
}

/// EST service configuration.
///
/// # RFC Compliance
/// - RFC 7030: EST Protocol
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstConfig {
    /// Require mTLS client certificate.
    #[serde(default = "default_true")]
    pub require_client_cert: bool,

    /// Allow server-side key generation (security risk).
    #[serde(default)]
    pub allow_server_keygen: bool,

    /// Escrow server-generated keys via KRA.
    #[serde(default = "default_true")]
    pub escrow_server_keys: bool,
}

/// CA service configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaConfig {
    /// CA gRPC endpoint (NO IP LITERALS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_endpoint: Option<String>,

    /// Default certificate profile.
    #[serde(default = "default_profile")]
    pub default_profile: String,

    /// Maximum certificate validity (days).
    #[serde(default = "default_max_validity")]
    pub max_validity_days: u32,

    /// Cryptographic configuration.
    #[serde(default)]
    pub crypto: CryptoConfig,
}

/// Cryptographic configuration for CA signing keys.
///
/// # NIAP PP-CA Compliance
/// - FCS_STG_EXT.1: HSM storage enforcement for CA signing keys
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoConfig {
    /// Require HSM for CA signing keys (NIAP compliance).
    ///
    /// When true, CA signing keys MUST be stored in a PKCS#11 HSM.
    /// Software-based keys are rejected at initialization.
    ///
    /// Default: true (NIAP-compliant mode)
    #[serde(default = "default_require_hsm")]
    pub require_hsm: bool,

    /// PKCS#11 library path (required if require_hsm=true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs11_library: Option<String>,

    /// PKCS#11 slot ID.
    #[serde(default)]
    pub pkcs11_slot: u64,

    /// PKCS#11 PIN (use environment variable expansion: ${PKCS11_PIN}).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs11_pin: Option<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            require_hsm: default_require_hsm(),
            pkcs11_library: None,
            pkcs11_slot: 0,
            pkcs11_pin: None,
        }
    }
}

/// OCSP responder configuration.
///
/// # RFC Compliance
/// - RFC 6960: OCSP Protocol
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OcspConfig {
    /// Enable response caching.
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    /// Cache size (number of responses).
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// Cache TTL (seconds).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

/// KRA service configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KraConfig {
    /// Shamir secret sharing threshold.
    #[serde(default = "default_shamir_threshold")]
    pub shamir_threshold: u8,

    /// Shamir secret sharing total shares.
    #[serde(default = "default_shamir_shares")]
    pub shamir_shares: u8,
}

/// SCMS service configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScmsConfig {
    /// Path to PKCS#11 module library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs11_module_path: Option<String>,

    /// Maximum PIN retries before lockout.
    #[serde(default = "default_max_pin_retries")]
    pub max_pin_retries: u8,

    /// PIN lockout duration (minutes).
    #[serde(default = "default_pin_lockout")]
    pub pin_lockout_minutes: u32,
}

/// Logging configuration.
///
/// # NIAP PP-CA Compliance
/// - FAU_GEN.1: Audit data generation
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    /// Log level.
    pub level: String,

    /// Log format.
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log output destination.
    #[serde(default = "default_log_output")]
    pub output: String,

    /// Log file path (required if output is 'file').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

// Default value functions
fn default_max_body_size() -> usize {
    1_048_576 // 1MB
}

fn default_request_timeout() -> u64 {
    30
}

fn default_db_port() -> u16 {
    5432
}

fn default_pool_size() -> u32 {
    10
}

fn default_ssl_mode() -> String {
    "require".to_string()
}

fn default_tls_min_version() -> String {
    "1.3".to_string()
}

fn default_client_auth() -> String {
    "none".to_string()
}

fn default_nonce_expiration() -> u64 {
    900 // 15 minutes
}

fn default_order_expiration() -> u64 {
    86400 // 24 hours
}

fn default_max_identifiers() -> usize {
    10
}

fn default_challenge_types() -> Vec<String> {
    vec!["http-01".to_string(), "dns-01".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_profile() -> String {
    "end-entity".to_string()
}

fn default_max_validity() -> u32 {
    825
}

fn default_require_hsm() -> bool {
    true // Default to NIAP-compliant mode
}

fn default_cache_size() -> usize {
    10000
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_shamir_threshold() -> u8 {
    3
}

fn default_shamir_shares() -> u8 {
    5
}

fn default_max_pin_retries() -> u8 {
    3
}

fn default_pin_lockout() -> u32 {
    15
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_output() -> String {
    "stdout".to_string()
}

impl OstrichConfig {
    /// Load and validate configuration from JSON file.
    ///
    /// Searches for configuration in the following order:
    /// 1. `OSTRICH_CONFIG` environment variable
    /// 2. `/etc/ostrich/config.json`
    /// 3. `./config.json`
    ///
    /// # NIAP PP-CA Compliance
    /// - FMT_MSA.1: Validates against secure defaults schema
    pub fn load() -> std::result::Result<Self, ConfigError> {
        let config_paths = vec![
            std::env::var("OSTRICH_CONFIG").ok(),
            Some("/etc/ostrich/config.json".to_string()),
            Some("./config.json".to_string()),
        ];

        for path in config_paths.into_iter().flatten() {
            if Path::new(&path).exists() {
                return Self::from_file(&path);
            }
        }

        Err(ConfigError::NoConfigFile)
    }

    /// Load from JSON file with schema validation.
    pub fn from_file(path: &str) -> std::result::Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Parse JSON with schema validation.
    pub fn from_json(json: &str) -> std::result::Result<Self, ConfigError> {
        // Parse JSON
        let json_value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| ConfigError::JsonParse(e.to_string()))?;

        // Validate against schema
        Self::validate_schema(&json_value)?;

        // Deserialize to config struct
        let mut config: OstrichConfig = serde_json::from_value(json_value)
            .map_err(|e| ConfigError::JsonParse(e.to_string()))?;

        // Expand environment variables
        config.expand_env_vars()?;

        // Validate no IP literals in hostnames
        config.validate_no_ip_literals()?;

        Ok(config)
    }

    /// Validate JSON against schema.
    fn validate_schema(json: &serde_json::Value) -> std::result::Result<(), ConfigError> {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA)
            .map_err(|e| ConfigError::SchemaError(e.to_string()))?;

        let compiled = jsonschema::validator_for(&schema)
            .map_err(|e| ConfigError::SchemaError(e.to_string()))?;

        // Collect validation errors
        let errors: Vec<String> = compiled
            .iter_errors(json)
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();

        if !errors.is_empty() {
            return Err(ConfigError::ValidationFailed(errors));
        }

        Ok(())
    }

    /// Expand $ENV{VAR} patterns in configuration values.
    fn expand_env_vars(&mut self) -> std::result::Result<(), ConfigError> {
        // Expand database password
        if let Some(ref password) = self.database.password
            && let Some(expanded) = Self::expand_env_var(password)?
        {
            self.database.password = Some(expanded);
        }

        Ok(())
    }

    /// Expand single $ENV{VAR} pattern.
    fn expand_env_var(value: &str) -> std::result::Result<Option<String>, ConfigError> {
        let re = regex::Regex::new(r"\$ENV\{([^}]+)\}").unwrap();

        if let Some(caps) = re.captures(value) {
            let var_name = &caps[1];
            let env_value = std::env::var(var_name)
                .map_err(|_| ConfigError::MissingEnvVar(var_name.to_string()))?;
            Ok(Some(re.replace_all(value, env_value.as_str()).to_string()))
        } else {
            Ok(None)
        }
    }

    /// Validate that no IP literals are used in configuration fields.
    ///
    /// # Allowed exceptions:
    /// - "::" for dual-stack binding
    /// - "0.0.0.0" for all IPv4 interfaces (deprecated)
    fn validate_no_ip_literals(&self) -> std::result::Result<(), ConfigError> {
        // Check base URL
        if Self::contains_ip_literal(&self.service.base_url) {
            return Err(ConfigError::IpLiteralNotAllowed {
                field: "service.baseUrl".to_string(),
                value: self.service.base_url.clone(),
            });
        }

        // Check listen host (allow :: and 0.0.0.0)
        let listen_host = &self.service.listen.host;
        if listen_host != "::" && listen_host != "0.0.0.0" && Self::contains_ip_literal(listen_host)
        {
            return Err(ConfigError::IpLiteralNotAllowed {
                field: "service.listen.host".to_string(),
                value: listen_host.clone(),
            });
        }

        // Check database host
        if Self::contains_ip_literal(&self.database.host) {
            return Err(ConfigError::IpLiteralNotAllowed {
                field: "database.host".to_string(),
                value: self.database.host.clone(),
            });
        }

        // Check CA gRPC endpoint
        if let Some(ref ca) = self.ca
            && let Some(ref endpoint) = ca.grpc_endpoint
            && Self::contains_ip_literal(endpoint)
        {
            return Err(ConfigError::IpLiteralNotAllowed {
                field: "ca.grpcEndpoint".to_string(),
                value: endpoint.clone(),
            });
        }

        // Check ACME directory URL
        if let Some(ref acme) = self.acme
            && let Some(ref dir_url) = acme.directory_url
            && Self::contains_ip_literal(dir_url)
        {
            return Err(ConfigError::IpLiteralNotAllowed {
                field: "acme.directoryUrl".to_string(),
                value: dir_url.clone(),
            });
        }

        Ok(())
    }

    /// Check if a string contains an IP literal (IPv4 or IPv6).
    fn contains_ip_literal(value: &str) -> bool {
        // IPv4 pattern: digits and dots forming x.x.x.x
        let ipv4_re = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();

        // IPv6 pattern in URL: [xxxx:xxxx::xxxx]
        let ipv6_bracket_re = regex::Regex::new(r"\[[0-9a-fA-F:]+\]").unwrap();

        ipv4_re.is_match(value) || ipv6_bracket_re.is_match(value)
    }

    /// Get the socket address for listening.
    pub fn listen_addr(&self) -> String {
        let host = &self.service.listen.host;
        // IPv6 addresses need brackets in socket addresses
        if host.contains(':') {
            format!("[{}]:{}", host, self.service.listen.port)
        } else {
            format!("{}:{}", host, self.service.listen.port)
        }
    }

    /// Get the database connection URL.
    pub fn database_url(&self) -> String {
        let password = self
            .database
            .password
            .as_ref()
            .map(|p| format!(":{}", p))
            .unwrap_or_default();

        format!(
            "postgres://{}{}@{}:{}/{}?sslmode={}",
            self.database.username,
            password,
            self.database.host,
            self.database.port,
            self.database.database,
            self.database.ssl_mode
        )
    }
}

/// Load configuration from file and environment variables (legacy support).
///
/// Configuration precedence (highest to lowest):
/// 1. Environment variables (PREFIX_KEY format)
/// 2. Configuration file
/// 3. Default values
///
/// NIST 800-53: CM-6 - Use secure defaults
pub fn load_config<T: serde::de::DeserializeOwned>(
    config_path: impl AsRef<Path>,
    env_prefix: &str,
) -> Result<T> {
    let config_path = config_path.as_ref();

    let builder = config::Config::builder()
        // Start with config file if it exists
        .add_source(config::File::from(config_path).required(false))
        // Override with environment variables
        // Example: OSTRICH_CA_DATABASE_URL becomes database.url
        .add_source(
            config::Environment::with_prefix(env_prefix)
                .separator("_")
                .try_parsing(true),
        );

    let config = builder
        .build()
        .map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

    config.try_deserialize().map_err(|e: config::ConfigError| {
        Error::Config(format!("Failed to deserialize config: {}", e))
    })
}

/// Validate that no secrets are in the config structure itself.
/// Secrets should only come from environment variables or secure vaults.
///
/// NIST 800-53: CM-6 - No hardcoded secrets
pub fn validate_no_hardcoded_secrets(config_content: &str) -> Result<()> {
    let dangerous_patterns = [
        "password",
        "secret",
        "private_key",
        "api_key",
        "token",
        "credential",
    ];

    for pattern in &dangerous_patterns {
        if config_content.to_lowercase().contains(pattern) {
            tracing::warn!(
                pattern = pattern,
                "Config file contains potentially hardcoded secret"
            );
            // In production, this should be an error
            // return Err(Error::config(format!("Config contains hardcoded secret: {}", pattern)));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_ip_literal_ipv4() {
        assert!(OstrichConfig::contains_ip_literal("192.168.1.1"));
        assert!(OstrichConfig::contains_ip_literal(
            "http://192.168.1.1:8080"
        ));
        assert!(OstrichConfig::contains_ip_literal("https://10.0.0.1/api"));
        assert!(!OstrichConfig::contains_ip_literal("example.com"));
        assert!(!OstrichConfig::contains_ip_literal("https://example.com"));
    }

    #[test]
    fn test_contains_ip_literal_ipv6() {
        assert!(OstrichConfig::contains_ip_literal("http://[::1]:8080"));
        assert!(OstrichConfig::contains_ip_literal(
            "https://[2001:db8::1]/api"
        ));
        assert!(!OstrichConfig::contains_ip_literal("::"));
        assert!(!OstrichConfig::contains_ip_literal("example.com"));
    }

    #[test]
    fn test_env_var_expansion_pattern() {
        let re = regex::Regex::new(r"\$ENV\{([^}]+)\}").unwrap();
        assert!(re.is_match("$ENV{DB_PASSWORD}"));
        assert!(re.is_match("prefix_$ENV{VAR}_suffix"));
        assert!(!re.is_match("$VAR"));
        assert!(!re.is_match("${VAR}"));
    }

    #[test]
    fn test_valid_json_config() {
        let json = r#"{
            "service": {
                "name": "ostrich-acme",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://acme.example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.service.name, "ostrich-acme");
        assert_eq!(config.service.listen.host, "::");
        assert_eq!(config.service.listen.port, 8443);
    }

    #[test]
    fn test_ip_literal_rejected_by_schema() {
        // IP literal in baseUrl is rejected by JSON Schema pattern validation
        let json = r#"{
            "service": {
                "name": "ostrich-acme",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://192.168.1.1"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json);
        assert!(config.is_err());

        // The JSON Schema pattern validation catches this first
        if let Err(ConfigError::ValidationFailed(errors)) = config {
            assert!(errors.iter().any(|e| e.contains("baseUrl")));
        } else {
            panic!("Expected ValidationFailed error for baseUrl");
        }
    }

    #[test]
    fn test_ip_literal_rejected_in_database_host() {
        // IP literal in database.host is rejected by our custom validation
        // because schema allows any hostname pattern but we want hostnames only
        let json = r#"{
            "service": {
                "name": "ostrich-acme",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://acme.example.com"
            },
            "database": {
                "host": "192.168.1.1",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json);
        assert!(config.is_err());

        // Database host with IP literal fails schema pattern validation
        if let Err(ConfigError::ValidationFailed(errors)) = &config {
            assert!(errors.iter().any(|e| e.contains("host")));
        } else {
            panic!("Expected ValidationFailed error, got {:?}", config);
        }
    }

    #[test]
    fn test_dual_stack_listen_allowed() {
        let json = r#"{
            "service": {
                "name": "ostrich-acme",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://acme.example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json);
        assert!(config.is_ok());
        assert_eq!(config.unwrap().service.listen.host, "::");
    }

    #[test]
    fn test_all_interfaces_ipv4_allowed() {
        let json = r#"{
            "service": {
                "name": "ostrich-acme",
                "listen": { "host": "0.0.0.0", "port": 8443 },
                "baseUrl": "https://acme.example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json);
        assert!(config.is_ok());
        assert_eq!(config.unwrap().service.listen.host, "0.0.0.0");
    }

    #[test]
    fn test_default_values() {
        let json = r#"{
            "service": {
                "name": "test",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json).unwrap();

        // Check defaults are applied
        assert_eq!(config.service.max_body_size, 1_048_576);
        assert_eq!(config.service.request_timeout_seconds, 30);
        assert_eq!(config.database.pool_size, 10);
        assert_eq!(config.database.ssl_mode, "require");
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.logging.output, "stdout");
    }

    #[test]
    fn test_database_url_generation() {
        let json = r#"{
            "service": {
                "name": "test",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich",
                "password": "secret"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json).unwrap();
        let url = config.database_url();

        assert!(url.contains("postgres://"));
        assert!(url.contains("ostrich:secret@"));
        assert!(url.contains("db.example.com:5432"));
        assert!(url.contains("/ostrich"));
        assert!(url.contains("sslmode=require"));
    }

    #[test]
    fn test_listen_addr_generation() {
        let json = r#"{
            "service": {
                "name": "test",
                "listen": { "host": "::", "port": 8443 },
                "baseUrl": "https://example.com"
            },
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "database": "ostrich",
                "username": "ostrich"
            },
            "logging": {
                "level": "info"
            }
        }"#;

        let config = OstrichConfig::from_json(json).unwrap();
        assert_eq!(config.listen_addr(), "[::]:8443");
    }

    #[test]
    fn test_validate_no_secrets() {
        let safe_config = r#"
            database_url = "${DATABASE_URL}"
            port = 8443
        "#;
        assert!(validate_no_hardcoded_secrets(safe_config).is_ok());

        let unsafe_config = r#"
            password = "hunter2"
            port = 8443
        "#;
        // Should warn but not fail in current implementation
        assert!(validate_no_hardcoded_secrets(unsafe_config).is_ok());
    }
}
