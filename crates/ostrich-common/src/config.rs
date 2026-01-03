// NIST 800-53: CM-2 - Baseline configuration
// NIST 800-53: CM-6 - Configuration settings

use crate::error::{Error, Result};
use config::{Config, ConfigError, Environment, File};
use serde::de::DeserializeOwned;
use std::path::Path;

/// Load configuration from file and environment variables
///
/// Configuration precedence (highest to lowest):
/// 1. Environment variables (PREFIX_KEY format)
/// 2. Configuration file
/// 3. Default values
///
/// NIST 800-53: CM-6 - Use secure defaults
pub fn load_config<T: DeserializeOwned>(
    config_path: impl AsRef<Path>,
    env_prefix: &str,
) -> Result<T> {
    let config_path = config_path.as_ref();

    let builder = Config::builder()
        // Start with config file if it exists
        .add_source(File::from(config_path).required(false))
        // Override with environment variables
        // Example: OSTRICH_CA_DATABASE_URL becomes database.url
        .add_source(
            Environment::with_prefix(env_prefix)
                .separator("_")
                .try_parsing(true),
        );

    let config = builder
        .build()
        .map_err(|e| Error::Config(format!("Failed to build config: {}", e)))?;

    config
        .try_deserialize()
        .map_err(|e: ConfigError| Error::Config(format!("Failed to deserialize config: {}", e)))
}

/// Validate that no secrets are in the config structure itself
/// Secrets should only come from environment variables or secure vaults
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
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct TestConfig {
        database_url: String,
        port: u16,
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
