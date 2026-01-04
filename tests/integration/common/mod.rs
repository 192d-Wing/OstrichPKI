//! Common test utilities for integration tests
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)

use std::time::Duration;

pub mod fixtures;
pub mod http_client;

/// Test configuration
pub struct TestConfig {
    pub acme_base_url: String,
    pub est_base_url: String,
    pub ocsp_base_url: String,
    pub ca_grpc_endpoint: String,
    pub database_url: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            acme_base_url: std::env::var("ACME_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            est_base_url: std::env::var("EST_BASE_URL")
                .unwrap_or_else(|_| "https://localhost:8443".to_string()),
            ocsp_base_url: std::env::var("OCSP_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8081".to_string()),
            ca_grpc_endpoint: std::env::var("CA_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "https://localhost:50051".to_string()),
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgresql://ostrich_test:test_password_insecure@localhost:5432/ostrich_pki_test"
                    .to_string()
            }),
        }
    }
}

/// Wait for services to be ready
pub async fn wait_for_services() -> Result<(), Box<dyn std::error::Error>> {
    let config = TestConfig::default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Wait for ACME service
    wait_for_http_service(&client, &format!("{}/directory", config.acme_base_url)).await?;

    // Wait for OCSP service
    wait_for_http_service(&client, &format!("{}/health", config.ocsp_base_url)).await?;

    Ok(())
}

async fn wait_for_http_service(
    client: &reqwest::Client,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 1..=30 {
        match client.get(url).send().await {
            Ok(_) => {
                println!("✓ Service ready: {}", url);
                return Ok(());
            }
            Err(e) => {
                if attempt == 30 {
                    return Err(
                        format!("Service not ready after 30 attempts: {} ({})", url, e).into(),
                    );
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Ok(())
}

/// Generate a random account ID for testing
pub fn generate_test_account_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("test-account-{}", rng.gen::<u32>())
}

/// Generate a random domain name for testing
pub fn generate_test_domain() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("test-{}.example.com", rng.gen::<u32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = TestConfig::default();
        assert!(config.acme_base_url.contains("8080"));
        assert!(config.est_base_url.contains("8443"));
    }

    #[test]
    fn test_generate_test_account_id() {
        let id1 = generate_test_account_id();
        let id2 = generate_test_account_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("test-account-"));
    }

    #[test]
    fn test_generate_test_domain() {
        let domain1 = generate_test_domain();
        let domain2 = generate_test_domain();
        assert_ne!(domain1, domain2);
        assert!(domain1.ends_with(".example.com"));
    }
}
