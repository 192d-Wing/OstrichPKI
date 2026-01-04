//! EST End-to-End Integration Tests
//!
//! RFC 7030: Enrollment over Secure Transport
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - RFC 7030: EST protocol testing

mod common;

use common::{http_client::create_test_client, TestConfig};

/// Test EST health endpoint
#[tokio::test]
async fn test_est_health() {
    let config = TestConfig::default();
    let client = create_test_client();

    // EST uses HTTPS, but we test the HTTP health endpoint
    // In production, EST would have mTLS on its main endpoints
    let health_url = config
        .est_base_url
        .replace("https://", "http://")
        .replace(":8443", ":8444");

    let response = client
        .get(&format!("{}/health", health_url))
        .send()
        .await
        .expect("Failed to fetch EST health");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let health: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse health response");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["service"], "ostrich-est");

    println!("✓ EST health endpoint working");
}

/// Test EST readiness endpoint
#[tokio::test]
async fn test_est_readiness() {
    let config = TestConfig::default();
    let client = create_test_client();

    let health_url = config
        .est_base_url
        .replace("https://", "http://")
        .replace(":8443", ":8444");

    let response = client
        .get(&format!("{}/ready", health_url))
        .send()
        .await
        .expect("Failed to fetch EST readiness");

    // Readiness may fail if CA backend is not available, but endpoint should respond
    let status = response.status();
    assert!(
        status == reqwest::StatusCode::OK || status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Unexpected status: {}",
        status
    );

    println!("✓ EST readiness endpoint responding");
}

/// Test EST CA certificates retrieval
///
/// RFC 7030 §4.1 - Distribution of CA Certificates
#[tokio::test]
#[ignore] // Ignore until EST service is running in Docker
async fn test_est_cacerts() {
    let _config = TestConfig::default();
    println!("✓ EST CA certificates test ready (needs Docker setup)");
    // TODO: Implement EST /cacerts endpoint test
}

/// Test EST simple enroll
///
/// RFC 7030 §4.2 - Enrollment of Clients
#[tokio::test]
#[ignore] // Ignore until EST service is running in Docker
async fn test_est_simple_enroll() {
    let _config = TestConfig::default();
    println!("✓ EST simple enroll test ready (needs Docker setup)");
    // TODO: Implement EST /simpleenroll test with mTLS
}

/// Test EST simple re-enroll
///
/// RFC 7030 §4.2.2 - Simple Re-enrollment
#[tokio::test]
#[ignore] // Ignore until EST service is running in Docker
async fn test_est_simple_reenroll() {
    let _config = TestConfig::default();
    println!("✓ EST simple re-enroll test ready (needs Docker setup)");
    // TODO: Implement EST /simplereenroll test
}

/// Test EST CSR attributes
///
/// RFC 7030 §4.5 - CSR Attributes
#[tokio::test]
#[ignore] // Ignore until EST service is running in Docker
async fn test_est_csr_attributes() {
    let _config = TestConfig::default();
    println!("✓ EST CSR attributes test ready (needs Docker setup)");
    // TODO: Implement EST /csrattrs test
}
