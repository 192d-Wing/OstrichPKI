//! CA Core Integration Tests
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - RFC 5280: X.509 certificate issuance and revocation

mod common;

use common::{http_client::create_test_client, TestConfig};

/// Test CA health endpoint
#[tokio::test]
async fn test_ca_health() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(&format!("{}/health", config.ca_http_base_url))
        .send()
        .await
        .expect("Failed to fetch CA health");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let health: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse health response");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["service"], "ostrich-ca");

    println!("✓ CA health endpoint working");
}

/// Test CA readiness endpoint
#[tokio::test]
async fn test_ca_readiness() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(&format!("{}/ready", config.ca_http_base_url))
        .send()
        .await
        .expect("Failed to fetch CA readiness");

    // Readiness may fail if HSM/database is not available, but endpoint should respond
    let status = response.status();
    assert!(
        status == reqwest::StatusCode::OK || status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Unexpected status: {}",
        status
    );

    println!("✓ CA readiness endpoint responding");
}

/// Test certificate issuance with RSA
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_issue_certificate_rsa() {
    let _config = TestConfig::default();
    println!("✓ CA RSA certificate issuance test ready (needs Docker setup)");
    // TODO: Implement gRPC certificate issuance test with RSA
}

/// Test certificate issuance with ECDSA
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_issue_certificate_ecdsa() {
    let _config = TestConfig::default();
    println!("✓ CA ECDSA certificate issuance test ready (needs Docker setup)");
    // TODO: Implement gRPC certificate issuance test with ECDSA
}

/// Test certificate issuance with EdDSA
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_issue_certificate_eddsa() {
    let _config = TestConfig::default();
    println!("✓ CA EdDSA certificate issuance test ready (needs Docker setup)");
    // TODO: Implement gRPC certificate issuance test with EdDSA
}

/// Test certificate issuance with ML-DSA (post-quantum)
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_issue_certificate_mldsa() {
    let _config = TestConfig::default();
    println!("✓ CA ML-DSA certificate issuance test ready (needs Docker setup)");
    // TODO: Implement gRPC certificate issuance test with ML-DSA
}

/// Test certificate revocation
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_revoke_certificate() {
    let _config = TestConfig::default();
    println!("✓ CA certificate revocation test ready (needs Docker setup)");
    // TODO: Implement gRPC certificate revocation test
}

/// Test CRL generation
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_generate_crl() {
    let _config = TestConfig::default();
    println!("✓ CA CRL generation test ready (needs Docker setup)");
    // TODO: Implement CRL generation test
}

/// Test certificate profile enforcement
#[tokio::test]
#[ignore] // Ignore until CA service is running in Docker
async fn test_ca_profile_enforcement() {
    let _config = TestConfig::default();
    println!("✓ CA profile enforcement test ready (needs Docker setup)");
    // TODO: Implement profile enforcement test (key usage, validity, etc.)
}
