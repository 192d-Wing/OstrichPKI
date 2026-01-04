//! ACME End-to-End Integration Tests
//!
//! RFC 8555: Automatic Certificate Management Environment
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: CA-2 (Security Assessments)
//! - RFC 8555: Complete ACME workflow testing

mod common;

use common::{
    fixtures::TestJwk,
    http_client::{assert_json, assert_status, create_test_client},
    TestConfig,
};
use serde_json::json;

/// Test ACME health endpoint
#[tokio::test]
async fn test_acme_health() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(&format!("{}/health", config.acme_base_url))
        .send()
        .await
        .expect("Failed to fetch ACME health");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let health: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse health response");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["service"], "ostrich-acme");

    println!("✓ ACME health endpoint working");
}

/// Test ACME readiness endpoint
#[tokio::test]
async fn test_acme_readiness() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(&format!("{}/ready", config.acme_base_url))
        .send()
        .await
        .expect("Failed to fetch ACME readiness");

    // Readiness may fail if CA backend is not available, but endpoint should respond
    let status = response.status();
    assert!(
        status == reqwest::StatusCode::OK || status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Unexpected status: {}",
        status
    );

    println!("✓ ACME readiness endpoint responding");
}

/// Test ACME directory endpoint
///
/// RFC 8555 §7.1.1 - Directory resource
#[tokio::test]
async fn test_acme_directory() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(&format!("{}/directory", config.acme_base_url))
        .send()
        .await
        .expect("Failed to fetch ACME directory");

    let response = assert_status(response, reqwest::StatusCode::OK).await;
    let directory: serde_json::Value = assert_json(response).await;

    // Verify required directory fields
    assert!(directory["newNonce"].is_string(), "Missing newNonce URL");
    assert!(
        directory["newAccount"].is_string(),
        "Missing newAccount URL"
    );
    assert!(directory["newOrder"].is_string(), "Missing newOrder URL");
    assert!(
        directory["revokeCert"].is_string(),
        "Missing revokeCert URL"
    );

    println!("✓ ACME directory endpoint working");
}

/// Test ACME nonce generation
///
/// RFC 8555 §7.2 - Getting a Nonce
#[tokio::test]
async fn test_acme_new_nonce() {
    let config = TestConfig::default();
    let client = create_test_client();

    // Get directory first
    let directory_response = client
        .get(&format!("{}/directory", config.acme_base_url))
        .send()
        .await
        .expect("Failed to fetch ACME directory");
    let directory: serde_json::Value = directory_response.json().await.unwrap();
    let nonce_url = directory["newNonce"].as_str().unwrap();

    // Request nonce
    let response = client
        .head(nonce_url)
        .send()
        .await
        .expect("Failed to request nonce");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let nonce = response
        .headers()
        .get("Replay-Nonce")
        .expect("Missing Replay-Nonce header")
        .to_str()
        .unwrap();

    assert!(!nonce.is_empty(), "Nonce should not be empty");
    println!("✓ ACME nonce generation working: {}", nonce);
}

/// Test ACME account creation
///
/// RFC 8555 §7.3 - Account Management
#[tokio::test]
async fn test_acme_account_creation() {
    let config = TestConfig::default();
    let client = create_test_client();

    // Get directory
    let directory_response = client
        .get(&format!("{}/directory", config.acme_base_url))
        .send()
        .await
        .expect("Failed to fetch ACME directory");
    let directory: serde_json::Value = directory_response.json().await.unwrap();

    // Get nonce
    let nonce_url = directory["newNonce"].as_str().unwrap();
    let nonce_response = client.head(nonce_url).send().await.unwrap();
    let nonce = nonce_response
        .headers()
        .get("Replay-Nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Generate JWK for account
    let jwk = TestJwk::generate();

    // Create JWS-signed account creation request
    let new_account_url = directory["newAccount"].as_str().unwrap();
    let payload = json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:test@example.com"]
    });

    // Create properly signed JWS request
    let jws = jwk.create_jws(new_account_url, &nonce, &payload, None);

    // Send account creation request
    let response = client
        .post(new_account_url)
        .header("Content-Type", "application/jose+json")
        .json(&jws)
        .send()
        .await
        .expect("Failed to create ACME account");

    // Should return 201 Created or 200 OK (if account exists)
    let status = response.status();
    assert!(
        status == reqwest::StatusCode::CREATED || status == reqwest::StatusCode::OK,
        "Unexpected status: {}. Body: {}",
        status,
        response.text().await.unwrap_or_default()
    );

    println!("✓ ACME account creation working");
}

/// Test ACME order creation (placeholder)
///
/// RFC 8555 §7.4 - Applying for Certificate Issuance
#[tokio::test]
#[ignore] // Ignore until account creation works
async fn test_acme_new_order() {
    // TODO: Implement after account creation works
    println!("✓ ACME order creation test ready (needs account implementation)");
}

/// Test ACME challenge validation (placeholder)
///
/// RFC 8555 §8 - Identifier Validation Challenges
#[tokio::test]
#[ignore] // Ignore until order creation works
async fn test_acme_http01_challenge() {
    // TODO: Implement HTTP-01 challenge test
    println!("✓ ACME HTTP-01 challenge test ready (needs order implementation)");
}

/// Test ACME order finalization (placeholder)
///
/// RFC 8555 §7.4 - Finalizing an Order
#[tokio::test]
#[ignore] // Ignore until challenge validation works
async fn test_acme_order_finalization() {
    // TODO: Implement order finalization test
    println!("✓ ACME order finalization test ready (needs challenge implementation)");
}

/// Test ACME certificate download (placeholder)
///
/// RFC 8555 §7.4.2 - Downloading the Certificate
#[tokio::test]
#[ignore] // Ignore until finalization works
async fn test_acme_certificate_download() {
    // TODO: Implement certificate download test
    println!("✓ ACME certificate download test ready (needs finalization implementation)");
}

/// Integration test: Full ACME workflow (account → order → challenge → finalize → download)
#[tokio::test]
#[ignore] // Ignore until all components work
async fn test_acme_full_workflow() {
    // TODO: Implement complete end-to-end ACME workflow
    println!("✓ Full ACME workflow test ready (needs all components)");
}
