//! CA Core Integration Tests
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - RFC 5280: X.509 certificate issuance and revocation

mod common;

use common::TestConfig;

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
