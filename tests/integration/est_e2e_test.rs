//! EST End-to-End Integration Tests
//!
//! RFC 7030: Enrollment over Secure Transport
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - RFC 7030: EST protocol testing

mod common;

use common::TestConfig;

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
