//! gRPC client helpers for CA integration tests
//!
//! Shared "connect, issue, assert" building blocks used by ca_core_test.rs
//! (and any future test that needs an issued certificate as a precondition).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIAP PP-CA: FCS_COP.1 - certificate issuance round-trip evidence
//! - RFC 5280 §4.1 - issued certificate structure validation

use ostrich_protocol::certificate_authority_service_client::CertificateAuthorityServiceClient;
use ostrich_protocol::{
    subject_alt_name::Name, DistinguishedName, IssueCertificateRequest, IssueCertificateResponse,
    SubjectAltName,
};
use tonic::transport::Channel;
use x509_parser::prelude::*;

/// Requestor identity used for audit attribution (NIST 800-53: AU-3)
pub const TEST_REQUESTOR: &str = "integration-tests::ca_core";

/// Type alias for the connected CA gRPC client
pub type CaClient = CertificateAuthorityServiceClient<Channel>;

/// Connect to the CA gRPC endpoint (plaintext HTTP/2 in the test environment)
pub async fn connect_ca(endpoint: &str) -> CaClient {
    CertificateAuthorityServiceClient::connect(endpoint.to_string())
        .await
        .unwrap_or_else(|e| panic!("Failed to connect to CA gRPC at {}: {}", endpoint, e))
}

/// Build a test subject DN with the given common name
pub fn test_subject(common_name: &str) -> DistinguishedName {
    DistinguishedName {
        common_name: Some(common_name.to_string()),
        organization: Some("OstrichPKI Integration Tests".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("US".to_string()),
        serial_number: None,
    }
}

/// Build an IssueCertificateRequest for a test subject.
///
/// A DNS SAN equal to the common name is always included so the request is
/// valid for profiles with `subject_alt_name_required` (RFC 6125).
pub fn build_issue_request(
    profile_name: &str,
    common_name: &str,
    spki_der: Vec<u8>,
) -> IssueCertificateRequest {
    IssueCertificateRequest {
        profile_name: profile_name.to_string(),
        subject: Some(test_subject(common_name)),
        subject_alt_names: vec![SubjectAltName {
            name: Some(Name::DnsName(common_name.to_string())),
        }],
        public_key: spki_der,
        requestor: TEST_REQUESTOR.to_string(),
        metadata: std::collections::HashMap::from([(
            "test_suite".to_string(),
            "ca_core_test".to_string(),
        )]),
        // These tests issue from a bare public key (no CSR), so the dev-stack CA
        // runs with CA_REQUIRE_POP=false. Production defaults to requiring a CSR
        // (proof-of-possession); see services/ca-server CA_REQUIRE_POP.
        csr_der: Vec::new(),
    }
}

/// Issue a test certificate and return the response, panicking on failure.
///
/// Shared by the issuance and revocation tests.
pub async fn issue_test_certificate(
    client: &mut CaClient,
    profile_name: &str,
    common_name: &str,
    spki_der: Vec<u8>,
) -> IssueCertificateResponse {
    client
        .issue_certificate(tonic::Request::new(build_issue_request(
            profile_name,
            common_name,
            spki_der,
        )))
        .await
        .unwrap_or_else(|e| panic!("issue_certificate failed for CN={}: {}", common_name, e))
        .into_inner()
}

/// Assert an issuance response is well-formed and matches the request.
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §4.1.2.2 - serial number is a positive integer of at most 20 octets
/// - RFC 5280 §4.1.2.6 - subject matches the requested DN
/// - RFC 5280 §4.1.2.7 - subjectPublicKeyInfo matches the submitted key
pub fn assert_issued_certificate(
    response: &IssueCertificateResponse,
    expected_cn: &str,
    expected_spki_der: &[u8],
) {
    // Identifier and encodings present
    assert!(
        !response.certificate_id.is_empty(),
        "certificate_id must be non-empty"
    );
    uuid::Uuid::parse_str(&response.certificate_id)
        .expect("certificate_id must be a valid UUID");
    assert!(
        response.pem_encoded.starts_with("-----BEGIN CERTIFICATE-----"),
        "pem_encoded must be a PEM certificate, got: {:.40}",
        response.pem_encoded
    );
    assert!(
        !response.der_encoded.is_empty(),
        "der_encoded must be non-empty"
    );

    // RFC 5280 §4.1.2.2 - serial number at most 20 octets
    assert!(
        !response.serial_number.is_empty() && response.serial_number.len() <= 20,
        "serial number must be 1..=20 octets, got {} octets",
        response.serial_number.len()
    );

    // RFC 5280 §4.1.2.5 - sane validity window
    assert!(
        response.not_before < response.not_after,
        "notBefore must precede notAfter"
    );

    // Parse the issued certificate and verify it matches the request
    let (rest, cert) = X509Certificate::from_der(&response.der_encoded)
        .expect("issued certificate must parse as X.509 DER");
    assert!(rest.is_empty(), "trailing bytes after certificate DER");

    // Subject CN matches the requested DN (RFC 5280 §4.1.2.6)
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .expect("issued certificate must contain a subject CN");
    assert_eq!(cn, expected_cn, "subject CN mismatch");

    // SubjectPublicKeyInfo matches the submitted public key (RFC 5280 §4.1.2.7)
    assert_eq!(
        cert.public_key().raw,
        expected_spki_der,
        "subjectPublicKeyInfo does not match the submitted public key"
    );
}
