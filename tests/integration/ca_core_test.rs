//! CA Core Integration Tests
//!
//! Exercises the CA gRPC API (ostrich.ca.v1.CertificateAuthorityService) for
//! issuance, revocation, CRL generation, and profile enforcement. The ignored
//! tests require the live docker-compose environment
//! (tests/integration/docker-compose.yml).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: SC-17 (PKI Certificates - issuance lifecycle evidence)
//! - NIAP PP-CA: FCS_COP.1 - issuance round-trip evidence
//! - NIAP PP-CA: FDP_IFC.1 - certificate profile policy enforcement
//! - RFC 5280: X.509 certificate issuance and revocation
//! - RFC 5280 §5: CRL profile

mod common;

use common::ca_grpc::{
    assert_issued_certificate, build_issue_request, connect_ca, connect_ca_admin,
    issue_test_certificate, TEST_ADMIN_REQUESTOR, TEST_REQUESTOR,
};
use common::{fixtures, generate_test_domain, http_client::create_test_client, TestConfig};
use ostrich_protocol::{
    CheckRevocationStatusRequest, GenerateCrlRequest, RevocationReason, RevokeCertificateRequest,
};

/// Test CA health endpoint
#[tokio::test]
async fn test_ca_health() {
    let config = TestConfig::default();
    let client = create_test_client();

    let response = client
        .get(format!("{}/health", config.ca_http_base_url))
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
        .get(format!("{}/ready", config.ca_http_base_url))
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
///
/// COMPLIANCE MAPPING:
/// - FIPS 186-5: RSA digital signature keys
/// - RFC 5280 §4.1 - certificate issuance
/// - NIAP PP-CA: FCS_COP.1 - issuance round-trip evidence
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_issue_certificate_rsa() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    // Generate an RSA-2048 keypair locally and encode the public key as
    // DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
    let spki = fixtures::generate_test_rsa_spki();
    let common_name = generate_test_domain();

    let response = issue_test_certificate(
        &mut client,
        &config.ca_profile_name,
        &common_name,
        spki.clone(),
    )
    .await;

    assert_issued_certificate(&response, &common_name, &spki);
    println!("✓ RSA certificate issued: {}", response.certificate_id);
}

/// Offline check of the P-256 SPKI fixture used by the ECDSA issuance test:
/// ecPublicKey with the prime256v1 named curve and a 65-byte uncompressed
/// point. Needs no live environment.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SA-11 (Developer Security Testing)
/// - RFC 5480 §2.1.1, §2.2 - ECC SubjectPublicKeyInfo (namedCurve, ECPoint)
#[tokio::test]
async fn test_p256_spki_fixture_well_formed() {
    use x509_parser::prelude::FromDer;
    use x509_parser::x509::SubjectPublicKeyInfo;

    let spki_der = fixtures::generate_test_p256_spki().await;
    let (rest, spki) = SubjectPublicKeyInfo::from_der(&spki_der).expect("fixture SPKI must parse");
    assert!(rest.is_empty(), "no trailing bytes after SPKI");

    assert_eq!(spki.algorithm.algorithm.to_id_string(), "1.2.840.10045.2.1");
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .expect("namedCurve parameter");
    assert_eq!(curve.to_id_string(), "1.2.840.10045.3.1.7");

    let point = &spki.subject_public_key.data;
    assert_eq!(point.len(), 65, "uncompressed P-256 point");
    assert_eq!(point.first(), Some(&0x04));

    // Fresh throwaway key per call.
    assert_ne!(spki_der, fixtures::generate_test_p256_spki().await);
}

/// The fixture's key path (software provider EcP256 keygen + export_public_key)
/// yields an SPKI that an independent stateless verifier accepts: a signature
/// made with the same key verifies, and tampered data / wrong algorithm do not.
/// Proves the exported point is a usable on-curve P-256 key, not only
/// well-formed DER. Needs no live environment.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SA-11 (Developer Security Testing)
/// - FIPS 186-5: ECDSA P-256 sign/verify round trip (test fixture)
/// - RFC 5480 §2 - ECC SubjectPublicKeyInfo consumed by a verifier
#[tokio::test]
async fn test_p256_spki_fixture_path_verifies_signature() {
    use ostrich_crypto::{verify_with_spki, Algorithm, CryptoProviderFactory, KeyType};

    // Same provider calls as fixtures::generate_test_p256_spki, keeping the
    // key handle so we can sign with it.
    let provider = CryptoProviderFactory::create_software_provider();
    let key = provider
        .generate_key_pair(KeyType::EcP256, "test-p256-fixture", false)
        .await
        .expect("P-256 keygen");
    let spki_der = provider.export_public_key(&key).await.expect("export SPKI");

    let data = b"ostrich p256 fixture round trip";
    let sig = provider
        .sign(&key, Algorithm::EcdsaP256Sha256, data)
        .await
        .expect("sign");
    // Software provider emits fixed-size r||s for ECDSA.
    assert_eq!(sig.len(), 64);

    assert!(
        verify_with_spki(&spki_der, Algorithm::EcdsaP256Sha256, data, &sig, true)
            .expect("SPKI must be accepted by verifier"),
        "signature by the same key must verify against the exported SPKI"
    );
    assert!(
        !verify_with_spki(
            &spki_der,
            Algorithm::EcdsaP256Sha256,
            b"tampered",
            &sig,
            true
        )
        .expect("verifier returns Ok(false) on mismatch"),
        "tampered data must not verify"
    );
    assert!(
        !verify_with_spki(&spki_der, Algorithm::EcdsaP384Sha384, data, &sig, true).unwrap_or(false),
        "wrong-curve algorithm must not verify (fail secure)"
    );

    // A different fixture key must not verify this signature.
    let other = fixtures::generate_test_p256_spki().await;
    assert!(
        !verify_with_spki(&other, Algorithm::EcdsaP256Sha256, data, &sig, true)
            .expect("fixture SPKI must be accepted by verifier"),
        "signature must not verify under an unrelated fixture key"
    );
}

/// Test certificate issuance with ECDSA P-256
///
/// COMPLIANCE MAPPING:
/// - FIPS 186-5: ECDSA P-256 digital signature keys
/// - RFC 5480: ECC SubjectPublicKeyInfo
/// - NIAP PP-CA: FCS_COP.1 - issuance round-trip evidence
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_issue_certificate_ecdsa() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    let spki = fixtures::generate_test_p256_spki().await;
    let common_name = generate_test_domain();

    let response = issue_test_certificate(
        &mut client,
        &config.ca_profile_name,
        &common_name,
        spki.clone(),
    )
    .await;

    assert_issued_certificate(&response, &common_name, &spki);
    println!(
        "✓ ECDSA P-256 certificate issued: {}",
        response.certificate_id
    );
}

/// Test certificate issuance with EdDSA (Ed25519)
///
/// COMPLIANCE MAPPING:
/// - FIPS 186-5: EdDSA digital signature keys
/// - RFC 8410: Ed25519 algorithm identifiers in X.509
/// - NIAP PP-CA: FCS_COP.1 - issuance round-trip evidence
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_issue_certificate_eddsa() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    let spki = fixtures::generate_test_ed25519_spki();
    let common_name = generate_test_domain();

    let response = issue_test_certificate(
        &mut client,
        &config.ca_profile_name,
        &common_name,
        spki.clone(),
    )
    .await;

    assert_issued_certificate(&response, &common_name, &spki);
    println!("✓ Ed25519 certificate issued: {}", response.certificate_id);
}

/// Test certificate issuance with ML-DSA (post-quantum, FIPS 204)
///
/// ML-DSA is not yet implemented in the workspace (PQC crates are still
/// placeholders in the workspace Cargo.toml), so the current correct behavior
/// is a clean gRPC error rather than a panic or a malformed certificate.
///
/// POAM: Flip this to a success assertion (issue + assert_issued_certificate)
/// once FIPS 204 ML-DSA support lands and an ML-DSA profile is registered.
///
/// COMPLIANCE MAPPING:
/// - FIPS 204: ML-DSA-65 (negative-path evidence until implemented)
/// - NIST 800-53: SI-10 - input validation (unsupported algorithm rejected)
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_issue_certificate_mldsa() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    // ML-DSA-65 SPKI (FIPS 204 OID) with an ML-DSA profile name. Neither is
    // supported yet, so the CA must fail cleanly.
    let spki = fixtures::ml_dsa_65_placeholder_spki();
    let common_name = generate_test_domain();
    let request = build_issue_request("ml_dsa_65", &common_name, spki);

    let result = client.issue_certificate(tonic::Request::new(request)).await;

    let status = result
        .expect_err("ML-DSA issuance must fail cleanly until FIPS 204 support is implemented");
    assert!(
        !status.message().is_empty(),
        "error status must carry a diagnostic message"
    );
    println!(
        "✓ ML-DSA issuance rejected cleanly ({}): {}",
        status.code(),
        status.message()
    );
}

/// Test certificate revocation (issue → revoke → status check)
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §5.3.1 - keyCompromise revocation reason
/// - RFC 6960 §2.2 - revocation status check
/// - NIST 800-53: AU-2 - auditable event (revocation with requestor)
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_revoke_certificate() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    // Issue a certificate to revoke (RSA flow)
    let spki = fixtures::generate_test_rsa_spki();
    let common_name = generate_test_domain();
    let issued = issue_test_certificate(
        &mut client,
        &config.ca_profile_name,
        &common_name,
        spki.clone(),
    )
    .await;
    assert_issued_certificate(&issued, &common_name, &spki);

    // AC-5 / AC-6: the issuer identity may not revoke.
    let denied = client
        .revoke_certificate(tonic::Request::new(RevokeCertificateRequest {
            certificate_id: issued.certificate_id.clone(),
            reason: RevocationReason::KeyCompromise as i32,
            requestor: TEST_REQUESTOR.to_string(),
            justification: "integration test: issuer must not revoke".to_string(),
        }))
        .await
        .expect_err("issuer client must not revoke");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // Revoke with reason keyCompromise (RFC 5280 §5.3.1) as the admin identity
    let mut admin = connect_ca_admin(&config.ca_grpc_endpoint).await;
    let revoke_response = admin
        .revoke_certificate(tonic::Request::new(RevokeCertificateRequest {
            certificate_id: issued.certificate_id.clone(),
            reason: RevocationReason::KeyCompromise as i32,
            requestor: TEST_ADMIN_REQUESTOR.to_string(),
            justification: "integration test: simulated key compromise".to_string(),
        }))
        .await
        .expect("revoke_certificate failed")
        .into_inner();

    assert!(revoke_response.success, "revocation must report success");
    assert!(
        revoke_response.revocation_time > 0,
        "revocation_time must be a valid timestamp"
    );

    // Verify the certificate is now reported as revoked (RFC 6960 §2.2);
    // CheckRevocationStatus is admin-only.
    let status = admin
        .check_revocation_status(tonic::Request::new(CheckRevocationStatusRequest {
            certificate_id: issued.certificate_id.clone(),
        }))
        .await
        .expect("check_revocation_status failed")
        .into_inner();

    assert!(status.revoked, "certificate must be reported as revoked");
    assert_eq!(
        status.reason,
        Some(RevocationReason::KeyCompromise as i32),
        "revocation reason must be keyCompromise"
    );
    assert!(
        status.revocation_time.is_some(),
        "revocation_time must be present for a revoked certificate"
    );

    println!(
        "✓ Certificate {} revoked (keyCompromise)",
        issued.certificate_id
    );
}

/// Test CRL generation
///
/// COMPLIANCE MAPPING:
/// - RFC 5280 §5.1 - CRL generation
/// - RFC 7468 - PEM encoding ("X509 CRL" label)
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_generate_crl() {
    let config = TestConfig::default();
    // AC-6: GenerateCrl is admin-only; the issuer identity is refused.
    let denied = connect_ca(&config.ca_grpc_endpoint)
        .await
        .generate_crl(tonic::Request::new(GenerateCrlRequest {}))
        .await
        .expect_err("issuer client must not generate CRLs");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let mut client = connect_ca_admin(&config.ca_grpc_endpoint).await;

    let crl = client
        .generate_crl(tonic::Request::new(GenerateCrlRequest {}))
        .await
        .expect("generate_crl failed")
        .into_inner();

    assert!(
        crl.pem_encoded.starts_with("-----BEGIN X509 CRL-----"),
        "pem_encoded must be a PEM CRL, got: {:.40}",
        crl.pem_encoded
    );
    assert!(!crl.der_encoded.is_empty(), "der_encoded must be non-empty");
    // RFC 5280 §5.1.2.4/§5.1.2.5 - thisUpdate must precede nextUpdate
    assert!(
        crl.this_update < crl.next_update,
        "thisUpdate must precede nextUpdate"
    );

    println!(
        "✓ CRL #{} generated ({} revoked entries)",
        crl.crl_number, crl.revoked_count
    );
}

/// Test certificate profile enforcement (unknown profile is rejected)
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_IFC.1 - certificate profile policy enforcement
/// - NIST 800-53: SI-10 - input validation (fail secure on unknown profile)
#[tokio::test]
#[ignore] // Requires live docker-compose environment (tests/integration/docker-compose.yml)
async fn test_ca_profile_enforcement() {
    let config = TestConfig::default();
    let mut client = connect_ca(&config.ca_grpc_endpoint).await;

    let spki = fixtures::generate_test_rsa_spki();
    let common_name = generate_test_domain();
    let bogus_profile = format!("nonexistent-profile-{}", uuid::Uuid::new_v4());
    let request = build_issue_request(&bogus_profile, &common_name, spki);

    let result = client.issue_certificate(tonic::Request::new(request)).await;

    let status = result.expect_err("issuance with a nonexistent profile must fail");
    assert_ne!(status.code(), tonic::Code::Ok);
    assert!(
        status.message().to_lowercase().contains("profile"),
        "error should identify the profile failure, got: {}",
        status.message()
    );

    println!("✓ Unknown profile rejected cleanly: {}", status.message());
}
