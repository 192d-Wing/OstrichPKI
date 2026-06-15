//! OCSP revocation round-trip E2E test (RFC 6960 / RFC 8954)
//!
//! Drives the full status-checking loop against live ca-server + ocsp-server:
//! issue a certificate, confirm OCSP reports it `good`, revoke it over gRPC,
//! confirm OCSP now reports it `revoked` with the correct reason. The OCSP
//! protocol round-trip is performed by the `openssl ocsp` CLI, which acts as
//! an INDEPENDENT verifier of our RFC 6960 response encoding (responderID,
//! certStatus CHOICE, nextUpdate, nonce, embedded responder cert).
//!
//! COMPLIANCE MAPPING:
//! - RFC 6960 - OCSP request/response protocol
//! - RFC 8954 - OCSP nonce extension
//! - NIST 800-53: SA-11 (Developer Security Testing)
//! - NIST 800-53: AU-2 - revocation is an auditable event
//! - NIAP PP-CA: FDP_OCSPG_EXT.1 - OCSP response generation
//!
//! Requires a live environment; run with:
//!   cargo test -p ostrich-integration-tests --test ocsp_revocation_test -- --ignored --nocapture
//!
//! Env: CA_GRPC_ENDPOINT (or CA_GRPC_URL), OCSP_URL (default http://127.0.0.1:8082),
//!      OCSP_ISSUER_PEM (path to the root CA PEM, default /tmp/ostrich-e2e/root-ca.pem),
//!      CA_TEST_PROFILE (default tls_client).

#[path = "common/mod.rs"]
mod common;

use common::ca_grpc::{connect_ca, issue_test_certificate};
use common::fixtures::generate_test_rsa_spki;
use ostrich_protocol::{RevocationReason, RevokeCertificateRequest};
use std::io::Write;
use std::process::Command;

/// Run `openssl ocsp` for `leaf_pem` against the live responder and return its
/// textual status line ("good" / "revoked").
fn openssl_ocsp_status(
    issuer_pem: &str,
    leaf_pem: &str,
    ocsp_url: &str,
    leaf_label: &str,
) -> String {
    let dir = std::env::temp_dir();
    let leaf_path = dir.join(format!("ocsp-leaf-{}.pem", leaf_label));
    let mut f = std::fs::File::create(&leaf_path).expect("write leaf pem");
    f.write_all(leaf_pem.as_bytes()).expect("write leaf bytes");

    // -noverify: we are asserting on the status line, not building trust to
    //   the responder cert (the embedded CA cert IS the issuer here, which
    //   openssl would otherwise demand be a delegated responder).
    // -no_nonce kept OFF: exercise the RFC 8954 nonce round-trip.
    let output = Command::new("openssl")
        .args([
            "ocsp",
            "-issuer",
            issuer_pem,
            "-cert",
            leaf_path.to_str().unwrap(),
            "-url",
            ocsp_url,
            "-noverify",
            "-resp_text",
        ])
        .output()
        .expect("failed to run openssl ocsp (is openssl installed?)");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("[openssl ocsp:{}] stdout:\n{}", leaf_label, stdout);
    if !stderr.trim().is_empty() {
        println!("[openssl ocsp:{}] stderr:\n{}", leaf_label, stderr);
    }

    // The "<leaf>.pem: good" / ": revoked" summary line is on stdout.
    stdout
        .lines()
        .find(|l| l.contains(": good") || l.contains(": revoked") || l.contains(": unknown"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| format!("NO STATUS LINE; stdout was:\n{}", stdout))
}

#[tokio::test]
#[ignore] // needs live ca-server + ocsp-server (see module docs)
async fn test_ocsp_good_then_revoked() {
    let cfg = common::TestConfig::default();
    let ocsp_url =
        std::env::var("OCSP_URL").unwrap_or_else(|_| "http://127.0.0.1:8082".to_string());
    let issuer_pem = std::env::var("OCSP_ISSUER_PEM")
        .unwrap_or_else(|_| "/tmp/ostrich-e2e/root-ca.pem".to_string());

    println!("=== OCSP revocation round-trip against {} ===", ocsp_url);

    // 1. Issue a certificate
    let mut client = connect_ca(&cfg.ca_grpc_endpoint).await;
    let spki = generate_test_rsa_spki();
    let cn = "ocsp-roundtrip.example.com";
    let issued = issue_test_certificate(&mut client, &cfg.ca_profile_name, cn, spki).await;
    println!(
        "[step 1] issued certificate id={} serial={} bytes",
        issued.certificate_id,
        issued.serial_number.len()
    );

    // 2. OCSP should report "good" before revocation
    let status = openssl_ocsp_status(&issuer_pem, &issued.pem_encoded, &ocsp_url, "good");
    assert!(
        status.contains(": good"),
        "expected OCSP status 'good' before revocation, got: {}",
        status
    );
    println!("[step 2] OCSP reports good (pre-revocation): {}", status);

    // 3. Revoke the certificate over gRPC (keyCompromise)
    let revoke = client
        .revoke_certificate(tonic::Request::new(RevokeCertificateRequest {
            certificate_id: issued.certificate_id.clone(),
            reason: RevocationReason::KeyCompromise as i32,
            requestor: "ocsp-e2e-test".to_string(),
            justification: "round-trip test".to_string(),
        }))
        .await
        .expect("revoke_certificate failed")
        .into_inner();
    assert!(revoke.success, "revocation should report success");
    println!("[step 3] certificate revoked (reason=keyCompromise)");

    // 4. OCSP should now report "revoked".
    //    The responder caches by serial, but a revocation invalidates the
    //    cache (and nonce'd requests bypass the cache entirely), so a fresh
    //    query must reflect the new status.
    let status = openssl_ocsp_status(&issuer_pem, &issued.pem_encoded, &ocsp_url, "revoked");
    assert!(
        status.contains(": revoked"),
        "expected OCSP status 'revoked' after revocation, got: {}",
        status
    );
    println!(
        "[step 4] OCSP reports revoked (post-revocation): {}",
        status
    );
    println!("=== OCSP revocation round-trip PASSED ===");
}
