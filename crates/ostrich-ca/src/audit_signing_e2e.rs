//! Live end-to-end proof that the production CA emits SIGNED audit records
//! (AU-10 non-repudiation) verifiable with the CA's published public key.
//!
//! This exercises the real wiring added in `CertificateAuthority::new`: it builds
//! a CA backed by an HSM (PKCS#11) key, performs a real revocation, and shows
//! that the resulting audit record is signed and that `verify_signed_chain`
//! accepts it against the CA certificate's public key — and rejects it once a
//! signature byte is corrupted.
//!
//! A PKCS#11 key is used (not a software key) because that is the production
//! shape: software ECDSA/RSA CA keys fail FCS_STG_EXT.1 HSM validation, and the
//! software ML-DSA exception is not yet verifiable through `verify_with_spki`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-10 (Non-repudiation), AU-9(3) (Cryptographic protection)
//! - NIAP PP-CA: FAU_STG.4 (Prevention of undetected audit modification),
//!   FCS_STG_EXT.1 (HSM-backed CA key)
//!
//! Gated on DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + PKCS11_PIN; skips
//! (passes) when they are not set, so the normal `cargo test` run is unaffected.
//!
//! Run live with `--test-threads=1`: this and the issuance_aia_e2e test share
//! the database and the SoftHSM token, and two PKCS#11 providers opened against
//! the same module concurrently can crash.

use std::path::Path;

use ostrich_audit::sink::DatabaseAuditSink;
use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::{
    DatabasePool, PoolConfig,
    models::Certificate,
    repository::{AuditRepository, CaRepository, CertificateRepository, Repository},
};
use ostrich_x509::{CertificateBuilder, parser::RevocationReason, profile::KeyUsage};

use crate::CertificateAuthority;
use crate::revocation::RevocationRequest;

/// Assemble a DER Certificate from its TBS and signature (mirrors ostrich-init).
fn assemble_certificate(tbs_der: &[u8], signature: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode, asn1::BitString};
    use x509_cert::{Certificate as X509Cert, TbsCertificate};

    let tbs = TbsCertificate::from_der(tbs_der).expect("re-parse TBS");
    let signature_algorithm = tbs.signature.clone();
    let signature = BitString::from_bytes(signature).expect("signature BitString");
    X509Cert {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    }
    .to_der()
    .expect("encode certificate")
}

#[tokio::test]
async fn ca_emits_signed_audit_records_verifiable_with_ca_public_key() {
    let (Ok(db_url), Ok(module), Ok(slot), Ok(pin)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("PKCS11_MODULE_PATH"),
        std::env::var("PKCS11_SLOT"),
        std::env::var("PKCS11_PIN"),
    ) else {
        eprintln!(
            "audit_signing_e2e: set DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + \
             PKCS11_PIN to run this live test; skipping"
        );
        return;
    };
    let slot: u64 = slot.parse().expect("PKCS11_SLOT must be numeric");

    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .expect("connect to test DB");

    // Reset the tables this test touches (FK order: children first).
    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await
            .unwrap_or_else(|e| panic!("clean {table}: {e}"));
    }

    // --- HSM-backed CA key (ECDSA P-256) ---
    let crypto: Box<dyn CryptoProvider> =
        CryptoProviderFactory::create_pkcs11_provider(Path::new(&module), slot, &pin)
            .await
            .expect("PKCS#11 provider");
    let key_label = "ostrich-audit-e2e-ca";
    let key_handle = crypto
        .generate_key_pair(KeyType::EcP256, key_label, false)
        .await
        .expect("generate CA key in HSM");
    let ca_spki = crypto
        .export_public_key(&key_handle)
        .await
        .expect("export CA public key");
    let sig_alg = Algorithm::EcdsaP256Sha256;

    // --- Self-sign a root CA certificate (mirrors ostrich-init) ---
    let subject = DistinguishedName {
        common_name: Some("OstrichPKI Audit E2E Root CA".to_string()),
        organization: Some("OstrichPKI".to_string()),
        ..Default::default()
    };
    let mut serial_bytes = ostrich_common::util::random::secure_random_bytes(20);
    serial_bytes[0] &= 0x7F; // RFC 5280 §4.1.2.2 positive serial
    let serial = SerialNumber::from_bytes(serial_bytes).unwrap();

    let tbs = CertificateBuilder::new()
        .serial_number(serial.clone())
        .subject(subject.clone())
        .issuer(subject.clone())
        .validity_days(3650)
        .public_key(ca_spki.clone())
        .basic_constraints(true, None)
        .add_key_usage(KeyUsage::KeyCertSign)
        .add_key_usage(KeyUsage::CrlSign)
        .add_key_usage(KeyUsage::DigitalSignature)
        .signature_algorithm(sig_alg)
        .build_tbs()
        .expect("build TBS");
    let not_before = tbs.not_before;
    let not_after = tbs.not_after;
    let tbs_der = tbs.to_der().expect("encode TBS");
    let raw_sig = crypto.sign(&key_handle, sig_alg, &tbs_der).await.unwrap();
    let x509_sig = ostrich_x509::signing::encode_x509_signature(sig_alg, raw_sig).unwrap();
    let ca_der = assemble_certificate(&tbs_der, &x509_sig);
    let ca_pem =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &ca_der).unwrap();
    let dn = subject.to_string_rfc4514();

    // --- Register CA key + cert ---
    let ca_repo = CaRepository::new(pool.clone());
    let ca_key_row = ca_repo
        .create_ca_key(
            key_label,
            "EcP256",
            "EcdsaP256Sha256",
            "Pkcs11",
            Some(slot as i64),
            &key_handle.key_id,
            false,
        )
        .await
        .expect("register CA key");
    let ca_cert_row = ca_repo
        .create_ca_certificate(
            ca_key_row.id,
            serial.as_bytes(),
            &dn,
            &dn,
            not_before,
            not_after,
            &ca_der,
            &ca_pem,
            true,
            None,
            None,
        )
        .await
        .expect("register CA certificate");

    // CA model the CertificateAuthority operates with.
    let now = chrono::Utc::now();
    let ca_certificate = Certificate {
        id: ca_cert_row.id,
        ca_id: ca_cert_row.id,
        serial_number: serial.as_bytes().to_vec(),
        subject_dn: dn.clone(),
        issuer_dn: dn.clone(),
        not_before,
        not_after,
        der_encoded: ca_der.clone(),
        pem_encoded: ca_pem.clone(),
        revoked: false,
        revocation_time: None,
        revocation_reason: None,
        issuer_service: Some("CA".to_string()),
        requestor: None,
        profile_name: None,
        metadata: None,
        request_id: None,
        created_at: now,
        updated_at: now,
    };

    // --- Insert a leaf certificate to revoke ---
    let leaf_id = uuid::Uuid::new_v4();
    let mut leaf_serial = ostrich_common::util::random::secure_random_bytes(20);
    leaf_serial[0] &= 0x7F;
    let leaf = Certificate {
        id: leaf_id,
        ca_id: ca_cert_row.id,
        serial_number: leaf_serial,
        subject_dn: "CN=audit-e2e-leaf".to_string(),
        issuer_dn: dn.clone(),
        not_before,
        not_after,
        der_encoded: ca_der.clone(), // contents irrelevant to revoke()
        pem_encoded: ca_pem.clone(),
        revoked: false,
        revocation_time: None,
        revocation_reason: None,
        issuer_service: Some("CA".to_string()),
        requestor: Some("audit-e2e".to_string()),
        profile_name: None,
        metadata: None,
        request_id: None,
        created_at: now,
        updated_at: now,
    };
    CertificateRepository::new(pool.clone())
        .create(&leaf)
        .await
        .expect("insert leaf cert");

    // --- Build the real CA (this wires the SIGNED audit sinks) and revoke ---
    let ca = CertificateAuthority::new(
        ca_certificate,
        key_handle,
        crypto,
        pool.clone(),
        24, // crl_validity_hours
    )
    .expect("CertificateAuthority::new");

    ca.revocation_manager()
        .revoke(RevocationRequest {
            certificate_id: leaf_id,
            reason: RevocationReason::KeyCompromise,
            requestor: "audit-e2e-admin".to_string(),
            justification: Some("AU-10 live wiring proof".to_string()),
        })
        .await
        .expect("revoke leaf");

    // --- The revocation produced a SIGNED audit record ---
    let audit_repo = AuditRepository::new(pool.clone());
    let events = audit_repo.all_events_ordered().await.unwrap();
    assert!(!events.is_empty(), "expected at least one audit event");
    let revocation_evt = events
        .iter()
        .find(|e| e.event_type == "certificate_revocation")
        .expect("a certificate_revocation audit event");
    assert!(
        revocation_evt.signature.is_some(),
        "production CA audit record must be signed (AU-10)"
    );
    assert_eq!(
        revocation_evt.signing_key_id.as_deref(),
        Some(key_label),
        "signing_key_id must identify the CA key"
    );

    // --- It verifies against the CA certificate's public key ---
    let verifier = DatabaseAuditSink::new(pool.clone());
    assert!(
        verifier
            .verify_signed_chain(&ca_spki, sig_alg)
            .await
            .unwrap(),
        "signed audit chain must verify with the CA public key"
    );

    // --- Corrupting a signature byte makes verification fail (AU-10) ---
    let mut bad_sig = revocation_evt.signature.clone().unwrap();
    bad_sig[0] ^= 0xFF;
    sqlx::query("UPDATE audit_events SET signature = $1 WHERE id = $2")
        .bind(&bad_sig)
        .bind(revocation_evt.id)
        .execute(pool.pool())
        .await
        .unwrap();
    assert!(
        !verifier
            .verify_signed_chain(&ca_spki, sig_alg)
            .await
            .unwrap(),
        "a corrupted signature must be detected (AU-10)"
    );

    // Cleanup so the scratch DB carries no poisoned chain.
    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        let _ = sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await;
    }
}
