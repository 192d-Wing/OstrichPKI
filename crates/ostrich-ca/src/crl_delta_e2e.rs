//! Live delta-CRL lifecycle e2e (RFC 5280 §5.2.4 / §5.2.6), openssl-verified.
//!
//! Builds a SoftHSM-backed CA configured with a delta CRL URL, then:
//!   1. revokes cert A and generates a FULL CRL — openssl shows the Freshest CRL
//!      pointer (and the full CRL lists A),
//!   2. revokes cert B (after the full CRL) and generates a DELTA CRL — openssl
//!      shows the Delta CRL Indicator, and the delta lists only B (the change
//!      since the base), not A.
//!
//! Gated on DATABASE_URL + PKCS11_* + openssl; skips otherwise. Run live with
//! `--test-threads=1` (shares the DB + SoftHSM token with the other e2e tests).

use std::path::Path;
use std::process::Command;

use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::{
    DatabasePool, PoolConfig,
    models::Certificate,
    repository::{CaRepository, CertificateRepository, Repository},
};
use ostrich_x509::{CertificateBuilder, parser::RevocationReason, profile::KeyUsage};

use crate::CertificateAuthority;
use crate::revocation::RevocationRequest;

const DELTA_URL: &str = "http://crl.test.example/delta.crl";

fn assemble_certificate(tbs_der: &[u8], signature: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode, asn1::BitString};
    use x509_cert::{Certificate as X509Cert, TbsCertificate};
    let tbs = TbsCertificate::from_der(tbs_der).expect("re-parse TBS");
    let signature_algorithm = tbs.signature.clone();
    let signature = BitString::from_bytes(signature).expect("sig BitString");
    X509Cert {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    }
    .to_der()
    .expect("encode cert")
}

fn openssl_crl_text(der: &[u8], tag: &str) -> String {
    use std::io::Write as _;
    let path = std::env::temp_dir().join(format!("ostrich-{tag}.crl"));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(der)
        .unwrap();
    let out = Command::new("openssl")
        .args([
            "crl",
            "-inform",
            "DER",
            "-in",
            path.to_str().unwrap(),
            "-text",
            "-noout",
        ])
        .output()
        .expect("openssl crl");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "openssl crl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

async fn insert_and_revoke(
    ca: &CertificateAuthority,
    pool: &DatabasePool,
    ca_id: uuid::Uuid,
    serial: Vec<u8>,
) {
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let leaf = Certificate {
        id,
        ca_id,
        serial_number: serial,
        subject_dn: format!("CN=leaf-{id}"),
        issuer_dn: "CN=delta-ca".to_string(),
        not_before: now,
        not_after: now,
        der_encoded: vec![0x30, 0x00],
        pem_encoded: String::new(),
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
    CertificateRepository::new(pool.clone())
        .create(&leaf)
        .await
        .expect("insert leaf");
    ca.revocation_manager()
        .revoke(RevocationRequest {
            certificate_id: id,
            reason: RevocationReason::KeyCompromise,
            requestor: "crl-delta-e2e".to_string(),
            justification: None,
        })
        .await
        .expect("revoke leaf");
}

#[tokio::test]
async fn delta_crl_lifecycle_verified_by_openssl() {
    let (Ok(db_url), Ok(module), Ok(slot), Ok(pin)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("PKCS11_MODULE_PATH"),
        std::env::var("PKCS11_SLOT"),
        std::env::var("PKCS11_PIN"),
    ) else {
        eprintln!("crl_delta_e2e: set DATABASE_URL + PKCS11_* to run; skipping");
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        return;
    }
    let slot: u64 = slot.parse().unwrap();

    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .unwrap();
    for t in [
        "crls",
        "audit_events",
        "certificates",
        "ca_certificates",
        "ca_keys",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {t}")))
            .execute(pool.pool())
            .await
            .unwrap();
    }

    // --- SoftHSM CA + self-signed root ---
    let crypto: Box<dyn CryptoProvider> =
        CryptoProviderFactory::create_pkcs11_provider(Path::new(&module), slot, &pin)
            .await
            .unwrap();
    let key_label = "ostrich-delta-crl-ca";
    let key = crypto
        .generate_key_pair(KeyType::EcP256, key_label, false)
        .await
        .unwrap();
    let ca_spki = crypto.export_public_key(&key).await.unwrap();
    let sig_alg = Algorithm::EcdsaP256Sha256;
    let subject = DistinguishedName {
        common_name: Some("OstrichPKI Delta CRL E2E CA".to_string()),
        ..Default::default()
    };
    let mut sb = ostrich_common::util::random::secure_random_bytes(20);
    sb[0] &= 0x7F;
    let serial = SerialNumber::from_bytes(sb).unwrap();
    let tbs = CertificateBuilder::new()
        .serial_number(serial.clone())
        .subject(subject.clone())
        .issuer(subject.clone())
        .validity_days(3650)
        .public_key(ca_spki.clone())
        .basic_constraints(true, None)
        .add_key_usage(KeyUsage::KeyCertSign)
        .add_key_usage(KeyUsage::CrlSign)
        .signature_algorithm(sig_alg)
        .build_tbs()
        .unwrap();
    let (nb, na) = (tbs.not_before, tbs.not_after);
    let tbs_der = tbs.to_der().unwrap();
    let raw = crypto.sign(&key, sig_alg, &tbs_der).await.unwrap();
    let xsig = ostrich_x509::signing::encode_x509_signature(sig_alg, raw).unwrap();
    let ca_der = assemble_certificate(&tbs_der, &xsig);
    let ca_pem =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &ca_der).unwrap();
    let dn = subject.to_string_rfc4514();

    let ca_repo = CaRepository::new(pool.clone());
    let ca_key_row = ca_repo
        .create_ca_key(
            key_label,
            "EcP256",
            "EcdsaP256Sha256",
            "Pkcs11",
            Some(slot as i64),
            &key.key_id,
            false,
        )
        .await
        .unwrap();
    let ca_cert_row = ca_repo
        .create_ca_certificate(
            ca_key_row.id,
            serial.as_bytes(),
            &dn,
            &dn,
            nb,
            na,
            &ca_der,
            &ca_pem,
            true,
            None,
            None,
        )
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let ca_model = Certificate {
        id: ca_cert_row.id,
        ca_id: ca_cert_row.id,
        serial_number: serial.as_bytes().to_vec(),
        subject_dn: dn.clone(),
        issuer_dn: dn.clone(),
        not_before: nb,
        not_after: na,
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
    let mut ca = CertificateAuthority::new(ca_model, key, crypto, pool.clone(), 24).unwrap();
    ca.set_delta_crl_url(DELTA_URL);
    let ca_id = ca_cert_row.id;

    // --- 1. Revoke A, generate the FULL (base) CRL ---
    insert_and_revoke(&ca, &pool, ca_id, vec![0xAA, 0x01]).await;
    let full = ca
        .revocation_manager()
        .generate_crl(ca.ca_dn.clone())
        .await
        .unwrap();
    assert_eq!(full.revoked_count, 1, "full CRL should list cert A");
    let full_text = openssl_crl_text(&full.der_encoded, "full");
    assert!(
        full_text.contains("Freshest CRL"),
        "full CRL must carry a Freshest CRL pointer:\n{full_text}"
    );

    // --- 2. Revoke B (after the base CRL), generate the DELTA CRL ---
    insert_and_revoke(&ca, &pool, ca_id, vec![0xBB, 0x02]).await;
    let delta = ca
        .revocation_manager()
        .generate_delta_crl(ca.ca_dn.clone())
        .await
        .unwrap();
    assert_eq!(
        delta.revoked_count, 1,
        "delta must list ONLY cert B (the change since the base CRL)"
    );
    let delta_text = openssl_crl_text(&delta.der_encoded, "delta");
    assert!(
        delta_text.contains("Delta CRL Indicator"),
        "delta CRL must carry the Delta CRL Indicator:\n{delta_text}"
    );

    for t in [
        "crls",
        "audit_events",
        "certificates",
        "ca_certificates",
        "ca_keys",
    ] {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {t}")))
            .execute(pool.pool())
            .await;
    }
}
