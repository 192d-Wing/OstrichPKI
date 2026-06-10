//! Live proof of proof-of-possession (PoP) enforcement on the CA issuance path.
//!
//! With the secure default (`require_proof_of_possession = true`), end-entity
//! issuance must include a CSR whose signature verifies and whose public key
//! matches the request. This test exercises all three outcomes against a real
//! CA backed by a SoftHSM (PKCS#11) key:
//!   1. no CSR            -> rejected (PoP required)
//!   2. valid CSR + key   -> issued
//!   3. CSR + wrong key   -> rejected (public-key mismatch)
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (input validation), SC-8(1) (proof of possession)
//! - RFC 2986 - PKCS#10 certification request signature
//!
//! Gated on DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + PKCS11_PIN; skips
//! when not configured. Run live with `--test-threads=1` (shares the DB +
//! SoftHSM token with the other e2e tests).

use std::path::Path;

use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::{DatabasePool, PoolConfig, models::Certificate, repository::CaRepository};
use ostrich_x509::{CertificateBuilder, extensions::SubjectAltName, profile::KeyUsage};

use crate::CertificateAuthority;
use crate::approval::ApprovalConfig;
use crate::issuance::IssuanceRequest;

/// A valid PKCS#10 CSR (RSA-2048, subject C=US,ST=NY,L=NYC,O=OstrichPKI,CN=test-cn)
/// with a self-consistent sha256WithRSAEncryption signature. Shared with the
/// ostrich-x509 parser tests.
const CSR_HEX: &str = "308202e4308201cc020100304f310b3009060355040613025553310b300906\
     035504080c024e59310c300a06035504070c034e594331133011060355040a\
     0c0a4f737472696368504b493110300e06035504030c07746573742d636e30\
     820122300d06092a864886f70d01010105000382010f003082010a02820101\
     00be86f82dd15ef264fe2ecd0ebd5960d9378b5b84191b76214c581825185953\
     c7316c4de350058c45655b392d87f5de4ef9fb8f9fe4fcc595f82964412385e\
     9a8732c87b0eaa05b13849480c5050461dc50f79281935e03a585432cfc09c4\
     f6a4730164afd9743ded98fe135c1203d5ea96fbb3ec3a8620db6f89c7700a0\
     f19f201888a90936d54baabd79cfd2a3d1715282bb309ced5fe588d99db24ed\
     f1f66822eb57d5236a3093f5c0ab5adc66431b80c998163acc2fb0f881214a8\
     7a5be084ff4d209c31d04ee9d7422001eee801d66ee8be4d1ae18a63b325200\
     a3a11c9c7dab09adb5b7cf4c6e96418f7dc7ee1bc096e46b9d076a27f87cddc\
     8311bc83d0203010001a050304e06092a864886f70d01090e3141303f303d06\
     03551d1104363034820f7777772e6578616d706c652e636f6d820f6170692e\
     6578616d706c652e636f6d811074657374406578616d706c652e636f6d300d\
     06092a864886f70d01010b05000382010100b1bbfb93099c3b3e371ba55a16\
     580645faf0e793a9305d2fc4fc6a65b3314276614591094c01a3272898abfec\
     7d4e29cd23efb0608358f4aff0995f86fa0b92f763db99f3f4f4e9e53d246ed\
     88fa453f51a84db8714dec0cb6cca913b672f67c6787965f23ce679b232edde\
     711c78c118156e359aa67e443da2e369a4baf06a9d6f7d0b580db9b421ffd72\
     727904b8e266090be6e8735a8424f1706564bff395bbf4af2db95851c6dbaf\
     fc58d95d945993403016710c16bb51bdc44a7c5e855b51c3327c5991372e8c2\
     bed9bf228b4ecf90b5941b3efaf52b06f3c34cabc1182977f36eeeebbc5d5eb\
     beafc0f80845d755d818d30a5d67e979b2ffb5cc0a59c5";

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

fn req(
    profile_name: &str,
    public_key: Vec<u8>,
    csr_der: Option<Vec<u8>>,
) -> IssuanceRequest {
    IssuanceRequest {
        profile_name: profile_name.to_string(),
        subject: DistinguishedName {
            common_name: Some("test-cn".to_string()),
            ..Default::default()
        },
        subject_alt_names: vec![SubjectAltName::DnsName("www.example.com".to_string())],
        public_key,
        requestor: "pop-e2e".to_string(),
        metadata: None,
        csr_der,
        approval_request_id: None,
        request_id: None,
    }
}

#[tokio::test]
async fn proof_of_possession_is_enforced_for_end_entity_issuance() {
    let (Ok(db_url), Ok(module), Ok(slot), Ok(pin)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("PKCS11_MODULE_PATH"),
        std::env::var("PKCS11_SLOT"),
        std::env::var("PKCS11_PIN"),
    ) else {
        eprintln!("pop_e2e: set DATABASE_URL + PKCS11_* to run; skipping");
        return;
    };
    let slot: u64 = slot.parse().expect("PKCS11_SLOT numeric");

    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .unwrap();
    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await
            .unwrap_or_else(|e| panic!("clean {table}: {e}"));
    }

    // --- HSM-backed CA + self-signed root (mirrors the other e2e tests) ---
    let crypto: Box<dyn CryptoProvider> =
        CryptoProviderFactory::create_pkcs11_provider(Path::new(&module), slot, &pin)
            .await
            .unwrap();
    let key_label = "ostrich-pop-e2e-ca";
    let key_handle = crypto
        .generate_key_pair(KeyType::EcP256, key_label, false)
        .await
        .unwrap();
    let ca_spki = crypto.export_public_key(&key_handle).await.unwrap();
    let sig_alg = Algorithm::EcdsaP256Sha256;

    let subject = DistinguishedName {
        common_name: Some("OstrichPKI PoP E2E Root CA".to_string()),
        ..Default::default()
    };
    let mut serial_bytes = ostrich_common::util::random::secure_random_bytes(20);
    serial_bytes[0] &= 0x7F;
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
        .signature_algorithm(sig_alg)
        .build_tbs()
        .unwrap();
    let (not_before, not_after) = (tbs.not_before, tbs.not_after);
    let tbs_der = tbs.to_der().unwrap();
    let raw_sig = crypto.sign(&key_handle, sig_alg, &tbs_der).await.unwrap();
    let x509_sig = ostrich_x509::signing::encode_x509_signature(sig_alg, raw_sig).unwrap();
    let ca_der = assemble_certificate(&tbs_der, &x509_sig);
    let ca_pem =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &ca_der).unwrap();
    let dn = subject.to_string_rfc4514();

    let ca_repo = CaRepository::new(pool.clone());
    let ca_key_row = ca_repo
        .create_ca_key(
            key_label, "EcP256", "EcdsaP256Sha256", "Pkcs11", Some(slot as i64),
            &key_handle.key_id, false,
        )
        .await
        .unwrap();
    let ca_cert_row = ca_repo
        .create_ca_certificate(
            ca_key_row.id, serial.as_bytes(), &dn, &dn, not_before, not_after, &ca_der, &ca_pem,
            true, None, None,
        )
        .await
        .unwrap();

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

    let mut ca = CertificateAuthority::new(ca_certificate, key_handle, crypto, pool.clone(), 24)
        .unwrap();
    ca.set_approval_config(ApprovalConfig {
        require_approval: false,
        ..ApprovalConfig::default()
    });
    // Proof-of-possession stays at the secure default (required).
    let profile = ostrich_x509::CertificateProfile::tls_server(397);
    let profile_name = profile.name.clone();
    ca.add_profile(profile);

    let csr_der = hex::decode(CSR_HEX.replace(['\n', ' '], "")).unwrap();
    let csr_public_key = ostrich_x509::parser::parse_csr(&csr_der).unwrap().public_key;

    // 1. No CSR -> rejected (proof-of-possession required).
    let no_csr = ca
        .issuer()
        .issue(req(&profile_name, csr_public_key.clone(), None))
        .await;
    assert!(
        no_csr.is_err(),
        "end-entity issuance without a CSR must be rejected when PoP is required"
    );

    // 2. Valid CSR whose public key matches -> issued.
    let ok = ca
        .issuer()
        .issue(req(
            &profile_name,
            csr_public_key.clone(),
            Some(csr_der.clone()),
        ))
        .await;
    assert!(
        ok.is_ok(),
        "issuance with a valid CSR and matching key must succeed: {:?}",
        ok.err()
    );

    // 3. CSR present but request public key differs -> rejected (key mismatch).
    let other_provider = CryptoProviderFactory::create_software_provider();
    let other_key = other_provider
        .generate_key_pair(KeyType::EcP256, "pop-other", true)
        .await
        .unwrap();
    let other_spki = other_provider.export_public_key(&other_key).await.unwrap();
    let mismatch = ca
        .issuer()
        .issue(req(&profile_name, other_spki, Some(csr_der.clone())))
        .await;
    assert!(
        mismatch.is_err(),
        "a CSR whose public key does not match the request must be rejected"
    );

    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        let _ = sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await;
    }
}
