//! Live end-to-end proof that issued certificates carry the Authority
//! Information Access (AIA) extension — OCSP responder + CA Issuers URLs —
//! verified by parsing the issued certificate with the external `openssl` tool.
//!
//! This exercises the real `CertificateIssuer::issue()` path after configuring
//! the OCSP / CA-issuers URLs, closing the gap where issued leaves carried a CRL
//! Distribution Point but no AIA, leaving relying parties unable to discover the
//! OCSP responder (RFC 5280 §4.2.2.1 / RFC 6960).
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §4.2.2.1 - Authority Information Access (id-ad-ocsp, id-ad-caIssuers)
//! - RFC 6960 - OCSP responder discovery
//! - NIST 800-53: SC-17 - PKI certificate status distribution
//!
//! Gated on DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + PKCS11_PIN and the
//! presence of the `openssl` binary; skips (passes) when not configured.
//!
//! Run live with `--test-threads=1`: this and the audit_signing_e2e test share
//! the database and the SoftHSM token, and two PKCS#11 providers opened against
//! the same module concurrently can crash.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::{
    DatabasePool, PoolConfig,
    models::Certificate,
    repository::CaRepository,
};
use ostrich_x509::{CertificateBuilder, extensions::SubjectAltName, profile::KeyUsage};

use crate::CertificateAuthority;
use crate::approval::ApprovalConfig;
use crate::issuance::IssuanceRequest;

const OCSP_URL: &str = "http://ocsp.test.example";
const CA_ISSUERS_URL: &str = "http://ca.test.example/api/v1/ca-certificate";

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
async fn issued_certificates_carry_aia_extension_verified_by_openssl() {
    let (Ok(db_url), Ok(module), Ok(slot), Ok(pin)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("PKCS11_MODULE_PATH"),
        std::env::var("PKCS11_SLOT"),
        std::env::var("PKCS11_PIN"),
    ) else {
        eprintln!(
            "issuance_aia_e2e: set DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + \
             PKCS11_PIN to run this live test; skipping"
        );
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("issuance_aia_e2e: openssl not found; skipping");
        return;
    }
    let slot: u64 = slot.parse().expect("PKCS11_SLOT must be numeric");

    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .expect("connect to test DB");
    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await
            .unwrap_or_else(|e| panic!("clean {table}: {e}"));
    }

    // --- HSM-backed CA key (ECDSA P-256) + self-signed root cert ---
    let crypto: Box<dyn CryptoProvider> =
        CryptoProviderFactory::create_pkcs11_provider(Path::new(&module), slot, &pin)
            .await
            .expect("PKCS#11 provider");
    let key_label = "ostrich-aia-e2e-ca";
    let key_handle = crypto
        .generate_key_pair(KeyType::EcP256, key_label, false)
        .await
        .expect("generate CA key");
    let ca_spki = crypto.export_public_key(&key_handle).await.unwrap();
    let sig_alg = Algorithm::EcdsaP256Sha256;

    let subject = DistinguishedName {
        common_name: Some("OstrichPKI AIA E2E Root CA".to_string()),
        organization: Some("OstrichPKI".to_string()),
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
        .add_key_usage(KeyUsage::DigitalSignature)
        .signature_algorithm(sig_alg)
        .build_tbs()
        .unwrap();
    let not_before = tbs.not_before;
    let not_after = tbs.not_after;
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
            ca_key_row.id, serial.as_bytes(), &dn, &dn, not_before, not_after,
            &ca_der, &ca_pem, true, None, None,
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

    // --- Build the CA, configure AIA URLs, register a TLS server profile ---
    let mut ca = CertificateAuthority::new(ca_certificate, key_handle, crypto, pool.clone(), 24)
        .expect("CertificateAuthority::new");
    ca.set_ocsp_responder_url(OCSP_URL);
    ca.set_ca_issuers_url(CA_ISSUERS_URL);
    // Issue without an approval request for the test (the wiring under test is
    // AIA emission, not the approval workflow).
    ca.set_approval_config(ApprovalConfig {
        require_approval: false,
        ..ApprovalConfig::default()
    });
    let profile = ostrich_x509::CertificateProfile::tls_server(397);
    let profile_name = profile.name.clone();
    ca.add_profile(profile);

    // --- Leaf public key (software provider; the CA signs it) ---
    let leaf_provider = CryptoProviderFactory::create_software_provider();
    let leaf_key = leaf_provider
        .generate_key_pair(KeyType::EcP256, "aia-e2e-leaf", true)
        .await
        .unwrap();
    let leaf_spki = leaf_provider.export_public_key(&leaf_key).await.unwrap();

    // --- Issue the leaf (with a caller-supplied request_id for FDP_CER_EXT.2) ---
    let request_id = uuid::Uuid::new_v4();
    let issued = ca
        .issuer()
        .issue(IssuanceRequest {
            profile_name,
            subject: DistinguishedName {
                common_name: Some("leaf.test.example".to_string()),
                ..Default::default()
            },
            subject_alt_names: vec![SubjectAltName::DnsName("leaf.test.example".to_string())],
            public_key: leaf_spki,
            requestor: "aia-e2e".to_string(),
            metadata: None,
            csr_der: None,
            approval_request_id: None,
            request_id: Some(request_id),
        })
        .await
        .expect("issue leaf certificate");

    // --- External verification: openssl must show the AIA extension ---
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("ostrich-aia-e2e-{}.der", issued.certificate_id));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(&issued.der_encoded).unwrap();
    }
    let out = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&tmp)
        .args(["-noout", "-text"])
        .output()
        .expect("run openssl");
    let _ = std::fs::remove_file(&tmp);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        text.contains("Authority Information Access"),
        "issued cert must carry an AIA extension; openssl output:\n{text}"
    );
    assert!(
        text.contains(&format!("OCSP - URI:{OCSP_URL}")),
        "AIA must include the OCSP responder URI; openssl output:\n{text}"
    );
    assert!(
        text.contains(&format!("CA Issuers - URI:{CA_ISSUERS_URL}")),
        "AIA must include the CA Issuers URI; openssl output:\n{text}"
    );

    // --- FDP_CER_EXT.2: the request_id links request -> certificate -> audit ---
    let stored = ostrich_db::repository::CertificateRepository::new(pool.clone())
        .find_by_id(issued.certificate_id)
        .await
        .unwrap()
        .expect("issued certificate row");
    assert_eq!(
        stored.request_id,
        Some(request_id),
        "the issued certificate must record the request_id (FDP_CER_EXT.2)"
    );

    let events = ostrich_db::repository::AuditRepository::new(pool.clone())
        .all_events_ordered()
        .await
        .unwrap();
    let issuance_evt = events
        .iter()
        .find(|e| e.event_type == "certificate_issuance")
        .expect("a certificate_issuance audit event");
    assert_eq!(
        issuance_evt
            .details
            .as_ref()
            .and_then(|d| d.get("request_id"))
            .and_then(|v| v.as_str()),
        Some(request_id.to_string().as_str()),
        "the issuance audit event must record the same request_id (end-to-end traceability)"
    );

    // --- Secure-default enforcement: a weak profile is rejected at issuance ---
    // The successful issuance above already proves a compliant profile passes;
    // here a profile with end-entity validity beyond the 825-day ceiling must be
    // refused by issue() (NIAP FMT_MSA.1.2 / NIST CM-2).
    let mut weak = ostrich_x509::CertificateProfile::tls_server(4000);
    weak.name = "weak-overlong".to_string();
    weak.validity_days = 4000; // exceeds MAX_END_ENTITY_VALIDITY_DAYS (825)
    ca.add_profile(weak);
    let weak_leaf = leaf_provider.export_public_key(&leaf_key).await.unwrap();
    let weak_result = ca
        .issuer()
        .issue(IssuanceRequest {
            profile_name: "weak-overlong".to_string(),
            subject: DistinguishedName {
                common_name: Some("weak.test.example".to_string()),
                ..Default::default()
            },
            subject_alt_names: vec![SubjectAltName::DnsName("weak.test.example".to_string())],
            public_key: weak_leaf,
            requestor: "aia-e2e".to_string(),
            metadata: None,
            csr_der: None,
            approval_request_id: None,
            request_id: None,
        })
        .await;
    assert!(
        weak_result.is_err(),
        "issuance with an over-long-validity profile must be rejected by secure-default enforcement"
    );

    for table in ["audit_events", "certificates", "ca_certificates", "ca_keys"] {
        let _ = sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool.pool())
            .await;
    }
}
