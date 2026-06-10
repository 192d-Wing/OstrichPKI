//! Full live EST → CA stack e2e for server-side key generation (RFC 7030 §4.4),
//! exercised over real HTTP and gRPC, in-process.
//!
//! Spins up a CA gRPC service backed by a SoftHSM (PKCS#11) key and the EST HTTP
//! server wired to that CA, then POSTs a CSR to `/.well-known/est/serverkeygen`
//! and verifies the RFC 7030 §4.4.2 `multipart/mixed` response: the returned
//! PKCS#8 private key's public key matches the public key in the returned
//! (PKCS#7) certificate, as confirmed by the external `openssl` tool.
//!
//! Gated on DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + PKCS11_PIN and the
//! `openssl` binary; skips otherwise.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ostrich_audit::sink::DatabaseAuditSink;
use ostrich_common::auth::provider::{AuthProvider, AuthResult, Credentials, SessionInfo};
use ostrich_common::auth::user::{AuthMethod, AuthenticatedUser, UserId};
use ostrich_common::auth::{AuthError, RbacPolicy, roles::Role};
use ostrich_common::types::{DistinguishedName, SerialNumber};
use ostrich_crypto::{Algorithm, CryptoProvider, CryptoProviderFactory, KeyType};
use ostrich_db::{DatabasePool, PoolConfig, models::Certificate, repository::CaRepository};
use ostrich_x509::extensions::SubjectAltName;
use ostrich_x509::{CertificateBuilder, profile::KeyUsage};

/// AuthProvider that authenticates every request as a fixed RA-staff user (which
/// holds Permission::SubmitRequest). Lets the test drive the protected
/// /serverkeygen endpoint without standing up the full password/session stack.
struct TestAuthProvider {
    user: AuthenticatedUser,
}

#[async_trait::async_trait]
impl AuthProvider for TestAuthProvider {
    async fn authenticate(&self, _c: &Credentials) -> AuthResult<AuthenticatedUser> {
        Ok(self.user.clone())
    }
    async fn validate_session(&self, _t: &str) -> AuthResult<SessionInfo> {
        Ok(SessionInfo {
            token: "test".to_string(),
            user: self.user.clone(),
            expires_at: 0,
            is_valid: true,
        })
    }
    async fn create_session(&self, _u: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        Err(AuthError::Internal("unused".into()))
    }
    async fn invalidate_session(&self, _t: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn record_failed_attempt(&self, _u: &str, _r: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn is_account_locked(&self, _u: &str) -> AuthResult<bool> {
        Ok(false)
    }
    async fn unlock_account(&self, _u: &str) -> AuthResult<()> {
        Ok(())
    }
    fn provider_name(&self) -> &str {
        "test"
    }
    fn supported_methods(&self) -> &[AuthMethod] {
        &[AuthMethod::Password]
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

/// Wait until `addr` accepts a TCP connection (server is up).
async fn wait_for_port(addr: std::net::SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server at {addr} never came up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn est_serverkeygen_full_stack_over_http() {
    let (Ok(db_url), Ok(module), Ok(slot), Ok(pin)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("PKCS11_MODULE_PATH"),
        std::env::var("PKCS11_SLOT"),
        std::env::var("PKCS11_PIN"),
    ) else {
        eprintln!("est_serverkeygen_e2e: set DATABASE_URL + PKCS11_* to run; skipping");
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("est_serverkeygen_e2e: openssl not found; skipping");
        return;
    }
    let slot: u64 = slot.parse().expect("PKCS11_SLOT numeric");

    let pool = DatabasePool::new(&PoolConfig::from_url(&db_url).unwrap())
        .await
        .unwrap();
    for t in [
        "audit_events",
        "est_enrollments",
        "certificates",
        "ca_certificates",
        "ca_keys",
    ] {
        sqlx_del(&pool, t).await;
    }

    // --- Build the CA (SoftHSM key + self-signed root) ---
    let ca_crypto: Box<dyn CryptoProvider> =
        CryptoProviderFactory::create_pkcs11_provider(Path::new(&module), slot, &pin)
            .await
            .unwrap();
    let key_label = "ostrich-skg-e2e-ca";
    let ca_key = ca_crypto
        .generate_key_pair(KeyType::EcP256, key_label, false)
        .await
        .unwrap();
    let ca_spki = ca_crypto.export_public_key(&ca_key).await.unwrap();
    let sig_alg = Algorithm::EcdsaP256Sha256;
    let subject = DistinguishedName {
        common_name: Some("OstrichPKI ServerKeyGen E2E Root CA".to_string()),
        ..Default::default()
    };
    let mut sbytes = ostrich_common::util::random::secure_random_bytes(20);
    sbytes[0] &= 0x7F;
    let serial = SerialNumber::from_bytes(sbytes).unwrap();
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
    let raw = ca_crypto.sign(&ca_key, sig_alg, &tbs_der).await.unwrap();
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
            &ca_key.key_id,
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
    let mut ca =
        ostrich_ca::CertificateAuthority::new(ca_model, ca_key, ca_crypto, pool.clone(), 24)
            .unwrap();
    // Server-side keygen issues without an approval workflow; proof-of-possession
    // stays required (the EST server submits a CSR signed by the generated key).
    ca.set_approval_config(ostrich_ca::approval::ApprovalConfig {
        require_approval: false,
        ..Default::default()
    });
    let mut profile = ostrich_x509::CertificateProfile::tls_client(365);
    profile.name = "tls_client".to_string();
    ca.add_profile(profile);

    // --- Serve the CA gRPC service ---
    let ca_port = free_port();
    let ca_addr: std::net::SocketAddr = format!("127.0.0.1:{ca_port}").parse().unwrap();
    let grpc = ostrich_ca::CaGrpcService::new(Arc::new(ca));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                ostrich_protocol::certificate_authority_service_server::CertificateAuthorityServiceServer::new(grpc),
            )
            .serve(ca_addr)
            .await
            .unwrap();
    });
    wait_for_port(ca_addr).await;

    // --- Build the EST server wired to the CA ---
    let ca_client = ostrich_est::ca_integration::EstCaClient::new(
        ostrich_common::GrpcClientConfig {
            endpoint: format!("http://127.0.0.1:{ca_port}"),
            ..Default::default()
        },
        pool.clone(),
    )
    .await
    .unwrap();

    let est_crypto: Arc<dyn CryptoProvider> =
        Arc::from(CryptoProviderFactory::create_software_provider());
    let audit: Arc<dyn ostrich_audit::AuditSink> = Arc::new(DatabaseAuditSink::new(pool.clone()));
    let ra_user = AuthenticatedUser::new(
        UserId::new(),
        "ra-e2e".to_string(),
        vec![Role::RaStaff],
        AuthMethod::Password,
    );
    let auth: Arc<dyn AuthProvider> = Arc::new(TestAuthProvider { user: ra_user });
    let rbac = Arc::new(RbacPolicy::new());

    let est_state = ostrich_est::rest::EstState::new_with_auth(
        pool.clone(),
        est_crypto,
        audit,
        auth,
        rbac,
    )
    .with_ca(Some(Arc::new(ca_client)), Some(ca_der.clone()))
    .with_profile("tls_client");
    let router = ostrich_est::create_router(est_state);

    let est_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let est_addr = est_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(est_listener, router).await.unwrap();
    });
    wait_for_port(est_addr).await;

    // --- Build the client's serverkeygen CSR (subject + SAN; the server makes
    // its own key, so this CSR's key/signature are only conveying identity). ---
    let client_crypto = CryptoProviderFactory::create_software_provider();
    let client_key = client_crypto
        .generate_key_pair(KeyType::EcP256, "skg-client", true)
        .await
        .unwrap();
    let client_spki = client_crypto.export_public_key(&client_key).await.unwrap();
    let leaf_subject = DistinguishedName {
        common_name: Some("device-42.example.com".to_string()),
        ..Default::default()
    };
    let sans = vec![SubjectAltName::DnsName("device-42.example.com".to_string())];
    let csr_info = ostrich_x509::builder::build_csr_info_der(&leaf_subject, &client_spki, &sans)
        .unwrap();
    let csr_raw = client_crypto
        .sign(&client_key, Algorithm::EcdsaP256Sha256, &csr_info)
        .await
        .unwrap();
    let csr_x509 =
        ostrich_x509::signing::encode_x509_signature(Algorithm::EcdsaP256Sha256, csr_raw).unwrap();
    let client_csr = ostrich_x509::builder::assemble_csr(
        &csr_info,
        Algorithm::EcdsaP256Sha256,
        &csr_x509,
    )
    .unwrap();

    // --- POST to /serverkeygen over HTTP ---
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(&client_csr);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{est_addr}/.well-known/est/serverkeygen"
        ))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/pkcs10")
        .body(body)
        .send()
        .await
        .expect("serverkeygen request");

    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let text = resp.text().await.unwrap();
    assert!(
        status.is_success(),
        "serverkeygen failed: {status}\n{text}"
    );
    assert!(
        ctype.starts_with("multipart/mixed"),
        "expected multipart/mixed, got '{ctype}'"
    );

    // --- Parse the multipart parts (pkcs8 + pkcs7) ---
    let pkcs8_b64 = extract_part(&text, "application/pkcs8");
    let pkcs7_b64 = extract_part(&text, "application/pkcs7-mime");
    let pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(pkcs8_b64.trim())
        .expect("pkcs8 base64");
    let pkcs7 = base64::engine::general_purpose::STANDARD
        .decode(pkcs7_b64.trim())
        .expect("pkcs7 base64");

    // --- Verify with openssl: the returned key's public key == the cert's ---
    let dir = std::env::temp_dir();
    let kp = dir.join(format!("skg-key-{ca_port}.der"));
    let cp = dir.join(format!("skg-cert-{ca_port}.p7"));
    std::fs::File::create(&kp).unwrap().write_all(&pkcs8).unwrap();
    std::fs::File::create(&cp).unwrap().write_all(&pkcs7).unwrap();

    let key_pub = run_openssl(&["pkey", "-inform", "DER", "-in", kp.to_str().unwrap(), "-pubout"]);
    let certs_pem = run_openssl(&[
        "pkcs7",
        "-inform",
        "DER",
        "-in",
        cp.to_str().unwrap(),
        "-print_certs",
    ]);
    // Feed the cert PEM to x509 to extract its public key.
    let certs_path = dir.join(format!("skg-cert-{ca_port}.pem"));
    std::fs::File::create(&certs_path)
        .unwrap()
        .write_all(certs_pem.as_bytes())
        .unwrap();
    let cert_pub = run_openssl(&[
        "x509",
        "-in",
        certs_path.to_str().unwrap(),
        "-pubkey",
        "-noout",
    ]);

    let _ = std::fs::remove_file(&kp);
    let _ = std::fs::remove_file(&cp);
    let _ = std::fs::remove_file(&certs_path);

    assert_eq!(
        key_pub.trim(),
        cert_pub.trim(),
        "the returned private key must match the public key in the issued certificate"
    );
    assert!(
        certs_pem.contains("BEGIN CERTIFICATE"),
        "PKCS#7 must contain the issued certificate"
    );

    for t in [
        "audit_events",
        "est_enrollments",
        "certificates",
        "ca_certificates",
        "ca_keys",
    ] {
        sqlx_del(&pool, t).await;
    }
}

async fn sqlx_del(pool: &DatabasePool, table: &str) {
    // Best-effort cleanup; tables are FK-ordered by the caller.
    let _ = sqlx::query(&format!("DELETE FROM {table}"))
        .execute(pool.pool())
        .await;
}

/// Extract the base64 body of the multipart part whose Content-Type contains
/// `content_type`.
fn extract_part(body: &str, content_type: &str) -> String {
    for part in body.split("--estServerKeyGenBoundary") {
        if part.contains(content_type) {
            if let Some(idx) = part.find("\r\n\r\n") {
                return part[idx + 4..].trim().to_string();
            }
        }
    }
    panic!("multipart part '{content_type}' not found in:\n{body}");
}

fn run_openssl(args: &[&str]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("run openssl");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}
