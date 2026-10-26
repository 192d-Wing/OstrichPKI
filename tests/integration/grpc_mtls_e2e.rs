//! Offline e2e for the CA gRPC mTLS listener (`ostrich_common::grpc_tls`).
//!
//! Serves a stub `CertificateAuthorityService` through the real
//! `bind_mtls_incoming` + `SubjectAllowlistLayer` stack on 127.0.0.1 and talks
//! to it with the real `CaGrpcClient` (and raw rustls clients for the negative
//! cases). The PKI is generated with rcgen; no database, no network beyond
//! loopback.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing), AC-3 / AC-6 (allowlist),
//!   AC-17 / IA-3 / IA-5(2) (mTLS), SC-8 / SC-13 (TLS 1.3, FIPS provider),
//!   AU-2 / AU-3 (denial and handshake-failure audit)
//! - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.1/.2, FCS_TLSC_EXT.2, FIA_X509_EXT.1,
//!   FDP_ACF.1, FAU_GEN.1
//! - RFC 8446 (TLS 1.3 only), RFC 7301 (ALPN h2), RFC 5280 §4.2.1.12 (EKU)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ostrich_common::auth::{AuthAuditEvent, AuthAuditHook, AuthAuditKind};
use ostrich_common::grpc_tls::{
    bind_mtls_incoming, bind_mtls_incoming_with, grpc_client_config, grpc_server_config,
    GrpcListenerLimits, GrpcTlsConnector, GRPC_MAX_INFLIGHT_HANDSHAKES, GRPC_TLS_HANDSHAKE_TIMEOUT,
};
use ostrich_common::tls::TlsSettings;
use ostrich_common::{
    AuthorizedGrpcPeer, CaGrpcClient, ClientSubjectAllowlist, GrpcClientConfig, GrpcServerOptions,
    SubjectAllowlistLayer,
};
use ostrich_protocol::certificate_authority_service_client::CertificateAuthorityServiceClient;
use ostrich_protocol::certificate_authority_service_server::{
    CertificateAuthorityService, CertificateAuthorityServiceServer,
};
use ostrich_protocol::{
    CheckRevocationStatusRequest, CheckRevocationStatusResponse, GenerateCrlRequest,
    GenerateCrlResponse, GetCaInfoRequest, GetCaInfoResponse, IssueCertificateRequest,
    IssueCertificateResponse, ListProfilesRequest, ListProfilesResponse, RevokeCertificateRequest,
    RevokeCertificateResponse,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tonic::{Code, Request, Response, Status};

const LISTENER: &str = "ca-grpc";
const ISSUE_PATH: &str = "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate";

// ---------------------------------------------------------------- test PKI ---

struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl Pki {
    fn new(cn: &str) -> Self {
        Self::new_with(cn, &rcgen::PKCS_ECDSA_P256_SHA256)
    }

    fn new_with(cn: &str, alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate_for(alg).expect("ca key");
        Self {
            ca: CertifiedIssuer::self_signed(p, key).expect("ca cert"),
        }
    }

    /// Leaf with an explicit key algorithm and EKU list (empty = no
    /// extendedKeyUsage extension).
    fn leaf_with(
        &self,
        cn: &str,
        sans: &[&str],
        ekus: Vec<ExtendedKeyUsagePurpose>,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> Leaf {
        let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut p = CertificateParams::new(sans).expect("leaf params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = ekus;
        let key = KeyPair::generate_for(alg).expect("leaf key");
        let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn ca_pem(&self) -> String {
        self.ca.pem()
    }

    fn leaf(&self, cn: &str, sans: &[&str], eku: ExtendedKeyUsagePurpose) -> Leaf {
        let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut p = CertificateParams::new(sans).expect("leaf params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate().expect("leaf key");
        let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn client(&self, cn: &str) -> Leaf {
        self.leaf(cn, &[cn], ExtendedKeyUsagePurpose::ClientAuth)
    }
}

fn tmp_file(tag: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ostrich-grpc-mtls-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let path = dir.join(format!("{tag}-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, contents).expect("write pem");
    path
}

// ------------------------------------------------------------- stub server ---

/// Stub CA: returns a fixed issuance response and records the authorised peer.
#[derive(Clone, Default)]
struct StubCa {
    seen_peers: Arc<Mutex<Vec<String>>>,
}

#[tonic::async_trait]
impl CertificateAuthorityService for StubCa {
    async fn issue_certificate(
        &self,
        request: Request<IssueCertificateRequest>,
    ) -> Result<Response<IssueCertificateResponse>, Status> {
        let peer = request
            .extensions()
            .get::<AuthorizedGrpcPeer>()
            .map(|p| p.subject_dn.clone())
            .unwrap_or_else(|| "<none>".to_string());
        self.seen_peers.lock().unwrap().push(peer);
        Ok(Response::new(IssueCertificateResponse {
            certificate_id: "00000000-0000-0000-0000-000000000001".to_string(),
            serial_number: vec![1],
            der_encoded: vec![0x30],
            pem_encoded: "stub".to_string(),
            not_before: 0,
            not_after: 1,
        }))
    }

    async fn revoke_certificate(
        &self,
        _r: Request<RevokeCertificateRequest>,
    ) -> Result<Response<RevokeCertificateResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn generate_crl(
        &self,
        _r: Request<GenerateCrlRequest>,
    ) -> Result<Response<GenerateCrlResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn check_revocation_status(
        &self,
        _r: Request<CheckRevocationStatusRequest>,
    ) -> Result<Response<CheckRevocationStatusResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn get_ca_info(
        &self,
        _r: Request<GetCaInfoRequest>,
    ) -> Result<Response<GetCaInfoResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn list_profiles(
        &self,
        _r: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }
}

/// Audit hook that forwards every event to a channel.
struct RecordingHook(mpsc::UnboundedSender<AuthAuditEvent>);

#[async_trait]
impl AuthAuditHook for RecordingHook {
    async fn record_auth_event(&self, event: AuthAuditEvent) {
        let _ = self.0.send(event);
    }
}

/// A running stub CA behind the real mTLS listener + allowlist layer.
struct Served {
    addr: SocketAddr,
    events: mpsc::UnboundedReceiver<AuthAuditEvent>,
    seen_peers: Arc<Mutex<Vec<String>>>,
    server_config: Arc<rustls::ServerConfig>,
}

/// Serve the stub CA with the given TLS files and allowlist (the same
/// `grpc_server_config` + `bind_mtls_incoming` + `SubjectAllowlistLayer` stack
/// ca-server uses), with the production limits.
async fn serve_stub(settings: &TlsSettings, allowed: &[&str]) -> Served {
    serve_stub_with(settings, allowed, None).await
}

/// [`serve_stub`] with explicit listener / audit limits (`None` = defaults,
/// through the same `bind_mtls_incoming` / `SubjectAllowlistLayer::new` calls
/// ca-server makes).
async fn serve_stub_with(
    settings: &TlsSettings,
    allowed: &[&str],
    limits: Option<GrpcListenerLimits>,
) -> Served {
    let server_config = grpc_server_config(settings).expect("server config");
    let allowlist = Arc::new(
        ClientSubjectAllowlist::parse(&allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("allowlist"),
    );

    let (tx, events) = mpsc::unbounded_channel();
    let hook: Arc<dyn AuthAuditHook> = Arc::new(RecordingHook(tx));
    let incoming = match &limits {
        None => {
            bind_mtls_incoming(
                "127.0.0.1:0".parse().unwrap(),
                server_config.clone(),
                Some(hook.clone()),
                LISTENER,
            )
            .await
        }
        Some(limits) => {
            bind_mtls_incoming_with(
                "127.0.0.1:0".parse().unwrap(),
                server_config.clone(),
                Some(hook.clone()),
                LISTENER,
                limits.clone(),
            )
            .await
        }
    }
    .expect("bind");
    let addr = incoming.local_addr();
    let layer = match &limits {
        None => SubjectAllowlistLayer::new(allowlist, Some(hook), LISTENER),
        Some(limits) => SubjectAllowlistLayer::with_limits(allowlist, Some(hook), LISTENER, limits),
    };

    let stub = StubCa::default();
    let seen_peers = stub.seen_peers.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .layer(layer)
            .add_service(CertificateAuthorityServiceServer::new(stub))
            .serve_with_incoming_shutdown(incoming, std::future::pending::<()>())
            .await
            .expect("serve");
    });

    Served {
        addr,
        events,
        seen_peers,
        server_config,
    }
}

struct Harness {
    addr: SocketAddr,
    server_pki: Pki,
    client_pki: Pki,
    events: mpsc::UnboundedReceiver<AuthAuditEvent>,
    seen_peers: Arc<Mutex<Vec<String>>>,
    server_config: Arc<rustls::ServerConfig>,
}

impl Harness {
    /// Start the real mTLS listener + allowlist layer around the stub CA.
    async fn start(allowed: &[&str]) -> Self {
        Self::start_with(allowed, None, &rcgen::PKCS_ECDSA_P256_SHA256).await
    }

    /// [`Self::start`] with explicit limits and PKI key algorithm.
    async fn start_with(
        allowed: &[&str],
        limits: Option<GrpcListenerLimits>,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> Self {
        let server_pki = Pki::new_with("E2E gRPC Server CA", alg);
        let client_pki = Pki::new_with("E2E gRPC Client CA", alg);
        let server_leaf = server_pki.leaf_with(
            "ca-service",
            &["localhost", "ca-service", "127.0.0.1"],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            alg,
        );
        let settings = TlsSettings {
            cert_path: tmp_file("srv-cert", &server_leaf.cert_pem),
            key_path: tmp_file("srv-key", &server_leaf.key_pem),
            client_ca_path: Some(tmp_file("cli-ca", &client_pki.ca_pem())),
            optional_client_auth: false,
        };
        let served = serve_stub_with(&settings, allowed, limits).await;
        Self {
            addr: served.addr,
            server_pki,
            client_pki,
            events: served.events,
            seen_peers: served.seen_peers,
            server_config: served.server_config,
        }
    }

    fn client_config(&self, leaf: &Leaf) -> GrpcClientConfig {
        GrpcClientConfig {
            endpoint: format!("https://127.0.0.1:{}", self.addr.port()),
            client_cert_pem: leaf.cert_pem.clone(),
            client_key_pem: zeroize::Zeroizing::new(leaf.key_pem.clone()),
            ca_cert_pem: self.server_pki.ca_pem(),
            server_name: Some("localhost".to_string()),
            max_retries: 1,
            ..Default::default()
        }
    }

    /// Wait for the next audit event of `kind`, skipping others.
    async fn next_event(&mut self, kind: AuthAuditKind) -> AuthAuditEvent {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let ev = self.events.recv().await.expect("event channel open");
                if ev.kind == kind {
                    return ev;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {kind:?} audit event within 10s"))
    }
}

fn issue_request() -> IssueCertificateRequest {
    IssueCertificateRequest {
        profile_name: "tls_client".to_string(),
        subject: None,
        subject_alt_names: vec![],
        public_key: vec![],
        requestor: "grpc-mtls-e2e".to_string(),
        metadata: Default::default(),
        csr_der: vec![],
        request_id: String::new(),
    }
}

async fn issue_via(client: &CaGrpcClient) -> Result<IssueCertificateResponse, Status> {
    CertificateAuthorityServiceClient::new(client.channel())
        .issue_certificate(Request::new(issue_request()))
        .await
        .map(Response::into_inner)
}

/// Raw rustls client (aws-lc-rs) for negative cases.
fn raw_client_config(
    trust_pem: &str,
    client: Option<&Leaf>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(trust_pem.as_bytes()) {
        roots.add(c.expect("root pem")).expect("add root");
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .expect("versions")
    .with_root_certificates(roots);
    let mut config = match client {
        Some(leaf) => builder
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .expect("certs"),
                PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).expect("key"),
            )
            .expect("client auth"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Connect with a raw client and try to use the connection. Returns Ok only
/// if the server accepted it and answered the HTTP/2 preface.
async fn raw_connect_and_probe(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<()> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    // TLS 1.3: the client finishes before the server has checked the client
    // certificate, so the rejection surfaces on the first read.
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
    tls.flush().await?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::other("read timeout"))??;
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

// ------------------------------------------------------------------- tests ---

/// 1. An allow-listed subject issues; the service sees the authorised peer.
#[tokio::test]
async fn allowed_subject_issue_ok() {
    let mut h = Harness::start(&["CN=acme-server", "CN=est-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("mTLS connect");
    let resp = issue_via(&client).await.expect("issue");
    assert_eq!(resp.certificate_id, "00000000-0000-0000-0000-000000000001");
    assert_eq!(
        h.seen_peers.lock().unwrap().as_slice(),
        &["CN=acme-server".to_string()]
    );
    assert!(h.events.try_recv().is_err(), "no audit event on success");
}

/// 2. A trusted but non-allow-listed subject gets PERMISSION_DENIED + audit.
#[tokio::test]
async fn disallowed_subject_permission_denied_and_audited() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("intruder");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("TLS connect (cert is trusted)");
    let status = issue_via(&client).await.expect_err("must be denied");
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(
        !status.message().contains("acme-server"),
        "status must not echo the allowlist: {}",
        status.message()
    );

    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.subject, "CN=intruder");
    assert_eq!(ev.resource.as_deref(), Some(ISSUE_PATH));
    assert_eq!(ev.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(ev.reason.as_deref(), Some("subject_not_allowlisted"));
    assert_eq!(
        ev.details
            .as_ref()
            .and_then(|d| d.get("listener"))
            .and_then(|v| v.as_str()),
        Some(LISTENER)
    );
    assert!(
        h.seen_peers.lock().unwrap().is_empty(),
        "stub never reached"
    );
}

/// 3. No client certificate: the handshake fails and is audited.
#[tokio::test]
async fn no_client_cert_handshake_fails() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let config = raw_client_config(
        &h.server_pki.ca_pem(),
        None,
        &[&rustls::version::TLS13],
        &[b"h2"],
    );
    assert!(raw_connect_and_probe(h.addr, config).await.is_err());
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("no_client_certificate"));
    assert_eq!(ev.subject, "unauthenticated");
    assert_eq!(ev.resource.as_deref(), Some(LISTENER));
    assert_eq!(ev.ip_address.as_deref(), Some("127.0.0.1"));
}

/// 4. A client certificate from an untrusted CA fails the handshake (also via
/// the real client) and is audited.
#[tokio::test]
async fn untrusted_ca_client_cert_handshake_fails() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let rogue = Pki::new("Rogue CA").client("acme-server");
    let failed = match CaGrpcClient::new(h.client_config(&rogue)).await {
        Err(_) => true,
        Ok(client) => issue_via(&client).await.is_err(),
    };
    assert!(
        failed,
        "untrusted client certificate must not reach the service"
    );
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("untrusted_client_certificate"));
    assert!(h.seen_peers.lock().unwrap().is_empty());
}

/// 5. TLS 1.2-only clients are refused (TLS 1.3 only, RFC 8446 / SC-8).
#[tokio::test]
async fn tls12_client_rejected() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let config = raw_client_config(
        &h.server_pki.ca_pem(),
        Some(&leaf),
        &[&rustls::version::TLS12],
        &[b"h2"],
    );
    assert!(raw_connect_and_probe(h.addr, config).await.is_err());
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("peer_incompatible"));
}

/// 6. A client certificate without the clientAuth EKU is refused
/// (RFC 5280 §4.2.1.12).
#[tokio::test]
async fn server_only_eku_client_cert_rejected() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.leaf(
        "acme-server",
        &["acme-server"],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let failed = match CaGrpcClient::new(h.client_config(&leaf)).await {
        Err(_) => true,
        Ok(client) => issue_via(&client).await.is_err(),
    };
    assert!(failed, "serverAuth-only client certificate must be refused");
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("client_certificate_wrong_eku"));
}

/// 7. The client refuses a server whose certificate does not match the
/// configured TLS server name.
#[tokio::test]
async fn client_rejects_server_name_mismatch() {
    let h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let mut config = h.client_config(&leaf);
    config.server_name = Some("not-the-ca.example".to_string());
    let err = CaGrpcClient::new(config).await.err().expect("must fail");
    assert!(
        matches!(err, ostrich_common::Error::ServiceUnavailable(_)),
        "unexpected error: {err}"
    );
}

/// 8. ALPN: a client offering only http/1.1 is refused during the handshake;
/// a client offering no ALPN is dropped after it (gRPC requires h2).
#[tokio::test]
async fn non_h2_alpn_client_rejected() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");

    let http11 = raw_client_config(
        &h.server_pki.ca_pem(),
        Some(&leaf),
        &[&rustls::version::TLS13],
        &[b"http/1.1"],
    );
    assert!(raw_connect_and_probe(h.addr, http11).await.is_err());
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("no_application_protocol"));

    let no_alpn = raw_client_config(
        &h.server_pki.ca_pem(),
        Some(&leaf),
        &[&rustls::version::TLS13],
        &[],
    );
    assert!(raw_connect_and_probe(h.addr, no_alpn).await.is_err());
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("no_alpn_h2"));
    // NIST-011: the certificate was verified, so it is the recorded actor.
    assert_eq!(ev.subject, "CN=acme-server");
    assert!(h.seen_peers.lock().unwrap().is_empty());
}

/// 8b. RFC-013 / RFC 8446 §6.1: the post-handshake no-ALPN refusal is a clean
/// TLS close: the server sends close_notify before closing the TCP stream, so
/// the client reads a clean EOF (`Ok(0)`), not an unexpected-EOF error or a
/// reset.
#[tokio::test]
async fn no_alpn_refusal_sends_close_notify() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let no_alpn = raw_client_config(
        &h.server_pki.ca_pem(),
        Some(&leaf),
        &[&rustls::version::TLS13],
        &[],
    );
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let mut tls = tokio_rustls::TlsConnector::from(no_alpn)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("TLS 1.3 handshake completes on the client side");
    assert_eq!(tls.get_ref().1.alpn_protocol(), None);
    // Nothing is written, so the server has no unread data and closes with
    // FIN (never RST); a missing close_notify would surface as UnexpectedEof.
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("server closes promptly");
    assert!(
        matches!(read, Ok(0)),
        "expected clean close_notify EOF, got {read:?}"
    );
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("no_alpn_h2"));
}

/// 9. SC-13 evidence: the exact server and client configs used for a working
/// call report `fips()`, and both are TLS 1.3 / h2.
#[tokio::test]
async fn server_and_client_configs_report_fips() {
    let h = Harness::start(&["CN=acme-server"]).await;
    assert!(
        h.server_config.fips(),
        "server config passed to bind_mtls_incoming"
    );
    assert_eq!(h.server_config.alpn_protocols, vec![b"h2".to_vec()]);

    let leaf = h.client_pki.client("acme-server");
    let client_config =
        grpc_client_config(&leaf.cert_pem, &leaf.key_pem, &h.server_pki.ca_pem()).expect("client");
    assert!(
        client_config.fips(),
        "client config passed to the connector"
    );
    assert_eq!(client_config.alpn_protocols, vec![b"h2".to_vec()]);

    // Serve a call through exactly this client config.
    let connector = GrpcTlsConnector::new(client_config.clone(), "localhost").expect("connector");
    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://127.0.0.1:{}", h.addr.port()))
            .unwrap()
            .connect_with_connector(connector)
            .await
            .expect("connect");
    CertificateAuthorityServiceClient::new(channel)
        .issue_certificate(Request::new(issue_request()))
        .await
        .expect("issue over the asserted configs");

    // And the negotiated session really is TLS 1.3 + h2.
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("handshake");
    let (_, conn) = tls.get_ref();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));
}

/// 10. Fail closed: with no gRPC configuration the listener mode does not
/// resolve, and nothing is bound.
#[tokio::test]
async fn refuses_to_start_without_config() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let err = GrpcServerOptions::default()
        .resolve(true)
        .expect_err("must refuse");
    assert!(err.to_string().contains("refusing to start"), "{err}");
    let err = GrpcServerOptions {
        insecure_dev_plaintext: true,
        ..Default::default()
    }
    .resolve(true)
    .expect_err("dev flag refused in release builds");
    assert!(err.to_string().contains("release builds"), "{err}");

    // Nothing was bound by the failed resolution: the port is still free.
    std::net::TcpListener::bind(("127.0.0.1", port)).expect("port still free");
}

// ------------------------------------------------- QA additions (SA-11) ---

/// Wait up to `within` for the next audit event of `kind`, skipping others.
async fn next_event_within(
    events: &mut mpsc::UnboundedReceiver<AuthAuditEvent>,
    kind: AuthAuditKind,
    within: Duration,
) -> Option<AuthAuditEvent> {
    tokio::time::timeout(within, async {
        loop {
            let ev = events.recv().await?;
            if ev.kind == kind {
                return Some(ev);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// TLS 1.3 handshake with a client config against the listener.
async fn tls_handshake(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    tokio_rustls::TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
}

/// 11. SC-5: a client that connects and never sends a ClientHello is dropped
/// after `GRPC_TLS_HANDSHAKE_TIMEOUT` (10 s) and the drop is audited as
/// `handshake_timeout` (AU-2). Takes ~10 s of wall time by design.
#[tokio::test]
async fn stalled_handshake_times_out_and_is_audited() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let started = std::time::Instant::now();
    let mut stalled = tokio::net::TcpStream::connect(h.addr).await.unwrap();

    let ev = next_event_within(
        &mut h.events,
        AuthAuditKind::TlsHandshakeFailed,
        GRPC_TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(10),
    )
    .await
    .expect("handshake_timeout audit event");
    assert_eq!(ev.reason.as_deref(), Some("handshake_timeout"));
    assert_eq!(ev.subject, "unauthenticated");
    assert_eq!(ev.resource.as_deref(), Some(LISTENER));
    assert_eq!(ev.ip_address.as_deref(), Some("127.0.0.1"));
    assert!(
        started.elapsed() >= GRPC_TLS_HANDSHAKE_TIMEOUT - Duration::from_millis(500),
        "timeout fired early: {:?}",
        started.elapsed()
    );

    // The server closed the connection: the read sees EOF or a reset.
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("server must have closed the stalled connection");
    assert!(matches!(read, Ok(0) | Err(_)), "unexpected data: {read:?}");
}

/// 12. SC-5: at most `GRPC_MAX_INFLIGHT_HANDSHAKES` handshakes run at once.
/// With every slot held by a silent client, a valid client cannot complete a
/// handshake; once the slots are released it can. Silent clients that close
/// without sending anything are not audited (probe / health-check noise).
/// All test clients share 127.0.0.1, so the per-source cap (case 16) is raised
/// to the global cap here to reach the global limit.
#[tokio::test]
async fn handshake_concurrency_cap_applies_backpressure() {
    let mut h = Harness::start_with(
        &["CN=acme-server"],
        Some(GrpcListenerLimits {
            max_inflight_handshakes_per_ip: GRPC_MAX_INFLIGHT_HANDSHAKES,
            ..Default::default()
        }),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .await;
    let leaf = h.client_pki.client("acme-server");
    let config =
        grpc_client_config(&leaf.cert_pem, &leaf.key_pem, &h.server_pki.ca_pem()).expect("client");

    let mut stalled = Vec::with_capacity(GRPC_MAX_INFLIGHT_HANDSHAKES);
    for _ in 0..GRPC_MAX_INFLIGHT_HANDSHAKES {
        stalled.push(tokio::net::TcpStream::connect(h.addr).await.unwrap());
    }
    // Let the accept loop take every slot.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let blocked = tokio::time::timeout(
        Duration::from_secs(2),
        tls_handshake(h.addr, config.clone()),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a handshake completed while all {GRPC_MAX_INFLIGHT_HANDSHAKES} slots were held"
    );

    drop(stalled);
    let tls = tokio::time::timeout(Duration::from_secs(5), tls_handshake(h.addr, config))
        .await
        .expect("handshake must proceed once slots are free")
        .expect("handshake");
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    // Silent clients closing are never audited as handshake failures (well
    // before any of them could have hit the 10 s timeout).
    while let Ok(ev) = h.events.try_recv() {
        assert_ne!(
            ev.reason.as_deref(),
            Some("handshake_timeout"),
            "unexpected timeout audit: {ev:?}"
        );
    }
}

/// 13. AU-2 / AU-4 / SC-5: handshake-failure audit records are rate limited
/// on the real listener. 70 failed handshakes inside one 60 s window produce
/// exactly 60 `tls_handshake_failed` records and (the window has not rolled
/// over) no suppression summary yet.
#[tokio::test]
async fn handshake_failure_audit_is_rate_limited() {
    const ATTEMPTS: usize = 70;
    const AUDIT_CAP: usize = 60;
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let config = raw_client_config(
        &h.server_pki.ca_pem(),
        None,
        &[&rustls::version::TLS13],
        &[b"h2"],
    );
    for _ in 0..ATTEMPTS {
        assert!(raw_connect_and_probe(h.addr, config.clone()).await.is_err());
    }

    let mut recorded = 0usize;
    let mut summaries = 0usize;
    // Collect until the stream goes quiet for 1 s.
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(1), h.events.recv()).await {
        match ev.kind {
            AuthAuditKind::TlsHandshakeFailed => {
                assert_eq!(ev.reason.as_deref(), Some("no_client_certificate"));
                recorded += 1;
            }
            AuthAuditKind::TlsHandshakeFailuresSuppressed => summaries += 1,
            other => panic!("unexpected audit kind {other:?}"),
        }
    }
    assert_eq!(recorded, AUDIT_CAP, "records per window");
    assert_eq!(summaries, 0, "summary is only written in the next window");
}

/// 14. SC-13 / SC-24 call-site wiring: the client connector and the listener
/// themselves refuse configs that are not FIPS or not ALPN `h2` only, so a
/// config built outside `grpc_client_config` / `grpc_server_config` cannot be
/// used. Fails if the `ensure_fips_client` / `ensure_fips` calls are removed
/// from `GrpcTlsConnector::new` / `bind_mtls_incoming`.
#[tokio::test]
async fn connector_and_listener_refuse_non_fips_or_non_h2_configs() {
    let h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let good =
        grpc_client_config(&leaf.cert_pem, &leaf.key_pem, &h.server_pki.ca_pem()).expect("client");
    assert!(GrpcTlsConnector::new(good.clone(), "localhost").is_ok());

    let mut no_ems = (*good).clone();
    no_ems.require_ems = false;
    assert!(!no_ems.fips());
    assert!(
        GrpcTlsConnector::new(Arc::new(no_ems), "localhost").is_err(),
        "connector accepted a non-FIPS client config"
    );

    let mut x25519 = rustls::crypto::aws_lc_rs::default_provider();
    x25519
        .kx_groups
        .insert(0, rustls::crypto::aws_lc_rs::kx_group::X25519);
    let mut non_fips_kx = rustls::ClientConfig::builder_with_provider(Arc::new(x25519))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(good_roots(&h.server_pki.ca_pem()))
        .with_no_client_auth();
    non_fips_kx.alpn_protocols = vec![b"h2".to_vec()];
    assert!(!non_fips_kx.fips());
    assert!(GrpcTlsConnector::new(Arc::new(non_fips_kx), "localhost").is_err());

    for alpn in [
        vec![b"http/1.1".to_vec()],
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        vec![],
    ] {
        let mut c = (*good).clone();
        c.alpn_protocols = alpn.clone();
        assert!(
            GrpcTlsConnector::new(Arc::new(c), "localhost").is_err(),
            "connector accepted ALPN {alpn:?}"
        );
    }
    assert!(GrpcTlsConnector::new(good, "not a valid name!").is_err());

    let mut srv_no_ems = (*h.server_config).clone();
    srv_no_ems.require_ems = false;
    assert!(!srv_no_ems.fips());
    assert!(
        bind_mtls_incoming(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(srv_no_ems),
            None,
            LISTENER
        )
        .await
        .is_err(),
        "listener accepted a non-FIPS server config"
    );
    for alpn in [vec![b"h2".to_vec(), b"http/1.1".to_vec()], vec![]] {
        let mut s = (*h.server_config).clone();
        s.alpn_protocols = alpn.clone();
        assert!(
            bind_mtls_incoming("127.0.0.1:0".parse().unwrap(), Arc::new(s), None, LISTENER)
                .await
                .is_err(),
            "listener accepted ALPN {alpn:?}"
        );
    }
}

fn good_roots(ca_pem: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.expect("root pem")).expect("add root");
    }
    roots
}

/// 15. CM-6 / SC-8: material from `scripts/gen-dev-grpc-certs.sh` works with
/// the Rust server and client exactly as compose wires it: the server resolves
/// in release mode from the files, acme-server / est-server issue through the
/// compose allowlist under every server name compose dials (`ca-service`,
/// `ca`, `localhost`), `integration-tests` is refused unless allow-listed, and
/// the generated env file points at the generated files. Needs `bash` and
/// `openssl` (skips otherwise, like `fips_signature_openssl_interop`).
#[tokio::test]
async fn dev_cert_script_material_works_with_rust_server_and_client() {
    use std::process::Command;
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("grpc_mtls_e2e: openssl not found; skipping dev cert script check");
        return;
    }
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf();
    let out = std::env::temp_dir().join(format!(
        "ostrich-dev-grpc-certs-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let status = Command::new("bash")
        .arg(repo.join("scripts/gen-dev-grpc-certs.sh"))
        .arg(&out)
        .output()
        .expect("run gen-dev-grpc-certs.sh");
    assert!(
        status.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    // The dev CA private key never lands in the output directory.
    let names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n == "ca.key"),
        "CA key written: {names:?}"
    );

    let file = |n: &str| out.join(n);
    let read = |n: &str| std::fs::read_to_string(file(n)).expect(n);

    // Server side, exactly as ca-server resolves it (release-build rules).
    const COMPOSE_ALLOWLIST: &[&str] = &["CN=acme-server", "CN=est-server"];
    let mode = GrpcServerOptions {
        cert_path: Some(file("ca-service.crt").display().to_string()),
        key_path: Some(file("ca-service.key").display().to_string()),
        client_ca_path: Some(file("ca.crt").display().to_string()),
        allowed_subjects: COMPOSE_ALLOWLIST.iter().map(|s| s.to_string()).collect(),
        insecure_dev_plaintext: false,
    }
    .resolve(true)
    .expect("dev material resolves to mTLS");
    match mode {
        ostrich_common::GrpcServerMode::Mtls {
            config,
            allowlist,
            client_anchors,
        } => {
            assert!(config.fips());
            assert_eq!(allowlist.subjects(), COMPOSE_ALLOWLIST);
            assert_eq!(
                client_anchors.len(),
                1,
                "dev script ships one client anchor"
            );
        }
        _ => panic!("expected Mtls mode"),
    }
    let mut served = serve_stub(
        &TlsSettings {
            cert_path: file("ca-service.crt"),
            key_path: file("ca-service.key"),
            client_ca_path: Some(file("ca.crt")),
            optional_client_auth: false,
        },
        COMPOSE_ALLOWLIST,
    )
    .await;

    let client_cfg = |identity: &str, server_name: &str| GrpcClientConfig {
        endpoint: format!("https://127.0.0.1:{}", served.addr.port()),
        client_cert_pem: read(&format!("{identity}.crt")),
        client_key_pem: ostrich_common::read_private_key_pem(&file(&format!("{identity}.key")))
            .expect("key"),
        ca_cert_pem: read("ca.crt"),
        server_name: Some(server_name.to_string()),
        max_retries: 1,
        ..Default::default()
    };

    for identity in ["acme-server", "est-server"] {
        for server_name in ["ca-service", "ca", "localhost"] {
            let client = CaGrpcClient::new(client_cfg(identity, server_name))
                .await
                .unwrap_or_else(|e| panic!("{identity} -> {server_name}: {e}"));
            issue_via(&client)
                .await
                .unwrap_or_else(|e| panic!("{identity} -> {server_name}: {e}"));
        }
    }
    assert_eq!(served.seen_peers.lock().unwrap().len(), 6);

    // integration-tests is a valid client but not in the compose default
    // allowlist: PERMISSION_DENIED + audit.
    let client = CaGrpcClient::new(client_cfg("integration-tests", "localhost"))
        .await
        .expect("trusted client connects");
    let status = issue_via(&client).await.expect_err("not allow-listed");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = next_event_within(
        &mut served.events,
        AuthAuditKind::AccessDenied,
        Duration::from_secs(10),
    )
    .await
    .expect("access_denied audit");
    assert_eq!(ev.subject, "CN=integration-tests");

    // A name not in the server SAN is refused by the client.
    assert!(
        CaGrpcClient::new(client_cfg("acme-server", "ostrich-pki-ca"))
            .await
            .is_err()
    );

    // integration-tests.env references the generated files.
    let env = read("integration-tests.env");
    for (key, name) in [
        ("CA_GRPC_CLIENT_CERT_FILE", "integration-tests.crt"),
        ("CA_GRPC_CLIENT_KEY_FILE", "integration-tests.key"),
        ("CA_GRPC_CA_CERT_FILE", "ca.crt"),
    ] {
        let line = env
            .lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} missing from env file"));
        let value = line[key.len() + 1..].trim_matches('"');
        assert_eq!(
            PathBuf::from(value).canonicalize().unwrap(),
            file(name).canonicalize().unwrap()
        );
    }

    // ---- Per-service subdirectories (SEC-004 fix, docker-compose.yml mounts).
    // Each container mounts only its own subdirectory; the file names are the
    // compose / Kubernetes-secret defaults:
    //   ca-server/   -> /app/grpc-tls:        tls.crt, tls.key, client-ca.crt
    //   acme-server/ -> /app/ca-grpc-client:  tls.crt, tls.key, ca.crt
    //   est-server/  -> /app/ca-grpc-client:  tls.crt, tls.key, ca.crt
    // NIST 800-53: AC-6 (least privilege: no other service's key), SC-8, SA-11
    let sub = |d: &str, n: &str| out.join(d).join(n);
    let list = |d: &str| {
        let mut v: Vec<String> = std::fs::read_dir(out.join(d))
            .unwrap_or_else(|e| panic!("{d}/ missing: {e}"))
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        list("ca-server"),
        ["client-ca.crt", "tls.crt", "tls.key"],
        "ca-server/ must hold only its own material"
    );
    for d in ["acme-server", "est-server"] {
        assert_eq!(
            list(d),
            ["ca.crt", "tls.crt", "tls.key"],
            "{d}/ must hold only its own material"
        );
    }
    // The subdirectory identity is the expected leaf (no cross-copy).
    for (d, leaf) in [
        ("ca-server", "ca-service"),
        ("acme-server", "acme-server"),
        ("est-server", "est-server"),
    ] {
        assert_eq!(
            std::fs::read(sub(d, "tls.crt")).unwrap(),
            std::fs::read(file(&format!("{leaf}.crt"))).unwrap(),
            "{d}/tls.crt"
        );
    }

    // Server: resolve exactly as ca-server does with the compose defaults.
    let mode = GrpcServerOptions {
        cert_path: Some(sub("ca-server", "tls.crt").display().to_string()),
        key_path: Some(sub("ca-server", "tls.key").display().to_string()),
        client_ca_path: Some(sub("ca-server", "client-ca.crt").display().to_string()),
        allowed_subjects: COMPOSE_ALLOWLIST.iter().map(|s| s.to_string()).collect(),
        insecure_dev_plaintext: false,
    }
    .resolve(true)
    .expect("ca-server/ subdir resolves to mTLS");
    let ostrich_common::GrpcServerMode::Mtls { client_anchors, .. } = mode else {
        panic!("expected Mtls for ca-server/ subdir");
    };
    assert_eq!(client_anchors.len(), 1);
    // R1: the dev gRPC CA is a dedicated service-identity CA, so it passes
    // against an unrelated PKI issuing CA, and would be refused if an operator
    // reused it as the PKI issuing CA.
    let unrelated_issuing_ca = Pki::new("OstrichPKI Dev Issuing CA");
    let unrelated_der = CertificateDer::from_pem_slice(unrelated_issuing_ca.ca_pem().as_bytes())
        .expect("issuing ca der");
    ostrich_common::grpc_tls::ensure_dedicated_client_ca(
        &client_anchors,
        unrelated_der.as_ref(),
        &[],
    )
    .expect("dev gRPC CA accepted as a dedicated client CA");
    let dev_ca_der =
        CertificateDer::from_pem_file(sub("ca-server", "client-ca.crt")).expect("dev ca der");
    assert!(
        ostrich_common::grpc_tls::ensure_dedicated_client_ca(
            &client_anchors,
            dev_ca_der.as_ref(),
            &[]
        )
        .is_err(),
        "client CA equal to the issuing CA must be refused"
    );

    let mut served_sub = serve_stub(
        &TlsSettings {
            cert_path: sub("ca-server", "tls.crt"),
            key_path: sub("ca-server", "tls.key"),
            client_ca_path: Some(sub("ca-server", "client-ca.crt")),
            optional_client_auth: false,
        },
        COMPOSE_ALLOWLIST,
    )
    .await;
    let sub_client_cfg = |d: &str, server_name: &str| GrpcClientConfig {
        endpoint: format!("https://127.0.0.1:{}", served_sub.addr.port()),
        client_cert_pem: std::fs::read_to_string(sub(d, "tls.crt")).unwrap(),
        client_key_pem: ostrich_common::read_private_key_pem(&sub(d, "tls.key")).expect("key"),
        ca_cert_pem: std::fs::read_to_string(sub(d, "ca.crt")).unwrap(),
        server_name: Some(server_name.to_string()),
        max_retries: 1,
        ..Default::default()
    };
    for d in ["acme-server", "est-server"] {
        // "ca" is the compose service name used in CA_GRPC_URL=https://ca:50051.
        let client = CaGrpcClient::new(sub_client_cfg(d, "ca"))
            .await
            .unwrap_or_else(|e| panic!("{d}/ -> ca: {e}"));
        issue_via(&client)
            .await
            .unwrap_or_else(|e| panic!("{d}/ -> ca: {e}"));
    }
    {
        let seen = served_sub.seen_peers.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
    }
    // The CA server identity is not a client (serverAuth-only EKU, CN not allow-listed).
    let ca_as_client = GrpcClientConfig {
        client_cert_pem: std::fs::read_to_string(sub("ca-server", "tls.crt")).unwrap(),
        client_key_pem: ostrich_common::read_private_key_pem(&sub("ca-server", "tls.key"))
            .expect("key"),
        ..sub_client_cfg("acme-server", "ca")
    };
    let refused = match CaGrpcClient::new(ca_as_client).await {
        Err(_) => true,
        Ok(c) => issue_via(&c).await.is_err(),
    };
    assert!(
        refused,
        "ca-server/ identity must not be usable as a gRPC client"
    );
    let _ = &mut served_sub.events;

    let _ = std::fs::remove_dir_all(&out);
}

// ------------------------------------------------ fix round 1 additions ---

/// 16. SEC-002: one source address cannot hold more than
/// `GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP` handshake slots; a valid client from
/// the same address still connects once the idle ones go away.
#[tokio::test]
async fn per_source_cap_closes_excess_idle_connections() {
    use ostrich_common::grpc_tls::GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP;
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let mut idle = Vec::new();
    for _ in 0..GRPC_MAX_INFLIGHT_HANDSHAKES_PER_IP {
        idle.push(tokio::net::TcpStream::connect(h.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut extra = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
        .await
        .expect("excess connection closed promptly");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("per_source_handshake_limit"));
    assert_eq!(ev.ip_address.as_deref(), Some("127.0.0.1"));

    drop(idle);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect after idle clients left");
    issue_via(&client).await.expect("issue");
}

/// 17. RFC-008: a trusted, allow-listed leaf WITHOUT an extendedKeyUsage
/// extension passes webpki but is denied by the layer and audited.
#[tokio::test]
async fn leaf_without_eku_is_permission_denied() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.leaf_with(
        "acme-server",
        &["acme-server"],
        vec![],
        &rcgen::PKCS_ECDSA_P256_SHA256,
    );
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("TLS connects (webpki allows a missing EKU)");
    let status = issue_via(&client).await.expect_err("denied");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("missing_client_auth_eku"));
    assert_eq!(ev.subject, "CN=acme-server");
    assert!(h.seen_peers.lock().unwrap().is_empty());
}

/// 18. SEC-003 / NIST-009 / SEC-006: access-denied records are rate limited
/// per listener, and the overflow is summarised by the timer without further
/// denials.
#[tokio::test]
async fn access_denied_audit_is_rate_limited_and_summarised() {
    let mut h = Harness::start_with(
        &["CN=acme-server"],
        Some(GrpcListenerLimits {
            audit_max_per_window: 2,
            audit_window: Duration::from_millis(800),
            ..Default::default()
        }),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .await;
    let leaf = h.client_pki.client("intruder");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    for _ in 0..5 {
        let status = issue_via(&client).await.expect_err("denied");
        assert_eq!(
            status.code(),
            Code::PermissionDenied,
            "every call is denied"
        );
    }
    let mut denied = 0;
    let summary = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ev = h.events.recv().await.expect("open");
            match ev.kind {
                AuthAuditKind::AccessDenied => denied += 1,
                AuthAuditKind::AccessDeniedSuppressed => return ev,
                _ => {}
            }
        }
    })
    .await
    .expect("suppression summary from the timer");
    assert_eq!(denied, 2, "records per window");
    let details = summary.details.expect("details");
    assert_eq!(details["count"], 3);
    assert_eq!(summary.resource.as_deref(), Some(LISTENER));
}

/// 19. PQC-001 / PQC-002: a P-384 / SHA-384 PKI works end to end through
/// `CaGrpcClient`; a raw handshake with the exact client config negotiates
/// SecP256r1MLKEM768 and reports `fips()` on the live connection.
#[tokio::test]
async fn p384_chain_end_to_end_with_fips_hybrid_group() {
    let p384 = &rcgen::PKCS_ECDSA_P384_SHA384;
    let h = Harness::start_with(&["CN=acme-server"], None, p384).await;
    let leaf = h.client_pki.leaf_with(
        "acme-server",
        &["acme-server"],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        p384,
    );
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("mTLS connect");
    issue_via(&client).await.expect("issue over a P-384 chain");

    let config =
        grpc_client_config(&leaf.cert_pem, &leaf.key_pem, &h.server_pki.ca_pem()).expect("client");
    let tls = tls_handshake(h.addr, config).await.expect("handshake");
    let (_, conn) = tls.get_ref();
    assert!(conn.fips(), "client connection reports FIPS");
    assert_eq!(
        conn.negotiated_key_exchange_group().map(|g| g.name()),
        Some(rustls::NamedGroup::secp256r1MLKEM768)
    );
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

/// 20. PQC-001: a client offering only plain X25519 (not FIPS-approved) is
/// refused by the listener.
#[tokio::test]
async fn x25519_only_client_rejected() {
    let mut h = Harness::start(&["CN=acme-server"]).await;
    let leaf = h.client_pki.client("acme-server");
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(good_roots(&h.server_pki.ca_pem()))
        .with_client_auth_cert(
            CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("certs"),
            PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).expect("key"),
        )
        .expect("client auth");
    config.alpn_protocols = vec![b"h2".to_vec()];
    assert!(raw_connect_and_probe(h.addr, Arc::new(config))
        .await
        .is_err());
    let ev = h.next_event(AuthAuditKind::TlsHandshakeFailed).await;
    assert_eq!(ev.reason.as_deref(), Some("peer_incompatible"));
    assert!(h.seen_peers.lock().unwrap().is_empty());
}
