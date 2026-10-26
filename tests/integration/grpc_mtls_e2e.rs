//! Offline e2e for the CA gRPC mTLS listener (`ostrich_common::grpc_tls`).
//!
//! Serves a stub `CertificateAuthorityService` through the real
//! `bind_mtls_incoming` + `SubjectAllowlistLayer` stack (with the production
//! `ostrich_ca::grpc_authz::CA_GRPC_METHOD_RULES`, `bind_caller` and
//! `authorize_issue` with the per-namespace profile policy) on
//! 127.0.0.1 and talks to it with the real `CaGrpcClient` (and raw rustls
//! clients for the negative cases). The PKI is generated with rcgen; no
//! database, no network beyond loopback.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing), AC-3 / AC-5 / AC-6
//!   (per-role, per-method rules; role x RPC matrix), AU-3 / AU-10 (actor =
//!   verified peer, requestor bound to its namespace), SI-10 (requestor),
//!   AC-17 / IA-3 / IA-5(2) (mTLS), SC-8 / SC-13 (TLS 1.3, FIPS provider),
//!   AU-2 / AU-3 (denial and handshake-failure audit)
//! - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.1/.2, FCS_TLSC_EXT.2, FIA_X509_EXT.1,
//!   FDP_ACC.1, FDP_ACF.1, FMT_SMR.2, FAU_GEN.1, FAU_GEN.2
//! - RFC 8446 (TLS 1.3 only), RFC 7301 (ALPN h2), RFC 5280 §4.2.1.12 (EKU)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ostrich_ca::grpc_authz::{
    authorize_issue, bind_caller, IssuerProfilePolicy, CA_GRPC_METHOD_RULES, PROFILE_DENIED_MESSAGE,
};
use ostrich_common::auth::{AuthAuditEvent, AuthAuditHook, AuthAuditKind};
use ostrich_common::grpc_tls::{
    bind_mtls_incoming, bind_mtls_incoming_with, grpc_client_config, grpc_server_config,
    GrpcListenerLimits, GrpcTlsConnector, GRPC_MAX_INFLIGHT_HANDSHAKES, GRPC_TLS_HANDSHAKE_TIMEOUT,
};
use ostrich_common::tls::TlsSettings;
use ostrich_common::{
    AuthorizedGrpcPeer, CaGrpcClient, GrpcClientConfig, GrpcClientRegistry, GrpcServerOptions,
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
const SERVICE_PREFIX: &str = "/ostrich.ca.v1.CertificateAuthorityService/";
const RPCS: [&str; 6] = [
    "IssueCertificate",
    "RevokeCertificate",
    "GenerateCrl",
    "CheckRevocationStatus",
    "GetCaInfo",
    "ListProfiles",
];
/// Requestor sent by the generic acme-server test calls.
const ACME_REQUESTOR: &str = "acme::grpc-mtls-e2e";

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

    /// A subordinate CA `cn` signed by this CA (with AKI).
    fn sub_ca(&self, cn: &str) -> Pki {
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("sub ca params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().expect("sub ca key");
        Pki {
            ca: CertifiedIssuer::signed_by(p, key, &self.ca).expect("sub ca cert"),
        }
    }

    fn leaf(&self, cn: &str, sans: &[&str], eku: ExtendedKeyUsagePurpose) -> Leaf {
        let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut p = CertificateParams::new(sans).expect("leaf params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![eku];
        // RFC 5280 §4.2.1.1: AKI in non-self-signed certificates (admin
        // leaves are matched to the anchor by AKI, SEC-201).
        p.use_authority_key_identifier_extension = true;
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

    /// clientAuth leaf for `cn` that expires `secs` seconds from now.
    fn client_expiring_in(&self, cn: &str, secs: u64) -> Leaf {
        let mut p = CertificateParams::new(vec![cn.to_string()]).expect("leaf params");
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - Duration::from_secs(60);
        p.not_after = now + Duration::from_secs(secs);
        // RFC 5280 §4.2.1.1: AKI in non-self-signed certificates (admin
        // leaves are matched to the anchor by AKI, SEC-201).
        p.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().expect("leaf key");
        let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
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

/// One call that reached the stub's inner logic.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenCall {
    rpc: &'static str,
    /// Verified peer (from `AuthorizedGrpcPeer`).
    peer: String,
    /// Issue / Revoke: the bound audit actor and requestor (`bind_caller`).
    bound: Option<(Option<String>, String)>,
}

/// Stub CA: Issue and Revoke bind the requestor exactly as `CaGrpcService`
/// does (`authorize_issue` / `bind_caller` with `require_peer = true`, and
/// the per-namespace profile policy for Issue); every RPC records the call
/// and answers OK.
#[derive(Clone)]
struct StubCa {
    seen_peers: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<SeenCall>>>,
    profiles: Arc<IssuerProfilePolicy>,
}

impl Default for StubCa {
    fn default() -> Self {
        Self {
            seen_peers: Arc::default(),
            calls: Arc::default(),
            profiles: Arc::new(stub_profile_policy()),
        }
    }
}

/// The profiles ca-server registers (names only matter here) and the
/// dev/test compose allow lists: ACME `acme-default;tls_client`, EST the
/// default list.
fn stub_profile_policy() -> IssuerProfilePolicy {
    use ostrich_x509::profile::CertificateProfile;
    let named = |mut p: CertificateProfile, name: &str| {
        p.name = name.to_string();
        p
    };
    let profiles = [
        named(CertificateProfile::tls_server(90), "acme-default"),
        named(CertificateProfile::tls_client(365), "tls_client"),
        named(CertificateProfile::tls_server(397), "tls_server"),
        named(CertificateProfile::tls_server(397), "tls_server_client"),
        named(CertificateProfile::efs(730), "efs"),
        named(
            CertificateProfile::intermediate_ca(1825, 0),
            "intermediate_ca",
        ),
    ];
    let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    IssuerProfilePolicy::parse(
        &v(&["acme-default", "tls_client"]),
        &v(&["tls_client", "tls_server", "tls_server_client", "efs"]),
        None,
        &profiles,
    )
    .expect("stub profile policy")
}

impl StubCa {
    fn record<T>(
        &self,
        rpc: &'static str,
        request: &Request<T>,
        bound: Option<(Option<String>, String)>,
    ) {
        let peer = request
            .extensions()
            .get::<AuthorizedGrpcPeer>()
            .map(|p| p.subject_dn.clone())
            .unwrap_or_else(|| "<none>".to_string());
        self.seen_peers.lock().unwrap().push(peer.clone());
        self.calls
            .lock()
            .unwrap()
            .push(SeenCall { rpc, peer, bound });
    }
}

#[tonic::async_trait]
impl CertificateAuthorityService for StubCa {
    async fn issue_certificate(
        &self,
        request: Request<IssueCertificateRequest>,
    ) -> Result<Response<IssueCertificateResponse>, Status> {
        let caller = authorize_issue(
            &request,
            &request.get_ref().requestor,
            &request.get_ref().profile_name,
            &self.profiles,
            true,
        )
        .await?;
        self.record(
            "IssueCertificate",
            &request,
            Some((caller.actor().map(str::to_string), caller.requestor)),
        );
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
        request: Request<RevokeCertificateRequest>,
    ) -> Result<Response<RevokeCertificateResponse>, Status> {
        let caller = bind_caller(&request, &request.get_ref().requestor, true).await?;
        self.record(
            "RevokeCertificate",
            &request,
            Some((caller.actor().map(str::to_string), caller.requestor)),
        );
        Ok(Response::new(RevokeCertificateResponse {
            success: true,
            revocation_time: 1,
        }))
    }

    async fn generate_crl(
        &self,
        request: Request<GenerateCrlRequest>,
    ) -> Result<Response<GenerateCrlResponse>, Status> {
        self.record("GenerateCrl", &request, None);
        Ok(Response::new(GenerateCrlResponse::default()))
    }

    async fn check_revocation_status(
        &self,
        request: Request<CheckRevocationStatusRequest>,
    ) -> Result<Response<CheckRevocationStatusResponse>, Status> {
        self.record("CheckRevocationStatus", &request, None);
        Ok(Response::new(CheckRevocationStatusResponse::default()))
    }

    async fn get_ca_info(
        &self,
        request: Request<GetCaInfoRequest>,
    ) -> Result<Response<GetCaInfoResponse>, Status> {
        self.record("GetCaInfo", &request, None);
        Ok(Response::new(GetCaInfoResponse::default()))
    }

    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesResponse>, Status> {
        self.record("ListProfiles", &request, None);
        Ok(Response::new(ListProfilesResponse::default()))
    }
}

/// Audit hook that forwards every event to a channel, optionally after a
/// delay (to prove a denial record survives a cancelled call).
struct RecordingHook {
    tx: mpsc::UnboundedSender<AuthAuditEvent>,
    delay: Option<Duration>,
}

#[async_trait]
impl AuthAuditHook for RecordingHook {
    async fn record_auth_event(&self, event: AuthAuditEvent) {
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        let _ = self.tx.send(event);
    }
}

/// Client subject lists per role (`CA_GRPC_{ACME,EST,ADMIN}_CLIENT_SUBJECTS`).
#[derive(Clone, Copy)]
struct Roles<'a> {
    acme: &'a [&'a str],
    est: &'a [&'a str],
    admin: &'a [&'a str],
}

impl<'a> Roles<'a> {
    /// Only an ACME list (the shape of the pre-role tests).
    fn acme(acme: &'a [&'a str]) -> Self {
        Self {
            acme,
            est: &[],
            admin: &[],
        }
    }

    fn registry(&self) -> GrpcClientRegistry {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        GrpcClientRegistry::parse(&v(self.acme), &v(self.est), &v(self.admin)).expect("registry")
    }
}

/// The role lists of the method-matrix tests.
const MATRIX_ROLES: Roles<'static> = Roles {
    acme: &["CN=acme-server"],
    est: &["CN=est-server"],
    admin: &["CN=ops-admin"],
};

/// A running stub CA behind the real mTLS listener + authorization layer.
struct Served {
    addr: SocketAddr,
    events: mpsc::UnboundedReceiver<AuthAuditEvent>,
    seen_peers: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<SeenCall>>>,
    server_config: Arc<rustls::ServerConfig>,
}

/// Serve the stub CA with the given TLS files and role lists (the same
/// `grpc_server_config` + `bind_mtls_incoming` + `SubjectAllowlistLayer` +
/// `CA_GRPC_METHOD_RULES` stack ca-server uses), with the production limits.
async fn serve_stub(settings: &TlsSettings, roles: Roles<'_>) -> Served {
    serve_stub_with(settings, roles, None, None).await
}

/// [`serve_stub`] with explicit listener / audit limits (`None` = defaults,
/// through the same `bind_mtls_incoming` / `SubjectAllowlistLayer::new` calls
/// ca-server makes) and an optional audit-hook delay.
async fn serve_stub_with(
    settings: &TlsSettings,
    roles: Roles<'_>,
    limits: Option<GrpcListenerLimits>,
    audit_delay: Option<Duration>,
) -> Served {
    let server_config = grpc_server_config(settings).expect("server config");
    let clients = Arc::new(roles.registry());

    let (tx, events) = mpsc::unbounded_channel();
    let hook: Arc<dyn AuthAuditHook> = Arc::new(RecordingHook {
        tx,
        delay: audit_delay,
    });
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
        None => SubjectAllowlistLayer::new(clients, CA_GRPC_METHOD_RULES, Some(hook), LISTENER),
        Some(limits) => SubjectAllowlistLayer::with_limits(
            clients,
            CA_GRPC_METHOD_RULES,
            Some(hook),
            LISTENER,
            limits,
        ),
    };
    // SEC-101: the client trust anchors, as ca-server passes them.
    let anchors: Vec<CertificateDer<'static>> = settings
        .client_ca_path
        .as_ref()
        .map(|path| {
            CertificateDer::pem_file_iter(path)
                .expect("client ca")
                .collect::<Result<_, _>>()
                .expect("client ca pem")
        })
        .unwrap_or_default();
    let layer = layer
        .with_client_trust_anchors(&anchors)
        .expect("client trust anchors");

    let stub = StubCa::default();
    let seen_peers = stub.seen_peers.clone();
    let calls = stub.calls.clone();
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
        calls,
        server_config,
    }
}

struct Harness {
    addr: SocketAddr,
    server_pki: Pki,
    client_pki: Pki,
    events: mpsc::UnboundedReceiver<AuthAuditEvent>,
    seen_peers: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<SeenCall>>>,
    server_config: Arc<rustls::ServerConfig>,
}

impl Harness {
    /// Start the real mTLS listener + authorization layer around the stub CA,
    /// with `acme` as the only (ACME) client list.
    async fn start(acme: &[&str]) -> Self {
        Self::start_with(acme, None, &rcgen::PKCS_ECDSA_P256_SHA256).await
    }

    /// [`Self::start`] with explicit limits and PKI key algorithm.
    async fn start_with(
        acme: &[&str],
        limits: Option<GrpcListenerLimits>,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> Self {
        Self::start_roles(Roles::acme(acme), limits, alg, None).await
    }

    /// Start with explicit role lists, limits, key algorithm and audit delay.
    async fn start_roles(
        roles: Roles<'_>,
        limits: Option<GrpcListenerLimits>,
        alg: &'static rcgen::SignatureAlgorithm,
        audit_delay: Option<Duration>,
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
        let served = serve_stub_with(&settings, roles, limits, audit_delay).await;
        Self {
            addr: served.addr,
            server_pki,
            client_pki,
            events: served.events,
            seen_peers: served.seen_peers,
            calls: served.calls,
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
    issue_request_as(ACME_REQUESTOR)
}

fn issue_request_as(requestor: &str) -> IssueCertificateRequest {
    IssueCertificateRequest {
        profile_name: "tls_client".to_string(),
        subject: None,
        subject_alt_names: vec![],
        public_key: vec![],
        requestor: requestor.to_string(),
        metadata: Default::default(),
        csr_der: vec![],
        request_id: String::new(),
    }
}

async fn issue_via(client: &CaGrpcClient) -> Result<IssueCertificateResponse, Status> {
    issue_via_as(client, ACME_REQUESTOR).await
}

async fn issue_via_as(
    client: &CaGrpcClient,
    requestor: &str,
) -> Result<IssueCertificateResponse, Status> {
    CertificateAuthorityServiceClient::new(client.channel())
        .issue_certificate(Request::new(issue_request_as(requestor)))
        .await
        .map(Response::into_inner)
}

fn revoke_request(requestor: &str) -> RevokeCertificateRequest {
    RevokeCertificateRequest {
        certificate_id: "00000000-0000-0000-0000-000000000001".to_string(),
        reason: 1,
        requestor: requestor.to_string(),
        justification: String::new(),
    }
}

/// Call one CA RPC by name with `requestor` (Issue / Revoke only).
async fn call_rpc(client: &CaGrpcClient, rpc: &str, requestor: &str) -> Result<(), Status> {
    let mut c = CertificateAuthorityServiceClient::new(client.channel());
    match rpc {
        "IssueCertificate" => c
            .issue_certificate(Request::new(issue_request_as(requestor)))
            .await
            .map(drop),
        "RevokeCertificate" => c
            .revoke_certificate(Request::new(revoke_request(requestor)))
            .await
            .map(drop),
        "GenerateCrl" => c
            .generate_crl(Request::new(GenerateCrlRequest {}))
            .await
            .map(drop),
        "CheckRevocationStatus" => c
            .check_revocation_status(Request::new(CheckRevocationStatusRequest {
                certificate_id: "00000000-0000-0000-0000-000000000001".to_string(),
            }))
            .await
            .map(drop),
        "GetCaInfo" => c
            .get_ca_info(Request::new(GetCaInfoRequest {}))
            .await
            .map(drop),
        "ListProfiles" => c
            .list_profiles(Request::new(ListProfilesRequest {}))
            .await
            .map(drop),
        other => panic!("unknown rpc {other}"),
    }
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

// ------------------------------------- per-method authorization (POAM-26) ---

/// One client identity of the matrix tests.
struct Caller {
    name: &'static str,
    cn: &'static str,
    requestor: &'static str,
    allowed: &'static [&'static str],
}

const ISSUER_RPCS: &[&str] = &["IssueCertificate", "GetCaInfo", "ListProfiles"];
const ADMIN_RPCS: &[&str] = &[
    "RevokeCertificate",
    "GenerateCrl",
    "CheckRevocationStatus",
    "GetCaInfo",
    "ListProfiles",
];

/// 21. AC-3 / AC-5 / AC-6: {acme, est, admin, stranger} x six RPCs, each
/// with a valid requestor for its namespace. Allowed cells reach the stub;
/// denied cells get PERMISSION_DENIED, never reach the stub, and are audited
/// with the exact path and reason `method_not_permitted` (stranger:
/// `subject_not_allowlisted`).
#[tokio::test]
async fn role_method_matrix() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let callers = [
        Caller {
            name: "acme",
            cn: "acme-server",
            requestor: "acme::acct-1",
            allowed: ISSUER_RPCS,
        },
        Caller {
            name: "est",
            cn: "est-server",
            requestor: "est::client-1",
            allowed: ISSUER_RPCS,
        },
        Caller {
            name: "admin",
            cn: "ops-admin",
            requestor: "admin::ops",
            allowed: ADMIN_RPCS,
        },
        Caller {
            name: "stranger",
            cn: "stranger",
            requestor: "acme::x",
            allowed: &[],
        },
    ];
    for caller in &callers {
        let leaf = h.client_pki.client(caller.cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("mTLS connect");
        for rpc in RPCS {
            let before = h.calls.lock().unwrap().len();
            let result = call_rpc(&client, rpc, caller.requestor).await;
            let after = h.calls.lock().unwrap().clone();
            if caller.allowed.contains(&rpc) {
                result.unwrap_or_else(|e| panic!("{} {rpc}: {e}", caller.name));
                assert_eq!(after.len(), before + 1, "{} {rpc} reached", caller.name);
                let seen = after.last().expect("call");
                assert_eq!(seen.rpc, rpc);
                assert_eq!(seen.peer, format!("CN={}", caller.cn));
                if let Some((actor, requestor)) = &seen.bound {
                    assert_eq!(actor.as_deref(), Some(seen.peer.as_str()));
                    assert_eq!(requestor, caller.requestor);
                }
            } else {
                let status = result.expect_err("denied");
                assert_eq!(
                    status.code(),
                    Code::PermissionDenied,
                    "{} {rpc}",
                    caller.name
                );
                assert_eq!(after.len(), before, "{} {rpc} must not reach", caller.name);
                let ev = h.next_event(AuthAuditKind::AccessDenied).await;
                assert_eq!(ev.subject, format!("CN={}", caller.cn));
                assert_eq!(
                    ev.resource.as_deref(),
                    Some(format!("{SERVICE_PREFIX}{rpc}").as_str())
                );
                let expected = if caller.name == "stranger" {
                    "subject_not_allowlisted"
                } else {
                    "method_not_permitted"
                };
                assert_eq!(
                    ev.reason.as_deref(),
                    Some(expected),
                    "{} {rpc}",
                    caller.name
                );
            }
        }
    }
    assert!(
        h.events.try_recv().is_err(),
        "allowed calls are not audited"
    );
}

/// 22. Default deny: a path that is not in the method table is refused with
/// PERMISSION_DENIED (not UNIMPLEMENTED) and audited as `method_not_mapped`.
#[tokio::test]
async fn unknown_method_denied() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    for cn in ["acme-server", "ops-admin"] {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        let mut grpc = tonic::client::Grpc::new(client.channel());
        grpc.ready().await.expect("ready");
        let path = "/ostrich.ca.v1.CertificateAuthorityService/DeleteEverything";
        let status = grpc
            .unary::<GetCaInfoRequest, GetCaInfoResponse, _>(
                Request::new(GetCaInfoRequest {}),
                tonic::codegen::http::uri::PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .expect_err("unmapped method");
        assert_eq!(status.code(), Code::PermissionDenied, "{cn}");
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some("method_not_mapped"));
        assert_eq!(ev.resource.as_deref(), Some(path));
        assert_eq!(ev.subject, format!("CN={cn}"));
    }
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 23. AU-3 / SI-10: acme-server claiming `est::x` (and est-server claiming
/// `acme::x`) is refused before the service logic and audited with the peer
/// as subject and the expected namespace.
#[tokio::test]
async fn requestor_namespace_mismatch_denied_and_audited() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    for (cn, claimed, expected) in [
        ("acme-server", "est::x", "acme"),
        ("est-server", "acme::x", "est"),
    ] {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        let status = issue_via_as(&client, claimed)
            .await
            .expect_err("namespace mismatch");
        assert_eq!(status.code(), Code::PermissionDenied);
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some("requestor_namespace_mismatch"));
        assert_eq!(ev.subject, format!("CN={cn}"));
        assert_eq!(ev.resource.as_deref(), Some(ISSUE_PATH));
        assert_eq!(ev.ip_address.as_deref(), Some("127.0.0.1"));
        let d = ev.details.expect("details");
        assert_eq!(d["expected_namespace"], expected);
        assert_eq!(d["claimed_namespace"], claimed.split("::").next().unwrap());
        assert_eq!(d["role"], "issuer");
        assert_eq!(d["listener"], LISTENER);
    }
    assert!(
        h.calls.lock().unwrap().is_empty(),
        "inner logic never reached"
    );
}

/// 24. An issuer must name its principal: an empty requestor is refused.
#[tokio::test]
async fn empty_requestor_denied_for_issuer() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    let status = issue_via_as(&client, "").await.expect_err("empty");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("requestor_missing"));
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 25. SI-10: control characters and over-long requestors are refused; the
/// audited claimed namespace is escaped.
#[tokio::test]
async fn invalid_requestor_denied() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    let long = format!("acme::{}", "a".repeat(250));
    assert_eq!(long.len(), 256);
    for bad in ["acme::a\u{1b}[2Jb", "acme::\u{202e}x", long.as_str()] {
        let status = issue_via_as(&client, bad).await.expect_err("invalid");
        assert_eq!(status.code(), Code::PermissionDenied);
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some("requestor_invalid"), "{bad:?}");
    }
    // A control character in the namespace part is escaped in the record.
    let status = issue_via_as(&client, "ac\nme::x")
        .await
        .expect_err("mismatch");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("requestor_namespace_mismatch"));
    assert_eq!(ev.details.expect("details")["claimed_namespace"], "ac\\nme");
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 26. AU-3: an admin may revoke without an on-behalf-of principal; the
/// actor is the verified admin peer.
#[tokio::test]
async fn admin_revoke_without_requestor_ok() {
    let h = Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("ops-admin");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    call_rpc(&client, "RevokeCertificate", "")
        .await
        .expect("admin revoke");
    let calls = h.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[SeenCall {
            rpc: "RevokeCertificate",
            peer: "CN=ops-admin".to_string(),
            bound: Some((Some("CN=ops-admin".to_string()), String::new())),
        }]
    );
}

/// 27. An admin may not claim another namespace.
#[tokio::test]
async fn admin_revoke_with_acme_namespace_denied() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("ops-admin");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    let status = call_rpc(&client, "RevokeCertificate", "acme::victim")
        .await
        .expect_err("admin claiming acme::");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("requestor_namespace_mismatch"));
    assert_eq!(ev.subject, "CN=ops-admin");
    let d = ev.details.expect("details");
    assert_eq!(d["expected_namespace"], "admin");
    assert_eq!(d["role"], "admin");
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 28. AU-3 / AU-10: for an ACME issuance the bound actor is the verified
/// peer and the requestor is the claimed ACME account.
#[tokio::test]
async fn bound_caller_actor_is_peer() {
    let h = Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    issue_via_as(&client, "acme::acct-1").await.expect("issue");
    let calls = h.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[SeenCall {
            rpc: "IssueCertificate",
            peer: "CN=acme-server".to_string(),
            bound: Some((
                Some("CN=acme-server".to_string()),
                "acme::acct-1".to_string()
            )),
        }]
    );
}

/// 29. CM-6: with the default empty admin list nobody (not even an
/// otherwise valid client) may Revoke, GenerateCrl or CheckRevocationStatus.
#[tokio::test]
async fn admin_list_empty_default_denies_revoke_crl_status_for_all() {
    let mut h = Harness::start_roles(
        Roles {
            acme: &["CN=acme-server"],
            est: &["CN=est-server"],
            admin: &[],
        },
        None,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        None,
    )
    .await;
    for (cn, requestor, reason) in [
        ("acme-server", "acme::x", "method_not_permitted"),
        ("est-server", "est::x", "method_not_permitted"),
        ("ops-admin", "admin::x", "subject_not_allowlisted"),
    ] {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        for rpc in ["RevokeCertificate", "GenerateCrl", "CheckRevocationStatus"] {
            let status = call_rpc(&client, rpc, requestor)
                .await
                .expect_err("no admin configured");
            assert_eq!(status.code(), Code::PermissionDenied, "{cn} {rpc}");
            let ev = h.next_event(AuthAuditKind::AccessDenied).await;
            assert_eq!(ev.reason.as_deref(), Some(reason), "{cn} {rpc}");
        }
    }
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 30. SEC-010 for service-side denials: the client gives up (deadline,
/// RST_STREAM) while the requestor-denial record is still being written;
/// the record still arrives.
#[tokio::test]
async fn requestor_denial_audit_is_cancel_proof() {
    let mut h = Harness::start_roles(
        MATRIX_ROLES,
        None,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        Some(Duration::from_millis(800)),
    )
    .await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    let cancelled =
        tokio::time::timeout(Duration::from_millis(200), issue_via_as(&client, "est::x")).await;
    assert!(
        cancelled.is_err(),
        "call must still be pending when dropped"
    );
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("requestor_namespace_mismatch"));
    assert_eq!(ev.subject, "CN=acme-server");
    assert!(h.calls.lock().unwrap().is_empty());
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

/// 10b. CM-6 / SC-24 / AC-5: role-list configuration errors refuse to start
/// (overlap, removed legacy variable, admin only, malformed admin entry).
#[tokio::test]
async fn config_errors_refuse_to_start() {
    let server_pki = Pki::new("Config Server CA");
    let client_pki = Pki::new("Config Client CA");
    let leaf = server_pki.leaf(
        "ca-service",
        &["localhost"],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let cert = tmp_file("cfg-cert", &leaf.cert_pem).display().to_string();
    let key = tmp_file("cfg-key", &leaf.key_pem).display().to_string();
    let ca = tmp_file("cfg-ca", &client_pki.ca_pem())
        .display()
        .to_string();
    let base = || GrpcServerOptions {
        cert_path: Some(cert.clone()),
        key_path: Some(key.clone()),
        client_ca_path: Some(ca.clone()),
        acme_subjects: vec!["CN=acme-server".to_string()],
        est_subjects: vec!["CN=est-server".to_string()],
        admin_subjects: vec![String::new()],
        ..Default::default()
    };
    base().resolve(true).expect("baseline resolves");

    let mut overlap = base();
    overlap.admin_subjects = vec!["CN = acme-server".to_string()];
    let err = overlap.resolve(true).expect_err("overlap");
    assert!(err.to_string().contains("listed in both"), "{err}");

    let mut legacy = base();
    legacy.legacy_allowed_subjects = vec!["CN=acme-server".to_string()];
    let err = legacy.resolve(true).expect_err("legacy variable");
    assert!(
        err.to_string().contains("CA_GRPC_ALLOWED_CLIENT_SUBJECTS"),
        "{err}"
    );

    let mut admin_only = base();
    admin_only.acme_subjects = vec![String::new()];
    admin_only.est_subjects.clear();
    admin_only.admin_subjects = vec!["CN=ops-admin".to_string()];
    let err = admin_only.resolve(true).expect_err("no issuer");
    assert!(
        err.to_string().contains("no issuer client configured"),
        "{err}"
    );

    let mut malformed = base();
    malformed.admin_subjects = vec![r"CN=a\".to_string()];
    let err = malformed.resolve(true).expect_err("malformed admin entry");
    assert!(
        err.to_string().contains("CA_GRPC_ADMIN_CLIENT_SUBJECTS"),
        "{err}"
    );
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
/// `docker-compose.yml` role defaults under every server name compose dials
/// (`ca-service`, `ca`, `localhost`), `integration-tests` is refused unless
/// listed; with the `tests/integration/docker-compose.yml` roles
/// `integration-tests` issues (ACME namespace) but cannot revoke and
/// `integration-admin` revokes but cannot issue; and the generated env file
/// points at the generated files (incl. the admin identity). Needs `bash` and
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

    assert!(
        names.iter().any(|n| n == "integration-admin.crt")
            && names.iter().any(|n| n == "integration-admin.key"),
        "admin identity missing: {names:?}"
    );

    // Server side, exactly as ca-server resolves it (release-build rules).
    // docker-compose.yml defaults: ACME / EST service identities, no admin.
    const COMPOSE_ROLES: Roles<'static> = Roles {
        acme: &["CN=acme-server"],
        est: &["CN=est-server"],
        admin: &[],
    };
    // tests/integration/docker-compose.yml (and docker-compose.dev.yml).
    const INTEGRATION_ROLES: Roles<'static> = Roles {
        acme: &["CN=acme-server", "CN=integration-tests"],
        est: &["CN=est-server"],
        admin: &["CN=integration-admin"],
    };
    let role_options = |roles: Roles<'_>, cert: PathBuf, key: PathBuf, ca: PathBuf| {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        GrpcServerOptions {
            cert_path: Some(cert.display().to_string()),
            key_path: Some(key.display().to_string()),
            client_ca_path: Some(ca.display().to_string()),
            acme_subjects: v(roles.acme),
            est_subjects: v(roles.est),
            // compose always renders the admin variable, usually as "".
            admin_subjects: if roles.admin.is_empty() {
                vec![String::new()]
            } else {
                v(roles.admin)
            },
            ..Default::default()
        }
    };
    let mode = role_options(
        COMPOSE_ROLES,
        file("ca-service.crt"),
        file("ca-service.key"),
        file("ca.crt"),
    )
    .resolve(true)
    .expect("dev material resolves to mTLS");
    match mode {
        ostrich_common::GrpcServerMode::Mtls {
            config,
            clients,
            client_anchors,
        } => {
            assert!(config.fips());
            assert_eq!(
                clients.summary(),
                serde_json::json!({
                    "acme": ["CN=acme-server"],
                    "est": ["CN=est-server"],
                    "admin": [],
                })
            );
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
        COMPOSE_ROLES,
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

    for (identity, requestor) in [("acme-server", "acme::dev"), ("est-server", "est::dev")] {
        for server_name in ["ca-service", "ca", "localhost"] {
            let client = CaGrpcClient::new(client_cfg(identity, server_name))
                .await
                .unwrap_or_else(|e| panic!("{identity} -> {server_name}: {e}"));
            issue_via_as(&client, requestor)
                .await
                .unwrap_or_else(|e| panic!("{identity} -> {server_name}: {e}"));
        }
    }
    assert_eq!(served.seen_peers.lock().unwrap().len(), 6);

    // integration-tests is a valid client but not in the compose default
    // role lists: PERMISSION_DENIED + audit.
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
    assert_eq!(ev.reason.as_deref(), Some("subject_not_allowlisted"));
    // Nobody may revoke with the compose defaults (empty admin list).
    let client = CaGrpcClient::new(client_cfg("integration-admin", "localhost"))
        .await
        .expect("trusted admin client connects");
    let status = call_rpc(&client, "RevokeCertificate", "")
        .await
        .expect_err("admin not configured");
    assert_eq!(status.code(), Code::PermissionDenied);

    // Integration-test compose roles: issuer vs admin separation (AC-5).
    let mut served_it = serve_stub(
        &TlsSettings {
            cert_path: file("ca-service.crt"),
            key_path: file("ca-service.key"),
            client_ca_path: Some(file("ca.crt")),
            optional_client_auth: false,
        },
        INTEGRATION_ROLES,
    )
    .await;
    role_options(
        INTEGRATION_ROLES,
        file("ca-service.crt"),
        file("ca-service.key"),
        file("ca.crt"),
    )
    .resolve(true)
    .expect("integration compose roles resolve");
    let it_cfg = |identity: &str| GrpcClientConfig {
        endpoint: format!("https://127.0.0.1:{}", served_it.addr.port()),
        ..client_cfg(identity, "localhost")
    };
    let tests_client = CaGrpcClient::new(it_cfg("integration-tests"))
        .await
        .expect("connect");
    issue_via_as(&tests_client, "acme::integration-tests-ca-core")
        .await
        .expect("integration-tests issues in the acme namespace");
    let status = call_rpc(&tests_client, "RevokeCertificate", "acme::x")
        .await
        .expect_err("issuer cannot revoke");
    assert_eq!(status.code(), Code::PermissionDenied);
    let ev = next_event_within(
        &mut served_it.events,
        AuthAuditKind::AccessDenied,
        Duration::from_secs(10),
    )
    .await
    .expect("access_denied audit");
    assert_eq!(ev.reason.as_deref(), Some("method_not_permitted"));
    let admin_client = CaGrpcClient::new(it_cfg("integration-admin"))
        .await
        .expect("connect");
    for rpc in ["RevokeCertificate", "GenerateCrl", "CheckRevocationStatus"] {
        call_rpc(&admin_client, rpc, "admin::integration-tests")
            .await
            .unwrap_or_else(|e| panic!("integration-admin {rpc}: {e}"));
    }
    let status = issue_via_as(&admin_client, "admin::integration-tests")
        .await
        .expect_err("admin cannot issue");
    assert_eq!(status.code(), Code::PermissionDenied);
    {
        let calls = served_it.calls.lock().unwrap();
        let revoke = calls
            .iter()
            .find(|c| c.rpc == "RevokeCertificate")
            .expect("revoke reached the stub");
        assert_eq!(
            revoke.bound,
            Some((
                Some("CN=integration-admin".to_string()),
                "admin::integration-tests".to_string()
            ))
        );
    }

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
        ("CA_GRPC_ADMIN_CLIENT_CERT_FILE", "integration-admin.crt"),
        ("CA_GRPC_ADMIN_CLIENT_KEY_FILE", "integration-admin.key"),
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
    let mode = role_options(
        COMPOSE_ROLES,
        sub("ca-server", "tls.crt"),
        sub("ca-server", "tls.key"),
        sub("ca-server", "client-ca.crt"),
    )
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
        COMPOSE_ROLES,
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
    for (d, requestor) in [("acme-server", "acme::dev"), ("est-server", "est::dev")] {
        // "ca" is the compose service name used in CA_GRPC_URL=https://ca:50051.
        let client = CaGrpcClient::new(sub_client_cfg(d, "ca"))
            .await
            .unwrap_or_else(|e| panic!("{d}/ -> ca: {e}"));
        issue_via_as(&client, requestor)
            .await
            .unwrap_or_else(|e| panic!("{d}/ -> ca: {e}"));
    }
    {
        let seen = served_sub.seen_peers.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
    }
    // The CA server identity is not a client (serverAuth-only EKU, CN not in a role list).
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

// ------------------------------- QA additions: per-method authz (SA-11) ---

/// Raw unary call to an arbitrary `:path` (bypasses the generated client).
async fn raw_unary(client: &CaGrpcClient, path: &str) -> Result<GetCaInfoResponse, Status> {
    let mut grpc = tonic::client::Grpc::new(client.channel());
    grpc.ready().await.expect("ready");
    let path = tonic::codegen::http::uri::PathAndQuery::try_from(path.to_string())
        .unwrap_or_else(|e| panic!("{path:?} is not a valid :path: {e}"));
    grpc.unary::<GetCaInfoRequest, GetCaInfoResponse, _>(
        Request::new(GetCaInfoRequest {}),
        path,
        tonic_prost::ProstCodec::default(),
    )
    .await
    .map(Response::into_inner)
}

/// 31. QA / AC-3 / SI-10: non-canonical spellings of mapped paths (case
/// variants, trailing slash, extra / empty segments, other service names,
/// percent-encoding) are refused over the wire for every role with
/// PERMISSION_DENIED and audited as `method_not_mapped` with the raw path;
/// a stranger is refused as `subject_not_allowlisted`. The stub is never
/// reached.
#[tokio::test]
async fn qa_unmapped_path_variants_denied_over_the_wire() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let paths = [
        "/ostrich.ca.v1.certificateauthorityservice/IssueCertificate",
        "/ostrich.ca.v1.CertificateAuthorityService/issueCertificate",
        "/ostrich.ca.v1.CertificateAuthorityService/GENERATECRL",
        "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo/",
        "/ostrich.ca.v1.CertificateAuthorityService/RevokeCertificate/extra",
        "/ostrich.ca.v1.CertificateAuthorityService//ListProfiles",
        "//ostrich.ca.v1.CertificateAuthorityService/GetCaInfo",
        "/ostrich.ca.v2.CertificateAuthorityService/IssueCertificate",
        "/ostrich.ca.v1.CertificateAuthorityServiceX/GetCaInfo",
        "/grpc.health.v1.Health/Check",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/ostrich.ca.v1.CertificateAuthorityService/Issue%43ertificate",
        "/ostrich.ca.v1.CertificateAuthorityService%2FGetCaInfo",
        "/ostrich.ca.v1.CertificateAuthorityService/GetCaInfo%20",
    ];
    for (cn, reason) in [
        ("acme-server", "method_not_mapped"),
        ("est-server", "method_not_mapped"),
        ("ops-admin", "method_not_mapped"),
        ("stranger", "subject_not_allowlisted"),
    ] {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        for path in paths {
            let status = raw_unary(&client, path).await.expect_err("must be denied");
            assert_eq!(status.code(), Code::PermissionDenied, "{cn} {path}");
            assert_eq!(status.message(), "client is not authorised for this call");
            let ev = h.next_event(AuthAuditKind::AccessDenied).await;
            assert_eq!(ev.reason.as_deref(), Some(reason), "{cn} {path}");
            assert_eq!(ev.resource.as_deref(), Some(path), "{cn}");
            assert_eq!(ev.subject, format!("CN={cn}"));
        }
    }
    assert!(h.calls.lock().unwrap().is_empty(), "stub never reached");
}

/// 32. QA / SI-10 / AU-2: requestor edge cases for every role are refused
/// over the wire before the service logic, each audited with the peer as
/// subject, the exact reason, the caller's role and expected namespace; the
/// status message is generic and never echoes the requestor.
#[tokio::test]
async fn qa_requestor_edge_cases_denied_and_audited_per_role() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let est_256 = format!("est::{}", "a".repeat(251));
    assert_eq!(est_256.len(), 256);
    let acme_mb_256 = format!("acme::{}", "\u{e9}".repeat(125));
    assert_eq!(acme_mb_256.len(), 256);
    let admin_256 = format!("admin::{}", "a".repeat(249));
    assert_eq!(admin_256.len(), 256);
    let cases: Vec<(&str, &str, &str, String, &str)> = vec![
        // (cn, rpc, role, requestor, reason)
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "acme::".into(),
            "requestor_invalid",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "acme".into(),
            "requestor_namespace_mismatch",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "ACME::x".into(),
            "requestor_namespace_mismatch",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "admin::x".into(),
            "requestor_namespace_mismatch",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            acme_mb_256,
            "requestor_invalid",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "acme::a\u{200b}".into(),
            "requestor_invalid",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "acme::a\u{85}".into(),
            "requestor_invalid",
        ),
        (
            "acme-server",
            "IssueCertificate",
            "issuer",
            "acme::a\u{2067}".into(),
            "requestor_invalid",
        ),
        (
            "est-server",
            "IssueCertificate",
            "issuer",
            String::new(),
            "requestor_missing",
        ),
        (
            "est-server",
            "IssueCertificate",
            "issuer",
            "est::".into(),
            "requestor_invalid",
        ),
        (
            "est-server",
            "IssueCertificate",
            "issuer",
            est_256,
            "requestor_invalid",
        ),
        (
            "est-server",
            "IssueCertificate",
            "issuer",
            "est::a\tb".into(),
            "requestor_invalid",
        ),
        (
            "est-server",
            "IssueCertificate",
            "issuer",
            "est".into(),
            "requestor_namespace_mismatch",
        ),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin",
            "admin::".into(),
            "requestor_invalid",
        ),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin",
            "admin::\u{7}".into(),
            "requestor_invalid",
        ),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin",
            admin_256,
            "requestor_invalid",
        ),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin",
            "est::x".into(),
            "requestor_namespace_mismatch",
        ),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin",
            " ".into(),
            "requestor_namespace_mismatch",
        ),
    ];
    for (cn, rpc, role, requestor, reason) in &cases {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        let status = call_rpc(&client, rpc, requestor)
            .await
            .expect_err("requestor must be refused");
        assert_eq!(status.code(), Code::PermissionDenied, "{cn} {requestor:?}");
        assert_eq!(status.message(), "client is not authorised for this call");
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some(*reason), "{cn} {requestor:?}");
        assert_eq!(ev.subject, format!("CN={cn}"));
        assert_eq!(
            ev.resource.as_deref(),
            Some(format!("{SERVICE_PREFIX}{rpc}").as_str())
        );
        let d = ev.details.expect("details");
        assert_eq!(d["role"], *role, "{cn}");
        assert_eq!(d["listener"], LISTENER);
        let expected_ns = cn
            .split('-')
            .next()
            .map(|n| if n == "ops" { "admin" } else { n });
        assert_eq!(d["expected_namespace"], expected_ns.unwrap(), "{cn}");
        let claimed = d["claimed_namespace"].as_str().expect("claimed_namespace");
        assert!(claimed.chars().count() <= 32 * 10, "bounded: {claimed:?}");
        assert!(
            !claimed.chars().any(|c| c.is_control()),
            "escaped: {claimed:?}"
        );
    }
    assert!(
        h.calls.lock().unwrap().is_empty(),
        "inner logic never reached"
    );
}

/// 33. QA / AU-3: accepted requestors are bound verbatim for every role and
/// the bound actor is always the verified peer (EST with a nested `::`,
/// ACME at exactly 255 bytes, admin with `admin::<id>`).
#[tokio::test]
async fn qa_valid_requestors_bind_to_peer_for_each_role() {
    let h = Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let acme_255 = format!("acme::{}", "b".repeat(249));
    assert_eq!(acme_255.len(), 255);
    let cases = [
        (
            "est-server",
            "IssueCertificate",
            "est::tenant::client-9".to_string(),
        ),
        ("acme-server", "IssueCertificate", acme_255),
        (
            "ops-admin",
            "RevokeCertificate",
            "admin::ops-oncall".to_string(),
        ),
    ];
    for (cn, rpc, requestor) in &cases {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        call_rpc(&client, rpc, requestor)
            .await
            .unwrap_or_else(|e| panic!("{cn} {rpc}: {e}"));
        let calls = h.calls.lock().unwrap();
        let seen = calls.last().expect("call reached the stub");
        assert_eq!(
            seen,
            &SeenCall {
                rpc,
                peer: format!("CN={cn}"),
                bound: Some((Some(format!("CN={cn}")), requestor.clone())),
            }
        );
    }
    assert_eq!(h.calls.lock().unwrap().len(), cases.len());
}

// ------------------------------------------------- fix round 1 (SEC-001 ...) ---

fn issue_profile(requestor: &str, profile: &str) -> IssueCertificateRequest {
    IssueCertificateRequest {
        profile_name: profile.to_string(),
        ..issue_request_as(requestor)
    }
}

/// 34. SEC-001 (AC-6(10), CM-7): an issuer may only request its namespace's
/// allowed end-entity profiles. ACME asking for `intermediate_ca` and EST
/// asking for `acme-default` are refused with PERMISSION_DENIED (message
/// names the profile check), never reach issuance, and are audited as
/// `profile_not_permitted` with the requested profile, the namespace and
/// the peer certificate issuer / serial (RFC-001). Allowed profiles work.
#[tokio::test]
async fn issuer_profile_allowlist_enforced_and_audited() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let cases = [
        ("acme-server", "acme::acct-1", "intermediate_ca", false),
        ("acme-server", "acme::acct-1", "tls_server", false),
        ("acme-server", "acme::acct-1", "no-such-profile", false),
        ("est-server", "est::client-1", "acme-default", false),
        ("est-server", "est::client-1", "intermediate_ca", false),
        ("acme-server", "acme::acct-1", "acme-default", true),
        ("est-server", "est::client-1", "tls_server", true),
        ("est-server", "est::client-1", "efs", true),
    ];
    for (cn, requestor, profile, allowed) in cases {
        let leaf = h.client_pki.client(cn);
        let client = CaGrpcClient::new(h.client_config(&leaf))
            .await
            .expect("connect");
        let before = h.calls.lock().unwrap().len();
        let result = CertificateAuthorityServiceClient::new(client.channel())
            .issue_certificate(Request::new(issue_profile(requestor, profile)))
            .await;
        let after = h.calls.lock().unwrap().len();
        if allowed {
            result.unwrap_or_else(|e| panic!("{cn} {profile}: {e}"));
            assert_eq!(after, before + 1, "{cn} {profile} reached");
            continue;
        }
        let status = result.expect_err("profile denied");
        assert_eq!(status.code(), Code::PermissionDenied, "{cn} {profile}");
        assert_eq!(status.message(), PROFILE_DENIED_MESSAGE);
        assert!(status.message().contains("profile"));
        assert_eq!(after, before, "{cn} {profile} must not reach issuance");
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some("profile_not_permitted"));
        assert_eq!(ev.subject, format!("CN={cn}"));
        assert_eq!(ev.resource.as_deref(), Some(ISSUE_PATH));
        let d = ev.details.expect("details");
        assert_eq!(d["requested_profile"], profile);
        assert_eq!(d["namespace"], requestor.split("::").next().unwrap());
        assert_eq!(d["role"], "issuer");
        assert_eq!(d["peer_issuer"], "CN=E2E gRPC Client CA");
        assert!(d["peer_serial"].as_str().is_some_and(|s| !s.is_empty()));
    }
}

/// 35. RFC-002 (IA-3 / IA-9, RFC 5280 §4.1.2.5): a client certificate that
/// expires while its HTTP/2 connection stays open is refused per call
/// (UNAUTHENTICATED, `certificate_not_valid_now`, audited), although the
/// handshake accepted it.
#[tokio::test]
async fn certificate_expiring_on_live_connection_is_refused() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client_expiring_in("acme-server", 3);
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect while valid");
    let mut c = CertificateAuthorityServiceClient::new(client.channel());
    c.get_ca_info(Request::new(GetCaInfoRequest::default()))
        .await
        .expect("valid certificate accepted");
    tokio::time::sleep(Duration::from_millis(4500)).await;
    let status = c
        .get_ca_info(Request::new(GetCaInfoRequest::default()))
        .await
        .expect_err("expired certificate refused on the same connection");
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(status.message(), "client certificate not accepted");
    let ev = h.next_event(AuthAuditKind::AccessDenied).await;
    assert_eq!(ev.reason.as_deref(), Some("certificate_not_valid_now"));
    assert_eq!(ev.subject, "CN=acme-server");
    let d = ev.details.expect("details");
    assert_eq!(d["peer_issuer"], "CN=E2E gRPC Client CA");
}

/// 36. RFC-001 (AU-3): the bound caller carries the peer certificate's
/// issuer and serial, and SEC-002: a requestor id outside printable ASCII is
/// refused over the wire (U+2028, U+061C, U+2060, U+00AD, U+E0001).
#[tokio::test]
async fn bound_caller_has_certificate_and_non_ascii_requestor_denied() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let leaf = h.client_pki.client("acme-server");
    let client = CaGrpcClient::new(h.client_config(&leaf))
        .await
        .expect("connect");
    for c in ['\u{2028}', '\u{061C}', '\u{2060}', '\u{00AD}', '\u{E0001}'] {
        let requestor = format!("acme::acct{c}actor=CN=ops-admin");
        let status = issue_via_as(&client, &requestor)
            .await
            .expect_err("non-ASCII requestor");
        assert_eq!(status.code(), Code::PermissionDenied, "{c:?}");
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(ev.reason.as_deref(), Some("requestor_invalid"), "{c:?}");
    }
    assert!(h.calls.lock().unwrap().is_empty());
}

/// 37. SEC-101 (AC-3, IA-3; FMT_SMR.2): an admin certificate issued by an
/// intermediate under the client trust anchor is refused on every admin RPC
/// (PERMISSION_DENIED, audited `admin_issuer_not_anchor` with the
/// intermediate as `peer_issuer`); an issuer identity under the same
/// intermediate still issues, and an admin directly under the anchor works.
#[tokio::test]
async fn admin_under_intermediate_is_refused() {
    let mut h =
        Harness::start_roles(MATRIX_ROLES, None, &rcgen::PKCS_ECDSA_P256_SHA256, None).await;
    let sub = h.client_pki.sub_ca("E2E gRPC Client Sub CA");
    let with_chain = |leaf: Leaf| Leaf {
        cert_pem: format!("{}{}", leaf.cert_pem, sub.ca_pem()),
        key_pem: leaf.key_pem,
    };

    let admin = with_chain(sub.client("ops-admin"));
    let client = CaGrpcClient::new(h.client_config(&admin))
        .await
        .expect("chain validates to the anchor");
    for rpc in ["RevokeCertificate", "GenerateCrl", "CheckRevocationStatus"] {
        let status = call_rpc(&client, rpc, "")
            .await
            .expect_err("admin under intermediate");
        assert_eq!(status.code(), Code::PermissionDenied, "{rpc}");
        let ev = h.next_event(AuthAuditKind::AccessDenied).await;
        assert_eq!(
            ev.reason.as_deref(),
            Some("admin_issuer_not_anchor"),
            "{rpc}"
        );
        assert_eq!(ev.subject, "CN=ops-admin");
        let d = ev.details.expect("details");
        assert_eq!(d["role"], "admin");
        assert_eq!(d["peer_issuer"], "CN=E2E gRPC Client Sub CA");
    }
    assert!(h.calls.lock().unwrap().is_empty());

    let acme = with_chain(sub.client("acme-server"));
    let client = CaGrpcClient::new(h.client_config(&acme))
        .await
        .expect("connect");
    issue_via_as(&client, "acme::acct-1")
        .await
        .expect("issuer under intermediate");

    let direct = h.client_pki.client("ops-admin");
    let client = CaGrpcClient::new(h.client_config(&direct))
        .await
        .expect("connect");
    call_rpc(&client, "GenerateCrl", "")
        .await
        .expect("admin directly under the anchor");
    assert_eq!(h.calls.lock().unwrap().len(), 2);
}
