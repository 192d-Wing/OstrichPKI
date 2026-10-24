//! TLS server configuration and serving for service binaries
//!
//! Every OstrichPKI service binary serves its REST API through
//! [`serve`]. When a certificate and key are configured the listener speaks
//! TLS 1.3 (optionally requiring client certificates for mTLS); when they are
//! not, the service falls back to plain HTTP with a prominent startup warning
//! so development environments keep working while production misconfiguration
//! is impossible to miss.
//!
//! Configuration is all-or-nothing: providing a certificate without a key (or
//! vice versa) is a hard startup error rather than a silent HTTP fallback.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: SC-8 (Transmission Confidentiality and Integrity) - TLS 1.3
//! - NIST 800-53: SC-13 (Cryptographic Protection) - aws-lc-rs FIPS CryptoProvider
//! - NIST 800-53: SC-23 (Session Authenticity) - TLS 1.3 handshake
//! - NIST 800-53: AC-17 (Remote Access) - optional mTLS client verification
//! - NIST 800-53: CM-6 (Configuration Settings) - fail-fast on partial config
//! - NIAP PP-CA: FTP_TRP.1 (Trusted Path) / FTP_ITC.1 (Inter-TSF channel)
//! - RFC 8446: TLS 1.3

use crate::{Error, Result};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How long in-flight requests get to finish after a shutdown signal.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// TLS listener settings for a service binary.
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// Server certificate chain (PEM, leaf first)
    pub cert_path: PathBuf,
    /// Server private key (PEM: PKCS#8, RFC 5915 SEC1, or PKCS#1)
    pub key_path: PathBuf,
    /// Optional client CA bundle (PEM). When set, clients MUST present a
    /// certificate that chains to one of these CAs (mTLS, NIST AC-17) — unless
    /// [`optional_client_auth`](Self::optional_client_auth) is set.
    pub client_ca_path: Option<PathBuf>,
    /// When `true` (and a client CA is configured), the listener *requests* a
    /// client certificate but does not *require* one: a client that presents a
    /// cert has it verified against the CA, while a client that presents none
    /// still completes the handshake. This enables a single EST port to serve
    /// both certificate-less bootstrap and mTLS re-enrollment (RFC 7030 §3.3),
    /// with the HTTP layer deciding what each route requires. Defaults to
    /// `false` (mandatory mTLS) so inter-service channels stay strict.
    pub optional_client_auth: bool,
}

impl TlsSettings {
    /// Build settings from optional CLI/env values.
    ///
    /// Returns `Ok(None)` when neither cert nor key is configured (plain HTTP
    /// fallback). Returns an error when only one of the pair is configured,
    /// or when a client CA is configured without server TLS: a partially
    /// configured listener must fail at startup, not silently downgrade
    /// (NIST 800-53: CM-6 secure defaults, fail secure).
    pub fn from_options(
        cert_path: Option<String>,
        key_path: Option<String>,
        client_ca_path: Option<String>,
    ) -> Result<Option<Self>> {
        match (cert_path, key_path) {
            (Some(cert), Some(key)) => Ok(Some(Self {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
                client_ca_path: client_ca_path.map(PathBuf::from),
                optional_client_auth: false,
            })),
            (None, None) => {
                if client_ca_path.is_some() {
                    return Err(Error::Config(
                        "TLS client CA configured without server certificate/key".to_string(),
                    ));
                }
                Ok(None)
            }
            (Some(_), None) => Err(Error::Config(
                "TLS certificate configured without private key".to_string(),
            )),
            (None, Some(_)) => Err(Error::Config(
                "TLS private key configured without certificate".to_string(),
            )),
        }
    }

    /// Request-but-do-not-require client certificates (optional mTLS).
    ///
    /// Only meaningful together with a client CA. Lets one listener accept both
    /// certificate-less bootstrap and mTLS-authenticated requests; the HTTP
    /// layer enforces what each route needs. See [`Self::optional_client_auth`].
    pub fn with_optional_client_auth(mut self, optional: bool) -> Self {
        self.optional_client_auth = optional;
        self
    }

    /// Load certificates and build a TLS 1.3-only rustls server config.
    pub fn load(&self) -> Result<ServerConfig> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&self.cert_path)
            .map_err(|e| tls_err("read certificate", &self.cert_path, e))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| tls_err("parse certificate", &self.cert_path, e))?;
        if certs.is_empty() {
            return Err(Error::Config(format!(
                "No certificates found in {}",
                self.cert_path.display()
            )));
        }

        let key = PrivateKeyDer::from_pem_file(&self.key_path)
            .map_err(|e| tls_err("read private key", &self.key_path, e))?;

        // Explicitly select the aws-lc-rs provider (FIPS mode, approved
        // algorithms only: AWS-LC FIPS 4.2.0; CMVP certificate pending
        // confirmation, POAM-2026-10-23-01) so the TLS stack uses the same crypto
        // module as the rest of the project, regardless of which rustls provider
        // features other dependencies enable (SC-13). ring is deliberately NOT used here: it has
        // no FIPS mode, and a NIAP/FIPS deployment must terminate mTLS on the
        // FIPS-mode AWS-LC module. The client-cert verifier below is built from
        // this same provider: `ServerConfig::fips()` does not inspect the
        // verifier, so keeping it on `provider` is what keeps signature
        // verification of client certificates inside the module.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

        // TLS 1.3 only per project policy (NIST 800-53: SC-8, RFC 8446)
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Config(format!("TLS protocol configuration failed: {e}")))?;

        let builder = match &self.client_ca_path {
            Some(ca_path) => {
                let mut roots = RootCertStore::empty();
                for ca in CertificateDer::pem_file_iter(ca_path)
                    .map_err(|e| tls_err("read client CA", ca_path, e))?
                {
                    let ca = ca.map_err(|e| tls_err("parse client CA", ca_path, e))?;
                    roots
                        .add(ca)
                        .map_err(|e| Error::Config(format!("Invalid client CA: {e}")))?;
                }
                let verifier_builder =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
                // Optional mTLS: a presented cert is still verified against the
                // CA, but a client may also present none (bootstrap). Mandatory
                // otherwise (the secure default for inter-service channels).
                let verifier_builder = if self.optional_client_auth {
                    verifier_builder.allow_unauthenticated()
                } else {
                    verifier_builder
                };
                let verifier = verifier_builder
                    .build()
                    .map_err(|e| Error::Config(format!("Client verifier build failed: {e}")))?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };

        let mut config = builder
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("TLS certificate/key rejected: {e}")))?;

        // Defence in depth: `serve_with_config` re-checks, but failing here
        // reports the problem before any listener work starts.
        ensure_fips(&config)?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Refuse a rustls [`ServerConfig`] that does not report FIPS mode.
///
/// Called by [`TlsSettings::load`] and at the top of [`serve_with_config`], so
/// every HTTPS listener — including callers that build their own config, such
/// as the npe-portal ACME mode — fails closed on a non-FIPS TLS stack. Public so
/// a service that builds a config early (before spawning background work) can
/// check it at construction time as well.
///
/// What `ServerConfig::fips()` checks (rustls 0.23.46): `provider.fips() &&
/// require_ems`, where `provider.fips()` requires every cipher suite, every
/// key-exchange group, the signature-verification algorithms, the secure RNG
/// and the key provider to report FIPS mode — each of which, for the aws-lc-rs
/// provider, reduces to AWS-LC's `FIPS_mode()` plus rustls's allowlist
/// (ChaCha20-Poly1305 and plain X25519 are excluded). In AWS-LC FIPS 4.2.0
/// `FIPS_mode()` is a build-time property: it is false if the `fips` feature is
/// missing, a non-FIPS AWS-LC is linked, or AWS-LC was built without
/// `BORINGSSL_FIPS` (including ASAN/sanitizer builds). A power-on self-test
/// failure does not make it false: the module aborts the process in-module
/// (`AWS_LC_FIPS_failure`) rather than reporting a non-FIPS status. Under rustls's
/// FIPS-pending interpretation the ML-KEM hybrid group `X25519MLKEM768`
/// (ML-KEM share first) counts as FIPS. `require_ems` only has an effect while
/// rustls's `tls12` feature is enabled; it is still part of the predicate.
///
/// It does NOT check protocol versions: the TLS 1.3-only floor is enforced
/// separately by `with_protocol_versions(&[&TLS13])` (tested by
/// `server_rejects_tls12_only_client`). Nor does it inspect a custom
/// client-certificate verifier; that must be built from the same provider.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-13 (Cryptographic Protection) - approved algorithms only,
///   FIPS-mode AWS-LC FIPS 4.2.0 (CMVP certificate pending confirmation,
///   POAM-2026-10-23-01)
/// - NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
/// - NIST 800-53: CM-6 (Configuration Settings) - no toggle; secure default only
/// - NIST 800-53: SC-24 (Fail in Known State) - refuse to serve, never degrade
/// - NIAP PP-CA: FCS_COP.1, FCS_TLSS_EXT.1, FPT_FLS.1
// POAM: POAM-2026-10-23-05 - this guard covers rustls ServerConfigs served via
// `serve`/`serve_with_config` only. Still uncovered: plain-HTTP mode (no cert
// configured) and the absence of a process-level FIPS gate at startup; rustls
// ClientConfigs (web-ui and npe-portal backend clients, the ACME tls-alpn-01
// validator); tonic gRPC: the CA gRPC server is plaintext (no ServerTlsConfig,
// ca-server main.rs) and gRPC clients use the `tls-ring` provider
// (POAM-2026-10-23-08); ca-server spawns its gRPC listener before the HTTPS
// guard runs; no `ostrich-audit` event is emitted on refusal (error log only);
// and the project's crypto KATs do not run through AWS-LC.
pub fn ensure_fips(config: &ServerConfig) -> Result<()> {
    if config.fips() {
        return Ok(());
    }
    // NIST 800-53: SC-24 / AU-2 - log the refusal at the point it happens.
    tracing::error!(
        require_ems = config.require_ems,
        provider_fips = config.crypto_provider().fips(),
        "Refusing to serve TLS: ServerConfig is not in FIPS mode"
    );
    Err(Error::Config(
        "TLS configuration is not in FIPS mode; refusing to serve. Possible causes: \
         the rustls `fips` feature is missing, a non-FIPS AWS-LC is linked, \
         AWS-LC was built without BORINGSSL_FIPS (incl. ASAN/sanitizer builds), \
         or a non-approved suite/group or disabled extended master secret was \
         configured."
            .to_string(),
    ))
}

/// Version of the linked AWS-LC library (e.g. `"4.2.0"` for the FIPS 4.2.0
/// module), for startup logs. Identifies the build only; it does not by itself
/// establish FIPS mode or CMVP status (see [`ensure_fips`]).
pub fn aws_lc_module_version() -> &'static str {
    aws_lc_rs::awslc_version()
}

/// Request extension carrying the verified TLS client (peer) certificate —
/// the leaf, DER-encoded. `Some` only on an mTLS connection where the client
/// presented a certificate (which, when a client CA is configured, the rustls
/// `WebPkiClientVerifier` has already verified chains to it); `None` on plain
/// TLS or HTTP. Handlers read this to authenticate by certificate (NIST AC-17 /
/// IA-2; NIAP FIA_UAU.1 / FTP_ITC.1).
#[derive(Clone, Debug)]
pub struct PeerCertificate(pub Option<Vec<u8>>);

/// axum-server `Accept` wrapper that, after the rustls handshake completes,
/// captures the verified client certificate and injects it into every request
/// on that connection as a [`PeerCertificate`] extension.
#[derive(Clone)]
struct MtlsAcceptor(axum_server::tls_rustls::RustlsAcceptor);

impl<I, S> axum_server::accept::Accept<I, S> for MtlsAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = InjectPeerCert<S>;
    type Future = std::pin::Pin<
        Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.0.clone();
        Box::pin(async move {
            let (tls_stream, service) =
                axum_server::accept::Accept::accept(&acceptor, stream, service).await?;
            // peer_certificates() is populated once the handshake (awaited inside
            // the inner acceptor) has completed.
            let cert = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| c.as_ref().to_vec());
            Ok((
                tls_stream,
                InjectPeerCert {
                    inner: service,
                    cert: PeerCertificate(cert),
                },
            ))
        })
    }
}

/// Per-connection tower service that inserts the connection's
/// [`PeerCertificate`] into each request's extensions.
#[derive(Clone)]
struct InjectPeerCert<S> {
    inner: S,
    cert: PeerCertificate,
}

impl<S, B> tower::Service<axum::http::Request<B>> for InjectPeerCert<S>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.cert.clone());
        self.inner.call(req)
    }
}

/// Serve an axum router, with TLS when configured and plain HTTP otherwise.
///
/// The `shutdown` future triggers a graceful shutdown (in-flight requests get
/// [`GRACEFUL_SHUTDOWN_TIMEOUT`] to complete), matching the previous
/// `axum::serve(...).with_graceful_shutdown(...)` behavior.
pub async fn serve(
    addr: SocketAddr,
    app: axum::Router,
    tls: Option<&TlsSettings>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    match tls {
        Some(settings) => {
            let config = settings.load()?;
            tracing::info!(
                %addr,
                cert = %settings.cert_path.display(),
                mtls = settings.client_ca_path.is_some(),
                optional_mtls = settings.optional_client_auth,
                fips = true,
                aws_lc_version = aws_lc_module_version(),
                "Serving HTTPS (TLS 1.3)"
            );
            serve_with_config(addr, app, Arc::new(config), shutdown).await
        }
        None => {
            // NIST 800-53: SC-8 - plain HTTP violates transmission
            // confidentiality; permitted only for development. The warning is
            // emitted at startup so production misconfiguration is visible.
            tracing::warn!(
                %addr,
                "TLS NOT CONFIGURED - serving plain HTTP. Set TLS_CERT_FILE and \
                 TLS_KEY_FILE for production use (NIST 800-53: SC-8)."
            );
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown.await;
                shutdown_handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
            });
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .map_err(|e| Error::Config(format!("HTTP server error: {e}")))
        }
    }
}

/// Serve `app` over HTTPS (TLS 1.3) with a pre-built rustls [`ServerConfig`],
/// surfacing the verified client certificate to handlers via the
/// [`PeerCertificate`] extension (the same mTLS acceptor [`serve`] uses).
///
/// The config may use a dynamic certificate resolver (`with_cert_resolver`): the
/// resolver is consulted per TLS handshake, so a caller that swaps the resolved
/// certificate (e.g. ACME auto-renewal) takes effect on new connections without
/// a restart. NIST 800-53: SC-8.
///
/// Fails closed: the config is checked with [`ensure_fips`] before anything is
/// bound, so a caller-built config (e.g. npe-portal ACME mode) cannot serve on a
/// non-FIPS TLS stack. NIST 800-53: SC-13, SC-24.
pub async fn serve_with_config(
    addr: SocketAddr,
    app: axum::Router,
    config: Arc<ServerConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    ensure_fips(&config)?;

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
    });

    // Custom acceptor surfaces the verified client certificate to handlers via
    // the PeerCertificate request extension (mTLS auth).
    let acceptor = MtlsAcceptor(axum_server::tls_rustls::RustlsAcceptor::new(
        axum_server::tls_rustls::RustlsConfig::from_config(config),
    ));
    axum_server::bind(addr)
        .handle(handle)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Config(format!("HTTPS server error: {e}")))
}

fn tls_err(action: &str, path: &std::path::Path, err: impl std::fmt::Display) -> Error {
    Error::Config(format!("Failed to {action} {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_options_none_when_unconfigured() {
        assert!(
            TlsSettings::from_options(None, None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn from_options_some_when_fully_configured() {
        let settings =
            TlsSettings::from_options(Some("cert.pem".into()), Some("key.pem".into()), None)
                .unwrap()
                .unwrap();
        assert_eq!(settings.cert_path, PathBuf::from("cert.pem"));
        assert!(settings.client_ca_path.is_none());
    }

    #[test]
    fn from_options_rejects_partial_config() {
        assert!(TlsSettings::from_options(Some("cert.pem".into()), None, None).is_err());
        assert!(TlsSettings::from_options(None, Some("key.pem".into()), None).is_err());
        // Client CA without server TLS is also a misconfiguration
        assert!(TlsSettings::from_options(None, None, Some("ca.pem".into())).is_err());
    }

    #[test]
    fn load_fails_on_missing_files() {
        let settings = TlsSettings {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
            client_ca_path: None,
            optional_client_auth: false,
        };
        assert!(settings.load().is_err());
    }

    #[test]
    fn optional_client_auth_defaults_off_and_is_settable() {
        let settings =
            TlsSettings::from_options(Some("cert.pem".into()), Some("key.pem".into()), None)
                .unwrap()
                .unwrap();
        assert!(!settings.optional_client_auth);
        assert!(
            settings
                .with_optional_client_auth(true)
                .optional_client_auth
        );
    }

    // --- QA: rustls 0.23.46 / rustls-webpki 0.103.16 / AWS-LC FIPS 4.2.0 ---
    // NIST 800-53: SC-8, SC-13, AC-17, IA-2; RFC 8446; RFC 5280 §6.

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, ServerConnection};

    struct Pki {
        ca: CertifiedIssuer<'static, KeyPair>,
    }

    impl Pki {
        fn new(cn: &str) -> Self {
            let mut p = CertificateParams::new(Vec::<String>::new()).expect("ca params");
            p.distinguished_name.push(DnType::CommonName, cn);
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let key = KeyPair::generate().expect("ca key");
            Self {
                ca: CertifiedIssuer::self_signed(p, key).expect("ca cert"),
            }
        }

        /// Issue a leaf; returns (cert PEM, key PEM).
        fn leaf(&self, san: &str, eku: ExtendedKeyUsagePurpose) -> (String, String) {
            let mut p = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
            p.distinguished_name.push(DnType::CommonName, san);
            p.extended_key_usages = vec![eku];
            let key = KeyPair::generate().expect("leaf key");
            let cert = p.signed_by(&key, &self.ca).expect("leaf cert");
            (cert.pem(), key.serialize_pem())
        }
    }

    fn write_tmp(tag: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ostrich-tls-qa-{}-{tag}-{:?}.pem",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).expect("write temp pem");
        path
    }

    fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .expect("parse pem certs")
    }

    /// Drive an in-memory TLS handshake; Err carries the first rustls error.
    fn handshake(
        server: ServerConfig,
        client: ClientConfig,
    ) -> std::result::Result<ServerConnection, rustls::Error> {
        let mut s = ServerConnection::new(Arc::new(server))?;
        let mut c = ClientConnection::new(
            Arc::new(client),
            ServerName::try_from("localhost").expect("name"),
        )?;
        for _ in 0..20 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).expect("client write");
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd).expect("server read");
            }
            s.process_new_packets()?;
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).expect("server write");
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                c.read_tls(&mut rd).expect("client read");
            }
            c.process_new_packets()?;
            if !s.is_handshaking() && !c.is_handshaking() {
                return Ok(s);
            }
        }
        panic!("handshake did not complete");
    }

    fn client_config(
        trust_pem: &str,
        client_auth: Option<(&str, &str)>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        for c in pem_certs(trust_pem) {
            roots.add(c).expect("add root");
        }
        let b = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .expect("client versions")
        .with_root_certificates(roots);
        match client_auth {
            Some((cert, key)) => b
                .with_client_auth_cert(
                    pem_certs(cert),
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).expect("client key"),
                )
                .expect("client auth cert"),
            None => b.with_no_client_auth(),
        }
    }

    /// Server PKI + mandatory-mTLS settings (client CA = `client_pki`).
    fn mtls_settings(server_pki: &Pki, client_pki: &Pki, tag: &str) -> TlsSettings {
        let (cert, key) = server_pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        TlsSettings {
            cert_path: write_tmp(&format!("{tag}-srv-cert"), &cert),
            key_path: write_tmp(&format!("{tag}-srv-key"), &key),
            client_ca_path: Some(write_tmp(&format!("{tag}-cli-ca"), &client_pki.ca.pem())),
            optional_client_auth: false,
        }
    }

    /// `load()` yields a config backed by the FIPS AWS-LC module (SC-13).
    #[test]
    fn load_builds_fips_config_with_alpn() {
        let pki = Pki::new("QA Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let settings = TlsSettings {
            cert_path: write_tmp("fips-cert", &cert),
            key_path: write_tmp("fips-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        let config = settings.load().expect("load tls config");
        assert!(
            config.fips(),
            "ServerConfig must report FIPS mode (aws-lc-rs fips provider)"
        );
        assert!(rustls::crypto::aws_lc_rs::default_provider().fips());
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    /// QA (SC-13 fail-closed): the exact predicate [`ensure_fips`] gates on
    /// (`ServerConfig::fips()`) flips to false when a load()-built config has
    /// extended master secret disabled, so the guard is not vacuously true.
    /// `load()` itself hardcodes the FIPS provider and leaves `require_ems` at
    /// the builder default; the `Err` branch is exercised through
    /// `ensure_fips` directly (see `ensure_fips_rejects_non_fips_server_configs`).
    #[test]
    fn fips_predicate_false_when_extended_master_secret_not_required() {
        let pki = Pki::new("QA Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let settings = TlsSettings {
            cert_path: write_tmp("ems-cert", &cert),
            key_path: write_tmp("ems-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        let mut config = settings.load().expect("load tls config");
        assert!(config.require_ems, "FIPS builder must default require_ems");
        assert!(config.fips());
        config.require_ems = false;
        assert!(
            !config.fips(),
            "ServerConfig::fips() must be false without extended master secret"
        );
    }

    /// QA (SC-13 fail-closed): a server config built exactly like `load()` but
    /// with a non-FIPS key-exchange group (X25519, not SP 800-56A approved)
    /// reports `fips() == false`, i.e. [`ensure_fips`] (called from `load()`
    /// and `serve_with_config`) would reject it.
    #[test]
    fn fips_predicate_false_with_non_fips_kx_group() {
        let pki = Pki::new("QA Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        assert!(provider.fips(), "baseline provider must be FIPS");
        provider
            .kx_groups
            .push(rustls::crypto::aws_lc_rs::kx_group::X25519);
        assert!(!provider.fips(), "X25519 must not be FIPS-approved");
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(
                pem_certs(&cert),
                PrivateKeyDer::from_pem_slice(key.as_bytes()).expect("key"),
            )
            .expect("single cert");
        assert!(
            !config.fips(),
            "ServerConfig with a non-FIPS kx group must not report FIPS"
        );
    }

    /// Build a ServerConfig on `provider` exactly like `load()` (TLS 1.3 only,
    /// no client auth) without going through `load()`'s own guard.
    fn server_config_with_provider(provider: rustls::crypto::CryptoProvider) -> ServerConfig {
        let pki = Pki::new("Guard Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(
                pem_certs(&cert),
                PrivateKeyDer::from_pem_slice(key.as_bytes()).expect("key"),
            )
            .expect("single cert")
    }

    /// SC-13 / SC-24 fail-closed: `ensure_fips` refuses a config whose
    /// provider offers a non-approved group (plain X25519) and one with
    /// extended master secret disabled, with a `Config` error.
    #[test]
    fn ensure_fips_rejects_non_fips_server_configs() {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider
            .kx_groups
            .push(rustls::crypto::aws_lc_rs::kx_group::X25519);
        let non_fips_kx = server_config_with_provider(provider);
        assert!(
            matches!(ensure_fips(&non_fips_kx), Err(Error::Config(_))),
            "non-FIPS kx group must be refused"
        );

        let mut no_ems = server_config_with_provider(rustls::crypto::aws_lc_rs::default_provider());
        assert!(ensure_fips(&no_ems).is_ok(), "baseline must pass");
        no_ems.require_ems = false;
        assert!(
            matches!(ensure_fips(&no_ems), Err(Error::Config(_))),
            "require_ems = false must be refused"
        );
    }

    /// The guard accepts the config `load()` builds (no false refusals).
    #[test]
    fn ensure_fips_accepts_loaded_config() {
        let pki = Pki::new("QA Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let settings = TlsSettings {
            cert_path: write_tmp("guard-ok-cert", &cert),
            key_path: write_tmp("guard-ok-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        let config = settings.load().expect("load tls config");
        assert!(ensure_fips(&config).is_ok());
    }

    /// `serve_with_config` (the path npe-portal ACME mode uses) refuses a
    /// non-FIPS config before binding, instead of serving it.
    #[tokio::test]
    async fn serve_with_config_refuses_non_fips_config() {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider
            .kx_groups
            .push(rustls::crypto::aws_lc_rs::kx_group::X25519);
        let config = Arc::new(server_config_with_provider(provider));
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            serve_with_config(addr, axum::Router::new(), config, std::future::pending()),
        )
        .await
        .expect("serve_with_config must return immediately on a non-FIPS config");
        assert!(matches!(res, Err(Error::Config(_))), "got {res:?}");
    }

    /// QA (SC-13 / FIPS 203 posture): the FIPS-mode server config offers only
    /// approved groups — no bare X25519 — and keeps the ML-KEM hybrid
    /// (X25519MLKEM768, ML-KEM share first per SP 800-56C ordering).
    #[test]
    fn fips_server_config_kx_groups_exclude_x25519_keep_mlkem_hybrid() {
        let pki = Pki::new("QA Server CA");
        let (cert, key) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let settings = TlsSettings {
            cert_path: write_tmp("kx-cert", &cert),
            key_path: write_tmp("kx-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        let config = settings.load().expect("load tls config");
        let groups: Vec<rustls::NamedGroup> = config
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert!(
            !groups.contains(&rustls::NamedGroup::X25519),
            "groups: {groups:?}"
        );
        assert!(
            groups.contains(&rustls::NamedGroup::X25519MLKEM768),
            "groups: {groups:?}"
        );
        assert!(
            config.crypto_provider().kx_groups.iter().all(|g| g.fips()),
            "groups: {groups:?}"
        );
    }

    /// A client chaining to the configured client CA completes a TLS 1.3
    /// mTLS handshake and the server sees its certificate (AC-17, IA-2).
    #[test]
    fn mtls_handshake_accepts_trusted_client() {
        let srv = Pki::new("QA Server CA");
        let cli = Pki::new("QA Client CA");
        let config = mtls_settings(&srv, &cli, "ok").load().expect("load");
        let (c_cert, c_key) = cli.leaf("client.example", ExtendedKeyUsagePurpose::ClientAuth);
        let conn = handshake(
            config,
            client_config(
                &srv.ca.pem(),
                Some((&c_cert, &c_key)),
                &[&rustls::version::TLS13],
            ),
        )
        .expect("trusted client handshake");
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let peer = conn.peer_certificates().expect("peer cert present");
        assert_eq!(peer[0].as_ref(), pem_certs(&c_cert)[0].as_ref());
    }

    /// A client certificate from an untrusted CA is rejected (fail secure).
    #[test]
    fn mtls_handshake_rejects_untrusted_client() {
        let srv = Pki::new("QA Server CA");
        let cli = Pki::new("QA Client CA");
        let rogue = Pki::new("QA Rogue CA");
        let config = mtls_settings(&srv, &cli, "rogue").load().expect("load");
        let (c_cert, c_key) = rogue.leaf("client.example", ExtendedKeyUsagePurpose::ClientAuth);
        let err = handshake(
            config,
            client_config(
                &srv.ca.pem(),
                Some((&c_cert, &c_key)),
                &[&rustls::version::TLS13],
            ),
        )
        .expect_err("untrusted client must be rejected");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "unexpected error: {err:?}"
        );
    }

    /// Mandatory mTLS: a client presenting no certificate is rejected.
    #[test]
    fn mtls_handshake_rejects_missing_client_cert() {
        let srv = Pki::new("QA Server CA");
        let cli = Pki::new("QA Client CA");
        let config = mtls_settings(&srv, &cli, "nocert").load().expect("load");
        let err = handshake(
            config,
            client_config(&srv.ca.pem(), None, &[&rustls::version::TLS13]),
        )
        .expect_err("missing client cert must be rejected");
        assert!(
            matches!(err, rustls::Error::NoCertificatesPresented),
            "unexpected error: {err:?}"
        );
    }

    /// Optional client auth (bootstrap): no certificate is allowed, but a
    /// presented untrusted certificate is still rejected.
    #[test]
    fn optional_mtls_allows_anonymous_but_rejects_untrusted() {
        let srv = Pki::new("QA Server CA");
        let cli = Pki::new("QA Client CA");
        let rogue = Pki::new("QA Rogue CA");
        let settings = mtls_settings(&srv, &cli, "opt").with_optional_client_auth(true);
        let conn = handshake(
            settings.load().expect("load"),
            client_config(&srv.ca.pem(), None, &[&rustls::version::TLS13]),
        )
        .expect("anonymous client allowed");
        assert!(conn.peer_certificates().is_none());

        let (c_cert, c_key) = rogue.leaf("client.example", ExtendedKeyUsagePurpose::ClientAuth);
        let err = handshake(
            settings.load().expect("load"),
            client_config(
                &srv.ca.pem(),
                Some((&c_cert, &c_key)),
                &[&rustls::version::TLS13],
            ),
        )
        .expect_err("untrusted presented cert must be rejected");
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)));
    }

    /// TLS 1.3-only policy: a TLS 1.2-only client cannot connect (SC-8).
    #[test]
    fn server_rejects_tls12_only_client() {
        let srv = Pki::new("QA Server CA");
        let (cert, key) = srv.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let settings = TlsSettings {
            cert_path: write_tmp("tls12-cert", &cert),
            key_path: write_tmp("tls12-key", &key),
            client_ca_path: None,
            optional_client_auth: false,
        };
        let res = handshake(
            settings.load().expect("load"),
            client_config(&srv.ca.pem(), None, &[&rustls::version::TLS12]),
        );
        assert!(res.is_err(), "TLS 1.2-only client must not connect");
    }

    /// A client certificate without the clientAuth EKU (serverAuth only) is
    /// rejected by the webpki client verifier (RFC 5280 §4.2.1.12).
    #[test]
    fn mtls_handshake_rejects_client_cert_with_server_only_eku() {
        let srv = Pki::new("QA Server CA");
        let cli = Pki::new("QA Client CA");
        let config = mtls_settings(&srv, &cli, "eku").load().expect("load");
        let (c_cert, c_key) = cli.leaf("client.example", ExtendedKeyUsagePurpose::ServerAuth);
        let err = handshake(
            config,
            client_config(
                &srv.ca.pem(),
                Some((&c_cert, &c_key)),
                &[&rustls::version::TLS13],
            ),
        )
        .expect_err("wrong-EKU client must be rejected");
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)));
    }
}
