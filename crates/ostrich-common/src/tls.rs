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
//! - NIST 800-53: SC-13 (Cryptographic Protection) - ring CryptoProvider
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
    /// certificate that chains to one of these CAs (mTLS, NIST AC-17).
    pub client_ca_path: Option<PathBuf>,
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

    /// Load certificates and build a TLS 1.3-only rustls server config.
    pub fn load(&self) -> Result<ServerConfig> {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(&self.cert_path)
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

        // Explicitly select the ring provider so the TLS stack uses the same
        // crypto library as the rest of the project regardless of which
        // rustls provider features other dependencies enable (SC-13).
        let provider = Arc::new(rustls::crypto::ring::default_provider());

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
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()
                .map_err(|e| Error::Config(format!("Client verifier build failed: {e}")))?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };

        let mut config = builder
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("TLS certificate/key rejected: {e}")))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
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
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
    });

    match tls {
        Some(settings) => {
            let config = settings.load()?;
            tracing::info!(
                %addr,
                cert = %settings.cert_path.display(),
                mtls = settings.client_ca_path.is_some(),
                "Serving HTTPS (TLS 1.3)"
            );
            // Custom acceptor surfaces the verified client certificate to
            // handlers via the PeerCertificate request extension (mTLS auth).
            let acceptor = MtlsAcceptor(axum_server::tls_rustls::RustlsAcceptor::new(
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            ));
            axum_server::bind(addr)
                .handle(handle)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await
                .map_err(|e| Error::Config(format!("HTTPS server error: {e}")))
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
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .map_err(|e| Error::Config(format!("HTTP server error: {e}")))
        }
    }
}

fn tls_err(action: &str, path: &std::path::Path, err: impl std::fmt::Display) -> Error {
    Error::Config(format!("Failed to {action} {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_options_none_when_unconfigured() {
        assert!(TlsSettings::from_options(None, None, None)
            .unwrap()
            .is_none());
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
        };
        assert!(settings.load().is_err());
    }
}
