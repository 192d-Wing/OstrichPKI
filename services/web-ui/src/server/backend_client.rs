//! Pooled HTTP(S) client for reaching the backend services (CA, EST, …).
//!
//! The CA's REST API serves TLS 1.3 (`optional_mtls`), so web-ui must dial it
//! over `https://` and trust the CA's internal server certificate. The
//! connector is built `https_or_http`, so backends still reachable over plain
//! `http://` (dev, or the OCSP/EST responders) continue to work through the
//! same client.
//!
//! web-ui authenticates admins with a session-bound bearer token that the CA
//! verifies independently, so a client certificate is NOT required against an
//! `optional_mtls` CA — trust of the CA's server certificate is sufficient. A
//! client certificate can still be supplied for a CA that mandates mTLS.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (transmission confidentiality) - TLS to the backend
//! - NIST 800-53: SC-13 (cryptographic protection) - aws-lc-rs/FIPS provider
//! - NIST 800-53: AC-17 (remote access) - optional client-certificate mTLS

use anyhow::{Context, Result};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::Arc;

use super::config::BackendConfig;

/// Pooled HTTP(S) client used by the proxy and the auth handlers. The body type
/// is `axum::body::Body` so proxied request bodies pass straight through.
pub type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, axum::body::Body>;

/// Build the backend client.
///
/// Trust roots for verifying backend server certificates come from
/// `tls_ca_cert` when set (the CA's issuing/intermediate certificate); the
/// platform roots are used otherwise. A client certificate is presented only
/// when both `tls_client_cert` and `tls_client_key` are configured — supplying
/// exactly one is a hard error so a half-configured deployment fails fast at
/// startup rather than silently dialing without a client certificate
/// (NIST 800-53: CM-6 fail-fast), mirroring `TlsSettings::from_options`.
pub fn build(backend: &BackendConfig) -> Result<HttpClient> {
    match (&backend.tls_client_cert, &backend.tls_client_key) {
        (Some(_), None) | (None, Some(_)) => anyhow::bail!(
            "partial backend mTLS configuration: set both tlsClientCert and tlsClientKey, \
             or neither (NIST 800-53: CM-6 fail-fast)"
        ),
        _ => {}
    }

    // Explicitly select the aws-lc-rs (FIPS) provider, matching the rest of the
    // project's TLS stack (NIST 800-53: SC-13).
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS protocol configuration failed")?;

    // Trust roots for verifying the backend server certificates. rustls accepts
    // a server leaf directly signed by any configured trust anchor, so the CA's
    // intermediate certificate is sufficient here.
    let mut roots = RootCertStore::empty();
    if let Some(ca_path) = &backend.tls_ca_cert {
        let mut added = 0usize;
        for cert in CertificateDer::pem_file_iter(ca_path)
            .with_context(|| format!("read backend CA bundle {ca_path}"))?
        {
            let cert = cert.with_context(|| format!("parse backend CA bundle {ca_path}"))?;
            roots.add(cert).context("add backend CA to trust store")?;
            added += 1;
        }
        tracing::info!(ca_path = %ca_path, certs = added, "Backend client: loaded CA trust anchors");
    } else {
        tracing::warn!(
            "Backend client: no tlsCaCert configured; only platform roots are trusted. \
             An https:// CA URL with an internal certificate will fail to verify."
        );
    }

    let client_config = match (&backend.tls_client_cert, &backend.tls_client_key) {
        (Some(cert_path), Some(key_path)) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
                .with_context(|| format!("read web-ui client cert {cert_path}"))?
                .collect::<std::result::Result<_, _>>()
                .with_context(|| format!("parse web-ui client cert {cert_path}"))?;
            let key = PrivateKeyDer::from_pem_file(key_path)
                .with_context(|| format!("read web-ui client key {key_path}"))?;
            tracing::info!("Backend client: mTLS enabled (presenting web-ui client certificate)");
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)
                .context("web-ui client certificate/key rejected")?
        }
        _ => builder.with_root_certificates(roots).with_no_client_auth(),
    };

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_or_http()
        .enable_http1()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
}
