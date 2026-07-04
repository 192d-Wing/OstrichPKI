//! HTTP client for proxying to the CA/EST backends.
//!
//! When backend mTLS material is configured, the portal dials the backends over
//! mTLS and presents its client certificate, so the CA/EST can verify the portal
//! and trust the forwarded `X-Npe-*` identity (the identity bridge). The
//! connector is built `https_or_http`, so without mTLS material configured it
//! still dials plain `http://` backends for development.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (transmission confidentiality), AC-17 (mTLS),
//!   IA-2 (the portal authenticates itself to the backend)

use anyhow::{Context, Result};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::Arc;

use super::config::BackendConfig;

/// Pooled HTTP(S) client used by the backend proxy.
pub type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, axum::body::Body>;

/// Build the backend client. Uses mTLS when client cert + key + CA are all
/// configured; otherwise a plain-HTTP-capable client (development).
///
/// Backend mTLS is all-or-nothing: configuring some but not all of
/// `mtls_client_cert` / `mtls_client_key` / `mtls_ca_cert` is a hard error, so a
/// half-configured deployment fails fast at startup rather than silently dialing
/// without a client certificate (which would break the identity bridge in a
/// confusing way). Mirrors `TlsSettings::from_options`' fail-fast policy.
pub fn build(backend: &BackendConfig) -> Result<HttpClient> {
    let set_count = [
        backend.mtls_client_cert.is_some(),
        backend.mtls_client_key.is_some(),
        backend.mtls_ca_cert.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if set_count != 0 && set_count != 3 {
        anyhow::bail!(
            "partial backend mTLS configuration: set all of mtlsClientCert, mtlsClientKey, \
             and mtlsCaCert, or none (NIST 800-53: CM-6 fail-fast)"
        );
    }
    // SC-8: with mTLS configured, a plaintext backend URL would send the
    // forwarded X-Npe-* identity in the clear; warn loudly on that misconfig.
    if set_count == 3 {
        for (name, url) in [("caUrl", &backend.ca_url), ("estUrl", &backend.est_url)] {
            if url.starts_with("http://") {
                tracing::warn!(
                    backend = name,
                    url = %url,
                    "backend mTLS is configured but the URL is plaintext http://; the \
                     forwarded identity would not be protected (NIST 800-53: SC-8)"
                );
            }
        }
    }
    // Explicitly select the aws-lc-rs (FIPS) provider, matching the rest of the
    // project's TLS stack (NIST 800-53: SC-13).
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS protocol configuration failed")?;

    // Trust roots for verifying the backend server certificates.
    let mut roots = RootCertStore::empty();
    if let Some(ca_path) = &backend.mtls_ca_cert {
        for cert in CertificateDer::pem_file_iter(ca_path)
            .with_context(|| format!("read backend CA bundle {ca_path}"))?
        {
            let cert = cert.with_context(|| format!("parse backend CA bundle {ca_path}"))?;
            roots.add(cert).context("add backend CA to trust store")?;
        }
    }

    let client_config = match (
        &backend.mtls_client_cert,
        &backend.mtls_client_key,
        &backend.mtls_ca_cert,
    ) {
        (Some(cert_path), Some(key_path), Some(_)) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
                .with_context(|| format!("read portal client cert {cert_path}"))?
                .collect::<std::result::Result<_, _>>()
                .with_context(|| format!("parse portal client cert {cert_path}"))?;
            let key = PrivateKeyDer::from_pem_file(key_path)
                .with_context(|| format!("read portal client key {key_path}"))?;
            tracing::info!("Backend proxy: mTLS enabled (presenting portal client certificate)");
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)
                .context("portal client certificate/key rejected")?
        }
        _ => {
            tracing::warn!(
                "Backend proxy: no mTLS material configured; dialing backends without a client \
                 certificate. The identity bridge requires backend mTLS in production \
                 (NIST 800-53: AC-17)."
            );
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_or_http()
        .enable_http1()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
}
