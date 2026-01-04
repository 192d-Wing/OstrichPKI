//! mTLS client certificate handling for EST
//!
//! RFC 7030 §3.2 - Mutual TLS authentication
//! NIST 800-53: IA-2 - Identification and authentication

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ostrich_db::DatabasePool;
use x509_parser::prelude::*;

/// Client certificate extracted from TLS connection
///
/// RFC 7030 §3.2.3 - EST server authenticates client via certificate
#[derive(Debug, Clone)]
pub struct MtlsClientCert {
    /// DER-encoded client certificate
    pub certificate_der: Vec<u8>,
    /// Subject distinguished name
    pub subject_dn: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Issuer distinguished name
    pub issuer_dn: String,
    /// Certificate validity period start
    pub not_before: DateTime<Utc>,
    /// Certificate validity period end
    pub not_after: DateTime<Utc>,
    /// Client identifier (SHA-256 of certificate DER)
    pub client_id: String,
}

impl MtlsClientCert {
    /// Parse client certificate from DER bytes
    ///
    /// RFC 5280 §4.1 - Basic certificate fields
    /// NIST 800-53: SI-10 - Information input validation
    pub fn from_der(certificate_der: Vec<u8>) -> Result<Self> {
        // Parse certificate
        let (_, cert) = X509Certificate::from_der(&certificate_der)
            .map_err(|e| Error::InvalidCsr(format!("Invalid client certificate: {}", e)))?;

        // Validate certificate is not expired
        let now = Utc::now();
        let not_before = cert.validity().not_before.to_datetime().unix_timestamp();
        let not_after = cert.validity().not_after.to_datetime().unix_timestamp();

        let not_before_dt = DateTime::from_timestamp(not_before, 0)
            .ok_or_else(|| Error::InvalidCsr("Invalid not_before timestamp".to_string()))?;
        let not_after_dt = DateTime::from_timestamp(not_after, 0)
            .ok_or_else(|| Error::InvalidCsr("Invalid not_after timestamp".to_string()))?;

        if now < not_before_dt || now > not_after_dt {
            return Err(Error::Forbidden(
                "Client certificate expired or not yet valid".to_string(),
            ));
        }

        // Extract subject DN
        let subject_dn = cert.subject().to_string();
        let serial_number = cert.serial.to_string();
        let issuer_dn = cert.issuer().to_string();

        // Compute client identifier (SHA-256 of DER)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&certificate_der);
        let client_id = format!("{:x}", hasher.finalize());

        Ok(MtlsClientCert {
            certificate_der,
            subject_dn,
            serial_number,
            issuer_dn,
            not_before: not_before_dt,
            not_after: not_after_dt,
            client_id,
        })
    }
}

/// Axum extractor for client certificate from mTLS connection
///
/// This extractor retrieves the client certificate presented during TLS handshake.
/// It requires proper TLS server configuration with client authentication enabled.
///
/// # Usage
/// ```ignore
/// use crate::mtls::ClientCertExtractor;
///
/// async fn handler(
///     ClientCertExtractor(cert): ClientCertExtractor,
/// ) -> Result<Response> {
///     // Use cert.subject_dn, cert.serial_number, etc.
///     Ok(Response::new("Authenticated"))
/// }
/// ```
///
/// # Security Notes
/// - Returns 401 Unauthorized if no client certificate is present
/// - Returns 403 Forbidden if certificate is expired or invalid
/// - Always validate certificate against authorized clients database
///
/// # TLS Server Configuration Required
///
/// The EST server must be configured with rustls to require client certificates:
///
/// ```ignore
/// use rustls::{ServerConfig, RootCertStore};
/// use rustls_pemfile::{certs, private_key};
/// use tokio_rustls::TlsAcceptor;
/// use std::sync::Arc;
///
/// // Load CA certificate for client validation
/// let ca_cert_pem = std::fs::read("ca.pem")?;
/// let ca_certs = certs(&mut ca_cert_pem.as_slice())?;
///
/// let mut root_store = RootCertStore::empty();
/// for cert in ca_certs {
///     root_store.add(cert)?;
/// }
///
/// // Load server certificate and private key
/// let server_cert_pem = std::fs::read("server.pem")?;
/// let server_certs = certs(&mut server_cert_pem.as_slice())?;
///
/// let server_key_pem = std::fs::read("server-key.pem")?;
/// let server_key = private_key(&mut server_key_pem.as_slice())?;
///
/// // Create TLS config with client authentication
/// let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
///     .build()?;
///
/// let tls_config = ServerConfig::builder()
///     .with_client_cert_verifier(client_verifier)
///     .with_single_cert(server_certs, server_key)?;
///
/// let acceptor = TlsAcceptor::from(Arc::new(tls_config));
/// ```
///
/// # Compliance Mapping
/// - NIST 800-53: IA-2(3) - Multi-factor authentication (certificate-based)
/// - NIST 800-53: IA-5(2) - PKI-based authentication
/// - RFC 7030 §3.2.3 - EST client authentication requirements
#[derive(Debug, Clone)]
pub struct ClientCertExtractor(pub MtlsClientCert);

impl ClientCertExtractor {
    /// Extract client certificate from HTTP request headers (development mode)
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: IA-2(3) - Extract certificate for multi-factor authentication
    /// - RFC 7030 §3.2.3 - Client certificate verification
    ///
    /// NOTE: In production, the client certificate would be extracted from a TLS
    /// connection extension that's populated by rustls/tokio-rustls during the
    /// TLS handshake. The axum-server crate with TLS support would add this
    /// extension automatically when client authentication is configured.
    ///
    /// Expected production implementation would use `FromRequestParts` trait:
    /// ```ignore
    /// use axum::extract::FromRequestParts;
    /// use async_trait::async_trait;
    ///
    /// #[async_trait]
    /// impl<S> FromRequestParts<S> for ClientCertExtractor
    /// where
    ///     S: Send + Sync,
    /// {
    ///     type Rejection = Error;
    ///
    ///     async fn from_request_parts(
    ///         parts: &mut http::request::Parts,
    ///         _state: &S
    ///     ) -> Result<Self, Self::Rejection> {
    ///         let tls_info = parts.extensions.get::<TlsConnectionInfo>()?;
    ///         let peer_certs = tls_info.peer_certificates()?;
    ///         let client_cert_der = peer_certs.first()?;
    ///         let cert = MtlsClientCert::from_der(client_cert_der.to_vec())?;
    ///         Ok(ClientCertExtractor(cert))
    ///     }
    /// }
    /// ```
    ///
    /// For development/testing, this accepts a base64-encoded certificate in the
    /// `X-Client-Certificate-Der` header.
    pub fn from_header(header_value: &str) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

        let cert_der = BASE64
            .decode(header_value)
            .map_err(|_| Error::InvalidCsr("Invalid base64 certificate".to_string()))?;

        let cert = MtlsClientCert::from_der(cert_der)?;
        Ok(ClientCertExtractor(cert))
    }

    /// Extract from TLS connection (production mode - not yet implemented)
    ///
    /// This would extract the client certificate from the TLS connection extension
    /// provided by axum-server when TLS client authentication is enabled.
    pub fn from_tls_connection() -> Result<Self> {
        // TODO: Implement TLS connection extension extraction (Phase 12)
        Err(Error::Unauthorized)
    }
}

/// Validate client certificate against authorized clients database
///
/// RFC 7030 §3.2.3 - EST server should maintain list of authorized clients
/// NIST 800-53: AC-3 - Access enforcement
pub async fn validate_client(client_cert: &MtlsClientCert, db_pool: &DatabasePool) -> Result<()> {
    let repo = ostrich_db::repository::EstRepository::new(db_pool.clone());

    // Lookup authorized client by certificate hash
    let client = repo.find_authorized_client(&client_cert.client_id).await?;

    // Check if client is active
    if let Some(client_record) = client {
        if !client_record.active {
            return Err(Error::Forbidden(format!(
                "Client certificate revoked: {}",
                client_cert.subject_dn
            )));
        }
        Ok(())
    } else {
        // Client not found in authorized list
        Err(Error::Forbidden(format!(
            "Client certificate not authorized: {}",
            client_cert.subject_dn
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtls_client_cert_placeholder() {
        // TODO: Add tests with real certificate DER bytes
        // For now, just verify module compiles
        assert!(true);
    }
}
