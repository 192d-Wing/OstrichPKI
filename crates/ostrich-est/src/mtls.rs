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

/// Extract client certificate from TLS connection (placeholder)
///
/// This is a placeholder function. In production, you need to:
/// 1. Configure Axum server with TLS using rustls/tokio-rustls
/// 2. Enable client certificate requirement in TLS config
/// 3. Extract peer certificate from TLS connection info
/// 4. Parse and validate the certificate
///
/// Example TLS setup (not implemented yet):
/// ```ignore
/// use rustls::{ServerConfig, RootCertStore};
/// use rustls::server::AllowAnyAuthenticatedClient;
/// use tokio_rustls::TlsAcceptor;
///
/// let mut client_cert_verifier = RootCertStore::empty();
/// client_cert_verifier.add(&ca_cert)?;
///
/// let tls_config = ServerConfig::builder()
///     .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(client_cert_verifier))
///     .with_single_cert(server_cert_chain, server_private_key)?;
/// ```
///
/// Production implementation would extract cert from Axum extensions:
/// ```ignore
/// let tls_info = parts.extensions.get::<TlsConnectionInfo>()?;
/// let client_cert_der = tls_info.peer_certificates()?.first()?;
/// MtlsClientCert::from_der(client_cert_der.to_vec())
/// ```
pub fn extract_client_cert_placeholder() -> Result<MtlsClientCert> {
    // TODO: Implement actual TLS certificate extraction
    // For now, return error indicating mTLS not configured
    Err(Error::Forbidden(
        "mTLS not configured - TLS server setup required".to_string(),
    ))
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
