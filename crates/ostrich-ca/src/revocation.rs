//! Certificate revocation functionality
//!
//! RFC 5280 §5 - Certificate revocation lists
//! NIST 800-53: SC-12 - Key revocation

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use ostrich_db::{
    DatabasePool, Uuid,
    repository::{CertificateRepository, Repository},
};
use ostrich_x509::{
    crl::{CrlGenerator, RevokedCertificateInfo},
    parser::RevocationReason,
};
use serde::{Deserialize, Serialize};

/// Certificate revocation request
///
/// RFC 5280 §5.3.1 - Revocation reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Certificate ID or serial number
    pub certificate_id: Uuid,

    /// Revocation reason
    pub reason: RevocationReason,

    /// Requestor (for audit)
    pub requestor: String,

    /// Justification
    pub justification: Option<String>,
}

/// Revocation manager
///
/// NIST 800-53: SC-12 - Cryptographic key revocation
pub struct RevocationManager {
    /// CA key handle
    ca_key: KeyHandle,

    /// CA certificate ID
    ca_certificate_id: Uuid,

    /// Crypto provider
    crypto_provider: Box<dyn CryptoProvider>,

    /// Database pool
    db_pool: DatabasePool,

    /// Audit sink
    audit_sink: Box<dyn AuditSink>,

    /// CRL validity hours
    crl_validity_hours: u32,

    /// Current CRL number
    crl_number: std::sync::Arc<tokio::sync::Mutex<u64>>,
}

impl RevocationManager {
    /// Create a new revocation manager
    pub fn new(
        ca_key: KeyHandle,
        ca_certificate_id: Uuid,
        crypto_provider: Box<dyn CryptoProvider>,
        db_pool: DatabasePool,
        audit_sink: Box<dyn AuditSink>,
        crl_validity_hours: u32,
    ) -> Self {
        Self {
            ca_key,
            ca_certificate_id,
            crypto_provider,
            db_pool,
            audit_sink,
            crl_validity_hours,
            crl_number: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// Revoke a certificate
    ///
    /// RFC 5280 §5 - Certificate revocation
    /// NIST 800-53: AU-2 - Audit certificate revocation
    pub async fn revoke(&self, request: RevocationRequest) -> Result<()> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());

        // Find certificate
        let cert = cert_repo
            .find_by_id(request.certificate_id)
            .await?
            .ok_or_else(|| Error::InvalidRequest("Certificate not found".to_string()))?;

        // Create audit event
        let mut audit_event = AuditEventBuilder::new(
            EventType::CertificateRevocation,
            &request.requestor,
            request.certificate_id.to_string(),
            "revoke",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "serial_number": hex::encode(&cert.serial_number),
            "reason": request.reason.as_i32(),
            "subject": cert.subject_dn,
        }))
        .build();

        // Check if already revoked
        if cert.revoked {
            audit_event.outcome = EventOutcome::Failure;
            self.audit_sink
                .record(&mut audit_event)
                .await
                .map_err(Error::Audit)?;

            return Err(Error::Revocation("Certificate already revoked".to_string()));
        }

        // Revoke the certificate
        cert_repo
            .revoke(&request.certificate_id, request.reason.as_i32())
            .await?;

        // Record audit event
        self.audit_sink
            .record(&mut audit_event)
            .await
            .map_err(Error::Audit)?;

        tracing::info!(
            "Certificate revoked: {} (reason: {:?})",
            request.certificate_id,
            request.reason
        );

        Ok(())
    }

    /// Generate a new CRL
    ///
    /// RFC 5280 §5.1 - CRL generation
    /// NIST 800-53: AU-2 - Audit CRL generation
    pub async fn generate_crl(
        &self,
        issuer_dn: ostrich_common::types::DistinguishedName,
    ) -> Result<GeneratedCrl> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());

        // Create audit event
        let mut audit_event = AuditEventBuilder::new(
            EventType::CrlGeneration,
            "system",
            self.ca_certificate_id.to_string(),
            "generate",
            EventOutcome::Success,
        )
        .build();

        // Get all revoked certificates
        let revoked_certs = cert_repo.find_revoked(&self.ca_certificate_id).await?;

        // Convert to RevokedCertificateInfo
        let revoked_info: Vec<RevokedCertificateInfo> = revoked_certs
            .iter()
            .filter_map(|cert| {
                let revocation_time = cert.revocation_time?;
                let reason = cert.revocation_reason.and_then(RevocationReason::from_i32);

                Some(RevokedCertificateInfo::new(
                    cert.serial_number.clone(),
                    revocation_time,
                    reason,
                ))
            })
            .collect();

        // Count revoked certificates before moving
        let revoked_count = revoked_info.len();

        // Increment CRL number
        let mut crl_number = self.crl_number.lock().await;
        *crl_number += 1;
        let current_crl_number = *crl_number;
        drop(crl_number);

        // Generate CRL
        let crl_generator = CrlGenerator::new(issuer_dn, self.crl_validity_hours);
        let crl_builder = crl_generator.generate(current_crl_number, revoked_info)?;

        let tbs_crl = crl_builder.build_tbs()?;

        // Encode TBS CRL to DER for signing
        let tbs_der = tbs_crl.to_der()?;

        // Sign the TBS CRL with CA key
        let signature = self
            .crypto_provider
            .sign(&self.ca_key, Algorithm::RsaPssSha256, &tbs_der)
            .await?;

        // Construct final signed CRL
        let der_encoded = self.build_signed_crl(&tbs_der, &signature)?;

        // Convert DER to PEM
        let pem_encoded = self.crl_der_to_pem(&der_encoded)?;

        // Record audit event
        audit_event.details = Some(serde_json::json!({
            "crl_number": current_crl_number,
            "revoked_count": revoked_count,
        }));

        self.audit_sink
            .record(&mut audit_event)
            .await
            .map_err(Error::Audit)?;

        tracing::info!(
            "CRL generated: number {} with {} revoked certificates",
            current_crl_number,
            revoked_count
        );

        Ok(GeneratedCrl {
            crl_number: current_crl_number,
            this_update: tbs_crl.this_update,
            next_update: tbs_crl.next_update,
            revoked_count,
            der_encoded,
            pem_encoded,
        })
    }

    /// Build a signed CRL from TBS and signature
    ///
    /// RFC 5280 §5.1 - CRL structure
    fn build_signed_crl(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        use der::{Decode, Encode, asn1::BitString};
        use x509_cert::crl::{CertificateList, TbsCertList};

        // Parse TBS CRL from DER
        let tbs = TbsCertList::from_der(tbs_der)
            .map_err(|e| Error::CrlGeneration(format!("Failed to parse TBS CRL: {}", e)))?;

        // Get signature algorithm (same as in TBS)
        let signature_algorithm = tbs.signature.clone();

        // Convert signature bytes to BitString
        let signature_value = BitString::from_bytes(signature).map_err(|e| {
            Error::CrlGeneration(format!("Failed to create signature BitString: {}", e))
        })?;

        // Build complete CRL
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm,
            signature: signature_value,
        };

        // Encode to DER
        crl.to_der()
            .map_err(|e| Error::CrlGeneration(format!("Failed to encode CRL: {}", e)))
    }

    /// Convert DER-encoded CRL to PEM format
    ///
    /// RFC 7468 - PEM encoding
    fn crl_der_to_pem(&self, der: &[u8]) -> Result<String> {
        use pem_rfc7468::{LineEnding, encode_string};

        const CRL_LABEL: &str = "X509 CRL";

        encode_string(CRL_LABEL, LineEnding::LF, der)
            .map_err(|e| Error::CrlGeneration(format!("Failed to encode CRL PEM: {}", e)))
    }

    /// Check if a certificate is revoked
    ///
    /// RFC 6960 §2.2 - OCSP response
    pub async fn is_revoked(&self, certificate_id: &Uuid) -> Result<bool> {
        let cert_repo = CertificateRepository::new(self.db_pool.clone());
        let cert = cert_repo
            .find_by_id(*certificate_id)
            .await?
            .ok_or_else(|| Error::InvalidRequest("Certificate not found".to_string()))?;

        Ok(cert.revoked)
    }
}

/// Generated CRL information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedCrl {
    /// CRL number
    pub crl_number: u64,

    /// This update time
    pub this_update: DateTime<Utc>,

    /// Next update time
    pub next_update: DateTime<Utc>,

    /// Number of revoked certificates
    pub revoked_count: usize,

    /// DER-encoded CRL
    pub der_encoded: Vec<u8>,

    /// PEM-encoded CRL
    pub pem_encoded: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_request() {
        let request = RevocationRequest {
            certificate_id: Uuid::new_v4(),
            reason: RevocationReason::KeyCompromise,
            requestor: "admin@example.com".to_string(),
            justification: Some("Private key leaked".to_string()),
        };

        assert_eq!(request.reason.as_i32(), 1);
    }
}
