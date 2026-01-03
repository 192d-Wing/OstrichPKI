//! OCSP Responder core logic
//!
//! RFC 6960: Online Certificate Status Protocol

use crate::{
    Result,
    request::OcspRequest,
    response::{CertStatus, OcspResponse, SingleResponse},
};
use chrono::{Duration, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::CryptoProvider;
use ostrich_db::{DatabasePool, repository::CertificateRepository};
use std::sync::Arc;
use uuid::Uuid;

/// OCSP Responder configuration
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Validity period for responses (in seconds)
    pub response_validity: i64,

    /// CA certificate ID
    pub ca_id: Uuid,

    /// OCSP signing key handle
    pub signing_key_id: String,

    /// Whether to include nonce in response
    pub include_nonce: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            response_validity: 3600, // 1 hour
            ca_id: Uuid::nil(),
            signing_key_id: String::new(),
            include_nonce: true,
        }
    }
}

/// OCSP Responder
pub struct OcspResponder {
    config: OcspConfig,
    #[allow(dead_code)] // TODO: Use for response caching
    db: DatabasePool,
    #[allow(dead_code)] // TODO: Use for response signing
    crypto: Arc<dyn CryptoProvider>,
    audit: Arc<dyn AuditSink>,
    cert_repo: CertificateRepository,
}

impl OcspResponder {
    /// Create a new OCSP responder
    pub fn new(
        config: OcspConfig,
        db: DatabasePool,
        crypto: Arc<dyn CryptoProvider>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        let cert_repo = CertificateRepository::new(db.clone());

        Self {
            config,
            db,
            crypto,
            audit,
            cert_repo,
        }
    }

    /// Process an OCSP request
    pub async fn process_request(&self, request: OcspRequest) -> Result<OcspResponse> {
        // Log the request
        let mut event = AuditEventBuilder::new(
            EventType::OcspProtocol,
            "ocsp-responder",
            "certificate",
            "check_status",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "serial_number": hex::encode(&request.serial_number),
        }))
        .build();
        self.audit.record(&mut event).await.ok();

        // Look up certificate status
        let cert_opt = self
            .cert_repo
            .find_by_serial(&request.serial_number)
            .await?;

        let cert = match cert_opt {
            Some(c) => c,
            None => {
                // Certificate not found - return unknown status
                return self.create_unknown_response(request).await;
            }
        };

        // Create single response based on certificate status
        let single_response = if cert.revoked {
            SingleResponse {
                serial_number: request.serial_number.clone(),
                cert_status: CertStatus::Revoked {
                    revocation_time: cert.revocation_time.unwrap_or_else(Utc::now),
                    revocation_reason: cert.revocation_reason.map(|r| r as u8),
                },
                this_update: Utc::now(),
                next_update: Some(Utc::now() + Duration::seconds(self.config.response_validity)),
            }
        } else if !cert.is_time_valid() {
            // Expired certificate - still return "good" per OCSP spec
            SingleResponse {
                serial_number: request.serial_number.clone(),
                cert_status: CertStatus::Good,
                this_update: Utc::now(),
                next_update: Some(Utc::now() + Duration::seconds(self.config.response_validity)),
            }
        } else {
            SingleResponse {
                serial_number: request.serial_number.clone(),
                cert_status: CertStatus::Good,
                this_update: Utc::now(),
                next_update: Some(Utc::now() + Duration::seconds(self.config.response_validity)),
            }
        };

        // Sign the response
        let response = self
            .sign_response(vec![single_response], request.nonce)
            .await?;

        // Log successful response
        let mut event = AuditEventBuilder::new(
            EventType::OcspProtocol,
            "ocsp-responder",
            "certificate",
            "generate_response",
            EventOutcome::Success,
        )
        .build();
        self.audit.record(&mut event).await.ok();

        Ok(response)
    }

    /// Create an "unknown" status response
    async fn create_unknown_response(&self, request: OcspRequest) -> Result<OcspResponse> {
        let single_response = SingleResponse {
            serial_number: request.serial_number,
            cert_status: CertStatus::Unknown,
            this_update: Utc::now(),
            next_update: None,
        };

        self.sign_response(vec![single_response], request.nonce)
            .await
    }

    /// Sign an OCSP response
    async fn sign_response(
        &self,
        responses: Vec<SingleResponse>,
        nonce: Option<Vec<u8>>,
    ) -> Result<OcspResponse> {
        // TODO: Implement actual response signing
        // For now, create a placeholder response with empty signature

        let nonce = if self.config.include_nonce {
            nonce
        } else {
            None
        };

        Ok(OcspResponse::successful(
            responses,
            Vec::new(), // Placeholder signature
            Vec::new(), // Placeholder signing cert
            nonce,
        ))
    }

    /// Get OCSP responder configuration
    pub fn config(&self) -> &OcspConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_default() {
        let config = OcspConfig::default();
        assert_eq!(config.response_validity, 3600);
        assert!(config.include_nonce);
    }
}
