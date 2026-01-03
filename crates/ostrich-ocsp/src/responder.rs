//! OCSP Responder core logic
//!
//! RFC 6960: Online Certificate Status Protocol

use crate::{
    Result,
    request::OcspRequest,
    response::{CertStatus, OcspResponse, SingleResponse},
};
use chrono::{DateTime, Duration, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyType, key::ProviderId};
use ostrich_db::{DatabasePool, repository::CertificateRepository};
use std::sync::Arc;
use uuid::Uuid;

/// Response data structure for signing
struct ResponseData {
    produced_at: DateTime<Utc>,
    responses: Vec<SingleResponse>,
}

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
    ///
    /// RFC 6960 §4.2.1: BasicOCSPResponse signing
    async fn sign_response(
        &self,
        responses: Vec<SingleResponse>,
        nonce: Option<Vec<u8>>,
    ) -> Result<OcspResponse> {
        // Build response data structure for signing
        let response_data = ResponseData {
            produced_at: chrono::Utc::now(),
            responses: responses.clone(),
        };

        // Encode response data to DER for signing
        let tbs_der = self.encode_response_data(&response_data)?;

        // Sign the response data
        // TODO: Load actual key handle from database or configuration
        // For now, create a placeholder key handle
        let key_handle = ostrich_crypto::KeyHandle::new(
            ProviderId::Software,
            self.config.signing_key_id.as_bytes().to_vec(),
            KeyType::Rsa2048,
            Algorithm::RsaPssSha256,
            "ocsp-signing".to_string(),
        );
        let signature = self
            .crypto
            .sign(&key_handle, Algorithm::RsaPssSha256, &tbs_der)
            .await
            .map_err(|e| {
                crate::Error::SigningError(format!("Failed to sign OCSP response: {}", e))
            })?;

        let nonce = if self.config.include_nonce {
            nonce
        } else {
            None
        };

        // For now, use empty signing cert (should load from database)
        let signing_cert = Vec::new();

        Ok(OcspResponse::successful(
            responses,
            signature,
            signing_cert,
            nonce,
        ))
    }

    /// Encode ResponseData to DER for signing
    ///
    /// RFC 6960 §4.2.1: ResponseData structure
    fn encode_response_data(&self, data: &ResponseData) -> Result<Vec<u8>> {
        use der::asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString};
        use der::{Encode, Sequence};

        #[derive(Sequence)]
        struct AlgorithmIdentifier {
            algorithm: ObjectIdentifier,
        }

        #[derive(Sequence)]
        struct CertId {
            hash_algorithm: AlgorithmIdentifier,
            issuer_name_hash: OctetString,
            issuer_key_hash: OctetString,
            serial_number: Int,
        }

        #[derive(Sequence)]
        struct SingleResponseAsn1 {
            cert_id: CertId,
            cert_status: u8, // Simplified - just encode status as integer
            this_update: GeneralizedTime,
        }

        #[derive(Sequence)]
        struct ResponseDataAsn1 {
            produced_at: GeneralizedTime,
            responses: der::asn1::SequenceOf<SingleResponseAsn1, 10>,
        }

        let produced_at = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            data.produced_at.timestamp() as u64,
        ))
        .map_err(|e| crate::Error::InternalError(format!("Invalid timestamp: {}", e)))?;

        let mut asn1_responses = Vec::new();
        for resp in &data.responses {
            const SHA256_OID: ObjectIdentifier =
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

            let hash_alg = AlgorithmIdentifier {
                algorithm: SHA256_OID,
            };

            let cert_id = CertId {
                hash_algorithm: hash_alg,
                issuer_name_hash: OctetString::new(vec![0u8; 32]).map_err(|e| {
                    crate::Error::InternalError(format!("Failed to encode hash: {}", e))
                })?,
                issuer_key_hash: OctetString::new(vec![0u8; 32]).map_err(|e| {
                    crate::Error::InternalError(format!("Failed to encode hash: {}", e))
                })?,
                serial_number: Int::new(&resp.serial_number).map_err(|e| {
                    crate::Error::InternalError(format!("Failed to encode serial: {}", e))
                })?,
            };

            let cert_status = match &resp.cert_status {
                crate::response::CertStatus::Good => 0u8,
                crate::response::CertStatus::Revoked { .. } => 1u8,
                crate::response::CertStatus::Unknown => 2u8,
            };

            let this_update = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                resp.this_update.timestamp() as u64,
            ))
            .map_err(|e| crate::Error::InternalError(format!("Invalid timestamp: {}", e)))?;

            asn1_responses.push(SingleResponseAsn1 {
                cert_id,
                cert_status,
                this_update,
            });
        }

        // Convert Vec to array-backed SequenceOf
        let mut responses = der::asn1::SequenceOf::<SingleResponseAsn1, 10>::new();
        for resp in asn1_responses {
            responses
                .add(resp)
                .map_err(|e| crate::Error::InternalError(format!("Too many responses: {}", e)))?;
        }

        let response_data_asn1 = ResponseDataAsn1 {
            produced_at,
            responses,
        };

        response_data_asn1.to_der().map_err(|e| {
            crate::Error::InternalError(format!("Failed to encode response data: {}", e))
        })
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
