//! OCSP response generation
//!
//! RFC 6960 §4.2: Response Syntax

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// OCSP Response Status
///
/// RFC 6960 §4.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Response has valid confirmations
    Successful = 0,
    /// Illegal confirmation request
    MalformedRequest = 1,
    /// Internal error in issuer
    InternalError = 2,
    /// Try again later
    TryLater = 3,
    /// Must sign the request
    SigRequired = 5,
    /// Request unauthorized
    Unauthorized = 6,
}

/// Certificate Status
///
/// RFC 6960 §4.2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        revocation_time: DateTime<Utc>,
        revocation_reason: Option<u8>,
    },
    /// Status is unknown
    Unknown,
}

/// Single OCSP response for one certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleResponse {
    /// Certificate serial number
    pub serial_number: Vec<u8>,

    /// Certificate status
    pub cert_status: CertStatus,

    /// Time of this update
    pub this_update: DateTime<Utc>,

    /// Time of next update (optional)
    pub next_update: Option<DateTime<Utc>>,
}

/// OCSP Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponse {
    /// Response status
    pub response_status: ResponseStatus,

    /// Responses for individual certificates
    pub responses: Vec<SingleResponse>,

    /// Response signature (DER-encoded)
    pub signature: Vec<u8>,

    /// Signing certificate (DER-encoded)
    pub signing_cert: Vec<u8>,

    /// Produced at time
    pub produced_at: DateTime<Utc>,

    /// Nonce from request (if present)
    pub nonce: Option<Vec<u8>>,
}

impl OcspResponse {
    /// Create a successful OCSP response
    pub fn successful(
        responses: Vec<SingleResponse>,
        signature: Vec<u8>,
        signing_cert: Vec<u8>,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            response_status: ResponseStatus::Successful,
            responses,
            signature,
            signing_cert,
            produced_at: Utc::now(),
            nonce,
        }
    }

    /// Create an error response
    pub fn error(status: ResponseStatus) -> Self {
        Self {
            response_status: status,
            responses: Vec::new(),
            signature: Vec::new(),
            signing_cert: Vec::new(),
            produced_at: Utc::now(),
            nonce: None,
        }
    }

    /// Encode response to DER format
    ///
    /// RFC 6960 §4.2.1: OCSPResponse structure
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        use der::asn1::{BitString, GeneralizedTime, Int, ObjectIdentifier, OctetString};
        use der::{Encode, Sequence};

        // RFC 6960 §4.2.1 ASN.1 Structure:
        // OCSPResponse ::= SEQUENCE {
        //    responseStatus         OCSPResponseStatus,
        //    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
        //
        // ResponseBytes ::= SEQUENCE {
        //    responseType   OBJECT IDENTIFIER,
        //    response       OCTET STRING }
        //
        // BasicOCSPResponse ::= SEQUENCE {
        //    tbsResponseData      ResponseData,
        //    signatureAlgorithm   AlgorithmIdentifier,
        //    signature            BIT STRING,
        //    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
        //
        // ResponseData ::= SEQUENCE {
        //    version              [0] EXPLICIT Version DEFAULT v1,
        //    responderID          ResponderID,
        //    producedAt           GeneralizedTime,
        //    responses            SEQUENCE OF SingleResponse,
        //    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

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
            cert_status: u8, // Simplified encoding
            this_update: GeneralizedTime,
            #[asn1(optional = "true")]
            next_update: Option<GeneralizedTime>,
        }

        #[derive(Sequence)]
        struct ResponseData {
            produced_at: GeneralizedTime,
            responses: der::asn1::SequenceOf<SingleResponseAsn1, 10>,
        }

        #[derive(Sequence)]
        struct BasicOcspResponse {
            tbs_response_data: ResponseData,
            signature_algorithm: AlgorithmIdentifier,
            signature: BitString,
        }

        // For error responses, just encode the status
        if self.response_status != ResponseStatus::Successful {
            #[derive(Sequence)]
            struct OcspResponseStatus {
                status: u8,
            }

            let status = OcspResponseStatus {
                status: self.response_status.as_u8(),
            };
            return status.to_der();
        }

        // Convert produced_at to GeneralizedTime
        let produced_at = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            self.produced_at.timestamp() as u64,
        ))?;

        // Convert SingleResponse structs to ASN.1
        let mut asn1_responses = Vec::new();
        for resp in &self.responses {
            // SHA-256 OID (simplified - should match request)
            const SHA256_OID: ObjectIdentifier =
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

            let hash_alg = AlgorithmIdentifier {
                algorithm: SHA256_OID,
            };

            // Create CertID (simplified - using placeholder hashes)
            let cert_id = CertId {
                hash_algorithm: hash_alg,
                issuer_name_hash: OctetString::new(vec![0u8; 32])?,
                issuer_key_hash: OctetString::new(vec![0u8; 32])?,
                serial_number: Int::new(&resp.serial_number)?,
            };

            // Encode cert_status as CHOICE
            // Good = [0] IMPLICIT NULL
            // Revoked = [1] IMPLICIT RevokedInfo
            // Unknown = [2] IMPLICIT UnknownInfo
            let cert_status = match &resp.cert_status {
                CertStatus::Good => 0u8,
                CertStatus::Revoked { .. } => 1u8,
                CertStatus::Unknown => 2u8,
            };

            let this_update = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                resp.this_update.timestamp() as u64,
            ))?;

            let next_update = if let Some(nu) = resp.next_update {
                Some(GeneralizedTime::from_unix_duration(
                    std::time::Duration::from_secs(nu.timestamp() as u64),
                )?)
            } else {
                None
            };

            asn1_responses.push(SingleResponseAsn1 {
                cert_id,
                cert_status,
                this_update,
                next_update,
            });
        }

        // Convert Vec to array-backed SequenceOf
        let mut responses = der::asn1::SequenceOf::<SingleResponseAsn1, 10>::new();
        for resp in asn1_responses {
            responses.add(resp)?;
        }

        let response_data = ResponseData {
            produced_at,
            responses,
        };

        // RSA with SHA-256 OID (simplified)
        const RSA_SHA256_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let signature_algorithm = AlgorithmIdentifier {
            algorithm: RSA_SHA256_OID,
        };

        let signature = BitString::from_bytes(&self.signature)?;

        let basic_response = BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm,
            signature,
        };

        basic_response.to_der()
    }
}

impl ResponseStatus {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_status_values() {
        assert_eq!(ResponseStatus::Successful.as_u8(), 0);
        assert_eq!(ResponseStatus::MalformedRequest.as_u8(), 1);
        assert_eq!(ResponseStatus::InternalError.as_u8(), 2);
    }

    #[test]
    fn test_cert_status_good() {
        let status = CertStatus::Good;
        assert!(matches!(status, CertStatus::Good));
    }

    #[test]
    fn test_cert_status_revoked() {
        let now = Utc::now();
        let status = CertStatus::Revoked {
            revocation_time: now,
            revocation_reason: Some(1),
        };
        assert!(matches!(status, CertStatus::Revoked { .. }));
    }
}
