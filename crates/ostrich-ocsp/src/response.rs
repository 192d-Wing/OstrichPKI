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
    /// Note: This is a placeholder. Production implementation would use
    /// proper ASN.1 encoding.
    pub fn to_der(&self) -> Vec<u8> {
        // TODO: Implement proper ASN.1/DER encoding
        // For now, return empty vec as placeholder
        Vec::new()
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
