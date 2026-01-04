//! ACME challenge types
//!
//! This module defines ACME challenge types and their lifecycle management
//! for domain/identifier validation per RFC 8555 Section 8.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before any action
//!   - Challenge validation proves control over identifier.
//!   - Key authorization binds challenge to account's public key.
//!
//! - **FCS_COP.1**: Cryptographic operation
//!   - Key authorization uses SHA-256 (for DNS-01 digest).
//!   - Token generation uses cryptographic RNG.
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - Challenge creation, status changes, and validation audited.
//!   - Validation errors recorded with details.
//!
//! - **FPT_STM.1**: Reliable time stamps
//!   - Challenge validation timestamps from trusted time source.
//!   - Created/updated timestamps for lifecycle tracking.
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **IA-5(1)**: Authenticator Management (Challenge-Response)
//!   - HTTP-01, DNS-01, TLS-ALPN-01 challenge mechanisms.
//!
//! - **AU-2/AU-3**: Audit Events
//!   - Challenge lifecycle events logged.
//!
//! ## RFC Compliance
//!
//! - RFC 8555 §8: Identifier validation challenges
//! - RFC 8555 §8.1: Key authorization
//! - RFC 8555 §8.3: HTTP-01 challenge
//! - RFC 8555 §8.4: DNS-01 challenge
//! - RFC 8737: TLS-ALPN-01 challenge

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge type
///
/// RFC 8555 §8
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// HTTP-01 challenge (RFC 8555 §8.3)
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 challenge (RFC 8555 §8.4)
    #[serde(rename = "dns-01")]
    Dns01,
    /// TLS-ALPN-01 challenge (RFC 8737)
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// Challenge status
///
/// RFC 8555 §7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    /// Challenge is pending
    Pending,
    /// Challenge is being processed
    Processing,
    /// Challenge is valid
    Valid,
    /// Challenge is invalid
    Invalid,
}

/// Challenge object
///
/// RFC 8555 §7.1.5
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// Challenge ID (internal)
    #[serde(skip)]
    pub id: Uuid,

    /// Authorization ID this challenge belongs to
    #[serde(skip)]
    pub authorization_id: Uuid,

    /// Challenge type
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,

    /// Challenge status
    pub status: ChallengeStatus,

    /// Challenge URL
    pub url: String,

    /// Challenge token
    pub token: String,

    /// Validation error (if invalid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,

    /// Validation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<DateTime<Utc>>,

    /// Created timestamp
    #[serde(skip)]
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl Challenge {
    /// Create a new pending challenge
    pub fn new(authorization_id: Uuid, challenge_type: ChallengeType, token: String) -> Self {
        let id = Uuid::new_v4();
        let now = Utc::now();

        Self {
            id,
            authorization_id,
            challenge_type,
            status: ChallengeStatus::Pending,
            url: format!("/acme/challenge/{}", id),
            token,
            error: None,
            validated: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Mark challenge as processing
    pub fn mark_processing(&mut self) {
        self.status = ChallengeStatus::Processing;
        self.updated_at = Utc::now();
    }

    /// Mark challenge as valid
    pub fn mark_valid(&mut self) {
        self.status = ChallengeStatus::Valid;
        self.validated = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Mark challenge as invalid
    pub fn mark_invalid(&mut self, error: serde_json::Value) {
        self.status = ChallengeStatus::Invalid;
        self.error = Some(error);
        self.updated_at = Utc::now();
    }

    /// Compute key authorization
    ///
    /// RFC 8555 §8.1: key_authorization = token || '.' || base64url(SHA256(JWK))
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FIA_UAU.1**: Binds challenge to account's cryptographic identity.
    /// - **FCS_COP.1**: Uses JWK thumbprint (SHA-256 hash of canonical JWK).
    pub fn key_authorization(&self, account_jwk_thumbprint: &str) -> String {
        format!("{}.{}", self.token, account_jwk_thumbprint)
    }
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_creation() {
        let challenge = Challenge::new(
            Uuid::new_v4(),
            ChallengeType::Http01,
            "test-token-12345".to_string(),
        );

        assert_eq!(challenge.status, ChallengeStatus::Pending);
        assert_eq!(challenge.challenge_type, ChallengeType::Http01);
        assert_eq!(challenge.token, "test-token-12345");
    }

    #[test]
    fn test_challenge_lifecycle() {
        let mut challenge =
            Challenge::new(Uuid::new_v4(), ChallengeType::Dns01, "token".to_string());

        assert_eq!(challenge.status, ChallengeStatus::Pending);

        challenge.mark_processing();
        assert_eq!(challenge.status, ChallengeStatus::Processing);

        challenge.mark_valid();
        assert_eq!(challenge.status, ChallengeStatus::Valid);
        assert!(challenge.validated.is_some());
    }

    #[test]
    fn test_key_authorization() {
        let challenge = Challenge::new(
            Uuid::new_v4(),
            ChallengeType::Http01,
            "token123".to_string(),
        );

        let key_auth = challenge.key_authorization("thumbprint456");
        assert_eq!(key_auth, "token123.thumbprint456");
    }

    #[test]
    fn test_challenge_type_str() {
        assert_eq!(ChallengeType::Http01.as_str(), "http-01");
        assert_eq!(ChallengeType::Dns01.as_str(), "dns-01");
        assert_eq!(ChallengeType::TlsAlpn01.as_str(), "tls-alpn-01");
    }
}
