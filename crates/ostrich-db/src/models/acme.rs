//! ACME database models
//!
//! RFC 8555: Automatic Certificate Management Environment

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// ACME Account
///
/// RFC 8555 §7.1.2 - Account objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeAccount {
    pub id: Uuid,
    pub account_id: String,
    pub jwk_thumbprint: String,
    pub public_key_jwk: JsonValue,
    pub contact: Vec<String>,
    pub status: String,
    pub terms_of_service_agreed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Order
///
/// RFC 8555 §7.1.3 - Order objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeOrder {
    pub id: Uuid,
    pub order_id: String,
    pub account_id: Uuid,
    pub status: String,
    pub identifiers: JsonValue,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub expires: DateTime<Utc>,
    pub certificate_id: Option<Uuid>,
    /// CSR submitted during finalize (RFC 8555 §7.4)
    pub csr_der: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Authorization
///
/// RFC 8555 §7.1.4 - Authorization objects
#[derive(Debug, Clone, FromRow)]
pub struct AcmeAuthorization {
    pub id: Uuid,
    pub authorization_id: String,
    pub order_id: Uuid,
    pub identifier_type: String,
    pub identifier_value: String,
    pub status: String,
    pub expires: DateTime<Utc>,
    pub wildcard: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Challenge
///
/// RFC 8555 §8 - Challenge types
#[derive(Debug, Clone, FromRow)]
pub struct AcmeChallenge {
    pub id: Uuid,
    pub challenge_id: String,
    pub authorization_id: Uuid,
    pub challenge_type: String,
    pub token: String,
    pub status: String,
    pub validated_at: Option<DateTime<Utc>>,
    pub error_detail: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ACME Nonce
///
/// RFC 8555 §6.5 - Replay protection
#[derive(Debug, Clone, FromRow)]
pub struct AcmeNonce {
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_acme_account_structure() {
        let account = AcmeAccount {
            id: Uuid::new_v4(),
            account_id: "account-12345".to_string(),
            jwk_thumbprint: "abc123def456".to_string(),
            public_key_jwk: serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "example_x",
                "y": "example_y"
            }),
            contact: vec!["mailto:admin@example.com".to_string()],
            status: "valid".to_string(),
            terms_of_service_agreed: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(account.account_id, "account-12345");
        assert!(account.terms_of_service_agreed);
        assert_eq!(account.status, "valid");
        assert_eq!(account.contact.len(), 1);
    }

    #[test]
    fn test_acme_order_structure() {
        let now = Utc::now();
        let order = AcmeOrder {
            id: Uuid::new_v4(),
            order_id: "order-67890".to_string(),
            account_id: Uuid::new_v4(),
            status: "pending".to_string(),
            identifiers: serde_json::json!([
                {"type": "dns", "value": "example.com"},
                {"type": "dns", "value": "www.example.com"}
            ]),
            not_before: Some(now),
            not_after: Some(now + Duration::days(90)),
            expires: now + Duration::hours(24),
            certificate_id: None,
            csr_der: None,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(order.order_id, "order-67890");
        assert_eq!(order.status, "pending");
        assert!(order.certificate_id.is_none());
        assert!(order.csr_der.is_none());
    }

    #[test]
    fn test_acme_order_with_certificate() {
        let now = Utc::now();
        let cert_id = Uuid::new_v4();
        let order = AcmeOrder {
            id: Uuid::new_v4(),
            order_id: "order-complete".to_string(),
            account_id: Uuid::new_v4(),
            status: "valid".to_string(),
            identifiers: serde_json::json!([{"type": "dns", "value": "example.com"}]),
            not_before: Some(now),
            not_after: Some(now + Duration::days(90)),
            expires: now + Duration::hours(24),
            certificate_id: Some(cert_id),
            csr_der: Some(vec![0x30, 0x82, 0x01, 0x00]),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(order.status, "valid");
        assert_eq!(order.certificate_id, Some(cert_id));
        assert!(order.csr_der.is_some());
    }

    #[test]
    fn test_acme_authorization_structure() {
        let now = Utc::now();
        let authz = AcmeAuthorization {
            id: Uuid::new_v4(),
            authorization_id: "authz-abc123".to_string(),
            order_id: Uuid::new_v4(),
            identifier_type: "dns".to_string(),
            identifier_value: "example.com".to_string(),
            status: "pending".to_string(),
            expires: now + Duration::days(7),
            wildcard: false,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(authz.authorization_id, "authz-abc123");
        assert_eq!(authz.identifier_type, "dns");
        assert!(!authz.wildcard);
    }

    #[test]
    fn test_acme_authorization_wildcard() {
        let now = Utc::now();
        let authz = AcmeAuthorization {
            id: Uuid::new_v4(),
            authorization_id: "authz-wildcard".to_string(),
            order_id: Uuid::new_v4(),
            identifier_type: "dns".to_string(),
            identifier_value: "example.com".to_string(),
            status: "valid".to_string(),
            expires: now + Duration::days(7),
            wildcard: true,
            created_at: now,
            updated_at: now,
        };

        assert!(authz.wildcard);
        assert_eq!(authz.status, "valid");
    }

    #[test]
    fn test_acme_challenge_structure() {
        let now = Utc::now();
        let challenge = AcmeChallenge {
            id: Uuid::new_v4(),
            challenge_id: "chall-xyz789".to_string(),
            authorization_id: Uuid::new_v4(),
            challenge_type: "http-01".to_string(),
            token: "randomtoken123".to_string(),
            status: "pending".to_string(),
            validated_at: None,
            error_detail: None,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(challenge.challenge_type, "http-01");
        assert_eq!(challenge.status, "pending");
        assert!(challenge.validated_at.is_none());
        assert!(challenge.error_detail.is_none());
    }

    #[test]
    fn test_acme_challenge_validated() {
        let now = Utc::now();
        let challenge = AcmeChallenge {
            id: Uuid::new_v4(),
            challenge_id: "chall-valid".to_string(),
            authorization_id: Uuid::new_v4(),
            challenge_type: "dns-01".to_string(),
            token: "dnstoken456".to_string(),
            status: "valid".to_string(),
            validated_at: Some(now),
            error_detail: None,
            created_at: now - Duration::hours(1),
            updated_at: now,
        };

        assert_eq!(challenge.status, "valid");
        assert!(challenge.validated_at.is_some());
    }

    #[test]
    fn test_acme_challenge_with_error() {
        let now = Utc::now();
        let challenge = AcmeChallenge {
            id: Uuid::new_v4(),
            challenge_id: "chall-error".to_string(),
            authorization_id: Uuid::new_v4(),
            challenge_type: "http-01".to_string(),
            token: "failedtoken".to_string(),
            status: "invalid".to_string(),
            validated_at: None,
            error_detail: Some(serde_json::json!({
                "type": "urn:ietf:params:acme:error:connection",
                "detail": "Could not connect to host"
            })),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(challenge.status, "invalid");
        assert!(challenge.error_detail.is_some());
        let error = challenge.error_detail.unwrap();
        assert!(error["type"].as_str().unwrap().contains("connection"));
    }

    #[test]
    fn test_acme_nonce_structure() {
        let now = Utc::now();
        let nonce = AcmeNonce {
            nonce: "nonce-abc123xyz".to_string(),
            created_at: now,
            expires_at: now + Duration::minutes(30),
        };

        assert_eq!(nonce.nonce, "nonce-abc123xyz");
        assert!(nonce.expires_at > nonce.created_at);
    }
}
