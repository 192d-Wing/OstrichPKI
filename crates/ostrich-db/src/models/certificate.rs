//! Certificate database model
//!
//! RFC 5280: X.509 certificate storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Certificate database model
///
/// RFC 5280 §4.1 - Basic certificate fields
/// NIST 800-53: AU-3 - Audit record content (issuer_service, requestor tracking)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Certificate {
    /// Unique identifier
    pub id: Uuid,

    /// Issuing CA identifier
    pub ca_id: Uuid,

    /// Certificate serial number (unique per CA)
    ///
    /// RFC 5280 §4.1.2.2 - Serial number
    pub serial_number: Vec<u8>,

    /// Subject distinguished name
    ///
    /// RFC 5280 §4.1.2.6 - Subject
    pub subject_dn: String,

    /// Issuer distinguished name
    ///
    /// RFC 5280 §4.1.2.4 - Issuer
    pub issuer_dn: String,

    /// Certificate validity start time
    ///
    /// RFC 5280 §4.1.2.5 - Validity
    pub not_before: DateTime<Utc>,

    /// Certificate validity end time
    ///
    /// RFC 5280 §4.1.2.5 - Validity
    pub not_after: DateTime<Utc>,

    /// DER-encoded certificate
    pub der_encoded: Vec<u8>,

    /// PEM-encoded certificate (for convenience)
    pub pem_encoded: String,

    /// Whether the certificate has been revoked
    ///
    /// RFC 5280 §5 - CRL and certificate revocation
    pub revoked: bool,

    /// Time of revocation (if revoked)
    pub revocation_time: Option<DateTime<Utc>>,

    /// Reason for revocation (if revoked)
    ///
    /// RFC 5280 §5.3.1 - Reason code
    pub revocation_reason: Option<i32>,

    /// Service that issued this certificate
    ///
    /// NIST 800-53: AU-3(1) - Additional audit content
    /// Values: "CA" (direct), "ACME", "EST", "SCMS"
    pub issuer_service: Option<String>,

    /// Identity of requestor
    ///
    /// NIST 800-53: AU-3(b) - Subject identity
    /// Examples: ACME account ID, EST client ID, SCMS user ID
    pub requestor: Option<String>,

    /// Certificate profile used for issuance
    pub profile_name: Option<String>,

    /// Service-specific metadata
    ///
    /// NIST 800-53: AU-3(1) - Additional audit content
    /// Examples: {"acme_order_id": "...", "est_enrollment_id": "...", "scms_token_serial": "..."}
    pub metadata: Option<JsonValue>,

    /// Record creation timestamp
    pub created_at: DateTime<Utc>,

    /// Record last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl Certificate {
    /// Create a new certificate record
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ca_id: Uuid,
        serial_number: Vec<u8>,
        subject_dn: String,
        issuer_dn: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        der_encoded: Vec<u8>,
        pem_encoded: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ca_id,
            serial_number,
            subject_dn,
            issuer_dn,
            not_before,
            not_after,
            der_encoded,
            pem_encoded,
            revoked: false,
            revocation_time: None,
            revocation_reason: None,
            issuer_service: None,
            requestor: None,
            profile_name: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new certificate record with full metadata
    ///
    /// NIST 800-53: AU-3 - Complete audit record content
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_metadata(
        ca_id: Uuid,
        serial_number: Vec<u8>,
        subject_dn: String,
        issuer_dn: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        der_encoded: Vec<u8>,
        pem_encoded: String,
        issuer_service: Option<String>,
        requestor: Option<String>,
        profile_name: Option<String>,
        metadata: Option<JsonValue>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ca_id,
            serial_number,
            subject_dn,
            issuer_dn,
            not_before,
            not_after,
            der_encoded,
            pem_encoded,
            revoked: false,
            revocation_time: None,
            revocation_reason: None,
            issuer_service,
            requestor,
            profile_name,
            metadata,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if certificate is currently valid (not expired)
    ///
    /// RFC 5280 §4.1.2.5 - Validity period check
    pub fn is_time_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now < self.not_after
    }

    /// Check if certificate is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        self.is_time_valid() && !self.revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_certificate_new() {
        let ca_id = Uuid::new_v4();
        let serial = vec![0x01, 0x02, 0x03];
        let cert = Certificate::new(
            ca_id,
            serial.clone(),
            "CN=Test Subject".to_string(),
            "CN=Test Issuer".to_string(),
            Utc::now(),
            Utc::now() + Duration::days(365),
            vec![0xDE, 0xAD],
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        );

        assert_eq!(cert.ca_id, ca_id);
        assert_eq!(cert.serial_number, serial);
        assert_eq!(cert.subject_dn, "CN=Test Subject");
        assert!(!cert.revoked);
        assert!(cert.revocation_time.is_none());
    }

    #[test]
    fn test_certificate_new_with_metadata() {
        let cert = Certificate::new_with_metadata(
            Uuid::new_v4(),
            vec![0x01],
            "CN=Test".to_string(),
            "CN=CA".to_string(),
            Utc::now(),
            Utc::now() + Duration::days(30),
            vec![],
            String::new(),
            Some("ACME".to_string()),
            Some("acme-account-123".to_string()),
            Some("tls-server".to_string()),
            Some(serde_json::json!({"order_id": "order-456"})),
        );

        assert_eq!(cert.issuer_service, Some("ACME".to_string()));
        assert_eq!(cert.requestor, Some("acme-account-123".to_string()));
        assert_eq!(cert.profile_name, Some("tls-server".to_string()));
        assert!(cert.metadata.is_some());
    }

    #[test]
    fn test_certificate_is_time_valid() {
        // Valid certificate (current time within validity period)
        let valid_cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x01],
            "CN=Valid".to_string(),
            "CN=CA".to_string(),
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::days(30),
            vec![],
            String::new(),
        );
        assert!(valid_cert.is_time_valid());

        // Expired certificate
        let expired_cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x02],
            "CN=Expired".to_string(),
            "CN=CA".to_string(),
            Utc::now() - Duration::days(60),
            Utc::now() - Duration::days(30),
            vec![],
            String::new(),
        );
        assert!(!expired_cert.is_time_valid());

        // Not yet valid certificate
        let future_cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x03],
            "CN=Future".to_string(),
            "CN=CA".to_string(),
            Utc::now() + Duration::days(30),
            Utc::now() + Duration::days(60),
            vec![],
            String::new(),
        );
        assert!(!future_cert.is_time_valid());
    }

    #[test]
    fn test_certificate_is_valid() {
        // Valid and not revoked
        let valid_cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x01],
            "CN=Valid".to_string(),
            "CN=CA".to_string(),
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::days(30),
            vec![],
            String::new(),
        );
        assert!(valid_cert.is_valid());

        // Valid but revoked
        let mut revoked_cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x02],
            "CN=Revoked".to_string(),
            "CN=CA".to_string(),
            Utc::now() - Duration::hours(1),
            Utc::now() + Duration::days(30),
            vec![],
            String::new(),
        );
        revoked_cert.revoked = true;
        revoked_cert.revocation_time = Some(Utc::now());
        revoked_cert.revocation_reason = Some(1); // keyCompromise
        assert!(!revoked_cert.is_valid());
    }

    #[test]
    fn test_certificate_serialization() {
        let cert = Certificate::new(
            Uuid::new_v4(),
            vec![0x01, 0x02],
            "CN=Test".to_string(),
            "CN=CA".to_string(),
            Utc::now(),
            Utc::now() + Duration::days(1),
            vec![0xAB, 0xCD],
            "PEM".to_string(),
        );

        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("CN=Test"));
        assert!(json.contains("CN=CA"));

        let deserialized: Certificate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.subject_dn, cert.subject_dn);
        assert_eq!(deserialized.issuer_dn, cert.issuer_dn);
    }
}
