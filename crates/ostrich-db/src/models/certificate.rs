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
