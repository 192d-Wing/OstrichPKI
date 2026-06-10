//! Certificate Revocation List (CRL) database model
//!
//! Persists generated CRLs so the latest signed list can be served at a public
//! distribution point and so CRL numbers stay monotonic across restarts.
//!
//! # Compliance Mapping
//!
//! ## RFC Compliance
//! - RFC 5280 §5 - Certificate Revocation List storage
//! - RFC 5280 §5.2.3 - CRL number (monotonically increasing)
//!
//! ## NIST 800-53 Controls
//! - SC-17: PKI certificate status (CRL)
//! - AU-2: Audit/record CRL generation artifacts

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// CRL database model
///
/// Maps to the `crls` table (migration 00001).
///
/// RFC 5280 §5.1 - CertificateList fields persisted for serving and audit.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Crl {
    /// Unique identifier
    pub id: Uuid,

    /// Issuing CA identifier (FK ca_certificates)
    pub ca_id: Uuid,

    /// CRL number
    ///
    /// RFC 5280 §5.2.3 - Monotonically increasing per CA.
    pub crl_number: i64,

    /// thisUpdate time
    ///
    /// RFC 5280 §5.1.2.4
    pub this_update: DateTime<Utc>,

    /// nextUpdate time
    ///
    /// RFC 5280 §5.1.2.5
    pub next_update: DateTime<Utc>,

    /// DER-encoded signed CRL
    pub der_encoded: Vec<u8>,

    /// PEM-encoded signed CRL (for convenience)
    pub pem_encoded: String,

    /// Record creation timestamp
    pub created_at: DateTime<Utc>,
}
