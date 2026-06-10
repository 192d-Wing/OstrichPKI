//! CA key and CA certificate models
//!
//! These map to the `ca_keys` and `ca_certificates` tables (migration 00001)
//! and are used to bootstrap a running CertificateAuthority: the key row
//! carries everything needed to reconstruct a crypto-provider KeyHandle, and
//! the certificate row carries the CA's own X.509 certificate.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: SC-28 (Protection of Information at Rest) - key material
//!   itself is never stored here, only the provider reference
//! - NIAP PP-CA: FCS_STG_EXT.1 - provider_type records HSM vs software storage
//! - RFC 5280 §4.1 - CA certificate fields

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// CA signing key reference
///
/// Holds the provider-specific reference to a CA private key. The key
/// material lives in the crypto provider (PKCS#11 HSM or software store);
/// this row only records how to address it.
#[derive(Debug, Clone, FromRow)]
pub struct CaKey {
    pub id: Uuid,
    /// Human-readable unique label (e.g. "root-ca-2026")
    pub label: String,
    /// Key type name matching ostrich_crypto::KeyType (e.g. "EcP384")
    pub key_type: String,
    /// Algorithm name matching ostrich_crypto::Algorithm (e.g. "EcdsaP384Sha384")
    pub algorithm: String,
    /// Provider type: "Pkcs11" or "Software"
    pub provider_type: String,
    /// PKCS#11 slot id (None for software keys)
    pub provider_slot_id: Option<i64>,
    /// Provider-specific key identifier (CKA_ID for PKCS#11)
    pub key_id: Vec<u8>,
    /// Whether the key was created extractable (must be false for CA keys,
    /// NIAP PP-CA FCS_STG_EXT.1)
    pub extractable: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// CA certificate
///
/// The CA's own X.509 certificate (root or subordinate).
#[derive(Debug, Clone, FromRow)]
pub struct CaCertificate {
    pub id: Uuid,
    /// Reference to the ca_keys row for the matching private key
    pub ca_key_id: Uuid,
    /// RFC 5280 §4.1.2.2 - serial number (DER integer bytes)
    pub serial_number: Vec<u8>,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub der_encoded: Vec<u8>,
    pub pem_encoded: String,
    /// True for self-signed root CAs
    pub is_root: bool,
    /// Issuing CA for subordinates (None for roots)
    pub parent_ca_id: Option<Uuid>,
    /// RFC 5280 §4.2.1.9 - basicConstraints pathLenConstraint
    pub path_len_constraint: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_key_construction() {
        let key = CaKey {
            id: Uuid::new_v4(),
            label: "root-ca-2026".to_string(),
            key_type: "EcP384".to_string(),
            algorithm: "EcdsaP384Sha384".to_string(),
            provider_type: "Pkcs11".to_string(),
            provider_slot_id: Some(0),
            key_id: vec![1, 2, 3, 4],
            extractable: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(!key.extractable, "CA keys must be non-extractable");
        assert_eq!(key.provider_type, "Pkcs11");
    }

    #[test]
    fn ca_certificate_root_has_no_parent() {
        let now = Utc::now();
        let cert = CaCertificate {
            id: Uuid::new_v4(),
            ca_key_id: Uuid::new_v4(),
            serial_number: vec![1],
            subject_dn: "CN=Ostrich Root CA".to_string(),
            issuer_dn: "CN=Ostrich Root CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(3650),
            der_encoded: vec![0x30],
            pem_encoded: "-----BEGIN CERTIFICATE-----".to_string(),
            is_root: true,
            parent_ca_id: None,
            path_len_constraint: Some(1),
            created_at: now,
            updated_at: now,
        };
        assert!(cert.is_root);
        assert!(cert.parent_ca_id.is_none());
        assert_eq!(cert.subject_dn, cert.issuer_dn);
    }
}
