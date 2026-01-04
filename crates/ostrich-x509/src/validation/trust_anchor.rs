//! Trust anchor management for certificate path validation
//!
//! RFC 5280 §6.1.1(d) - Trust anchor information
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §6.1.1(d): Trust anchor information
//! - NIST 800-53 SC-12: Cryptographic key management (trust anchors)
//! - NIAP PP-CA FMT_SMF.1: Security management functions

use super::error::{Result, ValidationError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Trust anchor (trusted root CA certificate)
///
/// RFC 5280 §6.1.1(d)(1) - Trust anchor information consists of:
/// - Trust anchor name
/// - Trust anchor public key
/// - Optionally: name constraints, certificate policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Unique identifier for this trust anchor
    pub id: Uuid,

    /// Subject distinguished name (RFC 5280 §4.1.2.6)
    pub subject_dn: String,

    /// Subject public key info (DER-encoded SPKI)
    /// RFC 5280 §4.1.2.7
    pub subject_public_key: Vec<u8>,

    /// Subject key identifier (SHA-256 hash of public key)
    /// RFC 5280 §4.2.1.2
    pub subject_key_identifier: Option<Vec<u8>>,

    /// Original certificate DER (optional, for convenience)
    pub certificate_der: Option<Vec<u8>>,

    /// Name constraints (if any)
    /// RFC 5280 §4.2.1.10
    pub name_constraints: Option<String>, // JSON-serialized NameConstraints

    /// Trusted for these certificate policies (empty = any-policy)
    /// RFC 5280 §6.1.1(c)
    pub trust_policies: Vec<String>, // OIDs

    /// When this trust anchor was added
    pub created_at: DateTime<Utc>,

    /// Human-readable description
    pub description: Option<String>,
}

impl TrustAnchor {
    /// Create a new trust anchor
    pub fn new(
        subject_dn: String,
        subject_public_key: Vec<u8>,
        certificate_der: Option<Vec<u8>>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            subject_dn,
            subject_public_key,
            subject_key_identifier: None,
            certificate_der,
            name_constraints: None,
            trust_policies: Vec::new(),
            created_at: Utc::now(),
            description: None,
        }
    }

    /// Set subject key identifier
    pub fn with_subject_key_identifier(mut self, ski: Vec<u8>) -> Self {
        self.subject_key_identifier = Some(ski);
        self
    }

    /// Set name constraints
    pub fn with_name_constraints(mut self, constraints: String) -> Self {
        self.name_constraints = Some(constraints);
        self
    }

    /// Set trust policies
    pub fn with_trust_policies(mut self, policies: Vec<String>) -> Self {
        self.trust_policies = policies;
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: String) -> Self {
        self.description = Some(desc);
        self
    }
}

/// Trust anchor store (in-memory, will be database-backed in full implementation)
///
/// NIST 800-53 SC-12: Cryptographic key management
/// NIAP PP-CA FMT_SMF.1: Security management functions
#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    /// Create a new empty trust anchor store
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Add a trust anchor to the store
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA FMT_SMF.1: Security management functions
    pub fn add(&mut self, anchor: TrustAnchor) -> Result<Uuid> {
        let id = anchor.id;
        self.anchors.push(anchor);
        Ok(id)
    }

    /// Remove a trust anchor by ID
    ///
    /// COMPLIANCE MAPPING:
    /// - NIAP PP-CA FMT_SMF.1: Security management functions
    pub fn remove(&mut self, id: Uuid) -> Result<()> {
        let initial_len = self.anchors.len();
        self.anchors.retain(|anchor| anchor.id != id);

        if self.anchors.len() == initial_len {
            return Err(ValidationError::TrustAnchorNotFound);
        }

        Ok(())
    }

    /// Find trust anchors by issuer DN
    ///
    /// RFC 5280 §6.1.2 - Locate trust anchor for certificate
    pub fn find_by_issuer(&self, issuer_dn: &str) -> Vec<&TrustAnchor> {
        self.anchors
            .iter()
            .filter(|anchor| anchor.subject_dn == issuer_dn)
            .collect()
    }

    /// Find trust anchor by subject key identifier
    ///
    /// RFC 5280 §4.2.1.1 - Authority Key Identifier matching
    pub fn find_by_subject_key_identifier(&self, ski: &[u8]) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|anchor| {
            anchor
                .subject_key_identifier
                .as_ref()
                .map(|s| s.as_slice() == ski)
                .unwrap_or(false)
        })
    }

    /// Get trust anchor by ID
    pub fn get(&self, id: Uuid) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|anchor| anchor.id == id)
    }

    /// List all trust anchors
    pub fn list_all(&self) -> Vec<&TrustAnchor> {
        self.anchors.iter().collect()
    }

    /// Count of trust anchors
    pub fn count(&self) -> usize {
        self.anchors.len()
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_trust_anchor() {
        let anchor = TrustAnchor::new(
            "CN=Test Root CA,O=OstrichPKI".to_string(),
            vec![0x30, 0x82, 0x01, 0x22], // Mock SPKI
            None,
        )
        .with_description("Test root CA".to_string());

        assert_eq!(anchor.subject_dn, "CN=Test Root CA,O=OstrichPKI");
        assert_eq!(anchor.subject_public_key, vec![0x30, 0x82, 0x01, 0x22]);
        assert_eq!(anchor.description, Some("Test root CA".to_string()));
        assert!(anchor.trust_policies.is_empty());
    }

    #[test]
    fn test_trust_anchor_store_add_and_find() {
        let mut store = TrustAnchorStore::new();

        let anchor1 = TrustAnchor::new(
            "CN=Root CA 1,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );

        let anchor2 = TrustAnchor::new(
            "CN=Root CA 2,O=OstrichPKI".to_string(),
            vec![0x04, 0x05, 0x06],
            None,
        );

        let id1 = store.add(anchor1).unwrap();
        let id2 = store.add(anchor2).unwrap();

        assert_eq!(store.count(), 2);
        assert!(store.get(id1).is_some());
        assert!(store.get(id2).is_some());
    }

    #[test]
    fn test_trust_anchor_store_find_by_issuer() {
        let mut store = TrustAnchorStore::new();

        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );

        store.add(anchor).unwrap();

        let found = store.find_by_issuer("CN=Root CA,O=OstrichPKI");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject_dn, "CN=Root CA,O=OstrichPKI");

        let not_found = store.find_by_issuer("CN=Unknown CA");
        assert_eq!(not_found.len(), 0);
    }

    #[test]
    fn test_trust_anchor_store_find_by_ski() {
        let mut store = TrustAnchorStore::new();

        let ski = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        )
        .with_subject_key_identifier(ski.clone());

        store.add(anchor).unwrap();

        let found = store.find_by_subject_key_identifier(&ski);
        assert!(found.is_some());
        assert_eq!(found.unwrap().subject_dn, "CN=Root CA,O=OstrichPKI");

        let not_found = store.find_by_subject_key_identifier(&[0xff, 0xff]);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_trust_anchor_store_remove() {
        let mut store = TrustAnchorStore::new();

        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );

        let id = store.add(anchor).unwrap();
        assert_eq!(store.count(), 1);

        store.remove(id).unwrap();
        assert_eq!(store.count(), 0);

        // Removing non-existent anchor should fail
        let result = store.remove(Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn test_trust_anchor_with_policies() {
        let policies = vec![
            "2.5.29.32.0".to_string(), // any-policy
            "1.2.3.4.5.6".to_string(), // custom policy
        ];

        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        )
        .with_trust_policies(policies.clone());

        assert_eq!(anchor.trust_policies, policies);
    }
}
