//! Certificate chain building for path validation
//!
//! RFC 5280 §6.1 - Building certification paths
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §6.1: Path discovery and validation
//! - RFC 5280 §4.2.2.1: Authority Information Access (AIA)
//! - NIST 800-53 SC-17: PKI certificates

use super::error::{Result, ValidationError};
use super::trust_anchor::TrustAnchorStore;
use crate::parser::ParsedCertificate;

/// Certificate chain builder
///
/// RFC 5280 §6.1 - Builds certification paths from end-entity to trust anchor
pub struct PathBuilder {
    /// Trust anchor store
    trust_anchors: TrustAnchorStore,

    /// Maximum path length (prevent infinite loops)
    max_depth: usize,

    /// Enable AIA fetching (configurable per user requirement)
    /// Default: false for security
    enable_aia_fetching: bool,
}

impl PathBuilder {
    /// Create a new path builder
    pub fn new(trust_anchors: TrustAnchorStore) -> Self {
        Self {
            trust_anchors,
            max_depth: 10, // RFC recommended default
            enable_aia_fetching: false,
        }
    }

    /// Set maximum path depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Enable AIA (Authority Information Access) fetching
    ///
    /// User requirement: Make this configurable
    /// When enabled: Fetch intermediate certs from HTTP URLs
    /// Security: Only HTTPS, validate certs, 5s timeout
    pub fn with_aia_fetching(mut self, enabled: bool) -> Self {
        self.enable_aia_fetching = enabled;
        self
    }

    /// Build certificate chain from end-entity to trust anchor
    ///
    /// RFC 5280 §6.1.2 - Path discovery
    ///
    /// Returns: Vec of certificates from end entity (index 0) to root (last)
    /// Note: Trust anchor itself is not included in the returned chain
    pub fn build_path(&self, end_entity: &ParsedCertificate) -> Result<Vec<ParsedCertificate>> {
        let chain = vec![end_entity.clone()];
        let current_issuer_dn = &end_entity.issuer_dn;

        // Check if current cert is issued by a trust anchor
        let trust_anchors = self.trust_anchors.find_by_issuer(current_issuer_dn);

        if !trust_anchors.is_empty() {
            // Found trust anchor, path complete
            // Chain only contains end entity cert
            return Ok(chain);
        }

        // Check if current cert is self-signed (root without trust anchor)
        if current_issuer_dn == &chain.last().unwrap().subject_dn {
            return Err(ValidationError::TrustAnchorNotFound);
        }

        // TODO: Look up intermediate certificate
        // Phase 1: Stub implementation - no intermediate lookup
        // Phase 2+: Add database lookup for cached intermediates
        // If enable_aia_fetching: Parse AIA extension and fetch from URL
        // This will require iterative chain building with loop

        Err(ValidationError::PathBuildingFailed)
    }

    /// Get reference to trust anchor store
    pub fn trust_anchors(&self) -> &TrustAnchorStore {
        &self.trust_anchors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ParsedCertificate;
    use chrono::Utc;

    fn create_test_cert(subject: &str, issuer: &str) -> ParsedCertificate {
        ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: subject.to_string(),
            issuer_dn: issuer.to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key: vec![0x30, 0x82, 0x01, 0x22],
            signature: vec![0x00, 0x01, 0x02],
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            tbs_certificate: vec![],
            der_encoded: vec![],
            basic_constraints: None,
            key_usage: None,
            subject_alt_names: vec![],
        }
    }

    #[test]
    fn test_path_builder_new() {
        let store = TrustAnchorStore::new();
        let builder = PathBuilder::new(store);

        assert_eq!(builder.max_depth, 10);
        assert!(!builder.enable_aia_fetching);
    }

    #[test]
    fn test_path_builder_with_max_depth() {
        let store = TrustAnchorStore::new();
        let builder = PathBuilder::new(store).with_max_depth(5);

        assert_eq!(builder.max_depth, 5);
    }

    #[test]
    fn test_path_builder_with_aia_fetching() {
        let store = TrustAnchorStore::new();
        let builder = PathBuilder::new(store).with_aia_fetching(true);

        assert!(builder.enable_aia_fetching);
    }

    #[test]
    fn test_build_path_no_trust_anchor() {
        let store = TrustAnchorStore::new();
        let builder = PathBuilder::new(store);

        let cert = create_test_cert("CN=End Entity,O=OstrichPKI", "CN=Unknown CA,O=OstrichPKI");

        let result = builder.build_path(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_path_self_signed_without_trust() {
        let store = TrustAnchorStore::new();
        let builder = PathBuilder::new(store);

        // Self-signed certificate (subject == issuer)
        let cert = create_test_cert("CN=Self Signed,O=OstrichPKI", "CN=Self Signed,O=OstrichPKI");

        let result = builder.build_path(&cert);
        assert!(matches!(result, Err(ValidationError::TrustAnchorNotFound)));
    }

    #[test]
    fn test_build_path_with_trust_anchor() {
        use crate::validation::trust_anchor::TrustAnchor;

        let mut store = TrustAnchorStore::new();

        // Add trust anchor
        let anchor = TrustAnchor::new(
            "CN=Root CA,O=OstrichPKI".to_string(),
            vec![0x01, 0x02, 0x03],
            None,
        );
        store.add(anchor).unwrap();

        let builder = PathBuilder::new(store);

        // Certificate issued directly by trust anchor
        let cert = create_test_cert("CN=End Entity,O=OstrichPKI", "CN=Root CA,O=OstrichPKI");

        let result = builder.build_path(&cert);
        assert!(result.is_ok());

        let chain = result.unwrap();
        assert_eq!(chain.len(), 1); // Just the end entity (trust anchor not in chain)
        assert_eq!(chain[0].subject_dn, "CN=End Entity,O=OstrichPKI");
    }
}
