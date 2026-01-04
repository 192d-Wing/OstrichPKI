//! Certificate policy processing for path validation
//!
//! RFC 5280 §6.1.1 - Policy Processing
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §6.1.1: User-initial-policy-set
//! - RFC 5280 §6.1.5: Wrap-up procedure for policies
//! - NIAP PP-CA FDP_CER_EXT.1: Certificate validation

use super::error::Result;
use crate::parser::ParsedCertificate;

/// Certificate policy tree node
///
/// RFC 5280 §6.1.2(e) - Valid policy tree
#[derive(Debug, Clone)]
pub struct PolicyNode {
    /// Valid policy OID
    pub valid_policy: String,

    /// Policy qualifiers
    pub qualifier_set: Vec<String>,

    /// Expected policy set
    pub expected_policy_set: Vec<String>,

    /// Child nodes
    pub children: Vec<PolicyNode>,
}

/// Policy tree for path validation
///
/// RFC 5280 §6.1.2(e) - Valid policy tree state variable
#[derive(Debug, Clone)]
pub struct PolicyTree {
    /// Root node (any-policy)
    root: Option<PolicyNode>,
}

impl PolicyTree {
    /// Create new policy tree
    ///
    /// RFC 5280 §6.1.2(e) - Initialize with any-policy
    pub fn new() -> Self {
        Self {
            root: Some(PolicyNode {
                valid_policy: "2.5.29.32.0".to_string(), // any-policy OID
                qualifier_set: Vec::new(),
                expected_policy_set: vec!["2.5.29.32.0".to_string()],
                children: Vec::new(),
            }),
        }
    }

    /// Process certificate policies for a certificate
    ///
    /// RFC 5280 §6.1.3(f) - Policy processing
    ///
    /// User requirement: Start with simplified "any-policy" mode
    /// Future enhancement: Full policy tree construction
    pub fn process_certificate_policies(
        &mut self,
        _cert: &ParsedCertificate,
        _depth: usize,
    ) -> Result<()> {
        // TODO: Phase 3 - Implement full policy tree processing
        // For MVP: Accept any-policy (simplified mode)
        // Future: Parse certificatePolicies extension and build tree

        Ok(())
    }

    /// Check if policy tree is valid
    ///
    /// RFC 5280 §6.1.5(g) - Wrap-up procedure
    pub fn is_valid(&self) -> bool {
        self.root.is_some()
    }

    /// Get root node
    pub fn root(&self) -> Option<&PolicyNode> {
        self.root.as_ref()
    }
}

impl Default for PolicyTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_tree_new() {
        let tree = PolicyTree::new();
        assert!(tree.is_valid());
        assert!(tree.root().is_some());

        let root = tree.root().unwrap();
        assert_eq!(root.valid_policy, "2.5.29.32.0"); // any-policy
    }

    #[test]
    fn test_process_certificate_policies() {
        use chrono::Utc;

        let mut tree = PolicyTree::new();

        let cert = ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=CA".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key: vec![],
            signature: vec![],
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            tbs_certificate: vec![],
            der_encoded: vec![],
            basic_constraints: None,
            key_usage: None,
            subject_alt_names: vec![],
        };

        let result = tree.process_certificate_policies(&cert, 0);
        assert!(result.is_ok());
        assert!(tree.is_valid());
    }

    #[test]
    fn test_policy_node_creation() {
        let node = PolicyNode {
            valid_policy: "1.2.3.4.5".to_string(),
            qualifier_set: vec!["qualifier1".to_string()],
            expected_policy_set: vec!["1.2.3.4.5".to_string()],
            children: Vec::new(),
        };

        assert_eq!(node.valid_policy, "1.2.3.4.5");
        assert_eq!(node.qualifier_set.len(), 1);
        assert!(node.children.is_empty());
    }
}
