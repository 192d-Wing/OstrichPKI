//! Name constraints processing for path validation
//!
//! RFC 5280 §4.2.1.10 - Name Constraints
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §4.2.1.10: Name constraints extension
//! - RFC 5280 §6.1.3(e): Name constraints checking
//! - NIAP PP-CA FDP_CER_EXT.1: Certificate validation

use super::error::Result;
use crate::parser::ParsedCertificate;

/// Name constraints
///
/// RFC 5280 §4.2.1.10 - Name Constraints Extension
#[derive(Debug, Clone)]
pub struct NameConstraints {
    /// Permitted subtrees
    pub permitted_subtrees: Vec<GeneralSubtree>,

    /// Excluded subtrees
    pub excluded_subtrees: Vec<GeneralSubtree>,
}

/// General subtree for name constraints
///
/// RFC 5280 §4.2.1.10
#[derive(Debug, Clone)]
pub struct GeneralSubtree {
    /// Base (DNS, IP, email, etc.)
    pub base: String,

    /// Minimum (default 0)
    pub minimum: u32,

    /// Maximum (optional)
    pub maximum: Option<u32>,
}

impl NameConstraints {
    /// Create new name constraints
    pub fn new() -> Self {
        Self {
            permitted_subtrees: Vec::new(),
            excluded_subtrees: Vec::new(),
        }
    }

    /// Add permitted subtree
    pub fn add_permitted(&mut self, subtree: GeneralSubtree) {
        self.permitted_subtrees.push(subtree);
    }

    /// Add excluded subtree
    pub fn add_excluded(&mut self, subtree: GeneralSubtree) {
        self.excluded_subtrees.push(subtree);
    }

    /// Check if a name is permitted
    ///
    /// RFC 5280 §6.1.3(e) - Name constraints checking
    pub fn is_permitted(&self, _name: &str) -> bool {
        // TODO: Phase 3 - Implement name matching logic
        // For DNS: subdomain matching
        // For IP: subnet matching
        // For email: domain matching
        true
    }

    /// Check if a name is excluded
    ///
    /// RFC 5280 §6.1.3(e) - Name constraints checking
    pub fn is_excluded(&self, _name: &str) -> bool {
        // TODO: Phase 3 - Implement name matching logic
        false
    }
}

impl Default for NameConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Check name constraints for certificate
///
/// RFC 5280 §6.1.3(e)
pub fn check_name_constraints(
    _cert: &ParsedCertificate,
    _constraints: &NameConstraints,
) -> Result<()> {
    // TODO: Phase 3 - Extract names from certificate (subject DN, SANs)
    // and check against constraints
    // For now, stub implementation that allows all

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_constraints_new() {
        let nc = NameConstraints::new();
        assert!(nc.permitted_subtrees.is_empty());
        assert!(nc.excluded_subtrees.is_empty());
    }

    #[test]
    fn test_add_permitted_subtree() {
        let mut nc = NameConstraints::new();
        nc.add_permitted(GeneralSubtree {
            base: "DNS:.example.com".to_string(),
            minimum: 0,
            maximum: None,
        });

        assert_eq!(nc.permitted_subtrees.len(), 1);
        assert_eq!(nc.permitted_subtrees[0].base, "DNS:.example.com");
    }

    #[test]
    fn test_add_excluded_subtree() {
        let mut nc = NameConstraints::new();
        nc.add_excluded(GeneralSubtree {
            base: "DNS:.bad.example.com".to_string(),
            minimum: 0,
            maximum: None,
        });

        assert_eq!(nc.excluded_subtrees.len(), 1);
    }

    #[test]
    fn test_is_permitted() {
        let nc = NameConstraints::new();
        assert!(nc.is_permitted("DNS:www.example.com"));
    }

    #[test]
    fn test_is_excluded() {
        let nc = NameConstraints::new();
        assert!(!nc.is_excluded("DNS:www.example.com"));
    }

    #[test]
    fn test_check_name_constraints() {
        use chrono::Utc;

        let cert = ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=CA".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key: vec![],
            signature: vec![],
            der_encoded: vec![],
        };

        let nc = NameConstraints::new();
        let result = check_name_constraints(&cert, &nc);
        assert!(result.is_ok());
    }
}
