//! Extension validation helpers for path validation
//!
//! RFC 5280 §4.2 - Standard Extensions
//!
//! COMPLIANCE MAPPING:
//! - RFC 5280 §4.2: Certificate extensions
//! - RFC 5280 §6.1.3(g): Unknown critical extension processing

use super::error::Result;
use crate::parser::ParsedCertificate;

/// Basic Constraints extension data
///
/// RFC 5280 §4.2.1.9
#[derive(Debug, Clone)]
pub struct BasicConstraints {
    /// Is this a CA certificate?
    pub ca: bool,

    /// Path length constraint (None = no constraint)
    pub path_len_constraint: Option<u32>,
}

/// Key Usage flags
///
/// RFC 5280 §4.2.1.3
#[derive(Debug, Clone)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl KeyUsage {
    /// Check if keyCertSign is set (required for CA certificates)
    ///
    /// RFC 5280 §6.1.3(l)
    pub fn has_key_cert_sign(&self) -> bool {
        self.key_cert_sign
    }
}

/// Check for unknown critical extensions
///
/// RFC 5280 §6.1.3(g) - If a certificate contains a critical extension
/// that is not recognized, the implementation MUST reject the certificate.
pub fn check_unknown_critical_extensions(_cert: &ParsedCertificate) -> Result<()> {
    // TODO: Phase 2 - Parse extensions from DER and check critical flag
    // Known critical extensions: basicConstraints, keyUsage, policyConstraints, etc.
    // For now, stub implementation that accepts all

    Ok(())
}

/// Extract Basic Constraints from certificate
///
/// RFC 5280 §4.2.1.9
pub fn get_basic_constraints(_cert: &ParsedCertificate) -> Result<Option<BasicConstraints>> {
    // TODO: Phase 2 - Parse basicConstraints extension from DER
    // For now, stub that returns None (no constraints)

    Ok(None)
}

/// Extract Key Usage from certificate
///
/// RFC 5280 §4.2.1.3
pub fn get_key_usage(_cert: &ParsedCertificate) -> Result<Option<KeyUsage>> {
    // TODO: Phase 2 - Parse keyUsage extension from DER
    // For now, stub that returns all usages enabled

    Ok(Some(KeyUsage {
        digital_signature: true,
        non_repudiation: true,
        key_encipherment: true,
        data_encipherment: true,
        key_agreement: true,
        key_cert_sign: true,
        crl_sign: true,
        encipher_only: false,
        decipher_only: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_cert() -> ParsedCertificate {
        ParsedCertificate {
            serial_number: vec![0x01],
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=Issuer".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            public_key: vec![0x30, 0x82],
            signature: vec![0x00, 0x01],
            der_encoded: vec![],
        }
    }

    #[test]
    fn test_check_unknown_critical_extensions() {
        let cert = create_test_cert();
        let result = check_unknown_critical_extensions(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_basic_constraints() {
        let cert = create_test_cert();
        let result = get_basic_constraints(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_key_usage() {
        let cert = create_test_cert();
        let result = get_key_usage(&cert);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_key_usage_has_key_cert_sign() {
        let ku = KeyUsage {
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: true,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        };

        assert!(ku.has_key_cert_sign());
    }
}
