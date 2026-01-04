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
pub fn get_basic_constraints(cert: &ParsedCertificate) -> Result<Option<BasicConstraints>> {
    // Return parsed basic constraints from the certificate
    Ok(cert
        .basic_constraints
        .map(|(ca, path_len_constraint)| BasicConstraints {
            ca,
            path_len_constraint,
        }))
}

/// Extract Key Usage from certificate
///
/// RFC 5280 §4.2.1.3
pub fn get_key_usage(cert: &ParsedCertificate) -> Result<Option<KeyUsage>> {
    // Return parsed key usage from the certificate
    Ok(cert.key_usage.as_ref().map(|usages| KeyUsage {
        digital_signature: usages.contains(&"digitalSignature".to_string()),
        non_repudiation: usages.contains(&"nonRepudiation".to_string()),
        key_encipherment: usages.contains(&"keyEncipherment".to_string()),
        data_encipherment: usages.contains(&"dataEncipherment".to_string()),
        key_agreement: usages.contains(&"keyAgreement".to_string()),
        key_cert_sign: usages.contains(&"keyCertSign".to_string()),
        crl_sign: usages.contains(&"cRLSign".to_string()),
        encipher_only: usages.contains(&"encipherOnly".to_string()),
        decipher_only: usages.contains(&"decipherOnly".to_string()),
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
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            tbs_certificate: vec![],
            der_encoded: vec![],
            basic_constraints: None,
            key_usage: None,
            subject_alt_names: vec![],
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
        // Test cert has no key usage extension, so should return None
        assert!(result.unwrap().is_none());
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
