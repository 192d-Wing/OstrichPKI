//! Certificate profiles and templates
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - RFC 5280 §4.2: Certificate extensions
//!
//! ## NIST 800-53 Rev 5
//! - CM-2: Baseline configuration
//! - SC-17: PKI certificates
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_MSA.1: Management of security attributes
//! - FDP_IFC.1: Information flow control (certificate policies)

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Certificate profile types
///
/// RFC 5280 §4.2.1.9 - Basic constraints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileType {
    /// Root CA certificate
    ///
    /// RFC 5280 §4.2.1.9 - CA:TRUE, no path length constraint
    RootCa,

    /// Intermediate CA certificate
    ///
    /// RFC 5280 §4.2.1.9 - CA:TRUE, path length constraint
    IntermediateCa,

    /// TLS server certificate
    ///
    /// RFC 5280 §4.2.1.12 - serverAuth extended key usage
    TlsServer,

    /// TLS client certificate
    ///
    /// RFC 5280 §4.2.1.12 - clientAuth extended key usage
    TlsClient,

    /// Code signing certificate
    ///
    /// RFC 5280 §4.2.1.12 - codeSigning extended key usage
    CodeSigning,

    /// Email protection certificate (S/MIME)
    ///
    /// RFC 5280 §4.2.1.12 - emailProtection extended key usage
    EmailProtection,

    /// OCSP signing certificate
    ///
    /// RFC 6960 §4.2.2.2 - id-kp-OCSPSigning
    OcspSigning,

    /// Smartcard authentication certificate
    ///
    /// For PIV/CAC cards
    SmartcardAuth,

    /// Custom profile
    Custom,
}

impl ProfileType {
    /// Get the profile name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfileType::RootCa => "root_ca",
            ProfileType::IntermediateCa => "intermediate_ca",
            ProfileType::TlsServer => "tls_server",
            ProfileType::TlsClient => "tls_client",
            ProfileType::CodeSigning => "code_signing",
            ProfileType::EmailProtection => "email_protection",
            ProfileType::OcspSigning => "ocsp_signing",
            ProfileType::SmartcardAuth => "smartcard_auth",
            ProfileType::Custom => "custom",
        }
    }

    /// Check if this is a CA profile
    pub fn is_ca(&self) -> bool {
        matches!(self, ProfileType::RootCa | ProfileType::IntermediateCa)
    }
}

/// Key usage flags
///
/// RFC 5280 §4.2.1.3 - Key usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyUsage {
    /// Digital signature
    DigitalSignature,
    /// Non-repudiation (content commitment)
    NonRepudiation,
    /// Key encipherment
    KeyEncipherment,
    /// Data encipherment
    DataEncipherment,
    /// Key agreement
    KeyAgreement,
    /// Certificate signing
    KeyCertSign,
    /// CRL signing
    CrlSign,
    /// Encipher only
    EncipherOnly,
    /// Decipher only
    DecipherOnly,
}

/// Extended key usage purposes
///
/// RFC 5280 §4.2.1.12 - Extended key usage
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtendedKeyUsage {
    /// TLS server authentication
    ServerAuth,
    /// TLS client authentication
    ClientAuth,
    /// Code signing
    CodeSigning,
    /// Email protection
    EmailProtection,
    /// Time stamping
    TimeStamping,
    /// OCSP signing
    OcspSigning,
    /// Custom OID
    Custom(String),
}

impl ExtendedKeyUsage {
    /// Get the OID for this extended key usage
    pub fn oid(&self) -> &str {
        match self {
            ExtendedKeyUsage::ServerAuth => "1.3.6.1.5.5.7.3.1",
            ExtendedKeyUsage::ClientAuth => "1.3.6.1.5.5.7.3.2",
            ExtendedKeyUsage::CodeSigning => "1.3.6.1.5.5.7.3.3",
            ExtendedKeyUsage::EmailProtection => "1.3.6.1.5.5.7.3.4",
            ExtendedKeyUsage::TimeStamping => "1.3.6.1.5.5.7.3.8",
            ExtendedKeyUsage::OcspSigning => "1.3.6.1.5.5.7.3.9",
            ExtendedKeyUsage::Custom(oid) => oid,
        }
    }
}

/// Certificate profile configuration
///
/// Defines the structure and constraints for certificate issuance
///
/// NIST 800-53: CM-2 - Baseline configuration for certificate types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProfile {
    /// Profile name
    pub name: String,

    /// Profile type
    pub profile_type: ProfileType,

    /// Description
    pub description: Option<String>,

    /// Validity period in days
    ///
    /// RFC 5280 §4.1.2.5 - Validity
    pub validity_days: u32,

    /// Key type (e.g., "rsa_2048", "ec_p256", "ml_dsa_65")
    pub key_type: String,

    /// Signature algorithm (e.g., "rsa_pkcs1_sha256", "ecdsa_p256_sha256")
    pub algorithm: String,

    /// Key usage flags
    ///
    /// RFC 5280 §4.2.1.3 - Key usage (critical)
    pub key_usage: Vec<KeyUsage>,

    /// Extended key usage purposes
    ///
    /// RFC 5280 §4.2.1.12 - Extended key usage
    pub extended_key_usage: Vec<ExtendedKeyUsage>,

    /// Basic constraints - is CA
    ///
    /// RFC 5280 §4.2.1.9 - Basic constraints (critical)
    pub basic_constraints_ca: bool,

    /// Basic constraints - path length constraint
    ///
    /// RFC 5280 §4.2.1.9 - Maximum CA depth
    pub basic_constraints_path_len: Option<u8>,

    /// Subject Alternative Name required
    ///
    /// RFC 5280 §4.2.1.6 - Subject alternative name
    pub subject_alt_name_required: bool,

    /// Custom extensions (OID -> value)
    pub custom_extensions: HashMap<String, Vec<u8>>,
}

impl CertificateProfile {
    /// Create a new certificate profile
    pub fn new(
        name: impl Into<String>,
        profile_type: ProfileType,
        validity_days: u32,
        key_type: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            profile_type,
            description: None,
            validity_days,
            key_type: key_type.into(),
            algorithm: algorithm.into(),
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            basic_constraints_ca: profile_type.is_ca(),
            basic_constraints_path_len: None,
            subject_alt_name_required: false,
            custom_extensions: HashMap::new(),
        }
    }

    /// Create a Root CA profile
    ///
    /// RFC 5280 §4.2.1.9 - Self-signed CA certificate
    pub fn root_ca(validity_days: u32) -> Self {
        let mut profile = Self::new(
            "Root CA",
            ProfileType::RootCa,
            validity_days,
            "rsa_4096",
            "rsa_pss_sha384",
        );
        profile.key_usage = vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign];
        profile.basic_constraints_ca = true;
        profile.basic_constraints_path_len = None; // No constraint for root
        profile
    }

    /// Create an Intermediate CA profile
    ///
    /// RFC 5280 §4.2.1.9 - Subordinate CA certificate
    pub fn intermediate_ca(validity_days: u32, path_len: u8) -> Self {
        let mut profile = Self::new(
            "Intermediate CA",
            ProfileType::IntermediateCa,
            validity_days,
            "rsa_3072",
            "rsa_pss_sha256",
        );
        profile.key_usage = vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign];
        profile.basic_constraints_ca = true;
        profile.basic_constraints_path_len = Some(path_len);
        profile
    }

    /// Create a TLS Server profile
    ///
    /// RFC 5280 §4.2.1.12 - serverAuth
    pub fn tls_server(validity_days: u32) -> Self {
        let mut profile = Self::new(
            "TLS Server",
            ProfileType::TlsServer,
            validity_days,
            "ec_p256",
            "ecdsa_p256_sha256",
        );
        profile.key_usage = vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment];
        profile.extended_key_usage = vec![ExtendedKeyUsage::ServerAuth];
        profile.subject_alt_name_required = true; // RFC 6125 - DNS names required
        profile
    }

    /// Create a TLS Client profile
    ///
    /// RFC 5280 §4.2.1.12 - clientAuth
    pub fn tls_client(validity_days: u32) -> Self {
        let mut profile = Self::new(
            "TLS Client",
            ProfileType::TlsClient,
            validity_days,
            "ec_p256",
            "ecdsa_p256_sha256",
        );
        profile.key_usage = vec![KeyUsage::DigitalSignature];
        profile.extended_key_usage = vec![ExtendedKeyUsage::ClientAuth];
        profile
    }

    /// Create a Code Signing profile
    pub fn code_signing(validity_days: u32) -> Self {
        let mut profile = Self::new(
            "Code Signing",
            ProfileType::CodeSigning,
            validity_days,
            "rsa_3072",
            "rsa_pss_sha256",
        );
        profile.key_usage = vec![KeyUsage::DigitalSignature];
        profile.extended_key_usage = vec![ExtendedKeyUsage::CodeSigning];
        profile
    }

    /// Create an OCSP Signing profile
    ///
    /// RFC 6960 §4.2.2.2 - Delegated OCSP responder
    pub fn ocsp_signing(validity_days: u32) -> Self {
        let mut profile = Self::new(
            "OCSP Signing",
            ProfileType::OcspSigning,
            validity_days,
            "ec_p256",
            "ecdsa_p256_sha256",
        );
        profile.key_usage = vec![KeyUsage::DigitalSignature];
        profile.extended_key_usage = vec![ExtendedKeyUsage::OcspSigning];
        profile
    }

    /// Validate the profile configuration
    ///
    /// NIST 800-53: CM-2 - Configuration validation
    pub fn validate(&self) -> Result<()> {
        // Validate CA profiles
        if self.basic_constraints_ca && !self.key_usage.contains(&KeyUsage::KeyCertSign) {
            return Err(Error::ProfileValidation(
                "CA certificates must have keyCertSign".to_string(),
            ));
        }

        // Validate key usage is not empty
        if self.key_usage.is_empty() && self.extended_key_usage.is_empty() {
            return Err(Error::ProfileValidation(
                "Profile must have at least one key usage or extended key usage".to_string(),
            ));
        }

        // Validate validity period
        if self.validity_days == 0 {
            return Err(Error::ProfileValidation(
                "Validity period must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Add key usage
    pub fn with_key_usage(mut self, usage: KeyUsage) -> Self {
        if !self.key_usage.contains(&usage) {
            self.key_usage.push(usage);
        }
        self
    }

    /// Add extended key usage
    pub fn with_extended_key_usage(mut self, usage: ExtendedKeyUsage) -> Self {
        if !self.extended_key_usage.contains(&usage) {
            self.extended_key_usage.push(usage);
        }
        self
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_ca_profile() {
        let profile = CertificateProfile::root_ca(3650);
        assert_eq!(profile.profile_type, ProfileType::RootCa);
        assert!(profile.basic_constraints_ca);
        assert!(profile.basic_constraints_path_len.is_none());
        assert!(profile.key_usage.contains(&KeyUsage::KeyCertSign));
        assert!(profile.key_usage.contains(&KeyUsage::CrlSign));
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_intermediate_ca_profile() {
        let profile = CertificateProfile::intermediate_ca(1825, 0);
        assert_eq!(profile.profile_type, ProfileType::IntermediateCa);
        assert!(profile.basic_constraints_ca);
        assert_eq!(profile.basic_constraints_path_len, Some(0));
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_tls_server_profile() {
        let profile = CertificateProfile::tls_server(365);
        assert_eq!(profile.profile_type, ProfileType::TlsServer);
        assert!(!profile.basic_constraints_ca);
        assert!(profile.subject_alt_name_required);
        assert!(
            profile
                .extended_key_usage
                .contains(&ExtendedKeyUsage::ServerAuth)
        );
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_profile_validation_ca_without_keycertsign() {
        let mut profile = CertificateProfile::root_ca(365);
        profile.key_usage.clear();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_profile_validation_no_key_usage() {
        let mut profile = CertificateProfile::new(
            "Test",
            ProfileType::Custom,
            365,
            "ec_p256",
            "ecdsa_p256_sha256",
        );
        profile.basic_constraints_ca = false;
        assert!(profile.validate().is_err());
    }
}
