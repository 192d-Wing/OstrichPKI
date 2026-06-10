//! Secure Defaults Module
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FMT_MSA.1.2 (Management of Security Attributes)
//! - NIAP PP-CA: FMT_SMF.1 (Specification of Management Functions)
//! - NIST 800-53: CM-2 (Baseline Configuration)
//! - NIST 800-53: CM-6 (Configuration Settings)
//!
//! This module enforces secure default values for certificate issuance
//! and CA configuration as required by NIAP PP-CA v2.1.

use crate::profile::{CertificateProfile, KeyUsage, ProfileType};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Minimum RSA key size in bits per NIST SP 800-57
/// NIAP PP-CA: FCS_CKM.1 - Minimum key sizes
pub const MIN_RSA_KEY_SIZE: u32 = 2048;

/// Minimum EC key size in bits per NIST SP 800-57
pub const MIN_EC_KEY_SIZE: u32 = 256;

/// Maximum certificate validity in days for end-entity certificates
/// NIAP PP-CA: FMT_SMF.1 - Certificate lifecycle management
pub const MAX_END_ENTITY_VALIDITY_DAYS: u32 = 825; // ~27 months per CA/Browser Forum

/// Maximum certificate validity in days for CA certificates
pub const MAX_CA_VALIDITY_DAYS: u32 = 7300; // 20 years for root CAs

/// Minimum validity period in days
pub const MIN_VALIDITY_DAYS: u32 = 1;

/// Default certificate validity for end-entity certificates
pub const DEFAULT_END_ENTITY_VALIDITY_DAYS: u32 = 365;

/// Default certificate validity for CA certificates
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 3650;

/// Secure default configuration for CA operations
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FMT_MSA.1.2 - Default values for security attributes
/// - NIST 800-53: CM-6 - Secure configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureDefaults {
    /// Minimum RSA key size in bits
    pub min_rsa_key_size: u32,

    /// Minimum EC key size in bits
    pub min_ec_key_size: u32,

    /// Maximum end-entity certificate validity (days)
    pub max_end_entity_validity_days: u32,

    /// Maximum CA certificate validity (days)
    pub max_ca_validity_days: u32,

    /// Default end-entity certificate validity (days)
    pub default_end_entity_validity_days: u32,

    /// Default CA certificate validity (days)
    pub default_ca_validity_days: u32,

    /// Require CRL distribution points in certificates
    pub require_crl_distribution_points: bool,

    /// Require Authority Information Access extension
    pub require_aia: bool,

    /// Require Subject Alternative Name for TLS certificates
    pub require_san_for_tls: bool,

    /// Allowed signature algorithms
    pub allowed_signature_algorithms: Vec<String>,

    /// Allowed key types
    pub allowed_key_types: Vec<String>,

    /// Prohibited extended key usages
    pub prohibited_ekus: HashSet<String>,

    /// Maximum path length for subordinate CAs
    pub max_path_length: u8,

    /// Enforce critical extensions
    pub enforce_critical_extensions: bool,

    /// Require unique serial numbers
    pub require_unique_serial: bool,
}

impl Default for SecureDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureDefaults {
    /// Create new secure defaults with NIAP-compliant values
    ///
    /// NIAP PP-CA: FMT_MSA.1.2 - Initialize with restrictive defaults
    pub fn new() -> Self {
        Self {
            min_rsa_key_size: MIN_RSA_KEY_SIZE,
            min_ec_key_size: MIN_EC_KEY_SIZE,
            max_end_entity_validity_days: MAX_END_ENTITY_VALIDITY_DAYS,
            max_ca_validity_days: MAX_CA_VALIDITY_DAYS,
            default_end_entity_validity_days: DEFAULT_END_ENTITY_VALIDITY_DAYS,
            default_ca_validity_days: DEFAULT_CA_VALIDITY_DAYS,
            require_crl_distribution_points: true,
            require_aia: true,
            require_san_for_tls: true,
            allowed_signature_algorithms: Self::default_allowed_algorithms(),
            allowed_key_types: Self::default_allowed_key_types(),
            prohibited_ekus: Self::default_prohibited_ekus(),
            max_path_length: 1, // Allow only one subordinate CA level by default
            enforce_critical_extensions: true,
            require_unique_serial: true,
        }
    }

    /// Get default allowed signature algorithms
    ///
    /// FIPS 186-5, FIPS 204, FIPS 205 compliant algorithms
    fn default_allowed_algorithms() -> Vec<String> {
        vec![
            // RSA with SHA-2 (FIPS 186-5)
            "rsa_pkcs1_sha256".to_string(),
            "rsa_pkcs1_sha384".to_string(),
            "rsa_pkcs1_sha512".to_string(),
            "rsa_pss_sha256".to_string(),
            "rsa_pss_sha384".to_string(),
            "rsa_pss_sha512".to_string(),
            // ECDSA with SHA-2 (FIPS 186-5)
            "ecdsa_p256_sha256".to_string(),
            "ecdsa_p384_sha384".to_string(),
            "ecdsa_p521_sha512".to_string(),
            // EdDSA (RFC 8410)
            "ed25519".to_string(),
            "ed448".to_string(),
            // ML-DSA (FIPS 204)
            "ml_dsa_44".to_string(),
            "ml_dsa_65".to_string(),
            "ml_dsa_87".to_string(),
            // SLH-DSA (FIPS 205)
            "slh_dsa_sha2_128s".to_string(),
            "slh_dsa_sha2_128f".to_string(),
            "slh_dsa_sha2_192s".to_string(),
            "slh_dsa_sha2_192f".to_string(),
            "slh_dsa_sha2_256s".to_string(),
            "slh_dsa_sha2_256f".to_string(),
        ]
    }

    /// Get default allowed key types
    fn default_allowed_key_types() -> Vec<String> {
        vec![
            // RSA
            "rsa_2048".to_string(),
            "rsa_3072".to_string(),
            "rsa_4096".to_string(),
            // ECDSA
            "ec_p256".to_string(),
            "ec_p384".to_string(),
            "ec_p521".to_string(),
            // EdDSA
            "ed25519".to_string(),
            "ed448".to_string(),
            // ML-KEM (FIPS 203)
            "ml_kem_512".to_string(),
            "ml_kem_768".to_string(),
            "ml_kem_1024".to_string(),
            // ML-DSA (FIPS 204)
            "ml_dsa_44".to_string(),
            "ml_dsa_65".to_string(),
            "ml_dsa_87".to_string(),
            // SLH-DSA (FIPS 205)
            "slh_dsa_sha2_128s".to_string(),
            "slh_dsa_sha2_256f".to_string(),
        ]
    }

    /// Get default prohibited extended key usages
    ///
    /// These EKUs should not be combined or issued without proper authorization
    fn default_prohibited_ekus() -> HashSet<String> {
        let mut prohibited = HashSet::new();
        // anyExtendedKeyUsage is too permissive
        prohibited.insert("2.5.29.37.0".to_string());
        prohibited
    }

    /// Validate a certificate profile against secure defaults
    ///
    /// NIAP PP-CA: FMT_MSA.1.2 - Enforce security attribute constraints
    /// NIST 800-53: CM-2 - Baseline configuration validation
    pub fn validate_profile(&self, profile: &CertificateProfile) -> Result<()> {
        // Validate key type is allowed
        if !self.allowed_key_types.contains(&profile.key_type) {
            return Err(Error::SecureDefaults(format!(
                "Key type '{}' is not in allowed list",
                profile.key_type
            )));
        }

        // Validate signature algorithm is allowed
        if !self
            .allowed_signature_algorithms
            .contains(&profile.algorithm)
        {
            return Err(Error::SecureDefaults(format!(
                "Signature algorithm '{}' is not in allowed list",
                profile.algorithm
            )));
        }

        // Validate validity period
        let max_validity = if profile.basic_constraints_ca {
            self.max_ca_validity_days
        } else {
            self.max_end_entity_validity_days
        };

        if profile.validity_days > max_validity {
            return Err(Error::SecureDefaults(format!(
                "Validity period {} days exceeds maximum {} days",
                profile.validity_days, max_validity
            )));
        }

        if profile.validity_days < MIN_VALIDITY_DAYS {
            return Err(Error::SecureDefaults(format!(
                "Validity period {} days is below minimum {} day",
                profile.validity_days, MIN_VALIDITY_DAYS
            )));
        }

        // Validate key size for RSA
        if profile.key_type.starts_with("rsa_") {
            let key_size: u32 = profile
                .key_type
                .trim_start_matches("rsa_")
                .parse()
                .unwrap_or(0);
            if key_size < self.min_rsa_key_size {
                return Err(Error::SecureDefaults(format!(
                    "RSA key size {} bits is below minimum {} bits",
                    key_size, self.min_rsa_key_size
                )));
            }
        }

        // Validate key size for EC
        if profile.key_type.starts_with("ec_p") {
            let key_size: u32 = profile
                .key_type
                .trim_start_matches("ec_p")
                .parse()
                .unwrap_or(0);
            if key_size < self.min_ec_key_size {
                return Err(Error::SecureDefaults(format!(
                    "EC key size {} bits is below minimum {} bits",
                    key_size, self.min_ec_key_size
                )));
            }
        }

        // Validate TLS server certificates require SAN
        if self.require_san_for_tls
            && profile.profile_type == ProfileType::TlsServer
            && !profile.subject_alt_name_required
        {
            return Err(Error::SecureDefaults(
                "TLS server certificates must require Subject Alternative Name".to_string(),
            ));
        }

        // Validate path length for CA certificates
        if profile.basic_constraints_ca
            && let Some(path_len) = profile.basic_constraints_path_len
            && path_len > self.max_path_length
            && profile.profile_type != ProfileType::RootCa
        {
            return Err(Error::SecureDefaults(format!(
                "Path length constraint {} exceeds maximum {}",
                path_len, self.max_path_length
            )));
        }

        // Validate prohibited EKUs
        for eku in &profile.extended_key_usage {
            let oid = eku.oid();
            if self.prohibited_ekus.contains(oid) {
                return Err(Error::SecureDefaults(format!(
                    "Extended key usage OID {} is prohibited",
                    oid
                )));
            }
        }

        // CA certificates must have keyCertSign
        if profile.basic_constraints_ca && !profile.key_usage.contains(&KeyUsage::KeyCertSign) {
            return Err(Error::SecureDefaults(
                "CA certificates must have keyCertSign key usage".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate key size meets minimum requirements
    ///
    /// NIAP PP-CA: FCS_CKM.1 - Key size validation
    pub fn validate_key_size(&self, key_type: &str) -> Result<()> {
        if key_type.starts_with("rsa_") {
            let size: u32 = key_type.trim_start_matches("rsa_").parse().unwrap_or(0);
            if size < self.min_rsa_key_size {
                return Err(Error::SecureDefaults(format!(
                    "RSA key size {} bits below minimum {} bits",
                    size, self.min_rsa_key_size
                )));
            }
        } else if key_type.starts_with("ec_p") {
            let size: u32 = key_type.trim_start_matches("ec_p").parse().unwrap_or(0);
            if size < self.min_ec_key_size {
                return Err(Error::SecureDefaults(format!(
                    "EC key size {} bits below minimum {} bits",
                    size, self.min_ec_key_size
                )));
            }
        }
        Ok(())
    }

    /// Validate validity period meets constraints
    ///
    /// NIAP PP-CA: FMT_SMF.1 - Certificate lifecycle management
    pub fn validate_validity(&self, days: u32, is_ca: bool) -> Result<()> {
        let max = if is_ca {
            self.max_ca_validity_days
        } else {
            self.max_end_entity_validity_days
        };

        if days > max {
            return Err(Error::SecureDefaults(format!(
                "Validity period {} days exceeds maximum {} days",
                days, max
            )));
        }

        if days < MIN_VALIDITY_DAYS {
            return Err(Error::SecureDefaults(format!(
                "Validity period {} days below minimum {} day",
                days, MIN_VALIDITY_DAYS
            )));
        }

        Ok(())
    }

    /// Get the default validity period for a profile type
    pub fn default_validity(&self, is_ca: bool) -> u32 {
        if is_ca {
            self.default_ca_validity_days
        } else {
            self.default_end_entity_validity_days
        }
    }

    /// Check if an algorithm is allowed
    pub fn is_algorithm_allowed(&self, algorithm: &str) -> bool {
        self.allowed_signature_algorithms
            .contains(&algorithm.to_string())
    }

    /// Check if a key type is allowed
    pub fn is_key_type_allowed(&self, key_type: &str) -> bool {
        self.allowed_key_types.contains(&key_type.to_string())
    }

    /// Builder method: Set minimum RSA key size
    pub fn with_min_rsa_key_size(mut self, size: u32) -> Self {
        self.min_rsa_key_size = size;
        self
    }

    /// Builder method: Set minimum EC key size
    pub fn with_min_ec_key_size(mut self, size: u32) -> Self {
        self.min_ec_key_size = size;
        self
    }

    /// Builder method: Set maximum end-entity validity
    pub fn with_max_end_entity_validity(mut self, days: u32) -> Self {
        self.max_end_entity_validity_days = days;
        self
    }

    /// Builder method: Set maximum CA validity
    pub fn with_max_ca_validity(mut self, days: u32) -> Self {
        self.max_ca_validity_days = days;
        self
    }

    /// Builder method: Add allowed algorithm
    pub fn with_allowed_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        let alg = algorithm.into();
        if !self.allowed_signature_algorithms.contains(&alg) {
            self.allowed_signature_algorithms.push(alg);
        }
        self
    }

    /// Builder method: Add prohibited EKU
    pub fn with_prohibited_eku(mut self, oid: impl Into<String>) -> Self {
        self.prohibited_ekus.insert(oid.into());
        self
    }
}

/// Security attribute for certificate fields
///
/// NIAP PP-CA: FMT_MSA.1.2 - Security attributes with default values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAttribute<T> {
    /// The attribute value
    pub value: T,
    /// Whether this value can be modified
    pub modifiable: bool,
    /// Description of the attribute
    pub description: String,
    /// NIAP SFR reference
    pub sfr_reference: Option<String>,
}

impl<T: Clone> SecurityAttribute<T> {
    /// Create a new security attribute
    pub fn new(value: T, modifiable: bool, description: impl Into<String>) -> Self {
        Self {
            value,
            modifiable,
            description: description.into(),
            sfr_reference: None,
        }
    }

    /// Create an immutable security attribute
    pub fn immutable(value: T, description: impl Into<String>) -> Self {
        Self::new(value, false, description)
    }

    /// Create a modifiable security attribute
    pub fn modifiable(value: T, description: impl Into<String>) -> Self {
        Self::new(value, true, description)
    }

    /// Set SFR reference
    pub fn with_sfr(mut self, sfr: impl Into<String>) -> Self {
        self.sfr_reference = Some(sfr.into());
        self
    }

    /// Get the value if modifiable, or return the default
    pub fn get_or_default(&self, requested: Option<T>) -> T {
        if self.modifiable {
            requested.unwrap_or_else(|| self.value.clone())
        } else {
            self.value.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FMT_MSA.1.2 - Test secure defaults initialization
    #[test]
    fn test_secure_defaults_init() {
        let defaults = SecureDefaults::new();

        assert_eq!(defaults.min_rsa_key_size, MIN_RSA_KEY_SIZE);
        assert_eq!(defaults.min_ec_key_size, MIN_EC_KEY_SIZE);
        assert_eq!(
            defaults.max_end_entity_validity_days,
            MAX_END_ENTITY_VALIDITY_DAYS
        );
        assert_eq!(defaults.max_ca_validity_days, MAX_CA_VALIDITY_DAYS);
        assert!(defaults.require_crl_distribution_points);
        assert!(defaults.require_aia);
        assert!(defaults.require_san_for_tls);
        assert!(defaults.enforce_critical_extensions);
    }

    /// FMT_MSA.1.2 - Test profile validation
    #[test]
    fn test_validate_profile_success() {
        let defaults = SecureDefaults::new();
        let profile = CertificateProfile::tls_server(365);

        assert!(defaults.validate_profile(&profile).is_ok());
    }

    /// FMT_MSA.1.2 - Test profile validation with invalid key type
    #[test]
    fn test_validate_profile_invalid_key_type() {
        let defaults = SecureDefaults::new();
        let mut profile = CertificateProfile::tls_server(365);
        profile.key_type = "unknown_key".to_string();

        let result = defaults.validate_profile(&profile);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in allowed list")
        );
    }

    /// FMT_MSA.1.2 - Test profile validation with excessive validity
    #[test]
    fn test_validate_profile_excessive_validity() {
        let defaults = SecureDefaults::new();
        let mut profile = CertificateProfile::tls_server(1000);
        profile.validity_days = 1000; // Exceeds MAX_END_ENTITY_VALIDITY_DAYS

        let result = defaults.validate_profile(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    /// FMT_MSA.1.2 - Regression: every built-in profile constructor must pass
    /// secure-default validation, since issuance now enforces it on the active
    /// profile. A failure here would break legitimate issuance.
    #[test]
    fn test_builtin_profiles_pass_validation() {
        let defaults = SecureDefaults::new();
        for profile in [
            CertificateProfile::root_ca(3650),
            CertificateProfile::intermediate_ca(1825, 0),
            CertificateProfile::tls_server(397),
            CertificateProfile::tls_client(365),
            CertificateProfile::ocsp_signing(90),
        ] {
            assert!(
                defaults.validate_profile(&profile).is_ok(),
                "built-in profile '{}' must pass secure-default validation: {:?}",
                profile.name,
                defaults.validate_profile(&profile)
            );
        }
    }

    /// FMT_MSA.1.2 - A SHA-1 signature algorithm is not allow-listed and must be
    /// rejected (FIPS 186-5 requires SHA-2/SHA-3; SHA-1 is broken for signatures).
    #[test]
    fn test_validate_profile_rejects_sha1_and_weak_rsa() {
        let defaults = SecureDefaults::new();

        let mut sha1 = CertificateProfile::tls_server(365);
        sha1.algorithm = "rsa_pkcs1_sha1".to_string();
        assert!(
            defaults.validate_profile(&sha1).is_err(),
            "SHA-1 signature algorithm must be rejected"
        );

        let mut weak_rsa = CertificateProfile::tls_server(365);
        weak_rsa.key_type = "rsa_1024".to_string();
        weak_rsa.algorithm = "rsa_pkcs1_sha256".to_string();
        assert!(
            defaults.validate_profile(&weak_rsa).is_err(),
            "sub-2048-bit RSA key must be rejected"
        );
    }

    /// FMT_MSA.1.2 - Test CA profile validation
    #[test]
    fn test_validate_ca_profile() {
        let defaults = SecureDefaults::new();
        let profile = CertificateProfile::root_ca(3650);

        assert!(defaults.validate_profile(&profile).is_ok());
    }

    /// FMT_MSA.1.2 - Test CA profile without keyCertSign
    #[test]
    fn test_validate_ca_profile_no_keycertsign() {
        let defaults = SecureDefaults::new();
        let mut profile = CertificateProfile::root_ca(3650);
        profile.key_usage.clear();

        let result = defaults.validate_profile(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("keyCertSign"));
    }

    /// FCS_CKM.1 - Test key size validation
    #[test]
    fn test_validate_key_size() {
        let defaults = SecureDefaults::new();

        // Valid RSA key sizes
        assert!(defaults.validate_key_size("rsa_2048").is_ok());
        assert!(defaults.validate_key_size("rsa_3072").is_ok());
        assert!(defaults.validate_key_size("rsa_4096").is_ok());

        // Invalid RSA key size
        assert!(defaults.validate_key_size("rsa_1024").is_err());

        // Valid EC key sizes
        assert!(defaults.validate_key_size("ec_p256").is_ok());
        assert!(defaults.validate_key_size("ec_p384").is_ok());

        // Non-RSA/EC key types pass through
        assert!(defaults.validate_key_size("ed25519").is_ok());
    }

    /// FMT_SMF.1 - Test validity validation
    #[test]
    fn test_validate_validity() {
        let defaults = SecureDefaults::new();

        // Valid end-entity validity
        assert!(defaults.validate_validity(365, false).is_ok());
        assert!(defaults.validate_validity(825, false).is_ok());

        // Invalid end-entity validity (too long)
        assert!(defaults.validate_validity(1000, false).is_err());

        // Valid CA validity
        assert!(defaults.validate_validity(3650, true).is_ok());
        assert!(defaults.validate_validity(7300, true).is_ok());

        // Invalid CA validity (too long)
        assert!(defaults.validate_validity(10000, true).is_err());
    }

    /// FMT_MSA.1.2 - Test algorithm allowlist
    #[test]
    fn test_is_algorithm_allowed() {
        let defaults = SecureDefaults::new();

        // Allowed algorithms
        assert!(defaults.is_algorithm_allowed("rsa_pss_sha256"));
        assert!(defaults.is_algorithm_allowed("ecdsa_p256_sha256"));
        assert!(defaults.is_algorithm_allowed("ed25519"));
        assert!(defaults.is_algorithm_allowed("ml_dsa_65"));

        // Not allowed
        assert!(!defaults.is_algorithm_allowed("sha1_rsa"));
        assert!(!defaults.is_algorithm_allowed("md5_rsa"));
    }

    /// FMT_MSA.1.2 - Test key type allowlist
    #[test]
    fn test_is_key_type_allowed() {
        let defaults = SecureDefaults::new();

        // Allowed key types
        assert!(defaults.is_key_type_allowed("rsa_2048"));
        assert!(defaults.is_key_type_allowed("ec_p256"));
        assert!(defaults.is_key_type_allowed("ed25519"));
        assert!(defaults.is_key_type_allowed("ml_dsa_65"));

        // Not allowed
        assert!(!defaults.is_key_type_allowed("rsa_1024"));
        assert!(!defaults.is_key_type_allowed("unknown"));
    }

    /// FMT_MSA.1.2 - Test builder pattern
    #[test]
    fn test_builder_pattern() {
        let defaults = SecureDefaults::new()
            .with_min_rsa_key_size(3072)
            .with_max_end_entity_validity(397)
            .with_prohibited_eku("1.2.3.4.5");

        assert_eq!(defaults.min_rsa_key_size, 3072);
        assert_eq!(defaults.max_end_entity_validity_days, 397);
        assert!(defaults.prohibited_ekus.contains("1.2.3.4.5"));
    }

    /// FMT_MSA.1.2 - Test security attribute
    #[test]
    fn test_security_attribute() {
        let immutable = SecurityAttribute::immutable(365u32, "Certificate validity in days")
            .with_sfr("FMT_MSA.1.2");

        assert!(!immutable.modifiable);
        assert_eq!(immutable.get_or_default(Some(730)), 365);
        assert_eq!(immutable.sfr_reference, Some("FMT_MSA.1.2".to_string()));

        let modifiable = SecurityAttribute::modifiable(365u32, "Certificate validity in days");

        assert!(modifiable.modifiable);
        assert_eq!(modifiable.get_or_default(Some(730)), 730);
        assert_eq!(modifiable.get_or_default(None), 365);
    }

    /// FMT_MSA.1.2 - Test prohibited EKUs
    #[test]
    fn test_prohibited_ekus() {
        let defaults = SecureDefaults::new();

        // anyExtendedKeyUsage should be prohibited by default
        assert!(defaults.prohibited_ekus.contains("2.5.29.37.0"));
    }

    /// FMT_MSA.1.2 - Test default validity periods
    #[test]
    fn test_default_validity() {
        let defaults = SecureDefaults::new();

        assert_eq!(
            defaults.default_validity(false),
            DEFAULT_END_ENTITY_VALIDITY_DAYS
        );
        assert_eq!(defaults.default_validity(true), DEFAULT_CA_VALIDITY_DAYS);
    }
}
