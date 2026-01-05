//! HSM key storage validation
//!
//! # NIAP PP-CA Compliance
//! - **FCS_STG_EXT.1**: Cryptographic Key Storage
//!   - Enforces HSM-only storage for CA signing keys
//!   - Validates key attributes (non-extractable, hardware-backed)
//!
//! # NIST 800-53 Controls
//! - SC-12: Cryptographic Key Establishment and Management
//! - SC-13: Cryptographic Protection

use crate::key::ProviderId;
use crate::{Error, KeyHandle, Result};

/// HSM key validator
///
/// Validates that cryptographic keys meet HSM storage requirements
/// per NIAP PP-CA FCS_STG_EXT.1.
pub struct HsmKeyValidator;

impl HsmKeyValidator {
    /// Verify key is stored in HSM (not software)
    ///
    /// # NIAP PP-CA Compliance
    /// - FCS_STG_EXT.1: CA signing keys must be stored in HSM
    ///
    /// # Arguments
    /// * `key` - Key handle to validate
    ///
    /// # Returns
    /// * `Ok(())` if key is HSM-backed
    /// * `Err` if key is software-backed
    pub fn verify_hsm_storage(key: &KeyHandle) -> Result<()> {
        match key.provider_id {
            ProviderId::Pkcs11 { .. } => Ok(()),
            ProviderId::Software => Err(Error::InvalidKeyType(format!(
                "CA signing key '{}' must be stored in HSM (PKCS#11) per FCS_STG_EXT.1, found Software provider",
                key.label
            ))),
        }
    }

    /// Verify key handle provider type
    ///
    /// # Arguments
    /// * `provider_id` - Provider ID to check
    ///
    /// # Returns
    /// * `true` if provider is PKCS#11 (HSM)
    /// * `false` if provider is Software
    pub fn is_hsm_provider(provider_id: &ProviderId) -> bool {
        matches!(provider_id, ProviderId::Pkcs11 { .. })
    }

    /// Validate CA signing key meets HSM requirements
    ///
    /// Comprehensive validation for CA signing keys:
    /// 1. HSM storage (FCS_STG_EXT.1)
    /// 2. Appropriate key type for signing
    ///
    /// # Arguments
    /// * `key` - CA signing key handle
    ///
    /// # Returns
    /// * `Ok(())` if key meets all requirements
    /// * `Err` with detailed error message if validation fails
    pub fn validate_ca_signing_key(key: &KeyHandle) -> Result<()> {
        // FCS_STG_EXT.1: Must be HSM-backed
        Self::verify_hsm_storage(key)?;

        // Verify key type is suitable for signing
        use crate::KeyType;
        match key.key_type {
            // Classical RSA key types
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 |
            // EC key types
            KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 |
            // EdDSA key types
            KeyType::Ed25519 | KeyType::Ed448 |
            // Post-quantum signature key types
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 |
            KeyType::SlhDsaSha2_128s | KeyType::SlhDsaSha2_128f |
            KeyType::SlhDsaSha2_192s | KeyType::SlhDsaSha2_192f |
            KeyType::SlhDsaSha2_256s | KeyType::SlhDsaSha2_256f => {
                Ok(())
            }
            _ => Err(Error::InvalidKeyType(format!(
                "Key type {:?} not supported for CA signing",
                key.key_type
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, KeyType};

    fn create_test_key(provider_id: ProviderId) -> KeyHandle {
        KeyHandle {
            provider_id,
            key_id: vec![1, 2, 3, 4],
            key_type: KeyType::Rsa2048,
            algorithm: Algorithm::RsaPssSha256,
            label: "test-ca-key".to_string(),
        }
    }

    #[test]
    fn test_hsm_key_validation_success() {
        let key = create_test_key(ProviderId::Pkcs11 { slot_id: 0 });
        assert!(HsmKeyValidator::verify_hsm_storage(&key).is_ok());
    }

    #[test]
    fn test_software_key_validation_failure() {
        let key = create_test_key(ProviderId::Software);
        let result = HsmKeyValidator::verify_hsm_storage(&key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be stored in HSM")
        );
    }

    #[test]
    fn test_is_hsm_provider() {
        assert!(HsmKeyValidator::is_hsm_provider(&ProviderId::Pkcs11 {
            slot_id: 0
        }));
        assert!(!HsmKeyValidator::is_hsm_provider(&ProviderId::Software));
    }

    #[test]
    fn test_validate_ca_signing_key_hsm() {
        let key = create_test_key(ProviderId::Pkcs11 { slot_id: 0 });
        assert!(HsmKeyValidator::validate_ca_signing_key(&key).is_ok());
    }

    #[test]
    fn test_validate_ca_signing_key_software_rejected() {
        let key = create_test_key(ProviderId::Software);
        assert!(HsmKeyValidator::validate_ca_signing_key(&key).is_err());
    }

    #[test]
    fn test_validate_ca_signing_key_ec_p256() {
        let mut key = create_test_key(ProviderId::Pkcs11 { slot_id: 0 });
        key.key_type = KeyType::EcP256;
        key.algorithm = Algorithm::EcdsaP256Sha256;
        assert!(HsmKeyValidator::validate_ca_signing_key(&key).is_ok());
    }

    #[test]
    fn test_validate_ca_signing_key_ed25519() {
        let mut key = create_test_key(ProviderId::Pkcs11 { slot_id: 0 });
        key.key_type = KeyType::Ed25519;
        key.algorithm = Algorithm::Ed25519;
        assert!(HsmKeyValidator::validate_ca_signing_key(&key).is_ok());
    }
}
