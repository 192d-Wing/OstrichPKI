//! Cryptographic provider trait and factory
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5
//! - SC-12: Cryptographic key establishment and management
//! - SC-13: Cryptographic protection
//! - IA-7: Cryptographic module authentication
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FCS_CKM.1: Cryptographic key generation
//! - FCS_CKM.2: Cryptographic key distribution
//! - FCS_CKM.4: Cryptographic key destruction
//! - FCS_COP.1(1): Cryptographic operation - signing
//! - FCS_COP.1(2): Cryptographic operation - verification
//! - FCS_COP.1(3): Cryptographic operation - hashing
//!
//! ## FIPS Standards
//! - FIPS 186-5: Digital Signature Standard

use crate::{Algorithm, Error, KeyHandle, KeyType, Result};
use async_trait::async_trait;
use std::path::Path;
use zeroize::Zeroizing;

/// Core trait for all cryptographic operations
///
/// This trait abstracts over different cryptographic providers (HSM via PKCS#11,
/// software implementations, etc.) to provide a unified interface for:
/// - Key generation
/// - Digital signatures
/// - Signature verification
/// - Key wrapping/unwrapping (for KRA)
///
/// # NIAP PP-CA Compliance
/// - FCS_CKM.1: Key generation via `generate_key_pair()`
/// - FCS_CKM.4: Key destruction via `destroy_key()`
/// - FCS_COP.1(1): Signing via `sign()`
/// - FCS_COP.1(2): Verification via `verify()`
///
/// NIST 800-53: SC-13 - All crypto operations go through this abstraction
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Generate a new key pair in the provider
    ///
    /// # Arguments
    /// * `key_type` - Type of key to generate
    /// * `label` - Human-readable label for the key
    /// * `extractable` - Whether the private key can be extracted (should be false for HSM keys)
    ///
    /// # Returns
    /// An opaque handle to the generated key
    ///
    /// NIST 800-53: SC-12 - Cryptographic key generation
    /// NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation
    async fn generate_key_pair(
        &self,
        key_type: KeyType,
        label: &str,
        extractable: bool,
    ) -> Result<KeyHandle>;

    /// Sign data with a private key
    ///
    /// # Arguments
    /// * `key` - Handle to the signing key
    /// * `algorithm` - Signature algorithm to use
    /// * `data` - Data to sign
    ///
    /// # Returns
    /// The signature bytes
    ///
    /// FIPS 186-5: Digital signature generation
    /// RFC 5280 §4.1.1.2 - Signature algorithms
    /// NIAP PP-CA: FCS_COP.1(1) - Cryptographic operation (signing)
    async fn sign(&self, key: &KeyHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature with a public key
    ///
    /// # Arguments
    /// * `key` - Handle to the verification key
    /// * `algorithm` - Signature algorithm used
    /// * `data` - Original data that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid
    ///
    /// FIPS 186-5: Digital signature verification
    /// NIAP PP-CA: FCS_COP.1(2) - Cryptographic operation (verification)
    async fn verify(
        &self,
        key: &KeyHandle,
        algorithm: Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool>;

    /// Export the public key in SPKI (SubjectPublicKeyInfo) format
    ///
    /// # Arguments
    /// * `key` - Handle to the key
    ///
    /// # Returns
    /// DER-encoded SubjectPublicKeyInfo
    ///
    /// RFC 5280 §4.1.2.7 - Subject Public Key Info
    async fn export_public_key(&self, key: &KeyHandle) -> Result<Vec<u8>>;

    /// Import an existing private key (for software provider or key escrow)
    ///
    /// # Arguments
    /// * `key_type` - Type of the key
    /// * `private_key` - DER-encoded private key (will be zeroized)
    /// * `label` - Label for the imported key
    ///
    /// # Returns
    /// Handle to the imported key
    ///
    /// NIST 800-53: SC-12 - Cryptographic key establishment
    /// NIST 800-53: SI-12 - Private key will be zeroized after import
    async fn import_key(
        &self,
        key_type: KeyType,
        private_key: Zeroizing<Vec<u8>>,
        label: &str,
    ) -> Result<KeyHandle>;

    /// Destroy a key permanently
    ///
    /// # Arguments
    /// * `key` - Handle to the key to destroy
    ///
    /// NIST 800-53: SC-12 - Cryptographic key destruction
    /// NIAP PP-CA: FCS_CKM.4 - Cryptographic key destruction
    async fn destroy_key(&self, key: &KeyHandle) -> Result<()>;

    /// Wrap (encrypt) a key for transport
    ///
    /// Used by the Key Recovery Authority to encrypt keys for storage.
    ///
    /// # Arguments
    /// * `key_to_wrap` - The key to be wrapped
    /// * `wrapping_key` - The key used to wrap
    ///
    /// # Returns
    /// Wrapped (encrypted) key bytes
    ///
    /// NIST 800-53: SC-12 - Cryptographic key transport
    /// FIPS 203: ML-KEM for post-quantum key wrapping
    /// NIAP PP-CA: FCS_CKM.2 - Cryptographic key distribution
    async fn wrap_key(&self, key_to_wrap: &KeyHandle, wrapping_key: &KeyHandle) -> Result<Vec<u8>>;

    /// Unwrap (decrypt) a transported key
    ///
    /// Used by the Key Recovery Authority to decrypt escrowed keys.
    ///
    /// # Arguments
    /// * `wrapped_key` - The wrapped key bytes
    /// * `unwrapping_key` - The key used to unwrap
    /// * `key_type` - Expected type of the unwrapped key
    /// * `label` - Label for the unwrapped key
    ///
    /// # Returns
    /// Handle to the unwrapped key
    ///
    /// NIST 800-53: SC-12 - Cryptographic key recovery
    async fn unwrap_key(
        &self,
        wrapped_key: &[u8],
        unwrapping_key: &KeyHandle,
        key_type: KeyType,
        label: &str,
    ) -> Result<KeyHandle>;

    /// Generate cryptographically secure random bytes
    ///
    /// # Arguments
    /// * `len` - Number of random bytes to generate
    ///
    /// # Returns
    /// Vector of cryptographically secure random bytes
    ///
    /// # NIST SP 800-90A
    /// Uses NIST SP 800-90A compliant DRBG for random bit generation
    ///
    /// # NIAP PP-CA
    /// - FCS_RBG_EXT.1: Random Bit Generation using approved DRBG
    ///
    /// # NIST 800-53
    /// - SC-13: Cryptographic Protection - FIPS-validated random number generation
    async fn generate_random_bytes(&self, len: usize) -> Result<Vec<u8>>;

    /// Get the provider ID for this provider
    fn provider_id(&self) -> crate::key::ProviderId;

    /// List all available keys in this provider (optional)
    ///
    /// Returns a list of key handles for keys accessible to this provider.
    /// This is useful for management operations.
    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        // Default implementation returns empty list
        Ok(Vec::new())
    }
}

/// Configuration for creating a cryptographic provider
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Type of provider to create
    pub provider_type: ProviderType,

    /// PKCS#11 configuration (if using HSM)
    pub pkcs11: Option<Pkcs11Config>,
}

#[derive(Debug, Clone)]
pub enum ProviderType {
    /// Software-based cryptography (ring)
    Software,

    /// PKCS#11 HSM
    Pkcs11,

    /// Auto-detect: Try PKCS#11, fall back to software
    Auto,
}

#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Path to PKCS#11 library (.so/.dylib/.dll)
    pub library_path: String,

    /// Slot ID to use
    pub slot_id: u64,

    /// User PIN (will be zeroized)
    pub pin: String,
}

/// Factory for creating crypto providers
pub struct CryptoProviderFactory;

impl CryptoProviderFactory {
    /// Create a PKCS#11 provider connected to an HSM
    ///
    /// # Arguments
    /// * `library_path` - Path to PKCS#11 library
    /// * `slot_id` - HSM slot ID
    /// * `pin` - User PIN for the slot
    ///
    /// # Returns
    /// A boxed CryptoProvider backed by the HSM
    ///
    /// NIST 800-53: IA-7 - Cryptographic module authentication
    /// NIAP PP-CA: FCS_CKM.1 - Key generation in FIPS 140-3 validated module
    pub async fn create_pkcs11_provider(
        library_path: &Path,
        slot_id: u64,
        pin: &str,
    ) -> Result<Box<dyn CryptoProvider>> {
        crate::pkcs11::Pkcs11Provider::new(library_path, slot_id, pin)
            .await
            .map(|p| Box::new(p) as Box<dyn CryptoProvider>)
    }

    /// Create a software provider using ring
    ///
    /// # Returns
    /// A boxed CryptoProvider using software cryptography
    ///
    /// Note: Software providers should only be used for development/testing.
    /// Production systems should use HSMs.
    pub fn create_software_provider() -> Box<dyn CryptoProvider> {
        Box::new(crate::software::SoftwareProvider::new())
    }

    /// Create a provider based on configuration
    ///
    /// Tries PKCS#11 first if configured, falls back to software if:
    /// - PKCS#11 library not found
    /// - HSM not available
    /// - Configuration specifies Auto mode
    ///
    /// # Arguments
    /// * `config` - Provider configuration
    ///
    /// # Returns
    /// A boxed CryptoProvider
    pub async fn create_auto_provider(config: &CryptoConfig) -> Result<Box<dyn CryptoProvider>> {
        match config.provider_type {
            ProviderType::Software => Ok(Self::create_software_provider()),

            ProviderType::Pkcs11 => {
                let pkcs11_config = config
                    .pkcs11
                    .as_ref()
                    .ok_or_else(|| Error::KeyGeneration("PKCS#11 config required".to_string()))?;

                Self::create_pkcs11_provider(
                    Path::new(&pkcs11_config.library_path),
                    pkcs11_config.slot_id,
                    &pkcs11_config.pin,
                )
                .await
            }

            ProviderType::Auto => {
                if let Some(pkcs11_config) = &config.pkcs11 {
                    match Self::create_pkcs11_provider(
                        Path::new(&pkcs11_config.library_path),
                        pkcs11_config.slot_id,
                        &pkcs11_config.pin,
                    )
                    .await
                    {
                        Ok(provider) => {
                            tracing::info!("Using PKCS#11 HSM provider");
                            Ok(provider)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "PKCS#11 provider unavailable, falling back to software: {}",
                                e
                            );
                            Ok(Self::create_software_provider())
                        }
                    }
                } else {
                    tracing::info!("No PKCS#11 config, using software provider");
                    Ok(Self::create_software_provider())
                }
            }
        }
    }
}
