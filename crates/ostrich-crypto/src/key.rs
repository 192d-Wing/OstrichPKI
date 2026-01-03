//! Key handle types
//!
//! NIST 800-53: SC-12 - Cryptographic key establishment and management

use crate::{Algorithm, KeyType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Identifier for the cryptographic provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderId {
    /// PKCS#11 HSM provider with slot ID
    Pkcs11 { slot_id: u64 },
    /// Software provider (ring-based)
    Software,
}

/// Opaque handle to a cryptographic key
///
/// This handle does not contain the actual key material, only a reference
/// to the key stored in the cryptographic provider (HSM or software).
///
/// NIST 800-53: SC-12 - Keys are never exposed outside the provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHandle {
    /// Provider that manages this key
    pub provider_id: ProviderId,

    /// Provider-specific key identifier
    /// For PKCS#11: CKA_ID attribute
    /// For Software: key label/identifier
    #[serde(with = "serde_bytes_base64")]
    pub key_id: Vec<u8>,

    /// Type of the key
    pub key_type: KeyType,

    /// Compatible algorithms for this key
    pub algorithm: Algorithm,

    /// Human-readable label
    pub label: String,
}

impl KeyHandle {
    /// Create a new key handle
    pub fn new(
        provider_id: ProviderId,
        key_id: Vec<u8>,
        key_type: KeyType,
        algorithm: Algorithm,
        label: String,
    ) -> Self {
        Self {
            provider_id,
            key_id,
            key_type,
            algorithm,
            label,
        }
    }
}

/// Helper module for serde to serialize Vec<u8> as base64
mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Wrapper for sensitive key material that will be zeroized on drop
/// NIST 800-53: SI-12 - Information handling and retention
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveBytes(pub Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
