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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_id_serialization() {
        // Test Software provider serialization
        let software = ProviderId::Software;
        let json = serde_json::to_string(&software).unwrap();
        let deserialized: ProviderId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProviderId::Software);

        // Test PKCS#11 provider serialization
        let pkcs11 = ProviderId::Pkcs11 { slot_id: 42 };
        let json = serde_json::to_string(&pkcs11).unwrap();
        assert!(json.contains("42"));
        let deserialized: ProviderId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProviderId::Pkcs11 { slot_id: 42 });
    }

    #[test]
    fn test_key_handle_creation() {
        let handle = KeyHandle::new(
            ProviderId::Software,
            vec![1, 2, 3, 4],
            KeyType::EcP256,
            Algorithm::EcdsaP256Sha256,
            "test-key".to_string(),
        );

        assert!(matches!(handle.provider_id, ProviderId::Software));
        assert_eq!(handle.key_id, vec![1, 2, 3, 4]);
        assert_eq!(handle.key_type, KeyType::EcP256);
        assert_eq!(handle.algorithm, Algorithm::EcdsaP256Sha256);
        assert_eq!(handle.label, "test-key");
    }

    #[test]
    fn test_key_handle_serialization() {
        let handle = KeyHandle::new(
            ProviderId::Software,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            KeyType::Rsa2048,
            Algorithm::RsaPkcs1Sha256,
            "ca-signing-key".to_string(),
        );

        let json = serde_json::to_string(&handle).unwrap();

        // Verify base64 encoding of key_id
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let expected_key_id_b64 = STANDARD.encode(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(json.contains(&expected_key_id_b64));

        // Deserialize and verify
        let deserialized: KeyHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(deserialized.label, "ca-signing-key");
    }

    #[test]
    fn test_sensitive_bytes_creation() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let sensitive = SensitiveBytes::new(data.clone());

        assert_eq!(sensitive.as_bytes(), &data);
        assert_eq!(sensitive.as_ref(), &data[..]);
    }

    #[test]
    fn test_sensitive_bytes_from_vec() {
        let data = vec![0xAB, 0xCD, 0xEF];
        let sensitive: SensitiveBytes = data.clone().into();

        assert_eq!(sensitive.as_bytes(), &data);
    }

    #[test]
    fn test_key_handle_with_pkcs11_provider() {
        let handle = KeyHandle::new(
            ProviderId::Pkcs11 { slot_id: 1 },
            vec![0x01, 0x23, 0x45, 0x67],
            KeyType::EcP384,
            Algorithm::EcdsaP384Sha384,
            "hsm-key".to_string(),
        );

        match handle.provider_id {
            ProviderId::Pkcs11 { slot_id } => assert_eq!(slot_id, 1),
            _ => panic!("Expected PKCS#11 provider"),
        }
    }
}
