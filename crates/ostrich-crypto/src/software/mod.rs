//! Software cryptography provider using ring
//!
//! NIST 800-53: SC-13 - Cryptographic protection
//! Note: For development/testing only. Production should use HSM.

use crate::{Algorithm, Error, KeyHandle, KeyType, Result, key::ProviderId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

// RSA operations
use rand::rngs::OsRng;
use rsa::pkcs1v15::{SigningKey as Pkcs1SigningKey, VerifyingKey as Pkcs1VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::{BlindedSigningKey, Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};

// ECDSA operations (ring)
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
};

// EdDSA operations (ring)
use ring::signature::UnparsedPublicKey;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as Ed25519KeyPairTrait};

// SPKI/DER encoding
use der::{Encode, asn1::BitString};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

/// Elliptic curve identifier
#[derive(Debug, Clone, Copy)]
enum EcCurve {
    P256,
    P384,
    #[allow(dead_code)]
    P521, // Deferred to Phase 8 Part 2
}

/// RSA key pair with algorithm tracking
struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

/// ECDSA key pair
struct EcdsaKeyPairInternal {
    private_key: Zeroizing<Vec<u8>>, // PKCS#8 DER
    public_key: Vec<u8>,             // Raw public key bytes (not SPKI)
    curve: EcCurve,
}

/// Ed25519 key pair
struct Ed25519KeyPairInternal {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>, // 32 bytes
}

/// Internal key pair storage
enum KeyPair {
    Rsa(Box<RsaKeyPair>), // Boxed to reduce enum size
    Ecdsa(EcdsaKeyPairInternal),
    Ed25519(Ed25519KeyPairInternal),
}

// Implement Drop to manually zeroize private key material
impl Drop for KeyPair {
    fn drop(&mut self) {
        match self {
            KeyPair::Rsa(_) => {
                // RsaPrivateKey zeroizes itself on drop
            }
            KeyPair::Ecdsa(_) => {
                // Zeroizing<Vec<u8>> zeroizes itself on drop
            }
            KeyPair::Ed25519(_) => {
                // Ed25519KeyPair zeroizes itself on drop (ring implementation)
            }
        }
    }
}

/// Software provider using ring for cryptographic operations
pub struct SoftwareProvider {
    /// Map: key_id -> KeyPair
    keys: RwLock<HashMap<Vec<u8>, KeyPair>>,
}

impl SoftwareProvider {
    /// Create a new software provider
    pub fn new() -> Self {
        tracing::warn!("Using software crypto provider - NOT RECOMMENDED for production");
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    // ========== RSA Operations ==========

    /// Generate RSA key pair
    fn generate_rsa_key_pair(bits: usize) -> Result<RsaKeyPair> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| Error::KeyGeneration(format!("RSA key generation failed: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(RsaKeyPair {
            private_key,
            public_key,
        })
    }

    /// Sign with RSA
    fn sign_rsa(key_pair: &RsaKeyPair, data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        match algorithm {
            // RSA-PSS signatures
            Algorithm::RsaPssSha256 => {
                let signing_key = BlindedSigningKey::<Sha256>::new(key_pair.private_key.clone());
                let signature = signing_key.sign_with_rng(&mut OsRng, data);
                Ok(signature.to_bytes().to_vec())
            }
            Algorithm::RsaPssSha384 => {
                let signing_key = BlindedSigningKey::<Sha384>::new(key_pair.private_key.clone());
                let signature = signing_key.sign_with_rng(&mut OsRng, data);
                Ok(signature.to_bytes().to_vec())
            }
            Algorithm::RsaPssSha512 => {
                let signing_key = BlindedSigningKey::<Sha512>::new(key_pair.private_key.clone());
                let signature = signing_key.sign_with_rng(&mut OsRng, data);
                Ok(signature.to_bytes().to_vec())
            }

            // RSA PKCS#1 v1.5 signatures
            Algorithm::RsaPkcs1Sha256 => {
                let signing_key =
                    Pkcs1SigningKey::<Sha256>::new_unprefixed(key_pair.private_key.clone());
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            Algorithm::RsaPkcs1Sha384 => {
                let signing_key =
                    Pkcs1SigningKey::<Sha384>::new_unprefixed(key_pair.private_key.clone());
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            Algorithm::RsaPkcs1Sha512 => {
                let signing_key =
                    Pkcs1SigningKey::<Sha512>::new_unprefixed(key_pair.private_key.clone());
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }

            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Algorithm {:?} not supported for RSA signing",
                algorithm
            ))),
        }
    }

    /// Verify RSA signature
    fn verify_rsa(
        key_pair: &RsaKeyPair,
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        match algorithm {
            // RSA-PSS verification
            Algorithm::RsaPssSha256 => {
                let verifying_key = PssVerifyingKey::<Sha256>::new(key_pair.public_key.clone());
                let sig = PssSignature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PSS signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            Algorithm::RsaPssSha384 => {
                let verifying_key = PssVerifyingKey::<Sha384>::new(key_pair.public_key.clone());
                let sig = PssSignature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PSS signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            Algorithm::RsaPssSha512 => {
                let verifying_key = PssVerifyingKey::<Sha512>::new(key_pair.public_key.clone());
                let sig = PssSignature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PSS signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }

            // RSA PKCS#1 v1.5 verification
            Algorithm::RsaPkcs1Sha256 => {
                let verifying_key =
                    Pkcs1VerifyingKey::<Sha256>::new_unprefixed(key_pair.public_key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PKCS#1 signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            Algorithm::RsaPkcs1Sha384 => {
                let verifying_key =
                    Pkcs1VerifyingKey::<Sha384>::new_unprefixed(key_pair.public_key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PKCS#1 signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            Algorithm::RsaPkcs1Sha512 => {
                let verifying_key =
                    Pkcs1VerifyingKey::<Sha512>::new_unprefixed(key_pair.public_key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| Error::Verification("Invalid PKCS#1 signature format".into()))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }

            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Algorithm {:?} not supported for RSA verification",
                algorithm
            ))),
        }
    }

    /// Export RSA public key as SPKI DER
    fn export_rsa_spki(key_pair: &RsaKeyPair) -> Result<Vec<u8>> {
        key_pair
            .public_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| Error::Encoding(format!("RSA SPKI encoding failed: {}", e)))
    }

    // ========== ECDSA Operations ==========

    /// Generate ECDSA key pair
    fn generate_ecdsa_key_pair(curve: EcCurve) -> Result<EcdsaKeyPairInternal> {
        let rng = SystemRandom::new();

        match curve {
            EcCurve::P256 => {
                let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &rng,
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-256 key generation failed: {:?}", e))
                })?;

                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                    &rng,
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-256 key parse failed: {:?}", e))
                })?;

                let public_key = key_pair.public_key().as_ref().to_vec();

                Ok(EcdsaKeyPairInternal {
                    private_key: Zeroizing::new(pkcs8_bytes.as_ref().to_vec()),
                    public_key,
                    curve: EcCurve::P256,
                })
            }

            EcCurve::P384 => {
                let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    &rng,
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-384 key generation failed: {:?}", e))
                })?;

                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                    &rng,
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-384 key parse failed: {:?}", e))
                })?;

                let public_key = key_pair.public_key().as_ref().to_vec();

                Ok(EcdsaKeyPairInternal {
                    private_key: Zeroizing::new(pkcs8_bytes.as_ref().to_vec()),
                    public_key,
                    curve: EcCurve::P384,
                })
            }

            EcCurve::P521 => Err(Error::NotImplemented(
                "ECDSA P-521 support deferred to Phase 8 Part 2".into(),
            )),
        }
    }

    /// Sign with ECDSA
    fn sign_ecdsa(
        key_pair: &EcdsaKeyPairInternal,
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        match key_pair.curve {
            EcCurve::P256 => {
                if !matches!(algorithm, Algorithm::EcdsaP256Sha256) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with P-256",
                        algorithm
                    )));
                }

                let rng = SystemRandom::new();
                let ring_key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &key_pair.private_key,
                    &rng,
                )
                .map_err(|_| Error::Signing("Failed to parse ECDSA P-256 key".into()))?;
                let signature = ring_key_pair
                    .sign(&rng, data)
                    .map_err(|_| Error::Signing("ECDSA P-256 signing failed".into()))?;

                Ok(signature.as_ref().to_vec())
            }

            EcCurve::P384 => {
                if !matches!(algorithm, Algorithm::EcdsaP384Sha384) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with P-384",
                        algorithm
                    )));
                }

                let rng = SystemRandom::new();
                let ring_key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    &key_pair.private_key,
                    &rng,
                )
                .map_err(|_| Error::Signing("Failed to parse ECDSA P-384 key".into()))?;
                let signature = ring_key_pair
                    .sign(&rng, data)
                    .map_err(|_| Error::Signing("ECDSA P-384 signing failed".into()))?;

                Ok(signature.as_ref().to_vec())
            }

            EcCurve::P521 => Err(Error::NotImplemented(
                "ECDSA P-521 signing deferred to Phase 8 Part 2".into(),
            )),
        }
    }

    /// Verify ECDSA signature
    fn verify_ecdsa(
        key_pair: &EcdsaKeyPairInternal,
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        match key_pair.curve {
            EcCurve::P256 => {
                if !matches!(algorithm, Algorithm::EcdsaP256Sha256) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with P-256",
                        algorithm
                    )));
                }

                let public_key =
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key_pair.public_key);
                Ok(public_key.verify(data, signature).is_ok())
            }

            EcCurve::P384 => {
                if !matches!(algorithm, Algorithm::EcdsaP384Sha384) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with P-384",
                        algorithm
                    )));
                }

                let public_key =
                    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &key_pair.public_key);
                Ok(public_key.verify(data, signature).is_ok())
            }

            EcCurve::P521 => Err(Error::NotImplemented(
                "ECDSA P-521 verification deferred to Phase 8 Part 2".into(),
            )),
        }
    }

    /// Export ECDSA public key as SPKI DER
    fn export_ecdsa_spki(key_pair: &EcdsaKeyPairInternal) -> Result<Vec<u8>> {
        // ECDSA public key from ring is raw bytes, need to wrap in SPKI

        let curve_oid = match key_pair.curve {
            EcCurve::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"), // secp256r1
            EcCurve::P384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),        // secp384r1
            EcCurve::P521 => {
                return Err(Error::NotImplemented(
                    "ECDSA P-521 public key export deferred to Phase 8 Part 2".into(),
                ));
            }
        };

        let algorithm = AlgorithmIdentifier {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"), // ecPublicKey
            parameters: Some(der::asn1::AnyRef::from(&curve_oid)),
        };

        let subject_public_key = BitString::from_bytes(&key_pair.public_key)
            .map_err(|e| Error::Encoding(format!("Failed to create BitString: {}", e)))?;

        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        spki.to_der()
            .map_err(|e| Error::Encoding(format!("ECDSA SPKI encoding failed: {}", e)))
    }

    // ========== Ed25519 Operations ==========

    /// Generate Ed25519 key pair
    fn generate_ed25519_key_pair() -> Result<Ed25519KeyPairInternal> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| Error::KeyGeneration("Ed25519 key generation failed".into()))?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| Error::KeyGeneration("Ed25519 key parse failed".into()))?;

        let public_key = key_pair.public_key().as_ref().to_vec();

        Ok(Ed25519KeyPairInternal {
            key_pair,
            public_key,
        })
    }

    /// Sign with Ed25519 (deterministic)
    fn sign_ed25519(key_pair: &Ed25519KeyPairInternal, data: &[u8]) -> Result<Vec<u8>> {
        Ok(key_pair.key_pair.sign(data).as_ref().to_vec())
    }

    /// Verify Ed25519 signature
    fn verify_ed25519(
        key_pair: &Ed25519KeyPairInternal,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let public_key = UnparsedPublicKey::new(&ED25519, &key_pair.public_key);
        Ok(public_key.verify(data, signature).is_ok())
    }

    /// Export Ed25519 public key as SPKI DER
    fn export_ed25519_spki(key_pair: &Ed25519KeyPairInternal) -> Result<Vec<u8>> {
        // Ed25519 public key is 32 bytes, wrap in SPKI
        let algorithm = AlgorithmIdentifier {
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // id-Ed25519
            parameters: None::<der::asn1::AnyRef>,
        };

        let subject_public_key = BitString::from_bytes(&key_pair.public_key)
            .map_err(|e| Error::Encoding(format!("Failed to create BitString: {}", e)))?;

        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        spki.to_der()
            .map_err(|e| Error::Encoding(format!("Ed25519 SPKI encoding failed: {}", e)))
    }
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::provider::CryptoProvider for SoftwareProvider {
    async fn generate_key_pair(
        &self,
        key_type: KeyType,
        label: &str,
        _extractable: bool,
    ) -> Result<KeyHandle> {
        // Generate key pair based on type
        let (key_pair, algorithm) = match key_type {
            // RSA keys
            KeyType::Rsa2048 => (
                KeyPair::Rsa(Box::new(Self::generate_rsa_key_pair(2048)?)),
                Algorithm::RsaPssSha256, // Default to PSS
            ),
            KeyType::Rsa3072 => (
                KeyPair::Rsa(Box::new(Self::generate_rsa_key_pair(3072)?)),
                Algorithm::RsaPssSha256,
            ),
            KeyType::Rsa4096 => (
                KeyPair::Rsa(Box::new(Self::generate_rsa_key_pair(4096)?)),
                Algorithm::RsaPssSha256,
            ),

            // ECDSA keys
            KeyType::EcP256 => (
                KeyPair::Ecdsa(Self::generate_ecdsa_key_pair(EcCurve::P256)?),
                Algorithm::EcdsaP256Sha256,
            ),
            KeyType::EcP384 => (
                KeyPair::Ecdsa(Self::generate_ecdsa_key_pair(EcCurve::P384)?),
                Algorithm::EcdsaP384Sha384,
            ),
            KeyType::EcP521 => {
                return Err(Error::NotImplemented(
                    "ECDSA P-521 key generation deferred to Phase 8 Part 2".into(),
                ));
            }

            // EdDSA keys
            KeyType::Ed25519 => (
                KeyPair::Ed25519(Self::generate_ed25519_key_pair()?),
                Algorithm::Ed25519,
            ),
            KeyType::Ed448 => {
                return Err(Error::NotImplemented(
                    "Ed448 key generation deferred to Phase 8 Part 2".into(),
                ));
            }

            // Post-quantum algorithms - deferred
            _ => {
                return Err(Error::NotImplemented(format!(
                    "Key type {:?} not yet implemented in software provider",
                    key_type
                )));
            }
        };

        // Generate unique key ID
        let key_id = Uuid::new_v4().as_bytes().to_vec();

        // Store in HashMap
        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), key_pair);
        }

        // Return KeyHandle
        Ok(KeyHandle::new(
            ProviderId::Software,
            key_id,
            key_type,
            algorithm,
            label.to_string(),
        ))
    }

    async fn sign(&self, key: &KeyHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        // Validate provider
        if !matches!(key.provider_id, ProviderId::Software) {
            return Err(Error::InvalidKeyHandle(
                "Key handle is not from software provider".into(),
            ));
        }

        // Lookup key (read lock)
        let keys = self.keys.read().unwrap();
        let key_pair = keys
            .get(&key.key_id)
            .ok_or_else(|| Error::InvalidKeyHandle("Key not found in software provider".into()))?;

        // Sign based on key type
        match key_pair {
            KeyPair::Rsa(rsa_kp) => Self::sign_rsa(rsa_kp, data, algorithm),
            KeyPair::Ecdsa(ecdsa_kp) => Self::sign_ecdsa(ecdsa_kp, data, algorithm),
            KeyPair::Ed25519(ed_kp) => {
                if !matches!(algorithm, Algorithm::Ed25519) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with Ed25519",
                        algorithm
                    )));
                }
                Self::sign_ed25519(ed_kp, data)
            }
        }
    }

    async fn verify(
        &self,
        key: &KeyHandle,
        algorithm: Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        // Validate provider
        if !matches!(key.provider_id, ProviderId::Software) {
            return Err(Error::InvalidKeyHandle(
                "Key handle is not from software provider".into(),
            ));
        }

        // Lookup key (read lock)
        let keys = self.keys.read().unwrap();
        let key_pair = keys
            .get(&key.key_id)
            .ok_or_else(|| Error::InvalidKeyHandle("Key not found in software provider".into()))?;

        // Verify based on key type
        match key_pair {
            KeyPair::Rsa(rsa_kp) => Self::verify_rsa(rsa_kp, data, signature, algorithm),
            KeyPair::Ecdsa(ecdsa_kp) => Self::verify_ecdsa(ecdsa_kp, data, signature, algorithm),
            KeyPair::Ed25519(ed_kp) => {
                if !matches!(algorithm, Algorithm::Ed25519) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {:?} not compatible with Ed25519",
                        algorithm
                    )));
                }
                Self::verify_ed25519(ed_kp, data, signature)
            }
        }
    }

    async fn export_public_key(&self, key: &KeyHandle) -> Result<Vec<u8>> {
        // Validate provider
        if !matches!(key.provider_id, ProviderId::Software) {
            return Err(Error::InvalidKeyHandle(
                "Key handle is not from software provider".into(),
            ));
        }

        // Lookup key (read lock)
        let keys = self.keys.read().unwrap();
        let key_pair = keys
            .get(&key.key_id)
            .ok_or_else(|| Error::InvalidKeyHandle("Key not found in software provider".into()))?;

        // Export based on key type
        match key_pair {
            KeyPair::Rsa(rsa_kp) => Self::export_rsa_spki(rsa_kp),
            KeyPair::Ecdsa(ecdsa_kp) => Self::export_ecdsa_spki(ecdsa_kp),
            KeyPair::Ed25519(ed_kp) => Self::export_ed25519_spki(ed_kp),
        }
    }

    async fn import_key(
        &self,
        key_type: KeyType,
        private_key: Zeroizing<Vec<u8>>,
        label: &str,
    ) -> Result<KeyHandle> {
        // Parse PKCS#8 DER based on key type
        let (key_pair, algorithm) = match key_type {
            // RSA keys
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                let rsa_private = RsaPrivateKey::from_pkcs8_der(&private_key).map_err(|e| {
                    Error::KeyGeneration(format!("Failed to parse RSA PKCS#8: {}", e))
                })?;
                let rsa_public = RsaPublicKey::from(&rsa_private);

                (
                    KeyPair::Rsa(Box::new(RsaKeyPair {
                        private_key: rsa_private,
                        public_key: rsa_public,
                    })),
                    Algorithm::RsaPssSha256, // Default
                )
            }

            // ECDSA keys (stored as PKCS#8)
            KeyType::EcP256 => (
                KeyPair::Ecdsa(EcdsaKeyPairInternal {
                    private_key: private_key.clone(),
                    public_key: Vec::new(), // Will be populated from PKCS#8
                    curve: EcCurve::P256,
                }),
                Algorithm::EcdsaP256Sha256,
            ),

            KeyType::EcP384 => (
                KeyPair::Ecdsa(EcdsaKeyPairInternal {
                    private_key: private_key.clone(),
                    public_key: Vec::new(),
                    curve: EcCurve::P384,
                }),
                Algorithm::EcdsaP384Sha384,
            ),

            // EdDSA keys
            KeyType::Ed25519 => {
                let key_pair = Ed25519KeyPair::from_pkcs8(&private_key)
                    .map_err(|_| Error::KeyGeneration("Failed to parse Ed25519 PKCS#8".into()))?;
                let public_key = key_pair.public_key().as_ref().to_vec();

                (
                    KeyPair::Ed25519(Ed25519KeyPairInternal {
                        key_pair,
                        public_key,
                    }),
                    Algorithm::Ed25519,
                )
            }

            _ => {
                return Err(Error::NotImplemented(format!(
                    "Key import for {:?} not yet implemented",
                    key_type
                )));
            }
        };

        // Generate unique key ID
        let key_id = Uuid::new_v4().as_bytes().to_vec();

        // Store in HashMap
        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), key_pair);
        }

        // Return KeyHandle
        Ok(KeyHandle::new(
            ProviderId::Software,
            key_id,
            key_type,
            algorithm,
            label.to_string(),
        ))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<()> {
        // Validate provider
        if !matches!(key.provider_id, ProviderId::Software) {
            return Err(Error::InvalidKeyHandle(
                "Key handle is not from software provider".into(),
            ));
        }

        // Remove from HashMap (write lock)
        // Drop impl on KeyPair will zeroize private key material
        let mut keys = self.keys.write().unwrap();
        keys.remove(&key.key_id);

        Ok(())
    }

    async fn wrap_key(
        &self,
        _key_to_wrap: &KeyHandle,
        _wrapping_key: &KeyHandle,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "Key wrapping deferred to Phase 8 Part 2".into(),
        ))
    }

    async fn unwrap_key(
        &self,
        _wrapped_key: &[u8],
        _unwrapping_key: &KeyHandle,
        _key_type: KeyType,
        _label: &str,
    ) -> Result<KeyHandle> {
        Err(Error::NotImplemented(
            "Key unwrapping deferred to Phase 8 Part 2".into(),
        ))
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::Software
    }

    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let keys = self.keys.read().unwrap();
        let mut handles = Vec::new();

        for (key_id, key_pair) in keys.iter() {
            let (key_type, algorithm) = match key_pair {
                KeyPair::Rsa(rsa_kp) => {
                    let bits = rsa_kp.private_key.size() * 8;
                    let key_type = match bits {
                        2048 => KeyType::Rsa2048,
                        3072 => KeyType::Rsa3072,
                        4096 => KeyType::Rsa4096,
                        _ => continue, // Skip unknown sizes
                    };
                    (key_type, Algorithm::RsaPssSha256)
                }
                KeyPair::Ecdsa(ecdsa_kp) => match ecdsa_kp.curve {
                    EcCurve::P256 => (KeyType::EcP256, Algorithm::EcdsaP256Sha256),
                    EcCurve::P384 => (KeyType::EcP384, Algorithm::EcdsaP384Sha384),
                    EcCurve::P521 => continue, // Not implemented
                },
                KeyPair::Ed25519(_) => (KeyType::Ed25519, Algorithm::Ed25519),
            };

            handles.push(KeyHandle::new(
                ProviderId::Software,
                key_id.clone(),
                key_type,
                algorithm,
                String::new(), // Label not stored in this implementation
            ));
        }

        Ok(handles)
    }
}
