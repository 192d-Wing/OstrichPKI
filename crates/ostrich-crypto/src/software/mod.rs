//! Software cryptography provider backed by the AWS-LC FIPS 140-3 module
//!
//! NIST 800-53: SC-13 - Cryptographic protection
//! NIST 800-53: SC-12 - Cryptographic key generation
//! NIAP PP-CA: FCS_CKM.1 / FCS_COP.1 / FCS_RBG_EXT.1
//!
//! All classical signature, hashing, key-generation, and random-bit operations
//! run inside the FIPS-validated AWS-LC module via `aws-lc-rs` (the workspace
//! enables its `fips` feature). The previous `ring` (ECDSA/Ed25519) and
//! pure-Rust `rsa` backends — neither FIPS-validated — have been removed.
//!
//! ML-DSA (FIPS 204) is NOT available here: it requires `aws-lc-rs`'s
//! `unstable` feature, which is mutually exclusive with `fips`. ML-KEM
//! (FIPS 203) remains available via [`crate::kem`] (stable, in-FIPS-module).
//!
//! Note: for production CA signing keys, prefer the PKCS#11 HSM provider; this
//! software provider keeps private keys in process memory.

use crate::{Algorithm, Error, KeyHandle, KeyType, Result, key::ProviderId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

// FIPS-validated cryptography via AWS-LC (aws-lc-rs `fips` feature).
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as AwsRsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING, ED25519, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair as AwsKeyPairTrait, UnparsedPublicKey,
};

// SPKI/DER encoding for ECDSA/Ed25519 public keys (raw key bytes -> SPKI).
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

/// RSA key pair, backed by the AWS-LC FIPS module.
///
/// Holds the signing key plus cached public-key encodings: the RFC 8017
/// `RSAPublicKey` (PKCS#1) bytes used for verification, and the
/// SubjectPublicKeyInfo (SPKI) DER used for certificate issuance.
struct RsaKeyPairInternal {
    key_pair: AwsRsaKeyPair,
    public_pkcs1_der: Vec<u8>,
    spki_der: Vec<u8>,
    bits: usize,
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
    Rsa(Box<RsaKeyPairInternal>), // Boxed to reduce enum size
    Ecdsa(EcdsaKeyPairInternal),
    Ed25519(Ed25519KeyPairInternal),
}

// Implement Drop to manually zeroize private key material
impl Drop for KeyPair {
    fn drop(&mut self) {
        match self {
            KeyPair::Rsa(_) => {
                // aws-lc-rs KeyPair zeroizes its private key on drop
            }
            KeyPair::Ecdsa(_) => {
                // Zeroizing<Vec<u8>> zeroizes itself on drop
            }
            KeyPair::Ed25519(_) => {
                // aws-lc-rs Ed25519KeyPair zeroizes its private key on drop
            }
        }
    }
}

/// Software provider using the AWS-LC FIPS module for cryptographic operations
///
/// NIAP PP-CA: FCS_RBG_EXT.1 - Random bit generation via the FIPS DRBG
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

    // ========== RSA Operations (FIPS, via AWS-LC) ==========

    /// Map a key size in bits to the aws-lc-rs `KeySize`.
    fn rsa_key_size(bits: usize) -> Result<KeySize> {
        match bits {
            2048 => Ok(KeySize::Rsa2048),
            3072 => Ok(KeySize::Rsa3072),
            4096 => Ok(KeySize::Rsa4096),
            other => Err(Error::UnsupportedAlgorithm(format!(
                "Unsupported RSA modulus size: {other} bits"
            ))),
        }
    }

    /// Build the internal RSA representation (cached public encodings) from an
    /// aws-lc-rs key pair.
    fn rsa_internal(key_pair: AwsRsaKeyPair, bits: usize) -> Result<RsaKeyPairInternal> {
        let public_key = AwsKeyPairTrait::public_key(&key_pair);
        // `AsRef<[u8]>` on the RSA public key yields RFC 8017 `RSAPublicKey`
        // (PKCS#1) DER, which the aws-lc-rs RSA verifiers consume directly.
        let public_pkcs1_der = public_key.as_ref().to_vec();
        // `AsDer<PublicKeyX509Der>` yields the SubjectPublicKeyInfo for X.509.
        let spki_der = public_key
            .as_der()
            .map_err(|e| Error::Encoding(format!("RSA SPKI export failed: {e}")))?
            .as_ref()
            .to_vec();
        Ok(RsaKeyPairInternal {
            key_pair,
            public_pkcs1_der,
            spki_der,
            bits,
        })
    }

    /// Generate an RSA key pair using the FIPS key-generation path (includes the
    /// FIPS pairwise consistency test).
    ///
    /// NIAP PP-CA: FCS_CKM.1 - cryptographic key generation
    fn generate_rsa_key_pair(bits: usize) -> Result<RsaKeyPairInternal> {
        let size = Self::rsa_key_size(bits)?;
        // Under the `fips` feature, `generate` is the FIPS-validated key
        // generation path (the separate `generate_fips` is deprecated/redundant).
        let key_pair = AwsRsaKeyPair::generate(size)
            .map_err(|e| Error::KeyGeneration(format!("RSA key generation failed: {e}")))?;
        Self::rsa_internal(key_pair, bits)
    }

    /// Map an RSA `Algorithm` to the aws-lc-rs signing padding.
    fn rsa_padding(algorithm: Algorithm) -> Result<&'static dyn signature::RsaEncoding> {
        match algorithm {
            Algorithm::RsaPkcs1Sha256 => Ok(&signature::RSA_PKCS1_SHA256),
            Algorithm::RsaPkcs1Sha384 => Ok(&signature::RSA_PKCS1_SHA384),
            Algorithm::RsaPkcs1Sha512 => Ok(&signature::RSA_PKCS1_SHA512),
            Algorithm::RsaPssSha256 => Ok(&signature::RSA_PSS_SHA256),
            Algorithm::RsaPssSha384 => Ok(&signature::RSA_PSS_SHA384),
            Algorithm::RsaPssSha512 => Ok(&signature::RSA_PSS_SHA512),
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Algorithm {algorithm:?} not supported for RSA signing"
            ))),
        }
    }

    /// Sign with RSA (PKCS#1 v1.5 or PSS, per `algorithm`).
    fn sign_rsa(
        key_pair: &RsaKeyPairInternal,
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        let padding = Self::rsa_padding(algorithm)?;
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; key_pair.key_pair.public_modulus_len()];
        key_pair
            .key_pair
            .sign(padding, &rng, data, &mut signature)
            .map_err(|e| Error::Signing(format!("RSA signing failed: {e}")))?;
        Ok(signature)
    }

    /// Verify an RSA signature against the key pair's public key.
    fn verify_rsa(
        key_pair: &RsaKeyPairInternal,
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        let alg: &'static dyn signature::VerificationAlgorithm = match algorithm {
            Algorithm::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Algorithm::RsaPkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Algorithm::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
            Algorithm::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
            Algorithm::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Algorithm {algorithm:?} not supported for RSA verification"
                )));
            }
        };
        Ok(UnparsedPublicKey::new(alg, &key_pair.public_pkcs1_der)
            .verify(data, signature)
            .is_ok())
    }

    /// Export RSA public key as SPKI DER (cached at key generation/import).
    fn export_rsa_spki(key_pair: &RsaKeyPairInternal) -> Result<Vec<u8>> {
        Ok(key_pair.spki_der.clone())
    }

    // ========== ECDSA Operations (FIPS, via AWS-LC) ==========

    /// Generate ECDSA key pair.
    ///
    /// NIAP PP-CA: FCS_CKM.1 - key generation using the FIPS module's DRBG.
    fn generate_ecdsa_key_pair(&self, curve: EcCurve) -> Result<EcdsaKeyPairInternal> {
        let rng = SystemRandom::new();

        match curve {
            EcCurve::P256 => {
                let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &rng,
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-256 key generation failed: {e:?}"))
                })?;

                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-256 key parse failed: {e:?}"))
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
                    Error::KeyGeneration(format!("ECDSA P-384 key generation failed: {e:?}"))
                })?;

                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                )
                .map_err(|e| {
                    Error::KeyGeneration(format!("ECDSA P-384 key parse failed: {e:?}"))
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

    /// Recover the raw ECDSA public key from a stored PKCS#8 private key.
    fn ecdsa_public_from_pkcs8(curve: EcCurve, pkcs8: &[u8]) -> Result<Vec<u8>> {
        let alg = match curve {
            EcCurve::P256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcCurve::P384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
            EcCurve::P521 => {
                return Err(Error::NotImplemented(
                    "ECDSA P-521 deferred to Phase 8 Part 2".into(),
                ));
            }
        };
        let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8)
            .map_err(|_| Error::InvalidKeyType("Failed to parse ECDSA PKCS#8".into()))?;
        Ok(key_pair.public_key().as_ref().to_vec())
    }

    /// Sign with ECDSA.
    fn sign_ecdsa(
        &self,
        key_pair: &EcdsaKeyPairInternal,
        data: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        match key_pair.curve {
            EcCurve::P256 => {
                if !matches!(algorithm, Algorithm::EcdsaP256Sha256) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {algorithm:?} not compatible with P-256"
                    )));
                }

                let ecdsa_key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &key_pair.private_key,
                )
                .map_err(|_| Error::Signing("Failed to parse ECDSA P-256 key".into()))?;
                let signature = ecdsa_key_pair
                    .sign(&rng, data)
                    .map_err(|_| Error::Signing("ECDSA P-256 signing failed".into()))?;

                Ok(signature.as_ref().to_vec())
            }

            EcCurve::P384 => {
                if !matches!(algorithm, Algorithm::EcdsaP384Sha384) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {algorithm:?} not compatible with P-384"
                    )));
                }

                let ecdsa_key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    &key_pair.private_key,
                )
                .map_err(|_| Error::Signing("Failed to parse ECDSA P-384 key".into()))?;
                let signature = ecdsa_key_pair
                    .sign(&rng, data)
                    .map_err(|_| Error::Signing("ECDSA P-384 signing failed".into()))?;

                Ok(signature.as_ref().to_vec())
            }

            EcCurve::P521 => Err(Error::NotImplemented(
                "ECDSA P-521 signing deferred to Phase 8 Part 2".into(),
            )),
        }
    }

    /// Verify ECDSA signature (X.509/CMS ASN.1 form is produced by `sign`; this
    /// verifies the fixed r||s form emitted by aws-lc-rs `*_FIXED` signing).
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
                        "Algorithm {algorithm:?} not compatible with P-256"
                    )));
                }

                let public_key =
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key_pair.public_key);
                Ok(public_key.verify(data, signature).is_ok())
            }

            EcCurve::P384 => {
                if !matches!(algorithm, Algorithm::EcdsaP384Sha384) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {algorithm:?} not compatible with P-384"
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
        // ECDSA public key from aws-lc-rs is the raw uncompressed point; wrap in SPKI.
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
            .map_err(|e| Error::Encoding(format!("Failed to create BitString: {e}")))?;

        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        spki.to_der()
            .map_err(|e| Error::Encoding(format!("ECDSA SPKI encoding failed: {e}")))
    }

    // ========== Ed25519 Operations (FIPS, via AWS-LC) ==========

    /// Generate Ed25519 key pair.
    fn generate_ed25519_key_pair(&self) -> Result<Ed25519KeyPairInternal> {
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
            .map_err(|e| Error::Encoding(format!("Failed to create BitString: {e}")))?;

        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        spki.to_der()
            .map_err(|e| Error::Encoding(format!("Ed25519 SPKI encoding failed: {e}")))
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
                KeyPair::Ecdsa(self.generate_ecdsa_key_pair(EcCurve::P256)?),
                Algorithm::EcdsaP256Sha256,
            ),
            KeyType::EcP384 => (
                KeyPair::Ecdsa(self.generate_ecdsa_key_pair(EcCurve::P384)?),
                Algorithm::EcdsaP384Sha384,
            ),
            KeyType::EcP521 => {
                return Err(Error::NotImplemented(
                    "ECDSA P-521 key generation deferred to Phase 8 Part 2".into(),
                ));
            }

            // EdDSA keys
            KeyType::Ed25519 => (
                KeyPair::Ed25519(self.generate_ed25519_key_pair()?),
                Algorithm::Ed25519,
            ),
            KeyType::Ed448 => {
                return Err(Error::NotImplemented(
                    "Ed448 key generation deferred to Phase 8 Part 2".into(),
                ));
            }

            // ML-DSA (FIPS 204) is unavailable in a FIPS build: it requires
            // aws-lc-rs's `unstable` feature, mutually exclusive with `fips`.
            // ML-KEM (FIPS 203) is a KEM, not a signing key — see crate::kem.
            // SLH-DSA (FIPS 205) is not implemented.
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Key type {key_type:?} is not available in the FIPS software provider"
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
            KeyPair::Ecdsa(ecdsa_kp) => self.sign_ecdsa(ecdsa_kp, data, algorithm),
            KeyPair::Ed25519(ed_kp) => {
                if !matches!(algorithm, Algorithm::Ed25519) {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "Algorithm {algorithm:?} not compatible with Ed25519"
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
                        "Algorithm {algorithm:?} not compatible with Ed25519"
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

    /// Export the private key as PKCS#8 DER (RFC 5958). Supported for software
    /// RSA and ECDSA keys (used by EST server-side key generation, RFC 7030
    /// §4.4); Ed25519 export is not supported here. SI-12: the result is
    /// zeroizing and the caller must treat it as sensitive.
    async fn export_private_key(&self, key: &KeyHandle) -> Result<Zeroizing<Vec<u8>>> {
        if !matches!(key.provider_id, ProviderId::Software) {
            return Err(Error::InvalidKeyHandle(
                "Key handle is not from software provider".into(),
            ));
        }

        let keys = self.keys.read().unwrap();
        let key_pair = keys
            .get(&key.key_id)
            .ok_or_else(|| Error::InvalidKeyHandle("Key not found in software provider".into()))?;

        match key_pair {
            KeyPair::Rsa(rsa_kp) => {
                let doc = rsa_kp
                    .key_pair
                    .as_der()
                    .map_err(|e| Error::Encoding(format!("RSA PKCS#8 export failed: {e}")))?;
                Ok(Zeroizing::new(doc.as_ref().to_vec()))
            }
            // ECDSA private keys are already stored as PKCS#8 DER.
            KeyPair::Ecdsa(ecdsa_kp) => Ok(Zeroizing::new(ecdsa_kp.private_key.to_vec())),
            KeyPair::Ed25519(_) => Err(Error::NotImplemented(
                "private key export for this key type is not supported".to_string(),
            )),
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
                let aws_key_pair = AwsRsaKeyPair::from_pkcs8(&private_key).map_err(|e| {
                    Error::KeyGeneration(format!("Failed to parse RSA PKCS#8: {e}"))
                })?;
                let bits = aws_key_pair.public_modulus_len() * 8;
                (
                    KeyPair::Rsa(Box::new(Self::rsa_internal(aws_key_pair, bits)?)),
                    Algorithm::RsaPssSha256, // Default
                )
            }

            // ECDSA keys (stored as PKCS#8); recover the public key now so
            // verification works after import.
            KeyType::EcP256 => (
                KeyPair::Ecdsa(EcdsaKeyPairInternal {
                    public_key: Self::ecdsa_public_from_pkcs8(EcCurve::P256, &private_key)?,
                    private_key: private_key.clone(),
                    curve: EcCurve::P256,
                }),
                Algorithm::EcdsaP256Sha256,
            ),

            KeyType::EcP384 => (
                KeyPair::Ecdsa(EcdsaKeyPairInternal {
                    public_key: Self::ecdsa_public_from_pkcs8(EcCurve::P384, &private_key)?,
                    private_key: private_key.clone(),
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
                    "Key import for {key_type:?} not yet implemented"
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

    async fn generate_random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        // NIAP PP-CA: FCS_RBG_EXT.1 - random bits from the AWS-LC FIPS DRBG
        // NIST 800-53: SC-13 - FIPS-validated random number generation
        let mut buf = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut buf)
            .map_err(|_| Error::Entropy("AWS-LC FIPS DRBG fill failed".into()))?;
        Ok(buf)
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
                    let key_type = match rsa_kp.bits {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoProvider;

    /// export_private_key returns valid PKCS#8 for software RSA and ECDSA keys
    /// (used by EST server-side keygen), and errors for unsupported types.
    #[tokio::test]
    async fn export_private_key_pkcs8() {
        use pkcs8::PrivateKeyInfo;

        let provider = SoftwareProvider::new();

        // ECDSA P-256 and RSA-2048 must both export structurally valid PKCS#8.
        for (kt, label) in [(KeyType::EcP256, "exp-ec"), (KeyType::Rsa2048, "exp-rsa")] {
            let handle = provider.generate_key_pair(kt, label, true).await.unwrap();
            let pkcs8 = provider.export_private_key(&handle).await.unwrap();
            PrivateKeyInfo::try_from(pkcs8.as_slice())
                .unwrap_or_else(|e| panic!("{kt:?} export is not valid PKCS#8: {e}"));
        }

        // RSA PKCS#8 additionally round-trips through the rsa parser (dev-dep).
        use rsa::pkcs8::DecodePrivateKey;
        let rsa_key = provider
            .generate_key_pair(KeyType::Rsa2048, "exp-rsa2", true)
            .await
            .unwrap();
        let rsa_pkcs8 = provider.export_private_key(&rsa_key).await.unwrap();
        rsa::RsaPrivateKey::from_pkcs8_der(&rsa_pkcs8).expect("valid RSA PKCS#8");

        // Ed25519 export is not supported by this provider.
        let ed = provider
            .generate_key_pair(KeyType::Ed25519, "exp-ed", true)
            .await
            .unwrap();
        assert!(provider.export_private_key(&ed).await.is_err());
    }

    /// Software RSA PKCS#1 v1.5 signatures are standard (prefixed, RFC 8017) and
    /// verify through the stateless `verify_with_spki` path used by the CA, OCSP,
    /// CSR proof-of-possession, and audit signing.
    #[tokio::test]
    async fn rsa_pkcs1_signature_verifies_with_spki() {
        use crate::verify_with_spki;

        let provider = SoftwareProvider::new();
        let data = b"server-side keygen proof-of-possession payload";

        for (kt, alg) in [
            (KeyType::Rsa2048, Algorithm::RsaPkcs1Sha256),
            (KeyType::Rsa3072, Algorithm::RsaPkcs1Sha384),
        ] {
            let key = provider
                .generate_key_pair(kt, "rsa-spki", true)
                .await
                .unwrap();
            let spki = provider.export_public_key(&key).await.unwrap();
            let sig = provider.sign(&key, alg, data).await.unwrap();

            // The provider's own verify still round-trips.
            assert!(
                provider.verify(&key, alg, data, &sig).await.unwrap(),
                "{alg:?} provider self-verify"
            );
            // And the standard stateless verifier accepts it.
            assert!(
                verify_with_spki(&spki, alg, data, &sig, false).unwrap(),
                "{alg:?} must verify via verify_with_spki (prefixed PKCS#1)"
            );
            // A tampered message is rejected.
            assert!(!verify_with_spki(&spki, alg, b"other", &sig, false).unwrap());
        }
    }

    /// ECDSA and Ed25519 generate -> sign -> verify round-trip through the
    /// provider, all backed by the AWS-LC FIPS module.
    #[tokio::test]
    async fn ecdsa_ed25519_roundtrip() {
        let provider = SoftwareProvider::new();
        let msg = b"certificate TBS bytes";

        for (kt, alg) in [
            (KeyType::EcP256, Algorithm::EcdsaP256Sha256),
            (KeyType::EcP384, Algorithm::EcdsaP384Sha384),
            (KeyType::Ed25519, Algorithm::Ed25519),
        ] {
            let key = provider.generate_key_pair(kt, "sig", false).await.unwrap();
            let sig = provider.sign(&key, alg, msg).await.unwrap();
            assert!(
                provider.verify(&key, alg, msg, &sig).await.unwrap(),
                "{kt:?} verify"
            );
            assert!(
                !provider.verify(&key, alg, b"tampered", &sig).await.unwrap(),
                "{kt:?} must reject a different message"
            );
        }
    }
}
