//! Cryptographic algorithm definitions
//!
//! FIPS 186-5: Digital Signature Standard
//! FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//! FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//! FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

use serde::{Deserialize, Serialize};

/// Key types supported by the cryptographic provider
/// NIST 800-53: SC-12 - Cryptographic key establishment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    // Classical RSA
    Rsa2048,
    Rsa3072,
    Rsa4096,

    // Classical Elliptic Curve
    EcP256,
    EcP384,
    EcP521,

    // EdDSA - RFC 8410
    Ed25519,
    Ed448,

    // FIPS 203: ML-KEM (Post-Quantum Key Encapsulation)
    MlKem512,  // NIST Security Level 1
    MlKem768,  // NIST Security Level 3
    MlKem1024, // NIST Security Level 5

    // FIPS 204: ML-DSA (Post-Quantum Signatures)
    MlDsa44, // NIST Security Level 2
    MlDsa65, // NIST Security Level 3
    MlDsa87, // NIST Security Level 5

    // FIPS 205: SLH-DSA (Hash-Based Signatures)
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
}

impl KeyType {
    /// Returns the key size in bits
    pub fn key_size_bits(&self) -> usize {
        match self {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
            KeyType::EcP256 => 256,
            KeyType::EcP384 => 384,
            KeyType::EcP521 => 521,
            KeyType::Ed25519 => 256,
            KeyType::Ed448 => 448,
            KeyType::MlKem512 => 512,
            KeyType::MlKem768 => 768,
            KeyType::MlKem1024 => 1024,
            KeyType::MlDsa44 => 128, // Security level equivalent
            KeyType::MlDsa65 => 192,
            KeyType::MlDsa87 => 256,
            KeyType::SlhDsaSha2_128s | KeyType::SlhDsaSha2_128f => 128,
            KeyType::SlhDsaSha2_192s | KeyType::SlhDsaSha2_192f => 192,
            KeyType::SlhDsaSha2_256s | KeyType::SlhDsaSha2_256f => 256,
        }
    }

    /// Returns true if this is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            KeyType::MlKem512
                | KeyType::MlKem768
                | KeyType::MlKem1024
                | KeyType::MlDsa44
                | KeyType::MlDsa65
                | KeyType::MlDsa87
                | KeyType::SlhDsaSha2_128s
                | KeyType::SlhDsaSha2_128f
                | KeyType::SlhDsaSha2_192s
                | KeyType::SlhDsaSha2_192f
                | KeyType::SlhDsaSha2_256s
                | KeyType::SlhDsaSha2_256f
        )
    }

    /// Returns true if this is a signature algorithm
    pub fn is_signature_algorithm(&self) -> bool {
        !matches!(
            self,
            KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024
        )
    }
}

/// Signature and hash algorithms
/// FIPS 186-5: Digital Signature Standard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    // RSA with PKCS#1 v1.5 padding
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,

    // RSA with PSS padding (preferred)
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,

    // ECDSA
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,

    // EdDSA (deterministic)
    Ed25519,
    Ed448,

    // Post-Quantum Signatures - FIPS 204
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // Hash-Based Signatures - FIPS 205
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,

    // Hybrid (Classical + PQC)
    EcdsaP256MlDsa44,
    EcdsaP384MlDsa65,
    Ed25519MlDsa44,
}

impl Algorithm {
    /// Get the compatible key types for this algorithm
    pub fn compatible_key_types(&self) -> Vec<KeyType> {
        match self {
            Algorithm::RsaPkcs1Sha256
            | Algorithm::RsaPkcs1Sha384
            | Algorithm::RsaPkcs1Sha512
            | Algorithm::RsaPssSha256
            | Algorithm::RsaPssSha384
            | Algorithm::RsaPssSha512 => {
                vec![KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096]
            }
            Algorithm::EcdsaP256Sha256 => vec![KeyType::EcP256],
            Algorithm::EcdsaP384Sha384 => vec![KeyType::EcP384],
            Algorithm::EcdsaP521Sha512 => vec![KeyType::EcP521],
            Algorithm::Ed25519 => vec![KeyType::Ed25519],
            Algorithm::Ed448 => vec![KeyType::Ed448],
            Algorithm::MlDsa44 => vec![KeyType::MlDsa44],
            Algorithm::MlDsa65 => vec![KeyType::MlDsa65],
            Algorithm::MlDsa87 => vec![KeyType::MlDsa87],
            Algorithm::SlhDsaSha2_128s => vec![KeyType::SlhDsaSha2_128s],
            Algorithm::SlhDsaSha2_128f => vec![KeyType::SlhDsaSha2_128f],
            Algorithm::SlhDsaSha2_192s => vec![KeyType::SlhDsaSha2_192s],
            Algorithm::SlhDsaSha2_192f => vec![KeyType::SlhDsaSha2_192f],
            Algorithm::SlhDsaSha2_256s => vec![KeyType::SlhDsaSha2_256s],
            Algorithm::SlhDsaSha2_256f => vec![KeyType::SlhDsaSha2_256f],
            Algorithm::EcdsaP256MlDsa44 => vec![KeyType::EcP256, KeyType::MlDsa44],
            Algorithm::EcdsaP384MlDsa65 => vec![KeyType::EcP384, KeyType::MlDsa65],
            Algorithm::Ed25519MlDsa44 => vec![KeyType::Ed25519, KeyType::MlDsa44],
        }
    }

    /// Returns true if this is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaSha2_128s
                | Algorithm::SlhDsaSha2_128f
                | Algorithm::SlhDsaSha2_192s
                | Algorithm::SlhDsaSha2_192f
                | Algorithm::SlhDsaSha2_256s
                | Algorithm::SlhDsaSha2_256f
        )
    }

    /// Returns true if this is a hybrid algorithm
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Algorithm::EcdsaP256MlDsa44 | Algorithm::EcdsaP384MlDsa65 | Algorithm::Ed25519MlDsa44
        )
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::RsaPkcs1Sha256 => write!(f, "RSA-PKCS1-SHA256"),
            Algorithm::RsaPkcs1Sha384 => write!(f, "RSA-PKCS1-SHA384"),
            Algorithm::RsaPkcs1Sha512 => write!(f, "RSA-PKCS1-SHA512"),
            Algorithm::RsaPssSha256 => write!(f, "RSA-PSS-SHA256"),
            Algorithm::RsaPssSha384 => write!(f, "RSA-PSS-SHA384"),
            Algorithm::RsaPssSha512 => write!(f, "RSA-PSS-SHA512"),
            Algorithm::EcdsaP256Sha256 => write!(f, "ECDSA-P256-SHA256"),
            Algorithm::EcdsaP384Sha384 => write!(f, "ECDSA-P384-SHA384"),
            Algorithm::EcdsaP521Sha512 => write!(f, "ECDSA-P521-SHA512"),
            Algorithm::Ed25519 => write!(f, "Ed25519"),
            Algorithm::Ed448 => write!(f, "Ed448"),
            Algorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            Algorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            Algorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            Algorithm::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s"),
            Algorithm::SlhDsaSha2_128f => write!(f, "SLH-DSA-SHA2-128f"),
            Algorithm::SlhDsaSha2_192s => write!(f, "SLH-DSA-SHA2-192s"),
            Algorithm::SlhDsaSha2_192f => write!(f, "SLH-DSA-SHA2-192f"),
            Algorithm::SlhDsaSha2_256s => write!(f, "SLH-DSA-SHA2-256s"),
            Algorithm::SlhDsaSha2_256f => write!(f, "SLH-DSA-SHA2-256f"),
            Algorithm::EcdsaP256MlDsa44 => write!(f, "ECDSA-P256+ML-DSA-44"),
            Algorithm::EcdsaP384MlDsa65 => write!(f, "ECDSA-P384+ML-DSA-65"),
            Algorithm::Ed25519MlDsa44 => write!(f, "Ed25519+ML-DSA-44"),
        }
    }
}
