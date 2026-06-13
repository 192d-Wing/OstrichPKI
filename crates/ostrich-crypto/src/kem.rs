//! FIPS 203 ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism).
//!
//! ML-KEM is a key-encapsulation mechanism, not a signature scheme, so it does
//! not fit the sign/verify-oriented [`crate::CryptoProvider`] trait. It is
//! exposed here as a focused module providing the three FIPS 203 operations:
//!
//! * `ML-KEM.KeyGen`  -> [`MlKemKeyPair::generate`]
//! * `ML-KEM.Encaps`  -> [`encapsulate`]
//! * `ML-KEM.Decaps`  -> [`MlKemKeyPair::decapsulate`]
//!
//! plus raw key import/export so escrowed decapsulation keys can be persisted
//! and recovered by the KRA.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management),
//!   SC-13 (Cryptographic Protection), SI-12 (Information Handling — shared
//!   secrets and private keys are zeroized on drop)
//! - NIAP PP-CA: FCS_CKM.1 (key generation), FCS_CKM.2 (key establishment)
//! - FIPS 203: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5)
//! - draft-ietf-lamps-kyber-certificates: raw ek/dk encodings used here are the
//!   FIPS 203 standard encodings that the X.509 SubjectPublicKey carries.
//!
//! Backed by AWS aws-lc-rs's STABLE `kem` module. The same ML-KEM algorithm IDs
//! are implemented inside AWS-LC's FIPS module (`aws-lc-fips-sys`), so unlike
//! our ML-DSA path this code is FIPS-validatable today (see
//! `docs/compliance/FIPS_COMPLIANCE.md`). Unlike ML-DSA, ML-KEM is NOT gated by
//! the `unstable` feature and is available under the `fips` feature as well.

use crate::{Error, KeyType, Result};
use aws_lc_rs::kem::{
    Algorithm, AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_512,
    ML_KEM_768, ML_KEM_1024,
};
use zeroize::Zeroizing;

/// Map an ML-KEM [`KeyType`] to the aws-lc-rs algorithm constant.
///
/// FIPS 203: parameter-set selection.
fn algorithm_for(key_type: KeyType) -> Result<&'static Algorithm<AlgorithmId>> {
    match key_type {
        KeyType::MlKem512 => Ok(&ML_KEM_512),
        KeyType::MlKem768 => Ok(&ML_KEM_768),
        KeyType::MlKem1024 => Ok(&ML_KEM_1024),
        other => Err(Error::UnsupportedAlgorithm(format!(
            "{other:?} is not an ML-KEM key type"
        ))),
    }
}

/// Result of an ML-KEM encapsulation (FIPS 203 §6.2, `ML-KEM.Encaps`).
pub struct Encapsulation {
    /// The ciphertext to transmit to the holder of the decapsulation key.
    /// FIPS 203 ciphertext `c` (raw, standard encoding).
    pub ciphertext: Vec<u8>,
    /// The derived shared secret `K`. Sensitive key material — zeroized on drop.
    ///
    /// NIST 800-53: SI-12 - shared secret handled as sensitive data.
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// An ML-KEM key pair: the private decapsulation key (`dk`) plus its parameter
/// set. The public encapsulation key (`ek`) is derived on demand.
///
/// NIAP PP-CA: FCS_CKM.1 - generated/held cryptographic key.
pub struct MlKemKeyPair {
    decapsulation_key: DecapsulationKey<AlgorithmId>,
    key_type: KeyType,
}

impl MlKemKeyPair {
    /// Generate a fresh ML-KEM key pair (FIPS 203 §6.1, `ML-KEM.KeyGen`).
    ///
    /// NIAP PP-CA: FCS_CKM.1 - cryptographic key generation.
    /// NIST 800-53: SC-12 - key establishment.
    pub fn generate(key_type: KeyType) -> Result<Self> {
        let alg = algorithm_for(key_type)?;
        let decapsulation_key = DecapsulationKey::generate(alg)
            .map_err(|e| Error::KeyGeneration(format!("ML-KEM key generation failed: {e}")))?;
        Ok(Self {
            decapsulation_key,
            key_type,
        })
    }

    /// Reconstruct a key pair from a previously exported raw decapsulation key
    /// (`dk`). Used by the KRA to recover an escrowed ML-KEM private key.
    ///
    /// NIST 800-53: SC-12 - cryptographic key recovery.
    pub fn from_private_key_bytes(key_type: KeyType, dk_bytes: &[u8]) -> Result<Self> {
        let alg = algorithm_for(key_type)?;
        let decapsulation_key = DecapsulationKey::new(alg, dk_bytes)
            .map_err(|e| Error::InvalidKeyType(format!("ML-KEM private key import failed: {e}")))?;
        Ok(Self {
            decapsulation_key,
            key_type,
        })
    }

    /// The parameter set of this key pair.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Export the raw private decapsulation key (`dk`, FIPS 203 §6.1).
    ///
    /// SENSITIVE. Intended only for KRA escrow; the bytes are zeroized on drop.
    ///
    /// NIST 800-53: SI-12 - sensitive private key, zeroized after use.
    /// NIST 800-53: SC-12 - key storage/escrow.
    pub fn private_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self
            .decapsulation_key
            .key_bytes()
            .map_err(|e| Error::Encoding(format!("ML-KEM private key export failed: {e}")))?;
        Ok(Zeroizing::new(bytes.as_ref().to_vec()))
    }

    /// Export the raw public encapsulation key (`ek`, FIPS 203 §6.1). This is
    /// the value the X.509 SubjectPublicKey carries
    /// (draft-ietf-lamps-kyber-certificates).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let ek = self
            .decapsulation_key
            .encapsulation_key()
            .map_err(|e| Error::Encoding(format!("ML-KEM public key derivation failed: {e}")))?;
        let bytes = ek
            .key_bytes()
            .map_err(|e| Error::Encoding(format!("ML-KEM public key export failed: {e}")))?;
        Ok(bytes.as_ref().to_vec())
    }

    /// Decapsulate a ciphertext to recover the shared secret (FIPS 203 §6.3,
    /// `ML-KEM.Decaps`).
    ///
    /// Per FIPS 203 the decapsulation is constant-time and uses implicit
    /// rejection: a malformed/tampered ciphertext does not error but yields a
    /// pseudo-random shared secret that will not match the sender's.
    ///
    /// NIAP PP-CA: FCS_CKM.2 - key establishment (receiver side).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let shared_secret = self
            .decapsulation_key
            .decapsulate(Ciphertext::from(ciphertext))
            .map_err(|e| Error::Cryptographic(format!("ML-KEM decapsulation failed: {e}")))?;
        Ok(Zeroizing::new(shared_secret.as_ref().to_vec()))
    }
}

/// Encapsulate to a raw public encapsulation key (`ek`), producing a ciphertext
/// and the shared secret (FIPS 203 §6.2, `ML-KEM.Encaps`).
///
/// `key_type` must match the parameter set of `ek`; the import fails otherwise.
///
/// NIAP PP-CA: FCS_CKM.2 - key establishment (sender side).
/// NIST 800-53: SC-12 - cryptographic key establishment.
pub fn encapsulate(key_type: KeyType, ek_bytes: &[u8]) -> Result<Encapsulation> {
    let alg = algorithm_for(key_type)?;
    let ek = EncapsulationKey::new(alg, ek_bytes)
        .map_err(|e| Error::InvalidKeyType(format!("ML-KEM public key import failed: {e}")))?;
    let (ciphertext, shared_secret) = ek
        .encapsulate()
        .map_err(|e| Error::Cryptographic(format!("ML-KEM encapsulation failed: {e}")))?;
    Ok(Encapsulation {
        ciphertext: ciphertext.as_ref().to_vec(),
        shared_secret: Zeroizing::new(shared_secret.as_ref().to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203 Table 3 sizes: (ek, dk, ciphertext) in bytes. Shared secret is
    /// always 32 bytes.
    fn expected_sizes(kt: KeyType) -> (usize, usize, usize) {
        match kt {
            KeyType::MlKem512 => (800, 1632, 768),
            KeyType::MlKem768 => (1184, 2400, 1088),
            KeyType::MlKem1024 => (1568, 3168, 1568),
            _ => unreachable!(),
        }
    }

    const PARAM_SETS: [KeyType; 3] = [KeyType::MlKem512, KeyType::MlKem768, KeyType::MlKem1024];

    #[test]
    fn encaps_decaps_round_trip_all_param_sets() {
        for kt in PARAM_SETS {
            let kp = MlKemKeyPair::generate(kt).unwrap();
            let ek = kp.public_key_bytes().unwrap();
            let enc = encapsulate(kt, &ek).unwrap();
            let recovered = kp.decapsulate(&enc.ciphertext).unwrap();
            assert_eq!(
                enc.shared_secret.as_slice(),
                recovered.as_slice(),
                "{kt:?}: sender and receiver shared secrets must match"
            );
            assert_eq!(enc.shared_secret.len(), 32, "{kt:?}: shared secret is 32 bytes");
        }
    }

    #[test]
    fn key_and_ciphertext_sizes_match_fips_203() {
        for kt in PARAM_SETS {
            let (ek_len, dk_len, ct_len) = expected_sizes(kt);
            let kp = MlKemKeyPair::generate(kt).unwrap();
            assert_eq!(kp.public_key_bytes().unwrap().len(), ek_len, "{kt:?} ek size");
            assert_eq!(kp.private_key_bytes().unwrap().len(), dk_len, "{kt:?} dk size");
            let enc = encapsulate(kt, &kp.public_key_bytes().unwrap()).unwrap();
            assert_eq!(enc.ciphertext.len(), ct_len, "{kt:?} ciphertext size");
        }
    }

    #[test]
    fn private_key_escrow_round_trip() {
        // Simulates KRA escrow: export dk, persist, recover, decapsulate.
        for kt in PARAM_SETS {
            let kp = MlKemKeyPair::generate(kt).unwrap();
            let ek = kp.public_key_bytes().unwrap();
            let dk = kp.private_key_bytes().unwrap();

            let enc = encapsulate(kt, &ek).unwrap();

            let recovered_kp = MlKemKeyPair::from_private_key_bytes(kt, &dk).unwrap();
            let ss = recovered_kp.decapsulate(&enc.ciphertext).unwrap();
            assert_eq!(
                ss.as_slice(),
                enc.shared_secret.as_slice(),
                "{kt:?}: recovered escrow key must decapsulate to the same secret"
            );
        }
    }

    #[test]
    fn tampered_ciphertext_yields_different_secret() {
        // FIPS 203 implicit rejection: decaps does not error but the secret diverges.
        let kt = KeyType::MlKem768;
        let kp = MlKemKeyPair::generate(kt).unwrap();
        let ek = kp.public_key_bytes().unwrap();
        let enc = encapsulate(kt, &ek).unwrap();

        let mut bad = enc.ciphertext.clone();
        bad[0] ^= 0xFF;
        let recovered = kp.decapsulate(&bad).unwrap();
        assert_ne!(
            recovered.as_slice(),
            enc.shared_secret.as_slice(),
            "tampered ciphertext must not recover the original shared secret"
        );
    }

    #[test]
    fn wrong_param_set_for_public_key_is_rejected() {
        let kp = MlKemKeyPair::generate(KeyType::MlKem512).unwrap();
        let ek = kp.public_key_bytes().unwrap();
        // A 512 ek is the wrong length for 768; import must fail.
        assert!(encapsulate(KeyType::MlKem768, &ek).is_err());
    }

    #[test]
    fn non_ml_kem_key_type_is_rejected() {
        assert!(MlKemKeyPair::generate(KeyType::EcP256).is_err());
        assert!(algorithm_for(KeyType::MlDsa65).is_err());
    }
}
