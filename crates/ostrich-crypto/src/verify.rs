//! Stateless signature verification with caller-supplied public keys
//!
//! Protocol layers (ACME JWS, EST CSR proof-of-possession) verify signatures
//! made by EXTERNAL parties whose public keys arrive in the request. Those
//! keys are not - and must not be - resident in the crypto provider's key
//! store, so verification here is a pure function over the SPKI bytes rather
//! than a `CryptoProvider` keystore operation.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - AWS-LC FIPS verification
//! - NIST 800-53: IA-5 - authenticator (public key) verification
//! - NIST 800-53: SI-10 - input validation of attacker-supplied key material
//! - RFC 7515 §5.2 - JWS signature validation (ECDSA signatures are the raw
//!   fixed-size r||s concatenation, not ASN.1 DER)

use crate::{Algorithm, Error, Result};
use aws_lc_rs::signature::{self, UnparsedPublicKey};

/// Verify a signature with a DER-encoded SubjectPublicKeyInfo.
///
/// `ecdsa_fixed` selects the JWS signature form for ECDSA (raw r||s,
/// RFC 7515) instead of ASN.1 DER (X.509/CMS form).
pub fn verify_with_spki(
    spki_der: &[u8],
    algorithm: Algorithm,
    data: &[u8],
    signature: &[u8],
    ecdsa_fixed: bool,
) -> Result<bool> {
    // Extract the raw key material from the SPKI envelope: ring expects
    // PKCS#1 RSAPublicKey bytes for RSA, the uncompressed point for ECDSA,
    // and the raw 32 bytes for Ed25519 - all of which are exactly the SPKI
    // subjectPublicKey BIT STRING contents.
    let spki = spki::SubjectPublicKeyInfoOwned::try_from(spki_der)
        .map_err(|e| Error::InvalidInput(format!("Invalid SubjectPublicKeyInfo: {}", e)))?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::InvalidInput("Unaligned public key BIT STRING".to_string()))?;

    let alg: &'static dyn signature::VerificationAlgorithm = match (algorithm, ecdsa_fixed) {
        (Algorithm::RsaPkcs1Sha256, _) => &signature::RSA_PKCS1_2048_8192_SHA256,
        (Algorithm::RsaPkcs1Sha384, _) => &signature::RSA_PKCS1_2048_8192_SHA384,
        (Algorithm::RsaPkcs1Sha512, _) => &signature::RSA_PKCS1_2048_8192_SHA512,
        (Algorithm::RsaPssSha256, _) => &signature::RSA_PSS_2048_8192_SHA256,
        (Algorithm::RsaPssSha384, _) => &signature::RSA_PSS_2048_8192_SHA384,
        (Algorithm::RsaPssSha512, _) => &signature::RSA_PSS_2048_8192_SHA512,
        (Algorithm::EcdsaP256Sha256, true) => &signature::ECDSA_P256_SHA256_FIXED,
        (Algorithm::EcdsaP256Sha256, false) => &signature::ECDSA_P256_SHA256_ASN1,
        (Algorithm::EcdsaP384Sha384, true) => &signature::ECDSA_P384_SHA384_FIXED,
        (Algorithm::EcdsaP384Sha384, false) => &signature::ECDSA_P384_SHA384_ASN1,
        (Algorithm::Ed25519, _) => &signature::ED25519,
        (other, _) => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "Stateless verification not supported for {:?}",
                other
            )));
        }
    };

    // ring returns an opaque error on mismatch; map to Ok(false) so callers
    // can distinguish "bad signature" from "malformed input" (SI-11).
    Ok(UnparsedPublicKey::new(alg, key_bytes)
        .verify(data, signature)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::OsRng;
    use sha2::Digest;

    #[test]
    fn rsa_pkcs1_sha256_roundtrip() {
        let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let data = b"jws signing input";
        // Standard RS256: PKCS#1 v1.5 over SHA-256 with the DigestInfo prefix
        // (RFC 8017 EMSA-PKCS1-v1_5) - what real JWS signers and ring's
        // RSA_PKCS1_*_SHA256 verifier both use.
        let digest = sha2::Sha256::digest(data);
        let sig = private
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest)
            .unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();

        assert!(
            verify_with_spki(spki.as_bytes(), Algorithm::RsaPkcs1Sha256, data, &sig, false)
                .unwrap()
        );
        // Tampered data must fail verification, not error
        assert!(
            !verify_with_spki(spki.as_bytes(), Algorithm::RsaPkcs1Sha256, b"other", &sig, false)
                .unwrap()
        );
    }

    #[test]
    fn rejects_garbage_spki() {
        assert!(
            verify_with_spki(&[0u8; 10], Algorithm::RsaPkcs1Sha256, b"d", b"s", false).is_err()
        );
    }
}
