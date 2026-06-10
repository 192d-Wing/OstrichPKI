//! Classical signature-algorithm agility for CA signing paths
//!
//! Three things must agree for a valid X.509 / CMS / OCSP signature
//! (RFC 5280 §4.1.1.2): the AlgorithmIdentifier inside the TBS, the outer
//! signatureAlgorithm, and the algorithm the private key actually signed with.
//! This module is the single source of truth that keeps them consistent:
//!
//! - [`recommended_signature_algorithm`] maps a CA key type to the signature
//!   algorithm to sign with.
//! - [`algorithm_identifier`] produces the matching X.509 AlgorithmIdentifier
//!   (OID + parameters) that goes into both the TBS `signature` field and the
//!   outer `signatureAlgorithm`.
//! - [`encode_x509_signature`] converts the crypto provider's raw signature
//!   bytes into the form X.509 puts in the signature BIT STRING (ECDSA needs
//!   fixed r||s -> ASN.1 DER `Ecdsa-Sig-Value`).
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - RFC 5280 §4.1.1.2: signatureAlgorithm / tbsCertificate.signature must match
//! - RFC 4055: RSA PKCS#1 AlgorithmIdentifiers carry explicit NULL parameters
//! - RFC 5758 §3.2: ECDSA AlgorithmIdentifiers omit parameters; ECDSA signatures
//!   are encoded as `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
//! - RFC 8410: id-Ed25519 (1.3.101.112), absent parameters
//!
//! ## FIPS Standards
//! - FIPS 186-5: Digital Signature Standard (RSA, ECDSA, EdDSA)
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FCS_COP.1: Cryptographic operation (signature generation / encoding)
//!
//! ## Crypto-agility extension point
//! ML-DSA (FIPS 204) / hybrid signature support plugs into each function at the
//! `// ML-DSA extension point` markers below. ML-DSA signatures are emitted raw
//! (like Ed25519), so only `recommended_signature_algorithm` and
//! `algorithm_identifier` need new arms; `encode_x509_signature` already passes
//! non-ECDSA signatures through unchanged.

use ostrich_crypto::{Algorithm, Error, KeyType, Result};

/// Map a CA key type to the classical signature algorithm to sign with.
///
/// RFC 5280 §4.1.1.2 - the returned algorithm drives both the
/// AlgorithmIdentifier emitted in the TBS and the actual signing call, keeping
/// them identical.
///
/// FIPS 186-5 - RSA / ECDSA / EdDSA signature algorithms
/// NIAP PP-CA: FCS_COP.1 - approved signature algorithm selection
pub fn recommended_signature_algorithm(key_type: KeyType) -> Result<Algorithm> {
    match key_type {
        // RSA: keep matching the existing RSA signing path (PKCS#1 v1.5, not
        // PSS) - the rest of the system expects sha256WithRSAEncryption here.
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => Ok(Algorithm::RsaPkcs1Sha256),

        // ECDSA - RFC 5758 §3.2; SHA-2 digest sized to the curve (FIPS 186-5).
        KeyType::EcP256 => Ok(Algorithm::EcdsaP256Sha256),
        KeyType::EcP384 => Ok(Algorithm::EcdsaP384Sha384),

        // EdDSA - RFC 8410.
        KeyType::Ed25519 => Ok(Algorithm::Ed25519),

        // P-521 is unsupported because the software crypto provider does not
        // implement ECDSA P-521 signing (see ostrich-crypto software::sign_ecdsa).
        KeyType::EcP521 => Err(Error::UnsupportedAlgorithm(
            "ECDSA P-521 is not supported for CA signing (software provider does not \
             implement P-521 signing)"
                .to_string(),
        )),

        // Post-quantum - FIPS 204 ML-DSA (via AWS aws-lc-rs in the provider).
        KeyType::MlDsa44 => Ok(Algorithm::MlDsa44),
        KeyType::MlDsa65 => Ok(Algorithm::MlDsa65),
        KeyType::MlDsa87 => Ok(Algorithm::MlDsa87),

        other => Err(Error::UnsupportedAlgorithm(format!(
            "key type {:?} is not a supported signing algorithm \
             (KEM/SLH-DSA/Ed448 signing is not supported here)",
            other
        ))),
    }
}

/// Build the X.509 AlgorithmIdentifier (OID + parameters) for a signature
/// algorithm.
///
/// This identifier is written into both `tbsCertificate.signature` and the
/// outer `signatureAlgorithm` (RFC 5280 §4.1.1.2), and the equivalent fields in
/// CRLs and OCSP responses.
///
/// RFC 4055 - RSA PKCS#1 identifiers carry explicit NULL parameters
/// RFC 5758 §3.2 - ECDSA identifiers omit parameters
/// RFC 8410 - id-Ed25519 omits parameters
pub fn algorithm_identifier(
    alg: Algorithm,
) -> Result<x509_cert::spki::AlgorithmIdentifierOwned> {
    use const_oid::ObjectIdentifier;
    use const_oid::db::rfc5912::{
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };

    // RFC 5758 §3.2 - ecdsa-with-SHA256 / ecdsa-with-SHA384
    const ECDSA_WITH_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    // RFC 8410 - id-Ed25519
    const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    // NIST CSOR id-ml-dsa-* (FIPS 204), parameters absent. These match the
    // OIDs aws-lc-rs writes into the ML-DSA SubjectPublicKeyInfo.
    const ID_ML_DSA_44: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
    const ID_ML_DSA_65: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
    const ID_ML_DSA_87: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

    let (oid, parameters) = match alg {
        // RFC 4055: RSA PKCS#1 v1.5 requires explicit NULL parameters.
        Algorithm::RsaPkcs1Sha256 => (
            SHA_256_WITH_RSA_ENCRYPTION,
            Some(der::Any::null()),
        ),
        Algorithm::RsaPkcs1Sha384 => (
            SHA_384_WITH_RSA_ENCRYPTION,
            Some(der::Any::null()),
        ),
        Algorithm::RsaPkcs1Sha512 => (
            SHA_512_WITH_RSA_ENCRYPTION,
            Some(der::Any::null()),
        ),

        // RFC 5758 §3.2: ECDSA AlgorithmIdentifiers omit parameters (None).
        Algorithm::EcdsaP256Sha256 => (ECDSA_WITH_SHA256, None),
        Algorithm::EcdsaP384Sha384 => (ECDSA_WITH_SHA384, None),

        // RFC 8410: id-Ed25519, parameters absent.
        Algorithm::Ed25519 => (ID_ED25519, None),

        // FIPS 204: id-ml-dsa-*, parameters absent
        // (draft-ietf-lamps-dilithium-certificates).
        Algorithm::MlDsa44 => (ID_ML_DSA_44, None),
        Algorithm::MlDsa65 => (ID_ML_DSA_65, None),
        Algorithm::MlDsa87 => (ID_ML_DSA_87, None),

        other => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "no X.509 AlgorithmIdentifier mapping for {:?} \
                 (classical agility supports RSA-PKCS1, ECDSA P-256/P-384, Ed25519)",
                other
            )));
        }
    };

    Ok(x509_cert::spki::AlgorithmIdentifierOwned { oid, parameters })
}

/// DER-encode the X.509 AlgorithmIdentifier for a signature algorithm.
///
/// Convenience for callers that assemble DER by hand (e.g. the OCSP responder's
/// BasicOCSPResponse.signatureAlgorithm), so the emitted AlgorithmIdentifier
/// flows from the chosen algorithm instead of a hardcoded OID and stays
/// consistent with the signing call (RFC 6960 §4.2.1, RFC 5280 §4.1.1.2).
pub fn algorithm_identifier_der(alg: Algorithm) -> Result<Vec<u8>> {
    use der::Encode;
    algorithm_identifier(alg)?
        .to_der()
        .map_err(|e| Error::Encoding(format!("failed to encode AlgorithmIdentifier: {}", e)))
}

/// Compute the RFC 5280 §4.2.1.2 method-(1) key identifier for a public key.
///
/// The key identifier is the 160-bit SHA-1 digest of the value of the
/// `subjectPublicKey` BIT STRING (the public-key bytes only, *excluding* the
/// BIT STRING tag, length and unused-bits octet). It is used as the value of
/// the Subject Key Identifier extension (§4.2.1.2) on the key's own certificate
/// and, for the issuer's key, as the keyIdentifier of the Authority Key
/// Identifier extension (§4.2.1.1) on certificates that key signs.
///
/// SHA-1 is used here per RFC 5280's recommended method; it is a hash of a
/// *public* identifier (not a security-sensitive digest), so SHA-1's collision
/// weakness is not relevant to this use.
///
/// # Compliance Mapping
/// - RFC 5280 §4.2.1.2 - Subject Key Identifier (method 1: SHA-1 of public key)
/// - RFC 5280 §4.2.1.1 - Authority Key Identifier keyIdentifier derivation
/// - NIAP PP-CA: FDP_CER_EXT.1 - certificate field generation
/// - FIPS 180-4 - SHA-1
///
/// `spki_der` is a DER-encoded SubjectPublicKeyInfo.
pub fn key_identifier(spki_der: &[u8]) -> Result<Vec<u8>> {
    use sha1::{Digest, Sha1};
    use spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::try_from(spki_der).map_err(|e| {
        Error::Encoding(format!("failed to parse SubjectPublicKeyInfo for key id: {}", e))
    })?;

    // RFC 5280 §4.2.1.2 - hash the BIT STRING *contents* (the raw public-key
    // bytes), not the full SPKI and not the BIT STRING with its unused-bits
    // octet. `raw_bytes()` returns exactly those contents.
    let public_key_bits = spki.subject_public_key.raw_bytes();

    let digest = Sha1::digest(public_key_bits);
    Ok(digest.to_vec())
}

/// Convert a crypto provider's raw signature into the bytes X.509 puts in the
/// signature BIT STRING.
///
/// The software and PKCS#11 providers emit ECDSA signatures as fixed-length
/// `r || s` (ring's `ECDSA_*_FIXED_SIGNING`; PKCS#11 `CKM_ECDSA` likewise).
/// X.509 / CMS / OCSP require ECDSA signatures in ASN.1 DER form
/// (RFC 5758 §3.2 - `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`),
/// so ECDSA signatures are re-encoded here. RSA (PKCS#1) and Ed25519 (raw
/// 64-byte) signatures are already in their final form and pass through.
///
/// RFC 5758 §3.2 - ECDSA signature DER encoding
/// NIAP PP-CA: FCS_COP.1 - signature value encoding
pub fn encode_x509_signature(alg: Algorithm, raw_signature: Vec<u8>) -> Result<Vec<u8>> {
    match alg {
        Algorithm::EcdsaP256Sha256 | Algorithm::EcdsaP384Sha384 => {
            ecdsa_fixed_to_der(&raw_signature)
        }
        // RSA (PKCS#1), Ed25519 (raw 64-byte), and ML-DSA (raw FIPS 204)
        // signatures are already in their final X.509 form and pass through.
        _ => Ok(raw_signature),
    }
}

/// Encode a fixed-length `r || s` ECDSA signature as DER `Ecdsa-Sig-Value`.
///
/// RFC 5758 §3.2 - `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// where r and s are unsigned big-endian integers encoded as canonical
/// (minimal, non-negative) ASN.1 INTEGERs.
fn ecdsa_fixed_to_der(fixed: &[u8]) -> Result<Vec<u8>> {
    use der::{Encode, asn1::UintRef};

    if fixed.is_empty() || !fixed.len().is_multiple_of(2) {
        return Err(Error::Encoding(format!(
            "invalid fixed ECDSA signature length {} (expected non-zero even r||s)",
            fixed.len()
        )));
    }

    let (r_bytes, s_bytes) = fixed.split_at(fixed.len() / 2);

    // UintRef produces a canonical non-negative INTEGER: it strips leading
    // zero octets and re-adds a single 0x00 when the high bit is set, exactly
    // the encoding RFC 5758 requires for r and s.
    let r = UintRef::new(r_bytes)
        .map_err(|e| Error::Encoding(format!("invalid ECDSA r component: {}", e)))?;
    let s = UintRef::new(s_bytes)
        .map_err(|e| Error::Encoding(format!("invalid ECDSA s component: {}", e)))?;

    let mut sig_value = der::asn1::SequenceOf::<UintRef, 2>::new();
    sig_value
        .add(r)
        .map_err(|e| Error::Encoding(format!("failed to build Ecdsa-Sig-Value: {}", e)))?;
    sig_value
        .add(s)
        .map_err(|e| Error::Encoding(format!("failed to build Ecdsa-Sig-Value: {}", e)))?;

    sig_value
        .to_der()
        .map_err(|e| Error::Encoding(format!("failed to DER-encode Ecdsa-Sig-Value: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_types_use_pkcs1_sha256() {
        for kt in [KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096] {
            assert_eq!(
                recommended_signature_algorithm(kt).unwrap(),
                Algorithm::RsaPkcs1Sha256
            );
        }
    }

    #[test]
    fn ec_and_ed25519_map_to_expected_algorithms() {
        assert_eq!(
            recommended_signature_algorithm(KeyType::EcP256).unwrap(),
            Algorithm::EcdsaP256Sha256
        );
        assert_eq!(
            recommended_signature_algorithm(KeyType::EcP384).unwrap(),
            Algorithm::EcdsaP384Sha384
        );
        assert_eq!(
            recommended_signature_algorithm(KeyType::Ed25519).unwrap(),
            Algorithm::Ed25519
        );
    }

    #[test]
    fn ml_dsa_key_types_supported() {
        // FIPS 204 ML-DSA signing (via aws-lc-rs) maps to the ML-DSA algorithms
        // and the NIST CSOR id-ml-dsa-* OIDs with absent parameters.
        for (kt, alg, oid) in [
            (KeyType::MlDsa44, Algorithm::MlDsa44, "2.16.840.1.101.3.4.3.17"),
            (KeyType::MlDsa65, Algorithm::MlDsa65, "2.16.840.1.101.3.4.3.18"),
            (KeyType::MlDsa87, Algorithm::MlDsa87, "2.16.840.1.101.3.4.3.19"),
        ] {
            assert_eq!(recommended_signature_algorithm(kt).unwrap(), alg);
            let ai = algorithm_identifier(alg).unwrap();
            assert_eq!(ai.oid.to_string(), oid);
            assert!(ai.parameters.is_none(), "ML-DSA AlgId omits parameters");
        }
    }

    #[test]
    fn unsupported_key_types_error() {
        // P-521: software provider lacks signing support.
        assert!(recommended_signature_algorithm(KeyType::EcP521).is_err());
        // KEM key types cannot sign.
        assert!(recommended_signature_algorithm(KeyType::MlKem768).is_err());
        // Ed448 is not supported by the providers.
        assert!(recommended_signature_algorithm(KeyType::Ed448).is_err());
    }

    #[test]
    fn rsa_algorithm_identifier_has_null_params() {
        // RFC 4055 - explicit NULL parameters for RSA PKCS#1.
        let ai = algorithm_identifier(Algorithm::RsaPkcs1Sha256).unwrap();
        let params = ai.parameters.expect("RSA params must be present (NULL)");
        assert_eq!(params, der::Any::null());
    }

    #[test]
    fn ecdsa_and_ed25519_algorithm_identifiers_omit_params() {
        // RFC 5758 §3.2 / RFC 8410 - parameters absent.
        for alg in [
            Algorithm::EcdsaP256Sha256,
            Algorithm::EcdsaP384Sha384,
            Algorithm::Ed25519,
        ] {
            let ai = algorithm_identifier(alg).unwrap();
            assert!(ai.parameters.is_none(), "{:?} must omit parameters", alg);
        }
    }

    #[test]
    fn ecdsa_algorithm_identifier_oids() {
        use const_oid::ObjectIdentifier;
        assert_eq!(
            algorithm_identifier(Algorithm::EcdsaP256Sha256).unwrap().oid,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2")
        );
        assert_eq!(
            algorithm_identifier(Algorithm::EcdsaP384Sha384).unwrap().oid,
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")
        );
        assert_eq!(
            algorithm_identifier(Algorithm::Ed25519).unwrap().oid,
            ObjectIdentifier::new_unwrap("1.3.101.112")
        );
    }

    #[test]
    fn rsa_and_ed25519_signatures_pass_through_unchanged() {
        let raw = vec![1u8, 2, 3, 4, 5];
        assert_eq!(
            encode_x509_signature(Algorithm::RsaPkcs1Sha256, raw.clone()).unwrap(),
            raw
        );
        let ed = vec![7u8; 64];
        assert_eq!(
            encode_x509_signature(Algorithm::Ed25519, ed.clone()).unwrap(),
            ed
        );
    }

    #[test]
    fn ecdsa_fixed_roundtrips_to_valid_sig_value() {
        use der::{Decode, asn1::UintRef};

        // 64-byte P-256 fixed signature: r = 0x01.., s = 0x02..
        let mut fixed = vec![0u8; 64];
        fixed[31] = 0x11; // r low byte
        fixed[63] = 0x22; // s low byte

        let der_bytes =
            encode_x509_signature(Algorithm::EcdsaP256Sha256, fixed).unwrap();

        // Must parse back as SEQUENCE { INTEGER, INTEGER }.
        let parsed =
            der::asn1::SequenceOf::<UintRef, 2>::from_der(&der_bytes).unwrap();
        let items: Vec<_> = parsed.iter().collect();
        assert_eq!(items.len(), 2, "Ecdsa-Sig-Value must hold two INTEGERs");
        assert_eq!(items[0].as_bytes(), &[0x11]);
        assert_eq!(items[1].as_bytes(), &[0x22]);
    }

    #[test]
    fn key_identifier_is_stable_20_bytes() {
        // A minimal valid Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE {
        // SEQUENCE { OID id-Ed25519 }, BIT STRING (32-byte public key) }.
        // We only need a well-formed SPKI; the key value itself is arbitrary.
        let spki = hex::decode(
            "302a300506032b6570032100\
             0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
        .unwrap();

        let ki = key_identifier(&spki).unwrap();
        // RFC 5280 §4.2.1.2 method 1: 160-bit (20-byte) SHA-1 digest.
        assert_eq!(ki.len(), 20, "key identifier must be 160 bits");

        // Stable: same input -> same output.
        let ki2 = key_identifier(&spki).unwrap();
        assert_eq!(ki, ki2, "key identifier must be deterministic");

        // It hashes the BIT STRING contents (the 32 public-key bytes), so it
        // equals SHA-1 over exactly those bytes.
        use sha1::{Digest, Sha1};
        let pubkey: Vec<u8> = (1u8..=32).collect();
        let expected = Sha1::digest(&pubkey).to_vec();
        assert_eq!(ki, expected, "must be SHA-1 of subjectPublicKey contents");
    }

    #[test]
    fn key_identifier_rejects_garbage() {
        assert!(key_identifier(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn ecdsa_high_bit_component_gets_zero_prefix() {
        // r has its top bit set (0x80..) - canonical positive INTEGER encoding
        // must prepend a 0x00 byte so it is not read as negative.
        let mut fixed = vec![0u8; 64];
        fixed[0] = 0x80; // r high byte, high bit set
        fixed[32] = 0x01; // s high byte

        let der_bytes =
            encode_x509_signature(Algorithm::EcdsaP256Sha256, fixed).unwrap();

        // Walk the DER by hand: SEQUENCE (0x30) { INTEGER (0x02) r, INTEGER s }.
        assert_eq!(der_bytes[0], 0x30, "Ecdsa-Sig-Value must be a SEQUENCE");
        // First INTEGER tag follows the SEQUENCE tag+length (short-form length
        // for a 32-byte r value).
        let r_tag_pos = 2;
        assert_eq!(der_bytes[r_tag_pos], 0x02, "first element must be INTEGER");
        let r_len = der_bytes[r_tag_pos + 1] as usize;
        let r_contents = &der_bytes[r_tag_pos + 2..r_tag_pos + 2 + r_len];
        // 32-byte magnitude with high bit set => 33-byte INTEGER content with a
        // leading 0x00.
        assert_eq!(r_len, 33, "high-bit r must be padded to 33 bytes");
        assert_eq!(r_contents[0], 0x00, "high-bit r must get a 0x00 prefix");
        assert_eq!(r_contents[1], 0x80);
    }
}
