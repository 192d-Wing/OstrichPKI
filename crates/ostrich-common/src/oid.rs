// RFC 5280: X.509 PKI Certificate and CRL Profile
// RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, X448
// FIPS 186-5: Digital Signature Standard

use const_oid::ObjectIdentifier;

/// Common Object Identifiers (OIDs) used in PKI operations
///
/// RFC 5280 §4.1.1.2 - Algorithm identifiers
// RSA Encryption and Signature Algorithms
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub const SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
pub const SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// ECDSA Signature Algorithms
pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// EdDSA - RFC 8410
pub const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

// Hash Algorithms
pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
pub const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
pub const SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");
pub const SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

// X.509 Certificate Extensions - RFC 5280 §4.2
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
pub const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
pub const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

// Extended Key Usage - RFC 5280 §4.2.1.12
pub const EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
pub const EKU_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
pub const EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
pub const EKU_EMAIL_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
pub const EKU_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
pub const EKU_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

// Authority Information Access - RFC 5280 §4.2.2.1
pub const AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
pub const AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
pub const AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

// Distinguished Name Attributes - RFC 5280 §4.1.2.4
pub const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
pub const COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
pub const LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
pub const STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
pub const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
pub const ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
pub const SERIAL_NUMBER_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

// Post-Quantum Cryptography OIDs
// Official NIST OID assignments per FIPS 203, 204, 205 (August 2024)
// See: NIST SP 800-208, draft-ietf-lamps-dilithium-certificates,
//      draft-ietf-lamps-kyber-certificates

// FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
// Formerly known as CRYSTALS-Dilithium
// NIST Computer Security Objects Registry: 2.16.840.1.101.3.4.3.*
pub const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
pub const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
pub const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

// FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
// Formerly known as CRYSTALS-Kyber
// NIST Computer Security Objects Registry: 2.16.840.1.101.3.4.4.*
pub const ML_KEM_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");
pub const ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");
pub const ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

// FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
// Formerly known as SPHINCS+
// NIST Computer Security Objects Registry: 2.16.840.1.101.3.4.3.*
// SHA2 variants (FIPS 180-4)
pub const SLH_DSA_SHA2_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20");
pub const SLH_DSA_SHA2_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.21");
pub const SLH_DSA_SHA2_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22");
pub const SLH_DSA_SHA2_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.23");
pub const SLH_DSA_SHA2_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");
pub const SLH_DSA_SHA2_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.25");
// SHAKE variants (FIPS 202)
pub const SLH_DSA_SHAKE_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.26");
pub const SLH_DSA_SHAKE_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.27");
pub const SLH_DSA_SHAKE_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.28");
pub const SLH_DSA_SHAKE_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.29");
pub const SLH_DSA_SHAKE_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.30");
pub const SLH_DSA_SHAKE_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.31");

/// Helper function to get a human-readable name for an OID
pub fn oid_name(oid: &ObjectIdentifier) -> &'static str {
    match *oid {
        RSA_ENCRYPTION => "RSA Encryption",
        SHA256_WITH_RSA_ENCRYPTION => "SHA-256 with RSA",
        SHA384_WITH_RSA_ENCRYPTION => "SHA-384 with RSA",
        SHA512_WITH_RSA_ENCRYPTION => "SHA-512 with RSA",
        EC_PUBLIC_KEY => "EC Public Key",
        ECDSA_WITH_SHA256 => "ECDSA with SHA-256",
        ECDSA_WITH_SHA384 => "ECDSA with SHA-384",
        ECDSA_WITH_SHA512 => "ECDSA with SHA-512",
        ED25519 => "Ed25519",
        ED448 => "Ed448",
        SHA256 => "SHA-256",
        SHA384 => "SHA-384",
        SHA512 => "SHA-512",
        SUBJECT_KEY_IDENTIFIER => "Subject Key Identifier",
        KEY_USAGE => "Key Usage",
        SUBJECT_ALT_NAME => "Subject Alternative Name",
        BASIC_CONSTRAINTS => "Basic Constraints",
        AUTHORITY_KEY_IDENTIFIER => "Authority Key Identifier",
        EXTENDED_KEY_USAGE => "Extended Key Usage",
        ML_DSA_44 => "ML-DSA-44",
        ML_DSA_65 => "ML-DSA-65",
        ML_DSA_87 => "ML-DSA-87",
        ML_KEM_512 => "ML-KEM-512",
        ML_KEM_768 => "ML-KEM-768",
        ML_KEM_1024 => "ML-KEM-1024",
        SLH_DSA_SHA2_128S => "SLH-DSA-SHA2-128s",
        SLH_DSA_SHA2_128F => "SLH-DSA-SHA2-128f",
        SLH_DSA_SHA2_192S => "SLH-DSA-SHA2-192s",
        SLH_DSA_SHA2_192F => "SLH-DSA-SHA2-192f",
        SLH_DSA_SHA2_256S => "SLH-DSA-SHA2-256s",
        SLH_DSA_SHA2_256F => "SLH-DSA-SHA2-256f",
        SLH_DSA_SHAKE_128S => "SLH-DSA-SHAKE-128s",
        SLH_DSA_SHAKE_128F => "SLH-DSA-SHAKE-128f",
        SLH_DSA_SHAKE_192S => "SLH-DSA-SHAKE-192s",
        SLH_DSA_SHAKE_192F => "SLH-DSA-SHAKE-192f",
        SLH_DSA_SHAKE_256S => "SLH-DSA-SHAKE-256s",
        SLH_DSA_SHAKE_256F => "SLH-DSA-SHAKE-256f",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_oids() {
        assert_eq!(oid_name(&RSA_ENCRYPTION), "RSA Encryption");
        assert_eq!(oid_name(&SHA256_WITH_RSA_ENCRYPTION), "SHA-256 with RSA");
        assert_eq!(oid_name(&SHA384_WITH_RSA_ENCRYPTION), "SHA-384 with RSA");
        assert_eq!(oid_name(&SHA512_WITH_RSA_ENCRYPTION), "SHA-512 with RSA");
    }

    #[test]
    fn test_ecdsa_oids() {
        assert_eq!(oid_name(&EC_PUBLIC_KEY), "EC Public Key");
        assert_eq!(oid_name(&ECDSA_WITH_SHA256), "ECDSA with SHA-256");
        assert_eq!(oid_name(&ECDSA_WITH_SHA384), "ECDSA with SHA-384");
        assert_eq!(oid_name(&ECDSA_WITH_SHA512), "ECDSA with SHA-512");
    }

    #[test]
    fn test_eddsa_oids() {
        assert_eq!(oid_name(&ED25519), "Ed25519");
        assert_eq!(oid_name(&ED448), "Ed448");
    }

    #[test]
    fn test_hash_oids() {
        assert_eq!(oid_name(&SHA256), "SHA-256");
        assert_eq!(oid_name(&SHA384), "SHA-384");
        assert_eq!(oid_name(&SHA512), "SHA-512");
    }

    #[test]
    fn test_extension_oids() {
        assert_eq!(oid_name(&SUBJECT_KEY_IDENTIFIER), "Subject Key Identifier");
        assert_eq!(oid_name(&KEY_USAGE), "Key Usage");
        assert_eq!(oid_name(&SUBJECT_ALT_NAME), "Subject Alternative Name");
        assert_eq!(oid_name(&BASIC_CONSTRAINTS), "Basic Constraints");
        assert_eq!(
            oid_name(&AUTHORITY_KEY_IDENTIFIER),
            "Authority Key Identifier"
        );
        assert_eq!(oid_name(&EXTENDED_KEY_USAGE), "Extended Key Usage");
    }

    #[test]
    fn test_pqc_oids() {
        // ML-DSA (FIPS 204)
        assert_eq!(oid_name(&ML_DSA_44), "ML-DSA-44");
        assert_eq!(oid_name(&ML_DSA_65), "ML-DSA-65");
        assert_eq!(oid_name(&ML_DSA_87), "ML-DSA-87");

        // ML-KEM (FIPS 203)
        assert_eq!(oid_name(&ML_KEM_512), "ML-KEM-512");
        assert_eq!(oid_name(&ML_KEM_768), "ML-KEM-768");
        assert_eq!(oid_name(&ML_KEM_1024), "ML-KEM-1024");

        // SLH-DSA SHA2 variants (FIPS 205)
        assert_eq!(oid_name(&SLH_DSA_SHA2_128S), "SLH-DSA-SHA2-128s");
        assert_eq!(oid_name(&SLH_DSA_SHA2_128F), "SLH-DSA-SHA2-128f");
        assert_eq!(oid_name(&SLH_DSA_SHA2_192S), "SLH-DSA-SHA2-192s");
        assert_eq!(oid_name(&SLH_DSA_SHA2_192F), "SLH-DSA-SHA2-192f");
        assert_eq!(oid_name(&SLH_DSA_SHA2_256S), "SLH-DSA-SHA2-256s");
        assert_eq!(oid_name(&SLH_DSA_SHA2_256F), "SLH-DSA-SHA2-256f");

        // SLH-DSA SHAKE variants (FIPS 205)
        assert_eq!(oid_name(&SLH_DSA_SHAKE_128S), "SLH-DSA-SHAKE-128s");
        assert_eq!(oid_name(&SLH_DSA_SHAKE_128F), "SLH-DSA-SHAKE-128f");
        assert_eq!(oid_name(&SLH_DSA_SHAKE_192S), "SLH-DSA-SHAKE-192s");
        assert_eq!(oid_name(&SLH_DSA_SHAKE_192F), "SLH-DSA-SHAKE-192f");
        assert_eq!(oid_name(&SLH_DSA_SHAKE_256S), "SLH-DSA-SHAKE-256s");
        assert_eq!(oid_name(&SLH_DSA_SHAKE_256F), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn test_pqc_oid_values() {
        // Verify official NIST OID assignments
        // FIPS 204: ML-DSA
        assert_eq!(ML_DSA_44.to_string(), "2.16.840.1.101.3.4.3.17");
        assert_eq!(ML_DSA_65.to_string(), "2.16.840.1.101.3.4.3.18");
        assert_eq!(ML_DSA_87.to_string(), "2.16.840.1.101.3.4.3.19");

        // FIPS 203: ML-KEM
        assert_eq!(ML_KEM_512.to_string(), "2.16.840.1.101.3.4.4.1");
        assert_eq!(ML_KEM_768.to_string(), "2.16.840.1.101.3.4.4.2");
        assert_eq!(ML_KEM_1024.to_string(), "2.16.840.1.101.3.4.4.3");

        // FIPS 205: SLH-DSA SHA2 variants
        assert_eq!(SLH_DSA_SHA2_128S.to_string(), "2.16.840.1.101.3.4.3.20");
        assert_eq!(SLH_DSA_SHA2_128F.to_string(), "2.16.840.1.101.3.4.3.21");
        assert_eq!(SLH_DSA_SHA2_192S.to_string(), "2.16.840.1.101.3.4.3.22");
        assert_eq!(SLH_DSA_SHA2_192F.to_string(), "2.16.840.1.101.3.4.3.23");
        assert_eq!(SLH_DSA_SHA2_256S.to_string(), "2.16.840.1.101.3.4.3.24");
        assert_eq!(SLH_DSA_SHA2_256F.to_string(), "2.16.840.1.101.3.4.3.25");

        // FIPS 205: SLH-DSA SHAKE variants
        assert_eq!(SLH_DSA_SHAKE_128S.to_string(), "2.16.840.1.101.3.4.3.26");
        assert_eq!(SLH_DSA_SHAKE_128F.to_string(), "2.16.840.1.101.3.4.3.27");
        assert_eq!(SLH_DSA_SHAKE_192S.to_string(), "2.16.840.1.101.3.4.3.28");
        assert_eq!(SLH_DSA_SHAKE_192F.to_string(), "2.16.840.1.101.3.4.3.29");
        assert_eq!(SLH_DSA_SHAKE_256S.to_string(), "2.16.840.1.101.3.4.3.30");
        assert_eq!(SLH_DSA_SHAKE_256F.to_string(), "2.16.840.1.101.3.4.3.31");
    }

    #[test]
    fn test_unknown_oid() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        assert_eq!(oid_name(&unknown), "Unknown");
    }

    #[test]
    fn test_eku_oids() {
        // Extended Key Usage OIDs should exist
        assert_eq!(EKU_SERVER_AUTH.to_string(), "1.3.6.1.5.5.7.3.1");
        assert_eq!(EKU_CLIENT_AUTH.to_string(), "1.3.6.1.5.5.7.3.2");
        assert_eq!(EKU_CODE_SIGNING.to_string(), "1.3.6.1.5.5.7.3.3");
        assert_eq!(EKU_EMAIL_PROTECTION.to_string(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(EKU_TIME_STAMPING.to_string(), "1.3.6.1.5.5.7.3.8");
        assert_eq!(EKU_OCSP_SIGNING.to_string(), "1.3.6.1.5.5.7.3.9");
    }

    #[test]
    fn test_dn_attribute_oids() {
        assert_eq!(COMMON_NAME.to_string(), "2.5.4.3");
        assert_eq!(COUNTRY_NAME.to_string(), "2.5.4.6");
        assert_eq!(ORGANIZATION_NAME.to_string(), "2.5.4.10");
    }

    #[test]
    fn test_aia_oids() {
        // Authority Information Access
        assert_eq!(AUTHORITY_INFO_ACCESS.to_string(), "1.3.6.1.5.5.7.1.1");
        assert_eq!(AD_OCSP.to_string(), "1.3.6.1.5.5.7.48.1");
        assert_eq!(AD_CA_ISSUERS.to_string(), "1.3.6.1.5.5.7.48.2");
    }
}
