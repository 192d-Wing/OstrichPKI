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
// Note: These are draft/proposed OIDs and may change
// FIPS 204: ML-DSA (Dilithium)
// TODO: Update with official NIST OIDs when published
pub const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.4.4");
pub const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.6.5");
pub const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.8.7");

// FIPS 203: ML-KEM (Kyber)
// TODO: Update with official NIST OIDs when published
pub const ML_KEM_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.1");
pub const ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.2");
pub const ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.3");

// FIPS 205: SLH-DSA (SPHINCS+)
// TODO: Update with official NIST OIDs when published
pub const SLH_DSA_SHA2_128S: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.13");
pub const SLH_DSA_SHA2_128F: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.16");
pub const SLH_DSA_SHA2_256S: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.7.13");

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
        _ => "Unknown",
    }
}
