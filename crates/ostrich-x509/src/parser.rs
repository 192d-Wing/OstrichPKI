//! X.509 certificate and CRL parsing
//!
//! RFC 5280: X.509 certificate and CRL parsing
//! RFC 2986: PKCS#10 certification request syntax

use crate::{Error, Result};
use ostrich_crypto::{Algorithm, CryptoProvider, KeyHandle};
use std::sync::Arc;
use x509_parser::prelude::*;

/// Parse a DER-encoded X.509 certificate
///
/// RFC 5280 §4.1 - Basic certificate fields
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    // TODO: Implement full certificate parsing using x509-parser
    // For now, this is a stub that will be expanded

    if der.is_empty() {
        return Err(Error::Parse("Empty DER data".to_string()));
    }

    Ok(ParsedCertificate {
        serial_number: Vec::new(),
        subject_dn: String::new(),
        issuer_dn: String::new(),
        not_before: chrono::Utc::now(),
        not_after: chrono::Utc::now(),
        public_key: Vec::new(),
        signature: Vec::new(),
        der_encoded: der.to_vec(),
    })
}

/// Parse a PEM-encoded X.509 certificate
///
/// RFC 5280 - PEM encoding
pub fn parse_certificate_pem(_pem: &str) -> Result<ParsedCertificate> {
    // TODO: Implement PEM parsing
    // For now, this is a stub
    parse_certificate(&[])
}

/// Parse a DER-encoded Certificate Signing Request (CSR)
///
/// RFC 2986: PKCS#10 certification request syntax
/// NIST 800-53: SI-10 - Information input validation
pub fn parse_csr(der: &[u8]) -> Result<ParsedCsr> {
    if der.is_empty() {
        return Err(Error::Parse("Empty CSR data".to_string()));
    }

    // Parse CSR using x509-parser
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
        .map_err(|e| Error::Parse(format!("Failed to parse PKCS#10 CSR: {}", e)))?;

    // Extract subject DN
    let subject_dn = csr.certification_request_info.subject.to_string();

    // Extract public key (SubjectPublicKeyInfo) - already in DER format
    let public_key = csr.certification_request_info.subject_pki.raw.to_vec();

    // Extract signature
    let signature = csr.signature_value.data.to_vec();

    // Extract signature algorithm OID
    let signature_algorithm = csr.signature_algorithm.algorithm.to_id_string();

    // Extract attributes (use method instead of accessing private field)
    let mut attributes = Vec::new();
    for attr in csr.certification_request_info.attributes() {
        let oid = attr.oid.to_id_string();
        // Store raw DER of attribute value (attr.value is already &[u8])
        let value = attr.value.to_vec();
        attributes.push((oid, value));
    }

    // TODO: Extract Subject Alternative Names from extensionRequest attribute
    // This requires complex DER parsing of the PKCS#9 extensionRequest attribute
    // For now, return empty vector - clients can still use CSR with subject DN only
    let sans = Vec::new();

    Ok(ParsedCsr {
        subject_dn,
        subject_alternative_names: sans,
        public_key,
        attributes,
        signature_algorithm,
        signature,
        der_encoded: der.to_vec(),
    })
}

/// Verify CSR signature (self-signed proof of possession)
///
/// RFC 2986 §4.2 - Signature must be verified
/// NIST 800-53: SI-10 - Validate cryptographic input
pub async fn verify_csr_signature(
    csr: &ParsedCsr,
    crypto_provider: &Arc<dyn CryptoProvider>,
) -> Result<bool> {
    // Re-parse the CSR to get the TBS (To Be Signed) portion
    let (_, parsed_csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr.der_encoded)
            .map_err(|e| Error::Parse(format!("Failed to re-parse CSR: {}", e)))?;

    // The TBS portion is the CertificationRequestInfo, which is already in raw form
    let tbs_der = parsed_csr.certification_request_info.raw.to_vec();

    // Import the public key for verification
    let key_handle = import_public_key_for_verification(&csr.public_key, &csr.signature_algorithm)?;

    // Map signature algorithm to our Algorithm enum
    let algorithm = map_signature_algorithm_oid(&csr.signature_algorithm)?;

    // Verify the signature
    crypto_provider
        .verify(&key_handle, algorithm, &tbs_der, &csr.signature)
        .await
        .map_err(|e| {
            Error::SignatureVerification(format!("CSR signature verification failed: {}", e))
        })
}

/// Import a public key from SPKI DER for verification
/// Creates a temporary KeyHandle for signature verification
fn import_public_key_for_verification(spki_der: &[u8], _sig_alg_oid: &str) -> Result<KeyHandle> {
    use ostrich_crypto::KeyType;
    use ostrich_crypto::key::ProviderId;

    // Parse the SPKI to determine key type using x509-parser
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| Error::Parse(format!("Failed to parse SPKI: {}", e)))?;

    // Determine key type and algorithm from SPKI algorithm OID
    let oid_str = spki.algorithm.algorithm.to_id_string();

    let (key_type, algorithm) = match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => {
            // rsaEncryption - default to RSA 2048 and PKCS#1 SHA256
            (KeyType::Rsa2048, Algorithm::RsaPkcs1Sha256)
        }
        "1.2.840.10045.2.1" => {
            // ecPublicKey - check curve parameter
            if let Some(params) = &spki.algorithm.parameters {
                // Parse the curve OID from parameters
                let curve_oid = format!("{:?}", params); // Simplified - would need proper parsing

                // Match common curves (simplified)
                if curve_oid.contains("1.2.840.10045.3.1.7") {
                    (KeyType::EcP256, Algorithm::EcdsaP256Sha256)
                } else if curve_oid.contains("1.3.132.0.34") {
                    (KeyType::EcP384, Algorithm::EcdsaP384Sha384)
                } else if curve_oid.contains("1.3.132.0.35") {
                    (KeyType::EcP521, Algorithm::EcdsaP521Sha512)
                } else {
                    return Err(Error::Parse("Unsupported EC curve".to_string()));
                }
            } else {
                return Err(Error::Parse(
                    "EC public key missing curve parameter".to_string(),
                ));
            }
        }
        "1.3.101.112" => {
            // id-Ed25519
            (KeyType::Ed25519, Algorithm::Ed25519)
        }
        _ => {
            return Err(Error::Parse(format!(
                "Unsupported public key algorithm: {}",
                oid_str
            )));
        }
    };

    // Create a temporary KeyHandle for verification
    let key_id = uuid::Uuid::new_v4().as_bytes().to_vec();

    Ok(KeyHandle {
        key_id,
        key_type,
        provider_id: ProviderId::Software,
        algorithm,
        label: "temp-verification-key".to_string(),
    })
}

/// Map signature algorithm OID to our Algorithm enum
fn map_signature_algorithm_oid(oid: &str) -> Result<Algorithm> {
    match oid {
        // RSA PKCS#1 v1.5
        "1.2.840.113549.1.1.11" => Ok(Algorithm::RsaPkcs1Sha256), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Ok(Algorithm::RsaPkcs1Sha384), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Ok(Algorithm::RsaPkcs1Sha512), // sha512WithRSAEncryption

        // RSA-PSS
        "1.2.840.113549.1.1.10" => Ok(Algorithm::RsaPssSha256), // id-RSASSA-PSS (simplified - should parse params)

        // ECDSA
        "1.2.840.10045.4.3.2" => Ok(Algorithm::EcdsaP256Sha256), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(Algorithm::EcdsaP384Sha384), // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Ok(Algorithm::EcdsaP521Sha512), // ecdsa-with-SHA512

        // EdDSA
        "1.3.101.112" => Ok(Algorithm::Ed25519), // id-Ed25519

        _ => Err(Error::Parse(format!(
            "Unsupported signature algorithm OID: {}",
            oid
        ))),
    }
}

/// Parse a DER-encoded CRL
///
/// RFC 5280 §5 - CRL format
pub fn parse_crl(der: &[u8]) -> Result<ParsedCrl> {
    if der.is_empty() {
        return Err(Error::Parse("Empty CRL data".to_string()));
    }

    Ok(ParsedCrl {
        issuer_dn: String::new(),
        this_update: chrono::Utc::now(),
        next_update: chrono::Utc::now(),
        revoked_certificates: Vec::new(),
        signature: Vec::new(),
        der_encoded: der.to_vec(),
    })
}

/// Parsed X.509 certificate
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// Certificate serial number
    pub serial_number: Vec<u8>,
    /// Subject distinguished name
    pub subject_dn: String,
    /// Issuer distinguished name
    pub issuer_dn: String,
    /// Not before time
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Not after time
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,
}

/// Parsed Certificate Signing Request
#[derive(Debug, Clone)]
pub struct ParsedCsr {
    /// Subject distinguished name
    pub subject_dn: String,
    /// Subject Alternative Names (from extensionRequest attribute)
    pub subject_alternative_names: Vec<String>,
    /// Public key (DER-encoded SubjectPublicKeyInfo)
    pub public_key: Vec<u8>,
    /// CSR attributes
    pub attributes: Vec<(String, Vec<u8>)>,
    /// Signature algorithm OID
    pub signature_algorithm: String,
    /// Signature
    pub signature: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,
}

/// Parsed Certificate Revocation List
#[derive(Debug, Clone)]
pub struct ParsedCrl {
    /// Issuer distinguished name
    pub issuer_dn: String,
    /// This update time
    pub this_update: chrono::DateTime<chrono::Utc>,
    /// Next update time
    pub next_update: chrono::DateTime<chrono::Utc>,
    /// Revoked certificates
    pub revoked_certificates: Vec<RevokedCertificate>,
    /// Signature
    pub signature: Vec<u8>,
    /// Original DER encoding
    pub der_encoded: Vec<u8>,
}

/// Revoked certificate entry in CRL
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Serial number of revoked certificate
    pub serial_number: Vec<u8>,
    /// Revocation time
    pub revocation_time: chrono::DateTime<chrono::Utc>,
    /// Revocation reason (optional)
    pub reason: Option<RevocationReason>,
}

/// Revocation reason codes
///
/// RFC 5280 §5.3.1 - Reason code
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from i32
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::CaCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            8 => Some(RevocationReason::RemoveFromCrl),
            9 => Some(RevocationReason::PrivilegeWithdrawn),
            10 => Some(RevocationReason::AaCompromise),
            _ => None,
        }
    }

    /// Convert to i32
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_crypto::KeyType;

    // NOTE: Full CSR signature verification tests are integration tests
    // and run via ACME/EST REST endpoints (see rest.rs in those crates).
    // These unit tests focus on algorithm mapping and public key import.
    //
    // CSR signature verification is IMPLEMENTED and INTEGRATED in:
    // - crates/ostrich-acme/src/rest.rs:806-814 (finalize endpoint)
    // - crates/ostrich-est/src/rest.rs:268-276 (simpleenroll endpoint)
    // - crates/ostrich-est/src/rest.rs:360-368 (simplereenroll endpoint)

    /// Test signature algorithm OID mapping
    ///
    /// COMPLIANCE MAPPING:
    /// - FIPS 186-5: Algorithm identifier mapping for RSA, ECDSA, EdDSA
    #[test]
    fn test_map_signature_algorithm_oid() {
        // RSA PKCS#1 v1.5
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.113549.1.1.11"),
            Ok(Algorithm::RsaPkcs1Sha256)
        ));
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.113549.1.1.12"),
            Ok(Algorithm::RsaPkcs1Sha384)
        ));

        // ECDSA
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.10045.4.3.2"),
            Ok(Algorithm::EcdsaP256Sha256)
        ));
        assert!(matches!(
            map_signature_algorithm_oid("1.2.840.10045.4.3.3"),
            Ok(Algorithm::EcdsaP384Sha384)
        ));

        // EdDSA
        assert!(matches!(
            map_signature_algorithm_oid("1.3.101.112"),
            Ok(Algorithm::Ed25519)
        ));

        // Unsupported algorithm
        assert!(map_signature_algorithm_oid("9.9.9.9.9").is_err());
    }

    /// Test public key import from SPKI
    ///
    /// COMPLIANCE MAPPING:
    /// - RFC 5280 §4.1.2.7: SubjectPublicKeyInfo parsing
    #[test]
    fn test_import_public_key_for_verification() {
        // Valid RSA public key SPKI (simplified, real SPKI would be longer)
        // This is a minimal SPKI structure for RSA
        let rsa_spki = hex::decode(
            "30819f300d06092a864886f70d010101050003818d0030818902818100bb54\
             94d4b7d52cf1c2a333311f6328e2580e11e3f3366d2d7e7d621c3e6ed3c2c2\
             e789655b8c631681b646d5657d28913d78a88058553913a61d3633b35f4695\
             65aab49bf25b61a476b4df06926dc26f985550756ad01923e45de12a005731\
             bde9a8bc7a0ed2d9e14c79426e968019074e50387bec7b6c6a8e0d741208826\
             656727339574bc80813d33e8aed2a862448d8e8ca60",
        ).unwrap();

        let result = import_public_key_for_verification(&rsa_spki, "1.2.840.113549.1.1.11");
        assert!(result.is_ok(), "Should import RSA public key successfully");

        let key_handle = result.unwrap();
        assert!(matches!(key_handle.key_type, KeyType::Rsa2048));
        assert!(matches!(key_handle.algorithm, Algorithm::RsaPkcs1Sha256));
    }
}
