//! JWS (JSON Web Signature) validation for ACME
//!
//! This module implements JWS validation per RFC 7515 for ACME protocol
//! authentication. All ACME requests with non-empty bodies must be signed
//! using the account's key pair.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before any action
//!   - JWS signature verification provides cryptographic authentication.
//!   - All requests (except directory/nonce) must be JWS-signed.
//!   - Signature validates account holds the private key.
//!
//! - **FIA_UID.1**: User identification before any action
//!   - JWK thumbprint (RFC 7638) provides unique account identifier.
//!   - kid URL identifies existing accounts.
//!
//! - **FCS_COP.1**: Cryptographic operation
//!   - RS256, RS384, RS512: RSASSA-PKCS1-v1_5 with SHA-2.
//!   - PS256, PS384, PS512: RSASSA-PSS with SHA-2.
//!   - ES256, ES384, ES512: ECDSA with P-256/P-384/P-521.
//!   - EdDSA: Ed25519 digital signatures.
//!   - SHA-256 for JWK thumbprint computation.
//!
//! - **FCS_CKM.1**: Cryptographic key generation
//!   - Public keys imported from JWK format for verification.
//!   - Support for RSA, EC (P-256, P-384, P-521), and Ed25519 keys.
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **IA-5**: Authenticator Management
//!   - JWK public key serves as authenticator.
//!   - Key binding via cryptographic signature.
//!
//! - **SC-13**: Cryptographic Protection
//!   - FIPS-approved algorithms for signature verification.
//!
//! - **SC-23**: Session Authenticity
//!   - Nonce binding prevents replay attacks.
//!   - URL binding prevents cross-endpoint attacks.
//!
//! ## RFC Compliance
//!
//! - RFC 8555 §6.2: JWS encapsulation for ACME requests
//! - RFC 7515: JSON Web Signature (JWS) specification
//! - RFC 7517: JSON Web Key (JWK) specification
//! - RFC 7518: JSON Web Algorithms (JWA)
//! - RFC 7638: JSON Web Key (JWK) Thumbprint

use crate::{Error, Result};
use ostrich_common::util::encoding::{decode_base64url, encode_base64url};
use ostrich_crypto::{Algorithm, CryptoProvider};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// JWS envelope from ACME client (RFC 7515 §7.2.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsEnvelope {
    /// Base64url-encoded JSON protected header
    pub protected: String,
    /// Base64url-encoded payload
    pub payload: String,
    /// Base64url-encoded signature
    pub signature: String,
}

/// Parsed JWS protected header (RFC 8555 §6.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeader {
    /// JWS algorithm (REQUIRED)
    pub alg: String,
    /// Nonce from server (REQUIRED for ACME)
    pub nonce: String,
    /// Request URL (REQUIRED for ACME)
    pub url: String,
    /// JSON Web Key (REQUIRED for new-account, MUST be absent otherwise)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Key ID / account URL (REQUIRED for non-new-account requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// JSON Web Key (RFC 7517)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: "RSA", "EC", "OKP"
    pub kty: String,

    /// Algorithm (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key use (optional): "sig" for signature
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "use")]
    pub key_use: Option<String>,

    // RSA public key parameters
    /// RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // EC public key parameters
    /// Elliptic curve: "P-256", "P-384", "P-521"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC X coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC Y coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    // Note: For OKP (Ed25519), x is the public key
}

/// JWS algorithm identifier (RFC 7518 §3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512
    RS512,
    /// RSASSA-PSS with SHA-256
    PS256,
    /// RSASSA-PSS with SHA-384
    PS384,
    /// RSASSA-PSS with SHA-512
    PS512,
    /// ECDSA with P-256 and SHA-256
    ES256,
    /// ECDSA with P-384 and SHA-384
    ES384,
    /// ECDSA with P-521 and SHA-512
    ES512,
    /// EdDSA (Ed25519 or Ed448)
    EdDSA,
}

impl JwsAlgorithm {
    /// Parse algorithm from string
    pub fn parse(alg: &str) -> Result<Self> {
        match alg {
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "EdDSA" => Ok(Self::EdDSA),
            _ => Err(Error::Malformed(format!(
                "Unsupported JWS algorithm: {}",
                alg
            ))),
        }
    }

    /// Map JWS algorithm to our internal Algorithm enum
    pub fn to_crypto_algorithm(self) -> Result<Algorithm> {
        match self {
            Self::RS256 => Ok(Algorithm::RsaPkcs1Sha256),
            Self::RS384 => Ok(Algorithm::RsaPkcs1Sha384),
            Self::RS512 => Ok(Algorithm::RsaPkcs1Sha512),
            Self::PS256 => Ok(Algorithm::RsaPssSha256),
            Self::PS384 => Ok(Algorithm::RsaPssSha384),
            Self::PS512 => Ok(Algorithm::RsaPssSha512),
            Self::ES256 => Ok(Algorithm::EcdsaP256Sha256),
            Self::ES384 => Ok(Algorithm::EcdsaP384Sha384),
            Self::ES512 => Err(Error::Malformed("ES512 (P-521) not yet supported".into())),
            Self::EdDSA => Ok(Algorithm::Ed25519),
        }
    }
}

/// Parse JWS envelope from request body (RFC 7515 §7.2)
pub fn parse_jws(body: &[u8]) -> Result<JwsEnvelope> {
    serde_json::from_slice(body)
        .map_err(|e| Error::Malformed(format!("Invalid JWS envelope: {}", e)))
}

/// Decode and parse protected header (RFC 8555 §6.2)
pub fn decode_protected_header(protected: &str) -> Result<ProtectedHeader> {
    let bytes = decode_base64url(protected)
        .map_err(|e| Error::Malformed(format!("Invalid protected header encoding: {}", e)))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Malformed(format!("Invalid protected header JSON: {}", e)))
}

/// Compute JWK thumbprint (RFC 7638)
///
/// The thumbprint is computed by:
/// 1. Constructing a JSON object with only required fields in lexicographic order
/// 2. UTF-8 encoding the JSON
/// 3. SHA-256 hashing
/// 4. Base64url encoding the hash
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UID.1**: Thumbprint provides unique account identifier.
/// - **FCS_COP.1**: SHA-256 hash operation (FIPS 180-4).
pub fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<String> {
    use sha2::{Digest, Sha256};

    // Construct canonical JSON (RFC 7638 §3.3)
    let canonical = match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| Error::Malformed("RSA JWK missing 'n' parameter".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| Error::Malformed("RSA JWK missing 'e' parameter".into()))?;

            // RFC 7638 §3.3: Required fields in lexicographic order
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
        }
        "EC" => {
            let crv = jwk
                .crv
                .as_ref()
                .ok_or_else(|| Error::Malformed("EC JWK missing 'crv' parameter".into()))?;
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| Error::Malformed("EC JWK missing 'x' parameter".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| Error::Malformed("EC JWK missing 'y' parameter".into()))?;

            // RFC 7638 §3.3: Required fields in lexicographic order
            format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
        }
        "OKP" => {
            let default_crv = "Ed25519".to_string();
            let crv = jwk.crv.as_ref().unwrap_or(&default_crv);
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| Error::Malformed("OKP JWK missing 'x' parameter".into()))?;

            // RFC 7638 §3.3: Required fields in lexicographic order
            format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
        }
        _ => {
            return Err(Error::Malformed(format!(
                "Unsupported JWK key type: {}",
                jwk.kty
            )));
        }
    };

    // SHA-256 hash
    let hash = Sha256::digest(canonical.as_bytes());

    // Base64url encode
    Ok(encode_base64url(&hash))
}

/// Verify JWS signature using provided JWK
///
/// This performs the full JWS signature verification:
/// 1. Converts JWK to SPKI DER format
/// 2. Imports public key to crypto provider
/// 3. Constructs signing input (protected + "." + payload)
/// 4. Decodes signature from base64url
/// 5. Verifies signature
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Core authentication mechanism - signature verification.
/// - **FCS_COP.1**: Cryptographic signature verification operation.
/// - **FCS_CKM.1**: Public key import from JWK format.
///
/// # NIST 800-53 Controls
///
/// - **SC-13**: FIPS-approved signature algorithms.
/// - **IA-5**: Authenticator (public key) verification.
pub async fn verify_jws_with_jwk(
    jws: &JwsEnvelope,
    header: &ProtectedHeader,
    jwk: &Jwk,
    _crypto_provider: &Arc<dyn CryptoProvider>,
) -> Result<bool> {
    // Parse JWS algorithm
    let jws_alg = JwsAlgorithm::parse(&header.alg)?;
    let crypto_alg = jws_alg.to_crypto_algorithm()?;

    // Convert JWK to SPKI DER format
    let public_key_der = jwk_to_spki_der(jwk)?;

    // Construct signing input: ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
    // RFC 7515 §5.2
    let signing_input = format!("{}.{}", jws.protected, jws.payload);

    // Decode signature
    let signature_bytes = decode_base64url(&jws.signature)
        .map_err(|e| Error::Malformed(format!("Invalid signature encoding: {}", e)))?;

    // Verify directly against the request-supplied public key.
    //
    // The signer is an EXTERNAL ACME client whose key is NOT resident in our
    // crypto provider, so this is a stateless verification over the SPKI
    // bytes - not a provider keystore lookup. An earlier version imported the
    // key into the software provider and called provider.verify(), which (a)
    // mutated shared keystore state on every request and (b) used the
    // provider's unprefixed PKCS#1 encoding, rejecting standard RS256
    // signatures from real ACME clients - the bug surfaced as
    // "Key not found in software provider" on new-account.
    //
    // RFC 7515 §3.4: JWS ECDSA signatures are the raw fixed-size r||s
    // concatenation, so request `ecdsa_fixed = true`.
    ostrich_crypto::verify_with_spki(
        &public_key_der,
        crypto_alg,
        signing_input.as_bytes(),
        &signature_bytes,
        true,
    )
    .map_err(|e| Error::Unauthorized(format!("Signature verification failed: {}", e)))
}

/// Convert JWK to SPKI DER format
///
/// SPKI (SubjectPublicKeyInfo) is the standard format for public keys in X.509
fn jwk_to_spki_der(jwk: &Jwk) -> Result<Vec<u8>> {
    match jwk.kty.as_str() {
        "RSA" => jwk_rsa_to_spki(jwk),
        "EC" => jwk_ec_to_spki(jwk),
        "OKP" => jwk_okp_to_spki(jwk),
        _ => Err(Error::Malformed(format!(
            "Unsupported JWK key type: {}",
            jwk.kty
        ))),
    }
}

/// Convert RSA JWK to SPKI DER
fn jwk_rsa_to_spki(jwk: &Jwk) -> Result<Vec<u8>> {
    let n = jwk
        .n
        .as_ref()
        .ok_or_else(|| Error::Malformed("RSA JWK missing 'n'".into()))?;
    let e = jwk
        .e
        .as_ref()
        .ok_or_else(|| Error::Malformed("RSA JWK missing 'e'".into()))?;

    // Decode n and e from base64url
    let n_bytes = decode_base64url(n)
        .map_err(|e| Error::Malformed(format!("Invalid RSA modulus encoding: {}", e)))?;
    let e_bytes = decode_base64url(e)
        .map_err(|e| Error::Malformed(format!("Invalid RSA exponent encoding: {}", e)))?;

    // Use rsa crate to build public key
    use rsa::{BigUint, RsaPublicKey};

    let modulus = BigUint::from_bytes_be(&n_bytes);
    let exponent = BigUint::from_bytes_be(&e_bytes);

    let public_key = RsaPublicKey::new(modulus, exponent)
        .map_err(|e| Error::Malformed(format!("Invalid RSA public key: {}", e)))?;

    // Encode to SPKI DER
    use rsa::pkcs8::EncodePublicKey;
    let spki_der = public_key
        .to_public_key_der()
        .map_err(|e| Error::Malformed(format!("Failed to encode RSA SPKI: {}", e)))?;

    Ok(spki_der.as_bytes().to_vec())
}

/// Convert EC JWK to SPKI DER
fn jwk_ec_to_spki(jwk: &Jwk) -> Result<Vec<u8>> {
    use der::{Encode, asn1::BitString};
    use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

    let crv = jwk
        .crv
        .as_ref()
        .ok_or_else(|| Error::Malformed("EC JWK missing 'crv'".into()))?;
    let x = jwk
        .x
        .as_ref()
        .ok_or_else(|| Error::Malformed("EC JWK missing 'x'".into()))?;
    let y = jwk
        .y
        .as_ref()
        .ok_or_else(|| Error::Malformed("EC JWK missing 'y'".into()))?;

    // Decode coordinates
    let x_bytes = decode_base64url(x)
        .map_err(|e| Error::Malformed(format!("Invalid EC X coordinate: {}", e)))?;
    let y_bytes = decode_base64url(y)
        .map_err(|e| Error::Malformed(format!("Invalid EC Y coordinate: {}", e)))?;

    // Determine curve OID
    let curve_oid = match crv.as_str() {
        "P-256" => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"), // secp256r1
        "P-384" => ObjectIdentifier::new_unwrap("1.3.132.0.34"),        // secp384r1
        "P-521" => ObjectIdentifier::new_unwrap("1.3.132.0.35"),        // secp521r1
        _ => return Err(Error::Malformed(format!("Unsupported EC curve: {}", crv))),
    };

    // Construct uncompressed point: 0x04 || x || y
    let mut public_key_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    public_key_bytes.push(0x04); // Uncompressed point indicator
    public_key_bytes.extend_from_slice(&x_bytes);
    public_key_bytes.extend_from_slice(&y_bytes);

    // Construct SPKI
    let algorithm = AlgorithmIdentifier {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"), // ecPublicKey
        parameters: Some(der::asn1::AnyRef::from(&curve_oid)),
    };

    let subject_public_key = BitString::from_bytes(&public_key_bytes)
        .map_err(|e| Error::Malformed(format!("Failed to create BitString: {}", e)))?;

    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key,
    };

    spki.to_der()
        .map_err(|e| Error::Malformed(format!("Failed to encode EC SPKI: {}", e)))
}

/// Convert OKP (Ed25519) JWK to SPKI DER
fn jwk_okp_to_spki(jwk: &Jwk) -> Result<Vec<u8>> {
    use der::{Encode, asn1::BitString};
    use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

    let default_crv = "Ed25519".to_string();
    let crv = jwk.crv.as_ref().unwrap_or(&default_crv);
    let x = jwk
        .x
        .as_ref()
        .ok_or_else(|| Error::Malformed("OKP JWK missing 'x'".into()))?;

    // Only Ed25519 supported for now
    if crv != "Ed25519" {
        return Err(Error::Malformed(format!(
            "Unsupported OKP curve: {} (only Ed25519 supported)",
            crv
        )));
    }

    // Decode public key
    let public_key_bytes = decode_base64url(x)
        .map_err(|e| Error::Malformed(format!("Invalid Ed25519 public key: {}", e)))?;

    // Ed25519 public key must be exactly 32 bytes
    if public_key_bytes.len() != 32 {
        return Err(Error::Malformed(format!(
            "Invalid Ed25519 public key length: {} (expected 32)",
            public_key_bytes.len()
        )));
    }

    // Construct SPKI
    let algorithm = AlgorithmIdentifier {
        oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // id-Ed25519
        parameters: None::<der::asn1::AnyRef>,
    };

    let subject_public_key = BitString::from_bytes(&public_key_bytes)
        .map_err(|e| Error::Malformed(format!("Failed to create BitString: {}", e)))?;

    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key,
    };

    spki.to_der()
        .map_err(|e| Error::Malformed(format!("Failed to encode Ed25519 SPKI: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jws_envelope() {
        let jws_json = r#"{
            "protected": "eyJhbGciOiJSUzI1NiIsInVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYWNtZS9uZXctYWNjb3VudCIsIm5vbmNlIjoidGVzdC1ub25jZSJ9",
            "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZX0",
            "signature": "dGVzdC1zaWduYXR1cmU"
        }"#;

        let jws = parse_jws(jws_json.as_bytes()).unwrap();
        assert!(!jws.protected.is_empty());
        assert!(!jws.payload.is_empty());
        assert!(!jws.signature.is_empty());
    }

    #[test]
    fn test_decode_protected_header() {
        // {"alg":"RS256","url":"https://example.com/acme/new-account","nonce":"test-nonce"}
        let protected = "eyJhbGciOiJSUzI1NiIsInVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYWNtZS9uZXctYWNjb3VudCIsIm5vbmNlIjoidGVzdC1ub25jZSJ9";

        let header = decode_protected_header(protected).unwrap();
        assert_eq!(header.alg, "RS256");
        assert_eq!(header.url, "https://example.com/acme/new-account");
        assert_eq!(header.nonce, "test-nonce");
    }

    #[test]
    fn test_jws_algorithm_parsing() {
        assert_eq!(JwsAlgorithm::parse("RS256").unwrap(), JwsAlgorithm::RS256);
        assert_eq!(JwsAlgorithm::parse("ES256").unwrap(), JwsAlgorithm::ES256);
        assert_eq!(JwsAlgorithm::parse("EdDSA").unwrap(), JwsAlgorithm::EdDSA);

        assert!(JwsAlgorithm::parse("HS256").is_err()); // HMAC not supported
    }

    #[test]
    fn test_compute_rsa_jwk_thumbprint() {
        // Example RSA JWK
        let jwk = Jwk {
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: Some("xjlCRBqkQRr6W5nFGCRdgJgGFxFKBgIUd-Nq Vw0RsFYCrYR6WwqJCJ4UZrD-Z3FjLGQ4Z8k5jHVvZ4z8yZqW8l3wJ5gKk".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('=')); // Base64url should not have padding
    }

    #[test]
    fn test_compute_ec_jwk_thumbprint() {
        // Example EC JWK (P-256)
        let jwk = Jwk {
            kty: "EC".to_string(),
            alg: Some("ES256".to_string()),
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some("WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis".to_string()),
            y: Some("y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE".to_string()),
        };

        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('='));
    }
}
