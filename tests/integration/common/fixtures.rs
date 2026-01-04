//! Test fixtures for integration tests
//!
//! Provides pre-generated keys, certificates, and CSRs for testing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing)

use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

/// Generate a test RSA key pair
pub fn generate_test_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let public_key = private_key.to_public_key();
    (private_key, public_key)
}

/// Generate a test certificate signing request (CSR)
#[allow(dead_code)]
pub fn generate_test_csr(_common_name: &str) -> Vec<u8> {
    // TODO: Implement CSR generation (Phase 14)
    // For now, return empty vec as placeholder
    vec![]
}

/// Test certificate chain fixture
pub struct TestCertificateChain {
    pub root_ca_cert_pem: String,
    pub root_ca_key_pem: String,
    pub intermediate_ca_cert_pem: String,
    pub intermediate_ca_key_pem: String,
    pub end_entity_cert_pem: String,
    pub end_entity_key_pem: String,
}

impl TestCertificateChain {
    /// Load test certificate chain from fixtures directory
    pub fn load() -> Result<Self, std::io::Error> {
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("integration")
            .join("fixtures")
            .join("certs");

        Ok(Self {
            root_ca_cert_pem: std::fs::read_to_string(fixtures_dir.join("root-ca.pem"))?,
            root_ca_key_pem: std::fs::read_to_string(fixtures_dir.join("root-ca-key.pem"))?,
            intermediate_ca_cert_pem: std::fs::read_to_string(
                fixtures_dir.join("intermediate-ca.pem"),
            )?,
            intermediate_ca_key_pem: std::fs::read_to_string(
                fixtures_dir.join("intermediate-ca-key.pem"),
            )?,
            end_entity_cert_pem: std::fs::read_to_string(fixtures_dir.join("client.pem"))?,
            end_entity_key_pem: std::fs::read_to_string(fixtures_dir.join("client-key.pem"))?,
        })
    }

    /// Create new test certificate chain (for test setup)
    pub fn generate() -> Self {
        // TODO: Implement test certificate chain generation (Phase 14)
        // For now, return placeholder
        Self {
            root_ca_cert_pem: String::new(),
            root_ca_key_pem: String::new(),
            intermediate_ca_cert_pem: String::new(),
            intermediate_ca_key_pem: String::new(),
            end_entity_cert_pem: String::new(),
            end_entity_key_pem: String::new(),
        }
    }
}

/// JWK (JSON Web Key) test fixture for ACME
pub struct TestJwk {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub jwk_json: serde_json::Value,
}

impl TestJwk {
    /// Generate a new test JWK
    pub fn generate() -> Self {
        let (private_key, public_key) = generate_test_rsa_keypair();

        // Export public key components for JWK
        use rsa::traits::PublicKeyParts;
        let n = public_key.n();
        let e = public_key.e();

        use base64::Engine;
        let jwk_json = serde_json::json!({
            "kty": "RSA",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n.to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e.to_bytes_be()),
        });

        Self {
            private_key,
            public_key,
            jwk_json,
        }
    }

    /// Sign data using this JWK (for JWS)
    /// Returns RS256 signature
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key.sign(data);
        signature.to_vec()
    }

    /// Create a JWS (JSON Web Signature) for ACME requests
    /// RFC 7515 - JSON Web Signature
    pub fn create_jws(
        &self,
        url: &str,
        nonce: &str,
        payload: &serde_json::Value,
        key_id: Option<&str>,
    ) -> serde_json::Value {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Build protected header
        let protected = if let Some(kid) = key_id {
            // Use key ID for existing accounts
            serde_json::json!({
                "alg": "RS256",
                "kid": kid,
                "nonce": nonce,
                "url": url
            })
        } else {
            // Use JWK for new account registration
            serde_json::json!({
                "alg": "RS256",
                "jwk": self.jwk_json,
                "nonce": nonce,
                "url": url
            })
        };

        let protected_b64 = b64.encode(protected.to_string().as_bytes());
        let payload_b64 = if payload.is_null() {
            String::new() // Empty payload for POST-as-GET
        } else {
            b64.encode(payload.to_string().as_bytes())
        };

        // Sign protected.payload
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let signature = self.sign(signing_input.as_bytes());
        let signature_b64 = b64.encode(&signature);

        serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        })
    }

    /// Get the JWK thumbprint (for account key binding)
    /// RFC 7638 - JSON Web Key Thumbprint
    pub fn thumbprint(&self) -> String {
        use base64::Engine;
        use sha2::Digest;

        // Canonical JWK for thumbprint (alphabetically sorted, minimal)
        let canonical = serde_json::json!({
            "e": self.jwk_json["e"],
            "kty": "RSA",
            "n": self.jwk_json["n"]
        });

        let hash = sha2::Sha256::digest(canonical.to_string().as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_generate_rsa_keypair() {
        let (private_key, public_key) = generate_test_rsa_keypair();
        // Verify keypair components are valid (2048 bits = 256 bytes)
        assert!(private_key.size() >= 256);
        assert!(public_key.size() >= 256);
    }

    #[test]
    fn test_generate_test_jwk() {
        let jwk = TestJwk::generate();
        assert_eq!(jwk.jwk_json["kty"], "RSA");
        assert!(jwk.jwk_json["n"].is_string());
        assert!(jwk.jwk_json["e"].is_string());
    }

    #[test]
    fn test_jwk_sign() {
        let jwk = TestJwk::generate();
        let data = b"test data";
        let signature = jwk.sign(data);
        // RS256 signature should be 256 bytes for 2048-bit key
        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn test_jwk_create_jws() {
        let jwk = TestJwk::generate();
        let payload = serde_json::json!({"test": "value"});
        let jws = jwk.create_jws("https://example.com/test", "test-nonce", &payload, None);

        assert!(jws["protected"].is_string());
        assert!(jws["payload"].is_string());
        assert!(jws["signature"].is_string());
    }

    #[test]
    fn test_jwk_thumbprint() {
        let jwk = TestJwk::generate();
        let thumbprint = jwk.thumbprint();
        // SHA-256 base64url encoded should be 43 characters
        assert_eq!(thumbprint.len(), 43);
    }
}
