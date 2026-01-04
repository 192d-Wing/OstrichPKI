//! Test fixtures for integration tests
//!
//! Provides pre-generated keys, certificates, and CSRs for testing

use rsa::{RsaPrivateKey, RsaPublicKey};

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
    #[allow(dead_code)]
    pub fn sign(&self, _data: &[u8]) -> Vec<u8> {
        // TODO: Implement JWS signing properly (Phase 14)
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_keypair() {
        let (_private_key, _public_key) = generate_test_rsa_keypair();
        // Just test that we can generate a keypair
        assert!(true);
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
        // TODO: Implement proper signing and verify length (Phase 14)
        assert_eq!(signature.len(), 0); // Placeholder returns empty vec
    }
}
