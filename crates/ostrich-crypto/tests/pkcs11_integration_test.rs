//! PKCS#11 Integration Tests with SoftHSM
//!
//! These tests require SoftHSM to be installed and configured:
//! - macOS: `brew install softhsm`
//! - Linux: `apt-get install softhsm2` or `yum install softhsm`
//!
//! Environment setup:
//! ```bash
//! # Initialize SoftHSM token (if not already done)
//! softhsm2-util --init-token --slot 0 --label "OstrichPKI-Test" --so-pin 12345678 --pin 1234
//!
//! # Set PKCS11_MODULE_PATH to SoftHSM library
//! export PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so  # macOS
//! # or
//! export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so        # Linux
//! ```
//!
//! Run tests with:
//! ```bash
//! cargo test --test pkcs11_integration_test -- --test-threads=1
//! ```
//!
//! NIST 800-53: CA-8 - Penetration testing (cryptographic module validation)

use ostrich_crypto::key::ProviderId;
use ostrich_crypto::pkcs11::Pkcs11Provider;
use ostrich_crypto::{Algorithm, CryptoProvider, KeyType};
use std::env;
use std::path::Path;

/// Get SoftHSM module path from environment or use default
fn get_softhsm_path() -> String {
    env::var("PKCS11_MODULE_PATH").unwrap_or_else(|_| {
        // Try common SoftHSM locations
        let common_paths = vec![
            "/usr/local/lib/softhsm/libsofthsm2.so",    // macOS Homebrew
            "/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS Apple Silicon
            "/usr/lib/softhsm/libsofthsm2.so",          // Linux
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", // Debian/Ubuntu
        ];

        for path in common_paths {
            if std::path::Path::new(path).exists() {
                return path.to_string();
            }
        }

        panic!(
            "SoftHSM library not found. Please install SoftHSM and set PKCS11_MODULE_PATH:\n\
             macOS: brew install softhsm\n\
             Linux: apt-get install softhsm2\n\
             Then: export PKCS11_MODULE_PATH=/path/to/libsofthsm2.so"
        );
    })
}

/// Find slot index by token label using PKCS#11
/// Returns the index into the slots array, not the actual slot ID
fn find_slot_index_by_label(module_path: &str, label: &str) -> Option<u64> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};

    let ctx = Pkcs11::new(module_path).ok()?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .ok()?;

    // Get slots with tokens (same as Pkcs11Provider::new uses)
    let slots = ctx.get_slots_with_token().ok()?;
    for (index, slot) in slots.iter().enumerate() {
        if let Ok(info) = ctx.get_token_info(*slot) {
            let token_label = info.label().trim();
            if token_label == label {
                return Some(index as u64);
            }
        }
    }
    None
}

/// Initialize SoftHSM provider for testing
async fn init_test_provider() -> Pkcs11Provider {
    let module_path = get_softhsm_path();
    let pin = "1234"; // Test PIN

    // Find the slot index by token label (Pkcs11Provider uses index, not slot ID)
    let slot_index = find_slot_index_by_label(&module_path, "OstrichPKI-Test")
        .or_else(|| {
            // Fallback: try to find any initialized token
            find_slot_index_by_label(&module_path, "ostrich-test")
        })
        .unwrap_or(0); // Last resort: try index 0

    Pkcs11Provider::new(Path::new(&module_path), slot_index, pin)
        .await
        .expect("Failed to initialize PKCS#11 provider")
}

#[tokio::test]
async fn test_pkcs11_provider_initialization() {
    // NIST 800-53: IA-7 - Cryptographic module authentication
    let provider = init_test_provider().await;

    // Verify provider is ready (slot_id varies based on SoftHSM initialization)
    let provider_id = provider.provider_id();
    assert!(matches!(provider_id, ProviderId::Pkcs11 { .. }));
}

#[tokio::test]
async fn test_rsa2048_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: RSA key generation
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa2048-keypair", false)
        .await
        .expect("Failed to generate RSA-2048 key pair");

    assert_eq!(key_handle.key_type, KeyType::Rsa2048);
    assert_eq!(key_handle.label, "test-rsa2048-keypair");
    assert!(!key_handle.key_id.is_empty());
}

#[tokio::test]
async fn test_rsa3072_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: RSA key generation (3072-bit for 128-bit security)
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa3072, "test-rsa3072-keypair", false)
        .await
        .expect("Failed to generate RSA-3072 key pair");

    assert_eq!(key_handle.key_type, KeyType::Rsa3072);
    assert_eq!(key_handle.label, "test-rsa3072-keypair");
}

#[tokio::test]
async fn test_rsa4096_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: RSA key generation (4096-bit for high security)
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa4096, "test-rsa4096-keypair", false)
        .await
        .expect("Failed to generate RSA-4096 key pair");

    assert_eq!(key_handle.key_type, KeyType::Rsa4096);
    assert_eq!(key_handle.label, "test-rsa4096-keypair");
}

#[tokio::test]
async fn test_ecp256_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: ECDSA key generation on P-256
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::EcP256, "test-ecp256-keypair", false)
        .await
        .expect("Failed to generate EC P-256 key pair");

    assert_eq!(key_handle.key_type, KeyType::EcP256);
    assert_eq!(key_handle.label, "test-ecp256-keypair");
}

#[tokio::test]
async fn test_ecp384_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: ECDSA key generation on P-384
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::EcP384, "test-ecp384-keypair", false)
        .await
        .expect("Failed to generate EC P-384 key pair");

    assert_eq!(key_handle.key_type, KeyType::EcP384);
    assert_eq!(key_handle.label, "test-ecp384-keypair");
}

#[tokio::test]
async fn test_ecp521_key_generation() {
    // NIST 800-53: SC-12 - Cryptographic key establishment and management
    // FIPS 186-5: ECDSA key generation on P-521
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::EcP521, "test-ecp521-keypair", false)
        .await
        .expect("Failed to generate EC P-521 key pair");

    assert_eq!(key_handle.key_type, KeyType::EcP521);
    assert_eq!(key_handle.label, "test-ecp521-keypair");
}

#[tokio::test]
async fn test_rsa_pss_signing_and_verification() {
    // NIST 800-53: SC-13 - Cryptographic protection (digital signatures)
    // FIPS 186-5: RSA-PSS signature generation and verification
    let provider = init_test_provider().await;

    // Generate RSA key pair
    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa-pss-sign", false)
        .await
        .expect("Failed to generate RSA key pair");

    // Test data to sign
    let message = b"The quick brown fox jumps over the lazy dog";

    // Sign with RSA-PSS SHA-256
    let signature = provider
        .sign(&key_handle, Algorithm::RsaPssSha256, message)
        .await
        .expect("Failed to sign with RSA-PSS");

    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 256); // 2048-bit RSA = 256 bytes

    // Export public key for verification
    let public_key = provider
        .export_public_key(&key_handle)
        .await
        .expect("Failed to export public key");

    assert!(!public_key.is_empty());

    // Verify signature
    let is_valid = provider
        .verify(&key_handle, Algorithm::RsaPssSha256, message, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification should succeed");

    // Verify with tampered message should fail
    let tampered = b"The quick brown fox jumps over the lazy cat";
    let is_valid = provider
        .verify(&key_handle, Algorithm::RsaPssSha256, tampered, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(
        !is_valid,
        "Signature verification should fail for tampered message"
    );
}

#[tokio::test]
async fn test_rsa_pkcs1_signing_and_verification() {
    // NIST 800-53: SC-13 - Cryptographic protection (digital signatures)
    // FIPS 186-5: RSA PKCS#1 v1.5 signature generation
    let provider = init_test_provider().await;

    // Generate RSA key pair
    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa-pkcs1-sign", false)
        .await
        .expect("Failed to generate RSA key pair");

    let message = b"Test message for RSA PKCS#1 v1.5 signature";

    // Sign with RSA PKCS#1 v1.5 SHA-256
    let signature = provider
        .sign(&key_handle, Algorithm::RsaPkcs1Sha256, message)
        .await
        .expect("Failed to sign with RSA PKCS#1");

    assert!(!signature.is_empty());

    // Verify signature
    let is_valid = provider
        .verify(&key_handle, Algorithm::RsaPkcs1Sha256, message, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification should succeed");
}

#[tokio::test]
async fn test_ecdsa_p256_signing_and_verification() {
    // NIST 800-53: SC-13 - Cryptographic protection (digital signatures)
    // FIPS 186-5: ECDSA signature generation on P-256
    let provider = init_test_provider().await;

    // Generate EC P-256 key pair
    let key_handle = provider
        .generate_key_pair(KeyType::EcP256, "test-ecdsa-p256-sign", false)
        .await
        .expect("Failed to generate EC P-256 key pair");

    let message = b"Test message for ECDSA P-256 signature";

    // Sign with ECDSA P-256 SHA-256
    let signature = provider
        .sign(&key_handle, Algorithm::EcdsaP256Sha256, message)
        .await
        .expect("Failed to sign with ECDSA P-256");

    assert!(!signature.is_empty());

    // Export public key
    let public_key = provider
        .export_public_key(&key_handle)
        .await
        .expect("Failed to export public key");

    assert!(!public_key.is_empty());

    // Verify signature
    let is_valid = provider
        .verify(&key_handle, Algorithm::EcdsaP256Sha256, message, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification should succeed");

    // Verify with tampered message should fail
    let tampered = b"Tampered message for ECDSA P-256 signature";
    let is_valid = provider
        .verify(
            &key_handle,
            Algorithm::EcdsaP256Sha256,
            tampered,
            &signature,
        )
        .await
        .expect("Failed to verify signature");

    assert!(
        !is_valid,
        "Signature verification should fail for tampered message"
    );
}

#[tokio::test]
async fn test_ecdsa_p384_signing_and_verification() {
    // NIST 800-53: SC-13 - Cryptographic protection (digital signatures)
    // FIPS 186-5: ECDSA signature generation on P-384
    let provider = init_test_provider().await;

    // Generate EC P-384 key pair
    let key_handle = provider
        .generate_key_pair(KeyType::EcP384, "test-ecdsa-p384-sign", false)
        .await
        .expect("Failed to generate EC P-384 key pair");

    let message = b"Test message for ECDSA P-384 signature";

    // Sign with ECDSA P-384 SHA-384
    let signature = provider
        .sign(&key_handle, Algorithm::EcdsaP384Sha384, message)
        .await
        .expect("Failed to sign with ECDSA P-384");

    assert!(!signature.is_empty());

    // Verify signature
    let is_valid = provider
        .verify(&key_handle, Algorithm::EcdsaP384Sha384, message, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification should succeed");
}

#[tokio::test]
async fn test_ecdsa_p521_signing_and_verification() {
    // NIST 800-53: SC-13 - Cryptographic protection (digital signatures)
    // FIPS 186-5: ECDSA signature generation on P-521
    let provider = init_test_provider().await;

    // Generate EC P-521 key pair
    let key_handle = provider
        .generate_key_pair(KeyType::EcP521, "test-ecdsa-p521-sign", false)
        .await
        .expect("Failed to generate EC P-521 key pair");

    let message = b"Test message for ECDSA P-521 signature";

    // Sign with ECDSA P-521 SHA-512
    let signature = provider
        .sign(&key_handle, Algorithm::EcdsaP521Sha512, message)
        .await
        .expect("Failed to sign with ECDSA P-521");

    assert!(!signature.is_empty());

    // Verify signature
    let is_valid = provider
        .verify(&key_handle, Algorithm::EcdsaP521Sha512, message, &signature)
        .await
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification should succeed");
}

#[tokio::test]
async fn test_public_key_export_rsa() {
    // NIST 800-53: SC-12 - Public key can be exported, private key never exposed
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa-pubkey-export", false)
        .await
        .expect("Failed to generate RSA key pair");

    let public_key = provider
        .export_public_key(&key_handle)
        .await
        .expect("Failed to export public key");

    // Public key should be in DER format (SubjectPublicKeyInfo)
    assert!(!public_key.is_empty());
    assert!(public_key.len() > 200); // RSA-2048 public key is ~294 bytes in DER
}

#[tokio::test]
async fn test_public_key_export_ec() {
    // NIST 800-53: SC-12 - Public key can be exported, private key never exposed
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::EcP256, "test-ec-pubkey-export", false)
        .await
        .expect("Failed to generate EC key pair");

    let public_key = provider
        .export_public_key(&key_handle)
        .await
        .expect("Failed to export public key");

    // Public key should be in DER format (SubjectPublicKeyInfo)
    assert!(!public_key.is_empty());
    assert!(public_key.len() > 50); // EC P-256 public key is ~91 bytes in DER
}

#[tokio::test]
#[ignore] // Requires KEK to be pre-generated in SoftHSM
async fn test_key_wrapping_and_unwrapping() {
    // NIST 800-53: SC-13 - Key wrapping for escrow
    // NIST SP 800-38F: AES Key Wrap
    let provider = init_test_provider().await;

    // Note: This test requires a KEK (Key Encryption Key) to be pre-generated
    // In production, the KRA would manage KEKs
    // For now, this is marked as ignored until KEK generation is implemented

    // Generate a key to wrap
    let _key_to_wrap = provider
        .generate_key_pair(KeyType::EcP256, "test-key-to-wrap", true)
        .await
        .expect("Failed to generate key to wrap");

    // TODO: Generate or use pre-existing KEK
    // let kek = provider.generate_kek("test-kek").await.expect("Failed to generate KEK");

    // Wrap the key
    // let wrapped = provider.wrap_key(&key_to_wrap, &kek).await.expect("Failed to wrap key");
    // assert!(!wrapped.is_empty());

    // Unwrap the key
    // let unwrapped = provider.unwrap_key(&wrapped, &kek, KeyType::EcP256, "test-key-unwrapped")
    //     .await
    //     .expect("Failed to unwrap key");

    // Verify unwrapped key can be used for signing
    // let message = b"Test message";
    // let signature = provider.sign(&unwrapped, Algorithm::EcdsaP256Sha256, message)
    //     .await
    //     .expect("Failed to sign with unwrapped key");
    // assert!(!signature.is_empty());
}

#[tokio::test]
async fn test_multiple_keys_same_provider() {
    // Verify that multiple keys can coexist in the same HSM slot
    let provider = init_test_provider().await;

    let key1 = provider
        .generate_key_pair(KeyType::Rsa2048, "test-multi-key-1", false)
        .await
        .expect("Failed to generate key 1");

    let key2 = provider
        .generate_key_pair(KeyType::EcP256, "test-multi-key-2", false)
        .await
        .expect("Failed to generate key 2");

    let key3 = provider
        .generate_key_pair(KeyType::EcP384, "test-multi-key-3", false)
        .await
        .expect("Failed to generate key 3");

    // All keys should have unique IDs
    assert_ne!(key1.key_id, key2.key_id);
    assert_ne!(key2.key_id, key3.key_id);
    assert_ne!(key1.key_id, key3.key_id);

    // All keys should be usable
    let message = b"Test message";

    let sig1 = provider
        .sign(&key1, Algorithm::RsaPssSha256, message)
        .await
        .expect("Failed to sign with key 1");

    let sig2 = provider
        .sign(&key2, Algorithm::EcdsaP256Sha256, message)
        .await
        .expect("Failed to sign with key 2");

    let sig3 = provider
        .sign(&key3, Algorithm::EcdsaP384Sha384, message)
        .await
        .expect("Failed to sign with key 3");

    assert!(!sig1.is_empty());
    assert!(!sig2.is_empty());
    assert!(!sig3.is_empty());
}

#[tokio::test]
async fn test_deterministic_signatures_rsa_pss() {
    // RSA-PSS uses random salt, so signatures should be different
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa-pss-nondeterministic", false)
        .await
        .expect("Failed to generate RSA key pair");

    let message = b"Same message";

    let sig1 = provider
        .sign(&key_handle, Algorithm::RsaPssSha256, message)
        .await
        .expect("Failed to sign message 1");

    let sig2 = provider
        .sign(&key_handle, Algorithm::RsaPssSha256, message)
        .await
        .expect("Failed to sign message 2");

    // RSA-PSS signatures should be different due to random salt
    assert_ne!(sig1, sig2, "RSA-PSS signatures should be non-deterministic");

    // But both should verify
    assert!(
        provider
            .verify(&key_handle, Algorithm::RsaPssSha256, message, &sig1)
            .await
            .unwrap()
    );
    assert!(
        provider
            .verify(&key_handle, Algorithm::RsaPssSha256, message, &sig2)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_signature_with_wrong_algorithm_fails() {
    // Verify that signing with wrong algorithm for key type fails appropriately
    let provider = init_test_provider().await;

    let rsa_key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-wrong-algo-rsa", false)
        .await
        .expect("Failed to generate RSA key pair");

    let message = b"Test message";

    // Try to sign RSA key with ECDSA algorithm (should fail)
    let result = provider
        .sign(&rsa_key, Algorithm::EcdsaP256Sha256, message)
        .await;

    assert!(
        result.is_err(),
        "Signing RSA key with ECDSA algorithm should fail"
    );
}

#[tokio::test]
async fn test_concurrent_operations() {
    // Test thread safety of PKCS#11 provider with concurrent operations
    use tokio::task::JoinSet;

    let provider = std::sync::Arc::new(init_test_provider().await);

    let mut tasks = JoinSet::new();

    // Spawn 10 concurrent key generation tasks
    for i in 0..10 {
        let provider_clone = provider.clone();
        tasks.spawn(async move {
            let label = format!("test-concurrent-key-{}", i);
            provider_clone
                .generate_key_pair(KeyType::EcP256, &label, false)
                .await
                .expect("Failed to generate key in concurrent task")
        });
    }

    // Wait for all tasks to complete
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.expect("Task panicked"));
    }

    assert_eq!(results.len(), 10);

    // Verify all keys are unique
    for i in 0..results.len() {
        for j in i + 1..results.len() {
            assert_ne!(
                results[i].key_id, results[j].key_id,
                "Concurrent key generation should produce unique keys"
            );
        }
    }
}
