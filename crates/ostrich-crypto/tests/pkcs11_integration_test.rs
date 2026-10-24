//! PKCS#11 Integration Tests with SoftHSM
//!
//! These tests require SoftHSM to be installed and configured:
//! - macOS: `brew install softhsm`
//! - Linux: `apt-get install softhsm2` or `yum install softhsm`
//!
//! Environment setup:
//! ```bash
//! # Initialize SoftHSM token (if not already done)
//! softhsm2-util --init-token --free --label "OstrichPKI-Test" --so-pin 12345678 --pin 1234
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
//! NIST 800-53: SA-11 (Developer Testing), IA-7 (Cryptographic Module Authentication),
//! SC-12/SC-13 (key generation and signing through the PKCS#11 provider)

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
    let result = provider
        .verify(&key_handle, Algorithm::RsaPssSha256, tampered, &signature)
        .await;

    assert!(
        matches!(result, Ok(false)),
        "Signature verification should fail for tampered message"
    );
}

/// Verify `signature` over `message` with a SOFTWARE RSA-PSS verifier
/// (AWS-LC FIPS via aws-lc-rs) using the SPKI exported from the HSM. aws-lc-rs
/// takes the PKCS#1 RSAPublicKey, which is the SPKI subjectPublicKey contents.
fn software_verify_rsa_pss(
    spki_der: &[u8],
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

    let spki = spki::SubjectPublicKeyInfoOwned::try_from(spki_der).expect("exported SPKI parses");
    assert_eq!(
        spki.algorithm.oid.to_string(),
        "1.2.840.113549.1.1.1",
        "exported SPKI must be rsaEncryption"
    );
    let rsa_public_key = spki
        .subject_public_key
        .as_bytes()
        .expect("SPKI BIT STRING is octet-aligned");

    let verifier: &'static dyn VerificationAlgorithm = match algorithm {
        Algorithm::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
        Algorithm::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
        Algorithm::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
        other => panic!("not an RSA-PSS algorithm: {other:?}"),
    };
    UnparsedPublicKey::new(verifier, rsa_public_key)
        .verify(message, signature)
        .is_ok()
}

#[tokio::test]
async fn test_rsa_pss_hsm_sign_software_verify() {
    // Interop: an HSM-produced RSA-PSS signature must be a standard RFC 8017
    // RSASSA-PSS signature over the MESSAGE (not over a double hash), so an
    // independent software verifier accepts it via the exported SPKI.
    // NIST 800-53: SC-13; NIAP PP-CA: FCS_COP.1
    // FIPS 186-5 §5.4 (RSASSA-PSS); RFC 8017 §8.1; PKCS#11 v3.0 §2.1.14
    let provider = init_test_provider().await;

    let key_handle = provider
        .generate_key_pair(KeyType::Rsa2048, "test-rsa-pss-interop", false)
        .await
        .expect("Failed to generate RSA key pair");
    let spki = provider
        .export_public_key(&key_handle)
        .await
        .expect("Failed to export public key");

    let message = b"HSM RSA-PSS interop message";
    let tampered = b"HSM RSA-PSS interop messagf";

    for algorithm in [
        Algorithm::RsaPssSha256,
        Algorithm::RsaPssSha384,
        Algorithm::RsaPssSha512,
    ] {
        let signature = provider
            .sign(&key_handle, algorithm, message)
            .await
            .unwrap_or_else(|e| panic!("HSM {algorithm:?} signing failed: {e}"));
        assert_eq!(signature.len(), 256, "{algorithm:?}: RSA-2048 signature");

        // Software verifier accepts the HSM signature.
        assert!(
            software_verify_rsa_pss(&spki, algorithm, message, &signature),
            "{algorithm:?}: software verifier must accept HSM signature"
        );
        // HSM verify path agrees.
        assert!(
            provider
                .verify(&key_handle, algorithm, message, &signature)
                .await
                .expect("HSM verify"),
            "{algorithm:?}: HSM verify must accept its own signature"
        );

        // Wrong message is rejected by both verifiers.
        assert!(
            !software_verify_rsa_pss(&spki, algorithm, tampered, &signature),
            "{algorithm:?}: software verifier must reject wrong message"
        );
        assert!(
            matches!(
                provider
                    .verify(&key_handle, algorithm, tampered, &signature)
                    .await,
                Ok(false)
            ),
            "{algorithm:?}: HSM verify must reject wrong message"
        );

        // Tampered signature is rejected by both verifiers.
        let mut bad_sig = signature.clone();
        if let Some(last) = bad_sig.last_mut() {
            *last ^= 0x01;
        }
        assert!(
            !software_verify_rsa_pss(&spki, algorithm, message, &bad_sig),
            "{algorithm:?}: software verifier must reject tampered signature"
        );
        assert!(
            matches!(
                provider
                    .verify(&key_handle, algorithm, message, &bad_sig)
                    .await,
                Ok(false)
            ),
            "{algorithm:?}: HSM verify must reject tampered signature"
        );

        // A signature under one hash must not verify under another.
        let other = if algorithm == Algorithm::RsaPssSha256 {
            Algorithm::RsaPssSha384
        } else {
            Algorithm::RsaPssSha256
        };
        assert!(
            !software_verify_rsa_pss(&spki, other, message, &signature),
            "{algorithm:?} signature must not verify as {other:?}"
        );
    }
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
    let result = provider
        .verify(
            &key_handle,
            Algorithm::EcdsaP256Sha256,
            tampered,
            &signature,
        )
        .await;

    assert!(
        matches!(result, Ok(false)),
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
async fn test_verify_token_fault_is_error_not_rejection() {
    // SEC-002 / QA-001: a token fault must surface as Err - fail closed and
    // observable - never as Ok(false), which is reserved for
    // CKR_SIGNATURE_INVALID / CKR_SIGNATURE_LEN_RANGE. The fault is induced
    // with an RSA public-key object whose CKA_VERIFY is false, so
    // C_VerifyInit fails with CKR_KEY_FUNCTION_NOT_PERMITTED.
    // NIST 800-53: SI-11, AU-2; PKCS#11 v3.0 §5.13
    use ostrich_crypto::software::SoftwareProvider;

    let sw = SoftwareProvider::new();
    let sw_key = sw
        .generate_key_pair(KeyType::Rsa2048, "test-verify-fault-sw", false)
        .await
        .expect("software keygen");
    let spki = sw.export_public_key(&sw_key).await.expect("software SPKI");
    let message = b"verify fault classification";
    let sig = sw
        .sign(&sw_key, Algorithm::RsaPssSha256, message)
        .await
        .expect("software sign");

    let no_verify_id = sw.generate_random_bytes(16).await.expect("random CKA_ID");
    let no_verify_label = "test-verify-fault-no-verify";
    import_rsa_public_key_into_token_with(&spki, &no_verify_id, no_verify_label, false);
    let ok_id = sw.generate_random_bytes(16).await.expect("random CKA_ID");
    let ok_label = "test-verify-fault-control";
    import_rsa_public_key_into_token(&spki, &ok_id, ok_label);

    let provider = init_test_provider().await;
    let ProviderId::Pkcs11 { slot_id } = provider.provider_id() else {
        panic!("expected PKCS#11 provider id");
    };
    let handle = |id: Vec<u8>, label: &str| {
        ostrich_crypto::KeyHandle::new(
            ProviderId::Pkcs11 { slot_id },
            id,
            KeyType::Rsa2048,
            Algorithm::RsaPssSha256,
            label.to_string(),
        )
    };
    let no_verify = handle(no_verify_id, no_verify_label);
    let control = handle(ok_id, ok_label);

    for (msg, what) in [
        (&message[..], "valid"),
        (&b"other message"[..], "wrong-message"),
    ] {
        let result = provider
            .verify(&no_verify, Algorithm::RsaPssSha256, msg, &sig)
            .await;
        assert!(
            matches!(result, Err(ostrich_crypto::Error::Pkcs11(_))),
            "{what}: token fault must be Err(Pkcs11), got {result:?}"
        );
    }

    // Control: the same key material with CKA_VERIFY = true gives exactly
    // Ok(true) for the valid signature and Ok(false) for a wrong message.
    let result = provider
        .verify(&control, Algorithm::RsaPssSha256, message, &sig)
        .await;
    assert!(matches!(result, Ok(true)), "control valid: got {result:?}");
    let result = provider
        .verify(&control, Algorithm::RsaPssSha256, b"other message", &sig)
        .await;
    assert!(
        matches!(result, Ok(false)),
        "control wrong message: got {result:?}"
    );

    provider
        .destroy_key(&no_verify)
        .await
        .expect("destroy imported public key");
    provider
        .destroy_key(&control)
        .await
        .expect("destroy imported public key");
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

// ============================================================================
// Key lifecycle: inventory (list_keys) and destruction (FCS_CKM.4)
// ============================================================================

/// Construct a provider with a SINGLE `C_Initialize` (slot index 0 — the test
/// token is the only one). `init_test_provider` additionally calls
/// `find_slot_index_by_label`, which initializes a second Cryptoki context;
/// PKCS#11 permits only one `C_Initialize` per process, so this lifecycle test
/// runs standalone with one provider.
async fn single_init_provider() -> Pkcs11Provider {
    let module_path = get_softhsm_path();
    Pkcs11Provider::new(Path::new(&module_path), 0, "1234")
        .await
        .expect("Failed to initialize PKCS#11 provider")
}

#[tokio::test]
async fn test_key_lifecycle_list_and_destroy() {
    // NIAP PP-CA: FCS_CKM.4 (destruction); NIST 800-53: SC-12 (lifecycle/inventory)
    let provider = single_init_provider().await;

    // Clean any keys left by a previous (possibly failed) run of this test so
    // the label-based assertions below are unambiguous. Dogfoods list+destroy.
    for k in provider.list_keys().await.expect("list_keys (cleanup)") {
        if k.label.starts_with("test-lifecycle-") {
            let _ = provider.destroy_key(&k).await;
        }
    }

    let rsa = provider
        .generate_key_pair(KeyType::Rsa2048, "test-lifecycle-rsa2048", false)
        .await
        .expect("generate rsa");
    let ec = provider
        .generate_key_pair(KeyType::EcP384, "test-lifecycle-ecp384", false)
        .await
        .expect("generate ec");

    // --- list_keys surfaces both with the correct mapped types ---
    let keys = provider.list_keys().await.expect("list_keys");
    let rsa_found = keys
        .iter()
        .find(|k| k.label == "test-lifecycle-rsa2048")
        .expect("RSA key present in listing");
    assert_eq!(rsa_found.key_type, KeyType::Rsa2048);
    assert_eq!(rsa_found.key_id, rsa.key_id);
    let ec_found = keys
        .iter()
        .find(|k| k.label == "test-lifecycle-ecp384")
        .expect("EC key present in listing");
    assert_eq!(ec_found.key_type, KeyType::EcP384);

    // --- destroy_key removes the key material (FCS_CKM.4): the key disappears
    //     from the inventory, proving the private object is gone ---
    provider.destroy_key(&rsa).await.expect("destroy rsa");
    let after_one = provider.list_keys().await.expect("list_keys after destroy");
    assert!(
        !after_one
            .iter()
            .any(|k| k.label == "test-lifecycle-rsa2048"),
        "destroyed RSA key must not appear in the listing (FCS_CKM.4)"
    );
    assert!(
        after_one.iter().any(|k| k.label == "test-lifecycle-ecp384"),
        "the still-live EC key must remain in the listing"
    );

    // --- destroy is idempotent: destroying the same key again is not an error ---
    provider
        .destroy_key(&rsa)
        .await
        .expect("second destroy is idempotent");

    // --- destroy the EC key too; the inventory is then clear of both ---
    provider.destroy_key(&ec).await.expect("destroy ec");
    let after_both = provider.list_keys().await.expect("list_keys final");
    assert!(
        !after_both
            .iter()
            .any(|k| k.label == "test-lifecycle-rsa2048" || k.label == "test-lifecycle-ecp384"),
        "both destroyed keys must be gone from the listing"
    );
}

// ---------------------------------------------------------------------------
// QA gap coverage for the RSA-PSS host-side digest fix (PKCS#11 v3.0 §2.1.14).
// NIST 800-53: SA-11, SC-13; NIAP PP-CA: FCS_COP.1; FIPS 186-5 §5.4; RFC 8017.
// ---------------------------------------------------------------------------

const ALL_RSA_PSS: [Algorithm; 3] = [
    Algorithm::RsaPssSha256,
    Algorithm::RsaPssSha384,
    Algorithm::RsaPssSha512,
];

const ALL_RSA_PKCS1: [Algorithm; 3] = [
    Algorithm::RsaPkcs1Sha256,
    Algorithm::RsaPkcs1Sha384,
    Algorithm::RsaPkcs1Sha512,
];

/// Sign `message` on the HSM with every algorithm in `algorithms` and check the
/// signature length, software (AWS-LC) acceptance, HSM acceptance, and that a
/// one-byte message change is rejected by both verifiers.
async fn hsm_sign_and_cross_verify(
    provider: &Pkcs11Provider,
    key_handle: &ostrich_crypto::KeyHandle,
    algorithms: &[Algorithm],
    modulus_bytes: usize,
    message: &[u8],
) {
    let spki = provider
        .export_public_key(key_handle)
        .await
        .expect("export public key");
    let mut wrong = message.to_vec();
    match wrong.last_mut() {
        Some(b) => *b ^= 0x01,
        None => wrong.push(0x00),
    }

    for &algorithm in algorithms {
        let signature = provider
            .sign(key_handle, algorithm, message)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{:?} {algorithm:?} sign ({} byte msg) failed: {e}",
                    key_handle.key_type,
                    message.len()
                )
            });
        assert_eq!(
            signature.len(),
            modulus_bytes,
            "{:?} {algorithm:?}: signature length must equal modulus length",
            key_handle.key_type
        );

        // Independent software verification via the public SPKI verifier.
        assert!(
            ostrich_crypto::verify_with_spki(&spki, algorithm, message, &signature, false)
                .expect("software verify runs"),
            "{:?} {algorithm:?}: software verifier must accept HSM signature",
            key_handle.key_type
        );
        assert!(
            provider
                .verify(key_handle, algorithm, message, &signature)
                .await
                .expect("HSM verify runs"),
            "{:?} {algorithm:?}: HSM verify must accept HSM signature",
            key_handle.key_type
        );

        assert!(
            !ostrich_crypto::verify_with_spki(&spki, algorithm, &wrong, &signature, false)
                .expect("software verify runs"),
            "{:?} {algorithm:?}: software verifier must reject wrong message",
            key_handle.key_type
        );
        assert!(
            matches!(
                provider
                    .verify(key_handle, algorithm, &wrong, &signature)
                    .await,
                Ok(false)
            ),
            "{:?} {algorithm:?}: HSM verify must reject wrong message",
            key_handle.key_type
        );
    }
}

#[tokio::test]
async fn test_rsa_pss_all_hashes_rsa3072_rsa4096() {
    // FIPS 186-5 §5.4: RSASSA-PSS with SHA-256/384/512 on 3072/4096-bit moduli
    // through the public CryptoProvider::sign/verify API (not only the helper),
    // cross-checked by an independent software verifier.
    let provider = init_test_provider().await;
    for (key_type, label, modulus_bytes) in [
        (KeyType::Rsa3072, "test-qa-pss-rsa3072", 384),
        (KeyType::Rsa4096, "test-qa-pss-rsa4096", 512),
    ] {
        let key = provider
            .generate_key_pair(key_type, label, false)
            .await
            .unwrap_or_else(|e| panic!("generate {key_type:?}: {e}"));
        hsm_sign_and_cross_verify(
            &provider,
            &key,
            &ALL_RSA_PSS,
            modulus_bytes,
            b"QA RSA-PSS large modulus",
        )
        .await;
        provider.destroy_key(&key).await.expect("destroy key");
    }
}

#[tokio::test]
async fn test_rsa_pss_empty_message() {
    // RFC 8017 §9.1.1: M may be empty; mHash = Hash("") is still hashLen octets.
    let provider = init_test_provider().await;
    let key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-qa-pss-empty", false)
        .await
        .expect("generate RSA-2048");
    hsm_sign_and_cross_verify(&provider, &key, &ALL_RSA_PSS, 256, b"").await;
    hsm_sign_and_cross_verify(&provider, &key, &ALL_RSA_PKCS1, 256, b"").await;
    provider.destroy_key(&key).await.expect("destroy key");
}

#[tokio::test]
async fn test_rsa_pss_large_message() {
    // > 1 MiB message: the host digests it, so only hashLen octets reach the
    // token for PSS. PKCS#1 v1.5 (combined mechanism) is exercised too.
    let provider = init_test_provider().await;
    let key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-qa-pss-large", false)
        .await
        .expect("generate RSA-2048");
    let message: Vec<u8> = (0..(1024 * 1024 + 4099)).map(|i| (i % 251) as u8).collect();
    assert!(message.len() > 1024 * 1024);
    hsm_sign_and_cross_verify(&provider, &key, &ALL_RSA_PSS, 256, &message).await;
    hsm_sign_and_cross_verify(&provider, &key, &ALL_RSA_PKCS1, 256, &message).await;
    provider.destroy_key(&key).await.expect("destroy key");
}

#[tokio::test]
async fn test_rsa_pkcs1_all_hashes_hsm_sign_software_verify() {
    // Regression guard: PKCS#1 v1.5 (combined CKM_SHAx_RSA_PKCS) is untouched by
    // the fix and still produces standard RFC 8017 §8.2 signatures.
    let provider = init_test_provider().await;
    let key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-qa-pkcs1-interop", false)
        .await
        .expect("generate RSA-2048");
    hsm_sign_and_cross_verify(
        &provider,
        &key,
        &ALL_RSA_PKCS1,
        256,
        b"QA PKCS#1 v1.5 interop",
    )
    .await;
    provider.destroy_key(&key).await.expect("destroy key");
}

/// Create a token-resident RSA public-key object holding `spki_der`'s key under
/// CKA_ID `key_id`, using a separate PKCS#11 context. Must run before the
/// provider under test is initialised (one live context per process).
fn import_rsa_public_key_into_token(spki_der: &[u8], key_id: &[u8], label: &str) {
    import_rsa_public_key_into_token_with(spki_der, key_id, label, true);
}

/// As [`import_rsa_public_key_into_token`], with an explicit `CKA_VERIFY`.
/// `verify = false` makes `C_VerifyInit` fail with a token error
/// (`CKR_KEY_FUNCTION_NOT_PERMITTED`) rather than a signature rejection.
fn import_rsa_public_key_into_token_with(
    spki_der: &[u8],
    key_id: &[u8],
    label: &str,
    verify: bool,
) {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::object::{Attribute, KeyType as CkKeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let public = rsa::RsaPublicKey::from_public_key_der(spki_der).expect("software SPKI is RSA");

    let ctx = Pkcs11::new(get_softhsm_path()).expect("load PKCS#11 module");
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("C_Initialize");
    let slot = ctx
        .get_slots_with_token()
        .expect("slots")
        .into_iter()
        .find(|s| {
            ctx.get_token_info(*s)
                .map(|i| i.label().trim() == "OstrichPKI-Test")
                .unwrap_or(false)
        })
        .expect("OstrichPKI-Test token present");
    let session = ctx.open_rw_session(slot).expect("open RW session");
    session
        .login(UserType::User, Some(&AuthPin::new("1234".into())))
        .expect("C_Login");
    session
        .create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(CkKeyType::RSA),
            Attribute::Token(true),
            Attribute::Verify(verify),
            Attribute::Modulus(public.n().to_bytes_be()),
            Attribute::PublicExponent(public.e().to_bytes_be()),
            Attribute::Id(key_id.to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .expect("C_CreateObject RSA public key");
    let _ = session.logout();
}

#[tokio::test]
async fn test_rsa_software_sign_hsm_verify() {
    // Reverse interop: signatures made by the SOFTWARE provider (AWS-LC) verify
    // through the HSM verify path. Proves the host-side digest + raw
    // CKM_RSA_PKCS_PSS verify accepts standard RSASSA-PSS from another
    // implementation, for every hash, and that PKCS#1 v1.5 still interoperates.
    use ostrich_crypto::software::SoftwareProvider;

    let sw = SoftwareProvider::new();
    let mut cases = Vec::new();
    for (key_type, modulus_bytes) in [(KeyType::Rsa2048, 256usize), (KeyType::Rsa3072, 384)] {
        let sw_key = sw
            .generate_key_pair(key_type, "qa-sw-rsa", false)
            .await
            .expect("software keygen");
        let spki = sw.export_public_key(&sw_key).await.expect("software SPKI");
        let key_id = sw.generate_random_bytes(16).await.expect("random CKA_ID");
        let label = format!("test-qa-sw-import-{key_type:?}");
        import_rsa_public_key_into_token(&spki, &key_id, &label);
        cases.push((sw_key, key_type, modulus_bytes, key_id, label));
    }

    let provider = init_test_provider().await;
    let ProviderId::Pkcs11 { slot_id } = provider.provider_id() else {
        panic!("expected PKCS#11 provider id");
    };

    let message = b"QA software-signed, HSM-verified";
    let wrong = b"QA software-signed, HSM-verifiee";
    for (sw_key, key_type, modulus_bytes, key_id, label) in cases {
        let hsm_handle = ostrich_crypto::KeyHandle::new(
            ProviderId::Pkcs11 { slot_id },
            key_id,
            key_type,
            Algorithm::RsaPssSha256,
            label,
        );
        for algorithm in ALL_RSA_PSS.iter().chain(ALL_RSA_PKCS1.iter()).copied() {
            let sig = sw
                .sign(&sw_key, algorithm, message)
                .await
                .unwrap_or_else(|e| panic!("software sign {algorithm:?}: {e}"));
            assert_eq!(sig.len(), modulus_bytes);
            assert!(
                provider
                    .verify(&hsm_handle, algorithm, message, &sig)
                    .await
                    .expect("HSM verify runs"),
                "{key_type:?} {algorithm:?}: HSM must accept software signature"
            );
            assert!(
                matches!(
                    provider.verify(&hsm_handle, algorithm, wrong, &sig).await,
                    Ok(false)
                ),
                "{key_type:?} {algorithm:?}: HSM must reject wrong message"
            );
            let mut bad = sig.clone();
            bad[modulus_bytes / 2] ^= 0x80;
            assert!(
                matches!(
                    provider.verify(&hsm_handle, algorithm, message, &bad).await,
                    Ok(false)
                ),
                "{key_type:?} {algorithm:?}: HSM must reject tampered signature"
            );
        }
        // Cross-hash confusion is rejected by the HSM path (fail secure).
        let sig256 = sw
            .sign(&sw_key, Algorithm::RsaPssSha256, message)
            .await
            .expect("software sign");
        for other in [
            Algorithm::RsaPssSha384,
            Algorithm::RsaPssSha512,
            Algorithm::RsaPkcs1Sha256,
        ] {
            assert!(
                matches!(
                    provider.verify(&hsm_handle, other, message, &sig256).await,
                    Ok(false)
                ),
                "{key_type:?}: PSS-SHA256 signature must not verify as {other:?}"
            );
        }
        // Cleanup: no private object exists; destroy_key is idempotent per class.
        provider
            .destroy_key(&hsm_handle)
            .await
            .expect("destroy imported public key");
    }
}

#[tokio::test]
async fn test_rsa_pss_verify_malformed_signature_denies() {
    // SI-10 / fail secure: truncated, oversized, empty, and all-zero signatures
    // must yield Ok(false) or Err - never Ok(true).
    let provider = init_test_provider().await;
    let key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-qa-pss-malformed", false)
        .await
        .expect("generate RSA-2048");
    let message = b"QA malformed signature";
    let good = provider
        .sign(&key, Algorithm::RsaPssSha256, message)
        .await
        .expect("sign");
    let mut oversized = good.clone();
    oversized.push(0);
    let candidates: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("truncated", good[..good.len() - 1].to_vec()),
        ("oversized", oversized),
        ("all-zero", vec![0u8; good.len()]),
    ];
    for algorithm in ALL_RSA_PSS {
        for (name, sig) in &candidates {
            let result = provider.verify(&key, algorithm, message, sig).await;
            assert!(
                !matches!(result, Ok(true)),
                "{algorithm:?}: {name} signature must not verify"
            );
        }
    }
    provider.destroy_key(&key).await.expect("destroy key");
}

#[tokio::test]
async fn test_pqc_algorithms_fail_closed_on_pkcs11() {
    // Fail secure: the PKCS#11 provider does not implement ML-DSA / SLH-DSA
    // (FIPS 204/205) yet, so sign/verify must return Err - never a signature
    // and never Ok(true) - including through the new host-digest helper path.
    let provider = init_test_provider().await;
    let key = provider
        .generate_key_pair(KeyType::Rsa2048, "test-qa-pqc-fail-closed", false)
        .await
        .expect("generate RSA-2048");
    let message = b"QA PQC fail closed";
    for algorithm in [
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::SlhDsaSha2_128s,
        Algorithm::SlhDsaSha2_256f,
    ] {
        assert!(
            provider.sign(&key, algorithm, message).await.is_err(),
            "{algorithm:?}: PKCS#11 sign must fail closed"
        );
        assert!(
            provider
                .verify(&key, algorithm, message, &[0u8; 64])
                .await
                .is_err(),
            "{algorithm:?}: PKCS#11 verify must fail closed"
        );
    }
    provider.destroy_key(&key).await.expect("destroy key");
}
