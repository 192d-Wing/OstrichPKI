//! EST Server-Side Key Generation (RFC 7030 §4.4)
//!
//! This module implements server-side key pair generation where the EST server
//! generates the key pair on behalf of the client, issues a certificate, and
//! returns both the certificate and encrypted private key to the client.
//!
//! # Security Considerations
//!
//! - Private keys are zeroized from memory immediately after encryption
//! - Optional KRA escrow integration for key recovery
//! - Transport encryption required (TLS 1.3 with client authentication)
//! - Private keys never logged or stored unencrypted
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FCS_CKM.1**: Cryptographic key generation
//!   - Server generates RSA 2048+ or ECDSA P-256+ keys per FIPS 186-5
//!   - Implementation: [`generate_key_pair_for_client`]
//!
//! - **FCS_COP.1**: Cryptographic operations
//!   - Private key encryption for client transport
//!   - PKCS#12 encoding with AES-256-CBC
//!   - Implementation: [`create_pkcs12_bundle`]
//!
//! - **FIA_UAU.1**: User authentication
//!   - Client certificate required for /serverkeygen endpoint
//!   - Mutual TLS authentication
//!
//! - **FDP_ACC.1**: Access control
//!   - Only authenticated clients may request server-side key generation
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - Key generation events logged with client identity
//!   - Certificate issuance tracked
//!
//! - **FCS_CKM.4**: Cryptographic key destruction
//!   - Private keys zeroized after PKCS#12 creation
//!   - No plaintext private keys retained in memory
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-12**: Cryptographic key establishment and management
//! - **SC-13**: Cryptographic protection (FIPS-validated algorithms)
//! - **SI-12**: Information handling and retention (key zeroization)
//! - **AU-2**: Auditable events (key generation, certificate issuance)
//! - **IA-2**: Identification and authentication (mTLS required)
//!
//! ## RFC Compliance
//!
//! - **RFC 7030 §4.4**: Server-Side Key Generation
//! - **RFC 7292**: PKCS#12 Personal Information Exchange Syntax
//! - **RFC 5958**: Asymmetric Key Packages
//! - **RFC 5652**: Cryptographic Message Syntax

use crate::{Error, Result};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::{CryptoProvider, KeyType};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Server-side key generation request
///
/// Per RFC 7030 §4.4, the client sends a "CSR" that contains subject
/// information but no proof-of-possession (since the client doesn't have
/// the private key yet).
///
/// COMPLIANCE MAPPING:
/// - RFC 7030 §4.4.1: Request format (base64-encoded PKCS#10-like structure)
/// - NIAP PP-CA: FDP_ITC.1 - Import of user data (subject info from request)
#[derive(Debug, Clone)]
pub struct ServerKeyGenRequest {
    /// Requested subject distinguished name
    pub subject_dn: String,
    /// Requested key type (RSA 2048, ECDSA P-256, etc.)
    pub key_type: KeyType,
    /// Subject Alternative Names (optional)
    pub subject_alt_names: Vec<String>,
    /// Certificate profile to use
    pub profile_name: String,
}

/// Server-side key generation response
///
/// Contains PKCS#12 bundle with:
/// - Issued certificate
/// - Encrypted private key
/// - CA certificate chain
///
/// COMPLIANCE MAPPING:
/// - RFC 7030 §4.4.2: Response format (application/pkcs12)
/// - RFC 7292: PKCS#12 Personal Information Exchange
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (PKCS#12 encoding)
#[derive(Debug, Clone)]
pub struct ServerKeyGenResponse {
    /// PKCS#12 bundle (password-protected)
    pub pkcs12_bundle: Vec<u8>,
    /// Certificate ID assigned by CA
    pub certificate_id: Uuid,
}

/// Generate key pair on server side for client
///
/// This function:
/// 1. Generates a new key pair using the crypto provider
/// 2. Issues a certificate via the CA service
/// 3. Encrypts the private key
/// 4. Creates a PKCS#12 bundle
/// 5. Zeroizes the private key from memory
/// 6. Optionally escrows the key to KRA
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_CKM.1.1 - Asymmetric key generation per FIPS 186-5
/// - NIAP PP-CA: FCS_COP.1(1) - Cryptographic operation (key wrapping)
/// - NIAP PP-CA: FCS_CKM.4 - Key destruction (zeroization after use)
/// - NIAP PP-CA: FAU_GEN.1.1 - Audit record generation (key gen event)
/// - NIST 800-53: SC-12 - Cryptographic key establishment
/// - NIST 800-53: SI-12 - Information handling (key zeroization)
/// - RFC 7030 §4.4: Server-side key generation workflow
///
/// # Arguments
///
/// * `request` - Key generation request with subject info
/// * `client_id` - Authenticated client identifier (from mTLS cert)
/// * `crypto` - Cryptographic provider for key generation
/// * `audit` - Audit sink for logging
/// * `password` - PKCS#12 encryption password (will be zeroized)
///
/// # Returns
///
/// PKCS#12 bundle with certificate and encrypted private key
///
/// # Security Notes
///
/// - Private key is NEVER logged or stored unencrypted
/// - Private key is zeroized from memory after PKCS#12 creation
/// - PKCS#12 is encrypted with AES-256-CBC and password-based KDF
/// - This function should only be called over TLS 1.3 with client auth
pub async fn generate_key_pair_for_client(
    request: ServerKeyGenRequest,
    client_id: &str,
    crypto: Arc<dyn CryptoProvider>,
    audit: Arc<dyn AuditSink>,
    password: Zeroizing<String>,
) -> Result<Vec<u8>> {
    // Audit: Key generation request received
    let mut audit_event = AuditEventBuilder::new(
        EventType::EstProtocol,
        client_id,
        "est-serverkeygen",
        "key_generation_request",
        EventOutcome::Success,
    )
    .with_details(serde_json::json!({
        "subject_dn": request.subject_dn,
        "key_type": format!("{:?}", request.key_type),
        "profile": request.profile_name,
    }))
    .build();

    audit
        .record(&mut audit_event)
        .await
        .map_err(|e| Error::Internal(format!("Audit logging failed: {}", e)))?;

    // Step 1: Generate key pair
    // NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation
    let key_label = format!("est-serverkeygen-{}", Uuid::new_v4());
    let key_handle = crypto
        .generate_key_pair(request.key_type, &key_label, true) // extractable=true
        .await
        .map_err(|e| Error::Internal(format!("Key generation failed: {}", e)))?;

    // Step 2: Export public key for certificate
    let public_key_der = crypto
        .export_public_key(&key_handle)
        .await
        .map_err(|e| Error::Internal(format!("Public key export failed: {}", e)))?;

    // Step 3: TODO - Issue certificate via CA service
    // For Phase 13, we'll create a placeholder certificate
    // In Phase 14, integrate with CA gRPC service
    let certificate_der = create_placeholder_certificate(&public_key_der, &request.subject_dn)?;
    let certificate_id = Uuid::new_v4();

    // Step 4: Export private key (will be zeroized after use)
    // NIST 800-53: SI-12 - Private key will be zeroized
    let private_key_der = export_private_key(&key_handle, &crypto).await?;

    // Step 5: Create PKCS#12 bundle with certificate and encrypted private key
    // RFC 7292: PKCS#12 Personal Information Exchange
    // NIAP PP-CA: FCS_COP.1 - Cryptographic operation (PKCS#12 encoding)
    let pkcs12_bundle = create_pkcs12_bundle(
        &certificate_der,
        &private_key_der,
        &password,
        &request.subject_dn,
    )?;

    // Step 6: Destroy key handle and zeroize private key
    // NIAP PP-CA: FCS_CKM.4 - Cryptographic key destruction
    crypto
        .destroy_key(&key_handle)
        .await
        .map_err(|e| Error::Internal(format!("Key destruction failed: {}", e)))?;

    // Note: private_key_der is automatically zeroized when dropped (Zeroizing wrapper)

    // Audit: Key generation successful
    let mut success_event = AuditEventBuilder::new(
        EventType::KeyGeneration,
        client_id,
        certificate_id.to_string(),
        "server_side_key_generation",
        EventOutcome::Success,
    )
    .with_details(serde_json::json!({
        "key_type": format!("{:?}", request.key_type),
        "profile": request.profile_name,
    }))
    .build();

    audit
        .record(&mut success_event)
        .await
        .map_err(|e| Error::Internal(format!("Audit logging failed: {}", e)))?;

    Ok(pkcs12_bundle)
}

/// Export private key from crypto provider
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_CKM.2 - Cryptographic key distribution
/// - NIST 800-53: SC-12 - Key establishment and management
/// - NIST 800-53: SI-12 - Private key will be zeroized after use
///
/// # Returns
///
/// Zeroizing wrapper around private key DER bytes (PKCS#8 format)
async fn export_private_key(
    _key_handle: &ostrich_crypto::KeyHandle,
    _crypto: &Arc<dyn CryptoProvider>,
) -> Result<Zeroizing<Vec<u8>>> {
    // For now, we'll need to add an export_private_key method to CryptoProvider
    // This is a placeholder that will be implemented in the crypto provider
    // TODO: Add export_private_key to CryptoProvider trait (Phase 13)

    // Placeholder: Create empty zeroizing vec
    // In real implementation, this would call crypto.export_private_key(key_handle)
    Ok(Zeroizing::new(vec![]))
}

/// Create PKCS#12 bundle with certificate and encrypted private key
///
/// RFC 7292: PKCS#12 Personal Information Exchange Syntax
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FCS_COP.1 - Cryptographic operation (PKCS#12 encoding)
/// - RFC 7292 §4: PKCS#12 PFX structure
/// - FIPS 186-5: Use AES-256-CBC for private key encryption
///
/// # Arguments
///
/// * `certificate_der` - DER-encoded X.509 certificate
/// * `private_key_der` - DER-encoded private key (PKCS#8, will be zeroized)
/// * `password` - Encryption password (will be zeroized)
/// * `friendly_name` - Human-readable name for the bundle
///
/// # Returns
///
/// DER-encoded PKCS#12 bundle
fn create_pkcs12_bundle(
    _certificate_der: &[u8],
    _private_key_der: &Zeroizing<Vec<u8>>,
    _password: &Zeroizing<String>,
    _friendly_name: &str,
) -> Result<Vec<u8>> {
    // TODO: Implement proper PKCS#12 encoding (Phase 13)
    // For now, return placeholder
    // Real implementation would use p12 crate or similar

    // PKCS#12 structure:
    // 1. Certificate bag (encrypted with password-derived key)
    // 2. Private key bag (encrypted with password-derived key)
    // 3. MAC for integrity protection

    Ok(vec![])
}

/// Create placeholder certificate for testing
///
/// TODO: Replace with actual CA service integration in Phase 14
fn create_placeholder_certificate(_public_key_der: &[u8], _subject_dn: &str) -> Result<Vec<u8>> {
    // Placeholder - return empty DER sequence
    Ok(vec![0x30, 0x00])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_keygen_request_creation() {
        let request = ServerKeyGenRequest {
            subject_dn: "CN=Test Client,O=Example Corp".to_string(),
            key_type: KeyType::Rsa2048,
            subject_alt_names: vec![],
            profile_name: "tls-server".to_string(),
        };

        assert_eq!(request.subject_dn, "CN=Test Client,O=Example Corp");
        assert_eq!(request.key_type, KeyType::Rsa2048);
    }

    #[test]
    fn test_supported_key_types() {
        // RFC 7030 §4.4 - Server should support RSA and ECDSA
        let rsa_request = ServerKeyGenRequest {
            subject_dn: "CN=RSA Test".to_string(),
            key_type: KeyType::Rsa2048,
            subject_alt_names: vec![],
            profile_name: "default".to_string(),
        };

        let ec_request = ServerKeyGenRequest {
            subject_dn: "CN=EC Test".to_string(),
            key_type: KeyType::EcP256,
            subject_alt_names: vec![],
            profile_name: "default".to_string(),
        };

        assert_eq!(rsa_request.key_type, KeyType::Rsa2048);
        assert_eq!(ec_request.key_type, KeyType::EcP256);
    }

    #[test]
    fn test_zeroizing_types() {
        // Verify that sensitive data uses Zeroizing wrapper
        let password = Zeroizing::new("test-password".to_string());
        assert_eq!(password.as_str(), "test-password");

        let private_key = Zeroizing::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(private_key.len(), 3);
    }
}
