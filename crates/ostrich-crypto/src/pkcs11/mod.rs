//! PKCS#11 HSM provider implementation
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-7 - Cryptographic module authentication
//! - NIST 800-53: SC-12 - Cryptographic key establishment and management
//! - NIST 800-53: SC-13 - Cryptographic protection (FIPS 140-3 modules)
//! - NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation (HSM-backed)
//! - NIAP PP-CA: FCS_COP.1 - Cryptographic operations (sign, verify)

use crate::{Algorithm, Error, KeyHandle, KeyType, Result, key::ProviderId};
use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::path::Path;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// PKCS#11 provider that interfaces with HSMs
///
/// This provider uses on-demand session management. Sessions are created per-operation
/// to ensure thread-safety. The PKCS#11 context is shared across threads.
///
/// COMPLIANCE MAPPING:
/// - FIPS 140-3: Cryptographic operations performed within validated module
/// - NIAP PP-CA: FCS_CKM.1 - Key generation in hardware security module
pub struct Pkcs11Provider {
    /// PKCS#11 library context (thread-safe)
    context: Arc<Pkcs11>,
    /// HSM slot object
    slot: Slot,
    /// Slot ID (for provider identification)
    slot_id: u64,
    /// User PIN (zeroized on drop, protected by mutex)
    pin: Arc<Mutex<Zeroizing<String>>>,
}

impl Pkcs11Provider {
    /// Create a new PKCS#11 provider
    ///
    /// # Arguments
    /// * `library_path` - Path to PKCS#11 library (e.g., `/usr/lib/softhsm/libsofthsm2.so`)
    /// * `slot_id` - HSM slot ID
    /// * `pin` - User PIN for authentication
    ///
    /// # Compliance
    /// - NIST 800-53: IA-7 - Authenticate to cryptographic module
    /// - NIST 800-53: IA-5(1) - Password-based authentication for HSM access
    /// - FIPS 140-3: User authentication required before cryptographic operations
    ///
    /// # Errors
    /// Returns error if:
    /// - PKCS#11 library cannot be loaded
    /// - Slot ID is invalid or token not present
    /// - Session cannot be opened
    /// - PIN authentication fails
    pub async fn new(library_path: &Path, slot_id: u64, pin: &str) -> Result<Self> {
        tracing::info!(
            library_path = %library_path.display(),
            slot_id = slot_id,
            "Initializing PKCS#11 provider"
        );

        // RFC 2119: PKCS#11 library MUST be initialized before use
        // NIST 800-53: SC-13 - Use FIPS-validated cryptographic module
        let context = Pkcs11::new(library_path)
            .map_err(|e| Error::Pkcs11(format!("Failed to load PKCS#11 library: {}", e)))?;

        // Initialize PKCS#11 library with thread-safe settings
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-13 - OS_LOCKING_OK enables thread-safe cryptographic operations
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Error::Pkcs11(format!("Failed to initialize PKCS#11: {}", e)))?;

        tracing::debug!("PKCS#11 library initialized successfully");

        // Find the requested slot
        let all_slots = context
            .get_slots_with_token()
            .map_err(|e| Error::Pkcs11(format!("Failed to enumerate slots: {}", e)))?;

        // Use the slot at the given index, or error if not found
        let slot = *all_slots
            .get(slot_id as usize)
            .ok_or_else(|| Error::SlotNotFound(slot_id))?;

        let slot_info = context
            .get_slot_info(slot)
            .map_err(|e| Error::Pkcs11(format!("Failed to get slot {} info: {}", slot_id, e)))?;

        tracing::debug!(
            slot_id = slot_id,
            manufacturer = ?slot_info.manufacturer_id(),
            description = ?slot_info.slot_description(),
            "HSM slot information retrieved"
        );

        let token_info = context
            .get_token_info(slot)
            .map_err(|e| Error::Pkcs11(format!("No token present in slot {}: {}", slot_id, e)))?;

        tracing::info!(
            token_label = ?token_info.label(),
            manufacturer = ?token_info.manufacturer_id(),
            model = ?token_info.model(),
            serial_number = ?token_info.serial_number(),
            "HSM token detected"
        );

        // Test session creation and authentication
        let test_session = context
            .open_rw_session(slot)
            .map_err(|e| Error::SessionError(format!("Failed to open test session: {}", e)))?;

        // Authenticate with PIN
        // NIST 800-53: IA-7 - Cryptographic module authentication
        // FIPS 140-3: User must authenticate before performing cryptographic operations
        let auth_pin = AuthPin::new(pin.to_string().into_boxed_str());
        test_session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| Error::Pkcs11(format!("Failed to authenticate to HSM: {}", e)))?;

        tracing::info!(slot_id = slot_id, "Successfully authenticated to HSM");

        // Close test session (sessions will be created on-demand)
        let _ = test_session.logout();

        // NIST 800-53: AU-3 - Log successful authentication
        tracing::info!(
            event = "pkcs11_provider_initialized",
            slot_id = slot_id,
            "PKCS#11 provider ready for cryptographic operations"
        );

        Ok(Self {
            context: Arc::new(context),
            slot,
            slot_id,
            pin: Arc::new(Mutex::new(Zeroizing::new(pin.to_string()))),
        })
    }

    /// Create an authenticated session for a cryptographic operation
    ///
    /// Sessions are created on-demand and should be short-lived. Each operation
    /// gets its own session to ensure thread-safety.
    ///
    /// # Compliance
    /// - NIST 800-53: IA-7 - Cryptographic module authentication
    /// - NIST 800-53: SC-12 - Cryptographic key establishment and management
    ///
    /// # Errors
    /// Returns error if session cannot be created or authentication fails
    fn open_session(&self) -> Result<Session> {
        // Open R/W session
        let session = self
            .context
            .open_rw_session(self.slot)
            .map_err(|e| Error::SessionError(format!("Failed to open session: {}", e)))?;

        // Authenticate with PIN
        let pin_guard = self
            .pin
            .lock()
            .map_err(|e| Error::SessionError(format!("Failed to acquire PIN lock: {}", e)))?;

        let auth_pin = AuthPin::new(pin_guard.to_string().into_boxed_str());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| Error::Pkcs11(format!("Failed to authenticate session: {}", e)))?;

        Ok(session)
    }

    /// Generate RSA key pair in HSM
    ///
    /// # Compliance
    /// - FIPS 186-5: RSA key generation with specified modulus size
    /// - NIAP PP-CA: FCS_CKM.1(1) - RSA key generation
    fn generate_rsa_key_pair(
        &self,
        session: &Session,
        modulus_bits: usize,
        key_id: &[u8],
        label: &str,
        extractable: bool,
    ) -> Result<(
        cryptoki::object::ObjectHandle,
        cryptoki::object::ObjectHandle,
    )> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, KeyType as CkKeyType, ObjectClass};

        // FIPS 186-5: Use public exponent 65537 (0x010001)
        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];

        // Public key attributes
        let public_key_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(CkKeyType::RSA),
            Attribute::Token(true), // Persistent key
            Attribute::Verify(true),
            Attribute::Encrypt(false), // Not for encryption, only signing
            Attribute::Wrap(false),
            Attribute::ModulusBits((modulus_bits as u64).into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.to_vec()),
        ];

        // Private key attributes
        let private_key_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(CkKeyType::RSA),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true), // Key material cannot be read
            Attribute::Extractable(extractable), // Usually false for CA keys
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.to_vec()),
        ];

        let (public_handle, private_handle) = session
            .generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &public_key_template,
                &private_key_template,
            )
            .map_err(|e| Error::KeyGeneration(format!("RSA key pair generation failed: {}", e)))?;

        tracing::debug!(
            modulus_bits = modulus_bits,
            label = %label,
            "RSA key pair generated in HSM"
        );

        Ok((public_handle, private_handle))
    }

    /// Generate EC key pair in HSM
    ///
    /// # Compliance
    /// - FIPS 186-5: ECDSA key generation on NIST curves
    /// - NIAP PP-CA: FCS_CKM.1(1) - ECC key generation
    fn generate_ec_key_pair(
        &self,
        session: &Session,
        curve_name: &str,
        key_id: &[u8],
        label: &str,
        extractable: bool,
    ) -> Result<(
        cryptoki::object::ObjectHandle,
        cryptoki::object::ObjectHandle,
    )> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, KeyType as CkKeyType, ObjectClass};

        // DER-encoded OID for the curve
        let ec_params = match curve_name {
            "secp256r1" => vec![
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
                0x07, // OID 1.2.840.10045.3.1.7
            ],
            "secp384r1" => vec![
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // OID 1.3.132.0.34
            ],
            "secp521r1" => vec![
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, // OID 1.3.132.0.35
            ],
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Unsupported curve: {}",
                    curve_name
                )));
            }
        };

        // Public key attributes
        let public_key_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(CkKeyType::EC),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::EcParams(ec_params),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.to_vec()),
        ];

        // Private key attributes
        let private_key_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(CkKeyType::EC),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(extractable),
            Attribute::Sign(true),
            Attribute::Derive(false), // Not for ECDH
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.to_vec()),
        ];

        let (public_handle, private_handle) = session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_key_template,
                &private_key_template,
            )
            .map_err(|e| Error::KeyGeneration(format!("EC key pair generation failed: {}", e)))?;

        tracing::debug!(
            curve = %curve_name,
            label = %label,
            "EC key pair generated in HSM"
        );

        Ok((public_handle, private_handle))
    }

    /// Export RSA public key in SPKI format
    ///
    /// # Compliance
    /// - RFC 8017: PKCS#1 RSA public key structure
    /// - RFC 5280 §4.1.2.7 - SubjectPublicKeyInfo
    fn export_rsa_public_key(
        &self,
        session: &Session,
        public_key_handle: cryptoki::object::ObjectHandle,
    ) -> Result<Vec<u8>> {
        use cryptoki::object::{Attribute, AttributeType};
        use der::Encode;
        use rsa::pkcs1::RsaPublicKey;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        // Get RSA modulus (n) and public exponent (e)
        let attributes = session
            .get_attributes(
                public_key_handle,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )
            .map_err(|e| {
                Error::Encoding(format!("Failed to get RSA public key attributes: {}", e))
            })?;

        let mut modulus = None;
        let mut public_exponent = None;

        for attr in attributes {
            match attr {
                Attribute::Modulus(n) => modulus = Some(n),
                Attribute::PublicExponent(e) => public_exponent = Some(e),
                _ => {}
            }
        }

        let modulus =
            modulus.ok_or_else(|| Error::Encoding("RSA modulus not found".to_string()))?;
        let public_exponent = public_exponent
            .ok_or_else(|| Error::Encoding("RSA public exponent not found".to_string()))?;

        // Build PKCS#1 RSAPublicKey structure
        use der::asn1::UintRef;
        let rsa_pub_key = RsaPublicKey {
            modulus: UintRef::new(&modulus)
                .map_err(|e| Error::Encoding(format!("Invalid RSA modulus: {}", e)))?,
            public_exponent: UintRef::new(&public_exponent)
                .map_err(|e| Error::Encoding(format!("Invalid RSA exponent: {}", e)))?,
        };

        // Encode to DER
        let rsa_pub_key_der = rsa_pub_key
            .to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode RSA public key: {}", e)))?;

        // Build SubjectPublicKeyInfo
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"), // rsaEncryption
            parameters: Some(der::asn1::AnyRef::from(der::asn1::Null).into()),
        };

        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: der::asn1::BitString::from_bytes(&rsa_pub_key_der)
                .map_err(|e| Error::Encoding(format!("Failed to create BitString: {}", e)))?,
        };

        // Encode SPKI to DER
        spki.to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode SPKI: {}", e)))
    }

    /// Export EC public key in SPKI format
    ///
    /// # Compliance
    /// - RFC 5480: EC public key structure
    /// - RFC 5280 §4.1.2.7 - SubjectPublicKeyInfo
    fn export_ec_public_key(
        &self,
        session: &Session,
        public_key_handle: cryptoki::object::ObjectHandle,
        key_type: &KeyType,
    ) -> Result<Vec<u8>> {
        use cryptoki::object::{Attribute, AttributeType};
        use der::Encode;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

        // Get EC point (uncompressed format: 0x04 || x || y)
        let attributes = session
            .get_attributes(public_key_handle, &[AttributeType::EcPoint])
            .map_err(|e| {
                Error::Encoding(format!("Failed to get EC public key attributes: {}", e))
            })?;

        let ec_point = attributes
            .iter()
            .find_map(|attr| {
                if let Attribute::EcPoint(point) = attr {
                    Some(point.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Encoding("EC point not found".to_string()))?;

        // Determine curve OID
        let curve_oid = match key_type {
            KeyType::EcP256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"), // secp256r1
            KeyType::EcP384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),        // secp384r1
            KeyType::EcP521 => ObjectIdentifier::new_unwrap("1.3.132.0.35"),        // secp521r1
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Unsupported EC key type: {:?}",
                    key_type
                )));
            }
        };

        // Build SubjectPublicKeyInfo
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"), // ecPublicKey
            parameters: Some(curve_oid.into()),
        };

        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: der::asn1::BitString::from_bytes(&ec_point)
                .map_err(|e| Error::Encoding(format!("Failed to create BitString: {}", e)))?,
        };

        // Encode SPKI to DER
        spki.to_der()
            .map_err(|e| Error::Encoding(format!("Failed to encode SPKI: {}", e)))
    }
}

impl Drop for Pkcs11Provider {
    /// Clean up PKCS#11 resources
    ///
    /// NIST 800-53: SC-12 - Proper cleanup of cryptographic resources
    fn drop(&mut self) {
        // Note: PKCS#11 context will be finalized when the Arc refcount reaches 0
        // This is safe because cryptoki handles cleanup automatically
        tracing::debug!(slot_id = self.slot_id, "PKCS#11 provider dropped");
    }
}

#[async_trait]
impl crate::provider::CryptoProvider for Pkcs11Provider {
    /// Generate a key pair in the HSM
    ///
    /// # Compliance
    /// - NIST 800-53: SC-12 - Cryptographic key establishment in FIPS 140-3 module
    /// - NIAP PP-CA: FCS_CKM.1 - Cryptographic key generation (RSA, ECDSA)
    /// - FIPS 186-5: Digital signature key pair generation
    ///
    /// # Arguments
    /// * `key_type` - Type of key to generate (RSA-2048/3072/4096, EC P-256/P-384/P-521, EdDSA)
    /// * `label` - Human-readable label for the key
    /// * `extractable` - Whether private key can be exported (usually false for CA keys)
    ///
    /// # Errors
    /// Returns error if key type is unsupported or key generation fails
    async fn generate_key_pair(
        &self,
        key_type: KeyType,
        label: &str,
        extractable: bool,
    ) -> Result<KeyHandle> {
        tracing::info!(
            key_type = ?key_type,
            label = %label,
            extractable = extractable,
            "Generating key pair in HSM"
        );

        // Generate unique key ID using OS entropy (FIPS 140-3 backed via getrandom).
        // 32 random bytes are sufficient for an opaque object identifier.
        let mut key_id = vec![0u8; 32];
        getrandom::fill(&mut key_id)
            .map_err(|e| Error::Entropy(format!("Failed to generate key id: {}", e)))?;

        // NIST 800-53: AU-3 - Audit key generation
        tracing::info!(
            event = "key_pair_generation_started",
            key_type = ?key_type,
            label = %label,
            key_id_len = key_id.len(),
            "Starting HSM key pair generation"
        );

        let session = self.open_session()?;

        let (_public_handle, _private_handle) = match key_type {
            // FIPS 186-5: RSA key generation
            KeyType::Rsa2048 => {
                self.generate_rsa_key_pair(&session, 2048, &key_id, label, extractable)?
            }
            KeyType::Rsa3072 => {
                self.generate_rsa_key_pair(&session, 3072, &key_id, label, extractable)?
            }
            KeyType::Rsa4096 => {
                self.generate_rsa_key_pair(&session, 4096, &key_id, label, extractable)?
            }

            // FIPS 186-5: ECDSA key generation
            KeyType::EcP256 => {
                self.generate_ec_key_pair(&session, "secp256r1", &key_id, label, extractable)?
            }
            KeyType::EcP384 => {
                self.generate_ec_key_pair(&session, "secp384r1", &key_id, label, extractable)?
            }
            KeyType::EcP521 => {
                self.generate_ec_key_pair(&session, "secp521r1", &key_id, label, extractable)?
            }

            // EdDSA not universally supported in PKCS#11 HSMs
            KeyType::Ed25519 | KeyType::Ed448 => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not supported by PKCS#11, use software provider",
                    key_type
                )));
            }

            // Post-quantum algorithms not yet supported
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not yet implemented",
                    key_type
                )));
            }
        };

        // Determine compatible algorithm
        let algorithm = match key_type {
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                crate::Algorithm::RsaPssSha256 // Prefer PSS for new keys
            }
            KeyType::EcP256 => crate::Algorithm::EcdsaP256Sha256,
            KeyType::EcP384 => crate::Algorithm::EcdsaP384Sha384,
            KeyType::EcP521 => crate::Algorithm::EcdsaP521Sha512,
            _ => unreachable!(),
        };

        // Logout session
        let _ = session.logout();

        // NIST 800-53: AU-3 - Audit successful key generation
        tracing::info!(
            event = "key_pair_generated",
            key_type = ?key_type,
            label = %label,
            key_id_len = key_id.len(),
            algorithm = ?algorithm,
            "Key pair successfully generated in HSM"
        );

        Ok(KeyHandle::new(
            self.provider_id(),
            key_id,
            key_type,
            algorithm,
            label.to_string(),
        ))
    }

    /// Sign data using a private key in the HSM
    ///
    /// # Compliance
    /// - NIST 800-53: SC-13 - Cryptographic protection using FIPS 140-3 module
    /// - NIAP PP-CA: FCS_COP.1(2) - Cryptographic signature generation
    /// - FIPS 186-5: Digital signature generation
    ///
    /// # Arguments
    /// * `key` - Handle to the private key in the HSM
    /// * `algorithm` - Signature algorithm to use
    /// * `data` - Data to sign (typically a hash for certificates/CRLs)
    ///
    /// # Errors
    /// Returns error if key not found, algorithm mismatch, or signing fails
    async fn sign(&self, key: &KeyHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, ObjectClass};

        // NIST 800-53: AU-3 - Audit signing operation
        tracing::debug!(
            key_label = %key.label,
            algorithm = ?algorithm,
            data_len = data.len(),
            "Signing data with HSM key"
        );

        let session = self.open_session()?;

        // Find the private key by ID
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(key.key_id.clone()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find key: {}", e)))?;

        if objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Private key with ID not found in HSM: {}",
                key.label
            )));
        }

        let private_key_handle = objects[0];

        // Select PKCS#11 mechanism based on algorithm
        let mechanism = match algorithm {
            // RSA-PSS (preferred for new signatures)
            Algorithm::RsaPssSha256 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA256,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into(), // Salt length = hash length
                })
            }
            Algorithm::RsaPssSha384 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA384,
                    mgf: PkcsMgfType::MGF1_SHA384,
                    s_len: 48.into(),
                })
            }
            Algorithm::RsaPssSha512 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA512,
                    mgf: PkcsMgfType::MGF1_SHA512,
                    s_len: 64.into(),
                })
            }

            // RSA PKCS#1 v1.5 (legacy compatibility)
            Algorithm::RsaPkcs1Sha256 => Mechanism::Sha256RsaPkcs,
            Algorithm::RsaPkcs1Sha384 => Mechanism::Sha384RsaPkcs,
            Algorithm::RsaPkcs1Sha512 => Mechanism::Sha512RsaPkcs,

            // ECDSA
            Algorithm::EcdsaP256Sha256 => Mechanism::Ecdsa,
            Algorithm::EcdsaP384Sha384 => Mechanism::Ecdsa,
            Algorithm::EcdsaP521Sha512 => Mechanism::Ecdsa,

            // EdDSA not supported in PKCS#11
            Algorithm::Ed25519 | Algorithm::Ed448 => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not supported by PKCS#11",
                    algorithm
                )));
            }

            // Post-quantum not yet supported
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not yet implemented",
                    algorithm
                )));
            }
        };

        // Perform signing operation
        // FIPS 186-5: Digital signature generation in FIPS 140-3 module
        let signature = session
            .sign(&mechanism, private_key_handle, data)
            .map_err(|e| Error::Signing(format!("HSM signing failed: {}", e)))?;

        // Logout session
        let _ = session.logout();

        // NIST 800-53: AU-3 - Audit successful signing
        tracing::info!(
            event = "signature_generated",
            key_label = %key.label,
            algorithm = ?algorithm,
            signature_len = signature.len(),
            "Data successfully signed in HSM"
        );

        Ok(signature)
    }

    /// Verify a signature using a public key in the HSM
    ///
    /// # Compliance
    /// - NIST 800-53: SC-13 - Cryptographic protection
    /// - NIAP PP-CA: FCS_COP.1(3) - Cryptographic signature verification
    /// - FIPS 186-5: Digital signature verification
    ///
    /// # Arguments
    /// * `key` - Handle to the public key in the HSM
    /// * `algorithm` - Signature algorithm used
    /// * `data` - Original data that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid
    async fn verify(
        &self,
        key: &KeyHandle,
        algorithm: Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, ObjectClass};

        tracing::debug!(
            key_label = %key.label,
            algorithm = ?algorithm,
            data_len = data.len(),
            signature_len = signature.len(),
            "Verifying signature with HSM key"
        );

        let session = self.open_session()?;

        // Find the public key by ID
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(key.key_id.clone()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find public key: {}", e)))?;

        if objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Public key with ID not found in HSM: {}",
                key.label
            )));
        }

        let public_key_handle = objects[0];

        // Select PKCS#11 mechanism (same as signing)
        let mechanism = match algorithm {
            Algorithm::RsaPssSha256 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA256,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into(),
                })
            }
            Algorithm::RsaPssSha384 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA384,
                    mgf: PkcsMgfType::MGF1_SHA384,
                    s_len: 48.into(),
                })
            }
            Algorithm::RsaPssSha512 => {
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
                Mechanism::RsaPkcsPss(PkcsPssParams {
                    hash_alg: cryptoki::mechanism::MechanismType::SHA512,
                    mgf: PkcsMgfType::MGF1_SHA512,
                    s_len: 64.into(),
                })
            }
            Algorithm::RsaPkcs1Sha256 => Mechanism::Sha256RsaPkcs,
            Algorithm::RsaPkcs1Sha384 => Mechanism::Sha384RsaPkcs,
            Algorithm::RsaPkcs1Sha512 => Mechanism::Sha512RsaPkcs,
            Algorithm::EcdsaP256Sha256
            | Algorithm::EcdsaP384Sha384
            | Algorithm::EcdsaP521Sha512 => Mechanism::Ecdsa,
            Algorithm::Ed25519 | Algorithm::Ed448 => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not supported by PKCS#11",
                    algorithm
                )));
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "{:?} not yet implemented",
                    algorithm
                )));
            }
        };

        // Perform verification
        let is_valid = session
            .verify(&mechanism, public_key_handle, data, signature)
            .is_ok();

        // Logout session
        let _ = session.logout();

        tracing::debug!(
            key_label = %key.label,
            is_valid = is_valid,
            "Signature verification completed"
        );

        Ok(is_valid)
    }

    /// Export public key from HSM in SPKI (SubjectPublicKeyInfo) format
    ///
    /// # Compliance
    /// - RFC 5280 §4.1.2.7 - SubjectPublicKeyInfo for certificate generation
    /// - NIST 800-53: SC-12 - Public key export for certificate issuance
    ///
    /// # Arguments
    /// * `key` - Handle to the key pair
    ///
    /// # Returns
    /// DER-encoded SubjectPublicKeyInfo structure
    ///
    /// # Errors
    /// Returns error if key not found or export fails
    async fn export_public_key(&self, key: &KeyHandle) -> Result<Vec<u8>> {
        use cryptoki::object::{Attribute, ObjectClass};

        tracing::debug!(
            key_label = %key.label,
            key_type = ?key.key_type,
            "Exporting public key from HSM"
        );

        let session = self.open_session()?;

        // Find the public key by ID
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(key.key_id.clone()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find public key: {}", e)))?;

        if objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Public key with ID not found in HSM: {}",
                key.label
            )));
        }

        let public_key_handle = objects[0];

        // Extract public key material based on key type
        let spki_bytes = match key.key_type {
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                self.export_rsa_public_key(&session, public_key_handle)?
            }
            KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
                self.export_ec_public_key(&session, public_key_handle, &key.key_type)?
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Public key export not implemented for {:?}",
                    key.key_type
                )));
            }
        };

        // Logout session
        let _ = session.logout();

        tracing::debug!(
            key_label = %key.label,
            spki_len = spki_bytes.len(),
            "Public key exported from HSM"
        );

        Ok(spki_bytes)
    }

    async fn import_key(
        &self,
        _key_type: KeyType,
        _private_key: Zeroizing<Vec<u8>>,
        _label: &str,
    ) -> Result<KeyHandle> {
        // TODO: Implement PKCS#11 key import
        Err(Error::KeyGeneration(
            "PKCS#11 key import not yet implemented".to_string(),
        ))
    }

    async fn destroy_key(&self, _key: &KeyHandle) -> Result<()> {
        // TODO: Implement PKCS#11 key destruction
        Err(Error::KeyGeneration(
            "PKCS#11 key destruction not yet implemented".to_string(),
        ))
    }

    /// Wrap (encrypt) a key using another key in the HSM
    ///
    /// # Compliance
    /// - NIST 800-53: SC-12 - Cryptographic key establishment and management
    /// - NIST 800-53: SC-13 - Key wrapping using FIPS-approved algorithms
    /// - NIAP PP-CA: FCS_CKM.4 - Cryptographic key destruction (key escrow)
    ///
    /// # Arguments
    /// * `key_to_wrap` - Handle to the key that should be wrapped
    /// * `wrapping_key` - Handle to the key encryption key (KEK)
    ///
    /// # Returns
    /// Encrypted key material (wrapped key blob)
    ///
    /// # Errors
    /// Returns error if keys not found or wrapping fails
    ///
    /// # Use Case
    /// Used by KRA to escrow private keys for recovery purposes
    async fn wrap_key(&self, key_to_wrap: &KeyHandle, wrapping_key: &KeyHandle) -> Result<Vec<u8>> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, ObjectClass};

        tracing::info!(
            key_to_wrap = %key_to_wrap.label,
            wrapping_key = %wrapping_key.label,
            "Wrapping key in HSM for escrow"
        );

        let session = self.open_session()?;

        // Find the key to wrap (must be extractable)
        let wrap_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(key_to_wrap.key_id.clone()),
        ];

        let wrap_objects = session
            .find_objects(&wrap_template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find key to wrap: {}", e)))?;

        if wrap_objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Key to wrap not found in HSM: {}",
                key_to_wrap.label
            )));
        }

        let key_to_wrap_handle = wrap_objects[0];

        // Find the wrapping key (KEK)
        let kek_template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Id(wrapping_key.key_id.clone()),
        ];

        let kek_objects = session
            .find_objects(&kek_template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find wrapping key: {}", e)))?;

        if kek_objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Wrapping key not found in HSM: {}",
                wrapping_key.label
            )));
        }

        let wrapping_key_handle = kek_objects[0];

        // Use AES-KW (Key Wrap) mechanism per NIST SP 800-38F
        // NIST 800-53: SC-13 - Use FIPS-approved key wrapping
        let mechanism = Mechanism::AesKeyWrap;

        // Perform key wrapping
        let wrapped_key = session
            .wrap_key(&mechanism, wrapping_key_handle, key_to_wrap_handle)
            .map_err(|e| Error::KeyGeneration(format!("Key wrapping failed: {}", e)))?;

        // Logout session
        let _ = session.logout();

        // NIST 800-53: AU-3 - Audit key wrapping for escrow
        tracing::info!(
            event = "key_wrapped",
            key_to_wrap = %key_to_wrap.label,
            wrapping_key = %wrapping_key.label,
            wrapped_len = wrapped_key.len(),
            "Key successfully wrapped for escrow"
        );

        Ok(wrapped_key)
    }

    /// Unwrap (decrypt) a previously wrapped key and import into HSM
    ///
    /// # Compliance
    /// - NIST 800-53: SC-12 - Cryptographic key establishment and management
    /// - NIST 800-53: SC-13 - Key unwrapping using FIPS-approved algorithms
    /// - NIAP PP-CA: FCS_CKM.4 - Key recovery from escrow
    ///
    /// # Arguments
    /// * `wrapped_key` - The encrypted key blob
    /// * `unwrapping_key` - Handle to the key encryption key (KEK)
    /// * `key_type` - Type of key being unwrapped
    /// * `label` - Label for the recovered key
    ///
    /// # Returns
    /// Handle to the unwrapped key now stored in the HSM
    ///
    /// # Errors
    /// Returns error if unwrapping key not found or unwrapping fails
    ///
    /// # Use Case
    /// Used by KRA to recover escrowed private keys
    async fn unwrap_key(
        &self,
        wrapped_key: &[u8],
        unwrapping_key: &KeyHandle,
        key_type: KeyType,
        label: &str,
    ) -> Result<KeyHandle> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, KeyType as CkKeyType, ObjectClass};

        tracing::info!(
            unwrapping_key = %unwrapping_key.label,
            key_type = ?key_type,
            label = %label,
            wrapped_len = wrapped_key.len(),
            "Unwrapping key from escrow in HSM"
        );

        let session = self.open_session()?;

        // Find the unwrapping key (KEK)
        let kek_template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Id(unwrapping_key.key_id.clone()),
        ];

        let kek_objects = session
            .find_objects(&kek_template)
            .map_err(|e| Error::KeyNotFound(format!("Failed to find unwrapping key: {}", e)))?;

        if kek_objects.is_empty() {
            return Err(Error::KeyNotFound(format!(
                "Unwrapping key not found in HSM: {}",
                unwrapping_key.label
            )));
        }

        let unwrapping_key_handle = kek_objects[0];

        // Generate new key ID for the recovered key using OS entropy.
        let mut key_id = vec![0u8; 32];
        getrandom::fill(&mut key_id)
            .map_err(|e| Error::Entropy(format!("Failed to generate key id: {}", e)))?;

        // Determine PKCS#11 key type
        let (ck_key_type, algorithm) = match key_type {
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                (CkKeyType::RSA, crate::Algorithm::RsaPssSha256)
            }
            KeyType::EcP256 => (CkKeyType::EC, crate::Algorithm::EcdsaP256Sha256),
            KeyType::EcP384 => (CkKeyType::EC, crate::Algorithm::EcdsaP384Sha384),
            KeyType::EcP521 => (CkKeyType::EC, crate::Algorithm::EcdsaP521Sha512),
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Key unwrapping not supported for {:?}",
                    key_type
                )));
            }
        };

        // Template for the unwrapped private key
        let unwrap_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(ck_key_type),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false), // Recovered keys are non-extractable
            Attribute::Sign(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(key_id.clone()),
        ];

        // Use AES-KW (Key Wrap) mechanism per NIST SP 800-38F
        // NIST 800-53: SC-13 - Use FIPS-approved key unwrapping
        let mechanism = Mechanism::AesKeyWrap;

        // Perform key unwrapping
        let _unwrapped_handle = session
            .unwrap_key(
                &mechanism,
                unwrapping_key_handle,
                wrapped_key,
                &unwrap_template,
            )
            .map_err(|e| Error::KeyGeneration(format!("Key unwrapping failed: {}", e)))?;

        // Logout session
        let _ = session.logout();

        // NIST 800-53: AU-3 - Audit key recovery from escrow
        tracing::info!(
            event = "key_unwrapped",
            unwrapping_key = %unwrapping_key.label,
            label = %label,
            key_type = ?key_type,
            "Key successfully recovered from escrow"
        );

        Ok(KeyHandle::new(
            self.provider_id(),
            key_id,
            key_type,
            algorithm,
            label.to_string(),
        ))
    }

    async fn generate_random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        // NIAP PP-CA: FCS_RBG_EXT.1 - Use HSM's FIPS-validated RNG if available
        // NIST 800-53: SC-13 - Cryptographic protection using HSM RNG

        // Try to use HSM's RNG first
        let session = self.open_session()?;
        let mut buffer = vec![0u8; len];
        match session.generate_random_slice(&mut buffer) {
            Ok(()) => {
                tracing::debug!(len = %len, "Generated random bytes using HSM RNG");
                Ok(buffer)
            }
            Err(e) => {
                // Fallback to software DRBG if HSM RNG unavailable
                tracing::warn!(
                    error = %e,
                    "HSM RNG unavailable, falling back to software DRBG"
                );
                use crate::drbg::SecureRng;
                let rng = SecureRng::new()?;
                rng.fill_bytes(len)
            }
        }
    }

    fn provider_id(&self) -> ProviderId {
        ProviderId::Pkcs11 {
            slot_id: self.slot_id,
        }
    }

    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        // TODO: Implement PKCS#11 key listing
        Ok(Vec::new())
    }
}
