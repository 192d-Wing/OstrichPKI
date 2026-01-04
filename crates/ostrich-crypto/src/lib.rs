//! Cryptographic abstraction layer for OstrichPKI
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5
//! - SC-12: Cryptographic key establishment and management
//! - SC-13: Cryptographic protection
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FCS_CKM.1: Cryptographic key generation
//! - FCS_CKM.2: Cryptographic key distribution
//! - FCS_CKM.4: Cryptographic key destruction
//! - FCS_COP.1: Cryptographic operation (signing, verification)
//! - FPT_TST_EXT.1: TSF self-testing
//!
//! ## FIPS Standards
//! - FIPS 186-5: Digital Signature Standard
//! - FIPS 203: ML-KEM (Post-Quantum Key Encapsulation)
//! - FIPS 204: ML-DSA (Post-Quantum Digital Signatures)
//! - FIPS 205: SLH-DSA (Hash-Based Digital Signatures)

pub mod algorithm;
pub mod error;
pub mod key;
pub mod pkcs11;
pub mod provider;
pub mod self_test;
pub mod software;

// Re-exports
pub use algorithm::{Algorithm, KeyType};
pub use error::{Error, Result};
pub use key::KeyHandle;
pub use provider::{CryptoProvider, CryptoProviderFactory};
pub use self_test::{SelfTestResult, SelfTestRunner, SelfTestSummary};
