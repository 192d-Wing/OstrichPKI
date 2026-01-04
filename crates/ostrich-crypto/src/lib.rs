//! Cryptographic abstraction layer for OstrichPKI
//!
//! NIST 800-53: SC-12 - Cryptographic key establishment and management
//! NIST 800-53: SC-13 - Cryptographic protection
//! FIPS 186-5: Digital Signature Standard
//! FIPS 203/204/205: Post-Quantum Cryptography standards
//! NIAP PP-CA: FPT_TST_EXT.1 - TSF Testing (self-tests)

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
