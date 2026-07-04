//! X.509 certificate and CRL handling for OstrichPKI
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - RFC 5280: X.509 Public Key Infrastructure Certificate and CRL Profile
//! - RFC 6818: Updates to RFC 5280
//! - RFC 5758: Additional Algorithms for X.509 (SHA-2)
//! - RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, X448
//!
//! ## NIST 800-53 Rev 5
//! - SC-12: Cryptographic key establishment and management
//! - SC-17: PKI certificates
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_MSA.1: Management of security attributes
//! - FMT_MSA.1.2: Secure defaults for security attributes
//! - FDP_IFC.1: Information flow control policy
//! - FCS_COP.1: Cryptographic operation (certificate signing)

pub mod builder;
pub mod crl;
pub mod error;
pub mod extensions;
pub mod parser;
pub mod pkcs12;
pub mod pkcs7;
pub mod profile;
pub mod secure_defaults;
pub mod signing;
pub mod validation;

pub use builder::{CertificateBuilder, CrlBuilder};
pub use error::{Error, Result};
pub use parser::{parse_certificate, parse_crl, parse_csr};
pub use profile::{CertificateProfile, ExtendedKeyUsage, ProfileType};
pub use secure_defaults::{SecureDefaults, SecurityAttribute};
