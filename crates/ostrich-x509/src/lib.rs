//! X.509 certificate and CRL handling for OstrichPKI
//!
//! RFC 5280: X.509 Public Key Infrastructure Certificate and CRL Profile
//! NIST 800-53: SC-12 - Cryptographic key establishment and management
//! NIAP PP-CA: FMT_MSA.1.2 - Secure defaults for security attributes

pub mod builder;
pub mod crl;
pub mod error;
pub mod extensions;
pub mod parser;
pub mod profile;
pub mod secure_defaults;

pub use builder::{CertificateBuilder, CrlBuilder};
pub use error::{Error, Result};
pub use parser::{parse_certificate, parse_crl, parse_csr};
pub use profile::{CertificateProfile, ProfileType};
pub use secure_defaults::{SecureDefaults, SecurityAttribute};
