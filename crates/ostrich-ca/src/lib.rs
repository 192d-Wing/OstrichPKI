//! Certificate Authority service
//!
//! RFC 5280: X.509 Public Key Infrastructure
//! NIST 800-53: SC-12 - Cryptographic key establishment and management

pub mod ca;
pub mod error;
pub mod issuance;
pub mod revocation;

pub use ca::CertificateAuthority;
pub use error::{Error, Result};
pub use issuance::{CertificateIssuer, IssuanceRequest};
pub use revocation::{RevocationManager, RevocationRequest};
