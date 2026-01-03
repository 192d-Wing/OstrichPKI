//! Certificate Authority service
//!
//! RFC 5280: X.509 Public Key Infrastructure
//! NIST 800-53: SC-12 - Cryptographic key establishment and management

pub mod ca;
pub mod error;
pub mod grpc;
pub mod issuance;
pub mod rest;
pub mod revocation;

pub use ca::CertificateAuthority;
pub use error::{Error, Result};
pub use grpc::CaGrpcService;
pub use issuance::{CertificateIssuer, IssuanceRequest};
pub use rest::create_router;
pub use revocation::{RevocationManager, RevocationRequest};
