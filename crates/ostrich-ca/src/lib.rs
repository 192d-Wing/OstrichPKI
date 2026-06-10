//! Certificate Authority service
//!
//! This crate provides the core Certificate Authority functionality for OstrichPKI,
//! including certificate issuance, revocation, and lifecycle management.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: Security management functions - Certificate issuance, revocation,
//!   profile management, and CA configuration operations
//! - **FCS_COP.1**: Cryptographic operations - Certificate signing using FIPS-validated
//!   algorithms (RSA-PSS, ECDSA, EdDSA, ML-DSA per FIPS 204)
//! - **FDP_IFC.1**: Information flow control - Certificate policy enforcement through
//!   profiles, extension validation, and issuance constraints
//! - **FDP_ACC.1**: Access control for CA operations - Role-based access to issuance,
//!   revocation, and administrative functions
//! - **FAU_GEN.1**: Audit data generation - All CA operations emit structured audit events
//! - **FPT_STM.1**: Reliable time stamps - Certificate validity periods and revocation times
//!
//! ## RFC Compliance
//! - RFC 5280: X.509 PKI Certificate and CRL Profile
//! - RFC 6960: OCSP (Online Certificate Status Protocol)
//! - RFC 5019: Lightweight OCSP Profile
//!
//! ## NIST 800-53 Controls
//! - SC-12: Cryptographic key establishment and management
//! - SC-13: Cryptographic protection
//! - AU-2/AU-3: Audit events and content

pub mod approval;
pub mod ca;
pub mod error;
pub mod grpc;
pub mod issuance;
pub mod rest;
pub mod revocation;

#[cfg(test)]
mod audit_signing_e2e;
#[cfg(test)]
mod issuance_aia_e2e;
#[cfg(test)]
mod pop_e2e;
#[cfg(test)]
mod crl_delta_e2e;

pub use approval::{ApprovalEngine, ApprovalRequest, ApprovalStatus, RequestType};
pub use ca::CertificateAuthority;
pub use error::{Error, Result};
pub use grpc::CaGrpcService;
pub use issuance::{CertificateIssuer, IssuanceRequest};
pub use rest::create_router;
pub use revocation::{RevocationManager, RevocationRequest};
