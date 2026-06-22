//! EST (Enrollment over Secure Transport) Server
//!
//! RFC 7030: Enrollment over Secure Transport
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! This crate implements the following Security Functional Requirements:
//!
//! - **FIA_UAU.1**: User authentication via mTLS client certificates
//!   - All EST operations (except cacerts) require client certificate authentication
//!   - Certificate validation performed before enrollment processing
//!   - Implementation: [`mtls::MtlsClientCert`], [`mtls::validate_client`]
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel (TLS 1.3)
//!   - All communications protected by TLS with mutual authentication
//!   - Server authenticates to client via TLS certificate
//!   - Client authenticates to server via mTLS client certificate
//!   - Implementation: TLS configuration in deployment
//!
//! - **FMT_SMF.1**: Security management functions for enrollment
//!   - Enrollment request creation and status management
//!   - CSR validation and certificate issuance workflow
//!   - Implementation: [`enrollment::Enrollment`], [`rest::simple_enroll`]
//!
//! - **FDP_ACC.1**: Access control policy for enrollment operations
//!   - Only authenticated clients may submit enrollment requests
//!   - Re-enrollment requires subject match with existing certificate
//!   - Implementation: [`rest::simple_enroll`], [`rest::simple_reenroll`]
//!
//! - **FCS_COP.1**: Cryptographic operations for CSR signature verification
//!   - CSR signatures verified before processing (proof of possession)
//!   - Implementation: [`rest::simple_enroll`] CSR signature check
//!
//! - **FAU_GEN.1**: Audit data generation for enrollment events
//!   - All enrollment operations generate audit records
//!   - Includes requestor identity, timestamp, and outcome
//!   - Implementation: Audit sink integration in handlers
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-12**: Cryptographic key establishment and management
//! - **SC-8**: Transmission confidentiality and integrity (TLS)
//! - **IA-2**: Identification and authentication (mTLS)
//! - **AU-2/AU-3**: Auditable events and audit content
//!
//! ## RFC Compliance
//!
//! - **RFC 7030**: Enrollment over Secure Transport (EST)
//! - **RFC 5280**: X.509 PKI Certificate and CRL Profile
//! - **RFC 2986**: PKCS #10 Certification Request Syntax

pub mod ca_integration;
pub mod enrollment;
pub mod enrollment_token;
pub mod error;
pub mod mtls;
pub mod rest;
pub mod serverkeygen;

pub use ca_integration::EstCaClient;
pub use enrollment::{
    CsrAttributes, Enrollment, EnrollmentRequest, EnrollmentResponse, EnrollmentStatus,
};
pub use error::{Error, Result};
pub use mtls::{ClientCertExtractor, MtlsClientCert, validate_client};
pub use rest::create_router;
pub use serverkeygen::{ServerKeyGenMaterial, ServerKeyGenRequest, generate_key_pair_for_client};
