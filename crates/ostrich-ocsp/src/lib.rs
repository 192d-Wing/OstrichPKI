//! OCSP Responder service
//!
//! This crate implements an Online Certificate Status Protocol (OCSP) responder
//! for providing real-time certificate revocation status information.
//!
//! # Compliance Mapping
//!
//! ## RFC Standards
//! - **RFC 6960**: Online Certificate Status Protocol (OCSP)
//!   - Section 4.1: Request Syntax
//!   - Section 4.2: Response Syntax
//!   - Section A.1: OCSP over HTTP
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FCS_COP.1(1)**: Cryptographic Operation - OCSP response signing using
//!   approved algorithms (RSA-PSS, ECDSA, EdDSA, ML-DSA)
//! - **FDP_CSI_EXT.1**: Certificate Status Information - Generation of OCSP
//!   responses in accordance with RFC 6960
//! - **FDP_OCSPG_EXT.1**: OCSP Response Generation - Producing signed OCSP
//!   responses with proper status (good, revoked, unknown)
//! - **FTP_ITC.1**: Inter-TSF Trusted Channel - Secure communication for
//!   OCSP queries via HTTPS/TLS
//! - **FDP_IFC.1**: Information Flow Control - Controlling access to
//!   revocation status information (unauthenticated access permitted per PP)
//! - **FAU_GEN.1**: Audit Data Generation - Logging OCSP request processing
//!   and response generation events
//! - **FPT_STM.1**: Reliable Time Stamps - Accurate timestamps in thisUpdate
//!   and nextUpdate fields
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-2**: Auditable Events - OCSP request/response logging
//! - **AU-3**: Content of Audit Records - Detailed OCSP audit records
//! - **SC-8**: Transmission Confidentiality - TLS for OCSP transport
//! - **SC-13**: Cryptographic Protection - FIPS-validated signing algorithms
//!
//! ## FIPS Standards
//! - **FIPS 186-5**: Digital Signature Standard (RSA, ECDSA, EdDSA)
//! - **FIPS 204**: ML-DSA for post-quantum OCSP response signing

pub mod cache;
pub mod error;
pub mod request;
pub mod responder;
pub mod response;
pub mod rest;

pub use cache::{CacheKey, OcspCache};
pub use error::{Error, Result};
pub use request::OcspRequest;
pub use responder::OcspResponder;
pub use response::{CertStatus, OcspResponse, ResponseStatus, SingleResponse};
pub use rest::create_router;
