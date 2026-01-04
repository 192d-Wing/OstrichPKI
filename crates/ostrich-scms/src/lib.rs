//! SCMS (Smartcard Management System)
//!
//! Token lifecycle management, PKCS#11 operations, and inventory tracking.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **IA-2**: Identification and Authentication - Multi-factor authentication with smartcards
//! - **IA-5**: Authenticator Management - PIN/credential lifecycle management
//! - **IA-7**: Cryptographic Module Authentication - PKCS#11/HSM authentication
//! - **SC-12**: Cryptographic Key Establishment and Management - Token-based key management
//!
//! ## NIAP PP-CA v2.1 SFRs (Security Functional Requirements)
//! - **FIA_AFL.1**: Authentication Failure Handling - PIN lockout after consecutive failures
//! - **FIA_UAU.1**: Timing of Authentication - PIN verification before token operations
//! - **FIA_UAU.5**: Multiple Authentication Mechanisms - PIN + SO-PIN support
//! - **FIA_UID.1**: Timing of Identification - Token/user identification before operations
//! - **FCS_CKM.1**: Cryptographic Key Generation - Key generation on hardware token
//! - **FCS_CKM.2**: Cryptographic Key Distribution - Secure key distribution via token
//! - **FCS_CKM.4**: Cryptographic Key Destruction - Secure key deletion from token
//! - **FMT_SMF.1**: Specification of Management Functions - Token management operations
//! - **FMT_SMR.1**: Security Roles - SO (Security Officer) and User role separation
//! - **FPT_STM.1**: Reliable Time Stamps - Timestamped token lifecycle events
//! - **FAU_GEN.1**: Audit Data Generation - Token operation audit logging

pub mod error;
pub mod rest;
pub mod token;

pub use error::{Error, Result};
pub use rest::create_router;
pub use token::{Token, TokenEvent, TokenKey, TokenModel, TokenStatus};
