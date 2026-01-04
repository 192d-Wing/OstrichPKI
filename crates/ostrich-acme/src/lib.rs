//! ACME (Automated Certificate Management Environment) Responder
//!
//! This crate implements the ACME protocol (RFC 8555) for automated certificate
//! issuance, providing endpoints for account management, order processing,
//! challenge validation, and certificate retrieval.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! This crate implements the following Security Functional Requirements from the
//! NIAP Protection Profile for Certificate Authorities v2.1:
//!
//! - **FIA_UAU.1**: User authentication before any action
//!   - ACME accounts must be authenticated via JWS signatures before any
//!     certificate operations. All requests (except directory/nonce) require
//!     valid JWS authentication using the account's registered public key.
//!
//! - **FIA_UID.1**: User identification before any action
//!   - ACME accounts are identified by their JWK thumbprint (RFC 7638).
//!   - Account URLs serve as unique identifiers for authenticated sessions.
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - All ACME communications MUST use TLS 1.2+ (preferably TLS 1.3).
//!   - Client-server communication protected by HTTPS.
//!   - Challenge validation (HTTP-01, DNS-01, TLS-ALPN-01) uses secure channels.
//!
//! - **FDP_ACC.1**: Subset access control
//!   - Access control enforced on all ACME resources (accounts, orders,
//!     authorizations, challenges, certificates).
//!   - Accounts can only access their own orders and certificates.
//!   - JWS kid (key identifier) validates resource ownership.
//!
//! - **FDP_ACF.1**: Security attribute based access control
//!   - Account status (valid, deactivated, revoked) determines access.
//!   - Order status determines available operations (finalize only when ready).
//!   - Authorization status controls certificate issuance eligibility.
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - Account creation, updates, and deactivation are audited.
//!   - Order lifecycle events (creation, finalization) are logged.
//!   - Challenge validation attempts and results are recorded.
//!   - Certificate issuance requests are audited with full context.
//!
//! - **FAU_GEN.2**: User identity association
//!   - All audit records include the ACME account identifier.
//!   - JWK thumbprint provides cryptographic identity binding.
//!
//! - **FCS_COP.1**: Cryptographic operation
//!   - JWS signature verification using RS256, ES256, ES384, EdDSA.
//!   - SHA-256 for JWK thumbprint computation (RFC 7638).
//!   - Challenge token generation uses cryptographic RNG.
//!
//! - **FPT_STM.1**: Reliable time stamps
//!   - Order and authorization expiration timestamps.
//!   - Nonce validity periods for replay protection.
//!   - Certificate validity periods in issued certificates.
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Automated certificate lifecycle management via ACME protocol.
//!
//! - **SC-23**: Session Authenticity
//!   - Nonce-based replay protection per RFC 8555 Section 6.5.
//!   - URL binding in JWS protected header prevents cross-endpoint attacks.
//!
//! - **IA-2**: Identification and Authentication
//!   - JWS-based authentication for all ACME operations.
//!   - Account key pair serves as authentication credential.
//!
//! - **IA-5**: Authenticator Management
//!   - Public key registration during account creation.
//!   - Key change mechanism for key rotation.
//!
//! - **AU-2/AU-3**: Auditable Events / Audit Content
//!   - Comprehensive audit logging of all ACME operations.
//!
//! - **SI-10**: Information Input Validation
//!   - CSR validation during order finalization.
//!   - Domain identifier validation.
//!   - JWS structure and signature validation.
//!
//! ## RFC Compliance
//!
//! - **RFC 8555**: ACME Protocol
//! - **RFC 7515**: JSON Web Signature (JWS)
//! - **RFC 7517**: JSON Web Key (JWK)
//! - **RFC 7638**: JWK Thumbprint
//! - **RFC 8737**: TLS-ALPN-01 Challenge
//! - **RFC 5280**: X.509 Certificate Profile (for issued certificates)

pub mod account;
pub mod authorization;
pub mod ca_integration;
pub mod challenge;
pub mod error;
pub mod jws;
pub mod order;
pub mod rest;
pub mod validation;

pub use account::{Account, AccountStatus};
pub use authorization::{Authorization, AuthorizationStatus};
pub use ca_integration::AcmeCaClient;
pub use challenge::{Challenge, ChallengeStatus, ChallengeType};
pub use error::{Error, Result};
pub use order::{Order, OrderStatus};
pub use rest::create_router;
pub use validation::{Dns01Validator, Http01Validator, TlsAlpn01Validator};
