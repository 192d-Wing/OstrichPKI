//! Trust Anchor Management Protocol (TAMP) — RFC 5934.
//!
//! OstrichPKI implements the **manager / authority** role of TAMP: it composes,
//! CMS-signs, and distributes TAMP messages to remote cryptographic modules,
//! and verifies and records their signed confirmations and status responses.
//! Trust-anchor and per-signer sequence-number state is held durably so that
//! replay protection (RFC 5934 §4.1) survives restarts.
//!
//! # Module map
//!
//! - [`oids`] — content-type and attribute object identifiers (RFC 5934 App. A).
//! - [`statuscode`] — the `StatusCode` ENUMERATED (RFC 5934 §5).
//! - [`asn1`] — DER message structures (RFC 5934 App. A.1, RFC 5914).
//! - [`cms`] — CMS `SignedData` wrapping / verification (RFC 5652, §2 of 5934).
//! - [`error`] — error type with `StatusCode` mapping.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5
//! - **SC-12 / SC-13**: trust-anchor (key) management; FIPS-validated CMS signing.
//! - **SC-23**: session authenticity — monotonic sequence-number replay protection.
//! - **SI-10**: strict DER validation of all received structures.
//! - **SI-12**: zeroization of contingency-key plaintext material.
//! - **AU-2 / AU-3 / AU-12**: every trust-anchor state change is audited.
//! - **IA-7**: CA/apex signing keys are HSM/PKCS#11 backed.
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FMT_SMF.1**: trust-anchor management functions.
//! - **FCS_COP.1**: CMS signature generation / verification.
//! - **FAU_GEN.1**: audit generation for management operations.
//! - **FPT_STM.1**: reliable timestamps on messages and audit records.
//!
//! ## RFC Compliance
//! - **RFC 5934**: Trust Anchor Management Protocol (TAMP).
//! - **RFC 5914**: Trust Anchor Format.
//! - **RFC 5652**: Cryptographic Message Syntax (message protection).
//! - **RFC 5280**: X.509 certificate / CRL profile.

pub mod asn1;
pub mod cms;
pub mod error;
pub mod manager;
pub mod oids;
pub mod rest;
pub mod statuscode;

pub use error::{Error, Result};
pub use manager::{IngestOutcome, IssuedMessage, SignerContext, TampManager, TrustAnchorEdit};
pub use rest::{TampSigner, TampState, create_router};
pub use statuscode::StatusCode;
