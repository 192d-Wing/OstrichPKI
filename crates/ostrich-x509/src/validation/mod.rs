//! Certificate path validation module
//!
//! RFC 5280 §6 - Certification Path Validation
//!
//! This module implements the complete RFC 5280 §6.1 path validation algorithm
//! for X.509 certificates.
//!
//! # COMPLIANCE MAPPING
//!
//! ## RFC Standards
//! - RFC 5280 §6: Certification Path Validation
//! - RFC 5280 §4.2: Certificate Extensions
//!
//! ## NIST 800-53 Rev 5
//! - SC-17: Public Key Infrastructure Certificates
//! - SC-12: Cryptographic Key Establishment and Management
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_X509_EXT.1: X.509 Certificate Validation
//! - FDP_CER_EXT.1: X.509 Certificate Validation
//! - FDP_CSI_EXT.1: Certificate Status Information
//!
//! # Architecture
//!
//! The path validation implementation is divided into modules:
//! - `error`: Validation error types
//! - `trust_anchor`: Trust anchor management
//! - `path_builder`: Certificate chain building
//! - `path_validator`: RFC 5280 §6.1 validation algorithm (Phase 2)
//! - `extensions`: Extension validation helpers (Phase 2)
//! - `name_constraints`: Name constraints processing (Phase 3)
//! - `policy`: Certificate policy processing (Phase 3)
//! - `revocation`: OCSP/CRL integration (Phase 4)
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use ostrich_x509::validation::{PathBuilder, TrustAnchorStore, TrustAnchor};
//!
//! // Create trust anchor store
//! let mut store = TrustAnchorStore::new();
//! store.add(TrustAnchor::new(
//!     "CN=Root CA,O=OstrichPKI".to_string(),
//!     root_public_key,
//!     Some(root_cert_der),
//! )).unwrap();
//!
//! // Build certificate chain
//! let builder = PathBuilder::new(store);
//! let chain = builder.build_path(&end_entity_cert)?;
//!
//! // Validate chain (Phase 2+)
//! // let result = PathValidator::validate(ctx)?;
//! ```

pub mod error;
pub mod extensions;
pub mod name_constraints;
pub mod path_builder;
pub mod path_validator;
pub mod policy;
pub mod revocation;
pub mod trust_anchor;

// Re-exports for convenience
pub use error::{Result, ValidationError};
pub use extensions::{BasicConstraints, KeyUsage};
pub use name_constraints::{GeneralSubtree, NameConstraints};
pub use path_builder::PathBuilder;
pub use path_validator::{PathValidator, ValidationContext, ValidationResult};
pub use policy::{PolicyNode, PolicyTree};
pub use revocation::{RevocationChecker, RevocationStatus};
pub use trust_anchor::{TrustAnchor, TrustAnchorStore};
