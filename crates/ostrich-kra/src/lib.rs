//! Key Recovery Authority (KRA) service
//!
//! The KRA provides secure key escrow and recovery capabilities for the PKI system.
//! It implements M-of-N threshold secret sharing using Shamir's algorithm to split
//! key encryption keys (KEKs) among recovery agents.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 Security Functional Requirements (SFRs)
//!
//! - **FCS_CKM.2**: Cryptographic Key Distribution
//!   - Implements secure distribution of key shares to authorized recovery agents
//!   - Uses Shamir's Secret Sharing for M-of-N threshold splitting
//!   - See [`escrow`] and [`shamir`] modules
//!
//! - **FCS_CKM.4**: Cryptographic Key Destruction
//!   - Supports secure key zeroization after recovery operations
//!   - Ensures ephemeral key material is properly destroyed
//!   - See [`recovery::KeyRecovery::complete_recovery`]
//!
//! - **FDP_ACC.1 / FDP_ACF.1**: Access Control Policy / Functions
//!   - Enforces role-based access control for key recovery operations
//!   - Only authorized recovery agents can submit shares
//!   - Recovery requires approval from designated authority
//!   - See [`recovery::RecoveryAgent`] and [`recovery::RecoveryRequest`]
//!
//! - **FAU_GEN.1**: Audit Data Generation
//!   - All key escrow and recovery operations are audited
//!   - Audit records include actor, action, outcome, and timestamp
//!   - See audit event emission throughout [`escrow`] and [`recovery`] modules
//!
//! - **FMT_MSA.1 / FMT_MSA.3**: Management of Security Attributes
//!   - Manages recovery agent attributes (active status, authorization)
//!   - Enforces threshold requirements for key reconstruction
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Establishes key escrow and recovery procedures
//! - **SC-12(1)**: Availability of Information
//!   - Key recovery enables availability during key loss scenarios
//!
//! ## NIST SP 800-57 Recommendations
//!
//! - Key management lifecycle: escrow, storage, recovery, destruction
//! - M-of-N threshold scheme for distributed trust

pub mod error;
pub mod escrow;
pub mod recovery;
pub mod shamir;

pub use error::{Error, Result};
pub use escrow::{KeyEscrow, KeyEscrowRequest};
pub use recovery::{KeyRecovery, RecoveryAgent, RecoveryRequest, RecoveryShare};
pub use shamir::ShamirSecretSharing;
