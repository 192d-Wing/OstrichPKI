//! Key Recovery Authority (KRA) service
//!
//! NIST 800-53: SC-12 - Cryptographic key establishment and management
//! NIST 800-57: Key management best practices

pub mod error;
pub mod escrow;
pub mod recovery;
pub mod shamir;

pub use error::{Error, Result};
pub use escrow::{KeyEscrow, KeyEscrowRequest};
pub use recovery::{KeyRecovery, RecoveryAgent, RecoveryRequest, RecoveryShare};
pub use shamir::ShamirSecretSharing;
