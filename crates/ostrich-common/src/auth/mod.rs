//! Authentication and Authorization Module
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)
//! - NIAP PP-CA: FIA_UAU.1 (User Authentication)
//! - NIAP PP-CA: FTA_SSL.1 (Session Locking)
//! - NIST 800-53: AC-7 (Unsuccessful Login Attempts)
//! - NIST 800-53: IA-11 (Re-authentication)

pub mod lockout;
pub mod session;

pub use lockout::{AuthLockout, LockoutConfig, LockoutStatus};
pub use session::{Session, SessionConfig, SessionManager, SessionStatus};
