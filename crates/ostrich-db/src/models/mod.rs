//! Database model types
//!
//! These models map to database tables and are used by repositories

pub mod audit;
pub mod certificate;

pub use audit::AuditEvent;
pub use certificate::Certificate;
