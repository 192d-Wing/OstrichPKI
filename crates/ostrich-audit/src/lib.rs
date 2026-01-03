//! Audit logging system for OstrichPKI
//!
//! NIST 800-53: AU-2 - Auditable events
//! NIST 800-53: AU-3 - Content of audit records
//! NIST 800-53: AU-9 - Protection of audit information
//! NIST 800-53: AU-10 - Non-repudiation

pub mod error;
pub mod event;
pub mod sink;

pub use error::{Error, Result};
pub use event::{AuditEvent, AuditEventBuilder, EventOutcome, EventType};
pub use sink::{AuditSink, DatabaseAuditSink};
