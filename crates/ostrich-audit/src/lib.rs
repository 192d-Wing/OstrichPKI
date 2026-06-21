//! Audit logging system for OstrichPKI
//!
//! This crate provides a comprehensive audit logging infrastructure for PKI operations,
//! implementing tamper-evident hash chains and secure storage of audit records.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - **AU-2**: Auditable events - Defines security-relevant events to audit
//! - **AU-3**: Content of audit records - Specifies required fields in audit records
//! - **AU-9**: Protection of audit information - Hash chain integrity protection
//! - **AU-10**: Non-repudiation - Cryptographic binding of events
//! - **AU-12**: Audit generation - Automatic audit record generation
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - **FAU_GEN.1**: Audit data generation - Generates audit records for CA events
//! - **FAU_GEN.2**: User identity association - Associates identity with audit events
//! - **FAU_STG.1**: Protected audit trail storage - Database-backed persistent storage
//! - **FAU_STG.4**: Prevention of audit data loss - Hash chain prevents undetected modification
//!
//! ## Related Standards
//! - RFC 5280: X.509 PKI Certificate and CRL Profile (certificate lifecycle events)
//! - FIPS 180-4: SHA-256 for audit record hashing

pub mod error;
pub mod event;
pub mod session_hook;
pub mod sink;

pub use error::{Error, Result};
pub use event::{AuditEvent, AuditEventBuilder, EventOutcome, EventType};
pub use session_hook::SessionAuditAdapter;
pub use sink::{AuditSink, DatabaseAuditSink};

#[cfg(any(test, feature = "testing"))]
pub use sink::MemoryAuditSink;
