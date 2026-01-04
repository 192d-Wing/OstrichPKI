//! Database abstraction layer for OstrichPKI
//!
//! This crate provides secure database access for all OstrichPKI components,
//! implementing protected storage for certificates, audit logs, keys, and
//! enrollment data.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - SC-28: Protection of information at rest
//! - AU-9: Protection of audit information
//! - AC-3: Access enforcement for database operations
//! - SC-8: Transmission confidentiality (TLS to database)
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FAU_STG.1: Protected audit trail storage - Audit events stored in append-only
//!   tables with hash chain integrity verification
//! - FAU_STG.4: Prevention of audit data loss - Database transactions ensure
//!   atomic writes of audit records
//! - FDP_ACC.1: Subset access control - Repository traits enforce role-based
//!   access to database entities
//! - FDP_ACF.1: Security attribute based access control - Access decisions
//!   based on entity ownership and permissions
//! - FDP_ITC.1: Import of user data without security attributes - CSR and
//!   certificate request data imported from external sources with validation
//! - FDP_ETC.1: Export of user data without security attributes - Certificate
//!   and CRL data exported to external requesters
//! - FPT_STM.1: Reliable time stamps - All database records include timestamps
//!   from trusted time sources
//!
//! ## FIPS Standards
//! - Database connections secured with FIPS-validated TLS implementations
//! - Audit hash chains use FIPS 180-4 SHA-256

pub mod error;
pub mod models;
pub mod pool;
pub mod repository;

pub use error::{Error, Result};
pub use pool::{DatabasePool, PoolConfig};

// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use sqlx;
pub use uuid::Uuid;
