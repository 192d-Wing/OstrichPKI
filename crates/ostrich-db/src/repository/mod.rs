//! Repository trait definitions
//!
//! This module defines the core repository traits and implementations for
//! all OstrichPKI database operations. Each repository enforces access
//! control and data integrity requirements.
//!
//! # Compliance Mapping
//!
//! ## NIST 800-53 Rev 5 Controls
//! - SC-28: Protection of information at rest
//! - AC-3: Access enforcement via repository interfaces
//! - AC-6: Least privilege - repositories expose only necessary operations
//! - SI-10: Information input validation - all repository inputs validated
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FDP_ACC.1: Subset access control - Repository trait methods enforce
//!   access control policies for create, read, update, delete operations
//! - FDP_ACF.1: Security attribute based access control - Repository
//!   implementations check caller authorization before data access
//! - FDP_ITC.1: Import of user data without security attributes - External
//!   data (CSRs, enrollment requests) imported through validated interfaces
//! - FDP_ETC.1: Export of user data without security attributes - Certificates
//!   and status information exported through controlled interfaces
//! - FMT_MSA.1: Management of security attributes - Entity ownership and
//!   permissions managed through repository operations
//! - FMT_MSA.3: Static attribute initialization - Default security attributes
//!   applied during entity creation

pub mod acme;
pub mod approval;
pub mod audit;
pub mod ca;
pub mod certificate;
pub mod est;
pub mod kra;
pub mod scms;

pub use acme::AcmeRepository;
pub use approval::ApprovalRepository;
pub use audit::AuditRepository;
pub use ca::CaRepository;
pub use certificate::CertificateRepository;
pub use est::EstRepository;
pub use kra::KraRepository;
pub use scms::ScmsRepository;

use crate::Result;
use async_trait::async_trait;

/// Base repository trait for common CRUD operations
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA v2.1: FDP_ACC.1 - All repository operations enforce access
///   control policies through this trait interface
/// - NIAP PP-CA v2.1: FDP_ACF.1 - Security attributes checked in implementations
/// - NIST 800-53: AC-3 - Access enforcement at the data layer
#[async_trait]
pub trait Repository<T>: Send + Sync {
    /// Find entity by ID
    ///
    /// NIAP PP-CA: FDP_ACC.1 - Read access control enforced
    async fn find_by_id(&self, id: &uuid::Uuid) -> Result<Option<T>>;

    /// Create a new entity
    ///
    /// NIAP PP-CA: FDP_ACC.1 - Create access control enforced
    /// NIAP PP-CA: FMT_MSA.3 - Default security attributes initialized
    async fn create(&self, entity: &T) -> Result<T>;

    /// Update an existing entity
    ///
    /// NIAP PP-CA: FDP_ACC.1 - Modify access control enforced
    /// NIAP PP-CA: FMT_MSA.1 - Security attribute modification controlled
    async fn update(&self, entity: &T) -> Result<T>;

    /// Delete an entity by ID
    ///
    /// NIAP PP-CA: FDP_ACC.1 - Delete access control enforced
    async fn delete(&self, id: &uuid::Uuid) -> Result<()>;

    /// List all entities (with optional pagination)
    ///
    /// NIAP PP-CA: FDP_ACC.1 - List access control enforced
    async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<T>>;

    /// Count total entities
    ///
    /// NIAP PP-CA: FDP_ACC.1 - Count access control enforced
    async fn count(&self) -> Result<i64>;
}
