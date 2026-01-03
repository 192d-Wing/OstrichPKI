//! Repository trait definitions
//!
//! NIST 800-53: SC-28 - Protection of information at rest

pub mod acme;
pub mod audit;
pub mod certificate;
pub mod est;
pub mod kra;
pub mod scms;

pub use acme::AcmeRepository;
pub use audit::AuditRepository;
pub use certificate::CertificateRepository;
pub use est::EstRepository;
pub use kra::KraRepository;
pub use scms::ScmsRepository;

use crate::Result;
use async_trait::async_trait;

/// Base repository trait for common CRUD operations
#[async_trait]
pub trait Repository<T>: Send + Sync {
    /// Find entity by ID
    async fn find_by_id(&self, id: &uuid::Uuid) -> Result<Option<T>>;

    /// Create a new entity
    async fn create(&self, entity: &T) -> Result<T>;

    /// Update an existing entity
    async fn update(&self, entity: &T) -> Result<T>;

    /// Delete an entity by ID
    async fn delete(&self, id: &uuid::Uuid) -> Result<()>;

    /// List all entities (with optional pagination)
    async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<T>>;

    /// Count total entities
    async fn count(&self) -> Result<i64>;
}
