//! Database abstraction layer for OstrichPKI
//!
//! NIST 800-53: SC-28 - Protection of information at rest
//! NIST 800-53: AU-9 - Protection of audit information

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
