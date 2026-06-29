//! System configuration model
//!
//! Maps to the `system_config` table — operator-tunable settings the CAA
//! manages.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: CM-2 (baseline), CM-3 (change control), CM-6 (settings)
//! - NIAP PP-CA: FMT_SMF.1, FMT_MTD.1

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// One system configuration setting.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SystemConfigRecord {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}
