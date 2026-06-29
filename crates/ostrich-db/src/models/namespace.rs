//! Certificate namespace / wildcard policy model
//!
//! Maps to the `namespaces` table. A rule allows or denies issuance for names
//! matching a DNS pattern; the CAA curates the list.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: CM-3 (change control), AC-6 (managed by ManageNamespaces)
//! - NIAP PP-CA: FMT_SMF.1, FDP_ACF.1 (name-based issuance constraint)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A single namespace / wildcard policy rule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NamespaceRecord {
    pub id: Uuid,
    /// DNS name pattern (lowercased; `*.` prefix = wildcard suffix).
    pub pattern: String,
    /// true = permitted, false = explicitly denied.
    pub allow: bool,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}
