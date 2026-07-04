//! Bulk certificate enrollment job models
//!
//! Maps to the `bulk_enrollment_jobs` and `bulk_enrollment_items` tables. An
//! Administrator uploads a ZIP of CSRs under one profile; one job row tracks the
//! batch and one item row records each CSR's outcome.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: AU-2 (auditable bulk operation), AC-3/AC-6 (submitter-owned)
//! - NIAP PP-CA: FDP_CER_EXT.2 (CSR -> request linkage), FDP_CER_EXT.3 (state)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A bulk enrollment job: one upload of many CSRs under a single profile.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BulkEnrollmentJobRecord {
    pub id: Uuid,
    /// Human-facing "Bulk Identifier" returned to the submitter.
    pub bulk_identifier: String,
    pub submitter_id: Uuid,
    pub submitter_username: String,
    /// The single issuance profile applied to every CSR in the batch.
    pub profile_name: String,
    /// `pending` -> `processing` -> `completed`.
    pub status: String,
    pub total_count: i32,
    pub succeeded_count: i32,
    pub failed_count: i32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// One CSR within a bulk enrollment job and its per-CSR outcome.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BulkEnrollmentItemRecord {
    pub id: Uuid,
    pub job_id: Uuid,
    /// 0-based position of the CSR within the uploaded ZIP.
    pub item_index: i32,
    /// Source file name from the ZIP entry.
    pub source_name: String,
    /// Subject CN parsed from the CSR (`None` when the CSR failed to parse).
    pub subject_cn: Option<String>,
    /// Per-CSR outcome: `validated`, `queued`, `issued`, or `failed`.
    pub status: String,
    /// The approval request created for a queued CSR (FDP_CER_EXT.2 linkage).
    pub request_id: Option<Uuid>,
    /// The certificate issued for an auto-issued CSR, when applicable.
    pub certificate_id: Option<Uuid>,
    /// Failure detail for a `failed` CSR; `None` on success.
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}
