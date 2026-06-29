//! Bulk certificate enrollment repository
//!
//! Database operations for the Administrator "Submit Bulk" workflow: one job per
//! upload, one item per CSR.
//!
//! # COMPLIANCE MAPPING
//! - NIST 800-53: AU-2 (auditable bulk operation), AC-3/AC-6 (submitter-owned),
//!   SI-10 (validated inputs persisted), SC-28 (at rest)
//! - NIAP PP-CA: FDP_CER_EXT.2 (CSR -> request linkage), FAU_GEN.1

use crate::{
    Error, Result,
    models::{BulkEnrollmentItemRecord, BulkEnrollmentJobRecord},
};
use sqlx::PgPool;
use uuid::Uuid;

/// Repository for bulk enrollment jobs and their per-CSR items.
pub struct BulkEnrollmentRepository {
    pool: PgPool,
}

impl BulkEnrollmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new bulk job row (status defaults applied by the caller).
    pub async fn create_job(
        &self,
        job: &BulkEnrollmentJobRecord,
    ) -> Result<BulkEnrollmentJobRecord> {
        sqlx::query_as::<_, BulkEnrollmentJobRecord>(
            r#"
            INSERT INTO bulk_enrollment_jobs (
                id, bulk_identifier, submitter_id, submitter_username,
                profile_name, status, total_count, succeeded_count,
                failed_count, created_at, completed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(job.id)
        .bind(&job.bulk_identifier)
        .bind(job.submitter_id)
        .bind(&job.submitter_username)
        .bind(&job.profile_name)
        .bind(&job.status)
        .bind(job.total_count)
        .bind(job.succeeded_count)
        .bind(job.failed_count)
        .bind(job.created_at)
        .bind(job.completed_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to create bulk job: {}", e)))
    }

    /// Append one CSR item to a job.
    pub async fn create_item(
        &self,
        item: &BulkEnrollmentItemRecord,
    ) -> Result<BulkEnrollmentItemRecord> {
        sqlx::query_as::<_, BulkEnrollmentItemRecord>(
            r#"
            INSERT INTO bulk_enrollment_items (
                id, job_id, item_index, source_name, subject_cn,
                status, request_id, certificate_id, error, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(item.id)
        .bind(item.job_id)
        .bind(item.item_index)
        .bind(&item.source_name)
        .bind(&item.subject_cn)
        .bind(&item.status)
        .bind(item.request_id)
        .bind(item.certificate_id)
        .bind(&item.error)
        .bind(item.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to create bulk item: {}", e)))
    }

    /// Mark a job terminal with its final counts.
    pub async fn finalize_job(
        &self,
        job_id: Uuid,
        status: &str,
        succeeded: i32,
        failed: i32,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE bulk_enrollment_jobs
            SET status = $2, succeeded_count = $3, failed_count = $4,
                completed_at = now()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(status)
        .bind(succeeded)
        .bind(failed)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to finalize bulk job: {}", e)))?;
        Ok(())
    }

    /// Fetch a job by id.
    pub async fn get_job(&self, job_id: Uuid) -> Result<Option<BulkEnrollmentJobRecord>> {
        sqlx::query_as::<_, BulkEnrollmentJobRecord>(
            "SELECT * FROM bulk_enrollment_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to load bulk job: {}", e)))
    }

    /// List a job's items in upload order.
    pub async fn list_items(&self, job_id: Uuid) -> Result<Vec<BulkEnrollmentItemRecord>> {
        sqlx::query_as::<_, BulkEnrollmentItemRecord>(
            "SELECT * FROM bulk_enrollment_items WHERE job_id = $1 ORDER BY item_index ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to list bulk items: {}", e)))
    }

    /// List jobs submitted by a given user, most recent first.
    pub async fn list_jobs_by_submitter(
        &self,
        submitter_id: Uuid,
    ) -> Result<Vec<BulkEnrollmentJobRecord>> {
        sqlx::query_as::<_, BulkEnrollmentJobRecord>(
            r#"
            SELECT * FROM bulk_enrollment_jobs
            WHERE submitter_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(submitter_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to list bulk jobs: {}", e)))
    }
}
