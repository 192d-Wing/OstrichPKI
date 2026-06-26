//! Approval workflow repository
//!
//! Provides database operations for certificate approval workflow.
//!
//! # COMPLIANCE MAPPING
//! - NIAP PP-CA: FDP_CER_EXT.2 - Maintains CSR → Request → Certificate linkage
//! - NIAP PP-CA: FDP_CER_EXT.3 - Persists approval workflow state
//! - NIAP PP-CA: FAU_GEN.1 - All operations generate audit events
//! - NIST 800-53: AU-2 - Auditable event generation

use crate::{
    Error, Result,
    models::{ApprovalDecisionRecord, ApprovalRequestRecord},
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Approval workflow repository
pub struct ApprovalRepository {
    pool: PgPool,
}

impl ApprovalRepository {
    /// Create new approval repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create approval request
    ///
    /// # COMPLIANCE
    /// - FDP_CER_EXT.3: Creates new approval request record
    pub async fn create_request(
        &self,
        request: &ApprovalRequestRecord,
    ) -> Result<ApprovalRequestRecord> {
        let record = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            INSERT INTO approval_requests (
                id, request_type, csr_id, certificate_id,
                requestor_id, requestor_username, requestor_roles,
                status, request_details, created_at, expires_at,
                approved_at, completed_at, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            "#,
        )
        .bind(request.id)
        .bind(&request.request_type)
        .bind(request.csr_id)
        .bind(request.certificate_id)
        .bind(request.requestor_id)
        .bind(&request.requestor_username)
        .bind(&request.requestor_roles)
        .bind(&request.status)
        .bind(&request.request_details)
        .bind(request.created_at)
        .bind(request.expires_at)
        .bind(request.approved_at)
        .bind(request.completed_at)
        .bind(&request.metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to create approval request: {}", e)))?;

        Ok(record)
    }

    /// Get approval request by ID
    pub async fn get_request(&self, id: &Uuid) -> Result<Option<ApprovalRequestRecord>> {
        let record = sqlx::query_as::<_, ApprovalRequestRecord>(
            "SELECT * FROM approval_requests WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to get approval request: {}", e)))?;

        Ok(record)
    }

    /// List pending approval requests
    ///
    /// Returns all requests with status='pending' ordered by creation date
    pub async fn list_pending_requests(&self) -> Result<Vec<ApprovalRequestRecord>> {
        let records = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            SELECT * FROM approval_requests
            WHERE status = 'pending'
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to list pending requests: {}", e)))?;

        Ok(records)
    }

    /// List approval requests by requestor
    pub async fn list_requests_by_requestor(
        &self,
        requestor_id: &Uuid,
    ) -> Result<Vec<ApprovalRequestRecord>> {
        let records = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            SELECT * FROM approval_requests
            WHERE requestor_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(requestor_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to list requests by requestor: {}", e)))?;

        Ok(records)
    }

    /// Fetch multiple approval requests by id, in one query, for a bulk-status
    /// lookup. Unknown ids are simply absent from the result. The caller is
    /// responsible for any own-scope filtering (a regular requester must only
    /// see their own requests).
    pub async fn list_requests_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<ApprovalRequestRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let records = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            SELECT * FROM approval_requests
            WHERE id = ANY($1)
            ORDER BY created_at DESC
            "#,
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to list requests by ids: {}", e)))?;

        Ok(records)
    }

    /// Update approval request status
    pub async fn update_request_status(
        &self,
        id: &Uuid,
        status: &str,
        approved_at: Option<DateTime<Utc>>,
    ) -> Result<ApprovalRequestRecord> {
        let record = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            UPDATE approval_requests
            SET status = $2, approved_at = $3
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(approved_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to update request status: {}", e)))?;

        Ok(record)
    }

    /// Mark request as completed
    ///
    /// # COMPLIANCE
    /// - FDP_CER_EXT.2: Links certificate_id to approval request
    pub async fn mark_request_completed(
        &self,
        id: &Uuid,
        certificate_id: Uuid,
    ) -> Result<ApprovalRequestRecord> {
        let now = Utc::now();
        let record = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            UPDATE approval_requests
            SET status = 'completed',
                certificate_id = $2,
                completed_at = $3
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(certificate_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to mark request completed: {}", e)))?;

        Ok(record)
    }

    /// Link CSR to approval request
    ///
    /// # COMPLIANCE
    /// - FDP_CER_EXT.2: Establishes CSR → Request linkage
    pub async fn link_csr(&self, id: &Uuid, csr_id: Uuid) -> Result<ApprovalRequestRecord> {
        let record = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            UPDATE approval_requests
            SET csr_id = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(csr_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to link CSR: {}", e)))?;

        Ok(record)
    }

    /// Expire old pending requests
    ///
    /// Updates status to 'expired' for pending requests past their expiration time
    pub async fn expire_old_requests(&self) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE approval_requests
            SET status = 'expired'
            WHERE status = 'pending' AND expires_at < $1
            "#,
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to expire old requests: {}", e)))?;

        Ok(result.rows_affected())
    }

    /// Create approval decision
    ///
    /// # COMPLIANCE
    /// - FAU_GEN.1: Decision record for audit trail
    pub async fn create_decision(
        &self,
        decision: &ApprovalDecisionRecord,
    ) -> Result<ApprovalDecisionRecord> {
        let record = sqlx::query_as::<_, ApprovalDecisionRecord>(
            r#"
            INSERT INTO approval_decisions (
                id, request_id, approver_id, approver_username,
                approver_roles, decision, reason, justification,
                decided_at, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(decision.id)
        .bind(decision.request_id)
        .bind(decision.approver_id)
        .bind(&decision.approver_username)
        .bind(&decision.approver_roles)
        .bind(&decision.decision)
        .bind(&decision.reason)
        .bind(&decision.justification)
        .bind(decision.decided_at)
        .bind(&decision.metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to create approval decision: {}", e)))?;

        Ok(record)
    }

    /// Get approval decisions for a request
    pub async fn get_decisions_for_request(
        &self,
        request_id: &Uuid,
    ) -> Result<Vec<ApprovalDecisionRecord>> {
        let records = sqlx::query_as::<_, ApprovalDecisionRecord>(
            r#"
            SELECT * FROM approval_decisions
            WHERE request_id = $1
            ORDER BY decided_at ASC
            "#,
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to get decisions: {}", e)))?;

        Ok(records)
    }

    /// Get request with decisions (full approval history)
    ///
    /// Returns request and all associated decisions for complete audit trail
    pub async fn get_request_with_decisions(
        &self,
        request_id: &Uuid,
    ) -> Result<Option<(ApprovalRequestRecord, Vec<ApprovalDecisionRecord>)>> {
        let request = self.get_request(request_id).await?;

        if let Some(req) = request {
            let decisions = self.get_decisions_for_request(request_id).await?;
            Ok(Some((req, decisions)))
        } else {
            Ok(None)
        }
    }

    /// Get requests by certificate ID
    ///
    /// # COMPLIANCE
    /// - FDP_CER_EXT.2: Lookup requests by issued certificate
    pub async fn get_requests_by_certificate(
        &self,
        certificate_id: &Uuid,
    ) -> Result<Vec<ApprovalRequestRecord>> {
        let records = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            SELECT * FROM approval_requests
            WHERE certificate_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(certificate_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to get requests by certificate: {}", e)))?;

        Ok(records)
    }

    /// Get requests by CSR ID
    ///
    /// # COMPLIANCE
    /// - FDP_CER_EXT.2: Lookup requests by CSR
    pub async fn get_requests_by_csr(&self, csr_id: &Uuid) -> Result<Vec<ApprovalRequestRecord>> {
        let records = sqlx::query_as::<_, ApprovalRequestRecord>(
            r#"
            SELECT * FROM approval_requests
            WHERE csr_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(csr_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Query(format!("Failed to get requests by CSR: {}", e)))?;

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Integration tests with actual database would go in tests/ directory
    // These are placeholder unit tests for structure validation

    #[test]
    fn test_approval_repository_construction() {
        // Verify we can construct the type (requires actual PgPool for real test)
        // This is just a compile-time check
        assert_eq!(
            std::mem::size_of::<ApprovalRepository>(),
            std::mem::size_of::<PgPool>()
        );
    }
}
