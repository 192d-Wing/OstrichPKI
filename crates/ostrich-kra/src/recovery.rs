//! Key recovery functionality
//!
//! NIST 800-57: Key recovery procedures with M-of-N threshold

use crate::{Error, Result, ShamirSecretSharing};
use chrono::{DateTime, Utc};
use ostrich_audit::{AuditEventBuilder, AuditSink, EventOutcome, EventType};
use ostrich_crypto::CryptoProvider;
use ostrich_db::DatabasePool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Recovery agent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAgent {
    /// Agent ID
    pub id: Uuid,

    /// Agent name
    pub name: String,

    /// Agent role
    pub role: String,

    /// Contact information
    pub contact: String,

    /// Whether agent is active
    pub active: bool,
}

/// Recovery share submitted by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShare {
    /// Share index (1-indexed)
    pub index: u8,

    /// Share value (encrypted)
    pub value: Vec<u8>,

    /// Agent who submitted this share
    pub agent_id: Uuid,

    /// Timestamp when share was submitted
    pub submitted_at: DateTime<Utc>,
}

/// Key recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Escrow ID to recover
    pub escrow_id: Uuid,

    /// Requestor identity
    pub requestor: String,

    /// Justification for recovery
    pub justification: String,

    /// Approval authority
    pub approved_by: Option<String>,
}

/// Recovery request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Request initiated, waiting for shares
    Pending,

    /// Collecting shares from agents
    CollectingShares,

    /// All required shares collected, key recovered
    Completed,

    /// Recovery request denied
    Denied,

    /// Recovery request cancelled
    Cancelled,
}

/// Recovery session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    /// Session ID
    pub id: Uuid,

    /// Escrow ID being recovered
    pub escrow_id: Uuid,

    /// Request status
    pub status: RecoveryStatus,

    /// Required number of shares
    pub threshold: usize,

    /// Shares collected so far
    pub shares_collected: usize,

    /// Requestor
    pub requestor: String,

    /// Justification
    pub justification: String,

    /// Approved by
    pub approved_by: Option<String>,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
}

/// Key recovery service
pub struct KeyRecovery {
    db: DatabasePool,
    #[allow(dead_code)] // TODO: Use for key unwrapping (Phase 10)
    crypto: Arc<dyn CryptoProvider>,
    audit: Arc<dyn AuditSink>,
}

impl KeyRecovery {
    /// Create new key recovery service
    pub fn new(
        db: DatabasePool,
        crypto: Arc<dyn CryptoProvider>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self { db, crypto, audit }
    }

    /// Initiate a key recovery request
    pub async fn initiate_recovery(&self, request: RecoveryRequest) -> Result<RecoverySession> {
        // Audit the recovery request
        let mut event = AuditEventBuilder::new(
            EventType::KeyRecovery,
            &request.requestor,
            request.escrow_id.to_string(),
            "initiate_recovery",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "escrow_id": request.escrow_id.to_string(),
            "justification": request.justification,
            "approved_by": request.approved_by,
        }))
        .build();

        self.audit.record(&mut event).await.ok();

        // Look up escrow record from database to verify it exists
        let repo = ostrich_db::repository::KraRepository::new(self.db.clone());
        let _escrowed_key = repo
            .find_escrowed_key(request.escrow_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(format!("Escrow ID: {}", request.escrow_id)))?;

        // TODO: Get threshold and num_agents from escrow metadata (Phase 12 - Escrow Metadata)
        // For now, use default M-of-N threshold (3-of-5)
        let threshold = 3;
        let total_agents = 5;

        // Create recovery request in database
        let db_recovery_request = repo
            .create_recovery_request(
                request.escrow_id,
                &request.requestor,
                &request.justification,
                threshold,
                total_agents,
            )
            .await?;

        // Create recovery session
        let session = RecoverySession {
            id: db_recovery_request.id,
            escrow_id: request.escrow_id,
            status: RecoveryStatus::Pending,
            threshold: threshold as usize,
            shares_collected: 0,
            requestor: request.requestor,
            justification: request.justification,
            approved_by: request.approved_by,
            created_at: db_recovery_request.created_at,
            completed_at: None,
        };

        Ok(session)
    }

    /// Submit a recovery share from an agent
    pub async fn submit_share(
        &self,
        session_id: Uuid,
        agent_id: Uuid,
        share: crate::shamir::Share,
    ) -> Result<RecoverySession> {
        // Audit the share submission
        let mut event = AuditEventBuilder::new(
            EventType::KeyRecovery,
            agent_id.to_string(),
            session_id.to_string(),
            "submit_share",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "session_id": session_id.to_string(),
            "agent_id": agent_id.to_string(),
            "share_index": share.index,
        }))
        .build();

        self.audit.record(&mut event).await.ok();

        // Store share in database
        let repo = ostrich_db::repository::KraRepository::new(self.db.clone());

        // First, load the recovery request to get escrow_id and threshold
        let recovery_request = repo
            .find_recovery_request(session_id)
            .await?
            .ok_or_else(|| {
                Error::RecoveryError(format!("Recovery session not found: {}", session_id))
            })?;

        // TODO: Validate agent is authorized for this recovery (Phase 12 - Agent Management)

        // Store the share (note: share.index is not stored separately, just the encrypted share data)
        repo.create_recovery_share(session_id, agent_id, share.value.clone())
            .await?;

        // Count submitted shares
        let shares_collected = repo.count_submitted_shares(session_id).await?;

        // Check if we have enough shares to reconstruct
        let status = if shares_collected >= recovery_request.required_shares as i64 {
            // TODO: Automatically reconstruct key when threshold is met (Phase 10)
            RecoveryStatus::CollectingShares // Keep as collecting for now
        } else {
            RecoveryStatus::CollectingShares
        };

        // Build session response
        let session = RecoverySession {
            id: session_id,
            escrow_id: recovery_request.escrowed_key_id,
            status,
            threshold: recovery_request.required_shares as usize,
            shares_collected: shares_collected as usize,
            requestor: recovery_request.requestor,
            justification: recovery_request.justification,
            approved_by: None, // TODO: Load from request approval table (Phase 12)
            created_at: recovery_request.created_at,
            completed_at: None,
        };

        Ok(session)
    }

    /// Complete recovery and reconstruct the private key
    pub async fn complete_recovery(
        &self,
        session_id: Uuid,
        shares: Vec<crate::shamir::Share>,
        threshold: usize,
    ) -> Result<Vec<u8>> {
        // Verify we have enough shares
        if shares.len() < threshold {
            return Err(Error::InsufficientShares {
                required: threshold,
                provided: shares.len(),
            });
        }

        // Reconstruct the KEK from shares
        let kek = ShamirSecretSharing::reconstruct(&shares, threshold)?;

        // TODO: Use KEK to unwrap the escrowed private key
        // For now, return placeholder

        // Audit successful recovery
        let mut event = AuditEventBuilder::new(
            EventType::KeyRecovery,
            "system",
            session_id.to_string(),
            "complete_recovery",
            EventOutcome::Success,
        )
        .with_details(serde_json::json!({
            "session_id": session_id.to_string(),
            "shares_used": shares.len(),
        }))
        .build();

        self.audit.record(&mut event).await.ok();

        Ok(kek)
    }

    /// List recovery agents
    pub async fn list_agents(&self) -> Result<Vec<RecoveryAgent>> {
        let repo = ostrich_db::repository::KraRepository::new(self.db.clone());
        let db_agents = repo.list_active_recovery_agents().await?;

        // Map database agents to RecoveryAgent struct
        let agents = db_agents
            .into_iter()
            .map(|agent| RecoveryAgent {
                id: agent.id,
                name: agent.name,
                role: "Recovery Agent".to_string(), // TODO: Add role field to database model (Phase 12)
                contact: agent.email,
                active: agent.active,
            })
            .collect();

        Ok(agents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_request_construction() {
        let request = RecoveryRequest {
            escrow_id: Uuid::new_v4(),
            requestor: "admin".to_string(),
            justification: "Emergency key recovery".to_string(),
            approved_by: Some("manager".to_string()),
        };

        assert_eq!(request.requestor, "admin");
        assert_eq!(request.justification, "Emergency key recovery");
        assert!(request.approved_by.is_some());
    }

    #[test]
    fn test_recovery_status_equality() {
        assert_eq!(RecoveryStatus::Pending, RecoveryStatus::Pending);
        assert_ne!(RecoveryStatus::Pending, RecoveryStatus::Completed);
        assert_ne!(RecoveryStatus::CollectingShares, RecoveryStatus::Denied);
    }

    #[test]
    fn test_recovery_session_construction() {
        let session = RecoverySession {
            id: Uuid::new_v4(),
            escrow_id: Uuid::new_v4(),
            status: RecoveryStatus::Pending,
            threshold: 3,
            shares_collected: 0,
            requestor: "admin".to_string(),
            justification: "Test recovery".to_string(),
            approved_by: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        assert_eq!(session.threshold, 3);
        assert_eq!(session.shares_collected, 0);
        assert_eq!(session.status, RecoveryStatus::Pending);
        assert!(session.completed_at.is_none());
    }

    #[test]
    fn test_recovery_agent_construction() {
        let agent = RecoveryAgent {
            id: Uuid::new_v4(),
            name: "Test Agent".to_string(),
            role: "Security Officer".to_string(),
            contact: "agent@example.com".to_string(),
            active: true,
        };

        assert!(agent.active);
        assert_eq!(agent.role, "Security Officer");
    }

    #[test]
    fn test_recovery_share_construction() {
        let share = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3, 4, 5],
            agent_id: Uuid::new_v4(),
            submitted_at: chrono::Utc::now(),
        };

        assert_eq!(share.index, 1);
        assert_eq!(share.value.len(), 5);
    }
}
