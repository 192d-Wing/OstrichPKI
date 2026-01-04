//! Certificate Request Approval Workflow
//!
//! Implements NIAP PP-CA v2.1 certificate request approval requirements with
//! mandatory segregation of duties enforcement.
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FDP_CER_EXT.2: Certificate Request Linkage - Maintains chain from CSR → Request → Certificate
//! - FDP_CER_EXT.3: Certificate Request Approval - Implements approval workflow before issuance
//! - FDP_SEPP.1: Segregation of Duties - Enforces requestor ≠ approver
//! - FAU_GEN.1: Audit Events - Logs all approval decisions with actor identity
//!
//! ## NIST 800-53 Rev 5
//! - AC-5: Separation of Duties - Prevents self-approval
//! - AU-2: Auditable Events - All workflow state changes logged
//! - AC-3: Access Enforcement - Role-based approval authorization
//!
//! # State Machine
//!
//! ```text
//!                    ┌──────────────┐
//!                    │   Pending    │◄─── Initial state
//!                    └──────┬───────┘
//!                           │
//!              ┌────────────┼────────────┐
//!              ▼            ▼            ▼
//!        ┌─────────┐  ┌──────────┐  ┌─────────┐
//!        │Approved │  │ Rejected │  │ Expired │
//!        └────┬────┘  └──────────┘  └─────────┘
//!             │
//!             ▼
//!       ┌───────────┐
//!       │ Completed │◄─── Certificate Issued
//!       └───────────┘
//! ```

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, Result};
use ostrich_common::auth::{
    user::{AuthenticatedUser, UserId},
    Role,
};

/// Approval request for certificate operations
///
/// # COMPLIANCE MAPPING
/// - FDP_CER_EXT.2: Links CSR to approval request to issued certificate
/// - FDP_SEPP.1: Stores requestor_id for segregation check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier
    pub id: Uuid,

    /// Type of certificate operation
    pub request_type: RequestType,

    /// CSR identifier (for issuance/renewal requests)
    pub csr_id: Option<Uuid>,

    /// Certificate identifier (for revocation requests)
    pub certificate_id: Option<Uuid>,

    /// User who submitted the request
    pub requestor_id: UserId,
    pub requestor_username: String,
    pub requestor_roles: Vec<Role>,

    /// Current approval status
    pub status: ApprovalStatus,

    /// Request-specific details (JSON-serialized)
    pub request_details: serde_json::Value,

    /// Timestamps
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,

    /// Approval decisions made on this request
    pub decisions: Vec<ApprovalDecision>,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Type of certificate operation requiring approval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestType {
    /// Certificate issuance request
    Issuance,
    /// Certificate revocation request
    Revocation,
    /// Certificate renewal request
    Renewal,
}

/// Approval workflow status
///
/// # State Transitions
/// - Pending → Approved (via approval decision)
/// - Pending → Rejected (via rejection decision)
/// - Pending → Expired (via time expiration)
/// - Approved → Completed (via certificate issuance)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    /// Awaiting approval decision
    Pending,
    /// Approved by authorized personnel
    Approved,
    /// Rejected by authorized personnel
    Rejected,
    /// Expired before decision
    Expired,
    /// Completed (certificate issued/revoked)
    Completed,
}

/// Individual approval decision
///
/// # COMPLIANCE MAPPING
/// - FDP_SEPP.1: Stores approver_id for segregation verification
/// - FAU_GEN.1: All fields used for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Decision identifier
    pub id: Uuid,

    /// Request being decided
    pub request_id: Uuid,

    /// User who made the decision
    pub approver_id: UserId,
    pub approver_username: String,
    pub approver_roles: Vec<Role>,

    /// Decision outcome
    pub decision: Decision,

    /// Optional reason for decision
    pub reason: Option<String>,

    /// Detailed justification (required for audit)
    pub justification: Option<String>,

    /// Timestamp of decision
    pub decided_at: DateTime<Utc>,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Approval decision outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Request approved
    Approved,
    /// Request rejected
    Rejected,
    /// Additional information needed
    NeedsInfo,
    /// Decision deferred
    Deferred,
}

/// Approval workflow configuration
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// Request expiration duration (default: 7 days)
    pub expiration_duration: Duration,

    /// Require multi-person approval (not currently implemented)
    pub require_multi_approval: bool,

    /// Number of approvals required (if multi-approval enabled)
    pub required_approvals: usize,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            expiration_duration: Duration::days(7),
            require_multi_approval: false,
            required_approvals: 1,
        }
    }
}

impl ApprovalRequest {
    /// Create new approval request
    ///
    /// # Arguments
    /// * `request_type` - Type of certificate operation
    /// * `requestor` - User submitting the request
    /// * `request_details` - Operation-specific details
    /// * `config` - Approval configuration
    ///
    /// # Returns
    /// New approval request in Pending state
    pub fn new(
        request_type: RequestType,
        requestor: &AuthenticatedUser,
        request_details: serde_json::Value,
        config: &ApprovalConfig,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + config.expiration_duration;

        Self {
            id: Uuid::new_v4(),
            request_type,
            csr_id: None,
            certificate_id: None,
            requestor_id: requestor.id,
            requestor_username: requestor.username.clone(),
            requestor_roles: requestor.roles.clone(),
            status: ApprovalStatus::Pending,
            request_details,
            created_at: now,
            expires_at,
            approved_at: None,
            completed_at: None,
            decisions: Vec::new(),
            metadata: None,
        }
    }

    /// Link CSR to approval request (FDP_CER_EXT.2)
    pub fn link_csr(&mut self, csr_id: Uuid) {
        self.csr_id = Some(csr_id);
    }

    /// Link certificate to approval request (FDP_CER_EXT.2)
    pub fn link_certificate(&mut self, certificate_id: Uuid) {
        self.certificate_id = Some(certificate_id);
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if user can approve this request (FDP_SEPP.1)
    ///
    /// # Segregation of Duties
    /// - Requestor CANNOT approve their own request
    /// - User must have RaStaff or Aor role
    ///
    /// # Arguments
    /// * `user` - User attempting to approve
    ///
    /// # Returns
    /// - `Ok(())` if user can approve
    /// - `Err(Error::SelfApprovalProhibited)` if user is requestor
    /// - `Err(Error::InsufficientRole)` if user lacks approval role
    pub fn can_approve(&self, user: &AuthenticatedUser) -> Result<()> {
        // FDP_SEPP.1: Requestor cannot approve their own request
        if self.requestor_id == user.id {
            return Err(Error::SelfApprovalProhibited);
        }

        // Check user has RA Staff or AOR role
        if !user.has_any_role(&[Role::RaStaff, Role::Aor]) {
            return Err(Error::InsufficientRole {
                required: "RaStaff or Aor".to_string(),
            });
        }

        // Check request is in pending state
        if self.status != ApprovalStatus::Pending {
            return Err(Error::InvalidApprovalState {
                current: format!("{:?}", self.status),
                expected: "Pending".to_string(),
            });
        }

        // Check request hasn't expired
        if self.is_expired() {
            return Err(Error::ApprovalRequestExpired {
                expired_at: self.expires_at,
            });
        }

        Ok(())
    }

    /// Add approval decision
    ///
    /// # COMPLIANCE MAPPING
    /// - FDP_SEPP.1: Enforces segregation before adding decision
    /// - FAU_GEN.1: Decision logged via audit events
    ///
    /// # Arguments
    /// * `approver` - User making the decision
    /// * `decision` - Approval decision
    /// * `reason` - Optional reason
    /// * `justification` - Detailed justification
    pub fn add_decision(
        &mut self,
        approver: &AuthenticatedUser,
        decision: Decision,
        reason: Option<String>,
        justification: Option<String>,
    ) -> Result<()> {
        // Verify user can approve (FDP_SEPP.1)
        self.can_approve(approver)?;

        // Create decision record
        let decision_record = ApprovalDecision {
            id: Uuid::new_v4(),
            request_id: self.id,
            approver_id: approver.id,
            approver_username: approver.username.clone(),
            approver_roles: approver.roles.clone(),
            decision,
            reason,
            justification,
            decided_at: Utc::now(),
            metadata: None,
        };

        self.decisions.push(decision_record);

        // Update request status based on decision
        match decision {
            Decision::Approved => {
                self.status = ApprovalStatus::Approved;
                self.approved_at = Some(Utc::now());
            }
            Decision::Rejected => {
                self.status = ApprovalStatus::Rejected;
            }
            Decision::NeedsInfo | Decision::Deferred => {
                // Status remains Pending
            }
        }

        Ok(())
    }

    /// Mark request as completed (certificate issued/revoked)
    ///
    /// # Arguments
    /// * `certificate_id` - ID of issued/revoked certificate
    pub fn mark_completed(&mut self, certificate_id: Uuid) -> Result<()> {
        if self.status != ApprovalStatus::Approved {
            return Err(Error::InvalidApprovalState {
                current: format!("{:?}", self.status),
                expected: "Approved".to_string(),
            });
        }

        self.certificate_id = Some(certificate_id);
        self.status = ApprovalStatus::Completed;
        self.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Expire request if past expiration time
    pub fn expire_if_needed(&mut self) {
        if self.status == ApprovalStatus::Pending && self.is_expired() {
            self.status = ApprovalStatus::Expired;
        }
    }
}

/// Approval workflow engine
///
/// Manages certificate request approval lifecycle with segregation of duties.
pub struct ApprovalEngine {
    config: ApprovalConfig,
    // Future: Add repository for persistence
}

impl ApprovalEngine {
    /// Create new approval engine
    pub fn new(config: ApprovalConfig) -> Self {
        Self { config }
    }

    /// Create new approval request
    ///
    /// # Arguments
    /// * `request_type` - Type of certificate operation
    /// * `requestor` - User submitting the request
    /// * `request_details` - Operation-specific details
    ///
    /// # Returns
    /// New approval request in Pending state
    pub fn create_request(
        &self,
        request_type: RequestType,
        requestor: &AuthenticatedUser,
        request_details: serde_json::Value,
    ) -> ApprovalRequest {
        ApprovalRequest::new(request_type, requestor, request_details, &self.config)
    }

    /// Approve request
    ///
    /// # COMPLIANCE MAPPING
    /// - FDP_SEPP.1: Enforces requestor ≠ approver
    /// - FAU_GEN.1: Approval logged (handled by caller)
    ///
    /// # Arguments
    /// * `request` - Approval request to approve
    /// * `approver` - User approving the request
    /// * `justification` - Approval justification
    pub fn approve_request(
        &self,
        request: &mut ApprovalRequest,
        approver: &AuthenticatedUser,
        justification: String,
    ) -> Result<()> {
        request.add_decision(
            approver,
            Decision::Approved,
            Some("Approved".to_string()),
            Some(justification),
        )
    }

    /// Reject request
    ///
    /// # Arguments
    /// * `request` - Approval request to reject
    /// * `approver` - User rejecting the request
    /// * `reason` - Rejection reason
    /// * `justification` - Detailed justification
    pub fn reject_request(
        &self,
        request: &mut ApprovalRequest,
        approver: &AuthenticatedUser,
        reason: String,
        justification: String,
    ) -> Result<()> {
        request.add_decision(
            approver,
            Decision::Rejected,
            Some(reason),
            Some(justification),
        )
    }

    /// Complete request after certificate operation
    ///
    /// # Arguments
    /// * `request` - Approved request to complete
    /// * `certificate_id` - ID of issued/revoked certificate
    pub fn complete_request(
        &self,
        request: &mut ApprovalRequest,
        certificate_id: Uuid,
    ) -> Result<()> {
        request.mark_completed(certificate_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrich_common::auth::user::AuthMethod;

    fn create_test_user(username: &str, roles: Vec<Role>) -> AuthenticatedUser {
        AuthenticatedUser::new(
            UserId::new(),
            username.to_string(),
            roles,
            AuthMethod::Password,
        )
    }

    #[test]
    fn test_create_approval_request() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let config = ApprovalConfig::default();

        let request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({"subject": "CN=example.com"}),
            &config,
        );

        assert_eq!(request.request_type, RequestType::Issuance);
        assert_eq!(request.requestor_username, "alice");
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert!(request.decisions.is_empty());
    }

    #[test]
    fn test_self_approval_prohibited() {
        let requestor = create_test_user("alice", vec![Role::RaStaff]);
        let config = ApprovalConfig::default();

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        // Attempt self-approval (should fail)
        let result = request.add_decision(
            &requestor,
            Decision::Approved,
            None,
            Some("Self-approval attempt".to_string()),
        );

        assert!(matches!(result, Err(Error::SelfApprovalProhibited)));
        assert_eq!(request.status, ApprovalStatus::Pending);
    }

    #[test]
    fn test_successful_approval() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let approver = create_test_user("bob", vec![Role::RaStaff]);
        let config = ApprovalConfig::default();

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        // Approve by different user
        let result = request.add_decision(
            &approver,
            Decision::Approved,
            Some("Looks good".to_string()),
            Some("Certificate request validated".to_string()),
        );

        assert!(result.is_ok());
        assert_eq!(request.status, ApprovalStatus::Approved);
        assert!(request.approved_at.is_some());
        assert_eq!(request.decisions.len(), 1);
        assert_eq!(request.decisions[0].approver_username, "bob");
    }

    #[test]
    fn test_insufficient_role_for_approval() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let approver = create_test_user("bob", vec![Role::Auditor]); // Wrong role
        let config = ApprovalConfig::default();

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        let result = request.add_decision(
            &approver,
            Decision::Approved,
            None,
            Some("Attempt".to_string()),
        );

        assert!(matches!(result, Err(Error::InsufficientRole { .. })));
    }

    #[test]
    fn test_request_expiration() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let mut config = ApprovalConfig::default();
        config.expiration_duration = Duration::seconds(-1); // Already expired

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        assert!(request.is_expired());
        request.expire_if_needed();
        assert_eq!(request.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_complete_approved_request() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let approver = create_test_user("bob", vec![Role::RaStaff]);
        let config = ApprovalConfig::default();

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        // Approve
        request
            .add_decision(&approver, Decision::Approved, None, Some("OK".to_string()))
            .unwrap();

        // Complete
        let cert_id = Uuid::new_v4();
        let result = request.mark_completed(cert_id);

        assert!(result.is_ok());
        assert_eq!(request.status, ApprovalStatus::Completed);
        assert_eq!(request.certificate_id, Some(cert_id));
        assert!(request.completed_at.is_some());
    }

    #[test]
    fn test_csr_certificate_linkage() {
        let requestor = create_test_user("alice", vec![Role::OperationsStaff]);
        let config = ApprovalConfig::default();

        let mut request = ApprovalRequest::new(
            RequestType::Issuance,
            &requestor,
            serde_json::json!({}),
            &config,
        );

        let csr_id = Uuid::new_v4();
        let cert_id = Uuid::new_v4();

        // Link CSR
        request.link_csr(csr_id);
        assert_eq!(request.csr_id, Some(csr_id));

        // Link certificate
        request.link_certificate(cert_id);
        assert_eq!(request.certificate_id, Some(cert_id));
    }
}
