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
    Permission, Role, any_role_has_permission,
    user::{AuthenticatedUser, UserId},
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

impl std::fmt::Display for RequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::Issuance => write!(f, "issuance"),
            RequestType::Revocation => write!(f, "revocation"),
            RequestType::Renewal => write!(f, "renewal"),
        }
    }
}

impl std::str::FromStr for RequestType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "issuance" => Ok(RequestType::Issuance),
            "revocation" => Ok(RequestType::Revocation),
            "renewal" => Ok(RequestType::Renewal),
            _ => Err(format!("Invalid request type: {}", s)),
        }
    }
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

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "pending"),
            ApprovalStatus::Approved => write!(f, "approved"),
            ApprovalStatus::Rejected => write!(f, "rejected"),
            ApprovalStatus::Expired => write!(f, "expired"),
            ApprovalStatus::Completed => write!(f, "completed"),
        }
    }
}

impl std::str::FromStr for ApprovalStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ApprovalStatus::Pending),
            "approved" => Ok(ApprovalStatus::Approved),
            "rejected" => Ok(ApprovalStatus::Rejected),
            "expired" => Ok(ApprovalStatus::Expired),
            "completed" => Ok(ApprovalStatus::Completed),
            _ => Err(format!("Invalid approval status: {}", s)),
        }
    }
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

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Approved => write!(f, "approved"),
            Decision::Rejected => write!(f, "rejected"),
            Decision::NeedsInfo => write!(f, "needs_info"),
            Decision::Deferred => write!(f, "deferred"),
        }
    }
}

/// Approval workflow configuration
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// Require approval for certificate issuance
    ///
    /// When true, all certificate issuance requests must go through
    /// the approval workflow (FDP_CER_EXT.3 compliance)
    pub require_approval: bool,

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
            require_approval: true, // Default to NIAP-compliant mode
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
    /// - User must hold the `ApproveRequest` permission
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

        // The approver must hold the ApproveRequest permission. Gating on the
        // permission (not a hardcoded RaStaff/Aor role set) keeps the engine in
        // lockstep with the REST authorization layer and admits every approver
        // role — RaStaff, Aor, and the NPE RegistrationAuthority alike. (Without
        // this, an NPE RA passed the route guard but was rejected here.)
        if !any_role_has_permission(&user.roles, Permission::ApproveRequest) {
            return Err(Error::InsufficientRole {
                required: "approval permission (ApproveRequest)".to_string(),
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

    /// Convert from database record
    ///
    /// Used by REST API to reconstitute approval request from persistence
    pub fn from_record(record: ostrich_db::models::ApprovalRequestRecord) -> Self {
        use std::str::FromStr;

        let status = ApprovalStatus::from_str(&record.status).unwrap_or(ApprovalStatus::Pending);
        let request_type =
            RequestType::from_str(&record.request_type).unwrap_or(RequestType::Issuance);
        let requestor_roles: Vec<Role> = record
            .requestor_roles
            .iter()
            .filter_map(|r| Role::from_str(r).ok())
            .collect();

        Self {
            id: record.id,
            request_type,
            csr_id: record.csr_id,
            certificate_id: record.certificate_id,
            requestor_id: UserId::from_uuid(record.requestor_id),
            requestor_username: record.requestor_username,
            requestor_roles,
            status,
            request_details: record.request_details,
            created_at: record.created_at,
            expires_at: record.expires_at,
            approved_at: record.approved_at,
            completed_at: record.completed_at,
            decisions: Vec::new(), // Decisions loaded separately
            metadata: record.metadata,
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
    ///
    /// # Returns
    /// The approval decision record
    pub fn approve_request(
        &self,
        request: &mut ApprovalRequest,
        approver: &AuthenticatedUser,
        justification: String,
    ) -> Result<ApprovalDecision> {
        // Verify user can approve (FDP_SEPP.1)
        request.can_approve(approver)?;

        // Create decision record
        let decision = ApprovalDecision {
            id: Uuid::new_v4(),
            request_id: request.id,
            approver_id: approver.id,
            approver_username: approver.username.clone(),
            approver_roles: approver.roles.clone(),
            decision: Decision::Approved,
            reason: Some("Approved".to_string()),
            justification: Some(justification),
            decided_at: Utc::now(),
            metadata: None,
        };

        // Add to request's decision history
        request.decisions.push(decision.clone());

        // Update request status
        request.status = ApprovalStatus::Approved;
        request.approved_at = Some(decision.decided_at);

        Ok(decision)
    }

    /// Reject request
    ///
    /// # Arguments
    /// * `request` - Approval request to reject
    /// * `approver` - User rejecting the request
    /// * `reason` - Rejection reason
    /// * `justification` - Detailed justification
    ///
    /// # Returns
    /// The rejection decision record
    pub fn reject_request(
        &self,
        request: &mut ApprovalRequest,
        approver: &AuthenticatedUser,
        reason: String,
        justification: String,
    ) -> Result<ApprovalDecision> {
        // Verify user can approve (same permission for reject)
        request.can_approve(approver)?;

        // Create decision record
        let decision = ApprovalDecision {
            id: Uuid::new_v4(),
            request_id: request.id,
            approver_id: approver.id,
            approver_username: approver.username.clone(),
            approver_roles: approver.roles.clone(),
            decision: Decision::Rejected,
            reason: Some(reason),
            justification: Some(justification),
            decided_at: Utc::now(),
            metadata: None,
        };

        // Add to request's decision history
        request.decisions.push(decision.clone());

        // Update request status
        request.status = ApprovalStatus::Rejected;

        Ok(decision)
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
        let config = ApprovalConfig {
            expiration_duration: Duration::seconds(-1), // Already expired
            ..Default::default()
        };

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
