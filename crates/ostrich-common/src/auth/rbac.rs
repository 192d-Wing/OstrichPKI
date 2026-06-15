//! Role-Based Access Control (RBAC) Policy Engine
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_SMR.2: Security Roles - role-based authorization
//! - FMT_MTD.1: Management of TSF Data - access control enforcement
//! - FDP_ACC.1: Access Control Policy
//! - FDP_ACF.1: Security Attribute Based Access Control
//!
//! ## NIST 800-53 Rev 5
//! - AC-3: Access Enforcement
//! - AC-5: Separation of Duties
//! - AC-6: Least Privilege

use std::sync::Arc;

use thiserror::Error;
use tracing::{info, warn};

use super::permissions::{Permission, any_role_has_permission};
use super::roles::Role;
use super::user::AuthenticatedUser;

/// Authorization error types
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// User lacks required permission
    #[error("Access denied: missing permission '{permission}'")]
    PermissionDenied { permission: Permission },

    /// User lacks required role
    #[error("Access denied: missing required role")]
    RoleDenied { required: Role },

    /// Resource not found or not accessible
    #[error("Resource not found or not accessible: {resource}")]
    ResourceNotFound { resource: String },

    /// Operation not allowed on resource
    #[error("Operation not allowed: {reason}")]
    OperationNotAllowed { reason: String },

    /// Separation of duties violation
    /// NIAP PP-CA: FMT_SMR.2 - Separation of duties
    #[error("Separation of duties violation: {reason}")]
    SeparationOfDutiesViolation { reason: String },

    /// Self-approval not allowed
    /// NIAP PP-CA: FDP_CER_EXT.3 - Requestor cannot approve own request
    #[error("Self-approval not allowed")]
    SelfApprovalProhibited,
}

/// Result type for authorization operations
pub type AuthzResult<T> = Result<T, AuthorizationError>;

/// Authorization decision for audit logging
#[derive(Debug, Clone)]
pub struct AuthorizationDecision {
    /// Whether access was granted
    pub granted: bool,

    /// The user who requested access
    pub user_id: String,

    /// The permission requested
    pub permission: Permission,

    /// The resource being accessed
    pub resource: String,

    /// Reason for denial (if denied)
    pub denial_reason: Option<String>,
}

/// RBAC Policy Engine
///
/// This engine enforces role-based access control policies based on
/// the NIAP PP-CA v2.1 and NIST 800-53 requirements.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_MTD.1 - Management of TSF data
/// - NIAP PP-CA: FDP_ACC.1 - Access control policy
/// - NIST 800-53: AC-3 - Access enforcement
#[derive(Debug, Clone)]
pub struct RbacPolicy {
    /// Whether to log all authorization decisions
    log_all_decisions: bool,

    /// Whether to enforce separation of duties strictly
    strict_separation: bool,
}

impl RbacPolicy {
    /// Create a new RBAC policy with default settings
    pub fn new() -> Self {
        Self {
            log_all_decisions: true,
            strict_separation: true,
        }
    }

    /// Configure logging of all authorization decisions
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_all_decisions = enabled;
        self
    }

    /// Configure strict separation of duties enforcement
    pub fn with_strict_separation(mut self, enabled: bool) -> Self {
        self.strict_separation = enabled;
        self
    }

    /// Check if a user has a specific permission
    ///
    /// # Arguments
    /// * `user` - The authenticated user
    /// * `permission` - The permission to check
    /// * `resource` - The resource being accessed (for audit)
    ///
    /// # Returns
    /// * `Ok(())` - Permission granted
    /// * `Err(AuthorizationError)` - Permission denied
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FMT_MTD.1 - Check permission before TSF data access
    /// - NIST 800-53: AC-3 - Enforce access control
    pub fn authorize(
        &self,
        user: &AuthenticatedUser,
        permission: Permission,
        resource: &str,
    ) -> AuthzResult<()> {
        let granted = any_role_has_permission(&user.roles, permission);

        let decision = AuthorizationDecision {
            granted,
            user_id: user.id.to_string(),
            permission,
            resource: resource.to_string(),
            denial_reason: if granted {
                None
            } else {
                Some(format!(
                    "User lacks permission '{}' (roles: {:?})",
                    permission.name(),
                    user.roles
                ))
            },
        };

        self.log_decision(&decision);

        if granted {
            Ok(())
        } else {
            Err(AuthorizationError::PermissionDenied { permission })
        }
    }

    /// Check if a user has any of the specified permissions
    ///
    /// Useful for operations that can be performed by multiple roles.
    pub fn authorize_any(
        &self,
        user: &AuthenticatedUser,
        permissions: &[Permission],
        resource: &str,
    ) -> AuthzResult<()> {
        for permission in permissions {
            if any_role_has_permission(&user.roles, *permission) {
                let decision = AuthorizationDecision {
                    granted: true,
                    user_id: user.id.to_string(),
                    permission: *permission,
                    resource: resource.to_string(),
                    denial_reason: None,
                };
                self.log_decision(&decision);
                return Ok(());
            }
        }

        // Log denial for the first permission
        if let Some(first_perm) = permissions.first() {
            let decision = AuthorizationDecision {
                granted: false,
                user_id: user.id.to_string(),
                permission: *first_perm,
                resource: resource.to_string(),
                denial_reason: Some(format!(
                    "User lacks any of permissions: {:?}",
                    permissions.iter().map(|p| p.name()).collect::<Vec<_>>()
                )),
            };
            self.log_decision(&decision);

            Err(AuthorizationError::PermissionDenied {
                permission: *first_perm,
            })
        } else {
            Err(AuthorizationError::OperationNotAllowed {
                reason: "No permissions specified".to_string(),
            })
        }
    }

    /// Check if a user has a specific role
    pub fn require_role(&self, user: &AuthenticatedUser, role: Role) -> AuthzResult<()> {
        if user.has_role(role) {
            Ok(())
        } else {
            Err(AuthorizationError::RoleDenied { required: role })
        }
    }

    /// Check if a user has any of the specified roles
    pub fn require_any_role(&self, user: &AuthenticatedUser, roles: &[Role]) -> AuthzResult<()> {
        if user.has_any_role(roles) {
            Ok(())
        } else {
            Err(AuthorizationError::RoleDenied {
                required: *roles.first().unwrap_or(&Role::Administrator),
            })
        }
    }

    /// Verify that a user can approve a request they didn't create
    ///
    /// Implements separation of duties for approval workflow.
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FDP_CER_EXT.3 - Requestor cannot approve own request
    /// - NIST 800-53: AC-5 - Separation of duties
    pub fn verify_can_approve(
        &self,
        approver: &AuthenticatedUser,
        requestor_id: &str,
    ) -> AuthzResult<()> {
        // Check if approver has permission
        self.authorize(approver, Permission::ApproveRequest, "approval_workflow")?;

        // Check separation of duties: requestor cannot approve their own request
        if approver.id.to_string() == requestor_id {
            warn!(
                approver_id = %approver.id,
                "Self-approval attempt blocked"
            );
            return Err(AuthorizationError::SelfApprovalProhibited);
        }

        Ok(())
    }

    /// Verify that a user can reject a request
    pub fn verify_can_reject(
        &self,
        user: &AuthenticatedUser,
        requestor_id: &str,
    ) -> AuthzResult<()> {
        // Rejection follows same rules as approval
        self.authorize(user, Permission::RejectRequest, "approval_workflow")?;

        // Self-rejection is also not allowed (should withdraw instead)
        if user.id.to_string() == requestor_id {
            return Err(AuthorizationError::SelfApprovalProhibited);
        }

        Ok(())
    }

    /// Log an authorization decision
    fn log_decision(&self, decision: &AuthorizationDecision) {
        if !self.log_all_decisions && decision.granted {
            return; // Only log denials
        }

        if decision.granted {
            info!(
                user_id = %decision.user_id,
                permission = %decision.permission.name(),
                resource = %decision.resource,
                "Authorization granted"
            );
        } else {
            warn!(
                user_id = %decision.user_id,
                permission = %decision.permission.name(),
                resource = %decision.resource,
                reason = ?decision.denial_reason,
                "Authorization denied"
            );
        }
    }
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// RBAC middleware for request handling
///
/// Wraps an RBAC policy for use in web frameworks.
#[derive(Clone)]
pub struct RbacMiddleware {
    policy: Arc<RbacPolicy>,
}

impl RbacMiddleware {
    /// Create a new RBAC middleware
    pub fn new(policy: RbacPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// Get a reference to the underlying policy
    pub fn policy(&self) -> &RbacPolicy {
        &self.policy
    }

    /// Authorize a user for a permission
    pub fn authorize(
        &self,
        user: &AuthenticatedUser,
        permission: Permission,
        resource: &str,
    ) -> AuthzResult<()> {
        self.policy.authorize(user, permission, resource)
    }

    /// Authorize for approval workflow
    pub fn verify_can_approve(
        &self,
        approver: &AuthenticatedUser,
        requestor_id: &str,
    ) -> AuthzResult<()> {
        self.policy.verify_can_approve(approver, requestor_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::user::{AuthMethod, UserId};

    fn make_user(roles: Vec<Role>) -> AuthenticatedUser {
        AuthenticatedUser::new(
            UserId::new(),
            "testuser".to_string(),
            roles,
            AuthMethod::Password,
        )
    }

    #[test]
    fn test_authorize_permission_granted() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::OperationsStaff]);

        let result = policy.authorize(&user, Permission::IssueCertificate, "certificate:123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_permission_denied() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::Auditor]);

        let result = policy.authorize(&user, Permission::IssueCertificate, "certificate:123");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AuthorizationError::PermissionDenied { .. })
        ));
    }

    #[test]
    fn test_auditor_can_read_logs() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::Auditor]);

        let result = policy.authorize(&user, Permission::ReadAuditLog, "audit:logs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_admin_cannot_read_audit_logs() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::Administrator]);

        let result = policy.authorize(&user, Permission::ReadAuditLog, "audit:logs");
        assert!(result.is_err());
    }

    #[test]
    fn test_self_approval_prohibited() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::RaStaff]);
        let user_id = user.id.to_string();

        let result = policy.verify_can_approve(&user, &user_id);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AuthorizationError::SelfApprovalProhibited)
        ));
    }

    #[test]
    fn test_approval_by_different_user() {
        let policy = RbacPolicy::new().with_logging(false);
        let approver = make_user(vec![Role::RaStaff]);
        let requestor = make_user(vec![Role::OperationsStaff]);

        let result = policy.verify_can_approve(&approver, &requestor.id.to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_any() {
        let policy = RbacPolicy::new().with_logging(false);
        let user = make_user(vec![Role::OperationsStaff]);

        // User has IssueCertificate but not ModifyConfig
        let result = policy.authorize_any(
            &user,
            &[Permission::ModifyConfig, Permission::IssueCertificate],
            "resource",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_role() {
        let policy = RbacPolicy::new();
        let user = make_user(vec![Role::Administrator]);

        assert!(policy.require_role(&user, Role::Administrator).is_ok());
        assert!(policy.require_role(&user, Role::Auditor).is_err());
    }

    #[test]
    fn test_require_any_role() {
        let policy = RbacPolicy::new();
        let user = make_user(vec![Role::RaStaff]);

        assert!(
            policy
                .require_any_role(&user, &[Role::RaStaff, Role::Aor])
                .is_ok()
        );
        assert!(
            policy
                .require_any_role(&user, &[Role::Administrator, Role::Auditor])
                .is_err()
        );
    }

    // ===== RBAC route-wiring evidence tests =====
    //
    // These tests document and enforce the permission matrix used by the service
    // routers (ostrich-ca, ostrich-scms, ostrich-est, ostrich-ocsp). Each test
    // asserts that a specific (Role, Permission) pair either allows or denies a
    // concrete action, so that a regression in permissions_for_role surfaces
    // here rather than in production.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3 (Access Enforcement), AC-5 (Separation of Duties)
    // - NIAP PP-CA: FMT_MOF.1, FMT_MTD.1

    /// SCMS: token management is IA-5 Authenticator Management.
    /// Administrator creates/modifies/deletes tokens; Auditor only views.
    #[test]
    fn rbac_matrix_scms_tokens() {
        let policy = RbacPolicy::new().with_logging(false);
        let admin = make_user(vec![Role::Administrator]);
        let auditor = make_user(vec![Role::Auditor]);
        let ops = make_user(vec![Role::OperationsStaff]);

        // Administrator: full lifecycle
        assert!(
            policy
                .authorize(&admin, Permission::CreateUser, "scms:tokens")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&admin, Permission::ModifyUser, "scms:token")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&admin, Permission::DeleteUser, "scms:token")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&admin, Permission::UnlockAccount, "scms:token")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&admin, Permission::ViewUsers, "scms:tokens")
                .is_ok()
        );

        // Auditor: read-only
        assert!(
            policy
                .authorize(&auditor, Permission::ViewUsers, "scms:tokens")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::CreateUser, "scms:tokens")
                .is_err()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::ModifyUser, "scms:token")
                .is_err()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::DeleteUser, "scms:token")
                .is_err()
        );

        // OperationsStaff: cannot manage users/tokens
        assert!(
            policy
                .authorize(&ops, Permission::CreateUser, "scms:tokens")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ops, Permission::ModifyUser, "scms:token")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ops, Permission::DeleteUser, "scms:token")
                .is_err()
        );
    }

    /// SCMS: only the Auditor may read token event audit logs.
    /// NIAP PP-CA FAU_SAR.1 - restricted audit review.
    #[test]
    fn rbac_matrix_scms_audit_auditor_only() {
        let policy = RbacPolicy::new().with_logging(false);
        assert!(
            policy
                .authorize(
                    &make_user(vec![Role::Auditor]),
                    Permission::ReadAuditLog,
                    "scms:events"
                )
                .is_ok()
        );
        assert!(
            policy
                .authorize(
                    &make_user(vec![Role::Administrator]),
                    Permission::ReadAuditLog,
                    "scms:events"
                )
                .is_err()
        );
        assert!(
            policy
                .authorize(
                    &make_user(vec![Role::OperationsStaff]),
                    Permission::ReadAuditLog,
                    "scms:events"
                )
                .is_err()
        );
        assert!(
            policy
                .authorize(
                    &make_user(vec![Role::RaStaff]),
                    Permission::ReadAuditLog,
                    "scms:events"
                )
                .is_err()
        );
    }

    /// SCMS: token model catalog config.
    /// Administrator writes, Administrator + Auditor read.
    #[test]
    fn rbac_matrix_scms_models() {
        let policy = RbacPolicy::new().with_logging(false);
        let admin = make_user(vec![Role::Administrator]);
        let auditor = make_user(vec![Role::Auditor]);
        let ops = make_user(vec![Role::OperationsStaff]);

        assert!(
            policy
                .authorize(&admin, Permission::ModifyConfig, "scms:models")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&admin, Permission::ViewConfig, "scms:models")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::ViewConfig, "scms:models")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::ModifyConfig, "scms:models")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ops, Permission::ModifyConfig, "scms:models")
                .is_err()
        );
    }

    /// CA: certificate lifecycle belongs to OperationsStaff.
    /// Admin must NOT be able to issue certs (separation of duties).
    #[test]
    fn rbac_matrix_ca_cert_lifecycle() {
        let policy = RbacPolicy::new().with_logging(false);
        let ops = make_user(vec![Role::OperationsStaff]);
        let admin = make_user(vec![Role::Administrator]);
        let ra = make_user(vec![Role::RaStaff]);

        assert!(
            policy
                .authorize(&ops, Permission::IssueCertificate, "cert")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&ops, Permission::RevokeCertificate, "cert")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&ops, Permission::GenerateCrl, "crl")
                .is_ok()
        );

        assert!(
            policy
                .authorize(&admin, Permission::IssueCertificate, "cert")
                .is_err()
        );
        assert!(
            policy
                .authorize(&admin, Permission::RevokeCertificate, "cert")
                .is_err()
        );

        assert!(
            policy
                .authorize(&ra, Permission::IssueCertificate, "cert")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ra, Permission::ApproveRequest, "approvals")
                .is_ok()
        );
    }

    /// CA approval workflow: RaStaff + Aor approve, OperationsStaff submits.
    #[test]
    fn rbac_matrix_ca_approvals() {
        let policy = RbacPolicy::new().with_logging(false);
        let ra = make_user(vec![Role::RaStaff]);
        let aor = make_user(vec![Role::Aor]);
        let ops = make_user(vec![Role::OperationsStaff]);

        assert!(
            policy
                .authorize(&ra, Permission::ApproveRequest, "approvals")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&ra, Permission::RejectRequest, "approvals")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&aor, Permission::ApproveRequest, "approvals")
                .is_ok()
        );

        assert!(
            policy
                .authorize(&ra, Permission::SubmitRequest, "approvals")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&aor, Permission::SubmitRequest, "approvals")
                .is_ok()
        );

        assert!(
            policy
                .authorize(&ops, Permission::ApproveRequest, "approvals")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ops, Permission::RejectRequest, "approvals")
                .is_err()
        );
    }

    /// CA configuration: /api/v1/profiles was moved from public to
    /// Permission::ViewConfig. Validate that only authorized roles can read it.
    #[test]
    fn rbac_matrix_ca_profiles_gated() {
        let policy = RbacPolicy::new().with_logging(false);
        let admin = make_user(vec![Role::Administrator]);
        let auditor = make_user(vec![Role::Auditor]);
        let ra = make_user(vec![Role::RaStaff]);
        let aor = make_user(vec![Role::Aor]);
        let ops = make_user(vec![Role::OperationsStaff]);

        assert!(
            policy
                .authorize(&admin, Permission::ViewConfig, "profiles")
                .is_ok()
        );
        assert!(
            policy
                .authorize(&auditor, Permission::ViewConfig, "profiles")
                .is_ok()
        );
        // OperationsStaff, RaStaff, Aor do NOT have ViewConfig per the matrix.
        assert!(
            policy
                .authorize(&ops, Permission::ViewConfig, "profiles")
                .is_err()
        );
        assert!(
            policy
                .authorize(&ra, Permission::ViewConfig, "profiles")
                .is_err()
        );
        assert!(
            policy
                .authorize(&aor, Permission::ViewConfig, "profiles")
                .is_err()
        );
    }

    /// Separation of duties: no single role can both modify data AND read
    /// the audit trail. This enforces AC-5 at the policy level.
    #[test]
    fn separation_of_duties_auditor_cannot_modify_and_admin_cannot_audit() {
        let policy = RbacPolicy::new().with_logging(false);

        for role in [
            Role::Administrator,
            Role::OperationsStaff,
            Role::RaStaff,
            Role::Aor,
        ] {
            let user = make_user(vec![role]);
            assert!(
                policy
                    .authorize(&user, Permission::ReadAuditLog, "audit")
                    .is_err(),
                "role {:?} must not be able to read audit logs",
                role
            );
        }

        let auditor = make_user(vec![Role::Auditor]);
        for mutating in [
            Permission::IssueCertificate,
            Permission::RevokeCertificate,
            Permission::ModifyConfig,
            Permission::CreateUser,
            Permission::ModifyUser,
            Permission::DeleteUser,
            Permission::ApproveRequest,
            Permission::GenerateCaKey,
        ] {
            assert!(
                policy.authorize(&auditor, mutating, "any").is_err(),
                "Auditor must not be able to perform {:?}",
                mutating
            );
        }
    }
}
