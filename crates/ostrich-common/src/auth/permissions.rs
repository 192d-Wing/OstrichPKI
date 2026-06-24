//! Permission Definitions for RBAC
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_MTD.1: Management of TSF Data - permission-based access control
//! - FMT_SMF.1: Security Management Functions - function authorization
//! - FDP_ACC.1: Access Control Policy - permission enforcement
//!
//! ## NIST 800-53 Rev 5
//! - AC-3: Access Enforcement
//! - AC-6: Least Privilege

use serde::{Deserialize, Serialize};

use super::roles::Role;

/// Permissions for CA operations
///
/// Each permission represents a specific action that can be performed
/// within the PKI system. Permissions are assigned to roles.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_MTD.1 - TSF data management
/// - NIST 800-53: AC-3 - Access enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // ===== Certificate Operations =====
    /// Issue new certificates
    /// NIAP PP-CA: FDP_CER_EXT.1 - Certificate generation
    IssueCertificate,

    /// Revoke existing certificates
    /// NIAP PP-CA: FDP_CER_EXT.4 - Certificate revocation
    RevokeCertificate,

    /// Renew certificates (re-issue with same key or new key)
    RenewCertificate,

    /// View certificate details
    ViewCertificate,

    // ===== CRL Operations =====
    /// Generate CRLs
    /// NIAP PP-CA: FDP_CRL_EXT.1 - CRL generation
    GenerateCrl,

    /// Publish CRLs to distribution points
    PublishCrl,

    /// View CRL details
    ViewCrl,

    // ===== Approval Workflow =====
    /// Submit certificate requests for approval
    SubmitRequest,

    /// Approve certificate requests
    /// NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval
    ApproveRequest,

    /// Reject certificate requests
    RejectRequest,

    /// View pending requests
    ViewRequests,

    // ===== EST Enrollment =====
    /// Generate time-limited bearer tokens for EST initial enrollment.
    /// Distinct from SubmitRequest: lets an operator MINT an enrollment
    /// credential without themselves being able to enroll a certificate.
    /// NIAP PP-CA: FMT_SMF.1 - management of enrollment credentials
    GenerateEstToken,

    // ===== Audit Operations =====
    /// Read audit logs
    /// NIAP PP-CA: FAU_SAR.1 - Audit review
    ReadAuditLog,

    /// Export audit logs
    /// NIAP PP-CA: FAU_SAR.2 - Restricted audit review
    ExportAuditLog,

    /// Search audit logs
    SearchAuditLog,

    // ===== Configuration Operations =====
    /// Modify system configuration
    /// NIAP PP-CA: FMT_SMF.1 - Security management functions
    ModifyConfig,

    /// View system configuration
    ViewConfig,

    // ===== User Management =====
    /// Create user accounts
    /// NIST 800-53: AC-2 - Account management
    CreateUser,

    /// Modify user accounts
    ModifyUser,

    /// Delete/disable user accounts
    DeleteUser,

    /// Assign roles to users
    /// NIAP PP-CA: FMT_SMR.2 - Role assignment
    AssignRoles,

    /// View user accounts
    ViewUsers,

    /// Unlock locked accounts
    /// NIAP PP-CA: FIA_AFL.1 - Authentication failure handling
    UnlockAccount,

    // ===== Trust Anchor Management =====
    /// Import trust anchors (root CAs)
    /// NIAP PP-CA: FMT_MTD.1 - TSF data management
    ImportTrustAnchor,

    /// Remove trust anchors
    RemoveTrustAnchor,

    /// View trust anchors
    ViewTrustAnchors,

    // ===== Key Management =====
    /// Generate CA keys
    /// NIAP PP-CA: FCS_CKM.1 - Key generation
    GenerateCaKey,

    /// Backup CA keys (via KRA)
    /// NIAP PP-CA: FCS_CKM.2 - Key distribution
    BackupCaKey,

    /// Recover escrowed keys
    /// NIAP PP-CA: FCS_CKM.2 - Key recovery
    RecoverKey,

    // ===== OCSP Operations =====
    /// Manage OCSP responder configuration
    ManageOcsp,

    /// View OCSP status
    ViewOcspStatus,

    // ===== Service Operations =====
    /// View service health and status
    ViewServiceHealth,

    /// Restart services
    RestartService,
}

impl Permission {
    /// Get the permission name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Permission::IssueCertificate => "issue_certificate",
            Permission::RevokeCertificate => "revoke_certificate",
            Permission::RenewCertificate => "renew_certificate",
            Permission::ViewCertificate => "view_certificate",
            Permission::GenerateCrl => "generate_crl",
            Permission::PublishCrl => "publish_crl",
            Permission::ViewCrl => "view_crl",
            Permission::SubmitRequest => "submit_request",
            Permission::ApproveRequest => "approve_request",
            Permission::RejectRequest => "reject_request",
            Permission::ViewRequests => "view_requests",
            Permission::GenerateEstToken => "generate_est_token",
            Permission::ReadAuditLog => "read_audit_log",
            Permission::ExportAuditLog => "export_audit_log",
            Permission::SearchAuditLog => "search_audit_log",
            Permission::ModifyConfig => "modify_config",
            Permission::ViewConfig => "view_config",
            Permission::CreateUser => "create_user",
            Permission::ModifyUser => "modify_user",
            Permission::DeleteUser => "delete_user",
            Permission::AssignRoles => "assign_roles",
            Permission::ViewUsers => "view_users",
            Permission::UnlockAccount => "unlock_account",
            Permission::ImportTrustAnchor => "import_trust_anchor",
            Permission::RemoveTrustAnchor => "remove_trust_anchor",
            Permission::ViewTrustAnchors => "view_trust_anchors",
            Permission::GenerateCaKey => "generate_ca_key",
            Permission::BackupCaKey => "backup_ca_key",
            Permission::RecoverKey => "recover_key",
            Permission::ManageOcsp => "manage_ocsp",
            Permission::ViewOcspStatus => "view_ocsp_status",
            Permission::ViewServiceHealth => "view_service_health",
            Permission::RestartService => "restart_service",
        }
    }

    /// Get a description of the permission
    pub fn description(&self) -> &'static str {
        match self {
            Permission::IssueCertificate => "Issue new certificates",
            Permission::RevokeCertificate => "Revoke existing certificates",
            Permission::RenewCertificate => "Renew certificates",
            Permission::ViewCertificate => "View certificate details",
            Permission::GenerateCrl => "Generate Certificate Revocation Lists",
            Permission::PublishCrl => "Publish CRLs to distribution points",
            Permission::ViewCrl => "View CRL details",
            Permission::SubmitRequest => "Submit certificate requests",
            Permission::ApproveRequest => "Approve certificate requests",
            Permission::RejectRequest => "Reject certificate requests",
            Permission::ViewRequests => "View pending requests",
            Permission::GenerateEstToken => "Generate EST enrollment tokens",
            Permission::ReadAuditLog => "Read audit logs",
            Permission::ExportAuditLog => "Export audit logs",
            Permission::SearchAuditLog => "Search audit logs",
            Permission::ModifyConfig => "Modify system configuration",
            Permission::ViewConfig => "View system configuration",
            Permission::CreateUser => "Create user accounts",
            Permission::ModifyUser => "Modify user accounts",
            Permission::DeleteUser => "Delete or disable user accounts",
            Permission::AssignRoles => "Assign roles to users",
            Permission::ViewUsers => "View user accounts",
            Permission::UnlockAccount => "Unlock locked user accounts",
            Permission::ImportTrustAnchor => "Import trust anchors",
            Permission::RemoveTrustAnchor => "Remove trust anchors",
            Permission::ViewTrustAnchors => "View trust anchors",
            Permission::GenerateCaKey => "Generate CA signing keys",
            Permission::BackupCaKey => "Backup CA keys via KRA",
            Permission::RecoverKey => "Recover escrowed keys",
            Permission::ManageOcsp => "Manage OCSP responder",
            Permission::ViewOcspStatus => "View OCSP status",
            Permission::ViewServiceHealth => "View service health",
            Permission::RestartService => "Restart services",
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Get all permissions granted to a role
///
/// This implements the role-permission matrix per NIAP PP-CA requirements.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_MTD.1 - Role-based access to TSF data
/// - NIST 800-53: AC-3 - Access enforcement via role permissions
pub fn permissions_for_role(role: Role) -> &'static [Permission] {
    match role {
        Role::Administrator => &[
            // Configuration
            Permission::ModifyConfig,
            Permission::ViewConfig,
            // User management
            Permission::CreateUser,
            Permission::ModifyUser,
            Permission::DeleteUser,
            Permission::AssignRoles,
            Permission::ViewUsers,
            Permission::UnlockAccount,
            // Trust anchors
            Permission::ImportTrustAnchor,
            Permission::RemoveTrustAnchor,
            Permission::ViewTrustAnchors,
            // Key management
            Permission::GenerateCaKey,
            Permission::BackupCaKey,
            // Service operations
            Permission::ViewServiceHealth,
            Permission::RestartService,
            // EST enrollment-token management
            Permission::GenerateEstToken,
            // View operations (read-only)
            Permission::ViewCertificate,
            Permission::ViewCrl,
            Permission::ViewRequests,
            Permission::ViewOcspStatus,
        ],

        Role::Auditor => &[
            // Audit operations (exclusive to Auditor)
            Permission::ReadAuditLog,
            Permission::ExportAuditLog,
            Permission::SearchAuditLog,
            // Read-only views
            Permission::ViewCertificate,
            Permission::ViewCrl,
            Permission::ViewRequests,
            Permission::ViewConfig,
            Permission::ViewUsers,
            Permission::ViewTrustAnchors,
            Permission::ViewOcspStatus,
            Permission::ViewServiceHealth,
        ],

        Role::OperationsStaff => &[
            // Certificate operations
            Permission::IssueCertificate,
            Permission::RevokeCertificate,
            Permission::RenewCertificate,
            Permission::ViewCertificate,
            // CRL operations
            Permission::GenerateCrl,
            Permission::PublishCrl,
            Permission::ViewCrl,
            // OCSP operations
            Permission::ManageOcsp,
            Permission::ViewOcspStatus,
            // Request viewing (not approval)
            Permission::ViewRequests,
            // EST: mint time-limited enrollment tokens for device bootstrap
            Permission::GenerateEstToken,
            // Service health
            Permission::ViewServiceHealth,
        ],

        Role::RaStaff => &[
            // Request approval
            Permission::ApproveRequest,
            Permission::RejectRequest,
            Permission::ViewRequests,
            // Submit requests
            Permission::SubmitRequest,
            // Read-only views
            Permission::ViewCertificate,
            Permission::ViewCrl,
            Permission::ViewServiceHealth,
        ],

        Role::Aor => &[
            // Request approval (limited scope)
            Permission::ApproveRequest,
            Permission::RejectRequest,
            Permission::ViewRequests,
            // Submit requests for their organization
            Permission::SubmitRequest,
            // Read-only views
            Permission::ViewCertificate,
        ],

        // Machine-only EST enrollment principal: exactly one capability, so a
        // leaked/abused enrollment token can do nothing but complete an
        // enrollment whose identity is already pinned by the token (H1).
        // NIST 800-53: AC-6 (least privilege).
        Role::EstEnrollee => &[Permission::SubmitRequest],

        // Machine-only EST re-enrollment principal: exactly one capability, so a
        // device authenticating with its existing certificate can renew that
        // certificate (RFC 7030 §3.3) and do nothing else. The re-enroll handler
        // further binds the CSR identity to a certificate previously issued to
        // the same client. NIST 800-53: AC-6 (least privilege).
        Role::EstDevice => &[Permission::RenewCertificate],
    }
}

/// Check if a role has a specific permission
///
/// NIAP PP-CA: FMT_MTD.1 - Permission check
pub fn role_has_permission(role: Role, permission: Permission) -> bool {
    permissions_for_role(role).contains(&permission)
}

/// Check if any of the given roles has the specified permission
pub fn any_role_has_permission(roles: &[Role], permission: Permission) -> bool {
    roles.iter().any(|r| role_has_permission(*r, permission))
}

/// Get all unique permissions for a set of roles
pub fn aggregate_permissions(roles: &[Role]) -> Vec<Permission> {
    use std::collections::HashSet;

    let mut perms: HashSet<Permission> = HashSet::new();
    for role in roles {
        for perm in permissions_for_role(*role) {
            perms.insert(*perm);
        }
    }
    perms.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_administrator_permissions() {
        assert!(role_has_permission(
            Role::Administrator,
            Permission::ModifyConfig
        ));
        assert!(role_has_permission(
            Role::Administrator,
            Permission::CreateUser
        ));
        assert!(role_has_permission(
            Role::Administrator,
            Permission::ImportTrustAnchor
        ));
        // Admin cannot issue certificates
        assert!(!role_has_permission(
            Role::Administrator,
            Permission::IssueCertificate
        ));
        // Admin cannot read audit logs (auditor only)
        assert!(!role_has_permission(
            Role::Administrator,
            Permission::ReadAuditLog
        ));
    }

    #[test]
    fn test_auditor_permissions() {
        assert!(role_has_permission(Role::Auditor, Permission::ReadAuditLog));
        assert!(role_has_permission(
            Role::Auditor,
            Permission::ExportAuditLog
        ));
        assert!(role_has_permission(
            Role::Auditor,
            Permission::ViewCertificate
        ));
        // Auditor cannot modify anything
        assert!(!role_has_permission(
            Role::Auditor,
            Permission::ModifyConfig
        ));
        assert!(!role_has_permission(
            Role::Auditor,
            Permission::IssueCertificate
        ));
    }

    #[test]
    fn test_operations_permissions() {
        assert!(role_has_permission(
            Role::OperationsStaff,
            Permission::IssueCertificate
        ));
        assert!(role_has_permission(
            Role::OperationsStaff,
            Permission::RevokeCertificate
        ));
        assert!(role_has_permission(
            Role::OperationsStaff,
            Permission::GenerateCrl
        ));
        // Operations cannot approve requests
        assert!(!role_has_permission(
            Role::OperationsStaff,
            Permission::ApproveRequest
        ));
        // Operations cannot read audit logs
        assert!(!role_has_permission(
            Role::OperationsStaff,
            Permission::ReadAuditLog
        ));
    }

    #[test]
    fn test_ra_permissions() {
        assert!(role_has_permission(
            Role::RaStaff,
            Permission::ApproveRequest
        ));
        assert!(role_has_permission(
            Role::RaStaff,
            Permission::RejectRequest
        ));
        // RA cannot issue certificates directly
        assert!(!role_has_permission(
            Role::RaStaff,
            Permission::IssueCertificate
        ));
    }

    #[test]
    fn test_est_device_permissions() {
        // A device authenticated by its existing certificate may renew it
        // (RFC 7030 §3.3) — this is exactly what unblocks /simplereenroll.
        assert!(role_has_permission(
            Role::EstDevice,
            Permission::RenewCertificate
        ));
        // Least privilege (AC-6): nothing else. In particular it may not submit
        // a fresh enrollment, issue, or revoke.
        assert_eq!(permissions_for_role(Role::EstDevice).len(), 1);
        assert!(!role_has_permission(
            Role::EstDevice,
            Permission::SubmitRequest
        ));
        assert!(!role_has_permission(
            Role::EstDevice,
            Permission::IssueCertificate
        ));
        assert!(!role_has_permission(
            Role::EstDevice,
            Permission::RevokeCertificate
        ));
    }

    #[test]
    fn test_any_role_has_permission() {
        let roles = vec![Role::RaStaff, Role::Aor];
        assert!(any_role_has_permission(&roles, Permission::ApproveRequest));
        assert!(!any_role_has_permission(
            &roles,
            Permission::IssueCertificate
        ));
    }

    #[test]
    fn test_aggregate_permissions() {
        let roles = vec![Role::Administrator, Role::OperationsStaff];
        let perms = aggregate_permissions(&roles);

        // Should have permissions from both roles
        assert!(perms.contains(&Permission::ModifyConfig)); // from Admin
        assert!(perms.contains(&Permission::IssueCertificate)); // from Operations
    }
}
