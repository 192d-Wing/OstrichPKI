//! Security Role Definitions
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FMT_SMR.2: Security Management Roles - role definitions with separation of duties
//! - FMT_MTD.1: Management of TSF Data - role-based access control
//!
//! ## NIST 800-53 Rev 5
//! - AC-2: Account Management - role-based account structure
//! - AC-3: Access Enforcement - role-based access control
//! - AC-5: Separation of Duties - incompatible role enforcement
//! - AC-6: Least Privilege - role-specific permissions

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Security roles defined per NIAP PP-CA v2.1
///
/// These roles implement the principle of separation of duties as required
/// by NIAP PP-CA FMT_SMR.2 and NIST 800-53 AC-5.
///
/// # Role Hierarchy
/// - Administrator: System configuration, user management (highest privilege)
/// - Auditor: Read-only audit access (must be separate from operational roles)
/// - OperationsStaff: Certificate issuance, revocation, CRL generation
/// - RaStaff: Registration Authority - request approval
/// - Aor: Authorized Organization Representative - request approval
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_SMR.2 - Security roles
/// - NIST 800-53: AC-5 - Separation of duties
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// System Administrator
    ///
    /// Responsibilities:
    /// - System configuration management
    /// - User account management
    /// - Trust anchor management
    /// - Security policy configuration
    ///
    /// NIAP PP-CA: FMT_SMF.1 - Management functions
    Administrator,

    /// Security Auditor
    ///
    /// Responsibilities:
    /// - Read-only access to audit logs
    /// - Audit log export
    /// - Security event review
    ///
    /// CRITICAL: Must be separate from Administrator and OperationsStaff
    /// per NIAP PP-CA FMT_SMR.2 separation of duties requirements.
    ///
    /// NIAP PP-CA: FAU_SAR.1 - Audit review
    Auditor,

    /// CA Operations Staff
    ///
    /// Responsibilities:
    /// - Certificate issuance
    /// - Certificate revocation
    /// - CRL generation
    /// - OCSP responder management
    ///
    /// NIAP PP-CA: FDP_CER_EXT.1 - Certificate generation
    OperationsStaff,

    /// Registration Authority Staff
    ///
    /// Responsibilities:
    /// - Certificate request approval
    /// - Identity verification
    /// - Request rejection with reason
    ///
    /// NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval
    RaStaff,

    /// Authorized Organization Representative
    ///
    /// Responsibilities:
    /// - Certificate request approval for their organization
    /// - Limited to organizational scope
    ///
    /// NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval
    Aor,

    /// EST Enrollee (machine identity, not human-assignable)
    ///
    /// Synthetic role carried by a principal authenticated via a single-use EST
    /// enrollment token. Grants only `SubmitRequest` so the bearer can complete
    /// one initial enrollment and nothing else. Never stored on a user account
    /// and intentionally excluded from [`Role::all`] (not selectable in role UIs).
    ///
    /// NIAP PP-CA: FDP_CER_EXT.1 - certificate enrollment; AC-6 - least privilege
    EstEnrollee,

    /// EST Device (machine identity, not human-assignable)
    ///
    /// Synthetic role carried by a device that authenticates to EST with the
    /// (still-valid, CA-issued) client certificate from a prior enrollment, in
    /// order to renew it (RFC 7030 §3.3 re-enrollment). Grants only
    /// `RenewCertificate` so the certificate holder can re-enroll its own
    /// identity and nothing else; the re-enroll handler additionally binds the
    /// CSR subject/SAN to a certificate previously issued to the same client.
    /// Never stored on a user account and intentionally excluded from
    /// [`Role::all`] (not selectable in role UIs).
    ///
    /// NIAP PP-CA: FDP_CER_EXT.1 - certificate enrollment; AC-6 - least privilege
    EstDevice,

    // ===== NPE Portal roles (Non-Person Entity portal) =====
    //
    // These roles are derived from client-certificate OIDs at the NPE portal's
    // mTLS handshake (not stored on accounts the way the CA roles are), but they
    // must exist in the shared RBAC model because the CA service is the
    // enforcement point for every action the portal proxies.
    /// NPE PKI Sponsor (standard requester)
    ///
    /// Submits certificate applications and rekeys, views the status of *its own*
    /// applications, and generates EST enrollment passwords (tokens) for initial
    /// device enrollment. Own-scope: a Sponsor never sees another requester's
    /// applications or certificates (enforced in the CA handlers).
    ///
    /// NIAP PP-CA: FDP_CER_EXT.1 - certificate enrollment; NIST 800-53: AC-6
    PkiSponsor,

    /// NPE PKI Sponsor authenticated with an Administrator certificate
    ///
    /// All Sponsor privileges plus bulk enrollment (submit a ZIP of CSRs). The
    /// elevation is driven by the presence of the Admin OID in the client
    /// certificate at handshake time.
    ///
    /// NIAP PP-CA: FMT_SMF.1 - management functions; NIST 800-53: AC-6
    PkiSponsorAdmin,

    /// NPE Registration Authority
    ///
    /// Approves, rejects, overrides, or cancels certificate applications and
    /// revokes issued certificates. The override capability lets an RA push an
    /// application past validation blocks straight to the CA (audited).
    ///
    /// NIAP PP-CA: FDP_CER_EXT.3 - request approval; FDP_CER_EXT.4 - revocation
    RegistrationAuthority,

    /// NPE Certificate Authority Admin (CAA)
    ///
    /// Configures global settings, manages namespaces/wildcards, and manages
    /// CAA/RA user roles. A self-action block prevents a CAA from disabling or
    /// modifying its own account (enforced in the user-management handler).
    ///
    /// NIAP PP-CA: FMT_SMF.1 / FMT_SMR.2 - security management & roles
    CaaAdmin,

    /// NPE Auditor
    ///
    /// A dedicated, read-only reviewer of the certificate-lifecycle audit trail
    /// (portal Audit Log page + integrity verification). Holds no issuance,
    /// approval, or configuration authority, so audit review can be assigned to a
    /// principal independent of those who act — the separation-of-duties posture
    /// (AU-6 / AC-5 / FMT_SMR.2) that an operational role holding audit-read
    /// cannot provide on its own.
    NpeAuditor,
}

impl Role {
    /// Get roles that are incompatible with this role
    ///
    /// Implements separation of duties per NIAP PP-CA FMT_SMR.2
    /// and NIST 800-53 AC-5.
    ///
    /// # Separation Rules
    /// - Auditor cannot be combined with Administrator or OperationsStaff
    ///   (ensures audit independence)
    /// - OperationsStaff cannot be combined with Auditor
    ///   (prevents self-audit of operations)
    pub fn incompatible_roles(&self) -> &'static [Role] {
        match self {
            // Auditor must be independent from operational and admin roles
            Role::Auditor => &[Role::Administrator, Role::OperationsStaff],
            // Operations staff cannot audit their own actions
            Role::OperationsStaff => &[Role::Auditor],
            // Other roles have no incompatibilities
            Role::Administrator => &[],
            Role::RaStaff => &[],
            Role::Aor => &[],
            // Machine-only enrollment principal; never combined with human roles.
            Role::EstEnrollee => &[],
            // Machine-only re-enrollment principal; never combined with human roles.
            Role::EstDevice => &[],
            // NPE portal roles: OID-derived, single-role-per-certificate by
            // design, so no in-set incompatibilities are defined here.
            Role::PkiSponsor => &[],
            Role::PkiSponsorAdmin => &[],
            Role::RegistrationAuthority => &[],
            Role::CaaAdmin => &[],
            Role::NpeAuditor => &[],
        }
    }

    /// Check if this role is compatible with another role
    ///
    /// NIAP PP-CA: FMT_SMR.2 - Separation of duties enforcement
    pub fn is_compatible_with(&self, other: Role) -> bool {
        !self.incompatible_roles().contains(&other)
    }

    /// Get a human-readable description of this role
    pub fn description(&self) -> &'static str {
        match self {
            Role::Administrator => "System configuration and user management",
            Role::Auditor => "Read-only audit log access and review",
            Role::OperationsStaff => "Certificate issuance, revocation, and CRL generation",
            Role::RaStaff => "Certificate request approval (Registration Authority)",
            Role::Aor => "Certificate request approval (Authorized Organization Representative)",
            Role::EstEnrollee => "EST enrollment token principal (single-use, machine identity)",
            Role::EstDevice => "EST device principal (re-enrollment by existing certificate)",
            Role::PkiSponsor => "NPE PKI Sponsor (submit/rekey applications, own-scope)",
            Role::PkiSponsorAdmin => {
                "NPE PKI Sponsor with admin certificate (adds bulk enrollment)"
            }
            Role::RegistrationAuthority => {
                "NPE Registration Authority (approve/reject/override/revoke)"
            }
            Role::CaaAdmin => "NPE Certificate Authority Admin (config, namespaces, user roles)",
            Role::NpeAuditor => "NPE Auditor (read-only audit review + integrity verification)",
        }
    }

    /// Get the role name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Role::Administrator => "administrator",
            Role::Auditor => "auditor",
            Role::OperationsStaff => "operations_staff",
            Role::RaStaff => "ra_staff",
            Role::Aor => "aor",
            Role::EstEnrollee => "est_enrollee",
            Role::EstDevice => "est_device",
            Role::PkiSponsor => "pki_sponsor",
            Role::PkiSponsorAdmin => "pki_sponsor_admin",
            Role::RegistrationAuthority => "registration_authority",
            Role::CaaAdmin => "caa_admin",
            Role::NpeAuditor => "npe_auditor",
        }
    }

    /// Parse a role from a string name
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "administrator" | "admin" => Some(Role::Administrator),
            "auditor" => Some(Role::Auditor),
            "operations_staff" | "operations" | "operator" => Some(Role::OperationsStaff),
            "ra_staff" | "ra" => Some(Role::RaStaff),
            "aor" | "authorized_org_rep" => Some(Role::Aor),
            "est_enrollee" => Some(Role::EstEnrollee),
            "est_device" => Some(Role::EstDevice),
            // NPE portal roles
            "pki_sponsor" | "sponsor" => Some(Role::PkiSponsor),
            "pki_sponsor_admin" | "sponsor_admin" => Some(Role::PkiSponsorAdmin),
            "registration_authority" | "npe_ra" => Some(Role::RegistrationAuthority),
            "caa_admin" | "caa" => Some(Role::CaaAdmin),
            "npe_auditor" => Some(Role::NpeAuditor),
            _ => None,
        }
    }

    /// Get all available roles
    pub fn all() -> &'static [Role] {
        &[
            Role::Administrator,
            Role::Auditor,
            Role::OperationsStaff,
            Role::RaStaff,
            Role::Aor,
            Role::PkiSponsor,
            Role::PkiSponsorAdmin,
            Role::RegistrationAuthority,
            Role::CaaAdmin,
            Role::NpeAuditor,
        ]
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "administrator" | "Administrator" => Ok(Role::Administrator),
            "auditor" | "Auditor" => Ok(Role::Auditor),
            "operations_staff" | "OperationsStaff" => Ok(Role::OperationsStaff),
            "ra_staff" | "RaStaff" => Ok(Role::RaStaff),
            "aor" | "Aor" | "AOR" => Ok(Role::Aor),
            "est_enrollee" | "EstEnrollee" => Ok(Role::EstEnrollee),
            "est_device" | "EstDevice" => Ok(Role::EstDevice),
            "pki_sponsor" | "PkiSponsor" => Ok(Role::PkiSponsor),
            "pki_sponsor_admin" | "PkiSponsorAdmin" => Ok(Role::PkiSponsorAdmin),
            "registration_authority" | "RegistrationAuthority" => Ok(Role::RegistrationAuthority),
            "caa_admin" | "CaaAdmin" => Ok(Role::CaaAdmin),
            "npe_auditor" | "NpeAuditor" => Ok(Role::NpeAuditor),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// Validate a set of roles for separation of duties compliance
///
/// Returns an error if any roles in the set are incompatible with each other.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FMT_SMR.2 - Separation of duties enforcement
/// - NIST 800-53: AC-5 - Separation of duties
///
/// # Example
/// ```
/// use ostrich_common::auth::roles::{Role, validate_role_set};
///
/// // Valid combination
/// let roles = vec![Role::Administrator, Role::RaStaff];
/// assert!(validate_role_set(&roles).is_ok());
///
/// // Invalid combination (Auditor + Administrator)
/// let roles = vec![Role::Auditor, Role::Administrator];
/// assert!(validate_role_set(&roles).is_err());
/// ```
pub fn validate_role_set(roles: &[Role]) -> Result<(), RoleValidationError> {
    let role_set: HashSet<Role> = roles.iter().copied().collect();

    for role in &role_set {
        for incompatible in role.incompatible_roles() {
            if role_set.contains(incompatible) {
                return Err(RoleValidationError::IncompatibleRoles {
                    role1: *role,
                    role2: *incompatible,
                    reason: format!(
                        "{} cannot be combined with {} per separation of duties policy",
                        role.name(),
                        incompatible.name()
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Error type for role validation
#[derive(Debug, Clone, thiserror::Error)]
pub enum RoleValidationError {
    /// Two roles are incompatible due to separation of duties
    #[error("Incompatible roles: {role1} and {role2} - {reason}")]
    IncompatibleRoles {
        role1: Role,
        role2: Role,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auditor_incompatibility() {
        // Auditor cannot be Administrator
        assert!(!Role::Auditor.is_compatible_with(Role::Administrator));
        // Auditor cannot be OperationsStaff
        assert!(!Role::Auditor.is_compatible_with(Role::OperationsStaff));
        // Auditor can be RaStaff
        assert!(Role::Auditor.is_compatible_with(Role::RaStaff));
    }

    #[test]
    fn test_operations_incompatibility() {
        // OperationsStaff cannot be Auditor
        assert!(!Role::OperationsStaff.is_compatible_with(Role::Auditor));
        // OperationsStaff can be Administrator
        assert!(Role::OperationsStaff.is_compatible_with(Role::Administrator));
    }

    #[test]
    fn test_validate_role_set_valid() {
        // Administrator + RaStaff is valid
        assert!(validate_role_set(&[Role::Administrator, Role::RaStaff]).is_ok());
        // OperationsStaff + RaStaff is valid
        assert!(validate_role_set(&[Role::OperationsStaff, Role::RaStaff]).is_ok());
        // Single role is always valid
        assert!(validate_role_set(&[Role::Auditor]).is_ok());
    }

    #[test]
    fn test_validate_role_set_invalid() {
        // Auditor + Administrator is invalid
        let result = validate_role_set(&[Role::Auditor, Role::Administrator]);
        assert!(result.is_err());

        // Auditor + OperationsStaff is invalid
        let result = validate_role_set(&[Role::Auditor, Role::OperationsStaff]);
        assert!(result.is_err());
    }

    #[test]
    fn test_role_from_name() {
        assert_eq!(Role::from_name("administrator"), Some(Role::Administrator));
        assert_eq!(Role::from_name("admin"), Some(Role::Administrator));
        assert_eq!(Role::from_name("auditor"), Some(Role::Auditor));
        assert_eq!(
            Role::from_name("operations_staff"),
            Some(Role::OperationsStaff)
        );
        assert_eq!(Role::from_name("ra_staff"), Some(Role::RaStaff));
        assert_eq!(Role::from_name("aor"), Some(Role::Aor));
        assert_eq!(Role::from_name("invalid"), None);
    }

    #[test]
    fn test_role_display() {
        assert_eq!(format!("{}", Role::Administrator), "administrator");
        assert_eq!(format!("{}", Role::Auditor), "auditor");
    }
}
