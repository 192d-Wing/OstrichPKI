//! User Identity and Credential Types
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UID.1: User Identification - unique user identity
//! - FIA_UAU.1: User Authentication - credential types
//! - FMT_SMR.2: Security Roles - role assignment
//!
//! ## NIST 800-53 Rev 5
//! - IA-2: Identification and Authentication
//! - IA-4: Identifier Management
//! - AC-2: Account Management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::roles::Role;

/// Unique identifier for a user
///
/// NIAP PP-CA: FIA_UID.1 - Each user has a unique identifier
/// NIST 800-53: IA-4 - Identifier management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(Uuid);

impl UserId {
    /// Create a new random user ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Authentication method used to authenticate the user
///
/// NIAP PP-CA: FIA_UAU.1 - Authentication before TSF-mediated actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Password-based authentication (Argon2id)
    Password,
    /// mTLS certificate authentication
    Certificate,
    /// API key for service accounts
    ApiKey,
    /// Multi-factor authentication (password + certificate/OTP)
    MultiFactor,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password => write!(f, "password"),
            AuthMethod::Certificate => write!(f, "certificate"),
            AuthMethod::ApiKey => write!(f, "api_key"),
            AuthMethod::MultiFactor => write!(f, "multi_factor"),
        }
    }
}

/// An authenticated user with verified identity
///
/// This struct represents a user who has successfully completed authentication.
/// It contains the user's identity, roles, and authentication metadata.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UID.1 - User identification
/// - NIAP PP-CA: FIA_UAU.1 - Successful authentication
/// - NIAP PP-CA: FMT_SMR.2 - Role assignment
/// - NIST 800-53: IA-2 - Identification and authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// Unique user identifier
    /// NIAP PP-CA: FIA_UID.1.1 - TSF identifies each user
    pub id: UserId,

    /// Username (human-readable identifier)
    pub username: String,

    /// Display name (optional)
    pub display_name: Option<String>,

    /// Email address (optional)
    pub email: Option<String>,

    /// Assigned security roles
    /// NIAP PP-CA: FMT_SMR.2 - Roles associated with users
    pub roles: Vec<Role>,

    /// Authentication method used
    /// NIAP PP-CA: FIA_UAU.1 - Authentication mechanism
    pub auth_method: AuthMethod,

    /// Timestamp when authentication occurred
    pub authenticated_at: DateTime<Utc>,

    /// Session token (if session-based auth)
    pub session_token: Option<String>,

    /// Certificate subject DN (if certificate auth)
    pub certificate_subject: Option<String>,

    /// Source IP address of authentication
    pub source_ip: Option<String>,
}

impl AuthenticatedUser {
    /// Create a new authenticated user
    pub fn new(id: UserId, username: String, roles: Vec<Role>, auth_method: AuthMethod) -> Self {
        Self {
            id,
            username,
            display_name: None,
            email: None,
            roles,
            auth_method,
            authenticated_at: Utc::now(),
            session_token: None,
            certificate_subject: None,
            source_ip: None,
        }
    }

    /// Check if user has a specific role
    ///
    /// NIAP PP-CA: FMT_SMR.2 - Role verification
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// Check if user has any of the specified roles
    ///
    /// NIAP PP-CA: FMT_SMR.2 - Role verification
    pub fn has_any_role(&self, roles: &[Role]) -> bool {
        roles.iter().any(|r| self.roles.contains(r))
    }

    /// Check if user has all of the specified roles
    pub fn has_all_roles(&self, roles: &[Role]) -> bool {
        roles.iter().all(|r| self.roles.contains(r))
    }

    /// Set the display name
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the session token
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    /// Set the certificate subject
    pub fn with_certificate_subject(mut self, subject: impl Into<String>) -> Self {
        self.certificate_subject = Some(subject.into());
        self
    }

    /// Set the source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }
}

/// User account status
///
/// NIAP PP-CA: FIA_AFL.1 - Account lockout status
/// NIST 800-53: AC-2 - Account management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccountStatus {
    /// Account is active and can authenticate
    #[default]
    Active,
    /// Account is locked due to failed attempts
    Locked,
    /// Account is suspended by administrator
    Suspended,
    /// Account is disabled (soft delete)
    Disabled,
    /// Account is pending activation
    PendingActivation,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Active => write!(f, "active"),
            AccountStatus::Locked => write!(f, "locked"),
            AccountStatus::Suspended => write!(f, "suspended"),
            AccountStatus::Disabled => write!(f, "disabled"),
            AccountStatus::PendingActivation => write!(f, "pending_activation"),
        }
    }
}

/// User account for persistence
///
/// This struct represents a user account as stored in the database.
///
/// NIST 800-53: AC-2 - Account management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    /// Unique user identifier
    pub id: UserId,

    /// Username (login identifier)
    pub username: String,

    /// Display name
    pub display_name: Option<String>,

    /// Email address
    pub email: Option<String>,

    /// Password hash (Argon2id)
    /// Note: This should never be serialized to clients
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,

    /// Certificate subject DN (for certificate-based auth)
    pub certificate_subject: Option<String>,

    /// Assigned roles
    pub roles: Vec<Role>,

    /// Account status
    pub status: AccountStatus,

    /// Account creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,

    /// Last successful login
    pub last_login_at: Option<DateTime<Utc>>,

    /// Account locked until (if locked)
    pub locked_until: Option<DateTime<Utc>>,

    /// Failed login attempt count (since last success)
    pub failed_attempts: u32,
}

impl UserAccount {
    /// Create a new user account
    pub fn new(username: impl Into<String>, roles: Vec<Role>) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            username: username.into(),
            display_name: None,
            email: None,
            password_hash: None,
            certificate_subject: None,
            roles,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
            last_login_at: None,
            locked_until: None,
            failed_attempts: 0,
        }
    }

    /// Check if account is currently locked
    ///
    /// NIAP PP-CA: FIA_AFL.1 - Account lockout check
    pub fn is_locked(&self) -> bool {
        match self.status {
            AccountStatus::Locked => {
                // Check if lock has expired
                if let Some(until) = self.locked_until {
                    Utc::now() < until
                } else {
                    true // Locked indefinitely (admin must unlock)
                }
            }
            _ => false,
        }
    }

    /// Check if account can authenticate
    pub fn can_authenticate(&self) -> bool {
        matches!(self.status, AccountStatus::Active) && !self.is_locked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_generation() {
        let id1 = UserId::new();
        let id2 = UserId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_authenticated_user_roles() {
        let user = AuthenticatedUser::new(
            UserId::new(),
            "admin".to_string(),
            vec![Role::Administrator, Role::Auditor],
            AuthMethod::Password,
        );

        assert!(user.has_role(Role::Administrator));
        assert!(user.has_role(Role::Auditor));
        assert!(!user.has_role(Role::OperationsStaff));
        assert!(user.has_any_role(&[Role::Administrator, Role::OperationsStaff]));
        assert!(!user.has_all_roles(&[Role::Administrator, Role::OperationsStaff]));
    }

    #[test]
    fn test_account_lockout() {
        let mut account = UserAccount::new("testuser", vec![Role::OperationsStaff]);
        assert!(account.can_authenticate());

        account.status = AccountStatus::Locked;
        account.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!account.can_authenticate());
        assert!(account.is_locked());
    }

    #[test]
    fn test_account_lock_expired() {
        let mut account = UserAccount::new("testuser", vec![Role::OperationsStaff]);
        account.status = AccountStatus::Locked;
        account.locked_until = Some(Utc::now() - chrono::Duration::hours(1));
        // Lock has expired, is_locked returns false
        assert!(!account.is_locked());
    }
}
