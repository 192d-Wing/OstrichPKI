//! Authentication and Authorization Module
//!
//! This module provides comprehensive authentication and authorization
//! infrastructure for the OstrichPKI system.
//!
//! # Components
//!
//! - **User Identity** (`user`): User accounts, credentials, and identity types
//! - **Roles** (`roles`): NIAP PP-CA defined security roles with separation of duties
//! - **Permissions** (`permissions`): Fine-grained permission definitions
//! - **Provider** (`provider`): Authentication provider trait and implementations
//! - **Password** (`password`): Password authentication with Argon2id
//! - **RBAC** (`rbac`): Role-Based Access Control policy engine
//! - **Lockout** (`lockout`): Account lockout after failed attempts
//! - **Session** (`session`): Session management
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_AFL.1: Authentication Failure Handling
//! - FIA_UAU.1: User Authentication
//! - FIA_UID.1: User Identification
//! - FMT_SMR.2: Security Management Roles
//! - FMT_MTD.1: Management of TSF Data
//! - FTA_SSL.1: Session Locking
//! - FTA_SSL.3: TSF-initiated Termination
//! - FTA_SSL.4: User-initiated Termination
//!
//! ## NIST 800-53 Rev 5
//! - AC-2: Account Management
//! - AC-3: Access Enforcement
//! - AC-5: Separation of Duties
//! - AC-6: Least Privilege
//! - AC-7: Unsuccessful Login Attempts
//! - IA-2: Identification and Authentication
//! - IA-4: Identifier Management
//! - IA-5: Authenticator Management
//! - IA-11: Re-authentication
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use ostrich_common::auth::{
//!     AuthenticatedUser, AuthMethod, Role, Permission,
//!     RbacPolicy, Credentials, AuthProvider,
//! };
//!
//! // Create RBAC policy
//! let policy = RbacPolicy::new();
//!
//! // Authenticate user
//! let creds = Credentials::password("admin", "secret");
//! let user = auth_provider.authenticate(&creds).await?;
//!
//! // Check authorization
//! policy.authorize(&user, Permission::IssueCertificate, "cert:123")?;
//! ```

pub mod lockout;
pub mod middleware;
pub mod mtls;
pub mod password;
pub mod permissions;
pub mod provider;
pub mod rbac;
pub mod roles;
pub mod session;
pub mod user;

// Re-export commonly used types
pub use lockout::{AuthLockout, LockoutConfig, LockoutStatus};
pub use middleware::{AuthLayer, AuthResponse, AuthUser, AuthzLayer};
pub use mtls::{CertificateAuthConfig, CertificateAuthProvider, CertificateUserRepository};
pub use password::{PasswordAuthProvider, PasswordHashConfig, UserRepository};
pub use permissions::{
    Permission, aggregate_permissions, any_role_has_permission, permissions_for_role,
    role_has_permission,
};
pub use provider::{
    AuthError, AuthProvider, AuthResult, CompositeAuthProvider, Credentials, SessionInfo,
};
pub use rbac::{AuthorizationError, AuthzResult, RbacMiddleware, RbacPolicy};
pub use roles::{Role, RoleValidationError, validate_role_set};
pub use session::{Session, SessionConfig, SessionManager, SessionStatus};
pub use user::{AccountStatus, AuthMethod, AuthenticatedUser, UserAccount, UserId};
