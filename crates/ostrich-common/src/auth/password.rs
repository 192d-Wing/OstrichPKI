//! Password Authentication Provider
//!
//! Implements password-based authentication using Argon2id password hashing.
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UAU.1: User Authentication - password authentication
//! - FIA_AFL.1: Authentication Failure Handling - lockout integration
//! - FTP_ITC.1: Inter-TSF Trusted Channel - protect password in transit (caller responsibility)
//!
//! ## NIST 800-53 Rev 5
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management - secure password hashing
//! - IA-5(1): Password-Based Authentication - FIPS-validated hashing
//! - AC-7: Unsuccessful Login Attempts - lockout integration
//!
//! ## Password Hashing Standards
//! - Argon2id (RFC 9106) - Memory-hard password hashing
//! - OWASP recommendations for password storage

use argon2::{
    Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::{
    lockout::AuthLockout,
    provider::{AuthError, AuthProvider, AuthResult, Credentials, SessionInfo},
    session::SessionManager,
    user::{AccountStatus, AuthMethod, AuthenticatedUser, UserAccount, UserId},
};

/// Argon2id password hashing configuration
///
/// Uses OWASP recommended parameters for Argon2id:
/// - Memory cost (m): 19 MiB (19456 KiB)
/// - Time cost (t): 2 iterations
/// - Parallelism (p): 1 thread
///
/// These parameters provide strong resistance to:
/// - Brute force attacks
/// - GPU/ASIC attacks (memory-hard)
/// - Side-channel attacks (constant-time)
///
/// NIST 800-53: IA-5(1) - Password-based authentication using approved techniques
#[derive(Debug, Clone)]
pub struct PasswordHashConfig {
    /// Memory cost in KiB (default: 19456 = 19 MiB per OWASP)
    pub memory_cost: u32,
    /// Time cost iterations (default: 2 per OWASP)
    pub time_cost: u32,
    /// Parallelism (default: 1)
    pub parallelism: u32,
}

impl Default for PasswordHashConfig {
    fn default() -> Self {
        Self {
            memory_cost: 19456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl PasswordHashConfig {
    /// Create configuration with custom parameters
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    /// Create low-memory configuration for testing
    /// WARNING: Not suitable for production
    pub fn low_memory() -> Self {
        Self {
            memory_cost: 4096, // 4 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }

    /// Build Argon2 parameters
    fn build_params(&self) -> Result<Params, argon2::Error> {
        Params::new(self.memory_cost, self.time_cost, self.parallelism, None)
    }
}

/// Hash a password with Argon2id (standalone form for provisioning tools
/// that don't construct a full PasswordAuthProvider).
///
/// NIST 800-53: IA-5(1) - Password hashing using approved algorithm
/// RFC 9106: Argon2 password hashing algorithm
pub fn hash_password(config: &PasswordHashConfig, password: &SecretString) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = config
        .build_params()
        .map_err(|e| AuthError::Internal(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|e| AuthError::Internal(format!("Password hashing failed: {}", e)))?;

    Ok(password_hash.to_string())
}

/// User repository trait for password provider
///
/// Abstracts database access for user authentication
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by username
    async fn find_by_username(&self, username: &str) -> AuthResult<Option<UserAccount>>;

    /// Update user's last login timestamp
    async fn update_last_login(&self, user_id: &UserId) -> AuthResult<()>;

    /// Record a failed login attempt
    async fn record_failed_attempt(&self, username: &str) -> AuthResult<()>;

    /// Reset failed attempts counter
    async fn reset_failed_attempts(&self, username: &str) -> AuthResult<()>;
}

/// Password-based authentication provider
///
/// Implements authentication using Argon2id password hashing with
/// account lockout and session management integration.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - Password authentication
/// - NIST 800-53: IA-5(1) - Password-based authentication
pub struct PasswordAuthProvider {
    /// Password hashing configuration
    config: PasswordHashConfig,

    /// User repository for database access
    user_repo: Arc<dyn UserRepository>,

    /// Account lockout manager
    lockout: Arc<AuthLockout>,

    /// Session manager
    session_manager: Arc<SessionManager>,
}

impl PasswordAuthProvider {
    /// Create a new password authentication provider
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        lockout: Arc<AuthLockout>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            config: PasswordHashConfig::default(),
            user_repo,
            lockout,
            session_manager,
        }
    }

    /// Create with custom password hashing configuration
    pub fn with_config(
        config: PasswordHashConfig,
        user_repo: Arc<dyn UserRepository>,
        lockout: Arc<AuthLockout>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            config,
            user_repo,
            lockout,
            session_manager,
        }
    }

    /// Hash a password using Argon2id
    ///
    /// NIST 800-53: IA-5(1) - Password hashing using approved algorithm
    /// RFC 9106: Argon2 password hashing algorithm
    pub fn hash_password(&self, password: &SecretString) -> AuthResult<String> {
        hash_password(&self.config, password)
    }

    /// Verify a password against a hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    fn verify_password(&self, password: &SecretString, hash: &str) -> AuthResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::Internal(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::Internal(format!(
                "Password verification error: {}",
                e
            ))),
        }
    }

    /// Authenticate with username and password
    async fn authenticate_password(
        &self,
        username: &str,
        password: &SecretString,
    ) -> AuthResult<AuthenticatedUser> {
        // Check if account is locked
        // NIAP PP-CA: FIA_AFL.1.2 - Prevent authentication when locked
        let is_allowed = self
            .lockout
            .is_authentication_allowed(username)
            .map_err(|e| AuthError::Internal(format!("Lockout check failed: {}", e)))?;

        if !is_allowed {
            let remaining = self
                .lockout
                .get_remaining_lockout_time(username)
                .unwrap_or(0);
            warn!(username = %username, "Authentication blocked: account locked");
            return Err(AuthError::AccountLocked {
                until: format!("{} seconds remaining", remaining),
            });
        }

        // Find user in database
        let user_account = self
            .user_repo
            .find_by_username(username)
            .await?
            .ok_or_else(|| {
                debug!(username = %username, "User not found");
                AuthError::InvalidCredentials
            })?;

        // Check account status
        match user_account.status {
            AccountStatus::Active => {
                // Check if temporary lock has expired
                if user_account.is_locked() {
                    warn!(username = %username, "Account temporarily locked");
                    return Err(AuthError::AccountLocked {
                        until: user_account
                            .locked_until
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_else(|| "indefinite".to_string()),
                    });
                }
            }
            AccountStatus::Locked => {
                warn!(username = %username, "Account locked by administrator");
                return Err(AuthError::AccountLocked {
                    until: "indefinite (admin must unlock)".to_string(),
                });
            }
            AccountStatus::Suspended => {
                warn!(username = %username, "Account suspended");
                return Err(AuthError::AccountSuspended);
            }
            AccountStatus::Disabled => {
                warn!(username = %username, "Account disabled");
                return Err(AuthError::AccountDisabled);
            }
            AccountStatus::PendingActivation => {
                warn!(username = %username, "Account pending activation");
                return Err(AuthError::AccountDisabled);
            }
        }

        // Verify password
        let password_hash = user_account
            .password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        let valid = self.verify_password(password, password_hash)?;

        if !valid {
            // Record failed attempt
            // NIAP PP-CA: FIA_AFL.1.1 - Track failed attempts
            warn!(username = %username, "Invalid password");
            let _ = self
                .lockout
                .record_failure(username, None, "invalid_password");
            let _ = self.user_repo.record_failed_attempt(username).await;
            return Err(AuthError::InvalidCredentials);
        }

        // Password is valid - reset lockout and create authenticated user
        info!(username = %username, "Password authentication successful");
        let _ = self.lockout.record_success(username);
        let _ = self.user_repo.reset_failed_attempts(username).await;
        let _ = self.user_repo.update_last_login(&user_account.id).await;

        // Create authenticated user
        let authenticated = AuthenticatedUser::new(
            user_account.id,
            user_account.username.clone(),
            user_account.roles.clone(),
            AuthMethod::Password,
        )
        .with_display_name(user_account.display_name.unwrap_or_default())
        .with_email(user_account.email.unwrap_or_default());

        Ok(authenticated)
    }
}

#[async_trait]
impl AuthProvider for PasswordAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
        match credentials {
            Credentials::Password { username, password } => {
                self.authenticate_password(username, password).await
            }
            _ => Err(AuthError::UnsupportedAuthMethod),
        }
    }

    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo> {
        let session = self
            .session_manager
            .validate_session(token)
            .map_err(|_| AuthError::InvalidSession)?;

        // Session stores user_id as a string - we'll use it as username for now
        // In a real implementation, user_id would be a UUID and we'd look up by ID
        let user_account = self
            .user_repo
            .find_by_username(&session.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let user = AuthenticatedUser::new(
            user_account.id,
            user_account.username.clone(),
            user_account.roles.clone(),
            AuthMethod::Password,
        );

        Ok(SessionInfo {
            token: token.to_string(),
            user,
            expires_at: session.expires_at.timestamp(),
            is_valid: true,
        })
    }

    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        let session = self
            .session_manager
            .create_session(&user.username, None, None) // ip_address, user_agent
            .map_err(|e| AuthError::Internal(format!("Session creation failed: {}", e)))?;

        Ok(SessionInfo {
            token: session.token.clone(),
            user: user.clone(),
            expires_at: session.expires_at.timestamp(),
            is_valid: true,
        })
    }

    async fn invalidate_session(&self, token: &str) -> AuthResult<()> {
        // First validate to get session ID
        let session = self
            .session_manager
            .validate_session(token)
            .map_err(|_| AuthError::InvalidSession)?;

        self.session_manager
            .terminate_session(&session.id) // Use 'id' field
            .map_err(|e| AuthError::Internal(format!("Session termination failed: {}", e)))
    }

    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()> {
        debug!(username = %username, reason = %reason, "Recording failed attempt");
        let _ = self.lockout.record_failure(username, None, reason);
        let _ = self.user_repo.record_failed_attempt(username).await;
        Ok(())
    }

    async fn is_account_locked(&self, username: &str) -> AuthResult<bool> {
        let is_allowed = self
            .lockout
            .is_authentication_allowed(username)
            .unwrap_or(false);
        Ok(!is_allowed)
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        info!(username = %username, "Unlocking account (admin action)");
        // admin_unlock requires admin_id - use system for now
        let _ = self.lockout.admin_unlock(username, "system");
        let _ = self.user_repo.reset_failed_attempts(username).await;
        Ok(())
    }

    fn provider_name(&self) -> &str {
        "password"
    }

    fn supported_methods(&self) -> &[AuthMethod] {
        &[AuthMethod::Password]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Role, lockout::LockoutConfig, session::SessionConfig};
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    /// In-memory user repository for testing
    struct InMemoryUserRepo {
        users: RwLock<HashMap<String, UserAccount>>,
    }

    impl InMemoryUserRepo {
        fn new() -> Self {
            Self {
                users: RwLock::new(HashMap::new()),
            }
        }

        async fn add_user(&self, account: UserAccount) {
            self.users
                .write()
                .await
                .insert(account.username.clone(), account);
        }
    }

    #[async_trait]
    impl UserRepository for InMemoryUserRepo {
        async fn find_by_username(&self, username: &str) -> AuthResult<Option<UserAccount>> {
            Ok(self.users.read().await.get(username).cloned())
        }

        async fn update_last_login(&self, _user_id: &UserId) -> AuthResult<()> {
            Ok(())
        }

        async fn record_failed_attempt(&self, _username: &str) -> AuthResult<()> {
            Ok(())
        }

        async fn reset_failed_attempts(&self, _username: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    fn create_test_provider(repo: Arc<dyn UserRepository>) -> PasswordAuthProvider {
        let lockout = Arc::new(AuthLockout::new(LockoutConfig::default()));
        let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));

        PasswordAuthProvider::with_config(
            PasswordHashConfig::low_memory(), // Use low memory for faster tests
            repo,
            lockout,
            session_manager,
        )
    }

    #[tokio::test]
    async fn test_hash_and_verify_password() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(repo);

        let password = SecretString::from("test-password-123");
        let hash = provider.hash_password(&password).unwrap();

        // Verify correct password
        assert!(provider.verify_password(&password, &hash).unwrap());

        // Verify incorrect password
        let wrong = SecretString::from("wrong-password");
        assert!(!provider.verify_password(&wrong, &hash).unwrap());
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(Arc::clone(&repo) as Arc<dyn UserRepository>);

        // Create test user
        let password = SecretString::from("secure-password");
        let hash = provider.hash_password(&password).unwrap();

        let mut user = UserAccount::new("testuser", vec![Role::OperationsStaff]);
        user.password_hash = Some(hash);

        repo.add_user(user).await;

        // Authenticate
        let creds = Credentials::password("testuser", "secure-password");
        let result = provider.authenticate(&creds).await;

        assert!(result.is_ok());
        let authenticated = result.unwrap();
        assert_eq!(authenticated.username, "testuser");
        assert_eq!(authenticated.auth_method, AuthMethod::Password);
        assert!(authenticated.has_role(Role::OperationsStaff));
    }

    #[tokio::test]
    async fn test_invalid_password() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(Arc::clone(&repo) as Arc<dyn UserRepository>);

        let password = SecretString::from("correct-password");
        let hash = provider.hash_password(&password).unwrap();

        let mut user = UserAccount::new("testuser", vec![Role::Administrator]);
        user.password_hash = Some(hash);
        repo.add_user(user).await;

        // Try wrong password
        let creds = Credentials::password("testuser", "wrong-password");
        let result = provider.authenticate(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(repo);

        let creds = Credentials::password("nonexistent", "password");
        let result = provider.authenticate(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_suspended_account() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(Arc::clone(&repo) as Arc<dyn UserRepository>);

        let password = SecretString::from("password");
        let hash = provider.hash_password(&password).unwrap();

        let mut user = UserAccount::new("suspended", vec![Role::Auditor]);
        user.password_hash = Some(hash);
        user.status = AccountStatus::Suspended;
        repo.add_user(user).await;

        let creds = Credentials::password("suspended", "password");
        let result = provider.authenticate(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::AccountSuspended)));
    }

    #[tokio::test]
    async fn test_lockout_after_failures() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(Arc::clone(&repo) as Arc<dyn UserRepository>);

        let password = SecretString::from("password");
        let hash = provider.hash_password(&password).unwrap();

        let mut user = UserAccount::new("testuser", vec![Role::RaStaff]);
        user.password_hash = Some(hash);
        repo.add_user(user).await;

        // Fail authentication multiple times
        for _ in 0..5 {
            let creds = Credentials::password("testuser", "wrong");
            let _ = provider.authenticate(&creds).await;
        }

        // Account should be locked
        let is_allowed = provider
            .lockout
            .is_authentication_allowed("testuser")
            .unwrap();
        assert!(!is_allowed);

        // Even correct password should fail
        let creds = Credentials::password("testuser", "password");
        let result = provider.authenticate(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::AccountLocked { .. })));
    }

    #[tokio::test]
    async fn test_session_creation_and_validation() {
        let repo = Arc::new(InMemoryUserRepo::new());
        let provider = create_test_provider(Arc::clone(&repo) as Arc<dyn UserRepository>);

        let password = SecretString::from("password");
        let hash = provider.hash_password(&password).unwrap();

        let mut user = UserAccount::new("testuser", vec![Role::Administrator]);
        user.password_hash = Some(hash);
        repo.add_user(user).await;

        // Authenticate
        let creds = Credentials::password("testuser", "password");
        let authenticated = provider.authenticate(&creds).await.unwrap();

        // Create session
        let session_info = provider.create_session(&authenticated).await.unwrap();
        assert!(session_info.is_valid);
        assert!(!session_info.token.is_empty());

        // Validate session
        let validated = provider
            .validate_session(&session_info.token)
            .await
            .unwrap();
        assert_eq!(validated.user.username, "testuser");
        assert!(validated.is_valid);
    }
}
