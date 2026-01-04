//! Authentication Provider Trait
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UAU.1: User Authentication - authentication before TSF-mediated actions
//! - FIA_UID.1: User Identification - user identification
//! - FIA_AFL.1: Authentication Failure Handling - failure tracking
//!
//! ## NIST 800-53 Rev 5
//! - IA-2: Identification and Authentication
//! - IA-5: Authenticator Management
//! - IA-11: Re-authentication

use async_trait::async_trait;
use secrecy::SecretString;
use thiserror::Error;

use super::user::{AuthMethod, AuthenticatedUser};

/// Credentials for authentication
///
/// Supports multiple authentication methods as required by NIAP PP-CA.
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - Authentication mechanisms
/// - NIST 800-53: IA-2 - Multi-factor authentication support
#[derive(Debug)]
pub enum Credentials {
    /// Password-based authentication
    ///
    /// NIAP PP-CA: FIA_UAU.1 - Password authentication
    Password {
        username: String,
        password: SecretString,
    },

    /// Certificate-based authentication (mTLS)
    ///
    /// NIAP PP-CA: FIA_UAU.1 - Certificate authentication
    Certificate {
        /// DER-encoded certificate chain
        cert_chain: Vec<Vec<u8>>,
        /// Client IP address for audit
        client_ip: Option<String>,
    },

    /// API key authentication for service accounts
    ApiKey { key: SecretString },

    /// Session token validation
    SessionToken { token: String },
}

impl Credentials {
    /// Create password credentials
    pub fn password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Credentials::Password {
            username: username.into(),
            password: SecretString::from(password.into()),
        }
    }

    /// Create certificate credentials
    pub fn certificate(cert_chain: Vec<Vec<u8>>) -> Self {
        Credentials::Certificate {
            cert_chain,
            client_ip: None,
        }
    }

    /// Create API key credentials
    pub fn api_key(key: impl Into<String>) -> Self {
        Credentials::ApiKey {
            key: SecretString::from(key.into()),
        }
    }

    /// Create session token credentials
    pub fn session_token(token: impl Into<String>) -> Self {
        Credentials::SessionToken {
            token: token.into(),
        }
    }

    /// Get the authentication method for these credentials
    pub fn auth_method(&self) -> AuthMethod {
        match self {
            Credentials::Password { .. } => AuthMethod::Password,
            Credentials::Certificate { .. } => AuthMethod::Certificate,
            Credentials::ApiKey { .. } => AuthMethod::ApiKey,
            Credentials::SessionToken { .. } => AuthMethod::Password, // Session from password auth
        }
    }
}

/// Authentication error types
///
/// NIAP PP-CA: FIA_AFL.1 - Authentication failure tracking
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Account is locked due to failed attempts
    /// NIAP PP-CA: FIA_AFL.1.2 - Account lockout
    #[error("Account is locked until {until}")]
    AccountLocked { until: String },

    /// Account is suspended by administrator
    #[error("Account is suspended")]
    AccountSuspended,

    /// Account is disabled
    #[error("Account is disabled")]
    AccountDisabled,

    /// User not found
    #[error("User not found")]
    UserNotFound,

    /// Session has expired
    #[error("Session has expired")]
    SessionExpired,

    /// Session is invalid
    #[error("Invalid session")]
    InvalidSession,

    /// Certificate validation failed
    #[error("Certificate validation failed: {reason}")]
    CertificateValidationFailed { reason: String },

    /// Certificate has expired
    #[error("Certificate has expired")]
    CertificateExpired,

    /// Certificate is revoked
    #[error("Certificate is revoked")]
    CertificateRevoked,

    /// Certificate subject not authorized
    #[error("Certificate subject not authorized")]
    CertificateNotAuthorized,

    /// API key is invalid or expired
    #[error("Invalid API key")]
    InvalidApiKey,

    /// Authentication method not supported
    #[error("Authentication method not supported")]
    UnsupportedAuthMethod,

    /// Internal error during authentication
    #[error("Internal authentication error: {0}")]
    Internal(String),
}

/// Result type for authentication operations
pub type AuthResult<T> = Result<T, AuthError>;

/// Session information returned after successful authentication
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session token
    pub token: String,

    /// User associated with the session
    pub user: AuthenticatedUser,

    /// Session expiration time (Unix timestamp)
    pub expires_at: i64,

    /// Whether the session is still valid
    pub is_valid: bool,
}

/// Authentication provider trait
///
/// This trait defines the interface for authentication providers.
/// Implementations can support different authentication mechanisms
/// (password, certificate, API key, etc.).
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - User authentication
/// - NIAP PP-CA: FIA_UID.1 - User identification
/// - NIST 800-53: IA-2 - Identification and authentication
///
/// # Example Implementation
/// ```ignore
/// struct MyAuthProvider { ... }
///
/// #[async_trait]
/// impl AuthProvider for MyAuthProvider {
///     async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
///         match credentials {
///             Credentials::Password { username, password } => {
///                 // Validate password against stored hash
///                 // ...
///             }
///             _ => Err(AuthError::UnsupportedAuthMethod),
///         }
///     }
///
///     // ... other methods
/// }
/// ```
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Authenticate a user with the provided credentials
    ///
    /// # Arguments
    /// * `credentials` - The credentials to validate
    ///
    /// # Returns
    /// * `Ok(AuthenticatedUser)` - Successfully authenticated user
    /// * `Err(AuthError)` - Authentication failed
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FIA_UAU.1.1 - TSF authenticates users before allowing actions
    /// - NIAP PP-CA: FIA_AFL.1.1 - Detect failed authentication attempts
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser>;

    /// Validate an existing session token
    ///
    /// # Arguments
    /// * `token` - The session token to validate
    ///
    /// # Returns
    /// * `Ok(SessionInfo)` - Valid session information
    /// * `Err(AuthError)` - Session is invalid or expired
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FTA_SSL.3 - TSF-initiated session termination
    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo>;

    /// Create a new session for an authenticated user
    ///
    /// # Arguments
    /// * `user` - The authenticated user
    ///
    /// # Returns
    /// * `Ok(SessionInfo)` - New session information
    /// * `Err(AuthError)` - Failed to create session
    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo>;

    /// Invalidate/terminate a session
    ///
    /// # Arguments
    /// * `token` - The session token to invalidate
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FTA_SSL.3 - TSF-initiated session termination
    /// - NIAP PP-CA: FTA_SSL.4 - User-initiated session termination
    async fn invalidate_session(&self, token: &str) -> AuthResult<()>;

    /// Record a failed authentication attempt
    ///
    /// This should be called when authentication fails to track
    /// attempts for account lockout purposes.
    ///
    /// # Arguments
    /// * `username` - The username that failed authentication
    /// * `reason` - The reason for the failure
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FIA_AFL.1.1 - Track failed attempts
    /// - NIAP PP-CA: FIA_AFL.1.2 - Take action when threshold reached
    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()>;

    /// Check if an account is locked
    ///
    /// # Arguments
    /// * `username` - The username to check
    ///
    /// # Returns
    /// * `Ok(false)` - Account is not locked
    /// * `Ok(true)` - Account is locked
    /// * `Err(AuthError)` - Error checking status
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FIA_AFL.1.2 - Account lockout check
    async fn is_account_locked(&self, username: &str) -> AuthResult<bool>;

    /// Unlock a locked account (admin action)
    ///
    /// # Arguments
    /// * `username` - The username to unlock
    ///
    /// # COMPLIANCE MAPPING
    /// - NIAP PP-CA: FIA_AFL.1.2 - Administrator unlock
    async fn unlock_account(&self, username: &str) -> AuthResult<()>;

    /// Get the name/identifier of this authentication provider
    fn provider_name(&self) -> &str;

    /// Get the supported authentication methods
    fn supported_methods(&self) -> &[AuthMethod];
}

/// A composite authentication provider that tries multiple providers
///
/// Useful for supporting multiple authentication methods (e.g., password + certificate).
pub struct CompositeAuthProvider {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl CompositeAuthProvider {
    /// Create a new composite provider
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the composite
    pub fn add_provider(mut self, provider: Box<dyn AuthProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Find a provider that supports the given auth method
    fn find_provider(&self, method: AuthMethod) -> Option<&dyn AuthProvider> {
        self.providers
            .iter()
            .find(|p| p.supported_methods().contains(&method))
            .map(|p| p.as_ref())
    }
}

impl Default for CompositeAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for CompositeAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
        let method = credentials.auth_method();
        let provider = self
            .find_provider(method)
            .ok_or(AuthError::UnsupportedAuthMethod)?;
        provider.authenticate(credentials).await
    }

    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo> {
        // Try each provider until one succeeds
        for provider in &self.providers {
            if let Ok(session) = provider.validate_session(token).await {
                return Ok(session);
            }
        }
        Err(AuthError::InvalidSession)
    }

    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        let method = user.auth_method;
        let provider = self
            .find_provider(method)
            .ok_or(AuthError::UnsupportedAuthMethod)?;
        provider.create_session(user).await
    }

    async fn invalidate_session(&self, token: &str) -> AuthResult<()> {
        // Try each provider
        for provider in &self.providers {
            if provider.invalidate_session(token).await.is_ok() {
                return Ok(());
            }
        }
        Err(AuthError::InvalidSession)
    }

    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()> {
        // Record on all providers that support it
        for provider in &self.providers {
            let _ = provider.record_failed_attempt(username, reason).await;
        }
        Ok(())
    }

    async fn is_account_locked(&self, username: &str) -> AuthResult<bool> {
        // Check all providers
        for provider in &self.providers {
            if let Ok(locked) = provider.is_account_locked(username).await
                && locked
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        // Unlock on all providers
        for provider in &self.providers {
            let _ = provider.unlock_account(username).await;
        }
        Ok(())
    }

    fn provider_name(&self) -> &str {
        "composite"
    }

    fn supported_methods(&self) -> &[AuthMethod] {
        // This is a limitation - we'd need to aggregate from all providers
        &[
            AuthMethod::Password,
            AuthMethod::Certificate,
            AuthMethod::ApiKey,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_password() {
        let creds = Credentials::password("user", "pass");
        assert!(matches!(creds, Credentials::Password { .. }));
        assert_eq!(creds.auth_method(), AuthMethod::Password);
    }

    #[test]
    fn test_credentials_certificate() {
        let creds = Credentials::certificate(vec![vec![1, 2, 3]]);
        assert!(matches!(creds, Credentials::Certificate { .. }));
        assert_eq!(creds.auth_method(), AuthMethod::Certificate);
    }

    #[test]
    fn test_credentials_api_key() {
        let creds = Credentials::api_key("my-api-key");
        assert!(matches!(creds, Credentials::ApiKey { .. }));
        assert_eq!(creds.auth_method(), AuthMethod::ApiKey);
    }
}
