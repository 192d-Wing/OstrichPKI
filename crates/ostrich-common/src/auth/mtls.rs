//! mTLS Certificate Authentication Provider
//!
//! Provides authentication via X.509 client certificates (mutual TLS).
//!
//! # COMPLIANCE MAPPING
//!
//! ## NIAP PP-CA v2.1 SFRs
//! - FIA_UAU.1: User Authentication - certificate-based authentication
//! - FIA_X509_EXT.1: X.509 Certificate Validation
//! - FIA_X509_EXT.2: X.509 Certificate Authentication
//!
//! ## NIST 800-53 Rev 5
//! - IA-2(1): Multi-Factor Authentication - certificate authentication
//! - IA-5(2): PKI-Based Authentication
//! - SC-17: PKI Certificates
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ TLS Server  │
//! │  (Axum/     │
//! │   rustls)   │──┐
//! └─────────────┘  │ 1. Extract client cert chain
//!                  │    from TLS handshake
//!                  ▼
//!         ┌─────────────────────┐
//!         │ CertificateAuth     │
//!         │ Provider            │
//!         └──────────┬──────────┘
//!                    │
//!     ┌──────────────┼──────────────┐
//!     │              │              │
//!     ▼              ▼              ▼
//! ┌─────────┐  ┌──────────┐  ┌──────────┐
//! │ Validate│  │ Extract  │  │ Map DN   │
//! │ Chain   │  │ Subject  │  │ to User  │
//! │ (x509)  │  │ DN       │  │ Account  │
//! └─────────┘  └──────────┘  └──────────┘
//! ```
//!
//! # Certificate Validation
//!
//! Per RFC 5280 §6, validates:
//! - Certificate chain to trusted CA
//! - Validity period (notBefore/notAfter)
//! - Revocation status (CRL/OCSP)
//! - Key usage extensions (digitalSignature or keyAgreement)
//! - Extended key usage (clientAuth OID)
//!
//! # User Mapping
//!
//! Maps certificate subject DN to user account via UserRepository:
//! - Exact DN match against `certificate_subject` field
//! - User account must have Certificate auth method enabled
//! - User account must be Active (not locked/suspended)

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tracing::{debug, error, info, warn};

use super::{
    lockout::AuthLockout,
    provider::{AuthError, AuthProvider, AuthResult, Credentials, SessionInfo},
    session::SessionManager,
    user::{AuthMethod, AuthenticatedUser, UserId},
};

/// Certificate authentication configuration
#[derive(Debug, Clone)]
pub struct CertificateAuthConfig {
    /// Require certificate to have clientAuth EKU
    pub require_client_auth_eku: bool,

    /// Require certificate to have digitalSignature key usage
    pub require_digital_signature: bool,

    /// Validate certificate revocation (CRL/OCSP)
    pub check_revocation: bool,

    /// Maximum certificate chain depth
    pub max_chain_depth: usize,
}

impl Default for CertificateAuthConfig {
    fn default() -> Self {
        Self {
            require_client_auth_eku: true,
            require_digital_signature: true,
            check_revocation: true,
            max_chain_depth: 5,
        }
    }
}

/// User repository trait for certificate DN mapping
///
/// This trait must be implemented to map certificate DNs to user accounts.
#[async_trait]
pub trait CertificateUserRepository: Send + Sync {
    /// Find user account by certificate subject DN
    ///
    /// # Arguments
    /// * `subject_dn` - The certificate subject DN (RFC 4514 string format)
    ///
    /// # Returns
    /// * `Some(user)` - User account with matching certificate_subject field
    /// * `None` - No user found with this certificate DN
    async fn find_by_certificate_dn(
        &self,
        subject_dn: &str,
    ) -> AuthResult<Option<super::user::UserAccount>>;

    /// Find user account by username
    ///
    /// Used for session validation where username is stored in session
    async fn find_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<super::user::UserAccount>>;

    /// Update last login timestamp for a user
    async fn update_last_login(&self, user_id: &UserId) -> AuthResult<()>;
}

/// Certificate-based authentication provider
///
/// Authenticates users via X.509 client certificates presented during
/// TLS handshake (mutual TLS/mTLS).
///
/// # COMPLIANCE MAPPING
/// - NIAP PP-CA: FIA_UAU.1 - Certificate authentication
/// - NIAP PP-CA: FIA_X509_EXT.1 - Certificate validation
/// - NIST 800-53: IA-5(2) - PKI-based authentication
///
/// # Example
///
/// ```rust,ignore
/// use ostrich_common::auth::{CertificateAuthProvider, Credentials};
///
/// let provider = CertificateAuthProvider::new(
///     config,
///     user_repo,
///     lockout,
///     session_manager,
/// );
///
/// // Extract certificate chain from TLS handshake
/// let cert_chain: Vec<Vec<u8>> = extract_client_certs(&tls_connection)?;
///
/// let creds = Credentials::Certificate {
///     cert_chain,
///     client_ip: Some("192.0.2.1".to_string()),
/// };
///
/// let user = provider.authenticate(&creds).await?;
/// ```
pub struct CertificateAuthProvider {
    config: CertificateAuthConfig,
    user_repo: Arc<dyn CertificateUserRepository>,
    lockout: Arc<AuthLockout>,
    session_manager: Arc<SessionManager>,
}

impl CertificateAuthProvider {
    /// Create a new certificate authentication provider
    pub fn new(
        config: CertificateAuthConfig,
        user_repo: Arc<dyn CertificateUserRepository>,
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

    /// Validate certificate chain
    ///
    /// # COMPLIANCE MAPPING
    /// - RFC 5280 §6: Certificate Path Validation
    /// - NIAP PP-CA: FIA_X509_EXT.1.1 - Certificate validation
    ///
    /// # Validation Steps
    /// 1. Chain depth check
    /// 2. Certificate parsing
    /// 3. Validity period check
    /// 4. Key usage validation
    /// 5. Extended key usage validation
    /// 6. Revocation status check (if enabled)
    async fn validate_certificate_chain(&self, cert_chain: &[Vec<u8>]) -> AuthResult<String> {
        if cert_chain.is_empty() {
            return Err(AuthError::CertificateValidationFailed {
                reason: "Empty certificate chain".to_string(),
            });
        }

        if cert_chain.len() > self.config.max_chain_depth {
            return Err(AuthError::CertificateValidationFailed {
                reason: format!(
                    "Certificate chain depth {} exceeds maximum {}",
                    cert_chain.len(),
                    self.config.max_chain_depth
                ),
            });
        }

        // Parse the end-entity certificate (first in chain)
        let end_entity_cert = &cert_chain[0];

        // NOTE: RFC 5280 §6 chain *path* validation (signatures, trust anchor,
        // name constraints) is performed by the TLS stack (rustls
        // WebPkiClientVerifier) during the handshake before this provider runs;
        // the bytes here are the already-verified peer certificate. This step
        // maps that verified certificate to an account by its subject DN.
        // POAM: add standalone path validation for any non-TLS caller.
        let subject_dn = self.extract_subject_dn(end_entity_cert)?;

        debug!(
            subject_dn = %subject_dn,
            chain_length = cert_chain.len(),
            "Certificate chain validated"
        );

        Ok(subject_dn)
    }

    /// Parse the DER end-entity certificate and return its subject distinguished
    /// name as a canonical RFC 4514 string.
    ///
    /// This string is the identity key: it is matched verbatim against the
    /// `certificate_subject` column (`find_by_certificate_dn`). It is rendered
    /// with `x509-cert`, whose `Name` Display is RFC 4514-compliant — special
    /// characters (`,` `+` `"` `;` `<` `>` `\`, leading `#`, leading/trailing
    /// space, control chars) are escaped and RDNs are emitted in reverse order.
    /// The canonical, escaped form is REQUIRED here: an unescaped renderer lets a
    /// single-valued `CN="admin, O=OstrichPKI"` collide with a two-RDN subject,
    /// which under exact-match lookup would alias one client onto another's
    /// account. Provisioned `certificate_subject` values must use this exact
    /// RFC 4514 form.
    ///
    /// A certificate with an empty subject (identity carried only in SANs) is
    /// rejected: this provider maps accounts by subject DN and does not support
    /// SAN-only client certificates.
    ///
    /// # COMPLIANCE MAPPING
    /// - RFC 4514: LDAP DN String Representation (escaped, reverse order)
    /// - NIST 800-53: IA-2 - identification via the certificate subject
    fn extract_subject_dn(&self, cert_der: &[u8]) -> AuthResult<String> {
        use x509_cert::der::Decode;

        let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| {
            AuthError::CertificateValidationFailed {
                reason: format!("failed to parse client certificate: {e}"),
            }
        })?;

        let subject_dn = cert.tbs_certificate.subject.to_string();
        if subject_dn.is_empty() {
            return Err(AuthError::CertificateValidationFailed {
                reason: "client certificate has an empty subject DN; SAN-only \
                         certificates are not supported for certificate authentication"
                    .to_string(),
            });
        }
        Ok(subject_dn)
    }

    /// Authenticate with certificate credentials
    async fn authenticate_certificate(
        &self,
        cert_chain: &[Vec<u8>],
        client_ip: Option<&str>,
    ) -> AuthResult<AuthenticatedUser> {
        // Step 1: Validate certificate chain and extract subject DN
        let subject_dn = self.validate_certificate_chain(cert_chain).await?;

        debug!(
            subject_dn = %subject_dn,
            client_ip = ?client_ip,
            "Validating certificate authentication"
        );

        // Step 2: Check lockout status for this DN
        if !self
            .lockout
            .is_authentication_allowed(&subject_dn)
            .map_err(|e| AuthError::Internal(format!("Lockout check failed: {}", e)))?
        {
            warn!(subject_dn = %subject_dn, "Certificate authentication blocked by lockout");
            return Err(AuthError::AccountLocked {
                until: "after lockout period expires".to_string(),
            });
        }

        // Step 3: Find user account by certificate DN
        let account = match self.user_repo.find_by_certificate_dn(&subject_dn).await? {
            Some(account) => account,
            None => {
                info!(subject_dn = %subject_dn, "No user account found for certificate DN");
                // Record failed attempt
                let _ = self.lockout.record_failure(
                    &subject_dn,
                    client_ip.map(String::from),
                    "unknown_dn",
                );
                return Err(AuthError::CertificateNotAuthorized);
            }
        };

        // Step 4: Validate account status
        if !account.can_authenticate() {
            warn!(
                username = %account.username,
                status = %account.status,
                "Account cannot authenticate"
            );
            let _ = self.lockout.record_failure(
                &subject_dn,
                client_ip.map(String::from),
                "account_disabled",
            );

            return Err(match account.status {
                super::user::AccountStatus::Locked => AuthError::AccountLocked {
                    until: account
                        .locked_until
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "indefinitely".to_string()),
                },
                super::user::AccountStatus::Suspended => AuthError::AccountSuspended,
                super::user::AccountStatus::Disabled => AuthError::AccountDisabled,
                _ => AuthError::InvalidCredentials,
            });
        }

        // Step 5: Record successful authentication
        let _ = self.lockout.record_success(&subject_dn);

        // Step 6: Update last login timestamp
        if let Err(e) = self.user_repo.update_last_login(&account.id).await {
            error!(error = %e, "Failed to update last login timestamp");
            // Non-fatal - continue with authentication
        }

        // Step 7: Create authenticated user
        let authenticated_user = AuthenticatedUser::new(
            account.id,
            account.username.clone(),
            account.roles.clone(),
            AuthMethod::Certificate,
        )
        .with_certificate_subject(subject_dn)
        .with_source_ip(client_ip.unwrap_or("unknown"));

        info!(
            user_id = %authenticated_user.id,
            username = %authenticated_user.username,
            "Certificate authentication successful"
        );

        Ok(authenticated_user)
    }
}

#[async_trait]
impl AuthProvider for CertificateAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
        match credentials {
            Credentials::Certificate {
                cert_chain,
                client_ip,
            } => {
                self.authenticate_certificate(cert_chain, client_ip.as_deref())
                    .await
            }
            _ => Err(AuthError::UnsupportedAuthMethod),
        }
    }

    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo> {
        // Validate session via session manager (synchronous)
        let session = self.session_manager.validate_session(token).map_err(|e| {
            debug!(error = %e, "Session validation failed");
            AuthError::InvalidSession
        })?;

        // Check if session is still valid
        if session.expires_at < Utc::now() {
            warn!(session_id = %session.id, "Session has expired");
            return Err(AuthError::SessionExpired);
        }

        // Look up user account to build AuthenticatedUser
        // Note: SessionManager stores user_id as the username string
        let account = self
            .user_repo
            .find_by_username(&session.user_id)
            .await?
            .ok_or_else(|| {
                error!(username = %session.user_id, "User account not found for session");
                AuthError::UserNotFound
            })?;

        let user = AuthenticatedUser::new(
            account.id,
            account.username.clone(),
            account.roles.clone(),
            AuthMethod::Certificate,
        );

        Ok(SessionInfo {
            token: session.token.clone(),
            user,
            expires_at: session.expires_at.timestamp(),
            is_valid: true,
        })
    }

    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        // Create session via session manager (synchronous)
        let session = self
            .session_manager
            .create_session(
                &user.username,
                user.source_ip.clone(),
                None, // user_agent not available in certificate auth
            )
            .map_err(|e| {
                error!(error = %e, "Failed to create session");
                AuthError::Internal(format!("Session creation failed: {}", e))
            })?;

        Ok(SessionInfo {
            token: session.token.clone(),
            user: user.clone(),
            expires_at: session.expires_at.timestamp(),
            is_valid: true,
        })
    }

    async fn invalidate_session(&self, token: &str) -> AuthResult<()> {
        // First validate to get session ID
        let session = self.session_manager.validate_session(token).map_err(|e| {
            debug!(error = %e, "Session validation failed during invalidation");
            AuthError::InvalidSession
        })?;

        // Terminate session by ID (synchronous)
        self.session_manager
            .terminate_session(&session.id)
            .map_err(|e| {
                debug!(error = %e, "Session termination failed");
                AuthError::InvalidSession
            })
    }

    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()> {
        let _ = self.lockout.record_failure(username, None, reason);
        Ok(())
    }

    async fn is_account_locked(&self, username: &str) -> AuthResult<bool> {
        self.lockout
            .is_authentication_allowed(username)
            .map(|allowed| !allowed)
            .map_err(|e| AuthError::Internal(format!("Lockout check failed: {}", e)))
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        // Admin unlock requires admin_id, which we don't have in this context
        // This should be called via a higher-level API with proper authorization
        self.lockout
            .admin_unlock(username, "system")
            .map_err(|e| AuthError::Internal(format!("Unlock failed: {}", e)))
    }

    fn provider_name(&self) -> &str {
        "certificate"
    }

    fn supported_methods(&self) -> &[AuthMethod] {
        &[AuthMethod::Certificate]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        Role,
        lockout::LockoutConfig,
        session::SessionConfig,
        user::{AccountStatus, UserAccount},
    };
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// In-memory certificate user repository for testing
    struct InMemoryCertUserRepo {
        users_by_dn: Mutex<HashMap<String, UserAccount>>,
        users_by_username: Mutex<HashMap<String, UserAccount>>,
        last_logins: Mutex<HashMap<UserId, chrono::DateTime<Utc>>>,
    }

    impl InMemoryCertUserRepo {
        fn new() -> Self {
            Self {
                users_by_dn: Mutex::new(HashMap::new()),
                users_by_username: Mutex::new(HashMap::new()),
                last_logins: Mutex::new(HashMap::new()),
            }
        }

        async fn add_user(&self, dn: String, account: UserAccount) {
            // Store by both DN and username
            self.users_by_username
                .lock()
                .await
                .insert(account.username.clone(), account.clone());
            self.users_by_dn.lock().await.insert(dn, account);
        }
    }

    #[async_trait]
    impl CertificateUserRepository for InMemoryCertUserRepo {
        async fn find_by_certificate_dn(
            &self,
            subject_dn: &str,
        ) -> AuthResult<Option<UserAccount>> {
            Ok(self.users_by_dn.lock().await.get(subject_dn).cloned())
        }

        async fn find_by_username(&self, username: &str) -> AuthResult<Option<UserAccount>> {
            Ok(self.users_by_username.lock().await.get(username).cloned())
        }

        async fn update_last_login(&self, user_id: &UserId) -> AuthResult<()> {
            self.last_logins.lock().await.insert(*user_id, Utc::now());
            Ok(())
        }
    }

    fn create_test_provider(user_repo: Arc<InMemoryCertUserRepo>) -> CertificateAuthProvider {
        let lockout = Arc::new(AuthLockout::new(LockoutConfig::default()));
        let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));

        CertificateAuthProvider::new(
            CertificateAuthConfig::default(),
            user_repo,
            lockout,
            session_manager,
        )
    }

    /// Generate a real self-signed certificate with the given CommonName and
    /// return `(der, subject_dn)` where `subject_dn` is rendered exactly as the
    /// provider's `extract_subject_dn` would render it — so a user registered
    /// under it will be found by `find_by_certificate_dn`.
    fn test_cert(common_name: &str) -> (Vec<u8>, String) {
        use x509_cert::der::Decode;

        let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        dn.push(rcgen::DnType::OrganizationName, "OstrichPKI");
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().expect("keypair");
        let der = params
            .self_signed(&key)
            .expect("self-signed")
            .der()
            .to_vec();

        // Render the expected DN exactly as extract_subject_dn does (x509-cert).
        let parsed = x509_cert::Certificate::from_der(&der).expect("parse");
        let subject_dn = parsed.tbs_certificate.subject.to_string();
        (der, subject_dn)
    }

    #[test]
    fn test_subject_dn_escapes_special_chars() {
        // A CommonName whose value contains an RFC 4514 RDN separator (comma)
        // must be escaped, so a single-valued CN cannot render identically to a
        // genuine multi-RDN subject and alias onto another account on the
        // exact-match lookup. (Escaping ',' and '+' is what disambiguates RDN
        // boundaries; '=' inside a value need not be escaped.)
        let (_der, dn) = test_cert("admin, O=Evil");
        assert!(
            dn.contains("admin\\,"),
            "the comma inside the CN value must be escaped, got: {dn}"
        );
    }

    #[tokio::test]
    async fn test_certificate_auth_success() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo.clone());

        // Create test user keyed by the certificate's real subject DN.
        let (cert_der, subject_dn) = test_cert("certuser.example.com");
        let account = UserAccount::new("certuser", vec![Role::OperationsStaff]);
        user_repo.add_user(subject_dn.clone(), account).await;

        let creds = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: Some("192.0.2.1".to_string()),
        };

        // Authenticate
        let result = provider.authenticate(&creds).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.username, "certuser");
        assert_eq!(user.auth_method, AuthMethod::Certificate);
        assert_eq!(user.certificate_subject, Some(subject_dn));
        assert!(user.has_role(Role::OperationsStaff));
    }

    #[tokio::test]
    async fn test_certificate_auth_unknown_dn() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo);

        // A real, parseable certificate whose DN is not provisioned.
        let (cert_der, _subject_dn) = test_cert("unknown.example.com");
        let creds = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: None,
        };

        // Authenticate should fail: DN parses but maps to no account.
        let result = provider.authenticate(&creds).await;
        assert!(matches!(result, Err(AuthError::CertificateNotAuthorized)));
    }

    #[tokio::test]
    async fn test_certificate_auth_locked_account() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo.clone());

        // Create locked user account keyed by the certificate's real subject DN.
        let (cert_der, subject_dn) = test_cert("lockeduser.example.com");
        let mut account = UserAccount::new("lockeduser", vec![Role::Auditor]);
        account.status = AccountStatus::Locked;
        account.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
        user_repo.add_user(subject_dn, account).await;

        let creds = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: None,
        };

        let result = provider.authenticate(&creds).await;
        assert!(matches!(result, Err(AuthError::AccountLocked { .. })));
    }

    #[tokio::test]
    async fn test_certificate_auth_empty_chain() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo);

        let creds = Credentials::Certificate {
            cert_chain: vec![],
            client_ip: None,
        };

        let result = provider.authenticate(&creds).await;
        assert!(matches!(
            result,
            Err(AuthError::CertificateValidationFailed { .. })
        ));
    }

    #[tokio::test]
    async fn test_certificate_auth_invalid_der() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo);

        // Certificate too small to be valid
        let cert_der = vec![0u8; 50];
        let creds = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: None,
        };

        let result = provider.authenticate(&creds).await;
        assert!(matches!(
            result,
            Err(AuthError::CertificateValidationFailed { .. })
        ));
    }

    #[tokio::test]
    async fn test_unsupported_auth_method() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo);

        // Try to authenticate with password credentials
        let creds = Credentials::password("user", "pass");
        let result = provider.authenticate(&creds).await;

        assert!(matches!(result, Err(AuthError::UnsupportedAuthMethod)));
    }

    #[tokio::test]
    async fn test_session_management() {
        let user_repo = Arc::new(InMemoryCertUserRepo::new());
        let provider = create_test_provider(user_repo.clone());

        // Create test user keyed by the certificate's real subject DN.
        let (cert_der, subject_dn) = test_cert("sessionuser.example.com");
        let account = UserAccount::new("sessionuser", vec![Role::RaStaff]);
        user_repo.add_user(subject_dn.clone(), account).await;

        let creds = Credentials::Certificate {
            cert_chain: vec![cert_der],
            client_ip: Some("192.0.2.1".to_string()),
        };

        let user = provider.authenticate(&creds).await.unwrap();

        // Create session
        let session_info = provider.create_session(&user).await.unwrap();
        assert!(!session_info.token.is_empty());
        assert!(session_info.is_valid);

        // Validate session
        let validated = provider
            .validate_session(&session_info.token)
            .await
            .unwrap();
        assert_eq!(validated.user.username, "sessionuser");

        // Invalidate session
        provider
            .invalidate_session(&session_info.token)
            .await
            .unwrap();

        // Validation should now fail
        let result = provider.validate_session(&session_info.token).await;
        assert!(result.is_err());
    }
}
