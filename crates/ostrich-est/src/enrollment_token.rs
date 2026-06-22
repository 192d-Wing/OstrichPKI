//! Single-use, time-limited EST enrollment tokens (RFC 7030 bootstrap).
//!
//! An operator with `Permission::GenerateEstToken` mints a bearer token bound to
//! a specific device identity. [`EnrollmentTokenAuthProvider`] wraps the normal
//! session [`AuthProvider`] so that, when such a token is presented to an EST
//! enrollment endpoint, it resolves to a least-privilege principal whose
//! username is the token's pinned identity and whose only permission is
//! `SubmitRequest` (via [`Role::EstEnrollee`]). The EST H1 binding then forces
//! the CSR's CN/SAN to equal that identity, and the enroll handler consumes the
//! token on success so it cannot be reused.
//!
//! Any token that is not a live enrollment token falls through to the inner
//! provider unchanged (normal operator/session authentication), so this wrapper
//! is transparent to every existing auth path.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege),
//!   IA-5 (authenticator management)
//! - NIAP PP-CA: FDP_CER_EXT.1 (enrollment), FMT_MTD.1 (credential management)

use async_trait::async_trait;
use ostrich_common::auth::{
    AuthMethod, AuthProvider, AuthResult, AuthenticatedUser, Credentials, Role, SessionInfo, UserId,
};
use ostrich_db::repository::EstRepository;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// SHA-256 of a presented bearer token, matching the `token_hash` column.
pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Auth provider that accepts single-use EST enrollment tokens, delegating
/// everything else to an inner (session) provider.
pub struct EnrollmentTokenAuthProvider {
    tokens: EstRepository,
    inner: Arc<dyn AuthProvider>,
}

impl EnrollmentTokenAuthProvider {
    /// Wrap `inner`, matching presented tokens against the enrollment-token store.
    pub fn new(tokens: EstRepository, inner: Arc<dyn AuthProvider>) -> Self {
        Self { tokens, inner }
    }
}

#[async_trait]
impl AuthProvider for EnrollmentTokenAuthProvider {
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
        self.inner.authenticate(credentials).await
    }

    async fn validate_session(&self, token: &str) -> AuthResult<SessionInfo> {
        // Try the enrollment-token store first. A live (unused, unexpired) token
        // yields a pinned, least-privilege principal. A DB error is treated as
        // "not an enrollment token" and falls through — the inner provider then
        // fails closed for an unknown token.
        match self
            .tokens
            .find_live_enrollment_token(&hash_token(token))
            .await
        {
            Ok(Some((id, identity, expires_at))) => Ok(SessionInfo {
                token: token.to_string(),
                user: AuthenticatedUser::new(
                    UserId::from_uuid(id),
                    identity,
                    vec![Role::EstEnrollee],
                    // A bearer enrollment token is an API-key-style credential.
                    AuthMethod::ApiKey,
                ),
                expires_at: expires_at.timestamp(),
                is_valid: true,
            }),
            Ok(None) => self.inner.validate_session(token).await,
            Err(e) => {
                tracing::warn!(error = %e, "EST enrollment-token lookup failed; trying session auth");
                self.inner.validate_session(token).await
            }
        }
    }

    async fn create_session(&self, user: &AuthenticatedUser) -> AuthResult<SessionInfo> {
        self.inner.create_session(user).await
    }

    async fn invalidate_session(&self, token: &str) -> AuthResult<()> {
        self.inner.invalidate_session(token).await
    }

    async fn record_failed_attempt(&self, username: &str, reason: &str) -> AuthResult<()> {
        self.inner.record_failed_attempt(username, reason).await
    }

    async fn is_account_locked(&self, username: &str) -> AuthResult<bool> {
        self.inner.is_account_locked(username).await
    }

    async fn unlock_account(&self, username: &str) -> AuthResult<()> {
        self.inner.unlock_account(username).await
    }

    fn provider_name(&self) -> &str {
        "est-enrollment-token"
    }

    fn supported_methods(&self) -> &[AuthMethod] {
        self.inner.supported_methods()
    }
}
