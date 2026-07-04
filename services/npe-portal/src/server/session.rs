//! NPE Portal session management.
//!
//! Sessions are minted after a successful mTLS handshake + OID->role resolution,
//! and are process-local/in-memory (ephemeral by design for a stateless BFF; the
//! client re-authenticates by re-presenting its certificate). Two NPE-specific
//! properties beyond the admin web-ui session:
//!
//! - `accepted_consent`: the USG consent banner must be acknowledged before any
//!   proxied API call is permitted (the session exists but is "gated" until OK).
//! - 30-minute inactivity timeout (NPE portal requirement; NIAP PP-CA FTA_SSL.1).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-12 (Session Termination), SC-23 (Session Authenticity)
//! - NIAP PP-CA: FTA_SSL.1 (inactivity lock), FTA_SSL.3 (termination)

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use chrono::{DateTime, Duration, Utc};
use ostrich_common::auth::Role;
use ostrich_common::util::random::secure_random_bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

const SESSION_TOKEN_LENGTH: usize = 32;

/// Server-side session data for an authenticated NPE operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Opaque session id (for audit correlation).
    pub id: String,
    /// Certificate Common Name (e.g. LAST.FIRST.M.ID_NUMBER).
    pub common_name: String,
    /// Full RFC 4514 subject DN.
    pub subject_dn: String,
    /// Resolved NPE role names (e.g. "pki_sponsor").
    pub roles: Vec<String>,
    /// SHA-256 hex fingerprint of the client certificate that minted this
    /// session. Every request that presents a cert is checked against this so a
    /// leaked cookie cannot be replayed under a different mTLS identity
    /// (NIST SC-23 session authenticity).
    pub cert_fingerprint: String,
    /// Whether the USG consent banner has been acknowledged this session.
    pub accepted_consent: bool,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Whether the session has locked due to inactivity.
    pub locked: bool,
}

impl SessionData {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn should_lock(&self, inactivity_timeout: Duration) -> bool {
        Utc::now() > self.last_activity + inactivity_timeout
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// In-memory session manager.
pub struct SessionManager {
    sessions: RwLock<HashMap<String, SessionData>>,
    inactivity_timeout: Duration,
    absolute_timeout: Duration,
}

impl SessionManager {
    pub fn new(inactivity_timeout_secs: i64, absolute_timeout_secs: i64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            inactivity_timeout: Duration::seconds(inactivity_timeout_secs),
            absolute_timeout: Duration::seconds(absolute_timeout_secs),
        }
    }

    fn generate_token() -> String {
        BASE64.encode(secure_random_bytes(SESSION_TOKEN_LENGTH))
    }

    /// Create a new session. `accepted_consent` starts `false`: the USG consent
    /// banner must be acknowledged before the session can be used for API calls.
    pub async fn create_session(
        &self,
        common_name: String,
        subject_dn: String,
        roles: Vec<Role>,
        cert_fingerprint: String,
    ) -> (String, SessionData) {
        let token = Self::generate_token();
        let now = Utc::now();
        let session = SessionData {
            id: Uuid::new_v4().to_string(),
            common_name,
            subject_dn,
            roles: roles.iter().map(|r| r.name().to_string()).collect(),
            cert_fingerprint,
            accepted_consent: false,
            created_at: now,
            last_activity: now,
            expires_at: now + self.absolute_timeout,
            locked: false,
        };
        self.sessions
            .write()
            .await
            .insert(token.clone(), session.clone());
        self.purge_expired().await;
        tracing::info!(
            session_id = %session.id,
            cn = %session.common_name,
            roles = ?session.roles,
            "NPE session created (consent pending)"
        );
        (token, session)
    }

    /// Validate a token: enforces absolute expiry and the inactivity lock.
    ///
    /// `refresh` controls whether last-activity is reset. Pass `true` only for
    /// genuine user activity (a proxied API call); pass `false` for passive
    /// probes (session/userinfo polling) so background refetches cannot hold the
    /// 30-minute inactivity timer open indefinitely (NIAP FTA_SSL.1).
    pub async fn validate_session(&self, token: &str, refresh: bool) -> Option<SessionData> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get(token)?.clone();

        if session.is_expired() {
            sessions.remove(token);
            return None;
        }

        if session.should_lock(self.inactivity_timeout) {
            if !session.locked {
                let mut locked = session.clone();
                locked.locked = true;
                sessions.insert(token.to_string(), locked.clone());
                return Some(locked);
            }
            return Some(session);
        }

        if refresh {
            let mut active = session;
            active.touch();
            sessions.insert(token.to_string(), active.clone());
            Some(active)
        } else {
            Some(session)
        }
    }

    /// Acknowledge the USG consent banner for a session. Returns the updated
    /// session, or `None` if the token is unknown, expired, or already locked
    /// for inactivity (a locked session must re-authenticate, not be revived
    /// through the consent path — FTA_SSL.1).
    pub async fn accept_consent(&self, token: &str) -> Option<SessionData> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get(token)?.clone();
        if session.is_expired() {
            sessions.remove(token);
            return None;
        }
        if session.locked || session.should_lock(self.inactivity_timeout) {
            return None;
        }
        let mut updated = session;
        updated.accepted_consent = true;
        updated.touch();
        sessions.insert(token.to_string(), updated.clone());
        tracing::info!(session_id = %updated.id, "USG consent acknowledged");
        Some(updated)
    }

    /// Invalidate (delete) a session.
    pub async fn invalidate_session(&self, token: &str) -> bool {
        self.sessions.write().await.remove(token).is_some()
    }

    async fn purge_expired(&self) {
        self.sessions.write().await.retain(|_, s| !s.is_expired());
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consent_starts_false_and_can_be_accepted() {
        let mgr = SessionManager::new(1800, 28800);
        let (token, session) = mgr
            .create_session(
                "DOE.JOHN.A.123".to_string(),
                "CN=DOE.JOHN.A.123".to_string(),
                vec![Role::PkiSponsor],
                "fp".to_string(),
            )
            .await;
        assert!(!session.accepted_consent);

        let updated = mgr.accept_consent(&token).await.unwrap();
        assert!(updated.accepted_consent);

        let validated = mgr.validate_session(&token, false).await.unwrap();
        assert!(validated.accepted_consent);
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let mgr = SessionManager::new(1800, 28800);
        assert!(mgr.validate_session("nope", true).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_removes_session() {
        let mgr = SessionManager::new(1800, 28800);
        let (token, _) = mgr
            .create_session(
                "x".to_string(),
                "CN=x".to_string(),
                vec![Role::CaaAdmin],
                "fp".to_string(),
            )
            .await;
        assert!(mgr.invalidate_session(&token).await);
        assert!(mgr.validate_session(&token, true).await.is_none());
    }

    #[tokio::test]
    async fn session_binds_cert_fingerprint() {
        let mgr = SessionManager::new(1800, 28800);
        let (token, session) = mgr
            .create_session(
                "x".to_string(),
                "CN=x".to_string(),
                vec![Role::PkiSponsor],
                "abc123".to_string(),
            )
            .await;
        assert_eq!(session.cert_fingerprint, "abc123");
        let validated = mgr.validate_session(&token, false).await.unwrap();
        assert_eq!(validated.cert_fingerprint, "abc123");
    }

    #[tokio::test]
    async fn inactive_session_locks_and_blocks_consent() {
        // Zero inactivity window: the session is immediately past the lock
        // threshold, so consent must be refused (must re-authenticate).
        let mgr = SessionManager::new(0, 28800);
        let (token, _) = mgr
            .create_session(
                "x".to_string(),
                "CN=x".to_string(),
                vec![Role::PkiSponsor],
                "fp".to_string(),
            )
            .await;
        assert!(mgr.accept_consent(&token).await.is_none());
        let locked = mgr.validate_session(&token, true).await.unwrap();
        assert!(locked.locked);
    }
}
