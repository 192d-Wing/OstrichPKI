//! Session Management
//!
//! Manages web-UI user sessions after OIDC (or internal-auth) login.
//!
//! ## Durability: ephemeral by design
//!
//! Web-UI sessions are intentionally **in-memory and process-local** — they do
//! not survive a restart and are not shared across instances. This is a
//! deliberate choice for a stateless BFF, not an oversight:
//!
//! - On restart, users simply re-authenticate via OIDC, which is cheap and
//!   already the expected flow when an id-token expires.
//! - [`SessionData::backend_token`] (the upstream CA credential used to proxy in
//!   internal-auth mode) is `#[serde(skip_serializing)]` and **cannot be
//!   persisted** — it is a live per-login bearer token. A restored session would
//!   therefore be unable to proxy until the user re-authenticated anyway, so
//!   persisting the rest buys little in that mode.
//!
//! Storage is nonetheless kept behind the [`WebUiSessionStore`] trait so a
//! durable backend (database or Redis, for multi-instance deployments) can be
//! dropped in later via [`SessionManager::with_store`] without touching the
//! session-policy logic. The default is [`InMemoryWebUiSessionStore`].
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-12 (Session Termination)
//! - NIST 800-53: SC-23 (Session Authenticity)
//! - NIAP PP-CA: FTA_SSL.1 (TSF-initiated Session Locking)
//! - NIAP PP-CA: FTA_SSL.3 (TSF-initiated Session Termination)

#![allow(dead_code)] // Some lifecycle helpers are used only by future integration

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use ostrich_common::util::random::secure_random_bytes;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Session token length in bytes
const SESSION_TOKEN_LENGTH: usize = 32;

/// Session data stored server-side
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session ID
    pub id: String,

    /// User subject (from OIDC)
    pub user_subject: String,

    /// Username
    pub username: Option<String>,

    /// User email
    pub email: Option<String>,

    /// User roles
    pub roles: Vec<String>,

    /// Session creation time
    pub created_at: DateTime<Utc>,

    /// Last activity time
    pub last_activity: DateTime<Utc>,

    /// Session expiration (absolute)
    pub expires_at: DateTime<Utc>,

    /// Whether the session is locked (requires re-authentication)
    pub locked: bool,

    /// Backend credential to present to upstream services when proxying.
    ///
    /// In internal-auth mode this holds the CA's own bearer token (obtained
    /// from `POST /api/v1/auth/login`), so the proxy authenticates each request
    /// to the CA as the actual admin rather than relying on network position
    /// (closes the confused-deputy gap). `None` in OIDC mode.
    ///
    /// `skip_serializing`: this is a live credential and is never written to any
    /// durable store; it lives only in process memory for the session's lifetime.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AC-3 (Access Enforcement) - end-to-end authenticated proxy
    /// - NIST 800-53: IA-2 - the upstream call carries the user's own credential
    #[serde(default, skip_serializing)]
    pub backend_token: Option<String>,
}

impl SessionData {
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session should be locked due to inactivity
    pub fn should_lock(&self, inactivity_timeout: Duration) -> bool {
        Utc::now() > self.last_activity + inactivity_timeout
    }

    /// Update last activity time
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Pluggable storage backend for web-UI sessions, keyed by session token.
///
/// The default [`InMemoryWebUiSessionStore`] is process-local (ephemeral by
/// design — see the module docs). A durable implementation (database/Redis) can
/// be supplied via [`SessionManager::with_store`] for multi-instance
/// deployments without changing the session-policy logic in [`SessionManager`].
#[async_trait]
pub trait WebUiSessionStore: Send + Sync {
    /// Store a session under its token.
    async fn insert(&self, token: String, data: SessionData);

    /// Fetch a session by token.
    async fn get(&self, token: &str) -> Option<SessionData>;

    /// Persist mutated session fields. Must not create a session that is absent
    /// (an update to a removed token is a no-op).
    async fn update(&self, token: &str, data: SessionData);

    /// Remove a session, returning it if present.
    async fn remove(&self, token: &str) -> Option<SessionData>;

    /// Drop all expired sessions; returns how many were removed.
    async fn purge_expired(&self) -> usize;

    /// Number of stored sessions (for monitoring).
    async fn count(&self) -> usize;
}

/// In-memory [`WebUiSessionStore`] (process-local, non-durable).
#[derive(Default)]
pub struct InMemoryWebUiSessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
}

impl InMemoryWebUiSessionStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WebUiSessionStore for InMemoryWebUiSessionStore {
    async fn insert(&self, token: String, data: SessionData) {
        self.sessions.write().await.insert(token, data);
    }

    async fn get(&self, token: &str) -> Option<SessionData> {
        self.sessions.read().await.get(token).cloned()
    }

    async fn update(&self, token: &str, data: SessionData) {
        let mut sessions = self.sessions.write().await;
        // Only update an existing entry; never resurrect a removed session.
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            sessions.entry(token.to_string())
        {
            e.insert(data);
        }
    }

    async fn remove(&self, token: &str) -> Option<SessionData> {
        self.sessions.write().await.remove(token)
    }

    async fn purge_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        before - sessions.len()
    }

    async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

/// Session manager.
///
/// Owns session policy (token generation, inactivity locking, absolute expiry)
/// over a pluggable [`WebUiSessionStore`]. The default store is in-memory; see
/// the module docs for why web-UI sessions are ephemeral by design.
pub struct SessionManager {
    /// Backing store (token -> session data)
    store: Arc<dyn WebUiSessionStore>,

    /// Inactivity timeout
    inactivity_timeout: Duration,

    /// Absolute session timeout
    absolute_timeout: Duration,
}

impl SessionManager {
    /// Create a session manager backed by the default in-memory store.
    pub fn new(inactivity_timeout_secs: i64, absolute_timeout_secs: i64) -> Self {
        Self::with_store(
            Arc::new(InMemoryWebUiSessionStore::new()),
            inactivity_timeout_secs,
            absolute_timeout_secs,
        )
    }

    /// Create a session manager backed by the supplied store. Use this to plug
    /// in a durable backend (database/Redis) for multi-instance deployments.
    pub fn with_store(
        store: Arc<dyn WebUiSessionStore>,
        inactivity_timeout_secs: i64,
        absolute_timeout_secs: i64,
    ) -> Self {
        Self {
            store,
            inactivity_timeout: Duration::seconds(inactivity_timeout_secs),
            absolute_timeout: Duration::seconds(absolute_timeout_secs),
        }
    }

    /// Generate a cryptographically secure session token
    fn generate_token() -> String {
        let bytes = secure_random_bytes(SESSION_TOKEN_LENGTH);
        BASE64.encode(&bytes)
    }

    /// Create a new session (OIDC mode; no backend token).
    pub async fn create_session(
        &self,
        user_subject: String,
        username: Option<String>,
        email: Option<String>,
        roles: Vec<String>,
    ) -> (String, SessionData) {
        self.create_session_with_token(user_subject, username, email, roles, None)
            .await
    }

    /// Create a new session carrying a backend credential.
    ///
    /// Used by internal-auth mode to bind the CA's own bearer token to the web
    /// session so the proxy can authenticate upstream as the actual admin.
    pub async fn create_session_with_token(
        &self,
        user_subject: String,
        username: Option<String>,
        email: Option<String>,
        roles: Vec<String>,
        backend_token: Option<String>,
    ) -> (String, SessionData) {
        let token = Self::generate_token();
        let now = Utc::now();

        let session = SessionData {
            id: Uuid::new_v4().to_string(),
            user_subject,
            username,
            email,
            roles,
            created_at: now,
            last_activity: now,
            expires_at: now + self.absolute_timeout,
            locked: false,
            backend_token,
        };

        self.store.insert(token.clone(), session.clone()).await;
        // Opportunistic cleanup of any sessions that have aged out.
        self.store.purge_expired().await;

        tracing::info!(
            session_id = %session.id,
            user = ?session.username,
            expires_at = %session.expires_at,
            "Session created"
        );

        (token, session)
    }

    /// Validate a session token and return session data
    pub async fn validate_session(&self, token: &str) -> Option<SessionData> {
        let mut session = self.store.get(token).await?;

        // Absolute expiry: drop and reject.
        if session.is_expired() {
            self.store.remove(token).await;
            tracing::debug!(session_id = %session.id, "Session expired");
            return None;
        }

        // Inactivity lock: flag and persist, then return the locked session so
        // the client can prompt for re-authentication.
        if session.should_lock(self.inactivity_timeout) && !session.locked {
            session.locked = true;
            tracing::info!(session_id = %session.id, "Session locked due to inactivity");
            self.store.update(token, session.clone()).await;
            return Some(session);
        }

        // Active: refresh last activity.
        session.touch();
        self.store.update(token, session.clone()).await;
        Some(session)
    }

    /// Invalidate (delete) a session
    pub async fn invalidate_session(&self, token: &str) -> bool {
        if let Some(session) = self.store.remove(token).await {
            tracing::info!(
                session_id = %session.id,
                user = ?session.username,
                "Session invalidated"
            );
            true
        } else {
            false
        }
    }

    /// Unlock a session after re-authentication
    pub async fn unlock_session(&self, token: &str) -> Option<SessionData> {
        let mut session = self.store.get(token).await?;

        if session.is_expired() {
            self.store.remove(token).await;
            return None;
        }

        session.locked = false;
        session.last_activity = Utc::now();
        self.store.update(token, session.clone()).await;

        tracing::info!(session_id = %session.id, "Session unlocked");
        Some(session)
    }

    /// Get session count (for monitoring)
    pub async fn session_count(&self) -> usize {
        self.store.count().await
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(
            900,   // 15 minutes inactivity (NIAP PP-CA requirement)
            28800, // 8 hours absolute
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_session() {
        let manager = SessionManager::new(900, 28800);

        let (token, session) = manager
            .create_session(
                "user-123".to_string(),
                Some("testuser".to_string()),
                Some("test@example.com".to_string()),
                vec!["admin".to_string()],
            )
            .await;

        assert!(!token.is_empty());
        assert_eq!(session.user_subject, "user-123");
        assert_eq!(session.username, Some("testuser".to_string()));
        assert!(!session.locked);
    }

    #[tokio::test]
    async fn test_validate_session() {
        let manager = SessionManager::new(900, 28800);

        let (token, _) = manager
            .create_session(
                "user-123".to_string(),
                Some("testuser".to_string()),
                None,
                vec![],
            )
            .await;

        // Should be valid
        let validated = manager.validate_session(&token).await;
        assert!(validated.is_some());

        // Invalid token should return None
        let invalid = manager.validate_session("invalid-token").await;
        assert!(invalid.is_none());
    }

    #[tokio::test]
    async fn test_invalidate_session() {
        let manager = SessionManager::new(900, 28800);

        let (token, _) = manager
            .create_session("user-123".to_string(), None, None, vec![])
            .await;

        // Should succeed
        assert!(manager.invalidate_session(&token).await);

        // Session should be gone
        assert!(manager.validate_session(&token).await.is_none());
    }

    /// An update to an already-removed session must not resurrect it.
    #[tokio::test]
    async fn test_update_does_not_resurrect() {
        let store = InMemoryWebUiSessionStore::new();
        let now = Utc::now();
        let data = SessionData {
            id: "s1".to_string(),
            user_subject: "user".to_string(),
            username: None,
            email: None,
            roles: vec![],
            created_at: now,
            last_activity: now,
            expires_at: now + Duration::hours(1),
            locked: false,
            backend_token: None,
        };
        store.insert("tok".to_string(), data.clone()).await;
        store.remove("tok").await;
        store.update("tok", data).await;
        assert!(store.get("tok").await.is_none());
        assert_eq!(store.count().await, 0);
    }

    #[test]
    fn test_session_expiry() {
        let now = Utc::now();
        let expired_session = SessionData {
            id: "test".to_string(),
            user_subject: "user".to_string(),
            username: None,
            email: None,
            roles: vec![],
            created_at: now - Duration::hours(10),
            last_activity: now - Duration::hours(1),
            expires_at: now - Duration::minutes(1), // Expired
            locked: false,
            backend_token: None,
        };

        assert!(expired_session.is_expired());
    }

    #[test]
    fn test_session_should_lock() {
        let now = Utc::now();
        let inactive_session = SessionData {
            id: "test".to_string(),
            user_subject: "user".to_string(),
            username: None,
            email: None,
            roles: vec![],
            created_at: now - Duration::hours(1),
            last_activity: now - Duration::minutes(20), // Inactive
            expires_at: now + Duration::hours(7),
            locked: false,
            backend_token: None,
        };

        assert!(inactive_session.should_lock(Duration::minutes(15)));
        assert!(!inactive_session.should_lock(Duration::minutes(30)));
    }
}
