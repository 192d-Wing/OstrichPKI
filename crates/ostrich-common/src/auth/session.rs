//! Session Management Module
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FTA_SSL.1 (TSF-initiated Session Locking)
//! - NIAP PP-CA: FTA_SSL.3 (TSF-initiated Termination)
//! - NIAP PP-CA: FTA_SSL.4 (User-initiated Termination)
//! - NIST 800-53: AC-12 (Session Termination)
//! - NIST 800-53: IA-11 (Re-authentication)
//! - NIST 800-53: SC-23 (Session Authenticity)
//!
//! This module provides session management with automatic timeout,
//! manual termination, and session tracking as required by NIAP PP-CA v2.1.
//!
//! Session state lives behind a [`SessionStore`]. The default in-memory store
//! is process-local and does not survive a restart; a database-backed store
//! (`ostrich_db::repository::DbSessionStore`) makes Postgres the source of
//! truth so sessions are durable and shared across service instances
//! (NIST 800-53: SC-23, AC-12).

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use uuid::Uuid;

/// Default session inactivity timeout in seconds (15 minutes)
/// NIAP PP-CA: FTA_SSL.1 - Configurable inactivity period
pub const DEFAULT_INACTIVITY_TIMEOUT_SECS: i64 = 900;

/// Default absolute session timeout in seconds (8 hours)
/// Maximum session duration regardless of activity
pub const DEFAULT_ABSOLUTE_TIMEOUT_SECS: i64 = 28800;

/// Default session token length in bytes
pub const DEFAULT_TOKEN_LENGTH: usize = 32;

/// Session status
///
/// NIAP PP-CA: FTA_SSL.1 - Session states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session is active and valid
    Active,

    /// Session is locked due to inactivity (requires re-authentication)
    Locked,

    /// Session has expired (absolute timeout)
    Expired,

    /// Session was terminated by user
    Terminated,

    /// Session was terminated by admin
    AdminTerminated,
}

/// Session configuration
///
/// NIAP PP-CA: FTA_SSL.1 - Configurable session parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Inactivity timeout in seconds
    pub inactivity_timeout_secs: i64,

    /// Absolute session timeout in seconds
    pub absolute_timeout_secs: i64,

    /// Whether to lock sessions on inactivity (vs terminate)
    pub lock_on_inactivity: bool,

    /// Whether to allow session renewal
    pub allow_renewal: bool,

    /// Maximum number of concurrent sessions per user
    pub max_concurrent_sessions: u32,

    /// Whether to track session IP address
    pub track_ip: bool,

    /// Whether to track session user agent
    pub track_user_agent: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionConfig {
    /// Create default session configuration
    ///
    /// NIAP PP-CA: FTA_SSL.1 - Secure defaults
    pub fn new() -> Self {
        Self {
            inactivity_timeout_secs: DEFAULT_INACTIVITY_TIMEOUT_SECS,
            absolute_timeout_secs: DEFAULT_ABSOLUTE_TIMEOUT_SECS,
            lock_on_inactivity: true,
            allow_renewal: true,
            max_concurrent_sessions: 3,
            track_ip: true,
            track_user_agent: true,
        }
    }

    /// Create a high-security configuration
    pub fn high_security() -> Self {
        Self {
            inactivity_timeout_secs: 300, // 5 minutes
            absolute_timeout_secs: 14400, // 4 hours
            lock_on_inactivity: true,
            allow_renewal: false,
            max_concurrent_sessions: 1,
            track_ip: true,
            track_user_agent: true,
        }
    }

    /// Builder: Set inactivity timeout
    pub fn with_inactivity_timeout(mut self, secs: i64) -> Self {
        self.inactivity_timeout_secs = secs;
        self
    }

    /// Builder: Set absolute timeout
    pub fn with_absolute_timeout(mut self, secs: i64) -> Self {
        self.absolute_timeout_secs = secs;
        self
    }

    /// Builder: Set max concurrent sessions
    pub fn with_max_concurrent(mut self, max: u32) -> Self {
        self.max_concurrent_sessions = max;
        self
    }
}

/// Session information
///
/// NIAP PP-CA: FTA_SSL.1 - Session tracking
/// NIST 800-53: SC-23 - Session authenticity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: Uuid,

    /// Session token (for authentication)
    pub token: String,

    /// User identifier
    pub user_id: String,

    /// Current session status
    pub status: SessionStatus,

    /// User's IP address
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Session creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,

    /// Session expiration timestamp (absolute)
    pub expires_at: DateTime<Utc>,

    /// Additional session metadata
    pub metadata: Option<serde_json::Value>,
}

impl Session {
    /// Create a new session
    pub fn new(
        user_id: impl Into<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        config: &SessionConfig,
    ) -> Self {
        let now = Utc::now();
        let token = Self::generate_token();

        Self {
            id: Uuid::new_v4(),
            token,
            user_id: user_id.into(),
            status: SessionStatus::Active,
            ip_address,
            user_agent,
            created_at: now,
            last_activity: now,
            expires_at: now + Duration::seconds(config.absolute_timeout_secs),
            metadata: None,
        }
    }

    /// Generate a cryptographically secure session token
    fn generate_token() -> String {
        use rand::RngExt; // rand 0.10: `random()` is provided by the RngExt trait.
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..DEFAULT_TOKEN_LENGTH).map(|_| rng.random()).collect();
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Check if session is expired (absolute timeout)
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is inactive (beyond inactivity timeout)
    pub fn is_inactive(&self, timeout_secs: i64) -> bool {
        let cutoff = Utc::now() - Duration::seconds(timeout_secs);
        self.last_activity < cutoff
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Lock the session
    pub fn lock(&mut self) {
        self.status = SessionStatus::Locked;
    }

    /// Unlock the session (after re-authentication)
    pub fn unlock(&mut self) {
        if self.status == SessionStatus::Locked {
            self.status = SessionStatus::Active;
            self.touch();
        }
    }

    /// Terminate the session
    pub fn terminate(&mut self) {
        self.status = SessionStatus::Terminated;
    }

    /// Admin terminate the session
    pub fn admin_terminate(&mut self) {
        self.status = SessionStatus::AdminTerminated;
    }

    /// Get remaining time until expiration in seconds
    pub fn remaining_time(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }

    /// Get time since last activity in seconds
    pub fn idle_time(&self) -> i64 {
        (Utc::now() - self.last_activity).num_seconds()
    }
}

/// Pluggable persistence backend for sessions.
///
/// `SessionManager` holds no session state itself; it delegates storage to a
/// `SessionStore`. The store determines durability: the Postgres-backed store
/// (`ostrich_db::repository::DbSessionStore`) makes the database the single
/// source of truth, so sessions survive a restart and are shared across service
/// instances. [`InMemorySessionStore`] preserves the previous process-local
/// behaviour for tests and for callers without a database.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-12 (Session Termination), SC-23 (Session Authenticity)
/// - NIAP PP-CA: FTA_SSL.1/.3/.4 - session lifecycle persisted by the store
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Persist a newly created session.
    async fn create(&self, session: &Session) -> Result<(), SessionError>;

    /// Fetch a session by its bearer token, if present.
    async fn get_by_token(&self, token: &str) -> Result<Option<Session>, SessionError>;

    /// Fetch a session by its identifier, if present.
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Session>, SessionError>;

    /// Persist mutable session fields (status, last_activity, expiry, metadata).
    async fn update(&self, session: &Session) -> Result<(), SessionError>;

    /// All currently active or locked sessions for a user.
    async fn list_active_for_user(&self, user_id: &str) -> Result<Vec<Session>, SessionError>;

    /// Remove sessions whose absolute expiry has passed; returns the count removed.
    async fn delete_expired(&self) -> Result<u64, SessionError>;
}

/// In-memory `SessionStore` (process-local, non-durable).
///
/// Retains the original pre-persistence behaviour. Suitable for unit tests and
/// single-process callers that do not require sessions to survive a restart.
#[derive(Default)]
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<Uuid, Session>>,
}

impl InMemorySessionStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(&self, session: &Session) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<Session>, SessionError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;
        Ok(sessions.values().find(|s| s.token == token).cloned())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Session>, SessionError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;
        Ok(sessions.get(id).cloned())
    }

    async fn update(&self, session: &Session) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;
        // Mirror the DB store's guard: never replace a terminal status with a
        // non-terminal one, so a concurrent activity-touch cannot resurrect a
        // session that was terminated in between. NIST 800-53: AC-12.
        if let Some(existing) = sessions.get(&session.id) {
            let existing_terminal = matches!(
                existing.status,
                SessionStatus::Terminated | SessionStatus::AdminTerminated
            );
            let new_terminal = matches!(
                session.status,
                SessionStatus::Terminated | SessionStatus::AdminTerminated
            );
            if existing_terminal && !new_terminal {
                return Ok(());
            }
        }
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn list_active_for_user(&self, user_id: &str) -> Result<Vec<Session>, SessionError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;
        Ok(sessions
            .values()
            .filter(|s| {
                s.user_id == user_id
                    && (s.status == SessionStatus::Active || s.status == SessionStatus::Locked)
            })
            .cloned()
            .collect())
    }

    async fn delete_expired(&self) -> Result<u64, SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;
        let before = sessions.len();
        // Reap absolute-expired and terminated sessions alike (parity with the
        // DB store); validation already rejects both.
        sessions.retain(|_, s| {
            !s.is_expired()
                && !matches!(
                    s.status,
                    SessionStatus::Terminated | SessionStatus::AdminTerminated
                )
        });
        Ok((before - sessions.len()) as u64)
    }
}

/// Session manager
///
/// Applies session policy (timeouts, concurrent-session limits, lifecycle
/// transitions) on top of a pluggable [`SessionStore`]. The store determines
/// durability; the manager itself is stateless beyond its configuration.
///
/// NIAP PP-CA: FTA_SSL.1, FTA_SSL.3, FTA_SSL.4 - Session management
/// NIST 800-53: AC-12 - Session termination
pub struct SessionManager {
    /// Configuration
    config: SessionConfig,

    /// Backing store (source of truth for session state)
    store: Arc<dyn SessionStore>,
}

impl SessionManager {
    /// Default cadence for the background session reaper ([`Self::spawn_reaper`]).
    pub const DEFAULT_REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

    /// Create a session manager backed by a non-durable in-memory store.
    ///
    /// Sessions created through this manager do not survive a restart. For
    /// durable, cross-instance sessions use [`SessionManager::with_store`] with
    /// a database-backed `SessionStore`.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            store: Arc::new(InMemorySessionStore::new()),
        }
    }

    /// Create a session manager backed by the supplied store.
    ///
    /// NIST 800-53: SC-23 - durable session authenticity when given a
    /// database-backed store.
    pub fn with_store(config: SessionConfig, store: Arc<dyn SessionStore>) -> Self {
        Self { config, store }
    }

    /// Create with default configuration (in-memory store)
    pub fn with_defaults() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Create a new session for a user
    ///
    /// NIST 800-53: SC-23 - Session authenticity
    pub async fn create_session(
        &self,
        user_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session, SessionError> {
        // Enforce the concurrent-session limit (NIAP PP-CA: FTA_MCS.1).
        let active_count = self
            .store
            .list_active_for_user(user_id)
            .await?
            .iter()
            .filter(|s| s.status == SessionStatus::Active)
            .count();

        if active_count >= self.config.max_concurrent_sessions as usize {
            tracing::warn!(
                user_id = user_id,
                active_sessions = active_count,
                max_sessions = self.config.max_concurrent_sessions,
                "Concurrent session limit exceeded"
            );
            return Err(SessionError::MaxConcurrentSessionsExceeded);
        }

        let session = Session::new(user_id, ip_address, user_agent, &self.config);
        self.store.create(&session).await?;

        tracing::info!(
            session_id = %session.id,
            user_id = user_id,
            "Session created"
        );

        Ok(session)
    }

    /// Validate a session by token
    ///
    /// NIAP PP-CA: FTA_SSL.1 - Check session validity and timeout
    pub async fn validate_session(&self, token: &str) -> Result<Session, SessionError> {
        let mut session = self
            .store
            .get_by_token(token)
            .await?
            .ok_or(SessionError::SessionNotFound)?;
        self.evaluate(&mut session).await
    }

    /// Validate a session by ID
    pub async fn validate_session_by_id(&self, session_id: &Uuid) -> Result<Session, SessionError> {
        let mut session = self
            .store
            .get_by_id(session_id)
            .await?
            .ok_or(SessionError::SessionNotFound)?;
        self.evaluate(&mut session).await
    }

    /// Apply expiry / inactivity / status policy to a fetched session,
    /// persisting any resulting state transition (expire, lock, activity touch).
    ///
    /// NIAP PP-CA: FTA_SSL.1 - timeout enforcement; transitions are persisted so
    /// they hold across a restart (NIST 800-53: SC-23).
    async fn evaluate(&self, session: &mut Session) -> Result<Session, SessionError> {
        // Absolute timeout
        if session.is_expired() {
            if session.status != SessionStatus::Expired {
                session.status = SessionStatus::Expired;
                self.store.update(session).await?;
            }
            tracing::info!(session_id = %session.id, "Session expired");
            return Err(SessionError::SessionExpired);
        }

        match session.status {
            SessionStatus::Active => {
                // Inactivity timeout
                if session.is_inactive(self.config.inactivity_timeout_secs) {
                    if self.config.lock_on_inactivity {
                        session.lock();
                        self.store.update(session).await?;
                        tracing::info!(
                            session_id = %session.id,
                            idle_time = session.idle_time(),
                            "Session locked due to inactivity"
                        );
                        return Err(SessionError::SessionLocked);
                    } else {
                        session.status = SessionStatus::Expired;
                        self.store.update(session).await?;
                        tracing::info!(
                            session_id = %session.id,
                            idle_time = session.idle_time(),
                            "Session terminated due to inactivity"
                        );
                        return Err(SessionError::SessionExpired);
                    }
                }

                // Update activity
                session.touch();
                self.store.update(session).await?;
                Ok(session.clone())
            }
            SessionStatus::Locked => Err(SessionError::SessionLocked),
            SessionStatus::Expired => Err(SessionError::SessionExpired),
            SessionStatus::Terminated | SessionStatus::AdminTerminated => {
                Err(SessionError::SessionTerminated)
            }
        }
    }

    /// Unlock a locked session (after re-authentication)
    ///
    /// NIST 800-53: IA-11 - Re-authentication
    pub async fn unlock_session(&self, session_id: &Uuid) -> Result<(), SessionError> {
        let mut session = self
            .store
            .get_by_id(session_id)
            .await?
            .ok_or(SessionError::SessionNotFound)?;

        if session.status != SessionStatus::Locked {
            return Err(SessionError::InvalidState(
                "Session is not locked".to_string(),
            ));
        }

        session.unlock();
        self.store.update(&session).await?;
        tracing::info!(session_id = %session_id, "Session unlocked after re-authentication");
        Ok(())
    }

    /// Terminate a session (user-initiated)
    ///
    /// NIAP PP-CA: FTA_SSL.4 - User-initiated termination
    pub async fn terminate_session(&self, session_id: &Uuid) -> Result<(), SessionError> {
        let mut session = self
            .store
            .get_by_id(session_id)
            .await?
            .ok_or(SessionError::SessionNotFound)?;

        session.terminate();
        self.store.update(&session).await?;
        tracing::info!(session_id = %session_id, user_id = %session.user_id, "Session terminated by user");
        Ok(())
    }

    /// Admin terminate a session
    ///
    /// NIAP PP-CA: FTA_SSL.3 - TSF-initiated termination
    pub async fn admin_terminate_session(
        &self,
        session_id: &Uuid,
        admin_id: &str,
    ) -> Result<(), SessionError> {
        let mut session = self
            .store
            .get_by_id(session_id)
            .await?
            .ok_or(SessionError::SessionNotFound)?;

        session.admin_terminate();
        self.store.update(&session).await?;
        tracing::info!(
            session_id = %session_id,
            user_id = %session.user_id,
            admin_id = admin_id,
            "Session terminated by admin"
        );
        Ok(())
    }

    /// Terminate all sessions for a user
    ///
    /// NIAP PP-CA: FTA_SSL.3 - Terminate all user sessions
    pub async fn terminate_user_sessions(
        &self,
        user_id: &str,
        admin_id: Option<&str>,
    ) -> Result<u32, SessionError> {
        let sessions = self.store.list_active_for_user(user_id).await?;

        let mut terminated = 0;
        for mut session in sessions {
            if session.status == SessionStatus::Active || session.status == SessionStatus::Locked {
                if admin_id.is_some() {
                    session.admin_terminate();
                } else {
                    session.terminate();
                }
                self.store.update(&session).await?;
                terminated += 1;
            }
        }

        tracing::info!(
            user_id = user_id,
            admin_id = ?admin_id,
            terminated_count = terminated,
            "User sessions terminated"
        );

        Ok(terminated)
    }

    /// Get all active (or locked) sessions for a user
    pub async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, SessionError> {
        self.store.list_active_for_user(user_id).await
    }

    /// Cleanup expired sessions
    ///
    /// Should be called periodically to remove sessions past their absolute
    /// expiry. With a database-backed store this bounds table growth; expired
    /// sessions are already rejected at validation time regardless.
    pub async fn cleanup_expired(&self) -> Result<u64, SessionError> {
        let count = self.store.delete_expired().await?;
        if count > 0 {
            tracing::debug!(expired_count = count, "Cleaned up expired sessions");
        }
        Ok(count)
    }

    /// Spawn a background task that periodically reaps expired sessions from the
    /// store, bounding table growth from sessions that age out or are
    /// terminated. The task runs for the life of the process; the returned
    /// `JoinHandle` may be dropped to detach it.
    ///
    /// NIST 800-53: AC-12 - sessions do not linger past their lifetime.
    pub fn spawn_reaper(
        self: Arc<Self>,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            // The first tick fires immediately; skip it so we don't sweep at
            // startup before anything could have expired.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match self.cleanup_expired().await {
                    Ok(n) if n > 0 => tracing::debug!(reaped = n, "expired sessions reaped"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "session reaper sweep failed"),
                }
            }
        })
    }

    /// Get the session configuration
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }
}

/// Session-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionError {
    /// Session not found
    #[error("Session not found")]
    SessionNotFound,

    /// Session expired
    #[error("Session expired")]
    SessionExpired,

    /// Session locked
    #[error("Session locked - re-authentication required")]
    SessionLocked,

    /// Session terminated
    #[error("Session terminated")]
    SessionTerminated,

    /// Invalid session state
    #[error("Invalid session state: {0}")]
    InvalidState(String),

    /// Maximum concurrent sessions exceeded
    #[error("Maximum concurrent sessions exceeded")]
    MaxConcurrentSessionsExceeded,

    /// Internal lock error (in-memory store)
    #[error("Internal lock error")]
    LockPoisoned,

    /// Persistence backend error (e.g. database failure)
    #[error("Session store backend error: {0}")]
    Backend(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_constants::test_ipv4;

    /// FTA_SSL.1 - Test session creation
    #[tokio::test]
    async fn test_session_creation() {
        let manager = SessionManager::with_defaults();
        let session = manager
            .create_session("user1", Some(test_ipv4::TEST_NET_1.to_string()), None) // RFC 5737 TEST-NET-1
            .await
            .unwrap();

        assert_eq!(session.user_id, "user1");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(!session.token.is_empty());
    }

    /// FTA_SSL.1 - Test session validation
    #[tokio::test]
    async fn test_session_validation() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).await.unwrap();

        let validated = manager.validate_session(&session.token).await.unwrap();
        assert_eq!(validated.id, session.id);
    }

    /// FTA_SSL.1 - Test inactivity timeout
    #[tokio::test]
    async fn test_inactivity_timeout() {
        let manager = SessionManager::new(SessionConfig::new().with_inactivity_timeout(1));
        let session = manager.create_session("user1", None, None).await.unwrap();

        // Wait for inactivity
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = manager.validate_session(&session.token).await;
        assert!(matches!(result, Err(SessionError::SessionLocked)));
    }

    /// FTA_SSL.4 - Test user-initiated termination
    #[tokio::test]
    async fn test_user_termination() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).await.unwrap();

        manager.terminate_session(&session.id).await.unwrap();

        let result = manager.validate_session(&session.token).await;
        assert!(matches!(result, Err(SessionError::SessionTerminated)));
    }

    /// FTA_SSL.3 - Test admin termination
    #[tokio::test]
    async fn test_admin_termination() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).await.unwrap();

        manager
            .admin_terminate_session(&session.id, "admin")
            .await
            .unwrap();

        let result = manager.validate_session(&session.token).await;
        assert!(matches!(result, Err(SessionError::SessionTerminated)));
    }

    /// FTA_SSL.1 - Test session unlock
    #[tokio::test]
    async fn test_session_unlock() {
        let manager = SessionManager::new(SessionConfig::new().with_inactivity_timeout(1));
        let session = manager.create_session("user1", None, None).await.unwrap();

        // Wait for inactivity to lock
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = manager.validate_session(&session.token).await;

        // Unlock
        manager.unlock_session(&session.id).await.unwrap();

        // Should be valid again
        let validated = manager.validate_session_by_id(&session.id).await.unwrap();
        assert_eq!(validated.status, SessionStatus::Active);
    }

    /// AC-12 - Test concurrent session limit
    #[tokio::test]
    async fn test_concurrent_session_limit() {
        let manager = SessionManager::new(SessionConfig::new().with_max_concurrent(2));

        // Create two sessions
        manager.create_session("user1", None, None).await.unwrap();
        manager.create_session("user1", None, None).await.unwrap();

        // Third should fail
        let result = manager.create_session("user1", None, None).await;
        assert!(matches!(
            result,
            Err(SessionError::MaxConcurrentSessionsExceeded)
        ));
    }

    /// FTA_SSL.3 - Test terminate all user sessions
    #[tokio::test]
    async fn test_terminate_user_sessions() {
        let manager = SessionManager::new(SessionConfig::new().with_max_concurrent(5));

        // Create multiple sessions
        manager.create_session("user1", None, None).await.unwrap();
        manager.create_session("user1", None, None).await.unwrap();
        manager.create_session("user1", None, None).await.unwrap();

        // Terminate all
        let count = manager
            .terminate_user_sessions("user1", Some("admin"))
            .await
            .unwrap();
        assert_eq!(count, 3);

        // Should have no active sessions
        let sessions = manager.get_user_sessions("user1").await.unwrap();
        assert!(sessions.is_empty());
    }

    /// AC-12 - a stale activity-touch must not resurrect a terminated session.
    #[tokio::test]
    async fn test_terminated_not_resurrected_by_update() {
        let store = InMemorySessionStore::new();
        let cfg = SessionConfig::default();
        let mut session = Session::new("user1", None, None, &cfg);
        store.create(&session).await.unwrap();

        session.terminate();
        store.update(&session).await.unwrap();

        // A concurrent validate that read the pre-termination snapshot tries to
        // write Active back; the guard must reject the resurrection.
        let mut revive = session.clone();
        revive.status = SessionStatus::Active;
        store.update(&revive).await.unwrap();

        let got = store.get_by_id(&session.id).await.unwrap().unwrap();
        assert_eq!(got.status, SessionStatus::Terminated);
    }

    /// The reaper removes terminated sessions, not only absolute-expired ones.
    #[tokio::test]
    async fn test_cleanup_reaps_terminated() {
        let store = InMemorySessionStore::new();
        let cfg = SessionConfig::default();
        let mut session = Session::new("user1", None, None, &cfg);
        store.create(&session).await.unwrap();

        session.terminate();
        store.update(&session).await.unwrap();

        assert_eq!(store.delete_expired().await.unwrap(), 1);
        assert!(store.get_by_id(&session.id).await.unwrap().is_none());
    }

    /// Test session remaining time
    #[tokio::test]
    async fn test_remaining_time() {
        let manager = SessionManager::new(SessionConfig::new().with_absolute_timeout(60));
        let session = manager.create_session("user1", None, None).await.unwrap();

        assert!(session.remaining_time() > 55 && session.remaining_time() <= 60);
    }
}
