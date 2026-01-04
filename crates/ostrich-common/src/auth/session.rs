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

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..DEFAULT_TOKEN_LENGTH).map(|_| rng.r#gen()).collect();
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

/// Session manager
///
/// NIAP PP-CA: FTA_SSL.1, FTA_SSL.3, FTA_SSL.4 - Session management
/// NIST 800-53: AC-12 - Session termination
pub struct SessionManager {
    /// Configuration
    config: SessionConfig,

    /// Active sessions
    sessions: RwLock<HashMap<Uuid, Session>>,

    /// User to session ID mapping (for concurrent session tracking)
    user_sessions: RwLock<HashMap<String, Vec<Uuid>>>,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            user_sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Create a new session for a user
    ///
    /// NIST 800-53: SC-23 - Session authenticity
    pub fn create_session(
        &self,
        user_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session, SessionError> {
        // Check concurrent session limit
        {
            let user_sessions = self
                .user_sessions
                .read()
                .map_err(|_| SessionError::LockPoisoned)?;
            if let Some(sessions) = user_sessions.get(user_id) {
                let active_count = {
                    let sessions_map = self
                        .sessions
                        .read()
                        .map_err(|_| SessionError::LockPoisoned)?;
                    sessions
                        .iter()
                        .filter(|id| {
                            sessions_map
                                .get(*id)
                                .is_some_and(|s| s.status == SessionStatus::Active)
                        })
                        .count()
                };

                if active_count >= self.config.max_concurrent_sessions as usize {
                    tracing::warn!(
                        user_id = user_id,
                        active_sessions = active_count,
                        max_sessions = self.config.max_concurrent_sessions,
                        "Concurrent session limit exceeded"
                    );
                    return Err(SessionError::MaxConcurrentSessionsExceeded);
                }
            }
        }

        let session = Session::new(user_id, ip_address, user_agent, &self.config);

        // Store session
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| SessionError::LockPoisoned)?;
            sessions.insert(session.id, session.clone());
        }

        // Update user session mapping
        {
            let mut user_sessions = self
                .user_sessions
                .write()
                .map_err(|_| SessionError::LockPoisoned)?;
            user_sessions
                .entry(user_id.to_string())
                .or_default()
                .push(session.id);
        }

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
    pub fn validate_session(&self, token: &str) -> Result<Session, SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session = sessions
            .values_mut()
            .find(|s| s.token == token)
            .ok_or(SessionError::SessionNotFound)?;

        // Check if expired
        if session.is_expired() {
            session.status = SessionStatus::Expired;
            tracing::info!(session_id = %session.id, "Session expired");
            return Err(SessionError::SessionExpired);
        }

        // Check status
        match session.status {
            SessionStatus::Active => {
                // Check inactivity
                if session.is_inactive(self.config.inactivity_timeout_secs) {
                    if self.config.lock_on_inactivity {
                        session.lock();
                        tracing::info!(
                            session_id = %session.id,
                            idle_time = session.idle_time(),
                            "Session locked due to inactivity"
                        );
                        return Err(SessionError::SessionLocked);
                    } else {
                        session.status = SessionStatus::Expired;
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
                Ok(session.clone())
            }
            SessionStatus::Locked => Err(SessionError::SessionLocked),
            SessionStatus::Expired => Err(SessionError::SessionExpired),
            SessionStatus::Terminated | SessionStatus::AdminTerminated => {
                Err(SessionError::SessionTerminated)
            }
        }
    }

    /// Validate a session by ID
    pub fn validate_session_by_id(&self, session_id: &Uuid) -> Result<Session, SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        // Check if expired
        if session.is_expired() {
            session.status = SessionStatus::Expired;
            return Err(SessionError::SessionExpired);
        }

        // Check status
        match session.status {
            SessionStatus::Active => {
                if session.is_inactive(self.config.inactivity_timeout_secs) {
                    if self.config.lock_on_inactivity {
                        session.lock();
                        return Err(SessionError::SessionLocked);
                    } else {
                        session.status = SessionStatus::Expired;
                        return Err(SessionError::SessionExpired);
                    }
                }
                session.touch();
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
    pub fn unlock_session(&self, session_id: &Uuid) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        if session.status != SessionStatus::Locked {
            return Err(SessionError::InvalidState(
                "Session is not locked".to_string(),
            ));
        }

        session.unlock();
        tracing::info!(session_id = %session_id, "Session unlocked after re-authentication");
        Ok(())
    }

    /// Terminate a session (user-initiated)
    ///
    /// NIAP PP-CA: FTA_SSL.4 - User-initiated termination
    pub fn terminate_session(&self, session_id: &Uuid) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        session.terminate();
        tracing::info!(session_id = %session_id, user_id = %session.user_id, "Session terminated by user");
        Ok(())
    }

    /// Admin terminate a session
    ///
    /// NIAP PP-CA: FTA_SSL.3 - TSF-initiated termination
    pub fn admin_terminate_session(
        &self,
        session_id: &Uuid,
        admin_id: &str,
    ) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        session.admin_terminate();
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
    pub fn terminate_user_sessions(
        &self,
        user_id: &str,
        admin_id: Option<&str>,
    ) -> Result<u32, SessionError> {
        let user_sessions = self
            .user_sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session_ids = user_sessions.get(user_id).cloned().unwrap_or_default();
        drop(user_sessions);

        let mut terminated = 0;
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        for session_id in session_ids {
            if let Some(session) = sessions.get_mut(&session_id)
                && (session.status == SessionStatus::Active
                    || session.status == SessionStatus::Locked)
            {
                if admin_id.is_some() {
                    session.admin_terminate();
                } else {
                    session.terminate();
                }
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

    /// Get all active sessions for a user
    pub fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, SessionError> {
        let user_sessions = self
            .user_sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SessionError::LockPoisoned)?;

        let session_ids = user_sessions.get(user_id).cloned().unwrap_or_default();

        let user_session_list: Vec<Session> = session_ids
            .iter()
            .filter_map(|id| sessions.get(id))
            .filter(|s| s.status == SessionStatus::Active || s.status == SessionStatus::Locked)
            .cloned()
            .collect();

        Ok(user_session_list)
    }

    /// Cleanup expired sessions
    ///
    /// Should be called periodically to clean up stale sessions
    pub fn cleanup_expired(&self) -> Result<u32, SessionError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionError::LockPoisoned)?;

        let expired_ids: Vec<Uuid> = sessions
            .values()
            .filter(|s| s.is_expired())
            .map(|s| s.id)
            .collect();

        for id in &expired_ids {
            if let Some(session) = sessions.get_mut(id) {
                session.status = SessionStatus::Expired;
            }
        }

        let count = expired_ids.len() as u32;
        if count > 0 {
            tracing::debug!(expired_count = count, "Cleaned up expired sessions");
        }

        Ok(count)
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

    /// Internal lock error
    #[error("Internal lock error")]
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FTA_SSL.1 - Test session creation
    #[test]
    fn test_session_creation() {
        let manager = SessionManager::with_defaults();
        let session = manager
            .create_session("user1", Some("192.168.1.1".to_string()), None)
            .unwrap();

        assert_eq!(session.user_id, "user1");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(!session.token.is_empty());
    }

    /// FTA_SSL.1 - Test session validation
    #[test]
    fn test_session_validation() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).unwrap();

        let validated = manager.validate_session(&session.token).unwrap();
        assert_eq!(validated.id, session.id);
    }

    /// FTA_SSL.1 - Test inactivity timeout
    #[test]
    fn test_inactivity_timeout() {
        let manager = SessionManager::new(SessionConfig::new().with_inactivity_timeout(1));
        let session = manager.create_session("user1", None, None).unwrap();

        // Wait for inactivity
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = manager.validate_session(&session.token);
        assert!(matches!(result, Err(SessionError::SessionLocked)));
    }

    /// FTA_SSL.4 - Test user-initiated termination
    #[test]
    fn test_user_termination() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).unwrap();

        manager.terminate_session(&session.id).unwrap();

        let result = manager.validate_session(&session.token);
        assert!(matches!(result, Err(SessionError::SessionTerminated)));
    }

    /// FTA_SSL.3 - Test admin termination
    #[test]
    fn test_admin_termination() {
        let manager = SessionManager::with_defaults();
        let session = manager.create_session("user1", None, None).unwrap();

        manager
            .admin_terminate_session(&session.id, "admin")
            .unwrap();

        let result = manager.validate_session(&session.token);
        assert!(matches!(result, Err(SessionError::SessionTerminated)));
    }

    /// FTA_SSL.1 - Test session unlock
    #[test]
    fn test_session_unlock() {
        let manager = SessionManager::new(SessionConfig::new().with_inactivity_timeout(1));
        let session = manager.create_session("user1", None, None).unwrap();

        // Wait for inactivity to lock
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = manager.validate_session(&session.token);

        // Unlock
        manager.unlock_session(&session.id).unwrap();

        // Should be valid again
        let validated = manager.validate_session_by_id(&session.id).unwrap();
        assert_eq!(validated.status, SessionStatus::Active);
    }

    /// AC-12 - Test concurrent session limit
    #[test]
    fn test_concurrent_session_limit() {
        let manager = SessionManager::new(SessionConfig::new().with_max_concurrent(2));

        // Create two sessions
        manager.create_session("user1", None, None).unwrap();
        manager.create_session("user1", None, None).unwrap();

        // Third should fail
        let result = manager.create_session("user1", None, None);
        assert!(matches!(
            result,
            Err(SessionError::MaxConcurrentSessionsExceeded)
        ));
    }

    /// FTA_SSL.3 - Test terminate all user sessions
    #[test]
    fn test_terminate_user_sessions() {
        let manager = SessionManager::new(SessionConfig::new().with_max_concurrent(5));

        // Create multiple sessions
        manager.create_session("user1", None, None).unwrap();
        manager.create_session("user1", None, None).unwrap();
        manager.create_session("user1", None, None).unwrap();

        // Terminate all
        let count = manager
            .terminate_user_sessions("user1", Some("admin"))
            .unwrap();
        assert_eq!(count, 3);

        // Should have no active sessions
        let sessions = manager.get_user_sessions("user1").unwrap();
        assert!(sessions.is_empty());
    }

    /// Test session remaining time
    #[test]
    fn test_remaining_time() {
        let manager = SessionManager::new(SessionConfig::new().with_absolute_timeout(60));
        let session = manager.create_session("user1", None, None).unwrap();

        assert!(session.remaining_time() > 55 && session.remaining_time() <= 60);
    }
}
