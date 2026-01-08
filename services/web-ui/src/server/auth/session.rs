//! Session Management
//!
//! Manages user sessions after OIDC authentication.
//! This module provides session lifecycle management for future integration.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-12 (Session Termination)
//! - NIST 800-53: SC-23 (Session Authenticity)
//! - NIAP PP-CA: FTA_SSL.1 (TSF-initiated Session Locking)
//! - NIAP PP-CA: FTA_SSL.3 (TSF-initiated Session Termination)

#![allow(dead_code)] // Module prepared for future integration

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use ostrich_common::util::random::secure_random_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};

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

/// Session manager for in-memory session storage
///
/// In production, this should be backed by Redis or a database
/// for multi-instance deployments.
pub struct SessionManager {
    /// Session storage (token -> session data)
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,

    /// Inactivity timeout
    inactivity_timeout: Duration,

    /// Absolute session timeout
    absolute_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(inactivity_timeout_secs: i64, absolute_timeout_secs: i64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            inactivity_timeout: Duration::seconds(inactivity_timeout_secs),
            absolute_timeout: Duration::seconds(absolute_timeout_secs),
        }
    }

    /// Generate a cryptographically secure session token
    fn generate_token() -> String {
        let bytes = secure_random_bytes(SESSION_TOKEN_LENGTH);
        BASE64.encode(&bytes)
    }

    /// Create a new session
    pub async fn create_session(
        &self,
        user_subject: String,
        username: Option<String>,
        email: Option<String>,
        roles: Vec<String>,
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
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(token.clone(), session.clone());

            // Clean up expired sessions
            sessions.retain(|_, s| !s.is_expired());
        }

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
        let mut sessions = self.sessions.write().await;

        // First check if session exists and if it's expired
        let session_state = sessions.get(token).map(|s| (s.id.clone(), s.is_expired()));

        if let Some((session_id, true)) = session_state {
            sessions.remove(token);
            tracing::debug!(session_id = %session_id, "Session expired");
            return None;
        }

        if let Some(session) = sessions.get_mut(token) {
            // Check if should be locked due to inactivity
            if session.should_lock(self.inactivity_timeout) && !session.locked {
                session.locked = true;
                tracing::info!(
                    session_id = %session.id,
                    "Session locked due to inactivity"
                );
                // Return the locked session (client should prompt for re-auth)
                return Some(session.clone());
            }

            // Update last activity
            session.touch();
            return Some(session.clone());
        }

        None
    }

    /// Invalidate (delete) a session
    pub async fn invalidate_session(&self, token: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(token) {
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
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(token) {
            if session.is_expired() {
                sessions.remove(token);
                return None;
            }

            session.locked = false;
            session.last_activity = Utc::now();

            tracing::info!(
                session_id = %session.id,
                "Session unlocked"
            );

            return Some(session.clone());
        }

        None
    }

    /// Get session count (for monitoring)
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
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
        };

        assert!(inactive_session.should_lock(Duration::minutes(15)));
        assert!(!inactive_session.should_lock(Duration::minutes(30)));
    }
}
