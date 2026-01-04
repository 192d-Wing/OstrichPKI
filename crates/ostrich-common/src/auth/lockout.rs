//! Authentication Failure Lockout Module
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)
//! - NIAP PP-CA: FIA_AFL.1.1 - Detect unsuccessful authentication attempts
//! - NIAP PP-CA: FIA_AFL.1.2 - Lockout after threshold exceeded
//! - NIST 800-53: AC-7 (Unsuccessful Login Attempts)
//!
//! This module provides authentication failure tracking and account lockout
//! functionality as required by NIAP PP-CA v2.1.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Default maximum failed authentication attempts before lockout
/// NIAP PP-CA: FIA_AFL.1 - Configurable threshold
pub const DEFAULT_MAX_FAILED_ATTEMPTS: u32 = 5;

/// Default lockout duration in seconds (15 minutes)
/// NIAP PP-CA: FIA_AFL.1 - Lockout duration
pub const DEFAULT_LOCKOUT_DURATION_SECS: i64 = 900;

/// Default window for counting failed attempts (1 hour)
pub const DEFAULT_FAILURE_WINDOW_SECS: i64 = 3600;

/// Lockout configuration
///
/// NIAP PP-CA: FIA_AFL.1 - Configurable authentication failure handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutConfig {
    /// Maximum failed authentication attempts before lockout
    pub max_failed_attempts: u32,

    /// Lockout duration in seconds
    pub lockout_duration_secs: i64,

    /// Time window for counting failures (failures older than this are forgotten)
    pub failure_window_secs: i64,

    /// Whether to enable permanent lockout (requires admin unlock)
    pub permanent_lockout: bool,

    /// Number of consecutive lockouts before permanent lockout
    pub lockouts_before_permanent: u32,

    /// Whether to notify admin on lockout
    pub notify_admin_on_lockout: bool,

    /// Whether to log each failed attempt
    pub log_failed_attempts: bool,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl LockoutConfig {
    /// Create default lockout configuration
    ///
    /// NIAP PP-CA: FIA_AFL.1 - Secure defaults
    pub fn new() -> Self {
        Self {
            max_failed_attempts: DEFAULT_MAX_FAILED_ATTEMPTS,
            lockout_duration_secs: DEFAULT_LOCKOUT_DURATION_SECS,
            failure_window_secs: DEFAULT_FAILURE_WINDOW_SECS,
            permanent_lockout: false,
            lockouts_before_permanent: 3,
            notify_admin_on_lockout: true,
            log_failed_attempts: true,
        }
    }

    /// Create a more restrictive configuration for high-security environments
    pub fn high_security() -> Self {
        Self {
            max_failed_attempts: 3,
            lockout_duration_secs: 1800, // 30 minutes
            failure_window_secs: 3600,
            permanent_lockout: true,
            lockouts_before_permanent: 2,
            notify_admin_on_lockout: true,
            log_failed_attempts: true,
        }
    }

    /// Builder: Set maximum failed attempts
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_failed_attempts = max;
        self
    }

    /// Builder: Set lockout duration
    pub fn with_lockout_duration(mut self, secs: i64) -> Self {
        self.lockout_duration_secs = secs;
        self
    }

    /// Builder: Enable permanent lockout
    pub fn with_permanent_lockout(mut self, after_count: u32) -> Self {
        self.permanent_lockout = true;
        self.lockouts_before_permanent = after_count;
        self
    }
}

/// Lockout status for an account
///
/// NIAP PP-CA: FIA_AFL.1.2 - Account lockout state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockoutStatus {
    /// Account is not locked, authentication allowed
    Active,

    /// Account is temporarily locked
    TemporarilyLocked,

    /// Account is permanently locked (requires admin intervention)
    PermanentlyLocked,
}

/// Failed authentication attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAttempt {
    /// Timestamp of the failed attempt
    pub timestamp: DateTime<Utc>,

    /// Source IP address (if available)
    pub ip_address: Option<String>,

    /// Reason for failure
    pub reason: String,
}

/// Account lockout state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    /// Account identifier (username, token ID, etc.)
    pub account_id: String,

    /// Current lockout status
    pub status: LockoutStatus,

    /// Failed attempts within the tracking window
    pub failed_attempts: Vec<FailedAttempt>,

    /// Total number of lockouts (for permanent lockout tracking)
    pub total_lockouts: u32,

    /// Timestamp when current lockout started
    pub locked_at: Option<DateTime<Utc>>,

    /// Timestamp when lockout expires (for temporary lockout)
    pub lockout_expires_at: Option<DateTime<Utc>>,

    /// Last successful authentication
    pub last_success: Option<DateTime<Utc>>,

    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AccountState {
    /// Create new account state
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            status: LockoutStatus::Active,
            failed_attempts: Vec::new(),
            total_lockouts: 0,
            locked_at: None,
            lockout_expires_at: None,
            last_success: None,
            created_at: Utc::now(),
        }
    }

    /// Get count of recent failed attempts within the window
    pub fn recent_failure_count(&self, window_secs: i64) -> u32 {
        let cutoff = Utc::now() - Duration::seconds(window_secs);
        self.failed_attempts
            .iter()
            .filter(|a| a.timestamp > cutoff)
            .count() as u32
    }

    /// Check if lockout has expired
    pub fn is_lockout_expired(&self) -> bool {
        match self.status {
            LockoutStatus::Active => true,
            LockoutStatus::PermanentlyLocked => false,
            LockoutStatus::TemporarilyLocked => {
                if let Some(expires) = self.lockout_expires_at {
                    Utc::now() > expires
                } else {
                    true
                }
            }
        }
    }
}

/// Authentication lockout manager
///
/// NIAP PP-CA: FIA_AFL.1 - Authentication failure handling
/// NIST 800-53: AC-7 - Unsuccessful login attempts
pub struct AuthLockout {
    /// Configuration
    config: LockoutConfig,

    /// Account states (in-memory tracking)
    /// In production, this should be backed by a database
    accounts: RwLock<HashMap<String, AccountState>>,
}

impl AuthLockout {
    /// Create new lockout manager with configuration
    pub fn new(config: LockoutConfig) -> Self {
        Self {
            config,
            accounts: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(LockoutConfig::default())
    }

    /// Check if an account is allowed to attempt authentication
    ///
    /// NIAP PP-CA: FIA_AFL.1.2 - Check lockout status before auth attempt
    pub fn is_authentication_allowed(&self, account_id: &str) -> Result<bool, LockoutError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| LockoutError::LockPoisoned)?;

        if let Some(state) = accounts.get(account_id) {
            match state.status {
                LockoutStatus::Active => Ok(true),
                LockoutStatus::PermanentlyLocked => {
                    tracing::warn!(
                        account_id = account_id,
                        "Authentication denied: account permanently locked"
                    );
                    Ok(false)
                }
                LockoutStatus::TemporarilyLocked => {
                    if state.is_lockout_expired() {
                        // Lockout expired, allow but don't update state here
                        Ok(true)
                    } else {
                        let remaining = state
                            .lockout_expires_at
                            .map(|e| (e - Utc::now()).num_seconds())
                            .unwrap_or(0);
                        tracing::warn!(
                            account_id = account_id,
                            remaining_seconds = remaining,
                            "Authentication denied: account temporarily locked"
                        );
                        Ok(false)
                    }
                }
            }
        } else {
            // Unknown account - allow (will be created on first failure)
            Ok(true)
        }
    }

    /// Record a failed authentication attempt
    ///
    /// NIAP PP-CA: FIA_AFL.1.1 - Detect unsuccessful authentication attempts
    /// Returns true if account is now locked
    pub fn record_failure(
        &self,
        account_id: &str,
        ip_address: Option<String>,
        reason: impl Into<String>,
    ) -> Result<LockoutStatus, LockoutError> {
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| LockoutError::LockPoisoned)?;

        let state = accounts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountState::new(account_id));

        // If previously locked but expired, reset to active
        if state.status == LockoutStatus::TemporarilyLocked && state.is_lockout_expired() {
            state.status = LockoutStatus::Active;
            state.locked_at = None;
            state.lockout_expires_at = None;
            // Keep failed_attempts for rate limiting within window
        }

        // Cannot authenticate if permanently locked
        if state.status == LockoutStatus::PermanentlyLocked {
            return Ok(LockoutStatus::PermanentlyLocked);
        }

        // Record the failed attempt
        let attempt = FailedAttempt {
            timestamp: Utc::now(),
            ip_address: ip_address.clone(),
            reason: reason.into(),
        };

        if self.config.log_failed_attempts {
            tracing::warn!(
                account_id = account_id,
                ip = ?ip_address,
                reason = %attempt.reason,
                "Authentication failure recorded"
            );
        }

        state.failed_attempts.push(attempt);

        // Clean up old attempts outside the window
        let cutoff = Utc::now() - Duration::seconds(self.config.failure_window_secs);
        state.failed_attempts.retain(|a| a.timestamp > cutoff);

        // Check if threshold exceeded
        let failure_count = state.recent_failure_count(self.config.failure_window_secs);

        if failure_count >= self.config.max_failed_attempts {
            state.total_lockouts += 1;

            // Check for permanent lockout
            if self.config.permanent_lockout
                && state.total_lockouts >= self.config.lockouts_before_permanent
            {
                state.status = LockoutStatus::PermanentlyLocked;
                state.locked_at = Some(Utc::now());
                state.lockout_expires_at = None;

                tracing::error!(
                    account_id = account_id,
                    total_lockouts = state.total_lockouts,
                    "Account permanently locked after repeated lockouts"
                );

                if self.config.notify_admin_on_lockout {
                    // In production, this would trigger an alert
                    tracing::error!(
                        "SECURITY ALERT: Account '{}' permanently locked - admin intervention required",
                        account_id
                    );
                }

                return Ok(LockoutStatus::PermanentlyLocked);
            }

            // Temporary lockout
            state.status = LockoutStatus::TemporarilyLocked;
            state.locked_at = Some(Utc::now());
            state.lockout_expires_at =
                Some(Utc::now() + Duration::seconds(self.config.lockout_duration_secs));

            tracing::warn!(
                account_id = account_id,
                lockout_number = state.total_lockouts,
                duration_secs = self.config.lockout_duration_secs,
                "Account temporarily locked due to failed authentication attempts"
            );

            if self.config.notify_admin_on_lockout {
                tracing::warn!(
                    "SECURITY ALERT: Account '{}' locked after {} failed attempts",
                    account_id,
                    failure_count
                );
            }

            return Ok(LockoutStatus::TemporarilyLocked);
        }

        Ok(LockoutStatus::Active)
    }

    /// Record a successful authentication
    ///
    /// Resets failure counter and updates last success timestamp
    pub fn record_success(&self, account_id: &str) -> Result<(), LockoutError> {
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| LockoutError::LockPoisoned)?;

        if let Some(state) = accounts.get_mut(account_id) {
            // Cannot unlock permanently locked accounts via success
            if state.status == LockoutStatus::PermanentlyLocked {
                return Err(LockoutError::PermanentlyLocked);
            }

            state.status = LockoutStatus::Active;
            state.failed_attempts.clear();
            state.locked_at = None;
            state.lockout_expires_at = None;
            state.last_success = Some(Utc::now());

            tracing::debug!(
                account_id = account_id,
                "Successful authentication recorded"
            );
        }

        Ok(())
    }

    /// Admin unlock - unlock a permanently locked account
    ///
    /// NIAP PP-CA: FIA_AFL.1 - Admin intervention for permanent lockout
    pub fn admin_unlock(&self, account_id: &str, admin_id: &str) -> Result<(), LockoutError> {
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| LockoutError::LockPoisoned)?;

        if let Some(state) = accounts.get_mut(account_id) {
            tracing::info!(
                account_id = account_id,
                admin_id = admin_id,
                previous_status = ?state.status,
                "Admin unlocking account"
            );

            state.status = LockoutStatus::Active;
            state.failed_attempts.clear();
            state.locked_at = None;
            state.lockout_expires_at = None;
            // Don't reset total_lockouts - keep for audit trail
        }

        Ok(())
    }

    /// Get the current lockout status for an account
    pub fn get_status(&self, account_id: &str) -> Result<Option<LockoutStatus>, LockoutError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| LockoutError::LockPoisoned)?;

        Ok(accounts.get(account_id).map(|s| {
            if s.status == LockoutStatus::TemporarilyLocked && s.is_lockout_expired() {
                LockoutStatus::Active
            } else {
                s.status
            }
        }))
    }

    /// Get the remaining lockout time in seconds (0 if not locked)
    pub fn get_remaining_lockout_time(&self, account_id: &str) -> Result<i64, LockoutError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| LockoutError::LockPoisoned)?;

        if let Some(state) = accounts.get(account_id) {
            if state.status == LockoutStatus::TemporarilyLocked {
                if let Some(expires) = state.lockout_expires_at {
                    let remaining = (expires - Utc::now()).num_seconds();
                    return Ok(remaining.max(0));
                }
            } else if state.status == LockoutStatus::PermanentlyLocked {
                return Ok(i64::MAX); // Infinite
            }
        }

        Ok(0)
    }

    /// Get recent failure count for an account
    pub fn get_failure_count(&self, account_id: &str) -> Result<u32, LockoutError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| LockoutError::LockPoisoned)?;

        Ok(accounts
            .get(account_id)
            .map(|s| s.recent_failure_count(self.config.failure_window_secs))
            .unwrap_or(0))
    }

    /// Get the lockout configuration
    pub fn config(&self) -> &LockoutConfig {
        &self.config
    }
}

/// Lockout-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum LockoutError {
    /// Internal lock was poisoned
    #[error("Internal lock error")]
    LockPoisoned,

    /// Account is permanently locked
    #[error("Account is permanently locked")]
    PermanentlyLocked,

    /// Account not found
    #[error("Account not found: {0}")]
    AccountNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_constants::test_ipv4;

    /// FIA_AFL.1 - Test lockout configuration
    #[test]
    fn test_lockout_config() {
        let config = LockoutConfig::new();
        assert_eq!(config.max_failed_attempts, DEFAULT_MAX_FAILED_ATTEMPTS);
        assert_eq!(config.lockout_duration_secs, DEFAULT_LOCKOUT_DURATION_SECS);
    }

    /// FIA_AFL.1 - Test high security configuration
    #[test]
    fn test_high_security_config() {
        let config = LockoutConfig::high_security();
        assert_eq!(config.max_failed_attempts, 3);
        assert!(config.permanent_lockout);
    }

    /// FIA_AFL.1.1 - Test failure recording
    #[test]
    fn test_record_failure() {
        let lockout = AuthLockout::new(LockoutConfig::new().with_max_attempts(3));

        // First failure (RFC 5737 TEST-NET-1)
        let status = lockout
            .record_failure("user1", Some(test_ipv4::TEST_NET_1.to_string()), "invalid password")
            .unwrap();
        assert_eq!(status, LockoutStatus::Active);

        // Second failure
        let status = lockout
            .record_failure("user1", Some(test_ipv4::TEST_NET_1.to_string()), "invalid password")
            .unwrap();
        assert_eq!(status, LockoutStatus::Active);

        // Third failure - should lock
        let status = lockout
            .record_failure("user1", Some(test_ipv4::TEST_NET_1.to_string()), "invalid password")
            .unwrap();
        assert_eq!(status, LockoutStatus::TemporarilyLocked);
    }

    /// FIA_AFL.1.2 - Test authentication blocking
    #[test]
    fn test_authentication_blocked() {
        let lockout = AuthLockout::new(LockoutConfig::new().with_max_attempts(2));

        // Lock the account
        lockout
            .record_failure("user1", None, "invalid password")
            .unwrap();
        lockout
            .record_failure("user1", None, "invalid password")
            .unwrap();

        // Authentication should be blocked
        assert!(!lockout.is_authentication_allowed("user1").unwrap());
    }

    /// FIA_AFL.1 - Test success resets failures
    #[test]
    fn test_success_resets_failures() {
        let lockout = AuthLockout::new(LockoutConfig::new().with_max_attempts(3));

        // Record two failures
        lockout.record_failure("user1", None, "fail").unwrap();
        lockout.record_failure("user1", None, "fail").unwrap();
        assert_eq!(lockout.get_failure_count("user1").unwrap(), 2);

        // Record success
        lockout.record_success("user1").unwrap();
        assert_eq!(lockout.get_failure_count("user1").unwrap(), 0);
    }

    /// FIA_AFL.1 - Test permanent lockout
    #[test]
    fn test_permanent_lockout() {
        let lockout = AuthLockout::new(
            LockoutConfig::new()
                .with_max_attempts(2)
                .with_lockout_duration(1) // 1 second for test
                .with_permanent_lockout(2),
        );

        // First lockout
        lockout.record_failure("user1", None, "fail").unwrap();
        let status = lockout.record_failure("user1", None, "fail").unwrap();
        assert_eq!(status, LockoutStatus::TemporarilyLocked);

        // Wait for lockout to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Second lockout - should be permanent
        lockout.record_failure("user1", None, "fail").unwrap();
        let status = lockout.record_failure("user1", None, "fail").unwrap();
        assert_eq!(status, LockoutStatus::PermanentlyLocked);

        // Verify account is permanently locked
        assert!(!lockout.is_authentication_allowed("user1").unwrap());
    }

    /// FIA_AFL.1 - Test admin unlock
    #[test]
    fn test_admin_unlock() {
        let lockout = AuthLockout::new(
            LockoutConfig::new()
                .with_max_attempts(1)
                .with_permanent_lockout(1),
        );

        // Lock the account
        lockout.record_failure("user1", None, "fail").unwrap();
        assert_eq!(
            lockout.get_status("user1").unwrap(),
            Some(LockoutStatus::PermanentlyLocked)
        );

        // Admin unlock
        lockout.admin_unlock("user1", "admin").unwrap();
        assert_eq!(
            lockout.get_status("user1").unwrap(),
            Some(LockoutStatus::Active)
        );
    }

    /// FIA_AFL.1 - Test unknown account allowed
    #[test]
    fn test_unknown_account_allowed() {
        let lockout = AuthLockout::with_defaults();
        assert!(lockout.is_authentication_allowed("unknown").unwrap());
    }

    /// FIA_AFL.1 - Test remaining lockout time
    #[test]
    fn test_remaining_lockout_time() {
        let lockout = AuthLockout::new(
            LockoutConfig::new()
                .with_max_attempts(1)
                .with_lockout_duration(60),
        );

        // Lock the account
        lockout.record_failure("user1", None, "fail").unwrap();

        let remaining = lockout.get_remaining_lockout_time("user1").unwrap();
        assert!(remaining > 55 && remaining <= 60);
    }
}
