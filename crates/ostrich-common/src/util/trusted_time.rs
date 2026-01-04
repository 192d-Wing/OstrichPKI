//! Reliable Time Stamps Module
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FPT_STM_EXT.1 (Reliable Time Stamps)
//! - NIAP PP-CA: FPT_STM.1 (Reliable Time Stamps - base)
//! - NIST 800-53: AU-8 (Time Stamps)
//! - NIST 800-53: SC-45 (System Time Synchronization)
//!
//! This module provides trusted timestamp functionality for:
//! - Certificate validity periods (notBefore, notAfter)
//! - Audit log timestamps
//! - CRL thisUpdate/nextUpdate
//! - OCSP response producedAt
//!
//! Per FPT_STM_EXT.1, the TOE must:
//! 1. Provide reliable time stamps from a trusted source
//! 2. Detect time source unavailability
//! 3. Take appropriate action when time is unreliable

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Maximum allowed clock skew in seconds before flagging as unreliable
/// NIAP PP-CA: FPT_STM_EXT.1 - Time reliability threshold
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 60;

/// Minimum time between time source checks in seconds
pub const MIN_TIME_CHECK_INTERVAL_SECONDS: i64 = 300; // 5 minutes

/// Global flag indicating whether system time is considered reliable
static TIME_RELIABLE: AtomicBool = AtomicBool::new(true);

/// Last known good timestamp (Unix timestamp)
static LAST_KNOWN_GOOD_TIME: AtomicI64 = AtomicI64::new(0);

/// Time source configuration
static TIME_SOURCE: RwLock<Option<TimeSourceConfig>> = RwLock::new(None);

/// Time source types
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Trusted time source selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum TimeSourceType {
    /// System clock (default, less trusted)
    #[default]
    System,
    /// NTP server (network time protocol)
    Ntp,
    /// Hardware security module clock
    Hsm,
    /// GPS receiver
    Gps,
    /// RFC 3161 Time Stamping Authority
    Tsa,
    /// Authenticated NTP (NTS)
    AuthenticatedNtp,
}


impl TimeSourceType {
    /// Get the trust level of this time source (higher is more trusted)
    pub fn trust_level(&self) -> u8 {
        match self {
            TimeSourceType::System => 1,
            TimeSourceType::Ntp => 2,
            TimeSourceType::AuthenticatedNtp => 4,
            TimeSourceType::Hsm => 5,
            TimeSourceType::Gps => 5,
            TimeSourceType::Tsa => 5,
        }
    }

    /// Check if this source requires network connectivity
    pub fn requires_network(&self) -> bool {
        matches!(
            self,
            TimeSourceType::Ntp | TimeSourceType::AuthenticatedNtp | TimeSourceType::Tsa
        )
    }
}

/// Time source configuration
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Time source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSourceConfig {
    /// Primary time source type
    pub source_type: TimeSourceType,
    /// NTP server addresses (for NTP/AuthenticatedNtp sources)
    pub ntp_servers: Vec<String>,
    /// Maximum allowed clock skew in seconds
    pub max_skew_seconds: i64,
    /// Whether to allow fallback to system time
    pub allow_system_fallback: bool,
    /// Time check interval in seconds
    pub check_interval_seconds: i64,
    /// Last successful time sync
    pub last_sync: Option<DateTime<Utc>>,
}

impl Default for TimeSourceConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSourceConfig {
    /// Create new time source configuration with secure defaults
    pub fn new() -> Self {
        Self {
            source_type: TimeSourceType::System,
            ntp_servers: vec![
                "time.nist.gov".to_string(),
                "time.google.com".to_string(),
                "pool.ntp.org".to_string(),
            ],
            max_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
            allow_system_fallback: true,
            check_interval_seconds: MIN_TIME_CHECK_INTERVAL_SECONDS,
            last_sync: None,
        }
    }

    /// Create configuration for HSM time source
    pub fn hsm() -> Self {
        Self {
            source_type: TimeSourceType::Hsm,
            ntp_servers: Vec::new(),
            max_skew_seconds: 1,          // HSM should be very accurate
            allow_system_fallback: false, // Don't trust system time if HSM fails
            check_interval_seconds: 60,
            last_sync: None,
        }
    }

    /// Create configuration for authenticated NTP
    pub fn authenticated_ntp(servers: Vec<String>) -> Self {
        Self {
            source_type: TimeSourceType::AuthenticatedNtp,
            ntp_servers: servers,
            max_skew_seconds: 5, // NTS should be very accurate
            allow_system_fallback: true,
            check_interval_seconds: 300,
            last_sync: None,
        }
    }
}

/// Trusted timestamp with metadata
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Timestamp with reliability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedTimestamp {
    /// The timestamp value
    pub timestamp: DateTime<Utc>,
    /// Whether this timestamp is from a trusted source
    pub is_trusted: bool,
    /// The source type that provided this timestamp
    pub source: TimeSourceType,
    /// Estimated accuracy in milliseconds
    pub accuracy_ms: Option<u32>,
    /// Reason if timestamp is not trusted
    pub untrusted_reason: Option<String>,
}

impl TrustedTimestamp {
    /// Create a new trusted timestamp from the current time
    pub fn now() -> Self {
        let is_reliable = TIME_RELIABLE.load(Ordering::SeqCst);
        let source = TIME_SOURCE
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|c| c.source_type))
            .unwrap_or(TimeSourceType::System);

        Self {
            timestamp: Utc::now(),
            is_trusted: is_reliable,
            source,
            accuracy_ms: None,
            untrusted_reason: if is_reliable {
                None
            } else {
                Some("Time source not verified".to_string())
            },
        }
    }

    /// Create a trusted timestamp from a specific datetime
    pub fn from_datetime(dt: DateTime<Utc>, source: TimeSourceType) -> Self {
        Self {
            timestamp: dt,
            is_trusted: true,
            source,
            accuracy_ms: None,
            untrusted_reason: None,
        }
    }

    /// Create an untrusted timestamp (for fallback scenarios)
    pub fn untrusted(dt: DateTime<Utc>, reason: impl Into<String>) -> Self {
        Self {
            timestamp: dt,
            is_trusted: false,
            source: TimeSourceType::System,
            accuracy_ms: None,
            untrusted_reason: Some(reason.into()),
        }
    }

    /// Set accuracy information
    pub fn with_accuracy(mut self, accuracy_ms: u32) -> Self {
        self.accuracy_ms = Some(accuracy_ms);
        self
    }

    /// Format as RFC 3339 string
    pub fn to_rfc3339(&self) -> String {
        self.timestamp.to_rfc3339()
    }

    /// Get Unix timestamp
    pub fn unix_timestamp(&self) -> i64 {
        self.timestamp.timestamp()
    }
}

/// Time reliability status
///
/// NIAP PP-CA: FPT_STM_EXT.1.2 - Time source status reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStatus {
    /// Whether time is considered reliable
    pub is_reliable: bool,
    /// Current time source
    pub source: TimeSourceType,
    /// Last successful sync time
    pub last_sync: Option<DateTime<Utc>>,
    /// Estimated clock offset from trusted source (if known)
    pub clock_offset_ms: Option<i64>,
    /// Any warnings about time reliability
    pub warnings: Vec<String>,
}

impl TimeStatus {
    /// Get current time status
    pub fn current() -> Self {
        let is_reliable = TIME_RELIABLE.load(Ordering::SeqCst);
        let config = TIME_SOURCE.read().ok().and_then(|s| s.clone());

        let (source, last_sync) = config
            .map(|c| (c.source_type, c.last_sync))
            .unwrap_or((TimeSourceType::System, None));

        let mut warnings = Vec::new();
        if !is_reliable {
            warnings.push("Time source is not verified as reliable".to_string());
        }
        if source == TimeSourceType::System {
            warnings.push(
                "Using system clock - consider configuring NTP or HSM time source".to_string(),
            );
        }

        Self {
            is_reliable,
            source,
            last_sync,
            clock_offset_ms: None,
            warnings,
        }
    }
}

/// Initialize the time subsystem with configuration
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Initialize reliable time source
pub fn initialize_time_source(config: TimeSourceConfig) -> Result<(), TimeError> {
    // Store configuration
    if let Ok(mut guard) = TIME_SOURCE.write() {
        *guard = Some(config.clone());
    }

    // For now, mark time as reliable if using system clock
    // In production, this would verify against the configured time source
    let reliable = match config.source_type {
        TimeSourceType::System => {
            // System clock is considered baseline reliable
            // but should log a warning about reduced assurance
            true
        }
        TimeSourceType::Ntp | TimeSourceType::AuthenticatedNtp => {
            // Would need to actually sync with NTP server
            // For now, mark as reliable if servers are configured
            !config.ntp_servers.is_empty()
        }
        TimeSourceType::Hsm | TimeSourceType::Gps | TimeSourceType::Tsa => {
            // These require actual hardware/service verification
            // For now, mark as unreliable until verified
            false
        }
    };

    TIME_RELIABLE.store(reliable, Ordering::SeqCst);
    LAST_KNOWN_GOOD_TIME.store(Utc::now().timestamp(), Ordering::SeqCst);

    Ok(())
}

/// Get current trusted time
///
/// NIAP PP-CA: FPT_STM_EXT.1.1 - Provide reliable time stamps
pub fn get_trusted_time() -> TrustedTimestamp {
    TrustedTimestamp::now()
}

/// Get current time for certificate operations
///
/// Returns the current UTC time if time source is reliable,
/// otherwise returns an error per FPT_STM_EXT.1.3
pub fn get_certificate_time() -> Result<DateTime<Utc>, TimeError> {
    if !TIME_RELIABLE.load(Ordering::SeqCst) {
        return Err(TimeError::TimeSourceUnavailable(
            "Time source is not reliable for certificate operations".to_string(),
        ));
    }
    Ok(Utc::now())
}

/// Get current time for audit logging
///
/// NIST 800-53: AU-8 - Time stamps for audit records
pub fn get_audit_time() -> TrustedTimestamp {
    TrustedTimestamp::now()
}

/// Validate that a timestamp is within acceptable bounds
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Validate timestamp reasonableness
pub fn validate_timestamp(timestamp: DateTime<Utc>) -> Result<(), TimeError> {
    let now = Utc::now();
    let skew = (now - timestamp).num_seconds().abs();

    if skew > MAX_CLOCK_SKEW_SECONDS {
        return Err(TimeError::ClockSkewExceeded {
            expected: now,
            actual: timestamp,
            skew_seconds: skew,
        });
    }

    // Also check for time going backwards
    let last_good = LAST_KNOWN_GOOD_TIME.load(Ordering::SeqCst);
    if timestamp.timestamp() < last_good - MAX_CLOCK_SKEW_SECONDS {
        return Err(TimeError::TimeWentBackward {
            current: timestamp,
            last_known: DateTime::from_timestamp(last_good, 0)
                .unwrap_or(DateTime::UNIX_EPOCH),
        });
    }

    // Update last known good time
    LAST_KNOWN_GOOD_TIME.store(timestamp.timestamp(), Ordering::SeqCst);

    Ok(())
}

/// Check if time source is currently reliable
///
/// NIAP PP-CA: FPT_STM_EXT.1.2 - Detect time source unavailability
pub fn is_time_reliable() -> bool {
    TIME_RELIABLE.load(Ordering::SeqCst)
}

/// Mark time source as unreliable
///
/// NIAP PP-CA: FPT_STM_EXT.1.3 - Handle time source failure
pub fn mark_time_unreliable(reason: impl Into<String>) {
    TIME_RELIABLE.store(false, Ordering::SeqCst);
    tracing::warn!(
        reason = reason.into(),
        "Time source marked as unreliable - certificate operations may be affected"
    );
}

/// Mark time source as reliable after verification
pub fn mark_time_reliable() {
    TIME_RELIABLE.store(true, Ordering::SeqCst);
    LAST_KNOWN_GOOD_TIME.store(Utc::now().timestamp(), Ordering::SeqCst);
    tracing::info!("Time source verified as reliable");
}

/// Calculate validity period from now
///
/// Helper for certificate issuance
pub fn validity_period(days: u32) -> (DateTime<Utc>, DateTime<Utc>) {
    let not_before = Utc::now();
    let not_after = not_before + Duration::days(i64::from(days));
    (not_before, not_after)
}

/// Calculate validity period with explicit start time
pub fn validity_period_from(start: DateTime<Utc>, days: u32) -> (DateTime<Utc>, DateTime<Utc>) {
    let not_after = start + Duration::days(i64::from(days));
    (start, not_after)
}

/// Time-related errors
///
/// NIAP PP-CA: FPT_STM_EXT.1 - Time error conditions
#[derive(Debug, Clone, thiserror::Error)]
pub enum TimeError {
    /// Time source is unavailable
    #[error("Time source unavailable: {0}")]
    TimeSourceUnavailable(String),

    /// Clock skew exceeded acceptable threshold
    #[error("Clock skew exceeded: expected {expected}, actual {actual}, skew {skew_seconds}s")]
    ClockSkewExceeded {
        expected: DateTime<Utc>,
        actual: DateTime<Utc>,
        skew_seconds: i64,
    },

    /// Time went backward unexpectedly
    #[error("Time went backward: current {current}, last known {last_known}")]
    TimeWentBackward {
        current: DateTime<Utc>,
        last_known: DateTime<Utc>,
    },

    /// Time synchronization failed
    #[error("Time synchronization failed: {0}")]
    SyncFailed(String),

    /// Time source configuration error
    #[error("Time source configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FPT_STM_EXT.1 - Test trusted timestamp creation
    #[test]
    fn test_trusted_timestamp_now() {
        let ts = TrustedTimestamp::now();

        // Timestamp should be close to current time
        let diff = (Utc::now() - ts.timestamp).num_seconds().abs();
        assert!(diff < 2);

        // Should have source information
        assert_eq!(ts.source, TimeSourceType::System);
    }

    /// FPT_STM_EXT.1 - Test time source types
    #[test]
    fn test_time_source_types() {
        // System has lowest trust
        assert_eq!(TimeSourceType::System.trust_level(), 1);

        // HSM, GPS, TSA have highest trust
        assert_eq!(TimeSourceType::Hsm.trust_level(), 5);
        assert_eq!(TimeSourceType::Gps.trust_level(), 5);
        assert_eq!(TimeSourceType::Tsa.trust_level(), 5);

        // NTP requires network
        assert!(TimeSourceType::Ntp.requires_network());
        assert!(!TimeSourceType::Hsm.requires_network());
    }

    /// FPT_STM_EXT.1 - Test time source configuration
    #[test]
    fn test_time_source_config() {
        let config = TimeSourceConfig::new();

        assert_eq!(config.source_type, TimeSourceType::System);
        assert!(!config.ntp_servers.is_empty());
        assert_eq!(config.max_skew_seconds, MAX_CLOCK_SKEW_SECONDS);
    }

    /// FPT_STM_EXT.1 - Test HSM time source configuration
    #[test]
    fn test_hsm_time_config() {
        let config = TimeSourceConfig::hsm();

        assert_eq!(config.source_type, TimeSourceType::Hsm);
        assert!(!config.allow_system_fallback);
        assert_eq!(config.max_skew_seconds, 1);
    }

    /// FPT_STM_EXT.1 - Test time initialization
    #[test]
    fn test_initialize_time_source() {
        let config = TimeSourceConfig::new();
        let result = initialize_time_source(config);

        assert!(result.is_ok());
        assert!(is_time_reliable());
    }

    /// FPT_STM_EXT.1 - Test timestamp validation
    #[test]
    fn test_validate_timestamp() {
        // Current time should be valid
        let now = Utc::now();
        assert!(validate_timestamp(now).is_ok());

        // Old time should fail
        let old = now - Duration::seconds(MAX_CLOCK_SKEW_SECONDS + 10);
        assert!(validate_timestamp(old).is_err());

        // Future time should fail
        let future = now + Duration::seconds(MAX_CLOCK_SKEW_SECONDS + 10);
        assert!(validate_timestamp(future).is_err());
    }

    /// FPT_STM_EXT.1 - Test time reliability marking
    #[test]
    fn test_time_reliability() {
        // Mark as reliable first
        mark_time_reliable();
        assert!(is_time_reliable());

        // Mark as unreliable
        mark_time_unreliable("Test failure");
        assert!(!is_time_reliable());

        // Mark as reliable again
        mark_time_reliable();
        assert!(is_time_reliable());
    }

    /// FPT_STM_EXT.1 - Test time status reporting
    #[test]
    fn test_time_status() {
        // Initialize with system clock
        let config = TimeSourceConfig::new();
        initialize_time_source(config).unwrap();

        let status = TimeStatus::current();
        assert!(status.is_reliable);
        assert_eq!(status.source, TimeSourceType::System);
        // System clock should have a warning
        assert!(!status.warnings.is_empty());
    }

    /// FPT_STM_EXT.1 - Test validity period calculation
    #[test]
    fn test_validity_period() {
        let (not_before, not_after) = validity_period(365);

        // not_after should be 365 days after not_before
        let diff = (not_after - not_before).num_days();
        assert_eq!(diff, 365);

        // not_before should be close to now
        let now_diff = (Utc::now() - not_before).num_seconds().abs();
        assert!(now_diff < 2);
    }

    /// FPT_STM_EXT.1 - Test validity period from specific start
    #[test]
    fn test_validity_period_from() {
        let start = Utc::now() + Duration::days(1);
        let (not_before, not_after) = validity_period_from(start, 365);

        assert_eq!(not_before, start);
        let diff = (not_after - not_before).num_days();
        assert_eq!(diff, 365);
    }

    /// AU-8 - Test audit time
    #[test]
    fn test_get_audit_time() {
        let audit_time = get_audit_time();

        // Should be close to current time
        let diff = (Utc::now() - audit_time.timestamp).num_seconds().abs();
        assert!(diff < 2);
    }

    /// FPT_STM_EXT.1 - Test certificate time with reliable source
    #[test]
    fn test_get_certificate_time() {
        mark_time_reliable();
        let result = get_certificate_time();
        assert!(result.is_ok());

        // Should be close to current time
        let diff = (Utc::now() - result.unwrap()).num_seconds().abs();
        assert!(diff < 2);
    }

    /// FPT_STM_EXT.1 - Test certificate time with unreliable source
    #[test]
    fn test_get_certificate_time_unreliable() {
        mark_time_unreliable("Test");
        let result = get_certificate_time();
        assert!(result.is_err());

        // Reset for other tests
        mark_time_reliable();
    }

    /// FPT_STM_EXT.1 - Test trusted timestamp formatting
    #[test]
    fn test_timestamp_formatting() {
        let ts = TrustedTimestamp::now();

        // RFC 3339 format
        let rfc3339 = ts.to_rfc3339();
        assert!(rfc3339.contains('T'));
        assert!(rfc3339.ends_with("+00:00") || rfc3339.ends_with('Z'));

        // Unix timestamp
        let unix = ts.unix_timestamp();
        assert!(unix > 0);
    }

    /// FPT_STM_EXT.1 - Test untrusted timestamp creation
    #[test]
    fn test_untrusted_timestamp() {
        let ts = TrustedTimestamp::untrusted(Utc::now(), "Test reason");

        assert!(!ts.is_trusted);
        assert_eq!(ts.source, TimeSourceType::System);
        assert!(ts.untrusted_reason.is_some());
        assert!(ts.untrusted_reason.unwrap().contains("Test reason"));
    }

    /// FPT_STM_EXT.1 - Test timestamp with accuracy
    #[test]
    fn test_timestamp_with_accuracy() {
        let ts = TrustedTimestamp::now().with_accuracy(100);

        assert_eq!(ts.accuracy_ms, Some(100));
    }
}
