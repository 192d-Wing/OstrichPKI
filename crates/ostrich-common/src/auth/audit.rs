//! Authentication audit events.
//!
//! Defines the seam by which the auth providers report security-relevant
//! authentication outcomes (failed login, account lockout, admin unlock) for
//! audit. The trait lives here so the foundational `ostrich-common` crate stays
//! independent of `ostrich-audit`; that crate provides the adapter that turns
//! these into hash-chained audit records.
//!
//! Successful logins are audited via the session-created event (see
//! `SessionAuditHook`), so this hook covers the *unsuccessful* and
//! lockout-management side that has no session.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Auditable events), AC-7 (Unsuccessful Logon Attempts)
//! - NIAP PP-CA: FAU_GEN.1 (Audit data generation), FIA_AFL.1 (auth failure handling)

use async_trait::async_trait;

/// Kind of authentication audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAuditKind {
    /// A login attempt failed (bad credentials).
    LoginFailed,
    /// Repeated failures crossed the threshold and the account was locked.
    AccountLocked,
    /// An account lock was cleared (administrative or automatic unlock).
    AccountUnlocked,
}

/// A security-relevant authentication event for audit emission.
#[derive(Debug, Clone)]
pub struct AuthAuditEvent {
    /// What happened.
    pub kind: AuthAuditKind,
    /// The subject of the event (username, or certificate subject for mTLS).
    pub subject: String,
    /// Client IP, when known.
    pub ip_address: Option<String>,
    /// Free-form reason / detail (e.g. "invalid_password"), when relevant.
    pub reason: Option<String>,
    /// The acting administrator, for an admin-initiated unlock.
    pub actor: Option<String>,
}

/// Sink for authentication audit events.
///
/// Implementations must not panic and must swallow their own backend errors:
/// audit emission must never change the outcome of the authentication it
/// describes. NIST 800-53: AU-2 / AC-7. NIAP PP-CA: FAU_GEN.1.
#[async_trait]
pub trait AuthAuditHook: Send + Sync {
    /// Record an authentication audit event.
    async fn record_auth_event(&self, event: AuthAuditEvent);
}
