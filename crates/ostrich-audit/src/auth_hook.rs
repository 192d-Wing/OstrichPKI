//! Adapter from authentication events to audit records.
//!
//! `ostrich-common` defines [`AuthAuditHook`] but cannot depend on this crate.
//! This adapter turns an [`AuthAuditEvent`] (failed login, account lock/unlock)
//! into a hash-chained [`AuditEvent`] on any [`AuditSink`]. Providers attach it
//! via `PasswordAuthProvider::with_audit_hook`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Auditable events), AC-7 (Unsuccessful Logon Attempts)
//! - NIST 800-53: AU-3 (Audit content) - subject, outcome, reason, IP
//! - NIAP PP-CA: FAU_GEN.1, FIA_AFL.1 (authentication failure handling)

use std::sync::Arc;

use async_trait::async_trait;
use ostrich_common::auth::{AuthAuditEvent, AuthAuditHook, AuthAuditKind};

use crate::{AuditEventBuilder, AuditSink, EventOutcome, EventType};

/// Writes authentication events to an [`AuditSink`] as `Authentication` records.
pub struct AuthAuditAdapter {
    sink: Arc<dyn AuditSink>,
}

impl AuthAuditAdapter {
    /// Wrap an audit sink so it can receive authentication events.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl AuthAuditHook for AuthAuditAdapter {
    async fn record_auth_event(&self, event: AuthAuditEvent) {
        let (action, outcome) = match event.kind {
            AuthAuditKind::LoginFailed => ("login_failed", EventOutcome::Failure),
            AuthAuditKind::AccountLocked => ("account_locked", EventOutcome::Failure),
            // An unlock is a successful administrative action.
            AuthAuditKind::AccountUnlocked => ("account_unlocked", EventOutcome::Success),
        };

        // actor = who performed the action (admin for unlock; otherwise the
        // subject is the actor of its own failed attempt). target = the subject.
        let actor = event.actor.clone().unwrap_or_else(|| event.subject.clone());

        let mut builder = AuditEventBuilder::new(
            EventType::Authentication,
            actor,
            event.subject.clone(),
            action,
            outcome,
        );
        if let Some(ip) = event.ip_address {
            builder = builder.with_ip(ip);
        }
        if let Some(reason) = event.reason {
            builder = builder.with_details(serde_json::json!({ "reason": reason }));
        }

        let mut record = builder.build();
        // Audit emission must never change the auth outcome; log and swallow.
        if let Err(e) = self.sink.record(&mut record).await {
            tracing::warn!(error = %e, action, "failed to record auth audit event");
        }
    }
}
