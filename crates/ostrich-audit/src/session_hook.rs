//! Adapter from the auth layer's session lifecycle events to audit records.
//!
//! `ostrich-common` defines [`SessionAuditHook`] but cannot depend on this crate
//! (the dependency runs the other way). This adapter lives here, where it can
//! turn a [`SessionAuditEvent`] into a hash-chained [`AuditEvent`] and write it
//! to any [`AuditSink`]. Services attach it to their `SessionManager` via
//! `SessionManager::with_audit_hook`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Auditable events) - login/logout/admin-termination
//! - NIST 800-53: AU-3 (Audit content) - actor, subject, session id, IP, outcome
//! - NIAP PP-CA: FAU_GEN.1 (Audit data generation), FAU_GEN.2 (identity association)

use std::sync::Arc;

use async_trait::async_trait;
use ostrich_common::auth::{SessionAuditEvent, SessionAuditHook, SessionAuditKind};

use crate::{AuditEventBuilder, AuditSink, EventOutcome, EventType};

/// Writes session lifecycle events to an [`AuditSink`] as `Authentication`
/// audit records.
pub struct SessionAuditAdapter {
    sink: Arc<dyn AuditSink>,
}

impl SessionAuditAdapter {
    /// Wrap an audit sink so it can receive session lifecycle events.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl SessionAuditHook for SessionAuditAdapter {
    async fn record_session_event(&self, event: SessionAuditEvent) {
        // actor = who performed the action; target = the session's subject.
        let (action, actor) = match event.kind {
            SessionAuditKind::Created => ("session_created", event.user_id.clone()),
            SessionAuditKind::TerminatedByUser => ("session_terminated", event.user_id.clone()),
            SessionAuditKind::TerminatedByAdmin => (
                "session_admin_terminated",
                event.actor.clone().unwrap_or_else(|| "admin".to_string()),
            ),
        };

        let mut builder = AuditEventBuilder::new(
            EventType::Authentication,
            actor,
            event.user_id.clone(),
            action,
            EventOutcome::Success,
        )
        .with_session(event.session_id.to_string());
        if let Some(ip) = event.ip_address {
            builder = builder.with_ip(ip);
        }

        let mut record = builder.build();
        // Audit emission must never fail the session operation it describes;
        // a sink error is logged and swallowed.
        if let Err(e) = self.sink.record(&mut record).await {
            tracing::warn!(error = %e, action, "failed to record session audit event");
        }
    }
}
