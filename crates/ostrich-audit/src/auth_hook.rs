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
        // COMPLIANCE MAPPING:
        // - NIST 800-53: AU-2 / AU-3 - access denials and TLS session failures
        //   are auditable; AC-3 - denials are Authorization records
        // - NIAP PP-CA: FAU_GEN.1 (TLS session establishment failure, access
        //   denial), FIA_X509_EXT.1 (certificate validation failure)
        let (event_type, action, outcome) = match event.kind {
            AuthAuditKind::LoginFailed => (
                EventType::Authentication,
                "login_failed",
                EventOutcome::Failure,
            ),
            AuthAuditKind::AccountLocked => (
                EventType::Authentication,
                "account_locked",
                EventOutcome::Failure,
            ),
            // An unlock is a successful administrative action.
            AuthAuditKind::AccountUnlocked => (
                EventType::Authentication,
                "account_unlocked",
                EventOutcome::Success,
            ),
            AuthAuditKind::AccessDenied => (
                EventType::Authorization,
                "access_denied",
                EventOutcome::Failure,
            ),
            AuthAuditKind::TlsHandshakeFailed => (
                EventType::Authentication,
                "tls_handshake_failed",
                EventOutcome::Failure,
            ),
            AuthAuditKind::TlsHandshakeFailuresSuppressed => (
                EventType::Authentication,
                "tls_handshake_failures_suppressed",
                EventOutcome::Failure,
            ),
            AuthAuditKind::AccessDeniedSuppressed => (
                EventType::Authorization,
                "access_denied_suppressed",
                EventOutcome::Failure,
            ),
        };

        // actor = who performed the action (admin for unlock; otherwise the
        // subject is the actor of its own failed attempt). target = the
        // resource acted on when known (e.g. a gRPC method), else the subject.
        let actor = event.actor.clone().unwrap_or_else(|| event.subject.clone());
        let target = event
            .resource
            .clone()
            .unwrap_or_else(|| event.subject.clone());

        let mut builder = AuditEventBuilder::new(event_type, actor, target, action, outcome);
        if let Some(ip) = event.ip_address {
            builder = builder.with_ip(ip);
        }
        if let Some(details) = merge_details(event.reason, event.details) {
            builder = builder.with_details(details);
        }

        let mut record = builder.build();
        // Audit emission must never change the auth outcome; log and swallow.
        if let Err(e) = self.sink.record(&mut record).await {
            tracing::warn!(error = %e, action, "failed to record auth audit event");
        }
    }
}

/// Combine the event `reason` and structured `details` into one JSON object.
/// Object details are merged key-by-key (`reason` wins on a clash); any other
/// JSON value is kept under a `details` key.
fn merge_details(
    reason: Option<String>,
    details: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    match details {
        Some(serde_json::Value::Object(obj)) => map.extend(obj),
        Some(other) => {
            map.insert("details".to_string(), other);
        }
        None => {}
    }
    if let Some(reason) = reason {
        map.insert("reason".to_string(), serde_json::Value::String(reason));
    }
    (!map.is_empty()).then_some(serde_json::Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryAuditSink;
    use crate::sink::QueryCriteria;

    async fn record_one(event: AuthAuditEvent) -> crate::AuditEvent {
        let sink = Arc::new(MemoryAuditSink::new());
        AuthAuditAdapter::new(sink.clone())
            .record_auth_event(event)
            .await;
        let mut events = sink
            .query_events(QueryCriteria::default())
            .await
            .expect("query");
        assert_eq!(events.len(), 1);
        events.remove(0)
    }

    /// AC-3 / AU-3: an allowlist denial is an Authorization failure whose
    /// target is the method path, with the peer subject as actor.
    #[tokio::test]
    async fn access_denied_maps_to_authorization_failure() {
        let rec = record_one(AuthAuditEvent {
            kind: AuthAuditKind::AccessDenied,
            subject: "CN=intruder".to_string(),
            ip_address: Some("10.0.0.7".to_string()),
            reason: Some("subject_not_allowlisted".to_string()),
            actor: None,
            resource: Some(
                "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate".to_string(),
            ),
            details: Some(serde_json::json!({ "listener": "ca-grpc" })),
        })
        .await;
        assert_eq!(rec.event_type, EventType::Authorization);
        assert_eq!(rec.action, "access_denied");
        assert_eq!(rec.outcome, EventOutcome::Failure);
        assert_eq!(rec.actor, "CN=intruder");
        assert_eq!(
            rec.target,
            "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate"
        );
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.7"));
        let details = rec.details.expect("details");
        assert_eq!(details["reason"], "subject_not_allowlisted");
        assert_eq!(details["listener"], "ca-grpc");
    }

    /// FAU_GEN.1: a TLS handshake failure is an Authentication failure whose
    /// target is the listener.
    #[tokio::test]
    async fn tls_handshake_failed_maps_to_authentication_failure() {
        let rec = record_one(AuthAuditEvent {
            kind: AuthAuditKind::TlsHandshakeFailed,
            subject: "unauthenticated".to_string(),
            ip_address: Some("10.0.0.8".to_string()),
            reason: Some("no_client_certificate".to_string()),
            actor: None,
            resource: Some("ca-grpc".to_string()),
            details: None,
        })
        .await;
        assert_eq!(rec.event_type, EventType::Authentication);
        assert_eq!(rec.action, "tls_handshake_failed");
        assert_eq!(rec.outcome, EventOutcome::Failure);
        assert_eq!(rec.actor, "unauthenticated");
        assert_eq!(rec.target, "ca-grpc");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.8"));
        assert_eq!(
            rec.details.expect("details")["reason"],
            "no_client_certificate"
        );
    }

    /// The suppression summary carries its count/window details.
    #[tokio::test]
    async fn suppressed_summary_keeps_structured_details() {
        let rec = record_one(AuthAuditEvent {
            kind: AuthAuditKind::TlsHandshakeFailuresSuppressed,
            subject: "system".to_string(),
            ip_address: None,
            reason: None,
            actor: None,
            resource: Some("ca-grpc".to_string()),
            details: Some(serde_json::json!({ "count": 12, "window_secs": 60 })),
        })
        .await;
        assert_eq!(rec.action, "tls_handshake_failures_suppressed");
        assert_eq!(rec.target, "ca-grpc");
        let details = rec.details.expect("details");
        assert_eq!(details["count"], 12);
        assert_eq!(details["window_secs"], 60);
        assert!(details.get("reason").is_none());
    }

    /// The access-denial suppression summary is an Authorization record.
    #[tokio::test]
    async fn access_denied_summary_maps_to_authorization() {
        let rec = record_one(AuthAuditEvent {
            kind: AuthAuditKind::AccessDeniedSuppressed,
            subject: "system".to_string(),
            ip_address: None,
            reason: None,
            actor: None,
            resource: Some("ca-grpc".to_string()),
            details: Some(serde_json::json!({ "count": 3, "window_secs": 60 })),
        })
        .await;
        assert_eq!(rec.event_type, EventType::Authorization);
        assert_eq!(rec.action, "access_denied_suppressed");
        assert_eq!(rec.outcome, EventOutcome::Failure);
        assert_eq!(rec.target, "ca-grpc");
        assert_eq!(rec.details.expect("details")["count"], 3);
    }

    /// Legacy events keep their previous shape: target = subject, details =
    /// `{reason}` only.
    #[tokio::test]
    async fn login_failed_unchanged() {
        let rec = record_one(AuthAuditEvent {
            kind: AuthAuditKind::LoginFailed,
            subject: "alice".to_string(),
            ip_address: None,
            reason: Some("invalid_password".to_string()),
            actor: None,
            resource: None,
            details: None,
        })
        .await;
        assert_eq!(rec.event_type, EventType::Authentication);
        assert_eq!(rec.action, "login_failed");
        assert_eq!(rec.target, "alice");
        assert_eq!(
            rec.details.expect("details"),
            serde_json::json!({ "reason": "invalid_password" })
        );
    }
}
