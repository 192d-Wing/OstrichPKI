//! Structured audit emission for the NPE portal.
//!
//! Every security-relevant auth action — login success, login failure, USG
//! consent acknowledgement, and logout — is recorded as a canonical
//! `ostrich_audit::AuditEvent` (AU-3 fields: actor, target, action, outcome,
//! timestamp, IP, session) and emitted as structured JSON on the dedicated
//! `ostrich_audit` tracing target. The event hash is computed so each record
//! carries an integrity digest.
//!
//! POAM: the BFF emits to the audit pipeline via tracing rather than writing
//! directly to the hash-chained, optionally-signed `DatabaseAuditSink`
//! (AU-9(3)/AU-10), because the portal does not hold a database connection.
//! When the portal is provisioned with the audit DB/service, swap `emit` for a
//! shared `Arc<dyn AuditSink>` so records land in the tamper-evident store.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Auditable events), AU-3 (Audit content),
//!   AU-12 (Audit generation), AC-7 (Unsuccessful logon attempts)
//! - NIAP PP-CA: FAU_GEN.1 / FAU_GEN.2 (audit generation + identity association)

use ostrich_audit::{AuditEventBuilder, EventOutcome, EventType};
use serde_json::Value;

/// Build, hash, and emit a single audit record on the `ostrich_audit` target.
fn emit(
    actor: &str,
    target: &str,
    action: &str,
    outcome: EventOutcome,
    ip: Option<&str>,
    session_id: Option<&str>,
    details: Option<Value>,
) {
    let mut builder = AuditEventBuilder::new(EventType::Authentication, actor, target, action, outcome);
    if let Some(ip) = ip {
        builder = builder.with_ip(ip);
    }
    if let Some(sid) = session_id {
        builder = builder.with_session(sid);
    }
    if let Some(d) = details {
        builder = builder.with_details(d);
    }
    let mut event = builder.build();
    // Integrity digest over the record (FAU_STG.4); the durable hash-chain link
    // is added by the DatabaseAuditSink once wired (see module POAM).
    event.event_hash = event.compute_hash();

    match serde_json::to_string(&event) {
        Ok(json) => tracing::info!(target: "ostrich_audit", audit = %json, "audit event"),
        Err(e) => tracing::error!(error = %e, action, "failed to serialize audit event"),
    }
}

/// Successful mTLS authentication → new session minted.
pub fn login_success(actor: &str, role: &str, ip: Option<&str>, session_id: &str) {
    emit(
        actor,
        actor,
        "login",
        EventOutcome::Success,
        ip,
        Some(session_id),
        Some(serde_json::json!({ "role": role, "auth_method": "mtls" })),
    );
}

/// Failed mTLS authentication (no/unauthorized client certificate).
pub fn login_failed(reason: &str, ip: Option<&str>) {
    emit(
        "unknown",
        "npe-portal",
        "login_failed",
        EventOutcome::Failure,
        ip,
        None,
        Some(serde_json::json!({ "reason": reason, "auth_method": "mtls" })),
    );
}

/// USG consent banner acknowledged for a session.
pub fn consent_accepted(actor: &str, ip: Option<&str>, session_id: &str) {
    emit(
        actor,
        actor,
        "consent_accepted",
        EventOutcome::Success,
        ip,
        Some(session_id),
        None,
    );
}

/// Session invalidated by the user.
pub fn logout(actor: &str, ip: Option<&str>, session_id: &str) {
    emit(
        actor,
        actor,
        "logout",
        EventOutcome::Success,
        ip,
        Some(session_id),
        None,
    );
}
