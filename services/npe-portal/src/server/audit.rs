//! Structured audit emission for the NPE portal.
//!
//! Every security-relevant auth action — login success, login failure, USG
//! consent acknowledgement, and logout — and every access-control denial at
//! the proxy boundary (unsafe CA/EST proxy path) is recorded as a canonical
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
//! - NIST 800-53: AC-3 (Access Enforcement) - proxy denials (`proxy_path_rejected`)
//!   are recorded as `EventType::Authorization` / `EventOutcome::Failure`
//! - NIAP PP-CA: FAU_GEN.1 / FAU_GEN.2 (audit generation + identity association)

use ostrich_audit::{AuditEventBuilder, EventOutcome, EventType};
use serde_json::Value;

/// Build, hash, and emit a single authentication audit record on the
/// `ostrich_audit` target.
fn emit(
    actor: &str,
    target: &str,
    action: &str,
    outcome: EventOutcome,
    ip: Option<&str>,
    session_id: Option<&str>,
    details: Option<Value>,
) {
    let builder = AuditEventBuilder::new(EventType::Authentication, actor, target, action, outcome);
    emit_built(builder, ip, session_id, details);
}

/// Attach the optional AU-3 fields to `builder`, hash the record, and emit it
/// on the `ostrich_audit` target. The builder fixes the `EventType`.
fn emit_built(
    mut builder: AuditEventBuilder,
    ip: Option<&str>,
    session_id: Option<&str>,
    details: Option<Value>,
) {
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
        Err(e) => {
            tracing::error!(error = %e, action = %event.action, "failed to serialize audit event");
        }
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

/// CA/EST proxy request refused because its raw path failed validation
/// (POAM-2026-10-23-46). Recorded as an access-control denial; no session id
/// is attached and the path is stored Debug-escaped.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3 (Access Enforcement) denial record, AU-2/AU-3/AU-12
/// - NIAP PP-CA: FAU_GEN.1.1 (audit of access-control failures), FDP_ACF.1 (supporting)
pub fn proxy_path_rejected(
    actor: &str,
    service: &str,
    method: &str,
    path: &str,
    reason: &str,
    ip: Option<&str>,
) {
    let builder = AuditEventBuilder::new(
        EventType::Authorization,
        actor,
        format!("npe-portal/{service}"),
        "proxy_path_rejected",
        EventOutcome::Failure,
    );
    // No session id: the record identifies the actor by certificate CN only.
    emit_built(
        builder,
        ip,
        None,
        Some(serde_json::json!({
            "method": method,
            "path": format!("{path:?}"),
            "reason": reason,
            "request_id": "-",
            "outcome": "denied",
        })),
    );
}
