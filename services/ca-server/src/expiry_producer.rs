//! Certificate-expiry notification producer.
//!
//! Periodically scans for certificates approaching expiry and publishes one
//! schedule message per certificate to the notify-service over NATS JetStream
//! (subject `cert.expiry.notify`). Recipients are resolved from the certificate's
//! originating approval request (the notification / ISSM / PM emails collected on
//! the submit form). Revoked certificates still inside the window are tombstoned.
//!
//! The full active set is re-published every scan, so the design is self-healing:
//! a transient NATS outage or a not-yet-created stream simply resolves on the
//! next scan, and the notify-side upsert is idempotent.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use ostrich_notify_contract::{NotifyMessage, SUBJECT_NOTIFY};
use sqlx::{PgPool, Row};

/// Producer configuration (sourced from CA env in `main`).
pub struct ProducerConfig {
    pub nats_url: String,
    /// CA cert (PEM) verifying the NATS server's TLS cert; `Some` requires TLS.
    pub nats_ca_file: Option<std::path::PathBuf>,
    /// NATS username / password for authenticated connections (optional).
    pub nats_user: Option<String>,
    pub nats_password: Option<String>,
    pub days_before: i64,
    pub scan_interval_hours: u64,
    pub default_frequency: String,
    pub default_time: String,
    pub default_days: Vec<String>,
}

/// Run the producer loop forever (spawn this). Logs and disables itself if NATS
/// is unreachable at startup; never panics.
pub async fn run(pool: PgPool, cfg: ProducerConfig) {
    // Optional TLS (verify the NATS server against the configured CA) + password
    // auth. SC-8/SC-13 (transport confidentiality), AC-3/IA-2 (authenticated client).
    let mut nats_opts = async_nats::ConnectOptions::new();
    if let Some(ca) = &cfg.nats_ca_file {
        nats_opts = nats_opts
            .add_root_certificates(ca.clone())
            .require_tls(true);
    }
    if let (Some(user), Some(pass)) = (&cfg.nats_user, &cfg.nats_password) {
        nats_opts = nats_opts.user_and_password(user.clone(), pass.clone());
    }
    let client = match nats_opts.connect(&cfg.nats_url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, nats = %cfg.nats_url,
                "expiry-notify producer: NATS connect failed; producer disabled");
            return;
        }
    };
    let js = async_nats::jetstream::new(client);
    tracing::info!(nats = %cfg.nats_url, days_before = cfg.days_before,
        interval_hours = cfg.scan_interval_hours, "expiry-notify producer started");

    let mut ticker =
        tokio::time::interval(Duration::from_secs(cfg.scan_interval_hours.max(1) * 3600));
    loop {
        ticker.tick().await;
        match scan_and_publish(&pool, &js, &cfg).await {
            Ok((active, tombstoned)) => {
                tracing::info!(active, tombstoned, "expiry-notify scan complete")
            }
            Err(e) => tracing::error!(error = %e, "expiry-notify scan failed"),
        }
    }
}

async fn scan_and_publish(
    pool: &PgPool,
    js: &async_nats::jetstream::Context,
    cfg: &ProducerConfig,
) -> Result<(usize, usize)> {
    // Active certs entering the notify window, with their request's details.
    // approval_requests links to certificates via approval_requests.certificate_id
    // (FK → certificates.id); certificates.request_id is an unrelated traceability
    // id (ACME order / EST enrollment), so the join must be on certificate_id.
    let rows = sqlx::query(
        r#"
        SELECT c.subject_dn, c.not_before, c.not_after, ar.request_details
        FROM certificates c
        LEFT JOIN approval_requests ar ON ar.certificate_id = c.id
        WHERE NOT c.revoked
          AND c.not_before <= now() AND c.not_after >= now()
          AND c.not_after < now() + make_interval(days => $1)
        "#,
    )
    .bind(cfg.days_before as i32)
    .fetch_all(pool)
    .await?;

    let mut active = 0;
    for r in &rows {
        let subject: String = r.get("subject_dn");
        let not_before: DateTime<Utc> = r.get("not_before");
        let not_after: DateTime<Utc> = r.get("not_after");
        let details: Option<serde_json::Value> = r.try_get("request_details").ok();
        let emails = extract_emails(details.as_ref());
        if emails.is_empty() {
            continue; // no resolvable recipient — skip
        }
        let body = format!(
            "The certificate '{subject}' expires on {}. Please renew it before then.",
            not_after.format("%Y-%m-%d")
        );
        let msg = NotifyMessage {
            certificate: subject,
            valid_from: not_before,
            valid_to: not_after,
            notification_emails: emails,
            notification_frequency: cfg.default_frequency.clone(),
            notification_time: cfg.default_time.clone(),
            notification_days: cfg.default_days.clone(),
            notification_subject: "Certificate Expiration Notification".to_string(),
            notification_body: body,
            notify_days_before_expiration: cfg.days_before,
            tombstone: false,
        };
        publish(js, &msg).await?;
        active += 1;
    }

    // Tombstone revoked certs still inside the window so their schedule stops.
    let revoked = sqlx::query(
        r#"
        SELECT c.subject_dn, c.not_before, c.not_after
        FROM certificates c
        WHERE c.revoked AND c.not_after >= now()
          AND c.not_after < now() + make_interval(days => $1)
        "#,
    )
    .bind(cfg.days_before as i32)
    .fetch_all(pool)
    .await?;

    for r in &revoked {
        let subject: String = r.get("subject_dn");
        let not_before: DateTime<Utc> = r.get("not_before");
        let not_after: DateTime<Utc> = r.get("not_after");
        let msg = NotifyMessage {
            certificate: subject,
            valid_from: not_before,
            valid_to: not_after,
            notification_emails: Vec::new(),
            notification_frequency: cfg.default_frequency.clone(),
            notification_time: cfg.default_time.clone(),
            notification_days: cfg.default_days.clone(),
            notification_subject: "Certificate Expiration Notification".to_string(),
            notification_body: String::new(),
            notify_days_before_expiration: cfg.days_before,
            tombstone: true,
        };
        publish(js, &msg).await?;
    }

    Ok((active, revoked.len()))
}

async fn publish(js: &async_nats::jetstream::Context, msg: &NotifyMessage) -> Result<()> {
    let payload = serde_json::to_vec(msg)?;
    js.publish(SUBJECT_NOTIFY.to_string(), payload.into())
        .await?
        .await?;
    Ok(())
}

/// Collect the distinct, non-empty notification recipients from a request's
/// `request_details` (the submit form's notification / ISSM / PM emails).
fn extract_emails(details: Option<&serde_json::Value>) -> Vec<String> {
    let mut emails: Vec<String> = Vec::new();
    if let Some(d) = details {
        for key in ["notification_email", "issm_email", "pm_email"] {
            if let Some(s) = d.get(key).and_then(|v| v.as_str()) {
                let s = s.trim();
                if !s.is_empty() && !emails.iter().any(|e| e == s) {
                    emails.push(s.to_string());
                }
            }
        }
    }
    emails
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_distinct_recipient_emails() {
        let d = serde_json::json!({
            "notification_email": "a@x.mil",
            "issm_email": "b@x.mil",
            "pm_email": "a@x.mil",
            "other": "ignored"
        });
        assert_eq!(extract_emails(Some(&d)), vec!["a@x.mil", "b@x.mil"]);
        assert!(extract_emails(None).is_empty());
        assert!(extract_emails(Some(&serde_json::json!({"pm_email": ""}))).is_empty());
    }
}
