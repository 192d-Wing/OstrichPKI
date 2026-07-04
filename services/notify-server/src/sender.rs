//! Sender role: consume `email.send` and deliver via an SMTP relay.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use async_nats::jetstream;
use futures::StreamExt;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::{Config, SmtpSecurity};
use crate::contract::{EmailJob, STREAM_NAME, SUBJECT_EMAIL};
use crate::db::{self, Pool};

type Mailer = AsyncSmtpTransport<Tokio1Executor>;

/// JetStream redelivery bound: a transient SMTP failure is retried up to this
/// many times before the message is dropped (so a relay outage doesn't loop
/// forever). Deterministic ("poison") failures are dropped on first attempt.
const MAX_DELIVER: i64 = 5;
/// How long JetStream waits for an ack before treating a delivery as failed.
const ACK_WAIT: Duration = Duration::from_secs(60);

/// Why a send failed — decides whether JetStream should retry. A `Permanent`
/// failure (unparseable From/recipients, body build) will fail identically on
/// every redelivery, so it is acked-and-dropped instead of looping forever; a
/// `Transient` failure (relay unreachable, temporary rejection) is NAK'd and
/// retried up to `MAX_DELIVER` times.
enum SendError {
    Permanent(anyhow::Error),
    Transient(anyhow::Error),
}

pub async fn run(pool: Pool, js: jetstream::Context, cfg: &Config) -> Result<()> {
    if cfg.smtp_host.trim().is_empty() {
        bail!("SMTP_HOST is required for the sender role");
    }
    let mailer = build_mailer(cfg)?;
    let active_port = match cfg.smtp_security {
        SmtpSecurity::Tls => cfg.smtp_tls_port,
        _ => cfg.smtp_port,
    };
    tracing::info!(host = %cfg.smtp_host, port = active_port, security = ?cfg.smtp_security, "sender ready");

    let stream = js.get_stream(STREAM_NAME).await?;
    let consumer = stream
        .get_or_create_consumer(
            "sender",
            jetstream::consumer::pull::Config {
                durable_name: Some("sender".to_string()),
                filter_subject: SUBJECT_EMAIL.to_string(),
                ack_policy: jetstream::consumer::AckPolicy::Explicit,
                // Bound redelivery so a poison message can't loop forever; the
                // scheduler's re-drive (sent_at IS NULL) is the safety net for a
                // genuinely transient outage that outlasts these retries.
                max_deliver: MAX_DELIVER,
                ack_wait: ACK_WAIT,
                ..Default::default()
            },
        )
        .await?;

    let mut messages = consumer.messages().await?;
    while let Some(msg) = messages.next().await {
        let msg = msg?;
        match serde_json::from_slice::<EmailJob>(&msg.payload) {
            Ok(job) => match send(&mailer, cfg, &job).await {
                Ok(()) => {
                    let _ = db::mark_sent(&pool, &job.certificate, &job.window_key).await;
                    msg.ack().await.map_err(|e| anyhow!("ack failed: {e}"))?;
                    tracing::info!(cert = %job.certificate, recipients = job.to.len(), "expiry email sent");
                }
                // Deterministic failure: dropping it avoids an infinite redelivery
                // loop. Ack so JetStream stops redelivering this poison message.
                Err(SendError::Permanent(e)) => {
                    tracing::error!(error = %e, cert = %job.certificate, "send failed permanently; dropping");
                    msg.ack().await.map_err(|e| anyhow!("ack failed: {e}"))?;
                }
                // Transient failure: NAK → JetStream redelivers up to MAX_DELIVER.
                Err(SendError::Transient(e)) => {
                    tracing::error!(error = %e, cert = %job.certificate, "send failed; will retry");
                    let _ = msg.ack_with(jetstream::AckKind::Nak(None)).await;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "invalid email job; dropping");
                msg.ack().await.map_err(|e| anyhow!("ack failed: {e}"))?;
            }
        }
    }
    Ok(())
}

fn build_mailer(cfg: &Config) -> Result<Mailer> {
    let (builder0, port) = match cfg.smtp_security {
        // Plaintext to a trusted internal relay.
        SmtpSecurity::None => (
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
            cfg.smtp_port,
        ),
        // STARTTLS: connect plaintext then upgrade (e.g. Office 365 on 587).
        SmtpSecurity::Starttls => (
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?,
            cfg.smtp_port,
        ),
        // Implicit TLS (SMTPS) from connection start.
        SmtpSecurity::Tls => (
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?,
            cfg.smtp_tls_port,
        ),
    };
    let mut builder = builder0.port(port);

    if let (Some(user), Some(pass)) = (&cfg.smtp_username, &cfg.smtp_password) {
        // Fail secure: never transmit SMTP AUTH credentials over an unencrypted
        // transport. `builder_dangerous` (SMTP_SECURITY=none) sends the AUTH
        // exchange in cleartext, exposing the relay password to any on-path
        // observer (NIST 800-53 SC-8 / SC-13). Require STARTTLS or implicit TLS
        // whenever credentials are configured.
        if matches!(cfg.smtp_security, SmtpSecurity::None) {
            return Err(anyhow::anyhow!(
                "refusing to send SMTP AUTH credentials over an unencrypted connection: \
                 set SMTP_SECURITY=starttls or =tls (or clear SMTP_USERNAME/SMTP_PASSWORD)"
            ));
        }
        // `pass` is a Zeroizing<String>; lettre copies it into its own Credentials,
        // but our config copy is zeroized on drop (NIST 800-53 SI-12).
        builder = builder.credentials(Credentials::new(user.clone(), pass.as_str().to_owned()));
    }
    Ok(builder.build())
}

async fn send(mailer: &Mailer, cfg: &Config, job: &EmailJob) -> Result<(), SendError> {
    // From/recipient parse failures and body-build failures are deterministic:
    // they fail identically on every redelivery, so they are Permanent.
    let from: Mailbox = cfg
        .smtp_from
        .parse()
        .map_err(|e| SendError::Permanent(anyhow!("invalid SMTP_FROM '{}': {e}", cfg.smtp_from)))?;

    let mut builder = Message::builder().from(from).subject(&job.subject);
    let mut recipients = 0;
    for addr in &job.to {
        match addr.parse::<Mailbox>() {
            Ok(mbox) => {
                builder = builder.to(mbox);
                recipients += 1;
            }
            Err(e) => tracing::warn!(addr = %addr, error = %e, "skipping invalid recipient"),
        }
    }
    if recipients == 0 {
        return Err(SendError::Permanent(anyhow!(
            "no valid recipients for certificate {}",
            job.certificate
        )));
    }

    let email = builder
        .body(job.body.clone())
        .map_err(|e| SendError::Permanent(anyhow!("building email: {e}")))?;
    // The actual relay handoff can fail for transient reasons (relay down,
    // greylisting, 4xx) — retry those.
    mailer
        .send(email)
        .await
        .map_err(|e| SendError::Transient(anyhow!("SMTP send: {e}")))?;
    Ok(())
}
