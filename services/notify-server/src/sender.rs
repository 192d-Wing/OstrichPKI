//! Sender role: consume `email.send` and deliver via an SMTP relay.

use anyhow::{Result, anyhow, bail};
use async_nats::jetstream;
use futures::StreamExt;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;
use crate::contract::{EmailJob, SUBJECT_EMAIL, STREAM_NAME};
use crate::db::{self, Pool};

type Mailer = AsyncSmtpTransport<Tokio1Executor>;

pub async fn run(pool: Pool, js: jetstream::Context, cfg: &Config) -> Result<()> {
    if cfg.smtp_host.trim().is_empty() {
        bail!("SMTP_HOST is required for the sender role");
    }
    let mailer = build_mailer(cfg)?;
    tracing::info!(host = %cfg.smtp_host, port = cfg.smtp_port, starttls = cfg.smtp_starttls, "sender ready");

    let stream = js.get_stream(STREAM_NAME).await?;
    let consumer = stream
        .get_or_create_consumer(
            "sender",
            jetstream::consumer::pull::Config {
                durable_name: Some("sender".to_string()),
                filter_subject: SUBJECT_EMAIL.to_string(),
                ack_policy: jetstream::consumer::AckPolicy::Explicit,
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
                Err(e) => {
                    // Negative-ack → JetStream redelivers (transient SMTP failure).
                    tracing::error!(error = %e, cert = %job.certificate, "send failed; will retry");
                    let _ = msg
                        .ack_with(jetstream::AckKind::Nak(None))
                        .await;
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
    let mut builder = if cfg.smtp_starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?
    } else {
        // Plain SMTP to a trusted internal relay (no TLS).
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
    }
    .port(cfg.smtp_port);

    if let (Some(user), Some(pass)) = (&cfg.smtp_username, &cfg.smtp_password) {
        builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    Ok(builder.build())
}

async fn send(mailer: &Mailer, cfg: &Config, job: &EmailJob) -> Result<()> {
    let from: Mailbox = cfg
        .smtp_from
        .parse()
        .map_err(|e| anyhow!("invalid SMTP_FROM '{}': {e}", cfg.smtp_from))?;

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
        bail!("no valid recipients for certificate {}", job.certificate);
    }

    let email = builder.body(job.body.clone())?;
    mailer.send(email).await?;
    Ok(())
}
