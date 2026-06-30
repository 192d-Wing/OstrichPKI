//! Scheduler role: ingest schedules from `cert.expiry.notify`, and on each tick
//! publish ready-to-send emails to `email.send` for schedules that are due.

use std::time::Duration;

use anyhow::{Result, anyhow};
use async_nats::jetstream;
use chrono::{DateTime, Datelike, Utc, Weekday};
use futures::StreamExt;

use crate::contract::{
    EmailJob, NotifyMessage, STREAM_NAME, SUBJECT_EMAIL, SUBJECT_NOTIFY, period_key, send_weekdays,
};
use crate::db::{self, Pool, Schedule};

/// Re-drive a claimed-but-unsent window only after the original send had this
/// long to land, and stop re-driving once it is older than the max age.
const REDRIVE_MIN_AGE_SECS: i64 = 600; // 10 min
const REDRIVE_MAX_AGE_SECS: i64 = 2 * 24 * 3600; // 2 days

pub async fn run(pool: Pool, js: jetstream::Context, tick_seconds: u64) -> Result<()> {
    // Ingest schedule messages in the background.
    let consume_pool = pool.clone();
    let consume_js = js.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = consume_loop(&consume_js, &consume_pool).await {
                tracing::error!(error = %e, "schedule consumer error; restarting in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });

    // Evaluate schedules on a fixed cadence.
    tracing::info!(tick_seconds, "scheduler evaluating schedules");
    let mut ticker = tokio::time::interval(Duration::from_secs(tick_seconds.max(10)));
    loop {
        ticker.tick().await;
        if let Err(e) = evaluate(&pool, &js).await {
            tracing::error!(error = %e, "schedule evaluation failed");
        }
    }
}

async fn consume_loop(js: &jetstream::Context, pool: &Pool) -> Result<()> {
    let stream = js.get_stream(STREAM_NAME).await?;
    let consumer = stream
        .get_or_create_consumer(
            "scheduler",
            jetstream::consumer::pull::Config {
                durable_name: Some("scheduler".to_string()),
                filter_subject: SUBJECT_NOTIFY.to_string(),
                ack_policy: jetstream::consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await?;

    let mut messages = consumer.messages().await?;
    while let Some(msg) = messages.next().await {
        let msg = msg?;
        match serde_json::from_slice::<NotifyMessage>(&msg.payload) {
            Ok(m) => {
                if m.tombstone {
                    db::deactivate(pool, &m.certificate).await?;
                    tracing::info!(cert = %m.certificate, "schedule deactivated (tombstone)");
                } else {
                    db::upsert(pool, &m).await?;
                    tracing::info!(cert = %m.certificate, "schedule upserted");
                }
            }
            Err(e) => tracing::warn!(error = %e, "invalid notify message; dropping"),
        }
        msg.ack().await.map_err(|e| anyhow!("ack failed: {e}"))?;
    }
    Ok(())
}

async fn evaluate(pool: &Pool, js: &jetstream::Context) -> Result<()> {
    let now = Utc::now();
    let weekday = now.weekday();

    // 1. Newly-due schedules: claim the cadence window, then publish.
    for s in db::list_active(pool).await? {
        if !is_due(&s, now, weekday) {
            continue;
        }
        if s.notification_emails.is_empty() {
            continue;
        }
        // The window key is the cadence period (day / ISO-week / month), so a
        // cert is emailed at most once per period even with multiple send-days
        // configured or multiple scheduler replicas running.
        let window_key = period_key(&s.frequency, now);
        if !db::try_claim_window(pool, &s.certificate, &window_key).await? {
            continue;
        }
        let job = EmailJob {
            to: s.notification_emails.clone(),
            subject: s.subject.clone(),
            body: s.body.clone(),
            certificate: s.certificate.clone(),
            window_key,
        };
        publish_job(js, &job).await?;
        tracing::info!(cert = %s.certificate, recipients = job.to.len(), "queued expiry email");
    }

    // 2. Re-drive windows that were claimed but never delivered (scheduler
    //    crashed after the claim, or the sender exhausted its retries). Without
    //    this the claim permanently burns the period and the expiry notice is
    //    silently lost — the worst failure for an expiry warning.
    for u in db::list_stale_unsent(pool, REDRIVE_MIN_AGE_SECS, REDRIVE_MAX_AGE_SECS).await? {
        let job = EmailJob {
            to: u.notification_emails,
            subject: u.subject,
            body: u.body,
            certificate: u.certificate.clone(),
            window_key: u.window_key.clone(),
        };
        if job.to.is_empty() {
            continue;
        }
        publish_job(js, &job).await?;
        tracing::warn!(cert = %u.certificate, window = %u.window_key, "re-driving unsent expiry email");
    }
    Ok(())
}

async fn publish_job(js: &jetstream::Context, job: &EmailJob) -> Result<()> {
    let payload = serde_json::to_vec(job)?;
    js.publish(SUBJECT_EMAIL.to_string(), payload.into())
        .await?
        .await?;
    Ok(())
}

/// A schedule is due now if the certificate is within its notify window, not yet
/// expired, today is a configured send-day, and it's at/after the send time.
fn is_due(s: &Schedule, now: DateTime<Utc>, weekday: Weekday) -> bool {
    if s.valid_to <= now {
        return false; // already expired
    }
    let window_start = s.valid_to - chrono::Duration::days(i64::from(s.notify_days_before));
    if now < window_start {
        return false; // not within notify_days_before yet
    }
    if !send_weekdays(&s.notification_days, &s.frequency).contains(&weekday) {
        return false; // not a send-day
    }
    now.time() >= s.notification_time
}
