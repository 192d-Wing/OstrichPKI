//! notify-service database access (its own Postgres).

use anyhow::Result;
use chrono::{DateTime, NaiveTime, Utc};
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;

use crate::contract::{NotifyMessage, parse_time};

pub type Pool = sqlx::PgPool;

/// Connect and apply the notify-service migrations (advisory-locked, so it is
/// safe for both roles to call concurrently).
pub async fn connect(url: &str) -> Result<Pool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// A stored, active notification schedule.
pub struct Schedule {
    pub certificate: String,
    pub valid_to: DateTime<Utc>,
    pub notification_emails: Vec<String>,
    pub frequency: String,
    pub notification_time: NaiveTime,
    pub notification_days: Vec<String>,
    pub subject: String,
    pub body: String,
    pub notify_days_before: i32,
}

/// Upsert a schedule from a producer message (keyed by certificate).
pub async fn upsert(pool: &Pool, msg: &NotifyMessage) -> Result<()> {
    let time = parse_time(&msg.notification_time);
    sqlx::query(
        r#"
        INSERT INTO schedules
            (certificate, valid_from, valid_to, notification_emails, frequency,
             notification_time, notification_days, subject, body,
             notify_days_before, active, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,now())
        ON CONFLICT (certificate) DO UPDATE SET
            valid_from = EXCLUDED.valid_from,
            valid_to = EXCLUDED.valid_to,
            notification_emails = EXCLUDED.notification_emails,
            frequency = EXCLUDED.frequency,
            notification_time = EXCLUDED.notification_time,
            notification_days = EXCLUDED.notification_days,
            subject = EXCLUDED.subject,
            body = EXCLUDED.body,
            notify_days_before = EXCLUDED.notify_days_before,
            active = true,
            updated_at = now()
        "#,
    )
    .bind(&msg.certificate)
    .bind(msg.valid_from)
    .bind(msg.valid_to)
    .bind(&msg.notification_emails)
    .bind(&msg.notification_frequency)
    .bind(time)
    .bind(&msg.notification_days)
    .bind(&msg.notification_subject)
    .bind(&msg.notification_body)
    .bind(msg.notify_days_before_expiration as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark a certificate's schedule inactive (renewed/revoked tombstone).
pub async fn deactivate(pool: &Pool, certificate: &str) -> Result<()> {
    sqlx::query("UPDATE schedules SET active = false, updated_at = now() WHERE certificate = $1")
        .bind(certificate)
        .execute(pool)
        .await?;
    Ok(())
}

/// All active schedules.
pub async fn list_active(pool: &Pool) -> Result<Vec<Schedule>> {
    let rows = sqlx::query(
        r#"SELECT certificate, valid_to, notification_emails, frequency,
                  notification_time, notification_days, subject, body, notify_days_before
           FROM schedules WHERE active"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Schedule {
            certificate: r.get("certificate"),
            valid_to: r.get("valid_to"),
            notification_emails: r.get("notification_emails"),
            frequency: r.get("frequency"),
            notification_time: r.get("notification_time"),
            notification_days: r.get("notification_days"),
            subject: r.get("subject"),
            body: r.get("body"),
            notify_days_before: r.get("notify_days_before"),
        })
        .collect())
}

/// Atomically claim a (certificate, window) send slot. Returns true if this
/// caller won the claim (and should publish the email), false if already taken.
pub async fn try_claim_window(pool: &Pool, certificate: &str, window_key: &str) -> Result<bool> {
    let res = sqlx::query(
        "INSERT INTO sent_notifications (certificate, window_key) VALUES ($1,$2)
         ON CONFLICT (certificate, window_key) DO NOTHING",
    )
    .bind(certificate)
    .bind(window_key)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Record that a claimed window was actually delivered.
pub async fn mark_sent(pool: &Pool, certificate: &str, window_key: &str) -> Result<()> {
    sqlx::query(
        "UPDATE sent_notifications SET sent_at = now() WHERE certificate = $1 AND window_key = $2",
    )
    .bind(certificate)
    .bind(window_key)
    .execute(pool)
    .await?;
    Ok(())
}
