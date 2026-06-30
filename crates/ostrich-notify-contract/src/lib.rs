//! Shared message contract for the certificate-expiry notify pipeline.
//!
//! These types and subject constants are the single source of truth exchanged
//! over NATS JetStream between the CA expiry-notify **producer** (ca-server) and
//! the **notify-service** scheduler/sender. Depending on this crate from both
//! sides means a rename of a field or subject is a compile error on both ends,
//! instead of a silently-dropped message at runtime.

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};

/// JetStream stream + subjects.
pub const STREAM_NAME: &str = "NOTIFY";
/// Producer → scheduler: one schedule per certificate (the agreed schema).
pub const SUBJECT_NOTIFY: &str = "cert.expiry.notify";
/// Scheduler → sender: a ready-to-deliver email.
pub const SUBJECT_EMAIL: &str = "email.send";

/// A certificate-expiry notification schedule, published to [`SUBJECT_NOTIFY`].
///
/// The producer re-publishes the current desired state per certificate on each
/// scan; a renewed/revoked certificate either stops appearing (and is aged out)
/// or is sent once with `tombstone = true` to deactivate it immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyMessage {
    /// Certificate subject DN — the schedule's identity key.
    pub certificate: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    #[serde(default)]
    pub notification_emails: Vec<String>,
    /// "daily" | "weekly" | "monthly" — sets the send cadence (one send per
    /// day/ISO-week/calendar-month) and derives send days when
    /// `notification_days` is empty.
    #[serde(default = "default_frequency")]
    pub notification_frequency: String,
    /// "HH:MM:SS" (optionally trailing "Z"); the time of day (UTC) to send.
    #[serde(default = "default_time")]
    pub notification_time: String,
    /// Days to send, e.g. ["Monday","Wednesday"]; empty = derive from frequency.
    #[serde(default)]
    pub notification_days: Vec<String>,
    #[serde(default = "default_subject")]
    pub notification_subject: String,
    #[serde(default)]
    pub notification_body: String,
    /// Start notifying once the certificate is within this many days of expiry.
    #[serde(default = "default_days_before")]
    pub notify_days_before_expiration: i64,
    /// Deactivate this schedule (certificate renewed/revoked).
    #[serde(default)]
    pub tombstone: bool,
}

fn default_frequency() -> String {
    "weekly".to_string()
}
fn default_time() -> String {
    "09:00:00Z".to_string()
}
fn default_subject() -> String {
    "Certificate Expiration Notification".to_string()
}
fn default_days_before() -> i64 {
    90
}

/// A ready-to-send email, published to [`SUBJECT_EMAIL`] and consumed by the
/// sender. Free of scheduling concerns — the sender just delivers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailJob {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    /// Source certificate (for logging / audit).
    pub certificate: String,
    /// De-dup window this job belongs to (e.g. "2026-06-30" / "2026-W26" / "2026-06").
    pub window_key: String,
}

/// Parse the schema's `notification_time` ("HH:MM:SS[Z]") to a UTC time-of-day,
/// defaulting to 09:00:00 on anything unparseable.
pub fn parse_time(s: &str) -> NaiveTime {
    let t = s.trim().trim_end_matches('Z');
    NaiveTime::parse_from_str(t, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(t, "%H:%M"))
        .unwrap_or_else(|_| NaiveTime::from_hms_opt(9, 0, 0).unwrap())
}

/// Parse a weekday name ("Monday", "Mon", case-insensitive).
pub fn parse_weekday(s: &str) -> Option<Weekday> {
    s.trim().parse::<Weekday>().ok()
}

/// The set of weekdays a schedule sends on: explicit `notification_days`, or
/// derived from `frequency` when none are given (daily → every day; weekly and
/// monthly → Monday). Cadence (once per day/week/month) is enforced separately
/// by [`period_key`] + the dedup ledger, so a multi-day list under `weekly`
/// still sends only once per week (on the first matching day).
pub fn send_weekdays(days: &[String], frequency: &str) -> Vec<Weekday> {
    let explicit: Vec<Weekday> = days.iter().filter_map(|d| parse_weekday(d)).collect();
    if !explicit.is_empty() {
        return explicit;
    }
    match frequency.to_ascii_lowercase().as_str() {
        "daily" => vec![
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
            Weekday::Sat,
            Weekday::Sun,
        ],
        // weekly/monthly fall back to Monday; cadence is enforced by period_key.
        _ => vec![Weekday::Mon],
    }
}

/// The dedup-window key for a schedule's cadence at `now`. This is what actually
/// enforces "once per period": the scheduler claims one (certificate, window)
/// slot per period, so the first eligible send-day in the period wins and the
/// rest are no-ops.
///
/// - `daily`   → calendar day  ("2026-06-30"): one send per day
/// - `weekly`  → ISO year-week ("2026-W26"):  one send per week
/// - `monthly` → calendar month("2026-06"):   one send per month
pub fn period_key(frequency: &str, now: DateTime<Utc>) -> String {
    match frequency.to_ascii_lowercase().as_str() {
        "weekly" => {
            let iso = now.iso_week();
            format!("{}-W{:02}", iso.year(), iso.week())
        }
        "monthly" => format!("{}-{:02}", now.year(), now.month()),
        // daily (and any unrecognized cadence) → per-day.
        _ => now.date_naive().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_schema_example() {
        let raw = r#"{
            "certificate": "cn=example.com, o=Example Organization, c=US",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2025-01-01T00:00:00Z",
            "notification_emails": ["john.willman.1@us.af.mil"],
            "notification_frequency": "weekly",
            "notification_time": "09:00:00Z",
            "notification_days": ["Monday", "Wednesday", "Friday"],
            "notification_subject": "Certificate Expiration Notification",
            "notification_body": "renew it",
            "notify_days_before_expiration": 90
        }"#;
        let m: NotifyMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(m.notify_days_before_expiration, 90);
        assert_eq!(parse_time(&m.notification_time), NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        assert_eq!(
            send_weekdays(&m.notification_days, &m.notification_frequency),
            vec![Weekday::Mon, Weekday::Wed, Weekday::Fri]
        );
        assert!(!m.tombstone);
    }

    #[test]
    fn empty_days_derive_from_frequency() {
        assert_eq!(send_weekdays(&[], "daily").len(), 7);
        assert_eq!(send_weekdays(&[], "weekly"), vec![Weekday::Mon]);
        assert_eq!(send_weekdays(&[], "monthly"), vec![Weekday::Mon]);
    }

    #[test]
    fn period_key_distinguishes_cadence() {
        // 2026-06-29 (Mon) .. 2026-07-05 (Sun) is one ISO week.
        let mon: DateTime<Utc> = "2026-06-29T12:00:00Z".parse().unwrap();
        let thu: DateTime<Utc> = "2026-07-02T08:00:00Z".parse().unwrap();

        // daily → per-day; weekly → ISO week; monthly → calendar month.
        assert_eq!(period_key("daily", mon), "2026-06-29");
        assert_eq!(period_key("monthly", mon), "2026-06");

        // Two different calendar days in the same ISO week share a weekly key
        // (→ once/week) but get distinct daily keys (→ once/day).
        assert_eq!(period_key("weekly", mon), period_key("weekly", thu));
        assert_ne!(period_key("daily", mon), period_key("daily", thu));

        // Different days in the same month share a monthly key (→ once/month),
        // even across an ISO-week boundary.
        let early: DateTime<Utc> = "2026-06-05T08:00:00Z".parse().unwrap();
        assert_eq!(period_key("monthly", early), period_key("monthly", mon));
        assert_ne!(period_key("weekly", early), period_key("weekly", mon));
    }
}
