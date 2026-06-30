//! notify-service configuration (CLI + env).

use clap::{Parser, ValueEnum};
use zeroize::Zeroizing;

/// Wrap a secret value so it is zeroized on drop (NIST 800-53 SI-12).
fn secret(s: &str) -> Result<Zeroizing<String>, std::convert::Infallible> {
    Ok(Zeroizing::new(s.to_string()))
}

/// Which runtime role this process plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Consume `cert.expiry.notify`, store schedules, and publish due emails.
    Scheduler,
    /// Consume `email.send` and deliver via SMTP.
    Sender,
}

/// SMTP connection security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SmtpSecurity {
    /// Plaintext, no encryption — trusted internal relay (typically port 25).
    None,
    /// STARTTLS: connect plaintext then upgrade to TLS (e.g. Office 365 on 587).
    Starttls,
    /// Implicit TLS (SMTPS): TLS from connection start (typically port 465).
    Tls,
}

#[derive(Debug, Parser)]
#[command(name = "ostrich-notify-server")]
#[command(about = "Certificate-expiry notification service (NATS JetStream -> SMTP)")]
pub struct Config {
    /// Runtime role: `scheduler` or `sender`.
    #[arg(long, env = "NOTIFY_ROLE", value_enum)]
    pub role: Role,

    /// NATS server URL.
    #[arg(long, env = "NATS_URL", default_value = "nats://nats:4222")]
    pub nats_url: String,

    /// PostgreSQL URL for the notify-service's OWN database.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    /// Health/readiness probe listen address.
    #[arg(long, env = "NOTIFY_HEALTH_ADDRESS", default_value = "0.0.0.0:8090")]
    pub health_address: String,

    // --- scheduler ---
    /// How often (seconds) the scheduler evaluates schedules for due sends.
    #[arg(long, env = "NOTIFY_TICK_SECONDS", default_value = "300")]
    pub tick_seconds: u64,

    // --- sender (SMTP) ---
    /// SMTP relay host. Required for the sender role.
    #[arg(long, env = "SMTP_HOST", default_value = "")]
    pub smtp_host: String,
    /// Port used for `none` / `starttls` security (e.g. 25 or 587).
    #[arg(long, env = "SMTP_PORT", default_value = "587")]
    pub smtp_port: u16,
    /// Port used for `tls` (implicit TLS / SMTPS), typically 465.
    #[arg(long, env = "SMTP_TLS_PORT", default_value = "465")]
    pub smtp_tls_port: u16,
    /// From address for outgoing mail.
    #[arg(long, env = "SMTP_FROM", default_value = "noreply@localhost")]
    pub smtp_from: String,
    #[arg(long, env = "SMTP_USERNAME")]
    pub smtp_username: Option<String>,
    /// SMTP relay password — held in a `Zeroizing` buffer so it is wiped from
    /// memory on drop (NIST 800-53 SI-12). Sourced from a k8s secret, never a
    /// plaintext env file.
    #[arg(long, env = "SMTP_PASSWORD", value_parser = secret)]
    pub smtp_password: Option<Zeroizing<String>>,
    /// SMTP connection security: `none` | `starttls` | `tls`. `starttls` (the
    /// default) suits submission relays like Office 365 on 587; `tls` is implicit
    /// SMTPS on `SMTP_TLS_PORT`; `none` is plaintext on `SMTP_PORT`.
    #[arg(long, env = "SMTP_SECURITY", value_enum, default_value = "starttls")]
    pub smtp_security: SmtpSecurity,

    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    pub log_json: bool,
}
