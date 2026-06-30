//! notify-service configuration (CLI + env).

use clap::{Parser, ValueEnum};

/// Which runtime role this process plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Consume `cert.expiry.notify`, store schedules, and publish due emails.
    Scheduler,
    /// Consume `email.send` and deliver via SMTP.
    Sender,
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
    #[arg(long, env = "SMTP_PORT", default_value = "25")]
    pub smtp_port: u16,
    /// From address for outgoing mail.
    #[arg(long, env = "SMTP_FROM", default_value = "noreply@localhost")]
    pub smtp_from: String,
    #[arg(long, env = "SMTP_USERNAME")]
    pub smtp_username: Option<String>,
    #[arg(long, env = "SMTP_PASSWORD")]
    pub smtp_password: Option<String>,
    /// Use STARTTLS (rustls) for the SMTP connection.
    #[arg(long, env = "SMTP_STARTTLS", default_value = "false")]
    pub smtp_starttls: bool,

    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    pub log_json: bool,
}
