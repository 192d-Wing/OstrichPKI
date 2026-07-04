//! OstrichPKI certificate-expiry notification service.
//!
//! Two runtime roles (`--role`):
//!   - `scheduler`: consumes `cert.expiry.notify`, stores per-certificate
//!     schedules in its own database, and publishes ready-to-send emails to
//!     `email.send` on the configured days/time/frequency.
//!   - `sender`: consumes `email.send` and delivers via an SMTP relay.
//!
//! Decoupled from issuance via NATS JetStream: an SMTP outage never blocks the CA.

mod config;
mod contract;
mod db;
mod scheduler;
mod sender;

use anyhow::{Context, Result};
use async_nats::jetstream;
use axum::{Router, routing::get};
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use config::{Config, Role};
use contract::{STREAM_NAME, SUBJECT_EMAIL, SUBJECT_NOTIFY};

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::parse();
    init_tracing(&cfg);
    tracing::info!(role = ?cfg.role, "Starting OstrichPKI notify-service");

    // Process-wide rustls provider (aws-lc-rs / FIPS) for lettre STARTTLS and any
    // NATS TLS. Idempotent. NIST 800-53: SC-13.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let pool = db::connect(&cfg.database_url)
        .await
        .context("connecting to notify database")?;

    // Health/readiness server for k8s probes. Readiness pings the DB so the pod
    // only reports Ready when its database is actually reachable (NIST SI-17).
    tokio::spawn(health_server(cfg.health_address.clone(), pool.clone()));

    // Build the NATS connection with optional TLS (verify the server against the
    // configured CA) and password auth. SC-8/SC-13 (transport confidentiality),
    // AC-3/IA-2 (authenticated client).
    let mut nats_opts = async_nats::ConnectOptions::new();
    if let Some(ca) = &cfg.nats_ca_file {
        nats_opts = nats_opts
            .add_root_certificates(ca.clone())
            .require_tls(true);
    }
    if let (Some(user), Some(pass)) = (&cfg.nats_user, &cfg.nats_password) {
        nats_opts = nats_opts.user_and_password(user.clone(), pass.as_str().to_owned());
    }
    let client = nats_opts
        .connect(&cfg.nats_url)
        .await
        .with_context(|| format!("connecting to NATS at {}", cfg.nats_url))?;
    let js = jetstream::new(client);
    ensure_stream(&js)
        .await
        .context("ensuring JetStream stream")?;

    match cfg.role {
        Role::Scheduler => scheduler::run(pool, js, cfg.tick_seconds).await,
        Role::Sender => sender::run(pool, js, &cfg).await,
    }
}

/// Create the durable JetStream stream backing both subjects (idempotent).
async fn ensure_stream(js: &jetstream::Context) -> Result<()> {
    js.get_or_create_stream(jetstream::stream::Config {
        name: STREAM_NAME.to_string(),
        subjects: vec![SUBJECT_NOTIFY.to_string(), SUBJECT_EMAIL.to_string()],
        ..Default::default()
    })
    .await?;
    Ok(())
}

async fn health_server(addr: String, pool: db::Pool) {
    use ostrich_common::health;
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health::health_response("notify-server") }),
        )
        .route(
            "/ready",
            get(move || {
                let pool = pool.clone();
                async move { health::readiness_response_with_pg_pool("notify-server", &pool).await }
            }),
        );
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            tracing::info!(%addr, "health server listening");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "health server error");
            }
        }
        Err(e) => tracing::error!(error = %e, %addr, "failed to bind health server"),
    }
}

fn init_tracing(cfg: &Config) {
    let filter = EnvFilter::try_new(&cfg.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    if cfg.log_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }
}
