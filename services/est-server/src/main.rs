//! OstrichPKI EST Enrollment Server
//!
//! COMPLIANCE MAPPING:
//! - RFC 7030: Enrollment over Secure Transport (EST)
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-8 (Transmission Confidentiality - mTLS)

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI EST Enrollment Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-est-server")]
#[command(about = "OstrichPKI EST Enrollment Server (RFC 7030)")]
#[command(version)]
struct Args {
    /// HTTPS bind address
    #[arg(long, env = "EST_BIND_ADDRESS", default_value = "0.0.0.0:8443")]
    bind_address: String,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// TLS certificate file
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

    /// TLS CA certificate for client authentication
    #[arg(long, env = "TLS_CA_CERT_FILE")]
    tls_ca_cert: Option<String>,

    /// Log level
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Enable JSON logging
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level, args.log_json)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI EST Server"
    );

    // Initialize database
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;

    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // Initialize providers
    let crypto_provider = ostrich_crypto::software::SoftwareProvider::new();
    let audit_sink = ostrich_audit::DatabaseAuditSink::new(db_pool.clone());

    // TODO: Initialize actual auth provider and RBAC policy from configuration
    // For now, use the backward-compatible new() method without auth
    // Production deployments should use new_with_auth() with proper authentication
    let state =
        ostrich_est::rest::EstState::new(db_pool, Arc::new(crypto_provider), Arc::new(audit_sink));

    // Create router
    let app = ostrich_est::rest::create_router(state);

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, "Starting EST server");

    // TODO: Add TLS support when TLS configuration is provided
    // For now, start without TLS (mTLS will be added in production)
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("EST Server shutdown complete");
    Ok(())
}

fn init_logging(level: &str, json: bool) -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C"),
        _ = terminate => tracing::info!("Received SIGTERM"),
    }
}
