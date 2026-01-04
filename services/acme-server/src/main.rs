//! OstrichPKI ACME Protocol Server
//!
//! COMPLIANCE MAPPING:
//! - RFC 8555: Automatic Certificate Management Environment (ACME)
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: AU-2 (Audit Events)

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI ACME Protocol Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-acme-server")]
#[command(about = "OstrichPKI ACME Protocol Server (RFC 8555)")]
#[command(version)]
struct Args {
    /// HTTP bind address
    #[arg(long, env = "ACME_BIND_ADDRESS", default_value = "0.0.0.0:8080")]
    bind_address: String,

    /// External base URL for ACME directory
    #[arg(long, env = "ACME_BASE_URL", default_value = "http://localhost:8080")]
    base_url: String,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Enable JSON logging format
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level, args.log_json)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI ACME Server"
    );

    // Initialize database connection
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;

    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // Initialize crypto provider
    let crypto_provider = ostrich_crypto::software::SoftwareProvider::new();

    // Initialize audit sink
    let audit_sink = ostrich_audit::DatabaseAuditSink::new(db_pool.clone());

    // Create ACME state
    let state = ostrich_acme::rest::AcmeState::new(
        db_pool,
        Arc::new(crypto_provider),
        Arc::new(audit_sink),
        args.base_url.clone(),
    );

    // Create REST API router
    let app = ostrich_acme::rest::create_router(state);

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, base_url = %args.base_url, "Starting ACME server");

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("ACME Server shutdown complete");
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
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
