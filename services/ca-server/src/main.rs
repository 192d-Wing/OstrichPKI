//! OstrichPKI Certificate Authority Server
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: AU-2 (Audit Events)
//! - NIAP PP-CA: FCS_CKM.1 (Cryptographic Key Generation)

use anyhow::Result;
use axum::{Json, Router, routing::get};
use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI Certificate Authority Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-ca-server")]
#[command(about = "OstrichPKI Certificate Authority Server")]
#[command(version)]
struct Args {
    /// REST API bind address
    #[arg(long, env = "CA_REST_ADDRESS", default_value = "0.0.0.0:8080")]
    rest_address: String,

    /// gRPC bind address
    #[arg(long, env = "CA_GRPC_ADDRESS", default_value = "0.0.0.0:50051")]
    grpc_address: String,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// CA certificate file (PEM)
    #[arg(long, env = "CA_CERT_FILE")]
    ca_cert: Option<String>,

    /// CA private key file (PEM)
    #[arg(long, env = "CA_KEY_FILE")]
    ca_key: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Enable JSON logging format
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logging
    // NIST 800-53: AU-2 - Audit Events
    init_logging(&args.log_level, args.log_json)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI CA Server"
    );

    // Initialize database connection
    // NIST 800-53: SC-8 - Transmission Confidentiality
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;

    // Run database migrations
    // NIST 800-53: CM-3 - Configuration Change Control
    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // TODO: Full CA initialization requires:
    // 1. Loading CA certificate from file
    // 2. Loading CA private key from file (or HSM)
    // 3. Creating CertificateAuthority with proper initialization
    //
    // For now, start with health endpoints only
    if args.ca_cert.is_none() || args.ca_key.is_none() {
        tracing::warn!("CA certificate and key not provided - running in health-check only mode");
        tracing::warn!("Set CA_CERT_FILE and CA_KEY_FILE to enable full CA functionality");
    }

    // Create minimal REST API router with health endpoints
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check));

    // Parse REST address
    let rest_addr: SocketAddr = args
        .rest_address
        .parse()
        .expect("Invalid REST bind address");

    tracing::info!(%rest_addr, "Starting REST API server");

    // Start REST server
    let listener = tokio::net::TcpListener::bind(rest_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("CA Server shutdown complete");
    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "ostrich-ca",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn readiness_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ready",
        "service": "ostrich-ca",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Initialize logging with tracing
fn init_logging(level: &str, json: bool) -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    if json {
        // JSON format for production
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        // Human-readable format for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    Ok(())
}

/// Graceful shutdown signal handler
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
