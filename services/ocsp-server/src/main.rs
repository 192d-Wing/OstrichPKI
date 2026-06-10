//! OstrichPKI OCSP Responder Server
//!
//! COMPLIANCE MAPPING:
//! - RFC 6960: Online Certificate Status Protocol (OCSP)
//! - NIST 800-53: SC-17 (PKI Certificates)

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI OCSP Responder Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-ocsp-server")]
#[command(about = "OstrichPKI OCSP Responder (RFC 6960)")]
#[command(version)]
struct Args {
    /// HTTP bind address
    #[arg(long, env = "OCSP_BIND_ADDRESS", default_value = "0.0.0.0:8081")]
    bind_address: String,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// OCSP signing certificate file
    #[arg(long, env = "OCSP_SIGNING_CERT")]
    signing_cert: Option<String>,

    /// OCSP signing key file
    #[arg(long, env = "OCSP_SIGNING_KEY")]
    signing_key: Option<String>,

    /// TLS certificate chain file (PEM). With --tls-key, serves HTTPS (TLS 1.3).
    /// OCSP responses are self-signed and verifiable, so plain HTTP is
    /// RFC 6960-conformant; TLS is still recommended for privacy.
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM)
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

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
        "Starting OstrichPKI OCSP Responder"
    );

    // Initialize database
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;

    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // Initialize crypto provider
    let crypto_provider = Arc::new(ostrich_crypto::software::SoftwareProvider::new());
    let audit_sink = Arc::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone()));

    // Create OCSP responder with default config
    // TODO: Load signing certificate and key from files
    let config = ostrich_ocsp::responder::OcspConfig::default();
    let responder = ostrich_ocsp::OcspResponder::new(config, db_pool, crypto_provider, audit_sink);

    // Create router
    let app = ostrich_ocsp::rest::create_router(Arc::new(responder));

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, "Starting OCSP responder");

    // NIST 800-53: SC-8 - HTTPS when TLS is configured (HTTP fallback warns).
    // OCSP is a public, unauthenticated protocol, so no client CA option here.
    let tls = ostrich_common::tls::TlsSettings::from_options(args.tls_cert, args.tls_key, None)?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

    tracing::info!("OCSP Responder shutdown complete");
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
