//! OstrichPKI Web UI Server
//!
//! This service provides a web-based administration interface for OstrichPKI.
//! It serves a Yew-based WASM application and provides OAuth/OIDC authentication
//! with Keycloak, along with an API proxy to backend services.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-2 (Account Management), AC-3 (Access Enforcement)
//! - NIST 800-53: AU-2 (Auditable Events), AU-3 (Content of Audit Records)
//! - NIST 800-53: IA-2 (Identification and Authentication), IA-8 (External IdP)
//! - NIST 800-53: SC-8 (Transmission Confidentiality), SC-18 (Mobile Code)
//! - NIAP PP-CA: FIA_UAU.1 (User Authentication), FAU_GEN.1 (Audit Generation)

mod server;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use server::{config::WebUiConfig, router::create_router};

/// OstrichPKI Web UI Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-web-ui")]
#[command(about = "OstrichPKI Web Administration Interface")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/web-ui.json")]
    config: String,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// Enable JSON logging format
    #[arg(long)]
    json_logs: bool,

    /// TLS certificate chain file (PEM). With --tls-key, serves HTTPS (TLS 1.3).
    /// NIST 800-53: SC-8 - Transmission Confidentiality
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM)
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    // NIST 800-53: AU-12 - Audit Generation
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if args.json_logs {
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

    info!(
        service = "ostrich-web-ui",
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI Web UI"
    );

    // Load configuration
    let config = WebUiConfig::load(&args.config).await?;

    info!(
        oidc_issuer = %config.oidc.issuer_url,
        "OIDC provider configured"
    );

    // Create the router with all routes
    let app = create_router(config).await?;

    // Parse listen address
    let addr: SocketAddr = args.listen.parse()?;

    info!(%addr, "Web UI server listening");

    // Run the server with graceful shutdown.
    // NIST 800-53: SC-8 - serves HTTPS directly when TLS is configured;
    // otherwise plain HTTP (e.g. behind a TLS-terminating reverse proxy) with
    // a startup warning.
    let tls = ostrich_common::tls::TlsSettings::from_options(args.tls_cert, args.tls_key, None)?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

    info!("Web UI server shutdown complete");

    Ok(())
}

/// Wait for shutdown signal
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
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
