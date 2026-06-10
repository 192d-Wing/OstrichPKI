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

    /// TLS certificate chain file (PEM). With --tls-key, serves HTTPS (TLS 1.3).
    /// NIST 800-53: SC-8 - Transmission Confidentiality
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM)
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

    /// Client CA bundle (PEM). When set, clients must present certificates (mTLS).
    #[arg(long, env = "TLS_CLIENT_CA_FILE")]
    tls_client_ca: Option<String>,

    /// CA gRPC endpoint for certificate issuance
    /// NIST 800-53: SC-17 - PKI certificate issuance via CA service
    #[arg(long, env = "CA_GRPC_URL")]
    ca_grpc_url: Option<String>,

    /// HTTP-01 challenge fetch port. RFC 8555 §8.3 mandates 80; override for
    /// dev/E2E environments only (like Pebble's -httpPort).
    #[arg(long, env = "ACME_HTTP01_PORT", default_value = "80")]
    http01_port: u16,

    /// Allow private-IP/localhost identifiers. DISABLES the SI-10 SSRF guard;
    /// dev/E2E ONLY.
    #[arg(long, env = "ACME_ALLOW_PRIVATE_IP_DOMAINS", default_value = "false")]
    allow_private_ip_domains: bool,

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

    // Initialize CA client for certificate issuance (RFC 8555 §7.4)
    // NIST 800-53: SC-17 - PKI certificate issuance via CA service
    // NIST 800-53: SC-8 - gRPC channel to CA (mTLS when configured)
    let ca_client = match &args.ca_grpc_url {
        Some(url) => {
            tracing::info!(endpoint = %url, "Connecting to CA gRPC service");
            let config = ostrich_common::GrpcClientConfig {
                endpoint: url.clone(),
                ..Default::default()
            };
            let client =
                ostrich_acme::ca_integration::AcmeCaClient::new(config, db_pool.clone()).await?;
            Some(Arc::new(client))
        }
        None => {
            // NIST 800-53: SI-17 - Fail secure: finalization will be rejected
            tracing::warn!(
                "CA_GRPC_URL not configured; ACME order finalization will fail \
                 until a CA gRPC endpoint is provided"
            );
            None
        }
    };

    // Create ACME state
    if args.allow_private_ip_domains {
        // NIST 800-53: SI-10 - make the disabled SSRF guard impossible to miss
        tracing::warn!(
            "ACME_ALLOW_PRIVATE_IP_DOMAINS=true: SSRF guard disabled; private/localhost \
             identifiers will validate. Dev/E2E environments only."
        );
    }
    let state = ostrich_acme::rest::AcmeState::new(
        db_pool,
        Arc::new(crypto_provider),
        Arc::new(audit_sink),
        args.base_url.clone(),
        ca_client,
    )
    .with_challenge_options(args.http01_port, args.allow_private_ip_domains);

    // Create REST API router
    let app = ostrich_acme::rest::create_router(state);

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, base_url = %args.base_url, "Starting ACME server");

    // Start server (HTTPS when TLS is configured, HTTP with warning otherwise)
    // NIST 800-53: SC-8 - Transmission Confidentiality and Integrity
    let tls = ostrich_common::tls::TlsSettings::from_options(
        args.tls_cert,
        args.tls_key,
        args.tls_client_ca,
    )?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

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
