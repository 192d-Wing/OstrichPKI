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

    /// Client certificate (PEM) for mTLS to the CA gRPC service. All of
    /// --ca-grpc-client-cert, --ca-grpc-client-key and --ca-grpc-ca-cert are
    /// required for mTLS (or none, with --ca-insecure in development).
    /// NIST 800-53: SC-8 / AC-17 / IA-5(2).
    #[arg(long, env = "CA_GRPC_CLIENT_CERT_FILE")]
    ca_grpc_client_cert: Option<String>,

    /// Client private key (PEM) for mTLS to the CA gRPC service.
    #[arg(long, env = "CA_GRPC_CLIENT_KEY_FILE")]
    ca_grpc_client_key: Option<String>,

    /// CA certificate(s) (PEM) used to verify the CA gRPC server.
    #[arg(long, env = "CA_GRPC_CA_CERT_FILE")]
    ca_grpc_ca_cert: Option<String>,

    /// TLS server name the CA gRPC server certificate must match. Defaults to
    /// the CA_GRPC_URL host.
    #[arg(long, env = "CA_GRPC_SERVER_NAME")]
    ca_grpc_server_name: Option<String>,

    /// Allow a plaintext (non-mTLS) gRPC channel to the CA. DEVELOPMENT ONLY -
    /// the ACME→CA channel carries issuance requests (NIST 800-53: SC-8, AC-17).
    #[arg(long = "ca-insecure", env = "CA_GRPC_INSECURE", num_args = 0..=1, default_missing_value = "true")]
    ca_insecure: Option<bool>,

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

    // Process-level FIPS gate before the database, the CA gRPC client or the
    // HTTPS listener. NIST 800-53: SC-13, SC-24.
    // NIAP PP-CA: supports FPT_TST_EXT.1; FPT_FLS.1.
    ostrich_common::tls::fips_gate()?;

    // Refuse the dev plaintext flag in release builds before any connection.
    let ca_insecure =
        ca_insecure_allowed(args.ca_insecure.unwrap_or(false), !cfg!(debug_assertions))?;

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
    // NIST 800-53: SC-8 / AC-17 - gRPC channel to the CA is TLS 1.3 mTLS on the
    // aws-lc-rs FIPS provider; plaintext only with the explicit dev flag.
    // NIAP PP-CA: FCS_TLSC_EXT.2, FTP_ITC.1.
    let ca_client = match &args.ca_grpc_url {
        Some(url) => {
            tracing::info!(endpoint = %url, "Connecting to CA gRPC service");
            let config = ostrich_common::GrpcClientConfig {
                endpoint: url.clone(),
                client_cert_pem: read_pem(&args.ca_grpc_client_cert)?,
                // NIST 800-53: SI-12 - the key PEM is zeroized on drop.
                client_key_pem: read_secret_pem(&args.ca_grpc_client_key)?,
                ca_cert_pem: read_pem(&args.ca_grpc_ca_cert)?,
                server_name: args.ca_grpc_server_name.clone(),
                allow_plaintext: ca_insecure,
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

/// Read a PEM file, or an empty string when no path is configured.
fn read_pem(path: &Option<String>) -> Result<String> {
    match path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("failed to read PEM file {p}: {e}")),
        None => Ok(String::new()),
    }
}

/// Read a private-key PEM file into `Zeroizing` memory (SI-12), or an empty
/// value when no path is configured.
fn read_secret_pem(path: &Option<String>) -> Result<zeroize::Zeroizing<String>> {
    match path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(p) => Ok(ostrich_common::read_private_key_pem(std::path::Path::new(
            p,
        ))?),
        None => Ok(zeroize::Zeroizing::new(String::new())),
    }
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

/// `--ca-insecure` / `CA_GRPC_INSECURE` is a development escape hatch: refused
/// in release builds (NIST 800-53: CM-6, SC-8, AC-17).
fn ca_insecure_allowed(requested: bool, release_build: bool) -> Result<bool> {
    if requested && release_build {
        anyhow::bail!(
            "CA_GRPC_INSECURE / --ca-insecure is not available in release builds; configure \
             CA_GRPC_CLIENT_CERT_FILE, CA_GRPC_CLIENT_KEY_FILE and CA_GRPC_CA_CERT_FILE for \
             mTLS to the CA; refusing to start"
        );
    }
    Ok(requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Args {
        let mut argv = vec!["ostrich-acme-server", "--database-url", "postgres://unused"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).expect("args")
    }

    /// CM-6: plaintext to the CA is opt-in; the flag parses bare or with a value.
    #[test]
    fn ca_insecure_defaults_off() {
        assert!(!parse(&[]).ca_insecure.unwrap_or(false));
        assert_eq!(parse(&["--ca-insecure"]).ca_insecure, Some(true));
        assert_eq!(parse(&["--ca-insecure", "false"]).ca_insecure, Some(false));
    }

    /// CM-6: the plaintext flag is refused in release builds.
    #[test]
    fn ca_insecure_is_debug_only() {
        assert!(ca_insecure_allowed(true, true).is_err());
        assert!(!ca_insecure_allowed(false, true).expect("off"));
        assert!(ca_insecure_allowed(true, false).expect("debug"));
    }

    #[test]
    fn grpc_client_material_args_parse() {
        let args = parse(&[
            "--ca-grpc-client-cert",
            "/c.pem",
            "--ca-grpc-client-key",
            "/k.pem",
            "--ca-grpc-ca-cert",
            "/ca.pem",
            "--ca-grpc-server-name",
            "ca-service",
        ]);
        assert_eq!(args.ca_grpc_server_name.as_deref(), Some("ca-service"));
        assert!(read_pem(&None).expect("none").is_empty());
        assert!(
            read_secret_pem(&Some(" ".to_string()))
                .expect("blank")
                .is_empty()
        );
        assert!(read_pem(&Some("/nonexistent/x.pem".to_string())).is_err());
    }
}
