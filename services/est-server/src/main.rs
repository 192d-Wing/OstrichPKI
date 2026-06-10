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

    /// CA gRPC endpoint for certificate issuance (RFC 7030 §4.2).
    /// NIST 800-53: SC-17 - PKI certificate issuance via CA service.
    #[arg(long, env = "CA_GRPC_URL")]
    ca_grpc_url: Option<String>,

    /// Certificate profile used for EST enrollment / re-enrollment.
    /// NIST 800-53: CM-6 - Configurable issuance profile (secure default).
    #[arg(long, env = "EST_ENROLL_PROFILE", default_value = "tls_client")]
    enroll_profile: String,

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

    // Authentication: database-backed password provider (argon2id) with
    // failed-attempt lockout and bearer-token sessions, mirroring ca-server.
    // The users table is provisioned via `ostrich-init`.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: IA-2 (Identification and Authentication)
    // - NIST 800-53: IA-5(1) (Password-based Authentication, Argon2id)
    // - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - lockout
    // - NIAP PP-CA: FIA_UAU.1 / FIA_AFL.1
    //
    // POAM: sessions are in-memory (SessionManager); they do not survive a
    // restart and do not replicate across instances.
    let auth_provider: Arc<dyn ostrich_common::auth::AuthProvider> =
        Arc::new(ostrich_common::auth::PasswordAuthProvider::new(
            Arc::new(ostrich_db::repository::DbUserRepository::new(
                db_pool.clone(),
            )),
            Arc::new(ostrich_common::auth::AuthLockout::new(
                ostrich_common::auth::LockoutConfig::default(),
            )),
            Arc::new(ostrich_common::auth::SessionManager::new(
                ostrich_common::auth::SessionConfig::default(),
            )),
        ));
    let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

    // Initialize the CA client for certificate issuance (RFC 7030 §4.2).
    // NIST 800-53: SC-17 - PKI certificate issuance via CA service.
    // NIST 800-53: SC-8 - gRPC channel to CA (mTLS when configured).
    let ca_client = match &args.ca_grpc_url {
        Some(url) => {
            tracing::info!(endpoint = %url, "Connecting to CA gRPC service");
            let config = ostrich_common::GrpcClientConfig {
                endpoint: url.clone(),
                ..Default::default()
            };
            let client =
                ostrich_est::ca_integration::EstCaClient::new(config, db_pool.clone()).await?;
            Some(Arc::new(client))
        }
        None => {
            // NIST 800-53: SI-17 - Fail secure: enrollment will be rejected.
            tracing::warn!(
                "CA_GRPC_URL not configured; EST enrollment will fail until a CA \
                 gRPC endpoint is provided"
            );
            None
        }
    };

    // Load the default CA certificate DER for /cacerts (RFC 7030 §4.1).
    let ca_repo = ostrich_db::repository::CaRepository::new(db_pool.clone());
    let ca_certificate_der = match ca_repo.find_default_ca_certificate().await? {
        Some(ca_cert) => {
            tracing::info!(ca_id = %ca_cert.id, "Loaded default CA certificate for /cacerts");
            Some(ca_cert.der_encoded)
        }
        None => {
            tracing::warn!(
                "No default CA certificate registered; /cacerts will return an empty PKCS#7"
            );
            None
        }
    };

    let state = ostrich_est::rest::EstState::new_with_auth(
        db_pool,
        Arc::new(crypto_provider),
        Arc::new(audit_sink),
        auth_provider.clone(),
        rbac_policy,
    )
    .with_ca(ca_client, ca_certificate_der)
    .with_profile(args.enroll_profile.clone());

    // Create router and mount the shared session API (login/logout).
    // Public by necessity; brute-force is mitigated by lockout (AC-7 / FIA_AFL.1).
    let app = ostrich_est::rest::create_router(state)
        .merge(ostrich_common::auth::auth_routes(auth_provider));

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, "Starting EST server");

    // Serve HTTPS when TLS is configured (HTTP fallback warns at startup).
    // RFC 7030 §3.3 requires TLS for EST; --tls-ca-cert enables the mTLS
    // client authentication EST relies on for enrollment identity.
    // NIST 800-53: SC-8 - Transmission Confidentiality and Integrity
    let tls = ostrich_common::tls::TlsSettings::from_options(
        args.tls_cert,
        args.tls_key,
        args.tls_ca_cert,
    )?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

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
