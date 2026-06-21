//! OstrichPKI SCMS (Smartcard Management System) Server
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5 (Authenticator Management)
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment)

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI SCMS Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-scms-server")]
#[command(about = "OstrichPKI Smartcard Management System Server")]
#[command(version)]
struct Args {
    /// HTTP bind address
    #[arg(long, env = "SCMS_BIND_ADDRESS", default_value = "0.0.0.0:8082")]
    bind_address: String,

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
        "Starting OstrichPKI SCMS Server"
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
    // failed-attempt lockout and bearer-token sessions. Users are provisioned
    // via `ostrich-init --admin-username/--admin-password` and (eventually)
    // the user-management API.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: IA-2, IA-5(1), AC-7 (lockout)
    // - NIAP PP-CA: FIA_UAU.1 / FIA_AFL.1
    //
    // Sessions are persisted in Postgres (DbSessionStore): they survive a
    // restart and are shared across instances (NIST 800-53: SC-23, AC-12). Each
    // service still scopes sessions to its own login (a token issued by
    // ca-server is not presented here) - the shared table is keyed by token.
    let session_manager = Arc::new(
        ostrich_common::auth::SessionManager::with_store(
            ostrich_common::auth::SessionConfig::default(),
            Arc::new(ostrich_db::repository::DbSessionStore::new(db_pool.clone())),
        )
        // Emit login/logout/admin-termination as audit events (NIST 800-53: AU-2).
        .with_audit_hook(Arc::new(ostrich_audit::SessionAuditAdapter::new(Arc::new(
            ostrich_audit::DatabaseAuditSink::new(db_pool.clone()),
        )))),
    );
    // Reap expired/terminated sessions periodically so the table does not grow
    // unbounded (NIST 800-53: AC-12).
    session_manager
        .clone()
        .spawn_reaper(ostrich_common::auth::SessionManager::DEFAULT_REAP_INTERVAL);
    let auth_provider: Arc<dyn ostrich_common::auth::AuthProvider> = Arc::new(
        ostrich_common::auth::PasswordAuthProvider::new(
            Arc::new(ostrich_db::repository::DbUserRepository::new(
                db_pool.clone(),
            )),
            ostrich_common::auth::LockoutConfig::default(),
            session_manager,
        )
        // Audit failed logins / lockouts / unlocks (NIST 800-53: AU-2, AC-7).
        .with_audit_hook(Arc::new(ostrich_audit::AuthAuditAdapter::new(Arc::new(
            ostrich_audit::DatabaseAuditSink::new(db_pool.clone()),
        )))),
    );

    // RBAC policy: enforces per-permission checks at handler entry.
    // NIST 800-53: AC-3 (Access Enforcement), AC-5 (Separation of Duties)
    // NIAP PP-CA: FMT_MTD.1 (Management of TSF Data)
    let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

    // Create SCMS state
    let state = ostrich_scms::rest::ScmsState::new(
        db_pool,
        Arc::new(crypto_provider),
        Arc::new(audit_sink),
        auth_provider.clone(),
        rbac_policy,
    );

    // Create router; merge the session API (login/logout). Public by
    // necessity; brute-force mitigated by lockout (AC-7 / FIA_AFL.1).
    let app = ostrich_scms::rest::create_router(state)
        .merge(ostrich_common::auth::auth_routes(auth_provider));

    // Parse bind address
    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, "Starting SCMS server");

    // NIST 800-53: SC-8 - HTTPS when TLS is configured (HTTP fallback warns)
    let tls = ostrich_common::tls::TlsSettings::from_options(
        args.tls_cert,
        args.tls_key,
        args.tls_client_ca,
    )?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

    tracing::info!("SCMS Server shutdown complete");
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
