//! OstrichPKI Trust Anchor Management Server (RFC 5934 TAMP).
//!
//! Runs the TAMP *manager / authority* role: issues signed trust-anchor
//! management messages and ingests targets' signed confirmations / status
//! responses over an HTTPS REST API.
//!
//! COMPLIANCE MAPPING:
//! - RFC 5934: Trust Anchor Management Protocol (TAMP)
//! - NIST 800-53: SC-8 (TLS), SC-12 (trust anchor management), AU-2 (audit),
//!   IA-2 (authentication), AC-3 (RBAC authorization)
//! - NIAP PP-CA: FMT_SMF.1 (management functions), FTP_ITC.1 (trusted channel)

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use ostrich_crypto::{Algorithm, CryptoProvider, KeyType};
use ostrich_tamp::{TampSigner, TampState};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI TAMP Manager Server.
///
/// Settings come from CLI flags or environment variables (env in parentheses).
#[derive(Parser, Debug)]
#[command(name = "ostrich-tamp-server")]
#[command(about = "OstrichPKI Trust Anchor Management Server (RFC 5934)")]
#[command(version)]
struct Args {
    /// HTTPS bind address.
    #[arg(long, env = "TAMP_BIND_ADDRESS", default_value = "0.0.0.0:8453")]
    bind_address: String,

    /// PostgreSQL database URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// TLS certificate file (PEM). HTTP (no TLS) is used if omitted (dev only).
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM).
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

    /// TLS CA certificate for client authentication (mTLS).
    #[arg(long, env = "TLS_CA_CERT_FILE")]
    tls_ca_cert: Option<String>,

    /// PKCS#8 private key file (PEM or DER) for the apex/management signing key.
    /// When omitted, an EPHEMERAL key is generated at startup (dev only); a
    /// persistent key keeps the subjectKeyIdentifier stable across restarts so
    /// targets continue to trust it (NIST 800-53 IA-7 / SC-12).
    #[arg(long, env = "TAMP_SIGNING_KEY_FILE")]
    signing_key_file: Option<String>,

    /// Algorithm of the signing key: ecdsa-p256 (default), ecdsa-p384, or ed25519.
    #[arg(long, env = "TAMP_SIGNING_KEY_ALGORITHM", default_value = "ecdsa-p256")]
    signing_key_algorithm: String,

    /// Log level.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Emit JSON logs.
    #[arg(long, env = "LOG_JSON", num_args = 0..=1, default_missing_value = "true")]
    log_json: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level, args.log_json.unwrap_or(false))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI TAMP Manager Server"
    );

    // Database + migrations (CM-3).
    let db_config = ostrich_db::PoolConfig::from_url(&args.database_url)?;
    let db_pool = ostrich_db::DatabasePool::new(&db_config).await?;
    tracing::info!("Running database migrations");
    db_pool.migrate().await?;

    // Crypto provider (FIPS-validated AWS-LC via the software provider).
    let crypto_provider: Arc<dyn CryptoProvider> =
        Arc::new(ostrich_crypto::software::SoftwareProvider::new());

    // Manager signing key (apex / management trust-anchor key). A persistent
    // PKCS#8 key (--signing-key-file) keeps the subjectKeyIdentifier stable
    // across restarts; otherwise an ephemeral key is generated for dev use.
    let (key, signing_algorithm) = match &args.signing_key_file {
        Some(path) => {
            let (key_type, algorithm) = parse_signing_algorithm(&args.signing_key_algorithm)?;
            let der = read_pkcs8_der(path)?;
            let key = crypto_provider
                .import_key(key_type, der, "tamp-manager-signing")
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to import signing key '{path}' as {} \
                         (check --signing-key-algorithm matches the key): {e}",
                        args.signing_key_algorithm
                    )
                })?;
            tracing::info!(path = %path, algorithm = %args.signing_key_algorithm,
                "Loaded persistent TAMP manager signing key");
            (key, algorithm)
        }
        None => {
            let key = crypto_provider
                .generate_key_pair(KeyType::EcP256, "tamp-manager-signing", true)
                .await?;
            tracing::warn!(
                "No --signing-key-file configured; using an EPHEMERAL ECDSA P-256 signing key \
                 (dev only). Its subjectKeyIdentifier changes on every restart — provide a \
                 persistent PKCS#8 key (or HSM key) in production (NIST 800-53 IA-7 / SC-12)."
            );
            (key, Algorithm::EcdsaP256Sha256)
        }
    };
    let spki = crypto_provider.export_public_key(&key).await?;
    let ski = ostrich_x509::signing::key_identifier(&spki)
        .map_err(|e| anyhow::anyhow!("failed to derive signing key identifier: {e}"))?;
    // Operators register this (SKI, SPKI) as a trusted signer on each target.
    tracing::info!(
        ski = %hex_encode(&ski),
        signer_spki_b64 = %base64_encode(&spki),
        "TAMP manager signing identity"
    );

    // Audit sink (tamper-evident hash chain; AU-9/AU-10).
    let audit_sink = Arc::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone()));

    // Authentication: database-backed password provider with bearer sessions,
    // mirroring the CA service (IA-2, IA-5(1), AC-7).
    let user_repo = Arc::new(ostrich_db::repository::DbUserRepository::new(
        db_pool.clone(),
    ));
    let sessions = Arc::new(
        ostrich_common::auth::SessionManager::with_store(
            ostrich_common::auth::SessionConfig::default(),
            Arc::new(ostrich_db::repository::DbSessionStore::new(db_pool.clone())),
        )
        .with_audit_hook(Arc::new(ostrich_audit::SessionAuditAdapter::new(
            audit_sink.clone(),
        ))),
    );
    sessions
        .clone()
        .spawn_reaper(ostrich_common::auth::SessionManager::DEFAULT_REAP_INTERVAL);
    let auth_audit = Arc::new(ostrich_audit::AuthAuditAdapter::new(audit_sink.clone()));
    let auth_provider: Arc<dyn ostrich_common::auth::AuthProvider> = Arc::new(
        ostrich_common::auth::PasswordAuthProvider::new(
            user_repo,
            ostrich_common::auth::LockoutConfig::default(),
            sessions,
        )
        .with_audit_hook(auth_audit),
    );
    let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

    // Assemble the manager + REST state.
    let repo = ostrich_db::repository::TampRepository::new(db_pool);
    let manager = Arc::new(ostrich_tamp::TampManager::new(repo, audit_sink));
    let signer = Arc::new(TampSigner {
        provider: crypto_provider,
        key,
        ski,
        algorithm: signing_algorithm,
    });
    let state = TampState {
        manager,
        signer,
        auth_provider: auth_provider.clone(),
        rbac_policy,
    };

    let app =
        ostrich_tamp::create_router(state).merge(ostrich_common::auth::auth_routes(auth_provider));

    let addr: SocketAddr = args.bind_address.parse().expect("Invalid bind address");
    tracing::info!(%addr, "Starting TAMP server");

    // TLS when configured (SC-8 / FTP_ITC.1).
    let tls = ostrich_common::tls::TlsSettings::from_options(
        args.tls_cert,
        args.tls_key,
        args.tls_ca_cert,
    )?;
    ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;

    tracing::info!("TAMP Server shutdown complete");
    Ok(())
}

/// Map a signing-algorithm name to the crypto key/signature types.
fn parse_signing_algorithm(name: &str) -> Result<(KeyType, Algorithm)> {
    match name.to_ascii_lowercase().as_str() {
        "ecdsa-p256" | "ec-p256" | "p256" => Ok((KeyType::EcP256, Algorithm::EcdsaP256Sha256)),
        "ecdsa-p384" | "ec-p384" | "p384" => Ok((KeyType::EcP384, Algorithm::EcdsaP384Sha384)),
        "ed25519" => Ok((KeyType::Ed25519, Algorithm::Ed25519)),
        other => anyhow::bail!(
            "unsupported --signing-key-algorithm '{other}' \
             (expected ecdsa-p256, ecdsa-p384, or ed25519)"
        ),
    }
}

/// Read a PKCS#8 private key file as DER, accepting PEM or raw DER. The bytes
/// are wrapped in `Zeroizing` so the plaintext key is wiped after import (SI-12).
fn read_pkcs8_der(path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read signing key file '{path}': {e}"))?;
    if bytes.starts_with(b"-----BEGIN") {
        let (label, der) = pem_rfc7468::decode_vec(&bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode PEM signing key '{path}': {e}"))?;
        // import_key expects PKCS#8 ("PRIVATE KEY"). Reject SEC1 ("EC PRIVATE
        // KEY") / PKCS#1 ("RSA PRIVATE KEY") with an actionable message instead
        // of a downstream "failed to parse PKCS#8" error.
        if label != "PRIVATE KEY" {
            anyhow::bail!(
                "signing key '{path}' is PEM '{label}', but a PKCS#8 key is required. \
                 Convert it, e.g.: openssl pkcs8 -topk8 -nocrypt -in {path} -out key.p8.pem"
            );
        }
        Ok(zeroize::Zeroizing::new(der))
    } else {
        Ok(zeroize::Zeroizing::new(bytes))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
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
