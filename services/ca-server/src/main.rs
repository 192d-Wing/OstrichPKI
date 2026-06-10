//! OstrichPKI Certificate Authority Server
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: AU-2 (Audit Events)
//! - NIAP PP-CA: FCS_CKM.1 (Cryptographic Key Generation)

use anyhow::{Context, Result};
use axum::{Json, Router, routing::get};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
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

    /// CA certificate ID (UUID of the ca_certificates row to serve).
    /// When omitted, the most recently created valid CA certificate is used.
    #[arg(long, env = "CA_CERTIFICATE_ID")]
    ca_certificate_id: Option<String>,

    /// PKCS#11 library path for HSM-backed CA keys (e.g. SoftHSM2 .so/.dylib)
    /// NIAP PP-CA: FCS_STG_EXT.1 - CA signing keys must be HSM-backed
    #[arg(long, env = "PKCS11_MODULE_PATH")]
    pkcs11_module: Option<String>,

    /// PKCS#11 slot ID
    #[arg(long, env = "PKCS11_SLOT_ID", default_value = "0")]
    pkcs11_slot: u64,

    /// PKCS#11 user PIN
    /// NIST 800-53: IA-7 - Cryptographic module authentication
    #[arg(long, env = "PKCS11_PIN")]
    pkcs11_pin: Option<String>,

    /// CRL validity period in hours
    #[arg(long, env = "CRL_VALIDITY_HOURS", default_value = "24")]
    crl_validity_hours: u32,

    /// TLS certificate chain file (PEM). With --tls-key, serves HTTPS (TLS 1.3).
    /// NIST 800-53: SC-8 - Transmission Confidentiality
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file (PEM)
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

    /// Client CA bundle (PEM). When set, clients must present certificates (mTLS).
    /// NIST 800-53: AC-17 - mTLS for inter-service communication
    #[arg(long, env = "TLS_CLIENT_CA_FILE")]
    tls_client_ca: Option<String>,

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

    // Bootstrap the Certificate Authority from the database.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-12 - CA key loaded by reference from the crypto provider
    // - NIAP PP-CA: FCS_STG_EXT.1 - CertificateAuthority::new validates the
    //   signing key is HSM-backed; software keys are rejected
    // - NIAP PP-CA: FMT_SMF.1 - CA initialization is a security management function
    let ca = bootstrap_ca(&args, &db_pool).await?;

    let app = match &ca {
        Some(ca) => {
            // Authentication: fail-closed placeholder until a real provider
            // (password DB, mTLS, OIDC) is wired in. All protected endpoints
            // return 401. Same pattern as scms-server.
            // NIST 800-53: AC-3 - fail-closed access enforcement
            tracing::warn!(
                "CA REST API is running with DisabledAuthProvider: protected endpoints \
                 return 401 until a real AuthProvider is configured"
            );
            let auth_provider: Arc<dyn ostrich_common::auth::AuthProvider> =
                Arc::new(ostrich_common::auth::DisabledAuthProvider::new());
            let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

            // Approval workflow (NIAP PP-CA FDP_CER_EXT.3: issuance requires approval)
            let approval_engine = Arc::new(ostrich_ca::ApprovalEngine::new(
                ostrich_ca::approval::ApprovalConfig::default(),
            ));
            let approval_repo = Arc::new(ostrich_db::repository::ApprovalRepository::new(
                db_pool.pool().clone(),
            ));

            // Start gRPC service for inter-service issuance (ACME/EST/SCMS).
            // NIST 800-53: AC-17 - production deployments must front this with
            // mTLS (tonic TLS config or service mesh).
            let grpc_addr: SocketAddr = args
                .grpc_address
                .parse()
                .context("Invalid gRPC bind address")?;
            let grpc_service = ostrich_ca::CaGrpcService::new(ca.clone());
            tracing::info!(%grpc_addr, "Starting CA gRPC service");
            tokio::spawn(async move {
                let result = tonic::transport::Server::builder()
                    .add_service(
                        ostrich_protocol::certificate_authority_service_server::CertificateAuthorityServiceServer::new(
                            grpc_service,
                        ),
                    )
                    .serve_with_shutdown(grpc_addr, shutdown_signal())
                    .await;
                if let Err(e) = result {
                    tracing::error!(error = %e, "CA gRPC server failed");
                }
            });

            ostrich_ca::rest::create_router(
                ca.clone(),
                auth_provider,
                rbac_policy,
                approval_engine,
                approval_repo,
            )
        }
        None => {
            tracing::warn!(
                "No CA certificate registered in the database - running in health-check \
                 only mode. Register a CA (ca_keys + ca_certificates) and set \
                 CA_CERTIFICATE_ID to enable issuance."
            );
            Router::new()
                .route("/health", get(health_check))
                .route("/ready", get(readiness_check))
        }
    };

    // Parse REST address
    let rest_addr: SocketAddr = args
        .rest_address
        .parse()
        .expect("Invalid REST bind address");

    tracing::info!(%rest_addr, "Starting REST API server");

    // Start REST server (HTTPS when TLS is configured, HTTP with warning otherwise)
    // NIST 800-53: SC-8 - Transmission Confidentiality and Integrity
    let tls = ostrich_common::tls::TlsSettings::from_options(
        args.tls_cert,
        args.tls_key,
        args.tls_client_ca,
    )?;
    ostrich_common::tls::serve(rest_addr, app, tls.as_ref(), shutdown_signal()).await?;

    tracing::info!("CA Server shutdown complete");
    Ok(())
}

/// Load the CA certificate + key reference from the database and construct
/// the CertificateAuthority.
///
/// Returns `Ok(None)` when no CA certificate is registered (health-check-only
/// mode). Errors are fatal: a *misconfigured* CA must not silently degrade.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 - key material stays in the crypto provider; only the
///   KeyHandle reference is reconstructed here
/// - NIST 800-53: CM-6 - explicit CA_CERTIFICATE_ID beats implicit selection
/// - NIAP PP-CA: FCS_STG_EXT.1 - HSM validation happens in CertificateAuthority::new
async fn bootstrap_ca(
    args: &Args,
    db_pool: &ostrich_db::DatabasePool,
) -> Result<Option<Arc<ostrich_ca::CertificateAuthority>>> {
    let repo = ostrich_db::repository::CaRepository::new(db_pool.clone());

    // Resolve the CA certificate row
    let ca_cert_row = match &args.ca_certificate_id {
        Some(id) => {
            let id = uuid::Uuid::parse_str(id).context("CA_CERTIFICATE_ID is not a valid UUID")?;
            Some(
                repo.find_ca_certificate(id)
                    .await?
                    .with_context(|| format!("CA certificate {} not found in database", id))?,
            )
        }
        None => repo.find_default_ca_certificate().await?,
    };
    let Some(ca_cert_row) = ca_cert_row else {
        return Ok(None);
    };

    // Resolve the key reference
    let ca_key_row = repo
        .find_ca_key(ca_cert_row.ca_key_id)
        .await?
        .with_context(|| format!("CA key {} not found in database", ca_cert_row.ca_key_id))?;

    let provider_id = match ca_key_row.provider_type.as_str() {
        "Pkcs11" => ostrich_crypto::key::ProviderId::Pkcs11 {
            slot_id: ca_key_row.provider_slot_id.unwrap_or(0) as u64,
        },
        "Software" => ostrich_crypto::key::ProviderId::Software,
        other => anyhow::bail!("Unknown CA key provider type: {}", other),
    };

    let key_handle = ostrich_crypto::KeyHandle {
        provider_id,
        key_id: ca_key_row.key_id.clone(),
        key_type: parse_crypto_enum(&ca_key_row.key_type)
            .context("Invalid key_type on ca_keys row")?,
        algorithm: parse_crypto_enum(&ca_key_row.algorithm)
            .context("Invalid algorithm on ca_keys row")?,
        label: ca_key_row.label.clone(),
    };

    // Crypto provider: PKCS#11 when configured, software otherwise.
    // NIAP PP-CA FCS_STG_EXT.1: with a software provider the HSM validation in
    // CertificateAuthority::new will reject the key - that failure is correct
    // and intentional for HSM-referenced keys without PKCS#11 config.
    let crypto_provider: Box<dyn ostrich_crypto::CryptoProvider> =
        match (&args.pkcs11_module, &args.pkcs11_pin) {
            (Some(module), Some(pin)) => {
                tracing::info!(module = %module, slot = args.pkcs11_slot, "Using PKCS#11 HSM provider");
                ostrich_crypto::CryptoProviderFactory::create_pkcs11_provider(
                    std::path::Path::new(module),
                    args.pkcs11_slot,
                    pin,
                )
                .await
                .context("Failed to initialize PKCS#11 provider")?
            }
            (None, None) => {
                tracing::warn!(
                    "No PKCS#11 configuration; using software crypto provider. \
                     HSM-referenced CA keys will fail FCS_STG_EXT.1 validation."
                );
                ostrich_crypto::CryptoProviderFactory::create_software_provider()
            }
            _ => anyhow::bail!(
                "Partial PKCS#11 configuration: both PKCS11_MODULE_PATH and PKCS11_PIN are required"
            ),
        };

    // Map the CA certificate row into the model CertificateAuthority expects.
    // For a root CA the issuing ca_id is itself.
    let ca_certificate = ostrich_db::models::Certificate {
        id: ca_cert_row.id,
        ca_id: ca_cert_row.parent_ca_id.unwrap_or(ca_cert_row.id),
        serial_number: ca_cert_row.serial_number.clone(),
        subject_dn: ca_cert_row.subject_dn.clone(),
        issuer_dn: ca_cert_row.issuer_dn.clone(),
        not_before: ca_cert_row.not_before,
        not_after: ca_cert_row.not_after,
        der_encoded: ca_cert_row.der_encoded.clone(),
        pem_encoded: ca_cert_row.pem_encoded.clone(),
        revoked: false,
        revocation_time: None,
        revocation_reason: None,
        issuer_service: Some("CA".to_string()),
        requestor: None,
        profile_name: None,
        metadata: None,
        created_at: ca_cert_row.created_at,
        updated_at: ca_cert_row.updated_at,
    };

    let audit_sink = Box::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone()));

    let ca = ostrich_ca::CertificateAuthority::new(
        ca_certificate,
        key_handle,
        crypto_provider,
        db_pool.clone(),
        audit_sink,
        args.crl_validity_hours,
    )
    .context("CertificateAuthority initialization failed")?;

    tracing::info!(
        ca_id = %ca_cert_row.id,
        subject = %ca_cert_row.subject_dn,
        is_root = ca_cert_row.is_root,
        "Certificate Authority initialized"
    );

    Ok(Some(Arc::new(ca)))
}

/// Parse an ostrich-crypto enum (KeyType/Algorithm) from its serde string form.
fn parse_crypto_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("'{}': {}", s, e))
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
