//! OstrichPKI OCSP Responder Server
//!
//! COMPLIANCE MAPPING:
//! - RFC 6960: Online Certificate Status Protocol (OCSP)
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIAP PP-CA: FDP_OCSPG_EXT.1 (OCSP Response Generation)

use anyhow::{Context, Result};
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

    /// CA certificate ID (UUID of the ca_certificates row whose key signs
    /// OCSP responses). When omitted, the most recently created valid CA
    /// certificate is used.
    #[arg(long, env = "CA_CERTIFICATE_ID")]
    ca_certificate_id: Option<String>,

    /// PKCS#11 library path for HSM-backed CA keys (e.g. SoftHSM2 .so/.dylib)
    /// NIAP PP-CA: FCS_STG_EXT.1 - CA signing keys should be HSM-backed
    #[arg(long, env = "PKCS11_MODULE_PATH")]
    pkcs11_module: Option<String>,

    /// PKCS#11 slot ID
    #[arg(long, env = "PKCS11_SLOT_ID", default_value = "0")]
    pkcs11_slot: u64,

    /// PKCS#11 user PIN
    /// NIST 800-53: IA-7 - Cryptographic module authentication
    #[arg(long, env = "PKCS11_PIN")]
    pkcs11_pin: Option<String>,

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

    // Bootstrap the OCSP signing configuration from the registered CA.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-12 - the CA key is loaded by reference (KeyHandle);
    //   key material stays in the crypto provider
    // - NIST 800-53: CM-6 - without a registered CA the responder runs with
    //   signing unconfigured and fails closed on every status request
    // - NIAP PP-CA: FCS_COP.1(1) - OCSP responses are signed with the real CA key
    let (config, crypto_provider) = bootstrap_ocsp(&args, &db_pool).await?;
    let audit_sink = Arc::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone()));

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

/// Load the CA certificate + key reference from the database and build the
/// OCSP responder configuration and crypto provider.
///
/// Mirrors the CA server bootstrap (services/ca-server/src/main.rs
/// `bootstrap_ca`). When no CA certificate is registered, the responder runs
/// with `signing_key: None` and fails closed on every status request
/// (a warning is logged). Misconfiguration (e.g. a registered CA whose key
/// row is missing, or partial PKCS#11 settings) is a fatal error.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-12 - key material stays in the crypto provider; only the
///   KeyHandle reference is reconstructed here
/// - NIST 800-53: CM-6 - explicit CA_CERTIFICATE_ID beats implicit selection;
///   fail-closed default when signing is unconfigured
/// - NIAP PP-CA: FDP_OCSPG_EXT.1 - responses signed by the CA key
/// - NIAP PP-CA: FPT_STM.1 - timestamps produced by the responder
async fn bootstrap_ocsp(
    args: &Args,
    db_pool: &ostrich_db::DatabasePool,
) -> Result<(
    ostrich_ocsp::responder::OcspConfig,
    Arc<dyn ostrich_crypto::CryptoProvider>,
)> {
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
        // NIST 800-53: CM-6 - fail-closed default: the responder starts but
        // refuses to sign (ostrich-ocsp returns SigningError per request).
        tracing::warn!(
            "No CA certificate registered in the database - OCSP signing is NOT configured \
             and every status request will fail closed. Register a CA (ca_keys + \
             ca_certificates) and set CA_CERTIFICATE_ID to enable signed responses."
        );
        let provider: Arc<dyn ostrich_crypto::CryptoProvider> =
            Arc::from(ostrich_crypto::CryptoProviderFactory::create_software_provider());
        return Ok((ostrich_ocsp::responder::OcspConfig::default(), provider));
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
    // NIAP PP-CA FCS_STG_EXT.1: HSM-backed CA keys require the PKCS#11
    // provider; with a software provider HSM-referenced keys will fail to
    // sign - that failure is correct and intentional.
    let crypto_provider: Box<dyn ostrich_crypto::CryptoProvider> =
        match (&args.pkcs11_module, &args.pkcs11_pin) {
            (Some(module), Some(pin)) => {
                // Prefer the slot recorded on the ca_keys row (SoftHSM assigns
                // random slot IDs at token init; the registered value is
                // authoritative). PKCS11_SLOT_ID is the fallback.
                let slot = ca_key_row
                    .provider_slot_id
                    .map(|s| s as u64)
                    .unwrap_or(args.pkcs11_slot);
                tracing::info!(module = %module, slot, "Using PKCS#11 HSM provider");
                ostrich_crypto::CryptoProviderFactory::create_pkcs11_provider(
                    std::path::Path::new(module),
                    slot,
                    pin,
                )
                .await
                .context("Failed to initialize PKCS#11 provider")?
            }
            (None, None) => {
                tracing::warn!(
                    "No PKCS#11 configuration; using software crypto provider. \
                     HSM-referenced CA keys will fail to sign OCSP responses."
                );
                ostrich_crypto::CryptoProviderFactory::create_software_provider()
            }
            _ => anyhow::bail!(
                "Partial PKCS#11 configuration: both PKCS11_MODULE_PATH and PKCS11_PIN are required"
            ),
        };

    tracing::info!(
        ca_id = %ca_cert_row.id,
        subject = %ca_cert_row.subject_dn,
        key_label = %ca_key_row.label,
        "OCSP responder signing configured with CA key"
    );

    let config = ostrich_ocsp::responder::OcspConfig {
        ca_id: ca_cert_row.id,
        signing_key: Some(key_handle),
        ca_certificate_der: Some(ca_cert_row.der_encoded.clone()),
        ..Default::default()
    };

    Ok((config, Arc::from(crypto_provider)))
}

/// Parse an ostrich-crypto enum (KeyType/Algorithm) from its serde string form.
fn parse_crypto_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("'{}': {}", s, e))
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
