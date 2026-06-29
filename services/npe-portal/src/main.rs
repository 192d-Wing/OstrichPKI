//! OstrichPKI NPE (Non-Person Entity) Enrollment Portal
//!
//! A standalone NPE portal: an Axum BFF that serves the
//! React/Cloudscape console (built separately under `web/` with Vite) and
//! proxies an allowlisted set of CA/EST routes. Unlike the admin web-ui, the
//! portal authenticates operators **passwordlessly via mTLS**: the verified
//! client certificate's OIDs are mapped to one of four NPE roles
//! (PKI Sponsor / Administrator / Registration Authority / CA Admin).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-2 (Identification & Authentication) - mTLS client cert
//! - NIST 800-53: IA-5(2) (PKI-Based Authentication)
//! - NIST 800-53: AC-3 (Access Enforcement) - OID-derived role + proxy allowlist
//! - NIST 800-53: AC-12 (Session Termination) - 30-minute inactivity timeout
//! - NIST 800-53: SC-8 (Transmission Confidentiality) - TLS 1.3 / mTLS
//! - NIAP PP-CA: FIA_UAU.1, FIA_X509_EXT.1/.2, FTA_SSL.1/FTA_SSL.3

mod server;

use anyhow::Result;
use clap::Parser;
use server::{config::NpePortalConfig, router::create_router};
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI NPE Portal Server
#[derive(Parser, Debug)]
#[command(name = "ostrich-npe-portal")]
#[command(about = "OstrichPKI Non-Person Entity Enrollment Portal")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/npe-portal.json")]
    config: String,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:8443", env = "NPE_BIND_ADDRESS")]
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

    /// Client CA bundle (PEM). REQUIRED for the portal's mandatory mTLS: every
    /// human authenticates with a client certificate that must chain to one of
    /// these CAs. NIST 800-53: IA-2, AC-17; NIAP FIA_X509_EXT.1
    #[arg(long, env = "TLS_CLIENT_CA_FILE")]
    tls_client_ca: Option<String>,

    /// Development-only escape hatch: permit startup WITHOUT mandatory mTLS
    /// (server cert/key + client CA). Without this flag the service fails closed
    /// and refuses to start unless full mTLS is configured (NIST 800-53: CM-6
    /// secure defaults, fail secure). Never set in production.
    #[arg(long, env = "NPE_ALLOW_INSECURE")]
    allow_insecure: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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
        service = "ostrich-npe-portal",
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI NPE Portal"
    );

    // Install the process-wide default rustls CryptoProvider (aws-lc-rs / FIPS).
    // ostrich_common::tls and the portal's own server config select the provider
    // explicitly, but the embedded ACME client (instant-acme) builds its HTTPS
    // client from the *process default*, which rustls cannot auto-select when
    // both aws-lc-rs and ring appear in the dependency graph. Idempotent: returns
    // Err if already installed, which we ignore. NIST 800-53: SC-13 (FIPS).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = NpePortalConfig::load(&args.config).await?;

    // ACME mode: the portal sources its server certificate from an ACME directory
    // (auto-enroll + auto-renew) instead of a static --tls-cert/--tls-key. The
    // server key never touches disk-as-config; mTLS client auth is still
    // mandatory, so a client CA bundle is required even in ACME mode.
    let acme_cfg = config.acme.clone();

    // Fail closed: mTLS is the portal's only human-auth path, so the service
    // refuses to start unless full mTLS (server cert + key + client CA) is
    // configured. The OID->role mapping cannot run without a verified client
    // certificate, and serving plain HTTP would expose an unauthenticated
    // portal. The --allow-insecure flag is the only way to bypass this, for
    // local development. NIST 800-53: IA-2, AC-17, CM-6 (fail secure).
    let mtls_ready = if acme_cfg.is_some() {
        // Server cert comes from ACME; client CA is still required for mTLS.
        args.tls_client_ca.is_some()
    } else {
        args.tls_cert.is_some() && args.tls_key.is_some() && args.tls_client_ca.is_some()
    };
    if !mtls_ready && !args.allow_insecure {
        anyhow::bail!(
            "refusing to start without mandatory mTLS: set --tls-cert, --tls-key, and \
             --tls-client-ca (TLS_CERT_FILE/TLS_KEY_FILE/TLS_CLIENT_CA_FILE), or pass \
             --allow-insecure for development only (NIST 800-53: IA-2, CM-6)"
        );
    }
    if !mtls_ready {
        tracing::warn!(
            "--allow-insecure set: mandatory mTLS is not enforced. Operators cannot be \
             authenticated by client certificate; this is for development only."
        );
    }

    let app = create_router(config).await?;
    let addr: SocketAddr = args.listen.parse()?;
    info!(%addr, "NPE Portal server listening");

    match acme_cfg {
        // ACME mode: enroll + serve mTLS with an auto-renewing server certificate.
        Some(acme) => {
            let client_ca = args.tls_client_ca.ok_or_else(|| {
                anyhow::anyhow!(
                    "ACME is configured but no client CA bundle was provided; mTLS client \
                     authentication is mandatory: set --tls-client-ca (TLS_CLIENT_CA_FILE)"
                )
            })?;
            serve_with_acme(addr, app, acme, &client_ca).await?;
        }
        // Static mode: serve HTTPS from a fixed --tls-cert/--tls-key (or plain
        // HTTP under --allow-insecure). NIST 800-53: SC-8.
        None => {
            let tls = ostrich_common::tls::TlsSettings::from_options(
                args.tls_cert,
                args.tls_key,
                args.tls_client_ca,
            )?;
            ostrich_common::tls::serve(addr, app, tls.as_ref(), shutdown_signal()).await?;
        }
    }

    info!("NPE Portal server shutdown complete");
    Ok(())
}

/// Serve the portal over mTLS using an ACME-issued, auto-renewing server
/// certificate. Spawns the HTTP-01 challenge responder, blocks until the initial
/// certificate is enrolled (so readiness is meaningful), then serves with a
/// dynamic resolver while a background task renews ahead of expiry.
///
/// NIST 800-53: SC-8 (TLS 1.3), SC-12 (automated key/cert rotation), IA-2/AC-17
/// (mandatory mTLS client authentication).
async fn serve_with_acme(
    addr: SocketAddr,
    app: axum::Router,
    acme: server::config::AcmeConfig,
    client_ca_path: &str,
) -> Result<()> {
    use server::acme::{
        AcmeCertResolver, acquire_on_startup, bind_challenge_responder, build_mtls_server_config,
        new_challenge_store, renewal_loop, run_challenge_responder,
    };

    let resolver = std::sync::Arc::new(AcmeCertResolver::new());
    let store = new_challenge_store();

    // Bind the challenge port up front so a bind failure (port in use, or no
    // privilege to bind :80) is fatal here rather than a silently-stalled
    // enrollment. The responder then runs detached for the life of the process,
    // serving HTTP-01 key authorizations for both initial enrollment and renewal.
    let listener = bind_challenge_responder(acme.challenge_port).await?;
    let challenge_store = store.clone();
    tokio::spawn(async move {
        if let Err(e) = run_challenge_responder(listener, challenge_store).await {
            tracing::error!(error = %e, "ACME challenge responder exited");
        }
    });

    // Block on the initial enrollment so the listener only comes up once it can
    // present a certificate.
    let not_after = acquire_on_startup(&acme, &store, &resolver).await?;

    // Build the mTLS server config bound to the dynamic resolver, then spawn the
    // background renewal task (swaps the cert in place — no restart).
    let server_config = std::sync::Arc::new(build_mtls_server_config(client_ca_path, resolver.clone())?);
    tokio::spawn(renewal_loop(acme, store, resolver, not_after));

    info!(%addr, "Serving HTTPS (TLS 1.3, mTLS) with ACME-managed certificate");
    ostrich_common::tls::serve_with_config(addr, app, server_config, shutdown_signal()).await?;
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
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
        _ = ctrl_c => info!("Received Ctrl+C, initiating graceful shutdown"),
        _ = terminate => info!("Received SIGTERM, initiating graceful shutdown"),
    }
}
