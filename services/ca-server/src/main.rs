//! OstrichPKI Certificate Authority Server
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
//! - NIST 800-53: AU-2 (Audit Events)
//! - NIAP PP-CA: FCS_CKM.1 (Cryptographic Key Generation)

mod expiry_producer;

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

    /// Public, externally-reachable URL of the CRL distribution point.
    /// When set, it is embedded into the CRL Distribution Points extension of
    /// every issued certificate (RFC 5280 §4.2.1.13) so relying parties can
    /// fetch revocation status. This MUST be the URL of the public GET CRL
    /// endpoint, e.g. https://ca.example.com/api/v1/crl
    /// NIST 800-53: SC-17 - PKI certificate status distribution
    #[arg(long, env = "CA_CRL_URL")]
    crl_distribution_url: Option<String>,

    /// Public URL of the delta CRL distribution point (RFC 5280 §5.2.6). When
    /// set, full CRLs carry a Freshest CRL extension pointing here so relying
    /// parties can discover delta CRLs (served at GET /api/v1/crl/delta).
    #[arg(long, env = "CA_DELTA_CRL_URL")]
    delta_crl_url: Option<String>,

    /// Public OCSP responder URL embedded into the Authority Information Access
    /// extension of every issued certificate (RFC 5280 §4.2.2.1 / RFC 6960) so
    /// relying parties can discover the OCSP responder for revocation checking.
    /// e.g. http://ocsp.example.com
    /// NIST 800-53: SC-17 - PKI certificate status distribution
    #[arg(long, env = "CA_OCSP_URL")]
    ocsp_responder_url: Option<String>,

    /// Public CA Issuers URL embedded into the Authority Information Access
    /// extension of every issued certificate (RFC 5280 §4.2.2.1, id-ad-caIssuers)
    /// so relying parties can fetch the issuing CA certificate for chain building.
    /// e.g. http://ca.example.com/api/v1/ca-certificate
    #[arg(long, env = "CA_ISSUERS_URL")]
    ca_issuers_url: Option<String>,

    /// Require a CSR (proof-of-possession) for end-entity issuance (RFC 2986 /
    /// NIST 800-53 SI-10). Enabled by default; disable only for trusted internal
    /// flows that issue against a bare public key.
    #[arg(long, env = "CA_REQUIRE_POP", default_value = "true")]
    require_proof_of_possession: bool,

    /// Require an approved request for every issuance (NIAP FDP_CER_EXT.3).
    /// Set to false for automated pipelines (e.g. ACME, dev/E2E) where
    /// challenge validation serves as the approval.
    #[arg(long, env = "CA_REQUIRE_APPROVAL", default_value = "true")]
    require_approval: bool,

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

    /// Comma-separated RFC 4514 subject DNs of trusted reverse proxies (the NPE
    /// portal's service certificate). When set, the CA accepts the proxy's
    /// mTLS-forwarded X-Npe-* identity headers in addition to bearer tokens (the
    /// identity bridge), and the client-cert verifier is set to optional so
    /// bearer clients without a certificate still connect. Requires
    /// --tls-client-ca to be the CA that issues the portal's certificate.
    /// NIST 800-53: IA-2 / AC-3 / AC-17
    #[arg(long, env = "CA_TRUSTED_PROXY_SUBJECTS", value_delimiter = ',')]
    trusted_proxy_subjects: Vec<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Enable JSON logging format
    #[arg(long, env = "LOG_JSON", default_value = "false")]
    log_json: bool,

    // --- Expiry-notification producer (publishes to the notify-service) ---
    /// Enable the certificate-expiry notification producer.
    #[arg(long, env = "NOTIFY_ENABLED", default_value = "false")]
    notify_enabled: bool,
    /// NATS server URL the producer publishes schedules to.
    #[arg(long, env = "NATS_URL", default_value = "nats://nats:4222")]
    nats_url: String,
    /// PEM file of the CA that signed the NATS server certificate. When set, the
    /// producer requires TLS and verifies the server against this root (SC-8/SC-13).
    #[arg(long, env = "NATS_CA_FILE")]
    nats_ca_file: Option<std::path::PathBuf>,
    /// NATS username for password authentication (AC-3 / IA-2). Optional.
    #[arg(long, env = "NATS_USER")]
    nats_user: Option<String>,
    /// NATS password — `Zeroizing` (SI-12), sourced from a k8s secret.
    #[arg(long, env = "NATS_PASSWORD", value_parser = nats_secret)]
    nats_password: Option<zeroize::Zeroizing<String>>,
    /// Notify when a certificate is within this many days of expiry.
    #[arg(long, env = "NOTIFY_DAYS_BEFORE", default_value = "90")]
    notify_days_before: i64,
    /// Hours between expiry scans.
    #[arg(long, env = "NOTIFY_SCAN_INTERVAL_HOURS", default_value = "24")]
    notify_scan_interval_hours: u64,
    /// Default reminder frequency (daily | weekly | monthly).
    #[arg(long, env = "NOTIFY_DEFAULT_FREQUENCY", default_value = "weekly")]
    notify_default_frequency: String,
    /// Default reminder time of day (UTC, "HH:MM:SS").
    #[arg(long, env = "NOTIFY_DEFAULT_TIME", default_value = "09:00:00Z")]
    notify_default_time: String,
    /// Default reminder weekdays.
    #[arg(
        long,
        env = "NOTIFY_DEFAULT_DAYS",
        value_delimiter = ',',
        default_value = "Monday"
    )]
    notify_default_days: Vec<String>,
}

/// clap value parser: wrap the NATS password in `Zeroizing` so it is wiped from
/// memory on drop (NIST 800-53 SI-12).
fn nats_secret(s: &str) -> Result<zeroize::Zeroizing<String>, std::convert::Infallible> {
    Ok(zeroize::Zeroizing::new(s.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logging
    // NIST 800-53: AU-2 - Audit Events
    init_logging(&args.log_level, args.log_json)?;

    // Install the process-wide rustls CryptoProvider (aws-lc-rs / FIPS) so the
    // NATS producer's optional TLS connection can build a client config. Idempotent
    // and harmless if another component already installed one. NIST 800-53: SC-13.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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

    // Certificate-expiry notification producer (opt-in): scans expiring certs and
    // publishes schedules to the notify-service over NATS. Runs detached; failures
    // never affect issuance.
    if args.notify_enabled {
        let producer_pool = db_pool.pool().clone();
        let producer_cfg = expiry_producer::ProducerConfig {
            nats_url: args.nats_url.clone(),
            nats_ca_file: args.nats_ca_file.clone(),
            nats_user: args.nats_user.clone(),
            nats_password: args.nats_password.as_ref().map(|p| p.as_str().to_owned()),
            days_before: args.notify_days_before,
            scan_interval_hours: args.notify_scan_interval_hours,
            default_frequency: args.notify_default_frequency.clone(),
            default_time: args.notify_default_time.clone(),
            default_days: args.notify_default_days.clone(),
        };
        tokio::spawn(expiry_producer::run(producer_pool, producer_cfg));
    }

    // Backfill the FQDN (SAN/CN) index for certificates issued before it existed.
    // Idempotent and cheap once populated (a single anti-join returning no rows);
    // new certificates are indexed transactionally at issuance. RFC 5280 §4.2.1.6.
    match ostrich_db::repository::CertificateRepository::new(db_pool.clone())
        .backfill_sans()
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(certificates = n, "backfilled FQDN (SAN/CN) index"),
        Err(e) => tracing::warn!(error = %e, "FQDN SAN index backfill failed (non-fatal)"),
    }

    // Bootstrap the Certificate Authority from the database.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-12 - CA key loaded by reference from the crypto provider
    // - NIAP PP-CA: FCS_STG_EXT.1 - CertificateAuthority::new validates the
    //   signing key is HSM-backed; software keys are rejected
    // - NIAP PP-CA: FMT_SMF.1 - CA initialization is a security management function
    let ca = bootstrap_ca(&args, &db_pool).await?;

    // Authentication: database-backed password provider (argon2id) with
    // failed-attempt lockout and bearer-token sessions. The users table is
    // provisioned via `ostrich-init --admin-username/--admin-password`.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: IA-2 (Identification and Authentication)
    // - NIST 800-53: IA-5(1) (Password-based Authentication, Argon2id)
    // - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - lockout
    // - NIAP PP-CA: FIA_UAU.1 / FIA_AFL.1
    //
    // Sessions are persisted in Postgres (DbSessionStore): they survive a
    // restart and are shared across instances, with the database as the single
    // source of truth (NIST 800-53: SC-23, AC-12).
    let session_manager = Arc::new(
        ostrich_common::auth::SessionManager::with_store(
            {
                // Max concurrent sessions per user. Defaults to the secure
                // SessionConfig default; CA_MAX_CONCURRENT_SESSIONS raises it
                // for dev/UI testing (a single admin opening several tabs or
                // re-logging-in would otherwise exhaust the default quota).
                let cfg = ostrich_common::auth::SessionConfig::default();
                match std::env::var("CA_MAX_CONCURRENT_SESSIONS")
                    .ok()
                    .and_then(|v| v.parse::<u32>().ok())
                {
                    Some(n) => cfg.with_max_concurrent(n),
                    None => cfg,
                }
            },
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

    // Identity bridge: if trusted-proxy subjects are configured, the CA accepts
    // the NPE portal's mTLS-forwarded identity. Requires a client CA so the
    // handshake can verify the portal certificate.
    let trusted_proxy = if args.trusted_proxy_subjects.is_empty() {
        None
    } else {
        if args.tls_client_ca.is_none() {
            anyhow::bail!(
                "CA_TRUSTED_PROXY_SUBJECTS is set but no --tls-client-ca is configured; \
                 the portal certificate cannot be verified (NIST 800-53: IA-2)"
            );
        }
        tracing::info!(
            subjects = ?args.trusted_proxy_subjects,
            "Identity bridge enabled: trusting NPE portal mTLS-forwarded identity"
        );
        Some(Arc::new(ostrich_common::auth::TrustedProxyConfig::new(
            args.trusted_proxy_subjects.clone(),
        )))
    };

    let app = match &ca {
        Some(ca) => {
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
                auth_provider.clone(),
                rbac_policy,
                approval_engine,
                approval_repo,
                db_pool.clone(),
                trusted_proxy.clone(),
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

    // Session API (login/logout). Public by necessity; brute-force is
    // mitigated by the provider's lockout (AC-7 / FIA_AFL.1).
    let app = app.merge(ostrich_common::auth::auth_routes(auth_provider));

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
    )?
    // With the identity bridge on, request (but don't require) a client cert:
    // the portal presents one and takes the trusted-proxy path, while bearer
    // clients (admin console) present none and still complete the handshake.
    .map(|s| s.with_optional_client_auth(trusted_proxy.is_some()));
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
        request_id: None,
        created_at: ca_cert_row.created_at,
        updated_at: ca_cert_row.updated_at,
    };

    // AU-10 (Non-repudiation): CertificateAuthority::new constructs SIGNED audit
    // sinks internally, signing each record's event_hash with this CA key (the
    // key + provider are shared there via Arc). The SHA-256 hash chain alone is
    // not tamper-evident against an attacker with DB write access; signing closes
    // that gap. Relying parties verify with the CA certificate's public key via
    // DatabaseAuditSink::verify_signed_chain. See migrations/00007_audit_signature.sql.
    let mut ca = ostrich_ca::CertificateAuthority::new(
        ca_certificate,
        key_handle,
        crypto_provider,
        db_pool.clone(),
        args.crl_validity_hours,
    )
    .context("CertificateAuthority initialization failed")?;

    // Register the default certificate profiles.
    // NIAP PP-CA: FDP_IFC.1 - issuance policy definitions
    // POAM: profiles should be loaded from the certificate_profiles table
    // (CM-2: configuration as data) instead of code defaults.
    for profile in default_profiles() {
        tracing::info!(profile = %profile.name, "Registering certificate profile");
        ca.add_profile(profile);
    }

    // Approval workflow toggle.
    // NIAP PP-CA: FDP_CER_EXT.3 - approval-required is the secure default.
    // When enabled, the issuer must hold the approval engine + repository so it
    // can verify the referenced request is Approved before issuing (otherwise
    // issuance fails closed with "Approval repository not configured").
    let approval_config = ostrich_ca::approval::ApprovalConfig {
        require_approval: args.require_approval,
        ..Default::default()
    };
    if args.require_approval {
        let approval_engine =
            std::sync::Arc::new(ostrich_ca::ApprovalEngine::new(approval_config.clone()));
        let approval_repo = std::sync::Arc::new(ostrich_db::repository::ApprovalRepository::new(
            db_pool.pool().clone(),
        ));
        ca.set_approval(approval_engine, approval_repo, approval_config);
    } else {
        tracing::warn!(
            "CA_REQUIRE_APPROVAL=false: certificates are issued WITHOUT an approval \
             workflow. Acceptable for automated pipelines (ACME) and dev/E2E only."
        );
        ca.set_approval_config(approval_config);
    }

    // RFC 5280 §4.2.1.13 - embed the public CRL distribution point into issued
    // certificates so relying parties can fetch revocation status. Must be the
    // externally-reachable URL of the public GET CRL endpoint
    // (e.g. https://ca.example.com/api/v1/crl).
    // NIST 800-53: SC-17 - PKI certificate status distribution.
    if let Some(crl_url) = &args.crl_distribution_url {
        tracing::info!(crl_url = %crl_url, "Embedding CRL Distribution Point in issued certificates");
        ca.set_crl_distribution_url(crl_url.clone());
    } else {
        tracing::warn!(
            "CA_CRL_URL not set: issued certificates will NOT carry a CRL \
             Distribution Points extension (RFC 5280 §4.2.1.13)."
        );
    }

    // Delta CRL distribution point (RFC 5280 §5.2.6): full CRLs gain a Freshest
    // CRL pointer so relying parties can discover delta CRLs.
    if let Some(delta_url) = &args.delta_crl_url {
        tracing::info!(delta_url = %delta_url, "Full CRLs will carry a Freshest CRL pointer to the delta CRL");
        ca.set_delta_crl_url(delta_url.clone());
    }

    // Authority Information Access (RFC 5280 §4.2.2.1 / RFC 6960): embed the
    // OCSP responder and CA Issuers URLs so relying parties can discover the
    // OCSP responder and fetch the issuing CA certificate.
    // NIST 800-53: SC-17 - PKI certificate status distribution.
    if let Some(ocsp_url) = &args.ocsp_responder_url {
        tracing::info!(ocsp_url = %ocsp_url, "Embedding AIA OCSP responder URL in issued certificates");
        ca.set_ocsp_responder_url(ocsp_url.clone());
    } else {
        tracing::warn!(
            "CA_OCSP_URL not set: issued certificates will NOT carry an AIA OCSP \
             accessDescription (RFC 5280 §4.2.2.1); relying parties cannot \
             auto-discover the OCSP responder."
        );
    }
    if let Some(ca_issuers_url) = &args.ca_issuers_url {
        tracing::info!(ca_issuers_url = %ca_issuers_url, "Embedding AIA CA Issuers URL in issued certificates");
        ca.set_ca_issuers_url(ca_issuers_url.clone());
    }

    // Proof-of-possession policy (RFC 2986 / SI-10). Secure default: required.
    ca.set_require_proof_of_possession(args.require_proof_of_possession);
    if !args.require_proof_of_possession {
        tracing::warn!(
            "CA_REQUIRE_POP=false: end-entity certificates may be issued against a \
             bare public key without proof-of-possession (not recommended)."
        );
    }

    tracing::info!(
        ca_id = %ca_cert_row.id,
        subject = %ca_cert_row.subject_dn,
        is_root = ca_cert_row.is_root,
        "Certificate Authority initialized"
    );

    Ok(Some(Arc::new(ca)))
}

/// Default certificate profiles registered at startup.
///
/// Names are the API-facing identifiers used by clients (REST/gRPC
/// `profile_name`, ACME's issuance path, the E2E test suite).
///
/// COMPLIANCE MAPPING:
/// - NIAP PP-CA: FDP_IFC.1 - certificate issuance policy definitions
/// - RFC 5280 §4.2.1.3/§4.2.1.12 - key usage / extended key usage per profile
/// - CA/Browser Forum BR §6.3.2 - 398-day max for TLS server certificates
fn default_profiles() -> Vec<ostrich_x509::CertificateProfile> {
    use ostrich_x509::{CertificateProfile, ExtendedKeyUsage};

    // RFC 6125 / CABF: server certs need SANs, ≤398 days
    let mut tls_server = CertificateProfile::tls_server(397);
    tls_server.name = "tls_server".to_string();
    tls_server.description = Some("TLS server authentication (serverAuth)".to_string());

    let mut tls_client = CertificateProfile::tls_client(365);
    tls_client.name = "tls_client".to_string();
    tls_client.description = Some("TLS client authentication (clientAuth)".to_string());

    // Combined server + client auth (mutual-TLS endpoints, EST-enrolled devices
    // that act as both client and server). serverAuth + clientAuth EKU.
    let mut tls_server_client =
        CertificateProfile::tls_server(397).with_extended_key_usage(ExtendedKeyUsage::ClientAuth);
    tls_server_client.name = "tls_server_client".to_string();
    tls_server_client.description =
        Some("TLS server + client authentication (serverAuth + clientAuth)".to_string());

    // ACME-issued certificates: short-lived, server auth, SAN required
    // (RFC 8555 identifiers become SANs)
    let mut acme_default = CertificateProfile::tls_server(90);
    acme_default.name = "acme-default".to_string();
    acme_default.description = Some("ACME-issued TLS server certificates (RFC 8555)".to_string());

    // EFS (Encrypting File System): server-side key generation delivered as an
    // encrypted PKCS#12. RSA, Microsoft EFS EKU (1.3.6.1.4.1.311.10.3.4).
    let mut efs = CertificateProfile::efs(730);
    efs.name = "efs".to_string();
    efs.description = Some("Microsoft EFS, server-side key generation".to_string());

    // Subordinate (intermediate) CA issuance via gRPC: CA=true, keyCertSign +
    // cRLSign, pathLenConstraint 0 (RFC 5280 §4.2.1.9), ~5 year validity.
    // NIAP PP-CA: FMT_SMF.1 - CA hierarchy management.
    let mut intermediate_ca = CertificateProfile::intermediate_ca(1825, 0);
    intermediate_ca.name = "intermediate_ca".to_string();
    intermediate_ca.description =
        Some("Subordinate CA certificates (RFC 5280 §4.2.1.9)".to_string());

    vec![
        tls_server,
        tls_client,
        tls_server_client,
        acme_default,
        efs,
        intermediate_ca,
    ]
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
