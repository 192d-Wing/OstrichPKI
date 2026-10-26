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

    // --- gRPC issuance listener: mandatory mTLS (TLS 1.3, aws-lc-rs FIPS) ---
    /// gRPC server certificate chain (PEM, leaf first). Its SAN must include
    /// the name clients dial (e.g. ca-service). NIST 800-53: SC-8, AC-17.
    #[arg(long = "grpc-tls-cert", env = "CA_GRPC_TLS_CERT_FILE")]
    grpc_tls_cert: Option<String>,

    /// gRPC server private key (PEM: PKCS#8, SEC1 or PKCS#1).
    #[arg(long = "grpc-tls-key", env = "CA_GRPC_TLS_KEY_FILE")]
    grpc_tls_key: Option<String>,

    /// Trust anchors (PEM) for gRPC client certificates. Required: every gRPC
    /// client must present a certificate chaining to one of these.
    /// NIST 800-53: IA-3, IA-9, IA-5(2).
    #[arg(long = "grpc-tls-client-ca", env = "CA_GRPC_TLS_CLIENT_CA_FILE")]
    grpc_tls_client_ca: Option<String>,

    /// `;`-separated RFC 4514 subject DNs (commas separate RDNs) of
    /// acme-server identities: role `Issuer` (IssueCertificate, GetCaInfo,
    /// ListProfiles), requestor namespace `acme::`. An empty value means none.
    /// NIST 800-53: AC-3, AC-6.
    #[arg(
        long = "grpc-acme-client-subjects",
        env = "CA_GRPC_ACME_CLIENT_SUBJECTS",
        value_delimiter = ';'
    )]
    grpc_acme_client_subjects: Vec<String>,

    /// `;`-separated subject DNs of est-server identities: role `Issuer`,
    /// requestor namespace `est::`. With the ACME list empty too, the CA
    /// refuses to start. NIST 800-53: AC-3, AC-6.
    #[arg(
        long = "grpc-est-client-subjects",
        env = "CA_GRPC_EST_CLIENT_SUBJECTS",
        value_delimiter = ';'
    )]
    grpc_est_client_subjects: Vec<String>,

    /// `;`-separated subject DNs of operator identities: role `Admin`
    /// (RevokeCertificate, GenerateCrl, CheckRevocationStatus, GetCaInfo,
    /// ListProfiles; never IssueCertificate), requestor namespace `admin::`.
    /// Empty by default: nobody may revoke over gRPC. A subject may be in
    /// one list only. NIST 800-53: AC-5, AC-6, CM-6.
    #[arg(
        long = "grpc-admin-client-subjects",
        env = "CA_GRPC_ADMIN_CLIENT_SUBJECTS",
        value_delimiter = ';'
    )]
    grpc_admin_client_subjects: Vec<String>,

    /// `;`-separated certificate profiles the `acme::` namespace may request
    /// over gRPC (exact names). Must name registered end-entity profiles; a
    /// CA profile (e.g. `intermediate_ca`) or an unknown name refuses startup,
    /// and so does an empty list while ACME subjects are configured.
    /// NIST 800-53: AC-6(10), CM-6, CM-7.
    #[arg(
        long = "grpc-acme-allowed-profiles",
        env = "CA_GRPC_ACME_ALLOWED_PROFILES",
        value_delimiter = ';',
        default_value = "acme-default"
    )]
    grpc_acme_allowed_profiles: Vec<String>,

    /// `;`-separated certificate profiles the `est::` namespace may request
    /// over gRPC. Same rules as `--grpc-acme-allowed-profiles`.
    /// NIST 800-53: AC-6(10), CM-6, CM-7.
    #[arg(
        long = "grpc-est-allowed-profiles",
        env = "CA_GRPC_EST_ALLOWED_PROFILES",
        value_delimiter = ';',
        default_value = "tls_client;tls_server;tls_server_client;efs"
    )]
    grpc_est_allowed_profiles: Vec<String>,

    /// Removed single allowlist; setting it refuses startup with a migration
    /// message naming the three role variables (CM-6).
    #[arg(
        long = "grpc-allowed-client-subjects",
        env = "CA_GRPC_ALLOWED_CLIENT_SUBJECTS",
        value_delimiter = ';',
        hide = true
    )]
    grpc_allowed_client_subjects: Vec<String>,

    /// DEVELOPMENT ONLY: serve gRPC as plaintext HTTP/2 with no client
    /// authentication. Honoured only in debug builds; setting it in a release
    /// build is a startup error. NIST 800-53: CM-6.
    #[arg(
        long = "grpc-insecure-dev-plaintext",
        env = "CA_GRPC_INSECURE_DEV_PLAINTEXT",
        default_value = "false"
    )]
    grpc_insecure_dev_plaintext: bool,

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

    // Process-level FIPS gate, before any database, NATS, gRPC or HTTPS work:
    // asserts AWS-LC FIPS mode and installs the aws-lc-rs FIPS provider as the
    // process default (the NATS producer's optional TLS client builds its config
    // from it). NIST 800-53: SC-13, SC-24.
    // NIAP PP-CA: supports FPT_TST_EXT.1; FPT_FLS.1.
    ostrich_common::tls::fips_gate()?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI CA Server"
    );

    // Resolve the gRPC listener mode now, before the database connects and
    // whether or not a CA is registered, so a missing or partial gRPC mTLS
    // configuration always stops the process (fail closed). The plaintext dev
    // flag is refused in release builds.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: CM-6 (secure defaults), SC-24 (fail in known state), AC-17
    // - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.2, FPT_FLS.1
    let grpc_addr: SocketAddr = args
        .grpc_address
        .parse()
        .context("Invalid gRPC bind address")?;
    let grpc_mode = grpc_server_options(&args)
        .resolve(!cfg!(debug_assertions))
        .context("CA gRPC listener configuration rejected")?;
    // SEC-001 / SEC-102: per-namespace issuance profile allowlists, validated
    // against the profiles this CA registers: `ca_profiles` is the one list
    // both validated here and registered on the CA in `bootstrap_ca`, so the
    // two cannot drift (fail closed, before the database). `issue()` also
    // refuses CA profiles to every gRPC caller at call time.
    // NIST 800-53: AC-6(10), CM-6, CM-7, SC-24; NIAP PP-CA: FDP_ACF.1, FMT_MTD.1
    let ca_profiles = default_profiles();
    let issuer_profiles = Arc::new(
        grpc_issuer_profiles(&args, &grpc_mode, &ca_profiles)
            .context("CA gRPC listener configuration rejected")?,
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
    let (ca, ca_lineage) = match bootstrap_ca(&args, &db_pool, &ca_profiles).await? {
        Some((ca, lineage)) => (Some(ca), Some(lineage)),
        None => (None, None),
    };
    // The CA gRPC server task, awaited before exit so its final audit flush
    // (suppressed-record summaries) is written (AU-2; SEC-012).
    let mut grpc_server: Option<tokio::task::JoinHandle<()>> = None;
    // Stops the gRPC server when the REST server exits for any reason
    // (signal or error), so the bounded wait below is meaningful (SEC-015).
    let (grpc_stop_tx, grpc_stop_rx) = tokio::sync::watch::channel(false);

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

    let app = match (&ca, ca_lineage) {
        (Some(ca), Some(lineage)) => {
            let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

            // Approval workflow (NIAP PP-CA FDP_CER_EXT.3: issuance requires approval)
            let approval_engine = Arc::new(ostrich_ca::ApprovalEngine::new(
                ostrich_ca::approval::ApprovalConfig::default(),
            ));
            let approval_repo = Arc::new(ostrich_db::repository::ApprovalRepository::new(
                db_pool.pool().clone(),
            ));

            // gRPC service for inter-service issuance (ACME/EST). The client
            // CA must not be in this CA's own chain (issuing CA, its
            // ancestors from the database, or CAs it issued): trust-anchor
            // separation. A refusal is audited, then stops the process.
            //
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AC-3, IA-3, SC-24, AU-2 (refusal recorded)
            // - NIAP PP-CA: FIA_X509_EXT.1, FDP_ACF.1, FPT_FLS.1, FAU_GEN.1
            let grpc_audit: Arc<dyn ostrich_audit::AuditSink> =
                Arc::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone()));
            let ca_repo = ostrich_db::repository::CaRepository::new(db_pool.clone());
            let ancestors = check_grpc_trust_anchors(
                &grpc_mode,
                ca.certificate_der(),
                &lineage,
                |id| {
                    let repo = &ca_repo;
                    async move {
                        Ok(repo.find_ca_certificate(id).await?.map(|row| CaChainLink {
                            parent_ca_id: row.parent_ca_id,
                            der: row.der_encoded,
                        }))
                    }
                },
                grpc_audit.as_ref(),
            )
            .await
            .context("CA gRPC listener configuration rejected")?;
            // Runtime defence in depth: leaves issued by this CA or its
            // ancestors are refused per call (`subscriber_issuing_ca`).
            let mut subscriber_cas: Vec<&[u8]> = vec![ca.certificate_der()];
            subscriber_cas.extend(ancestors.iter().map(Vec::as_slice));
            // SC-24: the service is built from the listener mode, so the mTLS
            // service always refuses calls without a verified peer; only the
            // debug plaintext listener skips requestor binding.
            let grpc_service = ostrich_ca::CaGrpcService::for_mode(
                &grpc_mode,
                ca.clone(),
                issuer_profiles.clone(),
            );
            let (_, task) = start_grpc_listener(
                grpc_mode,
                grpc_addr,
                grpc_service,
                issuer_profiles.summary(),
                grpc_audit,
                &subscriber_cas,
                grpc_shutdown(grpc_stop_rx),
            )
            .await?;
            grpc_server = Some(task);

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
        _ => {
            tracing::warn!(
                "No CA certificate registered in the database - running in health-check \
                 only mode. Register a CA (ca_keys + ca_certificates) and set \
                 CA_CERTIFICATE_ID to enable issuance."
            );
            tracing::info!(
                mode = ?grpc_mode,
                "gRPC listener configuration validated; listener not started (no CA)"
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
    let rest_result =
        ostrich_common::tls::serve(rest_addr, app, tls.as_ref(), shutdown_signal()).await;
    if let Err(e) = &rest_result {
        tracing::error!(error = %e, "REST server failed; stopping the CA gRPC server");
    }

    // SEC-012 / SEC-015: whether REST stopped on a signal or an error, stop
    // the gRPC server and wait (bounded) for it to flush its suppressed-record
    // summaries before returning (and before propagating a REST error).
    let _ = grpc_stop_tx.send(true);
    if let Some(task) = grpc_server {
        match tokio::time::timeout(GRPC_SHUTDOWN_GRACE, task).await {
            Ok(Ok(())) => tracing::info!("CA gRPC server stopped"),
            Ok(Err(e)) => tracing::error!(error = %e, "CA gRPC server task failed"),
            Err(_) => tracing::warn!(
                grace_secs = GRPC_SHUTDOWN_GRACE.as_secs(),
                "CA gRPC server did not stop within the shutdown grace period; \
                 final audit summaries may be missing (AU-5)"
            ),
        }
    }

    rest_result?;
    tracing::info!("CA Server shutdown complete");
    Ok(())
}

/// Shutdown future for the CA gRPC server: a process signal, or `stop`
/// turning true / its sender being dropped (the REST server exited).
async fn grpc_shutdown(mut stop: tokio::sync::watch::Receiver<bool>) {
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = stop.wait_for(|stopped| *stopped) => {
            tracing::info!("REST server exited; initiating gRPC shutdown");
        }
    }
}

/// Name of the CA gRPC listener in logs and audit records.
const GRPC_LISTENER: &str = "ca-grpc";

/// How long `main` waits for the gRPC server (and its final audit flush) after
/// the REST server has stopped.
const GRPC_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum CA hierarchy depth walked from the issuing CA towards its root.
const MAX_CA_ANCESTOR_DEPTH: usize = 16;

/// Identity of the issuing CA row in `ca_certificates` (for the ancestor walk).
#[derive(Debug, Clone, Copy)]
struct CaLineage {
    id: uuid::Uuid,
    parent_ca_id: Option<uuid::Uuid>,
}

/// One `ca_certificates` row in the ancestor walk.
struct CaChainLink {
    parent_ca_id: Option<uuid::Uuid>,
    der: Vec<u8>,
}

/// The issuing CA's ancestors (DER, parent first, up to the root) following
/// `ca_certificates.parent_ca_id`. `lookup` loads one row. Fails closed on a
/// missing parent row, a cycle, or a chain deeper than
/// [`MAX_CA_ANCESTOR_DEPTH`]; a row that names itself as parent ends the walk
/// (root).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, IA-3 (trust-anchor separation input), SC-24
/// - NIAP PP-CA: FIA_X509_EXT.1
/// - RFC 5280 §6.1 (certification path / trust anchor)
async fn walk_ca_ancestors<F, Fut>(lineage: &CaLineage, mut lookup: F) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(uuid::Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<Option<CaChainLink>>>,
{
    let mut seen = std::collections::HashSet::from([lineage.id]);
    let mut current = lineage.id;
    let mut next = lineage.parent_ca_id;
    let mut ancestors = Vec::new();
    while let Some(id) = next {
        if id == current {
            break;
        }
        if !seen.insert(id) {
            anyhow::bail!("CA hierarchy in ca_certificates has a cycle at {id}");
        }
        if ancestors.len() >= MAX_CA_ANCESTOR_DEPTH {
            anyhow::bail!(
                "CA hierarchy in ca_certificates is deeper than {MAX_CA_ANCESTOR_DEPTH} levels"
            );
        }
        let link = lookup(id)
            .await?
            .with_context(|| format!("parent CA certificate {id} not found in ca_certificates"))?;
        ancestors.push(link.der);
        next = link.parent_ca_id;
        current = id;
    }
    Ok(ancestors)
}

/// Build the gRPC listener options from CLI/env. An empty value (e.g. an
/// unset `${VAR:-}` in compose, or `CA_GRPC_ADMIN_CLIENT_SUBJECTS=""`) counts
/// as not configured, and blank subject entries (a trailing `;`) are dropped;
/// an all-blank role list means "no subjects". The resolver still refuses to
/// start with neither an ACME nor an EST subject (fail closed).
fn grpc_server_options(args: &Args) -> ostrich_common::GrpcServerOptions {
    let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());
    let subjects = |list: &[String]| -> Vec<String> {
        list.iter()
            // ASCII padding only: an entry of Unicode whitespace (e.g. NBSP)
            // is passed on and rejected by the subject parser (RFC-015).
            .filter(|s| !s.trim_matches([' ', '\t', '\r', '\n']).is_empty())
            .cloned()
            .collect()
    };
    ostrich_common::GrpcServerOptions {
        cert_path: non_empty(&args.grpc_tls_cert),
        key_path: non_empty(&args.grpc_tls_key),
        client_ca_path: non_empty(&args.grpc_tls_client_ca),
        acme_subjects: subjects(&args.grpc_acme_client_subjects),
        est_subjects: subjects(&args.grpc_est_client_subjects),
        admin_subjects: subjects(&args.grpc_admin_client_subjects),
        legacy_allowed_subjects: subjects(&args.grpc_allowed_client_subjects),
        insecure_dev_plaintext: args.grpc_insecure_dev_plaintext,
    }
}

/// Parse the per-namespace issuance profile allowlists
/// (`CA_GRPC_{ACME,EST}_ALLOWED_PROFILES`) against `profiles`; an empty list
/// is refused only for a namespace that has client subjects in `mode`.
fn grpc_issuer_profiles(
    args: &Args,
    mode: &ostrich_common::GrpcServerMode,
    profiles: &[ostrich_x509::CertificateProfile],
) -> Result<ostrich_ca::grpc_authz::IssuerProfilePolicy> {
    let clients = match mode {
        ostrich_common::GrpcServerMode::Mtls { clients, .. } => Some(clients.as_ref()),
        ostrich_common::GrpcServerMode::InsecureDevPlaintext => None,
    };
    Ok(ostrich_ca::grpc_authz::IssuerProfilePolicy::parse(
        &args.grpc_acme_allowed_profiles,
        &args.grpc_est_allowed_profiles,
        clients,
        profiles,
    )?)
}

/// Load the issuing CA's ancestors (`lookup`, see [`walk_ca_ancestors`]) and
/// run [`ensure_dedicated_grpc_client_ca`] against them. On any failure a
/// `grpc_listener_refused` ConfigurationChange record (outcome Failure) is
/// written to `audit` before the error is returned. Returns the ancestors.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-3, IA-3, SC-24, AU-2 / AU-3 (refusal recorded)
/// - NIAP PP-CA: FIA_X509_EXT.1, FPT_FLS.1, FAU_GEN.1
async fn check_grpc_trust_anchors<F, Fut>(
    mode: &ostrich_common::GrpcServerMode,
    issuing_ca_der: &[u8],
    lineage: &CaLineage,
    lookup: F,
    audit: &dyn ostrich_audit::AuditSink,
) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(uuid::Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<Option<CaChainLink>>>,
{
    let checked = async {
        let ancestors = walk_ca_ancestors(lineage, lookup).await?;
        let refs: Vec<&[u8]> = ancestors.iter().map(Vec::as_slice).collect();
        ensure_dedicated_grpc_client_ca(mode, issuing_ca_der, &refs)?;
        Ok::<_, anyhow::Error>(ancestors)
    }
    .await;
    if let Err(e) = &checked {
        // The reason names configuration items only (file, certificate
        // index, CA row id); no key material.
        audit_grpc_listener(
            audit,
            ostrich_audit::EventType::ConfigurationChange,
            "grpc_listener_refused",
            ostrich_audit::EventOutcome::Failure,
            serde_json::json!({
                "check": "client_ca_trust_anchor_separation",
                "reason": format!("{e:#}"),
            }),
        )
        .await;
    }
    checked
}

/// Refuse a gRPC client-CA bundle with an anchor in this CA's own chain: the
/// issuing certificate, a CA it issued, or any of `ancestor_ders` (see
/// [`ostrich_common::grpc_tls::ensure_dedicated_client_ca`]). No-op for the
/// debug-only plaintext mode.
fn ensure_dedicated_grpc_client_ca(
    mode: &ostrich_common::GrpcServerMode,
    issuing_ca_der: &[u8],
    ancestor_ders: &[&[u8]],
) -> Result<()> {
    if let ostrich_common::GrpcServerMode::Mtls { client_anchors, .. } = mode {
        ostrich_common::grpc_tls::ensure_dedicated_client_ca(
            client_anchors,
            issuing_ca_der,
            ancestor_ders,
        )?;
    }
    Ok(())
}

/// Write a system/configuration audit record for the gRPC listener. Failure to
/// record is logged, never fatal (the listener state is also in the log).
async fn audit_grpc_listener(
    sink: &dyn ostrich_audit::AuditSink,
    event_type: ostrich_audit::EventType,
    action: &str,
    outcome: ostrich_audit::EventOutcome,
    details: serde_json::Value,
) {
    let mut record = ostrich_audit::AuditEventBuilder::new(
        event_type,
        "ca-server",
        GRPC_LISTENER,
        action,
        outcome,
    )
    .with_details(details)
    .build();
    if let Err(e) = sink.record(&mut record).await {
        tracing::warn!(error = %e, action, "failed to record gRPC listener audit event");
    }
}

/// Start the CA gRPC issuance listener in the resolved mode.
///
/// mTLS mode binds the socket before returning (a bind failure is fatal), then
/// serves `CertificateAuthorityService` behind the listener-wide
/// [`ostrich_common::SubjectAllowlistLayer`] with
/// [`ostrich_ca::grpc_authz::CA_GRPC_METHOD_RULES`]: a call reaches the
/// service only when the client subject is in a role list and the method
/// table grants that role the RPC; others get PERMISSION_DENIED and an
/// `access_denied` audit record, and failed TLS handshakes are audited as
/// `tls_handshake_failed`. The startup record lists the effective client
/// lists, method rules and per-namespace issuer profiles (CM-3).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AC-17 (mTLS inter-service), AC-3 / AC-5 / AC-6 (per-role,
///   per-method rules), CM-2 / CM-3 (effective policy audited at start),
///   SC-8 / SC-8(1) (TLS 1.3), SC-13 (aws-lc-rs FIPS, `fips()` asserted),
///   IA-3 / IA-9 / IA-5(2) (client certificate authentication), AU-2 / AU-12,
///   CM-7 (only the mapped RPCs and listed profiles), AC-6(9)
///   (RevokeCertificate and GenerateCrl audited with the verified admin
///   peer; CheckRevocationStatus is an unaudited read, NIST-102)
/// - NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.1, FCS_TLSS_EXT.2, FDP_ACC.1,
///   FDP_ACF.1, FAU_GEN.1
/// - RFC 8446 (TLS 1.3), RFC 7301 (ALPN h2), RFC 5280 §6 (client cert path validation)
// POAM: POAM-2026-10-23-27 - client-certificate revocation is not checked on
// the gRPC listener (no CRL in the WebPkiClientVerifier); FIA_X509_EXT.1.1 /
// RFC 5280 §6.3.
///
/// `audit` receives the listener lifecycle record and (through
/// `AuthAuditAdapter`) every handshake-failure and access-denial record;
/// client leaves issued by any of `subscriber_issuing_cas` (DER) are denied
/// per call; `shutdown` stops the server. Returns the bound address and the
/// server task, which finishes after the final audit flush.
async fn start_grpc_listener<S, F>(
    mode: ostrich_common::GrpcServerMode,
    grpc_addr: SocketAddr,
    service: S,
    issuer_profiles: serde_json::Value,
    audit: Arc<dyn ostrich_audit::AuditSink>,
    subscriber_issuing_cas: &[&[u8]],
    shutdown: F,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)>
where
    S: ostrich_protocol::certificate_authority_service_server::CertificateAuthorityService,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    use ostrich_protocol::certificate_authority_service_server::CertificateAuthorityServiceServer;

    let service = CertificateAuthorityServiceServer::new(service);
    match mode {
        ostrich_common::GrpcServerMode::Mtls {
            config,
            clients,
            client_anchors,
        } => {
            let methods = ostrich_ca::grpc_authz::CA_GRPC_METHOD_RULES;
            let method_rules = ostrich_common::grpc_tls::grpc_method_rules_summary(methods);
            let hook: Arc<dyn ostrich_common::auth::AuthAuditHook> =
                Arc::new(ostrich_audit::AuthAuditAdapter::new(audit.clone()));
            // SEC-203: build (and validate) the authorization layer before the
            // socket is bound and before `grpc_listener_started` is written,
            // so a rejected configuration never leaves a "started" record; the
            // refusal is audited instead.
            //
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AU-2 / AU-3 (refusal recorded), CM-6, AC-3, IA-3
            //   (fail closed at startup)
            // - NIAP PP-CA: FAU_GEN.1, FPT_FLS.1, FIA_X509_EXT.1
            let layer = match ostrich_common::SubjectAllowlistLayer::new(
                clients.clone(),
                methods,
                Some(hook.clone()),
                GRPC_LISTENER,
            )
            .with_subscriber_issuing_cas(subscriber_issuing_cas)
            // SEC-101 / SEC-201: admin leaves must be issued directly by the
            // single client trust anchor, matched by AKI = anchor SKI
            // (NIST 800-53: AC-3, IA-3; NIAP FMT_SMR.2).
            .and_then(|layer| layer.with_client_trust_anchors(&client_anchors))
            {
                Ok(layer) => layer,
                Err(e) => {
                    // The reason names configuration items only (variables,
                    // certificate index); no key material.
                    audit_grpc_listener(
                        audit.as_ref(),
                        ostrich_audit::EventType::ConfigurationChange,
                        "grpc_listener_refused",
                        ostrich_audit::EventOutcome::Failure,
                        serde_json::json!({
                            "check": "grpc_authorization_layer",
                            "reason": e.to_string(),
                        }),
                    )
                    .await;
                    return Err(
                        anyhow::Error::new(e).context("CA gRPC listener configuration rejected")
                    );
                }
            };
            let mut incoming = ostrich_common::grpc_tls::bind_mtls_incoming(
                grpc_addr,
                config,
                Some(hook.clone()),
                GRPC_LISTENER,
            )
            .await
            .context("Failed to start the CA gRPC mTLS listener")?;
            let aws_lc_version = ostrich_common::tls::aws_lc_module_version();
            let bound = incoming.local_addr();
            tracing::info!(
                grpc_addr = %bound,
                tls = "1.3",
                fips = true,
                mtls = true,
                aws_lc_version,
                clients = %clients.summary(),
                method_rules = %method_rules,
                issuer_profiles = %issuer_profiles,
                "gRPC mTLS listener (TLS 1.3, FIPS)"
            );
            audit_grpc_listener(
                audit.as_ref(),
                ostrich_audit::EventType::System,
                "grpc_listener_started",
                ostrich_audit::EventOutcome::Success,
                serde_json::json!({
                    "mode": "mtls",
                    "tls": "1.3",
                    "fips": true,
                    "aws_lc_version": aws_lc_version,
                    "clients": clients.summary(),
                    "method_rules": method_rules,
                    "issuer_profiles": issuer_profiles,
                    "address": bound.to_string(),
                }),
            )
            .await;
            let accept_task = incoming.take_accept_task();
            let flush_layer = layer.clone();
            let task = tokio::spawn(async move {
                let result = tonic::transport::Server::builder()
                    .layer(layer)
                    .add_service(service)
                    .serve_with_incoming_shutdown(incoming, shutdown)
                    .await;
                if let Err(e) = result {
                    tracing::error!(error = %e, "CA gRPC server failed");
                }
                // SEC-012 / AU-2: flush the last suppressed-record summaries
                // (access denials here; handshake failures when the accept
                // loop sees the dropped stream) before the task completes.
                flush_layer.flush_suppressed_audit().await;
                if let Some(accept_task) = accept_task {
                    let _ = accept_task.await;
                }
            });
            Ok((bound, task))
        }
        ostrich_common::GrpcServerMode::InsecureDevPlaintext => {
            // NIST 800-53: SC-8 / AC-3 / CM-6 - impossible to miss, every start.
            tracing::warn!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            tracing::warn!(
                %grpc_addr,
                "CA gRPC listener is PLAINTEXT and UNAUTHENTICATED \
                 (CA_GRPC_INSECURE_DEV_PLAINTEXT=true, debug build)"
            );
            tracing::warn!(
                "LOCAL DEVELOPMENT ONLY: any client can issue certificates, revoke \
                 certificates and generate CRLs, with no verified audit actor; never deploy \
                 this build (NIST 800-53: SC-8, AC-3, AC-17)"
            );
            audit_grpc_listener(
                audit.as_ref(),
                ostrich_audit::EventType::ConfigurationChange,
                "grpc_insecure_dev_plaintext_enabled",
                ostrich_audit::EventOutcome::Success,
                serde_json::json!({
                    "build": "debug",
                    "address": grpc_addr.to_string(),
                }),
            )
            .await;
            let task = tokio::spawn(async move {
                let result = tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_shutdown(grpc_addr, shutdown)
                    .await;
                if let Err(e) = result {
                    tracing::error!(error = %e, "CA gRPC server failed");
                }
            });
            Ok((grpc_addr, task))
        }
    }
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
    profiles: &[ostrich_x509::CertificateProfile],
) -> Result<Option<(Arc<ostrich_ca::CertificateAuthority>, CaLineage)>> {
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

    // Register the certificate profiles: the same list the gRPC
    // IssuerProfilePolicy was validated against at startup (SEC-102).
    // NIAP PP-CA: FDP_IFC.1 - issuance policy definitions
    // POAM: POAM-2026-10-23-38 - profiles should be loaded from the certificate_profiles table
    // (CM-2: configuration as data) instead of code defaults. When they are,
    // IssuerProfilePolicy must be re-validated against the stored profiles
    // (unknown names and basic_constraints_ca refused) before the gRPC
    // listener starts; until then `issue()` refuses CA profiles to every
    // authenticated gRPC caller at call time (NIST-107).
    for profile in profiles.iter().cloned() {
        tracing::info!(profile = %profile.name, "Registering certificate profile");
        ca.add_profile(profile);
    }

    // Approval workflow toggle.
    // NIAP PP-CA: FDP_CER_EXT.3 - approval-required is the secure default.
    // When enabled, the issuer must hold the approval engine + repository so it
    // can verify the referenced request is Approved before issuing (otherwise
    // issuance fails closed with an internal "approval workflow unavailable").
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

    let lineage = CaLineage {
        id: ca_cert_row.id,
        parent_ca_id: ca_cert_row.parent_ca_id,
    };
    Ok(Some((Arc::new(ca), lineage)))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Args {
        let mut argv = vec!["ostrich-ca-server", "--database-url", "postgres://unused"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).expect("args")
    }

    /// CM-6: with no gRPC options the listener mode resolution refuses to start.
    #[test]
    fn grpc_defaults_refuse_to_start() {
        let args = parse(&[]);
        assert!(!args.grpc_insecure_dev_plaintext, "dev flag defaults off");
        assert!(grpc_server_options(&args).resolve(true).is_err());
        assert!(grpc_server_options(&args).resolve(false).is_err());
    }

    /// `;` separates subjects (commas belong to the DN) in each role list;
    /// blank values count as unset so `${VAR:-}` in compose does not create
    /// an empty entry.
    #[test]
    fn grpc_subjects_are_semicolon_delimited_and_blank_is_unset() {
        let args = parse(&[
            "--grpc-acme-client-subjects",
            "CN=acme-server,O=Ostrich;CN=integration-tests",
            "--grpc-est-client-subjects",
            "CN=est-server;",
            "--grpc-admin-client-subjects",
            "CN=ops-admin",
        ]);
        let o = grpc_server_options(&args);
        assert_eq!(
            o.acme_subjects,
            vec![
                "CN=acme-server,O=Ostrich".to_string(),
                "CN=integration-tests".to_string()
            ]
        );
        assert_eq!(o.est_subjects, vec!["CN=est-server".to_string()]);
        assert_eq!(o.admin_subjects, vec!["CN=ops-admin".to_string()]);
        assert!(o.legacy_allowed_subjects.is_empty());

        let blank = parse(&[
            "--grpc-acme-client-subjects",
            " ",
            "--grpc-est-client-subjects",
            "",
            "--grpc-admin-client-subjects",
            "",
            "--grpc-tls-cert",
            "",
        ]);
        let options = grpc_server_options(&blank);
        assert!(options.acme_subjects.is_empty());
        assert!(options.est_subjects.is_empty());
        assert!(options.admin_subjects.is_empty());
        assert!(options.cert_path.is_none());
    }

    /// Deploy shape (compose / Helm / k8s): the admin list is always rendered,
    /// usually as `""`, and the EST-only CI profile also sets the ACME list to
    /// `""`. Blank role values mean "no subjects", not a parse error; both
    /// issuer lists blank still refuses to start (CM-6, SC-24).
    #[test]
    fn grpc_blank_role_values_are_no_subjects() {
        let client_ca = ca("Blank Roles Client CA");
        let mut o = mtls_options(&client_ca.pem());
        let args = parse(&[
            "--grpc-acme-client-subjects",
            "",
            "--grpc-est-client-subjects",
            "CN=est-server",
            "--grpc-admin-client-subjects",
            "",
        ]);
        let parsed = grpc_server_options(&args);
        o.acme_subjects = parsed.acme_subjects;
        o.est_subjects = parsed.est_subjects;
        o.admin_subjects = parsed.admin_subjects;
        let mode = o.clone().resolve(true).expect("EST-only with blank admin");
        let ostrich_common::GrpcServerMode::Mtls { clients, .. } = mode else {
            panic!("expected Mtls");
        };
        assert_eq!(
            clients.summary(),
            serde_json::json!({"acme": [], "est": ["CN=est-server"], "admin": []})
        );

        let args = parse(&[
            "--grpc-acme-client-subjects",
            "",
            "--grpc-est-client-subjects",
            " ; ",
            "--grpc-admin-client-subjects",
            "CN=ops-admin",
        ]);
        let parsed = grpc_server_options(&args);
        o.acme_subjects = parsed.acme_subjects;
        o.est_subjects = parsed.est_subjects;
        o.admin_subjects = parsed.admin_subjects;
        let err = o.resolve(true).expect_err("no issuer");
        assert!(
            err.to_string().contains("no issuer client configured"),
            "{err}"
        );
    }

    /// The dev plaintext flag resolves only outside release builds.
    #[test]
    fn grpc_insecure_flag_is_debug_only() {
        let args = parse(&["--grpc-insecure-dev-plaintext"]);
        assert!(grpc_server_options(&args).resolve(true).is_err());
        assert!(matches!(
            grpc_server_options(&args).resolve(false),
            Ok(ostrich_common::GrpcServerMode::InsecureDevPlaintext)
        ));
    }

    /// NIST-013: a role list next to the dev plaintext flag is ambiguous.
    #[test]
    fn grpc_insecure_with_allowlist_is_ambiguous() {
        for flag in [
            "--grpc-acme-client-subjects",
            "--grpc-est-client-subjects",
            "--grpc-admin-client-subjects",
        ] {
            let args = parse(&["--grpc-insecure-dev-plaintext", flag, "CN=x"]);
            let err = grpc_server_options(&args)
                .resolve(false)
                .expect_err("ambiguous");
            assert!(err.to_string().contains("ambiguous"), "{flag}: {err}");
        }
    }

    /// CM-6: the removed `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` refuses startup
    /// with a migration message, in both modes.
    #[test]
    fn grpc_legacy_allowed_subjects_refuses_to_start() {
        let client_ca = ca("Legacy Client CA");
        let mut o = mtls_options(&client_ca.pem());
        o.legacy_allowed_subjects = grpc_server_options(&parse(&[
            "--grpc-allowed-client-subjects",
            "CN=acme-server;CN=est-server",
        ]))
        .legacy_allowed_subjects;
        let err = o.resolve(true).expect_err("legacy refused");
        let msg = err.to_string();
        assert!(msg.contains("CA_GRPC_ALLOWED_CLIENT_SUBJECTS"), "{msg}");
        assert!(msg.contains("CA_GRPC_ACME_CLIENT_SUBJECTS"), "{msg}");
        assert!(msg.contains("CA_GRPC_EST_CLIENT_SUBJECTS"), "{msg}");
        assert!(msg.contains("CA_GRPC_ADMIN_CLIENT_SUBJECTS"), "{msg}");

        let args = parse(&[
            "--grpc-insecure-dev-plaintext",
            "--grpc-allowed-client-subjects",
            "CN=acme-server",
        ]);
        assert!(grpc_server_options(&args).resolve(false).is_err());
        // Blank legacy value (an unset `${VAR:-}`) is ignored.
        let args = parse(&["--grpc-allowed-client-subjects", " ; "]);
        assert!(
            grpc_server_options(&args)
                .legacy_allowed_subjects
                .is_empty()
        );
    }

    /// AC-5: a subject in two role lists refuses startup (canonical match).
    #[test]
    fn grpc_overlapping_role_lists_refuse_to_start() {
        let client_ca = ca("Overlap Client CA");
        let mut o = mtls_options(&client_ca.pem());
        let parsed = grpc_server_options(&parse(&[
            "--grpc-acme-client-subjects",
            "CN=svc, O=Ostrich",
            "--grpc-admin-client-subjects",
            "CN=svc,O=Ostrich",
        ]));
        o.acme_subjects = parsed.acme_subjects;
        o.admin_subjects = parsed.admin_subjects;
        let err = o.resolve(true).expect_err("overlap");
        assert!(err.to_string().contains("listed in both"), "{err}");
    }

    /// RFC-003 / SEC-007: a trailing `;` is dropped; `\;` cannot smuggle a
    /// second subject (clap splits it into `CN=a\` + `CN=b`, and the dangling
    /// escape is rejected).
    #[test]
    fn grpc_subject_delimiter_edge_cases() {
        let args = parse(&["--grpc-acme-client-subjects", "CN=a;CN=b;"]);
        assert_eq!(
            grpc_server_options(&args).acme_subjects,
            vec!["CN=a".to_string(), "CN=b".to_string()]
        );
        assert_eq!(
            ostrich_common::ClientSubjectAllowlist::parse(
                &grpc_server_options(&args).acme_subjects
            )
            .expect("parse")
            .subjects(),
            &["CN=a".to_string(), "CN=b".to_string()]
        );

        let args = parse(&["--grpc-admin-client-subjects", r"CN=a\;CN=b"]);
        let entries = grpc_server_options(&args).admin_subjects;
        assert_eq!(entries, vec![r"CN=a\".to_string(), "CN=b".to_string()]);
        assert!(
            ostrich_common::GrpcClientRegistry::parse(&["CN=acme".to_string()], &[], &entries)
                .is_err()
        );

        let args = parse(&["--grpc-est-client-subjects", ";"]);
        assert!(grpc_server_options(&args).est_subjects.is_empty());
    }

    // ---- fix round 1: issuer profile lists (SEC-001), service per mode
    // (SEC-004 / QA-003), admin anchors (RFC-001) ----

    fn profile_policy(
        argv: &[&str],
        mode: &ostrich_common::GrpcServerMode,
    ) -> Result<ostrich_ca::grpc_authz::IssuerProfilePolicy> {
        grpc_issuer_profiles(&parse(argv), mode, &default_profiles())
    }

    fn acme_est_mode() -> ostrich_common::GrpcServerMode {
        let client_ca = ca("Profiles Client CA");
        let mut o = mtls_options(&client_ca.pem());
        o.est_subjects = vec!["CN=est-server".to_string()];
        o.resolve(true).expect("mtls mode")
    }

    /// SEC-001: the default lists (acme-default; tls_client, tls_server,
    /// tls_server_client, efs) parse against the registered profiles and
    /// never include a CA profile.
    #[test]
    fn grpc_profile_defaults() {
        let args = parse(&[]);
        assert_eq!(args.grpc_acme_allowed_profiles, vec!["acme-default"]);
        assert_eq!(
            args.grpc_est_allowed_profiles,
            vec!["tls_client", "tls_server", "tls_server_client", "efs"]
        );
        let mode = acme_est_mode();
        let policy = profile_policy(&[], &mode).expect("defaults");
        assert!(policy.allows("acme", "acme-default"));
        assert!(!policy.allows("acme", "intermediate_ca"));
        assert!(!policy.allows("est", "acme-default"));
        assert!(policy.allows("est", "efs"));
        for p in default_profiles().iter().filter(|p| p.basic_constraints_ca) {
            assert!(!policy.allows_any(&p.name), "{}", p.name);
        }
        // Dev/test compose: ACME may also request tls_client.
        let policy = profile_policy(
            &["--grpc-acme-allowed-profiles", "acme-default;tls_client;"],
            &mode,
        )
        .expect("dev list");
        assert!(policy.allows("acme", "tls_client"));
    }

    /// SEC-001: startup refusals for a CA profile, an unknown profile and an
    /// empty list for a namespace with subjects; EST-only accepts an empty or
    /// default ACME list.
    #[test]
    fn grpc_profile_lists_refuse_to_start() {
        let mode = acme_est_mode();
        for argv in [
            &[
                "--grpc-acme-allowed-profiles",
                "acme-default;intermediate_ca",
            ][..],
            &["--grpc-est-allowed-profiles", "intermediate_ca"][..],
            &["--grpc-acme-allowed-profiles", "nope"][..],
            &["--grpc-acme-allowed-profiles", ""][..],
            &["--grpc-est-allowed-profiles", ";"][..],
        ] {
            let err = profile_policy(argv, &mode).expect_err("refused");
            assert!(
                format!("{err:#}").contains("ALLOWED_PROFILES"),
                "{argv:?}: {err:#}"
            );
        }
        let est_only = {
            let client_ca = ca("EST-only Client CA");
            let mut o = mtls_options(&client_ca.pem());
            o.acme_subjects = vec![String::new()];
            o.est_subjects = vec!["CN=est-server".to_string()];
            o.resolve(true).expect("est-only mode")
        };
        profile_policy(&[], &est_only).expect("EST-only, default ACME list");
        profile_policy(&["--grpc-acme-allowed-profiles", ""], &est_only)
            .expect("EST-only, empty ACME list");
        assert!(
            profile_policy(
                &["--grpc-acme-allowed-profiles", "intermediate_ca"],
                &est_only
            )
            .is_err()
        );
    }

    /// SEC-004 / QA-003 (M18): the service's peer requirement follows the
    /// listener mode: always for mTLS; plaintext only skips it in debug.
    #[test]
    fn grpc_service_peer_requirement_follows_mode() {
        let mode = acme_est_mode();
        assert!(ostrich_ca::grpc::mode_requires_peer(&mode));
        let dev = ostrich_common::GrpcServerOptions {
            insecure_dev_plaintext: true,
            ..Default::default()
        }
        .resolve(false)
        .expect("dev");
        assert_eq!(
            ostrich_ca::grpc::mode_requires_peer(&dev),
            !cfg!(debug_assertions)
        );
    }

    /// RFC-001: an admin list with a two-anchor client CA file refuses to
    /// start; one anchor is accepted.
    #[test]
    fn grpc_admin_requires_single_client_anchor() {
        let a = ca("Anchor A");
        let b = ca("Anchor B");
        let mut o = mtls_options(&format!("{}{}", a.pem(), b.pem()));
        o.admin_subjects = vec!["CN=ops-admin".to_string()];
        let err = o.resolve(true).expect_err("two anchors with admin");
        assert!(err.to_string().contains("trust anchors"), "{err}");
        let mut o = mtls_options(&a.pem());
        o.admin_subjects = vec!["CN=ops-admin".to_string()];
        o.resolve(true).expect("one anchor");
    }

    // ---- start_grpc_listener with an injected audit sink (QA-002) ----

    use ostrich_protocol::certificate_authority_service_server::CertificateAuthorityService;
    use ostrich_protocol::{
        CheckRevocationStatusRequest, CheckRevocationStatusResponse, GenerateCrlRequest,
        GenerateCrlResponse, GetCaInfoRequest, GetCaInfoResponse, IssueCertificateRequest,
        IssueCertificateResponse, ListProfilesRequest, ListProfilesResponse,
        RevokeCertificateRequest, RevokeCertificateResponse,
    };
    use tonic::{Request, Response, Status};

    /// Service stub: the listener tests never issue.
    struct NoCa;

    #[tonic::async_trait]
    impl CertificateAuthorityService for NoCa {
        async fn issue_certificate(
            &self,
            _r: Request<IssueCertificateRequest>,
        ) -> std::result::Result<Response<IssueCertificateResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn revoke_certificate(
            &self,
            _r: Request<RevokeCertificateRequest>,
        ) -> std::result::Result<Response<RevokeCertificateResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn generate_crl(
            &self,
            _r: Request<GenerateCrlRequest>,
        ) -> std::result::Result<Response<GenerateCrlResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn check_revocation_status(
            &self,
            _r: Request<CheckRevocationStatusRequest>,
        ) -> std::result::Result<Response<CheckRevocationStatusResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn get_ca_info(
            &self,
            _r: Request<GetCaInfoRequest>,
        ) -> std::result::Result<Response<GetCaInfoResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn list_profiles(
            &self,
            _r: Request<ListProfilesRequest>,
        ) -> std::result::Result<Response<ListProfilesResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    fn ca(cn: &str) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        rcgen::CertifiedIssuer::self_signed(p, rcgen::KeyPair::generate().expect("key"))
            .expect("ca")
    }

    fn write_tmp(tag: &str, contents: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "ostrich-ca-server-test-{}-{tag}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, contents).expect("write");
        path.display().to_string()
    }

    /// mTLS options whose client CA is `client_ca_pem`.
    fn mtls_options(client_ca_pem: &str) -> ostrich_common::GrpcServerOptions {
        let server_ca = ca("Test gRPC Server CA");
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("p");
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = p.signed_by(&key, &server_ca).expect("leaf");
        ostrich_common::GrpcServerOptions {
            cert_path: Some(write_tmp("cert", &cert.pem())),
            key_path: Some(write_tmp("key", &key.serialize_pem())),
            client_ca_path: Some(write_tmp("client-ca", client_ca_pem)),
            acme_subjects: vec!["CN=acme-server".to_string()],
            ..Default::default()
        }
    }

    async fn recorded(sink: &ostrich_audit::MemoryAuditSink) -> Vec<ostrich_audit::AuditEvent> {
        use ostrich_audit::AuditSink;
        sink.query_events(ostrich_audit::sink::QueryCriteria::default())
            .await
            .expect("query")
    }

    /// AU-2 / AU-3: the mTLS listener writes `grpc_listener_started` with its
    /// mode, TLS/FIPS facts, client lists, method rules and bound address.
    #[tokio::test]
    async fn start_grpc_listener_mtls_audits_start() {
        let client_ca = ca("Test gRPC Client CA");
        let mode = mtls_options(&client_ca.pem())
            .resolve(true)
            .expect("mtls mode");
        let sink = Arc::new(ostrich_audit::MemoryAuditSink::new());
        let (bound, _task) = start_grpc_listener(
            mode,
            "127.0.0.1:0".parse().unwrap(),
            NoCa,
            serde_json::json!({"acme": ["acme-default"], "est": []}),
            sink.clone(),
            &[],
            std::future::pending::<()>(),
        )
        .await
        .expect("listener");
        assert_ne!(bound.port(), 0);

        let events = recorded(&sink).await;
        assert_eq!(events.len(), 1, "{events:?}");
        let ev = &events[0];
        assert_eq!(ev.event_type, ostrich_audit::EventType::System);
        assert_eq!(ev.action, "grpc_listener_started");
        assert_eq!(ev.actor, "ca-server");
        assert_eq!(ev.target, GRPC_LISTENER);
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Success);
        let d = ev.details.as_ref().expect("details");
        assert_eq!(d["mode"], "mtls");
        assert_eq!(d["tls"], "1.3");
        assert_eq!(d["fips"], true);
        assert_eq!(
            d["clients"],
            serde_json::json!({"acme": ["CN=acme-server"], "est": [], "admin": []})
        );
        // CM-3: the effective method table is part of the record.
        let rules = d["method_rules"].as_array().expect("method_rules");
        assert_eq!(
            rules.len(),
            ostrich_ca::grpc_authz::CA_GRPC_METHOD_RULES.len()
        );
        let issue = rules
            .iter()
            .find(|r| r["path"] == "/ostrich.ca.v1.CertificateAuthorityService/IssueCertificate")
            .expect("IssueCertificate rule");
        assert_eq!(issue["roles"], serde_json::json!(["issuer"]));
        // SEC-001: the per-namespace issuer profile lists are recorded.
        assert_eq!(
            d["issuer_profiles"],
            serde_json::json!({"acme": ["acme-default"], "est": []})
        );
        assert_eq!(d["address"], bound.to_string());
        assert!(d["aws_lc_version"].is_string());
    }

    /// SEC-203 / SEC-201: a configuration the authorization layer rejects
    /// (admin subjects with a client trust anchor that has no
    /// subjectKeyIdentifier, or an unparsable subscriber-issuing CA) writes
    /// only `grpc_listener_refused`, never `grpc_listener_started`, and the
    /// listener does not start.
    #[tokio::test]
    async fn start_grpc_listener_refusal_is_audited_without_started_record() {
        // Self-signed, not a CA in rcgen terms: no subjectKeyIdentifier.
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "SKI-less Client CA");
        let ski_less = p
            .self_signed(&rcgen::KeyPair::generate().expect("key"))
            .expect("anchor");
        let mut opts = mtls_options(&ski_less.pem());
        opts.admin_subjects = vec!["CN=ops-admin".to_string()];
        let client_ca = ca("Test gRPC Client CA");
        let cases: [(ostrich_common::GrpcServerOptions, &[&[u8]], &str); 2] = [
            (opts, &[], "no subjectKeyIdentifier"),
            (
                mtls_options(&client_ca.pem()),
                &[b"junk".as_slice()],
                "cannot be parsed",
            ),
        ];
        for (opts, subscriber_cas, needle) in cases {
            let mode = opts.resolve(true).expect("mtls mode");
            let sink = Arc::new(ostrich_audit::MemoryAuditSink::new());
            let err = start_grpc_listener(
                mode,
                "127.0.0.1:0".parse().unwrap(),
                NoCa,
                serde_json::json!({"acme": [], "est": []}),
                sink.clone(),
                subscriber_cas,
                std::future::pending::<()>(),
            )
            .await
            .expect_err("configuration rejected");
            assert!(format!("{err:#}").contains(needle), "{err:#}");
            let events = recorded(&sink).await;
            assert_eq!(events.len(), 1, "{needle}: {} records", events.len());
            let ev = &events[0];
            assert_eq!(ev.action, "grpc_listener_refused");
            assert_eq!(ev.event_type, ostrich_audit::EventType::ConfigurationChange);
            assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure);
            assert_eq!(ev.target, GRPC_LISTENER);
            let d = ev.details.as_ref().expect("details");
            assert_eq!(d["check"], "grpc_authorization_layer");
            assert!(
                d["reason"].as_str().expect("reason").contains(needle),
                "{needle}"
            );
        }
    }

    /// CM-6 / AU-2: the debug-only plaintext listener writes a
    /// ConfigurationChange record on every start.
    #[tokio::test]
    async fn start_grpc_listener_insecure_audits_dev_mode() {
        let mode = ostrich_common::GrpcServerOptions {
            insecure_dev_plaintext: true,
            ..Default::default()
        }
        .resolve(false)
        .expect("debug insecure mode");
        let sink = Arc::new(ostrich_audit::MemoryAuditSink::new());
        start_grpc_listener(
            mode,
            "127.0.0.1:0".parse().unwrap(),
            NoCa,
            serde_json::json!({"acme": ["acme-default"], "est": []}),
            sink.clone(),
            &[],
            std::future::pending::<()>(),
        )
        .await
        .expect("listener");
        let events = recorded(&sink).await;
        assert_eq!(events.len(), 1, "{events:?}");
        let ev = &events[0];
        assert_eq!(ev.event_type, ostrich_audit::EventType::ConfigurationChange);
        assert_eq!(ev.action, "grpc_insecure_dev_plaintext_enabled");
        assert_eq!(ev.target, GRPC_LISTENER);
        let d = ev.details.as_ref().expect("details");
        assert_eq!(d["build"], "debug");
        assert_eq!(d["address"], "127.0.0.1:0");
    }

    /// SEC-001: ca-server refuses a gRPC client CA that is its own issuing
    /// CA; a dedicated client CA is accepted.
    #[test]
    fn grpc_client_ca_must_not_be_the_issuing_ca() {
        let issuing = ca("OstrichPKI Issuing CA");
        let issuing_der = issuing.der().to_vec();

        let mode = mtls_options(&issuing.pem()).resolve(true).expect("mode");
        let err = ensure_dedicated_grpc_client_ca(&mode, &issuing_der, &[]).expect_err("same CA");
        assert!(
            err.to_string().contains("dedicated service-identity CA"),
            "{err}"
        );

        let dedicated = ca("Service Identity CA");
        let mode = mtls_options(&dedicated.pem()).resolve(true).expect("mode");
        ensure_dedicated_grpc_client_ca(&mode, &issuing_der, &[]).expect("dedicated CA accepted");

        // Plaintext dev mode has no client CA to check.
        let insecure = ostrich_common::GrpcServerOptions {
            insecure_dev_plaintext: true,
            ..Default::default()
        }
        .resolve(false)
        .expect("insecure");
        ensure_dedicated_grpc_client_ca(&insecure, &issuing_der, &[]).expect("no-op");
    }

    // ---- R2-2: ancestor walk + audited refusal (SEC-009 / RFC-010 / NIST-017) ----

    fn sub_ca(
        cn: &str,
        parent: &rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    ) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        p.use_authority_key_identifier_extension = true;
        rcgen::CertifiedIssuer::signed_by(p, rcgen::KeyPair::generate().expect("key"), parent)
            .expect("sub ca")
    }

    /// In-memory `ca_certificates`: id -> (parent_ca_id, der).
    type Rows = std::collections::HashMap<uuid::Uuid, (Option<uuid::Uuid>, Vec<u8>)>;

    fn lookup(
        rows: &Rows,
    ) -> impl FnMut(uuid::Uuid) -> std::future::Ready<Result<Option<CaChainLink>>> + '_ {
        move |id| {
            std::future::ready(Ok(rows.get(&id).map(|(parent, der)| CaChainLink {
                parent_ca_id: *parent,
                der: der.clone(),
            })))
        }
    }

    #[tokio::test]
    async fn walk_ca_ancestors_follows_parent_ca_id_and_fails_closed() {
        let (issuing, inter, root) = (
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut rows = Rows::new();
        rows.insert(inter, (Some(root), b"inter".to_vec()));
        rows.insert(root, (None, b"root".to_vec()));
        let lineage = CaLineage {
            id: issuing,
            parent_ca_id: Some(inter),
        };
        let chain = walk_ca_ancestors(&lineage, lookup(&rows))
            .await
            .expect("walk");
        assert_eq!(chain, vec![b"inter".to_vec(), b"root".to_vec()]);

        // Root issuing CA: nothing to walk; a self-referencing row ends it.
        let root_lineage = CaLineage {
            id: root,
            parent_ca_id: None,
        };
        assert!(
            walk_ca_ancestors(&root_lineage, lookup(&rows))
                .await
                .expect("root")
                .is_empty()
        );
        let self_ref = CaLineage {
            id: root,
            parent_ca_id: Some(root),
        };
        assert!(
            walk_ca_ancestors(&self_ref, lookup(&rows))
                .await
                .expect("self")
                .is_empty()
        );

        // Missing parent row.
        let missing = CaLineage {
            id: issuing,
            parent_ca_id: Some(uuid::Uuid::new_v4()),
        };
        let err = walk_ca_ancestors(&missing, lookup(&rows))
            .await
            .expect_err("missing");
        assert!(err.to_string().contains("not found"), "{err}");

        // Cycle back to the issuing CA.
        let mut cyclic = rows.clone();
        cyclic.insert(root, (Some(issuing), b"root".to_vec()));
        let err = walk_ca_ancestors(&lineage, lookup(&cyclic))
            .await
            .expect_err("cycle");
        assert!(err.to_string().contains("cycle"), "{err}");

        // Depth bound.
        let mut deep = Rows::new();
        let mut parent = None;
        let mut ids = Vec::new();
        for _ in 0..=MAX_CA_ANCESTOR_DEPTH {
            let id = uuid::Uuid::new_v4();
            deep.insert(id, (parent, b"x".to_vec()));
            parent = Some(id);
            ids.push(id);
        }
        let deep_lineage = CaLineage {
            id: uuid::Uuid::new_v4(),
            parent_ca_id: parent,
        };
        let err = walk_ca_ancestors(&deep_lineage, lookup(&deep))
            .await
            .expect_err("deep");
        assert!(err.to_string().contains("deeper"), "{err}");
    }

    /// An anchor two levels above the issuing CA (found only through the DB
    /// walk) is refused, and the refusal is audited; a dedicated CA passes
    /// without a refusal record.
    #[tokio::test]
    async fn grpc_trust_anchor_check_walks_db_chain_and_audits_refusal() {
        let root = ca("Walk Root CA");
        let inter = sub_ca("Walk Intermediate CA", &root);
        let issuing = sub_ca("Walk Issuing CA", &inter);
        let (inter_id, root_id) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut rows = Rows::new();
        rows.insert(inter_id, (Some(root_id), inter.der().to_vec()));
        rows.insert(root_id, (None, root.der().to_vec()));
        let lineage = CaLineage {
            id: uuid::Uuid::new_v4(),
            parent_ca_id: Some(inter_id),
        };

        let sink = ostrich_audit::MemoryAuditSink::new();
        let mode = mtls_options(&root.pem()).resolve(true).expect("mode");
        let err = check_grpc_trust_anchors(&mode, issuing.der(), &lineage, lookup(&rows), &sink)
            .await
            .expect_err("root is an ancestor");
        assert!(format!("{err:#}").contains("ancestor #2"), "{err:#}");
        let events = recorded(&sink).await;
        assert_eq!(events.len(), 1, "{events:?}");
        let ev = &events[0];
        assert_eq!(ev.action, "grpc_listener_refused");
        assert_eq!(ev.event_type, ostrich_audit::EventType::ConfigurationChange);
        assert_eq!(ev.outcome, ostrich_audit::EventOutcome::Failure);
        assert_eq!(ev.target, GRPC_LISTENER);
        let d = ev.details.as_ref().expect("details");
        assert_eq!(d["check"], "client_ca_trust_anchor_separation");
        assert!(
            d["reason"]
                .as_str()
                .expect("reason")
                .contains("ancestor #2")
        );

        // A walk failure is refused and audited the same way.
        let sink = ostrich_audit::MemoryAuditSink::new();
        let broken = CaLineage {
            id: lineage.id,
            parent_ca_id: Some(uuid::Uuid::new_v4()),
        };
        let dedicated = ca("Walk Service Identity CA");
        let mode = mtls_options(&dedicated.pem()).resolve(true).expect("mode");
        assert!(
            check_grpc_trust_anchors(&mode, issuing.der(), &broken, lookup(&rows), &sink)
                .await
                .is_err()
        );
        assert_eq!(recorded(&sink).await.len(), 1);

        // Dedicated CA with the full chain: accepted, ancestors returned.
        let sink = ostrich_audit::MemoryAuditSink::new();
        let ancestors =
            check_grpc_trust_anchors(&mode, issuing.der(), &lineage, lookup(&rows), &sink)
                .await
                .expect("dedicated");
        assert_eq!(ancestors.len(), 2);
        assert!(recorded(&sink).await.is_empty());
    }

    /// SEC-015: the gRPC shutdown future completes when the REST server
    /// exits (stop flag set, or its sender dropped), without a signal.
    #[tokio::test]
    async fn grpc_shutdown_follows_rest_exit() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let pending = tokio::spawn(grpc_shutdown(rx));
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        tx.send(true).expect("receiver alive");
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .expect("stopped on flag")
            .expect("no panic");

        let (tx, rx) = tokio::sync::watch::channel(false);
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), grpc_shutdown(rx))
            .await
            .expect("stopped when the sender is dropped");
    }

    /// SEC-012: the server task returned by `start_grpc_listener` completes
    /// after shutdown (so `main` can await the final audit flush).
    #[tokio::test]
    async fn grpc_server_task_completes_after_shutdown() {
        let client_ca = ca("Shutdown Client CA");
        let mode = mtls_options(&client_ca.pem()).resolve(true).expect("mode");
        let sink = Arc::new(ostrich_audit::MemoryAuditSink::new());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let issuing = ca("Shutdown Issuing CA");
        let (_, task) = start_grpc_listener(
            mode,
            "127.0.0.1:0".parse().unwrap(),
            NoCa,
            serde_json::json!({}),
            sink,
            &[issuing.der().as_ref()],
            async move {
                let _ = rx.await;
            },
        )
        .await
        .expect("listener");
        tx.send(()).expect("signal");
        tokio::time::timeout(GRPC_SHUTDOWN_GRACE, task)
            .await
            .expect("server task finished within the grace period")
            .expect("task did not panic");
    }
}
