//! OstrichPKI EST Enrollment Server
//!
//! COMPLIANCE MAPPING:
//! - RFC 7030: Enrollment over Secure Transport (EST)
//! - NIST 800-53: SC-17 (PKI Certificates)
//! - NIST 800-53: SC-8 (Transmission Confidentiality - mTLS)

mod config;

use anyhow::Result;
use clap::Parser;
use config::FileConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// OstrichPKI EST Enrollment Server
///
/// Settings may come from a JSON config file (`--config`), CLI flags, or
/// environment variables. Precedence: CLI/env > config file > built-in default.
#[derive(Parser, Debug)]
#[command(name = "ostrich-est-server")]
#[command(about = "OstrichPKI EST Enrollment Server (RFC 7030)")]
#[command(version)]
struct Args {
    /// Path to a JSON configuration file (validated against
    /// config/schema/est-server.schema.json). See config/est_server.example.json.
    #[arg(long, env = "EST_CONFIG")]
    config: Option<PathBuf>,

    /// HTTPS bind address (default: 0.0.0.0:8443)
    #[arg(long, env = "EST_BIND_ADDRESS")]
    bind_address: Option<String>,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// CA gRPC endpoint for certificate issuance (RFC 7030 §4.2).
    /// NIST 800-53: SC-17 - PKI certificate issuance via CA service.
    #[arg(long, env = "CA_GRPC_URL")]
    ca_grpc_url: Option<String>,

    /// Client certificate (PEM) for mTLS to the CA gRPC service.
    /// NIST 800-53: SC-8 / AC-17 - mutually authenticated inter-service channel.
    #[arg(long, env = "CA_GRPC_CLIENT_CERT_FILE")]
    ca_grpc_client_cert: Option<String>,

    /// Client private key (PEM) for mTLS to the CA gRPC service.
    #[arg(long, env = "CA_GRPC_CLIENT_KEY_FILE")]
    ca_grpc_client_key: Option<String>,

    /// CA certificate (PEM) used to verify the CA gRPC server.
    #[arg(long, env = "CA_GRPC_CA_CERT_FILE")]
    ca_grpc_ca_cert: Option<String>,

    /// How a CSR's requested identity is authorized against the authenticated
    /// account (H1): "username" (default) or "allowlist". NIST 800-53: AC-3 / AC-6.
    #[arg(long, env = "EST_IDENTITY_POLICY")]
    enroll_identity_policy: Option<String>,

    /// Allow bearer-token authentication for EST enrollment when no TLS client
    /// CA (--tls-ca-cert) is configured. RFC 7030 §3.3 expects mTLS; this is an
    /// explicit, non-default opt-in to the weaker posture (NIST 800-53: CM-6).
    #[arg(long, env = "EST_ALLOW_BEARER_AUTH", num_args = 0..=1, default_missing_value = "true")]
    allow_bearer_auth: Option<bool>,

    /// Allow a plaintext (non-mTLS) gRPC channel to a non-loopback CA endpoint.
    /// DEVELOPMENT ONLY - the EST→CA channel carries issuance requests and must
    /// be mutually authenticated in production (NIST 800-53: SC-8, AC-17).
    #[arg(long, env = "CA_GRPC_INSECURE", num_args = 0..=1, default_missing_value = "true")]
    ca_insecure: Option<bool>,

    /// Certificate profile used for EST enrollment / re-enrollment (default: tls_client).
    /// NIST 800-53: CM-6 - Configurable issuance profile (secure default).
    #[arg(long, env = "EST_ENROLL_PROFILE")]
    enroll_profile: Option<String>,

    /// TLS certificate file
    #[arg(long, env = "TLS_CERT_FILE")]
    tls_cert: Option<String>,

    /// TLS private key file
    #[arg(long, env = "TLS_KEY_FILE")]
    tls_key: Option<String>,

    /// TLS CA certificate for client authentication
    #[arg(long, env = "TLS_CA_CERT_FILE")]
    tls_ca_cert: Option<String>,

    /// Accept HTTP Basic authentication (RFC 7030 §3.2.3) as a fallback when a
    /// client does not present a TLS client certificate. Intended for bootstrap
    /// enrollment. Requires --tls-ca-cert (mTLS); Basic is rejected otherwise
    /// because it transmits a reusable password.
    #[arg(long, env = "EST_ALLOW_BASIC_AUTH", num_args = 0..=1, default_missing_value = "true")]
    allow_basic_auth: Option<bool>,

    /// Log level (default: info)
    #[arg(long, env = "RUST_LOG")]
    log_level: Option<String>,

    /// Enable JSON logging
    #[arg(long, env = "LOG_JSON", num_args = 0..=1, default_missing_value = "true")]
    log_json: Option<bool>,
}

/// Fully resolved EST server settings after merging CLI/env, config file, and
/// built-in defaults (in that precedence order).
struct Settings {
    bind_address: String,
    database_url: String,
    ca_grpc_url: Option<String>,
    ca_grpc_client_cert: Option<String>,
    ca_grpc_client_key: Option<String>,
    ca_grpc_ca_cert: Option<String>,
    ca_insecure: bool,
    enroll_profile: String,
    enroll_identity_policy: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_ca_cert: Option<String>,
    allow_basic_auth: bool,
    allow_bearer_auth: bool,
    log_level: String,
    log_json: bool,
}

impl Settings {
    /// Merge CLI/env args over an optional config file over built-in defaults.
    fn resolve(args: Args, file: FileConfig) -> Result<Self> {
        let database_url = args
            .database_url
            .or(file.database_url)
            .ok_or_else(|| anyhow::anyhow!(
                "database URL is required: set --database-url, DATABASE_URL, or \"databaseUrl\" in the config file"
            ))?;

        Ok(Self {
            bind_address: args
                .bind_address
                .or(file.bind_address)
                .unwrap_or_else(|| "0.0.0.0:8443".to_string()),
            database_url,
            ca_grpc_url: args.ca_grpc_url.or(file.ca_grpc_url),
            ca_grpc_client_cert: args.ca_grpc_client_cert.or(file.ca_grpc_client_cert),
            ca_grpc_client_key: args.ca_grpc_client_key.or(file.ca_grpc_client_key),
            ca_grpc_ca_cert: args.ca_grpc_ca_cert.or(file.ca_grpc_ca_cert),
            ca_insecure: args.ca_insecure.or(file.ca_insecure).unwrap_or(false),
            enroll_profile: args
                .enroll_profile
                .or(file.enroll_profile)
                .unwrap_or_else(|| "tls_client".to_string()),
            enroll_identity_policy: args
                .enroll_identity_policy
                .or(file.enroll_identity_policy)
                .unwrap_or_else(|| "username".to_string()),
            tls_cert: args.tls_cert.or(file.tls_cert),
            tls_key: args.tls_key.or(file.tls_key),
            tls_ca_cert: args.tls_ca_cert.or(file.tls_ca_cert),
            allow_basic_auth: args
                .allow_basic_auth
                .or(file.allow_basic_auth)
                .unwrap_or(false),
            allow_bearer_auth: args
                .allow_bearer_auth
                .or(file.allow_bearer_auth)
                .unwrap_or(false),
            log_level: args
                .log_level
                .or(file.log_level)
                .unwrap_or_else(|| "info".to_string()),
            log_json: args.log_json.or(file.log_json).unwrap_or(false),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load the optional JSON config file (schema-validated), then merge:
    // CLI/env > config file > built-in defaults. CM-2 / CM-6.
    let file = match args.config.as_deref() {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::default(),
    };
    let settings = Settings::resolve(args, file)?;

    init_logging(&settings.log_level, settings.log_json)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting OstrichPKI EST Server"
    );

    // Initialize database
    let db_config = ostrich_db::PoolConfig::from_url(&settings.database_url)?;
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
    // Sessions are persisted in Postgres (DbSessionStore): they survive a
    // restart and are shared across instances (NIST 800-53: SC-23, AC-12).
    // RFC 7030 §3.3 expects EST clients to authenticate with a TLS client
    // certificate. When mTLS is configured (--tls-ca-cert), authenticate by the
    // verified client certificate (mapped to an account by certificate_subject);
    // otherwise fall back to bearer/password auth.
    use ostrich_est::rest::EstAuthMode;

    let use_mtls_auth = settings.tls_ca_cert.is_some();

    // HTTP Basic transmits a reusable password; only offer it alongside mTLS on
    // a TLS listener (RFC 7030 §3.2.3). Fail closed on a misconfiguration rather
    // than silently exposing Basic on a non-mTLS endpoint.
    // NIST 800-53: SC-8 / CM-6 - secure default, no Basic without TLS client CA.
    if settings.allow_basic_auth && !use_mtls_auth {
        anyhow::bail!(
            "--allow-basic-auth requires --tls-ca-cert (mTLS); HTTP Basic is not \
             permitted without a TLS client CA configured"
        );
    }

    // M2 - fail closed on the auth posture. RFC 7030 §3.3 expects mTLS client
    // authentication; bearer-token auth is a non-RFC fallback. Refuse to start
    // the enrollment endpoints in bearer mode unless the operator has explicitly
    // opted in with --allow-bearer-auth, so the weaker posture is never the
    // silent default. NIST 800-53: CM-6 / AC-3 - secure default.
    if !use_mtls_auth && !settings.allow_bearer_auth {
        anyhow::bail!(
            "EST has no TLS client CA configured (--tls-ca-cert) for mTLS client \
             authentication (RFC 7030 §3.3). To run with bearer-token auth instead, \
             pass --allow-bearer-auth explicitly (not recommended for production)."
        );
    }

    let auth_mode = match (use_mtls_auth, settings.allow_basic_auth) {
        (true, true) => EstAuthMode::MtlsWithBasicFallback,
        (true, false) => EstAuthMode::Mtls,
        (false, _) => EstAuthMode::BearerToken,
    };

    let user_repo = Arc::new(ostrich_db::repository::DbUserRepository::new(
        db_pool.clone(),
    ));
    let sessions = Arc::new(
        ostrich_common::auth::SessionManager::with_store(
            ostrich_common::auth::SessionConfig::default(),
            Arc::new(ostrich_db::repository::DbSessionStore::new(db_pool.clone())),
        )
        // Emit login/logout/admin-termination as audit events (NIST 800-53: AU-2).
        .with_audit_hook(Arc::new(ostrich_audit::SessionAuditAdapter::new(
            Arc::new(ostrich_audit::DatabaseAuditSink::new(db_pool.clone())),
        ))),
    );
    // Reap expired/terminated sessions periodically so the table does not grow
    // unbounded (NIST 800-53: AC-12).
    sessions
        .clone()
        .spawn_reaper(ostrich_common::auth::SessionManager::DEFAULT_REAP_INTERVAL);
    // Audit failed logins / lockouts / unlocks for the password path (AU-2, AC-7).
    let auth_audit = Arc::new(ostrich_audit::AuthAuditAdapter::new(Arc::new(
        ostrich_audit::DatabaseAuditSink::new(db_pool.clone()),
    )));
    let auth_provider: Arc<dyn ostrich_common::auth::AuthProvider> = match auth_mode {
        EstAuthMode::MtlsWithBasicFallback => {
            tracing::info!(
                "EST mTLS authentication with HTTP Basic fallback enabled \
                 (RFC 7030 §3.3 + §3.2.3 bootstrap enrollment)"
            );
            // Composite: certificate identity preferred, password (Basic) fallback.
            // Both providers share the same lockout and session managers.
            let cert_provider = ostrich_common::auth::CertificateAuthProvider::new(
                ostrich_common::auth::CertificateAuthConfig::default(),
                user_repo.clone(),
                sessions.clone(),
            );
            let password_provider = ostrich_common::auth::PasswordAuthProvider::new(
                user_repo.clone(),
                ostrich_common::auth::LockoutConfig::default(),
                sessions,
            )
            .with_audit_hook(auth_audit.clone());
            Arc::new(
                ostrich_common::auth::CompositeAuthProvider::new()
                    .add_provider(Box::new(cert_provider))
                    .add_provider(Box::new(password_provider)),
            )
        }
        EstAuthMode::Mtls => {
            tracing::info!("EST mTLS client-certificate authentication enabled (RFC 7030 §3.3)");
            Arc::new(ostrich_common::auth::CertificateAuthProvider::new(
                ostrich_common::auth::CertificateAuthConfig::default(),
                user_repo.clone(),
                sessions,
            ))
        }
        EstAuthMode::BearerToken => {
            tracing::warn!(
                "EST using bearer/password authentication (no --tls-ca-cert configured); \
                 RFC 7030 §3.3 expects mTLS client authentication."
            );
            Arc::new(
                ostrich_common::auth::PasswordAuthProvider::new(
                    user_repo,
                    ostrich_common::auth::LockoutConfig::default(),
                    sessions,
                )
                .with_audit_hook(auth_audit.clone()),
            )
        }
    };
    let rbac_policy = Arc::new(ostrich_common::auth::RbacPolicy::new());

    // Initialize the CA client for certificate issuance (RFC 7030 §4.2).
    // NIST 800-53: SC-17 - PKI certificate issuance via CA service.
    // NIST 800-53: SC-8 - gRPC channel to CA (mTLS when configured).
    let ca_client = match &settings.ca_grpc_url {
        Some(url) => {
            tracing::info!(endpoint = %url, "Connecting to CA gRPC service");
            // Load CA mTLS material when configured (SC-8 / AC-17). All three
            // (client cert, client key, CA cert) are required for mTLS; partial
            // configuration is rejected so the channel can't silently degrade.
            let read_pem = |path: &Option<String>| -> Result<String> {
                match path {
                    Some(p) => Ok(std::fs::read_to_string(p)?),
                    None => Ok(String::new()),
                }
            };
            let client_cert_pem = read_pem(&settings.ca_grpc_client_cert)?;
            let client_key_pem = read_pem(&settings.ca_grpc_client_key)?;
            let ca_cert_pem = read_pem(&settings.ca_grpc_ca_cert)?;
            let any = !client_cert_pem.is_empty()
                || !client_key_pem.is_empty()
                || !ca_cert_pem.is_empty();
            let all = !client_cert_pem.is_empty()
                && !client_key_pem.is_empty()
                && !ca_cert_pem.is_empty();
            if any && !all {
                anyhow::bail!(
                    "CA gRPC mTLS requires all of --ca-grpc-client-cert, \
                     --ca-grpc-client-key, --ca-grpc-ca-cert"
                );
            }
            let config = ostrich_common::GrpcClientConfig {
                endpoint: url.clone(),
                client_cert_pem,
                client_key_pem,
                ca_cert_pem,
                ..Default::default()
            };
            let client = ostrich_est::ca_integration::EstCaClient::new(
                config,
                db_pool.clone(),
                settings.ca_insecure,
            )
            .await?;
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

    let mut state = ostrich_est::rest::EstState::new_with_auth(
        db_pool,
        Arc::new(crypto_provider),
        Arc::new(audit_sink),
        auth_provider.clone(),
        rbac_policy,
    )
    .with_ca(ca_client, ca_certificate_der)
    .with_profile(settings.enroll_profile.clone());
    state = match auth_mode {
        EstAuthMode::Mtls => state.with_mtls_auth(),
        EstAuthMode::MtlsWithBasicFallback => state.with_mtls_basic_fallback(),
        EstAuthMode::BearerToken => state,
    };

    // H1 - certificate identity authorization policy.
    let identity_policy = match settings
        .enroll_identity_policy
        .to_ascii_lowercase()
        .as_str()
    {
        "username" => ostrich_est::rest::EstIdentityPolicy::MatchUsername,
        "allowlist" | "allow-list" => ostrich_est::rest::EstIdentityPolicy::AccountAllowList,
        other => anyhow::bail!(
            "invalid --enroll-identity-policy '{other}' (expected 'username' or 'allowlist')"
        ),
    };
    tracing::info!(?identity_policy, "EST certificate identity policy");
    state = state.with_identity_policy(identity_policy);

    // Create router and mount the shared session API (login/logout).
    // Public by necessity; brute-force is mitigated by lockout (AC-7 / FIA_AFL.1).
    let app = ostrich_est::rest::create_router(state)
        .merge(ostrich_common::auth::auth_routes(auth_provider));

    // Parse bind address
    let addr: SocketAddr = settings.bind_address.parse().expect("Invalid bind address");

    tracing::info!(%addr, "Starting EST server");

    // Serve HTTPS when TLS is configured (HTTP fallback warns at startup).
    // RFC 7030 §3.3 requires TLS for EST; --tls-ca-cert enables the mTLS
    // client authentication EST relies on for enrollment identity.
    // NIST 800-53: SC-8 - Transmission Confidentiality and Integrity
    let tls = ostrich_common::tls::TlsSettings::from_options(
        settings.tls_cert,
        settings.tls_key,
        settings.tls_ca_cert,
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
