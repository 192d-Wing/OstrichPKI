//! gRPC client infrastructure with resilience patterns
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (Transmission confidentiality via mTLS, TLS 1.3 only)
//! - NIST 800-53: SC-13 (aws-lc-rs FIPS provider, `fips()` asserted)
//! - NIST 800-53: SC-23 (Session authenticity)
//! - NIST 800-53: SI-10 (Information input validation)
//! - NIST 800-53: SI-12 (client private key held in `Zeroizing`)
//! - NIAP PP-CA: FCS_TLSC_EXT.2, FTP_ITC.1

use crate::grpc_tls::{GrpcTlsConnector, endpoint_host, grpc_client_config};
use crate::{Error, Result};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::Status;
use tonic::transport::{Channel, Endpoint};
use zeroize::Zeroizing;

/// gRPC client configuration
///
/// mTLS material is all-or-nothing: either all three PEMs are set (TLS 1.3
/// mutual TLS, `https://` endpoint) or none are and `allow_plaintext` is set
/// (development only, `http://` endpoint). Anything else is rejected by
/// [`CaGrpcClient::new`].
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8(1) - Cryptographic protection for transmission
/// - NIST 800-53: SI-12 - the private key is zeroized on drop and never
///   printed by `Debug`
#[derive(Clone)]
pub struct GrpcClientConfig {
    /// CA gRPC server endpoint (e.g., "https://ca.example.com:50051")
    pub endpoint: String,

    /// mTLS client certificate (PEM-encoded)
    pub client_cert_pem: String,

    /// mTLS client private key (PEM-encoded). Zeroized on drop; redacted
    /// from `Debug`.
    pub client_key_pem: Zeroizing<String>,

    /// CA certificate for server verification (PEM-encoded)
    pub ca_cert_pem: String,

    /// TLS server name the CA's certificate must be valid for. Defaults to
    /// the endpoint URL host.
    pub server_name: Option<String>,

    /// Allow a plaintext (no TLS) channel when no mTLS material is configured.
    /// Development only; defaults to `false` (fail closed). Refused in release
    /// builds (`CaGrpcClient::new` errors when it would be used).
    pub allow_plaintext: bool,

    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,

    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,

    /// Max retry attempts for transient failures
    pub max_retries: u32,

    /// Initial retry backoff in milliseconds
    pub retry_initial_backoff_ms: u64,

    /// Maximum retry backoff in milliseconds
    pub retry_max_backoff_ms: u64,

    /// Circuit breaker failure threshold
    pub circuit_breaker_threshold: u32,

    /// Circuit breaker timeout (ms) before attempting recovery
    pub circuit_breaker_timeout_ms: u64,
}

impl fmt::Debug for GrpcClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NIST 800-53: SI-12 / IA-5 - never print the private key.
        let key = if self.client_key_pem.is_empty() {
            "<none>"
        } else {
            "<redacted>"
        };
        f.debug_struct("GrpcClientConfig")
            .field("endpoint", &self.endpoint)
            .field("client_cert_pem_len", &self.client_cert_pem.len())
            .field("client_key_pem", &key)
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .field("server_name", &self.server_name)
            .field("allow_plaintext", &self.allow_plaintext)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("retry_initial_backoff_ms", &self.retry_initial_backoff_ms)
            .field("retry_max_backoff_ms", &self.retry_max_backoff_ms)
            .field("circuit_breaker_threshold", &self.circuit_breaker_threshold)
            .field(
                "circuit_breaker_timeout_ms",
                &self.circuit_breaker_timeout_ms,
            )
            .finish()
    }
}

impl Default for GrpcClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://localhost:50051".to_string(),
            client_cert_pem: String::new(),
            client_key_pem: Zeroizing::new(String::new()),
            ca_cert_pem: String::new(),
            server_name: None,
            allow_plaintext: false,
            connect_timeout_ms: 5000,
            request_timeout_ms: 30000,
            max_retries: 3,
            retry_initial_backoff_ms: 100,
            retry_max_backoff_ms: 5000,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_ms: 60000,
        }
    }
}

/// How [`CaGrpcClient::new`] will connect, after validating the config.
#[derive(Debug, PartialEq, Eq)]
enum ChannelPlan {
    /// TLS 1.3 mTLS, verifying the server against this name.
    Mtls { server_name: String },
    /// Plaintext HTTP/2 (explicitly allowed, `http://` endpoint).
    Plaintext,
}

/// Validate the transport settings of a client config (fail closed).
///
/// NIST 800-53: SC-8 / AC-17 / CM-6 - partial material, plaintext without the
/// explicit flag, plaintext in a release build (`release_build`), and
/// scheme/material mismatches are all errors.
fn plan_channel(
    config: &GrpcClientConfig,
    uri: &tonic::codegen::http::Uri,
    release_build: bool,
) -> Result<ChannelPlan> {
    let present = [
        !config.client_cert_pem.is_empty(),
        !config.client_key_pem.is_empty(),
        !config.ca_cert_pem.is_empty(),
    ];
    let scheme = uri.scheme_str().unwrap_or_default();
    match present.iter().filter(|p| **p).count() {
        3 => {
            if scheme != "https" {
                return Err(Error::InvalidConfiguration(format!(
                    "gRPC mTLS requires an https:// endpoint, got '{}'",
                    config.endpoint
                )));
            }
            let server_name = match config.server_name.as_deref().map(str::trim) {
                Some(name) if !name.is_empty() => name.to_string(),
                _ => endpoint_host(uri).ok_or_else(|| {
                    Error::InvalidConfiguration(format!(
                        "gRPC endpoint '{}' has no host to use as TLS server name",
                        config.endpoint
                    ))
                })?,
            };
            Ok(ChannelPlan::Mtls { server_name })
        }
        0 => {
            if !config.allow_plaintext {
                return Err(Error::InvalidConfiguration(format!(
                    "refusing a plaintext gRPC channel to '{}': configure the mTLS client \
                     certificate, client key and CA certificate (NIST 800-53: SC-8, AC-17)",
                    config.endpoint
                )));
            }
            if release_build {
                return Err(Error::InvalidConfiguration(format!(
                    "refusing a plaintext gRPC channel to '{}': plaintext is a development \
                     escape hatch and is not available in release builds; configure the mTLS \
                     client certificate, client key and CA certificate (NIST 800-53: SC-8, \
                     AC-17, CM-6)",
                    config.endpoint
                )));
            }
            if scheme != "http" {
                return Err(Error::InvalidConfiguration(format!(
                    "plaintext gRPC requires an http:// endpoint, got '{}'",
                    config.endpoint
                )));
            }
            Ok(ChannelPlan::Plaintext)
        }
        _ => Err(Error::InvalidConfiguration(
            "partial gRPC mTLS configuration: client certificate, client key and CA \
             certificate are all required"
                .to_string(),
        )),
    }
}

/// Read a private-key PEM file directly into zeroize-on-drop memory.
///
/// The buffer is pre-sized from the file length so it does not reallocate
/// (which would leave unzeroized copies of partial key text behind). The error
/// names the path only, never contents.
///
/// NIST 800-53: SI-12 (Information Handling), SC-12, IA-5.
pub fn read_private_key_pem(path: &std::path::Path) -> Result<Zeroizing<String>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| Error::Config(format!("Failed to open key file {}: {e}", path.display())))?;
    let len = file
        .metadata()
        .map(|m| usize::try_from(m.len()).unwrap_or(0))
        .unwrap_or(0);
    let mut buf = Zeroizing::new(String::with_capacity(len.saturating_add(1)));
    file.read_to_string(&mut buf)
        .map_err(|e| Error::Config(format!("Failed to read key file {}: {e}", path.display())))?;
    Ok(buf)
}

/// Render an error with its source chain (the TLS cause sits in the sources).
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}

/// Circuit breaker states
///
/// NIST 800-53: SI-17 - Fail-secure design
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Too many failures, blocking requests
    Open { opened_at: Instant },
    /// Testing if service recovered
    HalfOpen,
}

/// Circuit breaker for service resilience
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SI-17 - Fail-secure state preservation
/// - NIST 800-53: SC-5 - Denial of service protection
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU64,
    threshold: u32,
    timeout: Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(threshold: u32, timeout: Duration) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            threshold,
            timeout,
        }
    }

    /// Check if a request is allowed
    ///
    /// NIST 800-53: SI-17 - Fail-secure check before operation
    pub async fn is_request_allowed(&self) -> Result<()> {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open { opened_at } => {
                // Check if timeout elapsed
                if opened_at.elapsed() >= self.timeout {
                    *state = CircuitState::HalfOpen;
                    Ok(())
                } else {
                    Err(Error::ServiceUnavailable(
                        "Circuit breaker is open".to_string(),
                    ))
                }
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    /// Record a successful request
    pub async fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        let mut state = self.state.write().await;
        *state = CircuitState::Closed;
    }

    /// Record a failed request
    ///
    /// NIST 800-53: SI-17 - Automatic failure handling
    pub async fn record_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        if failures >= self.threshold as u64 {
            let mut state = self.state.write().await;
            *state = CircuitState::Open {
                opened_at: Instant::now(),
            };
            tracing::warn!(
                failures = failures,
                threshold = self.threshold,
                "Circuit breaker opened due to failures"
            );
        }
    }

    /// Get current state (for testing/monitoring)
    pub async fn state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

/// CA gRPC client with resilience patterns
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8 - Transmission confidentiality (mTLS)
/// - NIST 800-53: SC-12 - Cryptographic key management
/// - NIST 800-53: SI-10 - Information input validation
pub struct CaGrpcClient {
    channel: Channel,
    circuit_breaker: Arc<CircuitBreaker>,
    config: GrpcClientConfig,
}

impl CaGrpcClient {
    /// Create a new CA gRPC client
    ///
    /// With mTLS material the channel is TLS 1.3 only, uses the aws-lc-rs FIPS
    /// provider (`fips()` asserted on the exact config used), presents the
    /// client certificate, verifies the server against `server_name` (default:
    /// the URL host) and requires ALPN `h2`. Without material it connects in
    /// plaintext only when `allow_plaintext` is set and the endpoint is
    /// `http://`. The connection is established eagerly, so a TLS failure
    /// surfaces here.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-8(1) - Establish mTLS connection
    /// - NIST 800-53: IA-5(2) - PKI-based authentication
    /// - NIST 800-53: SC-13 - FIPS provider asserted
    /// - NIAP PP-CA: FCS_TLSC_EXT.2, FTP_ITC.1
    pub async fn new(config: GrpcClientConfig) -> Result<Self> {
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|e| Error::InvalidConfiguration(format!("Invalid endpoint: {}", e)))?
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms));

        let channel = match plan_channel(&config, endpoint.uri(), !cfg!(debug_assertions))? {
            ChannelPlan::Mtls { server_name } => {
                let tls = grpc_client_config(
                    &config.client_cert_pem,
                    &config.client_key_pem,
                    &config.ca_cert_pem,
                )?;
                let connector = GrpcTlsConnector::new(tls, &server_name)?;
                tracing::info!(
                    endpoint = %config.endpoint,
                    server_name = %server_name,
                    fips = true,
                    tls = "1.3",
                    mtls = true,
                    "Connecting to CA gRPC service"
                );
                endpoint.connect_with_connector(connector).await
            }
            ChannelPlan::Plaintext => {
                tracing::warn!(
                    endpoint = %config.endpoint,
                    "gRPC channel WITHOUT TLS (allow_plaintext) - development only; \
                     configure client_cert_pem/client_key_pem/ca_cert_pem for production \
                     (NIST 800-53: SC-8, AC-17)"
                );
                endpoint.connect().await
            }
        }
        .map_err(|e| {
            Error::ServiceUnavailable(format!("Failed to connect: {}", error_chain(&e)))
        })?;

        // Create circuit breaker
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            config.circuit_breaker_threshold,
            Duration::from_millis(config.circuit_breaker_timeout_ms),
        ));

        Ok(Self {
            channel,
            circuit_breaker,
            config,
        })
    }

    /// Get the underlying channel for creating gRPC service clients
    ///
    /// This method should be used by service-specific implementations
    /// (ACME, EST, SCMS) to create their own typed gRPC clients.
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Execute a gRPC request with retry logic and circuit breaker
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SI-17 - Fail-secure retry logic
    /// - NIST 800-53: SC-23 - Session authenticity preservation
    ///
    /// # Arguments
    /// * `f` - Async closure that performs the gRPC call
    ///
    /// # Returns
    /// Result of the gRPC call, or error after exhausting retries
    pub async fn with_retry<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, Status>>,
    {
        // Check circuit breaker
        self.circuit_breaker.is_request_allowed().await?;

        let mut attempt = 0;
        let mut backoff_ms = self.config.retry_initial_backoff_ms;

        loop {
            attempt += 1;

            match f().await {
                Ok(response) => {
                    // Success - reset circuit breaker
                    self.circuit_breaker.record_success().await;
                    return Ok(response);
                }
                Err(status) => {
                    // Check if error is retryable
                    let is_retryable = Self::is_retryable_error(&status);

                    if !is_retryable || attempt >= self.config.max_retries {
                        // Non-retryable or exhausted retries
                        self.circuit_breaker.record_failure().await;

                        return Err(Error::GrpcError(format!(
                            "gRPC call failed after {} attempts: {}",
                            attempt, status
                        )));
                    }

                    // Retryable error - backoff and retry
                    tracing::warn!(
                        attempt = attempt,
                        max_retries = self.config.max_retries,
                        backoff_ms = backoff_ms,
                        error = %status,
                        "gRPC call failed, retrying"
                    );

                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                    // Exponential backoff with cap
                    backoff_ms = (backoff_ms * 2).min(self.config.retry_max_backoff_ms);
                }
            }
        }
    }

    /// Check if a gRPC error is retryable
    ///
    /// NIST 800-53: SI-10 - Error categorization
    fn is_retryable_error(status: &Status) -> bool {
        matches!(
            status.code(),
            tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::ResourceExhausted
                | tonic::Code::Aborted
        )
    }

    /// Get circuit breaker for testing/monitoring
    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        self.circuit_breaker.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_state_transitions() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(100));

        // Initial state: Closed
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.is_request_allowed().await.is_ok());

        // Record failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        // Third failure opens circuit
        cb.record_failure().await;
        assert!(matches!(cb.state().await, CircuitState::Open { .. }));
        assert!(cb.is_request_allowed().await.is_err());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Circuit should transition to HalfOpen
        assert!(cb.is_request_allowed().await.is_ok());
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Success closes circuit
        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[test]
    fn test_default_config() {
        let config = GrpcClientConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.circuit_breaker_threshold, 5);
        assert_eq!(config.connect_timeout_ms, 5000);
        assert!(!config.allow_plaintext, "plaintext must be opt-in");
        assert!(config.server_name.is_none());
    }

    const KEY_TEXT: &str =
        "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----";

    fn cfg(endpoint: &str, cert: bool, key: bool, ca: bool, plaintext: bool) -> GrpcClientConfig {
        GrpcClientConfig {
            endpoint: endpoint.to_string(),
            client_cert_pem: if cert { "CERT".into() } else { String::new() },
            client_key_pem: Zeroizing::new(if key { KEY_TEXT.into() } else { String::new() }),
            ca_cert_pem: if ca { "CA".into() } else { String::new() },
            allow_plaintext: plaintext,
            ..Default::default()
        }
    }

    /// SI-12: `Debug` never prints the private key.
    #[test]
    fn debug_redacts_private_key() {
        let printed = format!("{:?}", cfg("https://ca:50051", true, true, true, false));
        assert!(!printed.contains("SECRETKEYMATERIAL"), "{printed}");
        assert!(!printed.contains("PRIVATE KEY"), "{printed}");
        assert!(printed.contains("<redacted>"));
    }

    fn plan(c: &GrpcClientConfig) -> Result<ChannelPlan> {
        let uri: tonic::codegen::http::Uri = c.endpoint.parse().expect("uri");
        plan_channel(c, &uri, false)
    }

    /// CM-6 / SC-8: a release build refuses the plaintext channel even with
    /// `allow_plaintext`, and still plans mTLS.
    #[test]
    fn plan_channel_refuses_plaintext_in_release_builds() {
        let plain = cfg("http://127.0.0.1:50051", false, false, false, true);
        let uri: tonic::codegen::http::Uri = plain.endpoint.parse().expect("uri");
        let err = plan_channel(&plain, &uri, true).expect_err("release plaintext");
        assert!(err.to_string().contains("release builds"), "{err}");
        let mtls = cfg("https://ca-service:50051", true, true, true, true);
        let uri: tonic::codegen::http::Uri = mtls.endpoint.parse().expect("uri");
        assert!(matches!(
            plan_channel(&mtls, &uri, true),
            Ok(ChannelPlan::Mtls { .. })
        ));
    }

    /// SC-8 / CM-6: the transport plan fails closed.
    #[test]
    fn plan_channel_truth_table() {
        assert_eq!(
            plan(&cfg("https://ca-service:50051", true, true, true, false)).expect("mtls"),
            ChannelPlan::Mtls {
                server_name: "ca-service".to_string()
            }
        );
        let mut named = cfg("https://10.0.0.5:50051", true, true, true, false);
        named.server_name = Some("ca-service".to_string());
        assert_eq!(
            plan(&named).expect("named"),
            ChannelPlan::Mtls {
                server_name: "ca-service".to_string()
            }
        );
        assert_eq!(
            plan(&cfg("http://127.0.0.1:50051", false, false, false, true)).expect("plain"),
            ChannelPlan::Plaintext
        );
        // partial material
        assert!(plan(&cfg("https://ca:50051", true, false, true, false)).is_err());
        assert!(plan(&cfg("https://ca:50051", false, true, false, true)).is_err());
        // no material without allow_plaintext
        assert!(plan(&cfg("http://ca:50051", false, false, false, false)).is_err());
        // https + plaintext
        assert!(plan(&cfg("https://ca:50051", false, false, false, true)).is_err());
        // http + material
        assert!(plan(&cfg("http://ca:50051", true, true, true, false)).is_err());
    }

    #[test]
    fn read_private_key_pem_reads_and_reports_path_only() {
        let path = std::env::temp_dir().join(format!("ostrich-keypem-{}.pem", std::process::id()));
        std::fs::write(&path, KEY_TEXT).expect("write");
        assert_eq!(
            read_private_key_pem(&path).expect("read").as_str(),
            KEY_TEXT
        );
        std::fs::remove_file(&path).expect("rm");
        let err = read_private_key_pem(&path)
            .expect_err("missing")
            .to_string();
        assert!(err.contains("ostrich-keypem"));
    }

    /// `CaGrpcClient::new` rejects invalid transport configs before dialling.
    #[tokio::test]
    async fn new_rejects_invalid_transport_configs() {
        for c in [
            cfg("https://ca:50051", true, false, true, false),
            cfg("http://ca:50051", false, false, false, false),
            cfg("https://ca:50051", false, false, false, true),
            cfg("http://ca:50051", true, true, true, false),
        ] {
            let err = CaGrpcClient::new(c).await.err().expect("must fail");
            assert!(
                matches!(err, Error::InvalidConfiguration(_)),
                "unexpected error: {err}"
            );
            assert!(!err.to_string().contains("SECRETKEYMATERIAL"));
        }
        // Material present but not valid PEM: a config error, never the key text.
        let err = CaGrpcClient::new(cfg("https://ca:50051", true, true, true, false))
            .await
            .err()
            .expect("bad pem");
        assert!(!err.to_string().contains("SECRETKEYMATERIAL"), "{err}");
    }

    #[test]
    fn test_retryable_error_classification() {
        assert!(CaGrpcClient::is_retryable_error(&Status::unavailable(
            "service down"
        )));
        assert!(CaGrpcClient::is_retryable_error(
            &Status::deadline_exceeded("timeout")
        ));
        assert!(!CaGrpcClient::is_retryable_error(
            &Status::invalid_argument("bad request")
        ));
        assert!(!CaGrpcClient::is_retryable_error(&Status::not_found(
            "not found"
        )));
    }
}
