//! gRPC client infrastructure with resilience patterns
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8 (Transmission confidentiality via mTLS)
//! - NIST 800-53: SC-23 (Session authenticity)
//! - NIST 800-53: SI-10 (Information input validation)

use crate::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Status;

/// gRPC client configuration
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8(1) - Cryptographic protection for transmission
#[derive(Debug, Clone)]
pub struct GrpcClientConfig {
    /// CA gRPC server endpoint (e.g., "https://ca.example.com:50051")
    pub endpoint: String,

    /// mTLS client certificate (PEM-encoded)
    pub client_cert_pem: String,

    /// mTLS client private key (PEM-encoded)
    pub client_key_pem: String,

    /// CA certificate for server verification (PEM-encoded)
    pub ca_cert_pem: String,

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

impl Default for GrpcClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://localhost:50051".to_string(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
            ca_cert_pem: String::new(),
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
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SC-8(1) - Establish mTLS connection
    /// - NIST 800-53: IA-5(2) - PKI-based authentication
    pub async fn new(config: GrpcClientConfig) -> Result<Self> {
        // Load client certificate and key
        let client_identity = Identity::from_pem(&config.client_cert_pem, &config.client_key_pem);

        // Load CA certificate for server verification
        let ca_cert = Certificate::from_pem(&config.ca_cert_pem);

        // Configure mTLS
        let tls_config = ClientTlsConfig::new()
            .identity(client_identity)
            .ca_certificate(ca_cert)
            .domain_name("ostrich-ca"); // SNI hostname

        // Create channel with timeouts
        let channel = Channel::from_shared(config.endpoint.clone())
            .map_err(|e| Error::InvalidConfiguration(format!("Invalid endpoint: {}", e)))?
            .tls_config(tls_config)
            .map_err(|e| Error::InvalidConfiguration(format!("TLS config error: {}", e)))?
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .connect()
            .await
            .map_err(|e| Error::ServiceUnavailable(format!("Failed to connect: {}", e)))?;

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
