//! ACME challenge validation
//!
//! RFC 8555 §8 - Challenge validation methods
//! NIST 800-53: IA-5 - Authenticator management

use crate::{Error, Result};
use std::time::Duration;

/// HTTP-01 challenge validator (RFC 8555 §8.3)
///
/// Validates domain control by fetching a token from a well-known HTTP endpoint.
///
/// Process:
/// 1. Construct URL: http://<domain>/.well-known/acme-challenge/<token>
/// 2. Perform HTTP GET request with 10-second timeout
/// 3. Verify response body equals: <token>.<account_key_thumbprint>
/// 4. Follow HTTP redirects (max 10)
/// 5. Accept response with status 200 OK
///
/// Security considerations:
/// - Prevent SSRF by blocking private IP ranges
/// - Use DNS resolution to detect private IPs
/// - Enforce timeout to prevent DoS
/// - Follow redirects with limit
pub struct Http01Validator {
    /// HTTP client with timeout
    client: reqwest::Client,
    /// Maximum number of redirects to follow
    #[allow(dead_code)]
    max_redirects: usize,
    /// Request timeout in seconds
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl Http01Validator {
    /// Create new HTTP-01 validator
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("OstrichPKI-ACME/0.10.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            max_redirects: 10,
            timeout_secs: 10,
        }
    }

    /// Validate HTTP-01 challenge
    ///
    /// RFC 8555 §8.3 - HTTP challenge validation
    /// NIST 800-53: IA-5(1) - Challenge-response authentication
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        // Construct expected response
        let expected_response = format!("{}.{}", token, account_key_thumbprint);

        // Construct challenge URL
        let url = format!("http://{}/.well-known/acme-challenge/{}", domain, token);

        // TODO: Validate domain is not a private IP (SSRF prevention)
        // TODO: Perform DNS lookup and check for private IP ranges
        // For now, we'll just block obvious private IP patterns
        if is_private_ip_domain(domain) {
            return Err(Error::Malformed(format!(
                "Cannot validate private IP domain: {}",
                domain
            )));
        }

        // Perform HTTP GET request
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::ChallengeValidation(format!("HTTP request failed: {}", e)))?;

        // Check status code
        if !response.status().is_success() {
            return Err(Error::ChallengeValidation(format!(
                "HTTP challenge returned status {}: expected 200 OK",
                response.status()
            )));
        }

        // Get response body
        let body = response
            .text()
            .await
            .map_err(|e| Error::ChallengeValidation(format!("Failed to read response: {}", e)))?;

        // Verify response matches expected
        Ok(body.trim() == expected_response)
    }
}

impl Default for Http01Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS-01 challenge validator (RFC 8555 §8.4)
///
/// Validates domain control by checking for a TXT record at _acme-challenge.<domain>
///
/// Process:
/// 1. Construct TXT record name: _acme-challenge.<domain>
/// 2. Query DNS for TXT records
/// 3. Compute expected value: Base64URL(SHA256(<token>.<account_key_thumbprint>))
/// 4. Verify at least one TXT record matches expected value
/// 5. Use recursive DNS resolver (system default)
///
/// Security considerations:
/// - Use DNSSEC if available
/// - Query multiple nameservers if possible
/// - Enforce timeout to prevent DoS
pub struct Dns01Validator {
    /// DNS resolver timeout in seconds
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl Dns01Validator {
    /// Create new DNS-01 validator
    pub fn new() -> Self {
        Self { timeout_secs: 30 }
    }

    /// Validate DNS-01 challenge
    ///
    /// RFC 8555 §8.4 - DNS challenge validation
    /// NIST 800-53: IA-5(1) - Challenge-response authentication
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        use ostrich_common::util::encoding::encode_base64url;
        use sha2::{Digest, Sha256};

        // Compute expected TXT record value
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let hash = Sha256::digest(key_authorization.as_bytes());
        let expected_value = encode_base64url(&hash);

        // Construct TXT record name
        let txt_record_name = format!("_acme-challenge.{}", domain);

        // TODO: Implement DNS TXT record lookup
        // This requires adding trust-dns-resolver or similar DNS client
        // For now, return error indicating not implemented
        Err(Error::ChallengeValidation(format!(
            "DNS-01 validation not yet implemented (would query {} for {})",
            txt_record_name, expected_value
        )))
    }
}

impl Default for Dns01Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS-ALPN-01 challenge validator (RFC 8737)
///
/// Validates domain control by checking for a special ALPN protocol and certificate extension
/// during TLS handshake.
///
/// Process:
/// 1. Connect to <domain>:443 with TLS
/// 2. Send ALPN extension with protocol "acme-tls/1"
/// 3. Verify server responds with "acme-tls/1" protocol
/// 4. Verify certificate has acmeIdentifier extension with SHA256 hash
/// 5. Hash = SHA256(<token>.<account_key_thumbprint>)
///
/// Security considerations:
/// - Verify certificate chain
/// - Check for proper ALPN protocol
/// - Enforce timeout to prevent DoS
/// - Prevent SSRF by blocking private IPs
pub struct TlsAlpn01Validator {
    /// TLS connection timeout in seconds
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl TlsAlpn01Validator {
    /// Create new TLS-ALPN-01 validator
    pub fn new() -> Self {
        Self { timeout_secs: 10 }
    }

    /// Validate TLS-ALPN-01 challenge
    ///
    /// RFC 8737 - TLS-ALPN challenge validation
    /// NIST 800-53: IA-5(1) - Challenge-response authentication
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        use sha2::{Digest, Sha256};

        // Compute expected acmeIdentifier extension value
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let _expected_hash = Sha256::digest(key_authorization.as_bytes());

        // TODO: Implement TLS-ALPN connection with "acme-tls/1" protocol
        // This requires tokio-rustls or similar TLS client
        // For now, return error indicating not implemented
        Err(Error::ChallengeValidation(format!(
            "TLS-ALPN-01 validation not yet implemented (would connect to {}:443)",
            domain
        )))
    }
}

impl Default for TlsAlpn01Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if domain appears to be a private IP address
///
/// This is a basic check - production code should do DNS resolution
/// and check the resolved IP against private ranges.
fn is_private_ip_domain(domain: &str) -> bool {
    // Check for localhost variants
    if domain == "localhost"
        || domain == "localhost.localdomain"
        || domain.ends_with(".local")
        || domain.ends_with(".localhost")
    {
        return true;
    }

    // Check for obvious private IP patterns
    // TODO: This should be replaced with proper DNS resolution + IP range checking
    if domain.starts_with("10.")
        || domain.starts_with("192.168.")
        || domain.starts_with("172.16.")
        || domain.starts_with("172.17.")
        || domain.starts_with("172.18.")
        || domain.starts_with("172.19.")
        || domain.starts_with("172.20.")
        || domain.starts_with("172.21.")
        || domain.starts_with("172.22.")
        || domain.starts_with("172.23.")
        || domain.starts_with("172.24.")
        || domain.starts_with("172.25.")
        || domain.starts_with("172.26.")
        || domain.starts_with("172.27.")
        || domain.starts_with("172.28.")
        || domain.starts_with("172.29.")
        || domain.starts_with("172.30.")
        || domain.starts_with("172.31.")
        || domain.starts_with("127.")
        || domain == "::1"
        || domain.starts_with("fe80:")
        || domain.starts_with("fc00:")
        || domain.starts_with("fd00:")
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip_domain() {
        assert!(is_private_ip_domain("localhost"));
        assert!(is_private_ip_domain("127.0.0.1"));
        assert!(is_private_ip_domain("10.0.0.1"));
        assert!(is_private_ip_domain("192.168.1.1"));
        assert!(is_private_ip_domain("172.16.0.1"));
        assert!(is_private_ip_domain("test.local"));

        assert!(!is_private_ip_domain("example.com"));
        assert!(!is_private_ip_domain("192.167.1.1")); // Not in private range
        assert!(!is_private_ip_domain("8.8.8.8"));
    }

    #[tokio::test]
    async fn test_http01_validator_creation() {
        let validator = Http01Validator::new();
        assert_eq!(validator.max_redirects, 10);
        assert_eq!(validator.timeout_secs, 10);
    }

    #[tokio::test]
    async fn test_dns01_validator_not_implemented() {
        let validator = Dns01Validator::new();
        let result = validator
            .validate("example.com", "test-token", "test-thumbprint")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tls_alpn_validator_not_implemented() {
        let validator = TlsAlpn01Validator::new();
        let result = validator
            .validate("example.com", "test-token", "test-thumbprint")
            .await;
        assert!(result.is_err());
    }
}
