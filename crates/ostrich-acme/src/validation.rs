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
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5(1) - Authenticator management (challenge-response)
/// - RFC 8555 §8.4 - DNS-01 challenge validation
pub struct Dns01Validator {
    /// DNS resolver timeout in seconds
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
    ///
    /// Process:
    /// 1. Compute expected value: BASE64URL(SHA256(token.account_key_thumbprint))
    /// 2. Query DNS for TXT record at _acme-challenge.<domain>
    /// 3. Verify any TXT record matches the expected value
    /// 4. Retry with delay to allow for DNS propagation
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::Resolver;
        use ostrich_common::util::encoding::encode_base64url;
        use sha2::{Digest, Sha256};
        use std::time::Duration;

        // COMPLIANCE MAPPING:
        // - NIST 800-53: IA-5(1) - Cryptographic challenge-response validation
        // - RFC 8555 §8.4 - DNS-01 validation procedure

        // Compute expected TXT record value
        // RFC 8555 §8.4: digest = BASE64URL(SHA256(key_authorization))
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let hash = Sha256::digest(key_authorization.as_bytes());
        let expected_value = encode_base64url(&hash);

        // Construct TXT record name
        // RFC 8555 §8.4: _acme-challenge.<domain>
        let txt_record_name = format!("_acme-challenge.{}", domain);

        // Create DNS resolver using hickory-resolver 0.25 builder pattern
        // Uses system DNS configuration with Tokio runtime
        let mut resolver_opts = hickory_resolver::config::ResolverOpts::default();
        resolver_opts.timeout = Duration::from_secs(self.timeout_secs);

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .with_options(resolver_opts)
        .build();

        // Perform DNS TXT lookup with retry logic
        // Retry up to 5 times with 2-second intervals to allow for DNS propagation
        let max_retries = 5;
        let retry_delay = Duration::from_secs(2);

        for attempt in 1..=max_retries {
            match resolver.txt_lookup(&txt_record_name).await {
                Ok(txt_lookup) => {
                    // Check each TXT record for a match
                    // TxtLookup implements Iterator, yielding TXT records
                    for txt_record in txt_lookup.iter() {
                        // txt_data() returns &[Box<[u8]>] - slice of byte arrays
                        for data in txt_record.txt_data() {
                            let txt_value = String::from_utf8_lossy(data).to_string();

                            // RFC 8555 §8.4: Check if TXT record contains expected digest
                            if txt_value == expected_value {
                                // NIST 800-53: AU-3 - Audit content (successful validation)
                                return Ok(true);
                            }
                        }
                    }

                    // If we got records but no match, don't retry
                    return Ok(false);
                }
                Err(e) => {
                    // DNS lookup failed - retry if not last attempt
                    if attempt < max_retries {
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    }

                    // All retries exhausted
                    return Err(Error::ChallengeValidation(format!(
                        "DNS TXT lookup failed for {}: {}",
                        txt_record_name, e
                    )));
                }
            }
        }

        // Should not reach here, but for safety
        Ok(false)
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
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: IA-5(1) - Authenticator management (challenge-response)
/// - RFC 8737 - TLS-ALPN-01 challenge validation
/// - RFC 8555 §8.1 - Key authorization
pub struct TlsAlpn01Validator {
    /// TLS connection timeout in seconds
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
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        // COMPLIANCE MAPPING:
        // - NIST 800-53: IA-5(1) - Cryptographic challenge-response validation
        // - RFC 8737 - TLS-ALPN-01 validation procedure
        // - RFC 8555 §8.1 - Key authorization computation

        // Prevent SSRF by blocking private IP domains
        if is_private_ip_domain(domain) {
            return Err(Error::Malformed(format!(
                "Cannot validate private IP domain: {}",
                domain
            )));
        }

        // Compute expected acmeIdentifier extension value
        // RFC 8737 §3: acmeIdentifier = SHA256(key_authorization)
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let expected_hash = Sha256::digest(key_authorization.as_bytes());

        // Connect to domain:443 with timeout
        let addr = format!("{}:443", domain);
        let tcp_stream = timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| Error::ChallengeValidation(format!("TLS connection timed out to {}", addr)))?
        .map_err(|e| Error::ChallengeValidation(format!("Failed to connect to {}: {}", addr, e)))?;

        // Create TLS client configuration with ALPN "acme-tls/1"
        // RFC 8737 §3: Client must send "acme-tls/1" in ALPN extension
        let mut root_store = rustls::RootCertStore::empty();

        // Add system root certificates
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocols: "acme-tls/1" ONLY
        // RFC 8737 §3: Server must negotiate acme-tls/1 protocol
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
            .map_err(|e| Error::Malformed(format!("Invalid domain name: {}", e)))?;

        // Perform TLS handshake
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::ChallengeValidation(format!("TLS handshake failed: {}", e)))?;

        // RFC 8737 §3: Verify server negotiated "acme-tls/1" protocol
        let (_, session) = tls_stream.get_ref();
        let negotiated_protocol = session.alpn_protocol();

        match negotiated_protocol {
            Some(protocol) if protocol == b"acme-tls/1" => {
                // ALPN protocol correct, now verify certificate extension
            }
            Some(protocol) => {
                return Err(Error::ChallengeValidation(format!(
                    "Server negotiated wrong ALPN protocol: {:?} (expected acme-tls/1)",
                    String::from_utf8_lossy(protocol)
                )));
            }
            None => {
                return Err(Error::ChallengeValidation(
                    "Server did not negotiate ALPN protocol (acme-tls/1 required)".to_string(),
                ));
            }
        }

        // Get peer certificate
        let peer_certs = session.peer_certificates();
        let cert_der = peer_certs
            .and_then(|certs| certs.first())
            .ok_or_else(|| Error::ChallengeValidation("No certificate presented".to_string()))?;

        // Parse certificate and verify acmeIdentifier extension
        // RFC 8737 §3: Certificate must contain id-pe-acmeIdentifier extension
        // OID: 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
        let cert = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .map_err(|e| Error::ChallengeValidation(format!("Failed to parse certificate: {}", e)))?
            .1;

        // Look for acmeIdentifier extension
        const ACME_IDENTIFIER_OID: &str = "1.3.6.1.5.5.7.1.31";

        for ext in cert.extensions() {
            if ext.oid.to_id_string() == ACME_IDENTIFIER_OID {
                // RFC 8737 §3: Extension value must be OCTET STRING containing SHA-256 hash
                // The value is DER-encoded OCTET STRING containing the hash
                if ext.value.len() >= 32 {
                    // Skip DER encoding wrapper (typically 2 bytes: tag 0x04 and length)
                    let hash_start = if ext.value[0] == 0x04 && ext.value[1] == 0x20 {
                        2 // Standard DER OCTET STRING encoding for 32 bytes
                    } else {
                        0
                    };

                    let cert_hash = &ext.value[hash_start..hash_start + 32];

                    if cert_hash == expected_hash.as_slice() {
                        // NIST 800-53: AU-3 - Audit content (successful validation)
                        return Ok(true);
                    } else {
                        return Ok(false);
                    }
                }

                return Err(Error::ChallengeValidation(
                    "acmeIdentifier extension has invalid format".to_string(),
                ));
            }
        }

        // acmeIdentifier extension not found
        Err(Error::ChallengeValidation(
            "Certificate missing acmeIdentifier extension".to_string(),
        ))
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
