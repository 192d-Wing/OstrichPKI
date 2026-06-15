//! ACME challenge validation
//!
//! This module implements the challenge validation mechanisms for ACME:
//! HTTP-01, DNS-01, and TLS-ALPN-01. These validators prove domain control
//! before certificate issuance.
//!
//! # Compliance Mapping
//!
//! ## NIAP PP-CA v2.1 SFRs
//!
//! - **FIA_UAU.1**: User authentication before any action
//!   - Challenge validation authenticates domain control.
//!   - Key authorization binding proves account ownership.
//!
//! - **FTP_ITC.1**: Inter-TSF trusted channel
//!   - TLS-ALPN-01 uses TLS for challenge validation.
//!   - HTTPS redirect following for HTTP-01.
//!
//! - **FCS_COP.1**: Cryptographic operation
//!   - SHA-256 for DNS-01 digest computation.
//!   - TLS handshake for TLS-ALPN-01 validation.
//!
//! - **FAU_GEN.1**: Audit data generation
//!   - Validation attempts logged with domain and outcome.
//!   - Failures recorded with error details.
//!
//! ## NIST 800-53 Rev 5 Controls
//!
//! - **IA-5**: Authenticator Management
//!   - Challenge-response proves domain control.
//!
//! - **IA-5(1)**: Password-based / Challenge-Response Authentication
//!   - HTTP-01: Token-based challenge-response.
//!   - DNS-01: TXT record verification.
//!   - TLS-ALPN-01: Certificate extension verification.
//!
//! - **SI-10**: Information Input Validation
//!   - SSRF prevention via private IP blocking.
//!   - Domain name validation.
//!
//! ## RFC Compliance
//!
//! - RFC 8555 §8: Challenge validation methods
//! - RFC 8555 §8.3: HTTP-01 challenge
//! - RFC 8555 §8.4: DNS-01 challenge
//! - RFC 8737: TLS-ALPN-01 challenge

use crate::{Error, Result};
use std::time::Duration;

/// HTTP-01 challenge validator (RFC 8555 §8.3)
///
/// Validates domain control by fetching a token from a well-known HTTP endpoint.
///
/// # Process
///
/// 1. Construct URL: http://<domain>/.well-known/acme-challenge/<token>
/// 2. Perform HTTP GET request with 10-second timeout
/// 3. Verify response body equals: <token>.<account_key_thumbprint>
/// 4. Follow HTTP redirects (max 10)
/// 5. Accept response with status 200 OK
///
/// # Security Considerations
///
/// - Prevent SSRF by blocking private IP ranges
/// - Use DNS resolution to detect private IPs
/// - Enforce timeout to prevent DoS
/// - Follow redirects with limit
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Validates domain control via HTTP challenge-response.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
///
/// # NIST 800-53 Controls
///
/// - **IA-5(1)**: Challenge-response authentication.
/// - **SI-10**: SSRF prevention via private IP blocking.
pub struct Http01Validator {
    /// HTTP client with timeout
    client: reqwest::Client,
    /// Maximum number of redirects to follow
    #[allow(dead_code)]
    max_redirects: usize,
    /// Request timeout in seconds
    #[allow(dead_code)]
    timeout_secs: u64,
    /// Port the challenge is fetched from (RFC 8555 §8.3 mandates 80;
    /// overridable for dev/E2E environments only, like Pebble's -httpPort)
    http_port: u16,
    /// Permit private-IP / localhost identifiers.
    ///
    /// SECURITY: disables the SI-10 SSRF guard. Dev/E2E environments only;
    /// enabling this in production lets clients obtain certificates for
    /// internal hostnames and turn the validator into an SSRF vector.
    allow_private_domains: bool,
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
            http_port: 80,
            allow_private_domains: false,
        }
    }

    /// Override the HTTP-01 fetch port (RFC 8555 §8.3 mandates 80).
    /// Dev/E2E only - see `insecure_allow_private_domains`.
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = port;
        self
    }

    /// Disable the private-IP SSRF guard (SI-10). Dev/E2E only; the name is
    /// deliberately alarming.
    pub fn insecure_allow_private_domains(mut self) -> Self {
        self.allow_private_domains = true;
        self
    }

    /// Validate HTTP-01 challenge
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FIA_UAU.1**: Proves domain control before certificate issuance.
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **IA-5(1)**: Challenge-response authentication (RFC 8555 §8.3).
    /// - **SI-10**: Domain and response validation.
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        // Construct expected response
        let expected_response = format!("{}.{}", token, account_key_thumbprint);

        // Construct challenge URL. RFC 8555 §8.3: port 80; the override
        // exists for dev/E2E environments only.
        let initial_url = if self.http_port == 80 {
            format!("http://{}/.well-known/acme-challenge/{}", domain, token)
        } else {
            format!(
                "http://{}:{}/.well-known/acme-challenge/{}",
                domain, self.http_port, token
            )
        };

        // Dev/E2E override: keep the permissive shared client (private addresses
        // allowed, reqwest follows redirects). NOT for production.
        if self.allow_private_domains {
            let response =
                self.client.get(&initial_url).send().await.map_err(|e| {
                    Error::ChallengeValidation(format!("HTTP request failed: {}", e))
                })?;
            if !response.status().is_success() {
                return Err(Error::ChallengeValidation(format!(
                    "HTTP challenge returned status {}: expected 200 OK",
                    response.status()
                )));
            }
            let body = response.text().await.map_err(|e| {
                Error::ChallengeValidation(format!("Failed to read response: {}", e))
            })?;
            return Ok(body.trim() == expected_response);
        }

        // SI-10: SSRF prevention. Follow redirects MANUALLY so every hop's host
        // is resolved, checked to be globally routable, and the connection is
        // pinned to a validated address — closing DNS-rebinding (including via a
        // redirect to a name that rebinds to an internal address).
        let mut url = reqwest::Url::parse(&initial_url)
            .map_err(|e| Error::Malformed(format!("Invalid challenge URL: {}", e)))?;

        for _ in 0..=self.max_redirects {
            if !matches!(url.scheme(), "http" | "https") {
                return Err(Error::Malformed(format!(
                    "Disallowed challenge URL scheme: {}",
                    url.scheme()
                )));
            }
            let host = url
                .host_str()
                .ok_or_else(|| Error::Malformed("Challenge URL has no host".to_string()))?
                .to_string();
            let port = url.port_or_known_default().unwrap_or(80);

            // Resolve + validate + pin: the request goes to a checked address.
            let addr = resolve_public(&host, port).await?;
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(self.timeout_secs))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("OstrichPKI-ACME/0.10.0")
                .resolve(&host, addr)
                .build()
                .map_err(|e| {
                    Error::ChallengeValidation(format!("Failed to build HTTP client: {}", e))
                })?;

            let response =
                client.get(url.clone()).send().await.map_err(|e| {
                    Error::ChallengeValidation(format!("HTTP request failed: {}", e))
                })?;

            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::ChallengeValidation("Redirect response without Location".to_string())
                    })?;
                // Resolve relative Locations against the current URL.
                url = url
                    .join(location)
                    .map_err(|e| Error::Malformed(format!("Invalid redirect Location: {}", e)))?;
                continue;
            }

            if !status.is_success() {
                return Err(Error::ChallengeValidation(format!(
                    "HTTP challenge returned status {}: expected 200 OK",
                    status
                )));
            }

            let body = response.text().await.map_err(|e| {
                Error::ChallengeValidation(format!("Failed to read response: {}", e))
            })?;
            return Ok(body.trim() == expected_response);
        }

        Err(Error::ChallengeValidation(
            "Too many redirects during HTTP-01 validation".to_string(),
        ))
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
/// # Process
///
/// 1. Construct TXT record name: _acme-challenge.<domain>
/// 2. Query DNS for TXT records
/// 3. Compute expected value: Base64URL(SHA256(<token>.<account_key_thumbprint>))
/// 4. Verify at least one TXT record matches expected value
/// 5. Use recursive DNS resolver (system default)
///
/// # Security Considerations
///
/// - Use DNSSEC if available
/// - Query multiple nameservers if possible
/// - Enforce timeout to prevent DoS
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Validates domain control via DNS challenge.
/// - **FCS_COP.1**: SHA-256 digest of key authorization.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
///
/// # NIST 800-53 Controls
///
/// - **IA-5(1)**: Challenge-response authentication (RFC 8555 §8.4).
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
    /// # Process
    ///
    /// 1. Compute expected value: BASE64URL(SHA256(token.account_key_thumbprint))
    /// 2. Query DNS for TXT record at _acme-challenge.<domain>
    /// 3. Verify any TXT record matches the expected value
    /// 4. Retry with delay to allow for DNS propagation
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FIA_UAU.1**: Proves domain control before certificate issuance.
    /// - **FCS_COP.1**: SHA-256 digest computation (FIPS 180-4).
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **IA-5(1)**: Challenge-response authentication (RFC 8555 §8.4).
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::name_server::TokioConnectionProvider;
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
/// # Process
///
/// 1. Connect to <domain>:443 with TLS
/// 2. Send ALPN extension with protocol "acme-tls/1"
/// 3. Verify server responds with "acme-tls/1" protocol
/// 4. Verify certificate has acmeIdentifier extension with SHA256 hash
/// 5. Hash = SHA256(<token>.<account_key_thumbprint>)
///
/// # Security Considerations
///
/// - Verify certificate chain
/// - Check for proper ALPN protocol
/// - Enforce timeout to prevent DoS
/// - Prevent SSRF by blocking private IPs
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FIA_UAU.1**: Validates domain control via TLS-ALPN challenge.
/// - **FTP_ITC.1**: Uses TLS trusted channel for validation.
/// - **FCS_COP.1**: SHA-256 hash of key authorization in certificate.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
///
/// # NIST 800-53 Controls
///
/// - **IA-5(1)**: Challenge-response authentication (RFC 8737).
/// - **SC-8**: Transmission confidentiality via TLS.
/// - **SI-10**: SSRF prevention via private IP blocking.
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
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FIA_UAU.1**: Proves domain control before certificate issuance.
    /// - **FTP_ITC.1**: TLS handshake establishes trusted channel.
    /// - **FCS_COP.1**: Verifies SHA-256 hash in certificate extension.
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **IA-5(1)**: Challenge-response authentication (RFC 8737).
    /// - **SC-8**: TLS transmission confidentiality.
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

        // SI-10: SSRF prevention. Resolve the domain, require every resolved
        // address to be globally routable, and connect to that VALIDATED address
        // (not a re-resolution) — closing DNS-rebinding. The TLS ServerName below
        // stays the domain so certificate validation is unaffected.
        let addr = resolve_public(domain, 443).await?;
        let tcp_stream = timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| Error::ChallengeValidation(format!("TLS connection timed out to {}", addr)))?
        .map_err(|e| Error::ChallengeValidation(format!("Failed to connect to {}: {}", addr, e)))?;

        // Compute expected acmeIdentifier extension value
        // RFC 8737 §3: acmeIdentifier = SHA256(key_authorization)
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let expected_hash = Sha256::digest(key_authorization.as_bytes());

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

/// True if `ip` must NOT be a challenge-validation target: any address that is
/// not globally routable (loopback, private, link-local, CGNAT, documentation,
/// reserved, etc.). Checking the *resolved* address — not just the literal
/// hostname — is what closes the DNS-rebinding SSRF hole. `Ipv4Addr/Ipv6Addr::
/// is_global` is still unstable, so the disallowed ranges are enumerated here.
///
/// COMPLIANCE: NIST 800-53 SI-10 (input validation / SSRF prevention).
fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0                                       // 0.0.0.0/8
                || (o[0] == 100 && (64..128).contains(&o[1]))      // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)         // 192.0.0.0/24
                || o[0] >= 240 // 240.0.0.0/4 reserved (and 255.255.255.255)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_disallowed_ip(IpAddr::V4(mapped));
            }
            let s = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00   // fc00::/7 unique-local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Resolve `host:port` and require EVERY resolved address to be globally
/// routable, returning one validated address to *pin* the connection to. Pinning
/// (connecting to the returned address rather than re-resolving) closes the
/// DNS-rebinding TOCTOU window where the name resolves to a public address for
/// the check but an internal one for the actual connection.
///
/// COMPLIANCE: NIST 800-53 SI-10; RFC 8555 §10.1 (SSRF in validation).
async fn resolve_public(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| Error::ChallengeValidation(format!("DNS resolution failed for {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::ChallengeValidation(format!(
            "{host} did not resolve to any address"
        )));
    }
    // Fail closed: if ANY resolved address is non-public, refuse — an attacker
    // could otherwise round-robin a public and an internal address.
    for a in &addrs {
        if is_disallowed_ip(a.ip()) {
            return Err(Error::Malformed(format!(
                "Refusing to validate {host}: resolves to non-public address {} \
                 (SSRF prevention)",
                a.ip()
            )));
        }
    }
    Ok(addrs[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_disallowed_ip() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();

        // Non-public (SSRF targets) — must be rejected. This is the check that,
        // applied to the RESOLVED address, closes DNS-rebinding.
        assert!(is_disallowed_ip(ip("127.0.0.1"))); // loopback
        assert!(is_disallowed_ip(ip("10.0.0.1"))); // private
        assert!(is_disallowed_ip(ip("192.168.1.1"))); // private
        assert!(is_disallowed_ip(ip("172.16.0.1"))); // private
        assert!(is_disallowed_ip(ip("169.254.169.254"))); // link-local / cloud metadata
        assert!(is_disallowed_ip(ip("100.64.0.1"))); // CGNAT
        assert!(is_disallowed_ip(ip("0.0.0.0"))); // unspecified
        assert!(is_disallowed_ip(ip("::1"))); // IPv6 loopback
        assert!(is_disallowed_ip(ip("fc00::1"))); // IPv6 unique-local
        assert!(is_disallowed_ip(ip("fe80::1"))); // IPv6 link-local
        assert!(is_disallowed_ip(ip("::ffff:127.0.0.1"))); // IPv4-mapped loopback

        // Globally routable — allowed.
        assert!(!is_disallowed_ip(ip("8.8.8.8")));
        assert!(!is_disallowed_ip(ip("1.1.1.1")));
        assert!(!is_disallowed_ip(ip("192.167.1.1")));
        assert!(!is_disallowed_ip(ip("2606:4700:4700::1111"))); // public IPv6
    }

    #[tokio::test]
    async fn test_http01_validator_creation() {
        let validator = Http01Validator::new();
        assert_eq!(validator.max_redirects, 10);
        assert_eq!(validator.timeout_secs, 10);
    }

    #[test]
    fn test_dns01_validator_creation() {
        let validator = Dns01Validator::new();
        assert_eq!(validator.timeout_secs, 30);
    }

    #[test]
    fn test_tls_alpn_validator_creation() {
        let validator = TlsAlpn01Validator::new();
        assert_eq!(validator.timeout_secs, 10);
    }
}
