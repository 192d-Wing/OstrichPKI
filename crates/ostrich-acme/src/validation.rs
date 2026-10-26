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
//! - **FDP_CER_EXT.1**: Certificate profile - subject identifier verified
//!   - Challenge validation proves control of the identifier before issuance.
//!   - Key authorization binds the challenge response to the ACME account.
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
//! - **SC-17**: Public Key Infrastructure Certificates
//!   - Identifier (domain) control is verified before a certificate is issued.
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
use std::net::IpAddr;
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
/// - **FDP_CER_EXT.1**: Validates domain control via HTTP challenge-response.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
///
/// # NIST 800-53 Controls
///
/// - **SC-17**: Domain control verified before certificate issuance.
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
    /// - **FDP_CER_EXT.1**: Proves domain control before certificate issuance.
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **SC-17**: Domain control verified before issuance (RFC 8555 §8.3).
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
            let response = self
                .client
                .get(&initial_url)
                .send()
                .await
                .map_err(|e| http01_connection_error(domain, &e))?;
            if !response.status().is_success() {
                return Err(http01_status_error(domain, response.status()));
            }
            let body = response
                .text()
                .await
                .map_err(|e| http01_connection_error(domain, &e))?;
            return Ok(body.trim() == expected_response);
        }

        // SI-10: SSRF prevention. Follow redirects MANUALLY so every hop's host
        // is resolved, checked to be globally routable, and the connection is
        // pinned to a validated address — closing DNS-rebinding (including via a
        // redirect to a name that rebinds to an internal address).
        let mut url = reqwest::Url::parse(&initial_url).map_err(|e| {
            tracing::warn!(domain = %domain, error = %e, "http-01: invalid challenge URL");
            Error::Malformed(format!(
                "Identifier {domain} does not form a valid HTTP-01 challenge URL"
            ))
        })?;

        for _ in 0..=self.max_redirects {
            // Only a redirect can change the scheme (the initial URL is
            // http://), so a bad scheme is the target's response at fault.
            if !matches!(url.scheme(), "http" | "https") {
                tracing::warn!(
                    domain = %domain,
                    scheme = %url.scheme(),
                    "http-01: redirect to a disallowed URL scheme"
                );
                return Err(Error::IncorrectResponse(format!(
                    "HTTP-01 redirect for {domain} used a disallowed URL scheme"
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
                    // Local configuration fault, not the subscriber's.
                    tracing::error!(error = %e, "http-01: failed to build HTTP client");
                    Error::ServerInternal(format!("Failed to build HTTP client: {e}"))
                })?;

            let response = client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| http01_connection_error(domain, &e))?;

            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::IncorrectResponse(format!(
                            "HTTP-01 redirect for {domain} had no usable Location header"
                        ))
                    })?;
                // Resolve relative Locations against the current URL.
                url = url.join(location).map_err(|e| {
                    tracing::warn!(
                        domain = %domain,
                        error = %e,
                        "http-01: invalid redirect Location"
                    );
                    Error::IncorrectResponse(format!(
                        "HTTP-01 redirect for {domain} had an invalid Location header"
                    ))
                })?;
                continue;
            }

            if !status.is_success() {
                return Err(http01_status_error(domain, status));
            }

            let body = response
                .text()
                .await
                .map_err(|e| http01_connection_error(domain, &e))?;
            return Ok(body.trim() == expected_response);
        }

        Err(Error::IncorrectResponse(format!(
            "HTTP-01 validation for {domain} exceeded the redirect limit"
        )))
    }
}

impl Default for Http01Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// A failed HTTP-01 fetch (connect, timeout, or body read) as the RFC 8555
/// §6.7 `connection` problem type.
///
/// The raw `reqwest` error (which can name resolved addresses, proxies, or
/// TLS internals) is logged server-side only; the client sees the identifier.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - no raw transport errors to the client
// - RFC 8555 §6.7 - registered `connection` problem type
fn http01_connection_error(domain: &str, e: &reqwest::Error) -> Error {
    tracing::warn!(domain = %domain, error = %e, "http-01: challenge fetch failed");
    Error::Connection(format!("HTTP-01 request to {domain} failed"))
}

/// A non-2xx final HTTP-01 response as the RFC 8555 §6.7 `incorrectResponse`
/// problem type: the server was reached but did not serve the key
/// authorization. Any 2xx status is accepted, so the detail does not claim a
/// specific expected code. The numeric status is safe to report.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling)
// - RFC 8555 §6.7, §8.3 - registered problem type for a wrong response
fn http01_status_error(domain: &str, status: reqwest::StatusCode) -> Error {
    Error::IncorrectResponse(format!(
        "HTTP-01 request to {domain} returned unexpected HTTP status {}",
        status.as_u16()
    ))
}

/// Maximum number of operator-configured dns-01 upstream resolvers
/// (`--dns01-resolvers` / `ACME_DNS01_RESOLVERS`).
pub const MAX_DNS01_RESOLVERS: usize = 8;

/// Per-query timeout for dns-01 TXT lookups.
///
/// NIST 800-53: SC-5 - bounds how long a single validation can hold a task.
/// In hickory-resolver 0.26.2 `ResolverOpts::attempts` (2) is the number of
/// retries *after* a failed send (`RetryDnsHandle`), so one lookup makes up to
/// 1 + 2 = 3 sends, and the name-server pool enforces one `timeout` deadline per
/// send (`NameServerPool`). Nominal worst case per validation:
/// 5 rounds x 3 sends x 5 s + 4 x 2 s sleeps = 83 s (a round with a non-matching
/// TXT answer is retried too, but returns well within that). The pool checks its
/// deadline between server rounds, so a round started just before the deadline
/// can overrun it by at most one further per-request timeout.
pub const DNS01_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of TXT lookup rounds (RFC 8555 §8.2 - retry while DNS propagates).
const DNS01_MAX_RETRIES: u32 = 5;

/// Delay between TXT lookup rounds.
const DNS01_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Owner-name prefix for the dns-01 TXT record (RFC 8555 §8.4).
const ACME_CHALLENGE_LABEL: &str = "_acme-challenge";

/// Maximum number of CNAME hops followed from the challenge name inside one
/// answer section when deciding which TXT owner names are acceptable.
const MAX_CNAME_CHAIN: usize = 8;

/// Maximum presentation length of a domain name without the trailing dot
/// (RFC 1035 §3.1: 255 octets on the wire).
const MAX_DOMAIN_LEN: usize = 253;

/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// LDH hostname label check (RFC 1035 §2.3.1, RFC 5890 A-labels).
fn is_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => {
            bytes.len() <= MAX_LABEL_LEN
                && *first != b'-'
                && *last != b'-'
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        }
        // Empty label (e.g. `a..b`).
        _ => false,
    }
}

/// Build the dns-01 query name `_acme-challenge.<domain>.` from an ACME identifier.
///
/// The returned name is always fully qualified, so the resolver never applies
/// `domain` / `search` / `ndots` rewriting to it. The identifier itself must be
/// in certificate form, without a trailing dot.
///
/// # Errors
///
/// [`Error::Malformed`] if the identifier is empty, ends with a dot, has an
/// empty or non-LDH label (this includes `*` wildcards), a label over 63 octets,
/// is longer than 253 octets, has an all-numeric last label, or is an IP
/// address literal.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - the subscriber-supplied
//   identifier is validated before it reaches the resolver
// - NIAP PP-CA: FDP_CER_EXT.1 (certificate profile: subject identifier verified
//   before issuance)
// - RFC 8555 §8.4 - TXT record at `_acme-challenge.<domain>`
// - RFC 8555 §7.1.4 / RFC 5280 §4.2.1.6 - dns identifiers are ASCII A-labels
//   in certificate form (no trailing dot; RFC-008)
// - RFC 8738 §7 - dns-01 must not be used for IP identifiers
// - RFC 1035 §2.3.1 / §3.1 - LDH labels, 63-octet label and 255-octet name limits
// - RFC-004 - FQDN (trailing dot) query so search domains cannot rewrite the name
pub fn dns01_query_name(domain: &str) -> Result<hickory_proto::rr::Name> {
    use hickory_proto::rr::Name;

    let malformed = || Error::Malformed("dns-01 identifier is not a valid DNS name".to_string());

    // RFC-008: a trailing dot is not certificate (dNSName) form; reject it
    // rather than normalise, so the validated name is the name certified.
    let d = domain;
    if d.is_empty() || d.ends_with('.') || d.len() > MAX_DOMAIN_LEN {
        return Err(malformed());
    }

    // RFC 8738 §7: dns-01 is not a valid challenge for IP identifiers.
    if d.parse::<IpAddr>().is_ok() {
        return Err(Error::Malformed(
            "dns-01 is not valid for IP address identifiers".to_string(),
        ));
    }

    let mut last_label = "";
    for label in d.split('.') {
        if !is_ldh_label(label) {
            return Err(malformed());
        }
        last_label = label;
    }

    // RFC 3696 §2: a top-level label is never all-numeric. This also rejects
    // dotted-numeric forms that `IpAddr::from_str` does not accept (e.g. `127.1`).
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }

    // `from_ascii`, not `from_utf8`: ACME identifiers are already A-labels and
    // must not be IDNA-mapped. The trailing dot makes the name an FQDN.
    let name = Name::from_ascii(format!("{ACME_CHALLENGE_LABEL}.{d}.")).map_err(|_| malformed())?;
    if !name.is_fqdn() {
        return Err(malformed());
    }
    Ok(name)
}

/// Validate an operator-supplied dns-01 upstream resolver list.
///
/// Called at configuration load (the server refuses to start on failure) and
/// again before every validation as defence in depth. Loopback and private
/// addresses are allowed on purpose: a local stub (`127.0.0.53`) or an internal
/// recursive resolver is the normal production deployment, and the list is
/// operator-controlled, not subscriber-controlled.
///
/// # Errors
///
/// [`Error::Dns`] if the list has more than [`MAX_DNS01_RESOLVERS`] entries, or
/// contains an unspecified, multicast or broadcast address, or a duplicate.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - validated at load, fail closed
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIAP PP-CA: FMT_SMF.1 (security management function: resolver selection)
pub fn validate_dns01_resolver_ips(ips: &[IpAddr]) -> Result<()> {
    if ips.len() > MAX_DNS01_RESOLVERS {
        return Err(Error::Dns(format!(
            "dns-01 resolver list has {} entries; at most {MAX_DNS01_RESOLVERS} are allowed",
            ips.len()
        )));
    }
    let mut seen: Vec<IpAddr> = Vec::with_capacity(ips.len());
    for ip in ips {
        // Canonicalise IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so it cannot bypass
        // the checks below or the duplicate check.
        let canonical = ip.to_canonical();
        let broadcast = matches!(canonical, IpAddr::V4(v4) if v4.is_broadcast());
        if canonical.is_unspecified() || canonical.is_multicast() || broadcast {
            return Err(Error::Dns(format!(
                "dns-01 resolver {ip} is not a usable unicast address"
            )));
        }
        if seen.contains(&canonical) {
            return Err(Error::Dns(format!("dns-01 resolver {ip} is listed twice")));
        }
        seen.push(canonical);
    }
    Ok(())
}

/// Read the host's system resolver configuration (e.g. `/etc/resolv.conf`).
///
/// This is the production `system` source for [`dns01_resolver_config`].
///
/// # Errors
///
/// A description of the platform error. Callers must treat it as "no name
/// servers" and fail closed.
pub fn system_resolver_config()
-> std::result::Result<hickory_resolver::config::ResolverConfig, String> {
    hickory_resolver::system_conf::read_system_conf()
        .map(|(config, _opts)| config)
        .map_err(|e| e.to_string())
}

/// Build the dns-01 resolver configuration and options.
///
/// - A non-empty `upstreams` list (operator configuration) takes precedence;
///   `system` is then not called.
/// - Otherwise only the `name_servers` of the system configuration are kept.
///   The system `domain`, `search` and options (`ndots`, `attempts`, `rotate`,
///   `timeout`) are dropped.
/// - Response caching is disabled so the retry loop never reuses an earlier
///   (possibly negative) answer.
///
/// # Errors
///
/// [`Error::ServerInternal`] when the resulting configuration has no name
/// servers, when `system` fails, or when `upstreams` is invalid. The message
/// is generic: resolver addresses and platform errors are logged server-side
/// only.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure default is the host's
//   operator-controlled resolver configuration; no third-party public resolver
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded timeout/attempts
// - NIST 800-53: SC-21 - not implemented in TOE; inherited from operator's
//   validating recursor (environment assumption; POAM-2026-10-23-41)
// - NIST 800-53: SI-11 (Error Handling) - no resolver topology in client errors
// - NIAP PP-CA: FPT_FLS.1 (fail secure: empty resolver is an error, never a
//   silent no-op)
// - RFC 8555 §8.2 / RFC-005 - retries must not reuse a cached negative answer
pub fn dns01_resolver_config(
    upstreams: &[IpAddr],
    system: impl FnOnce() -> std::result::Result<hickory_resolver::config::ResolverConfig, String>,
    timeout: Duration,
) -> Result<(
    hickory_resolver::config::ResolverConfig,
    hickory_resolver::config::ResolverOpts,
)> {
    use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};

    let no_name_servers =
        || Error::ServerInternal("dns-01 resolver has no name servers configured".to_string());

    let name_servers: Vec<NameServerConfig> = if upstreams.is_empty() {
        match system() {
            Ok(config) => {
                let (_domain, _search, name_servers) = config.into_parts();
                name_servers
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "dns-01: failed to read system resolver configuration; failing closed"
                );
                return Err(no_name_servers());
            }
        }
    } else {
        if let Err(e) = validate_dns01_resolver_ips(upstreams) {
            tracing::error!(error = %e, "dns-01: invalid upstream resolver list; failing closed");
            return Err(no_name_servers());
        }
        upstreams
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect()
    };

    // NIAP PP-CA: FPT_FLS.1 - never build a resolver with no name servers.
    // hickory 0.26 would otherwise fail every lookup with NoConnections, which
    // is fail-closed but indistinguishable from a transient DNS outage.
    if name_servers.is_empty() {
        tracing::error!("dns-01: resolver configuration has no name servers; failing closed");
        return Err(no_name_servers());
    }

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    // `ResolverOpts` is `#[non_exhaustive]`: start from the default and set fields.
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 2;
    // RFC-005: no response cache, and zero TTL clamps as a second layer.
    opts.cache_size = 0;
    opts.positive_max_ttl = Some(Duration::ZERO);
    opts.negative_max_ttl = Some(Duration::ZERO);
    // Keep /etc/hosts out of the trust path for domain-control proofs.
    opts.use_hosts_file = ResolveHosts::Never;
    // CNAME -> TXT delegation of `_acme-challenge` is a common deployment pattern.
    opts.preserve_intermediates = true;

    Ok((config, opts))
}

/// Whether a TXT answer section proves control of `query_name` (RFC 8555 §8.4).
///
/// - Owner name: a TXT record counts only if its owner is `query_name` or a
///   name reached from `query_name` through CNAME records in the same answer
///   section, following at most [`MAX_CNAME_CHAIN`] hops. Names compare
///   case-insensitively. TXT records at any other owner name are ignored.
/// - Value: a record matches if and only if the concatenation of its
///   character-strings equals `expected` byte for byte. A record holding extra
///   strings next to the digest does not match.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - DNS answers are
//   untrusted; only records at the challenge name (or its CNAME chain) count
// - NIST 800-53: SC-17 - domain control verified before certificate issuance
// - NIAP PP-CA: FDP_CER_EXT.1 (subject identifier verified before issuance)
// - RFC 8555 §8.4 - TXT record at `_acme-challenge.<domain>` holds the digest
// - RFC 1035 §3.3.14 - TXT-DATA is one or more <character-string>s
// - RFC 1034 §3.6.2 - CNAME aliasing of the challenge name
pub(crate) fn txt_answers_match(
    query_name: &hickory_proto::rr::Name,
    answers: &[hickory_proto::rr::Record],
    expected: &[u8],
) -> bool {
    use hickory_proto::rr::{Name, RData};

    // Acceptable owner names: the query name, then each CNAME target in turn.
    // The loop stops at the hop limit, at a missing link, or at a name already
    // seen (CNAME loop).
    let mut owners: Vec<&Name> = vec![query_name];
    let mut current = query_name;
    for _ in 0..MAX_CNAME_CHAIN {
        let next = answers.iter().find_map(|record| match &record.data {
            RData::CNAME(target) if record.name == *current => Some(&target.0),
            _ => None,
        });
        match next {
            Some(target) if !owners.contains(&target) => {
                owners.push(target);
                current = target;
            }
            _ => break,
        }
    }

    answers.iter().any(|record| match &record.data {
        RData::TXT(txt) => {
            owners.iter().any(|owner| **owner == record.name)
                && txt
                    .txt_data
                    .iter()
                    .flat_map(|chunk| chunk.iter().copied())
                    .eq(expected.iter().copied())
        }
        _ => false,
    })
}

/// Read the system resolver configuration on the blocking thread pool.
///
/// `read_system_conf` does file I/O (e.g. `/etc/resolv.conf`), so it must not
/// run on an async worker thread. A failed or panicked task is reported as an
/// error, which callers treat as "no name servers" (fail closed).
async fn system_resolver_config_off_runtime()
-> std::result::Result<hickory_resolver::config::ResolverConfig, String> {
    match tokio::task::spawn_blocking(system_resolver_config).await {
        Ok(result) => result,
        Err(e) => Err(format!("system resolver configuration task failed: {e}")),
    }
}

/// DNS-01 challenge validator (RFC 8555 §8.4)
///
/// Validates domain control by checking for a TXT record at `_acme-challenge.<domain>.`
///
/// # Process
///
/// 1. Validate the identifier and build the FQDN `_acme-challenge.<domain>.`
/// 2. Build the resolver configuration: operator upstreams if configured,
///    otherwise the system name servers; fail closed if there are none
/// 3. Compute expected value: Base64URL(SHA256(<token>.<account_key_thumbprint>))
/// 4. Query TXT records with a fresh, cache-less resolver on every attempt
/// 5. Verify that one TXT record at the challenge name (or its CNAME chain)
///    whose concatenated strings equal the expected value byte for byte exists
///
/// # Security Considerations
///
/// - DNSSEC is not validated by this resolver; see POAM-2026-10-23-41. Production
///   deployments should point `ACME_DNS01_RESOLVERS` at a validating recursive
///   resolver on a trusted network segment: the CA-to-recursor channel is not
///   authenticated (no TSIG/DoT) and the AD bit is not checked.
/// - Enforce timeout to prevent DoS
/// - Resolver errors and addresses are logged server-side, never returned to the
///   subscriber
///
/// # NIAP PP-CA v2.1 Compliance
///
/// - **FDP_CER_EXT.1**: Validates domain control via DNS challenge before issuance.
/// - **FCS_COP.1**: SHA-256 digest of key authorization.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
/// - **FPT_FLS.1**: Every DNS or configuration error fails closed.
///
/// # NIST 800-53 Controls
///
/// - **SC-17**: Domain control verified before issuance (RFC 8555 §8.4).
/// - **SI-10**: Identifier validation before the DNS query.
/// - **CM-6**: Operator-configurable resolvers with a secure default.
// POAM: POAM-2026-10-23-41 - dns-01 does not perform CAA checking (RFC 8659) or
// in-process DNSSEC validation (RFC 8555 §11.2); no multi-perspective validation
// and no 0x20 query-name case randomisation. The CA-to-recursor channel is
// unauthenticated (no TSIG/DoT, AD bit not checked); deploy the recursor on a
// trusted segment. Wildcard identifiers are rejected until new_order stores the
// base domain with `wildcard: true` (RFC 8555 §7.1.4; POAM-2026-10-23-49).
pub struct Dns01Validator {
    /// DNS resolver timeout in seconds
    timeout_secs: u64,
    /// Operator-configured upstream resolvers; empty means the system
    /// resolver configuration.
    upstreams: Vec<IpAddr>,
    /// Delay between lookup rounds. Always [`DNS01_RETRY_DELAY`] outside tests.
    retry_delay: Duration,
}

impl Dns01Validator {
    /// Create new DNS-01 validator using the system resolver configuration
    pub fn new() -> Self {
        Self {
            timeout_secs: DNS01_TIMEOUT.as_secs(),
            upstreams: Vec::new(),
            retry_delay: DNS01_RETRY_DELAY,
        }
    }

    /// Shorten the delay between lookup rounds so retry-path tests run fast.
    #[cfg(test)]
    pub(crate) fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Use these upstream recursive resolvers (port 53, UDP with TCP fallback)
    /// instead of the system configuration. An empty list keeps the system
    /// configuration. The list is validated again at validation time.
    pub fn with_resolvers(mut self, ips: Vec<IpAddr>) -> Self {
        self.upstreams = ips;
        self
    }

    /// Validate DNS-01 challenge
    ///
    /// # Process
    ///
    /// 1. Compute expected value: BASE64URL(SHA256(token.account_key_thumbprint))
    /// 2. Query DNS for TXT record at `_acme-challenge.<domain>.`
    /// 3. Verify a TXT record matches the expected value (see [`txt_answers_match`])
    /// 4. Retry with delay to allow for DNS propagation
    ///
    /// Only an exact digest match returns `Ok(true)`. A failed lookup and a
    /// lookup without a matching record are both retried within the same
    /// bounded budget. When the last round still has no match the result is
    /// `Ok(false)`; when the last round's lookup fails it is [`Error::Dns`].
    /// Every configuration error returns `Err`.
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FDP_CER_EXT.1**: Proves domain control before certificate issuance.
    /// - **FCS_COP.1**: SHA-256 digest computation (FIPS 180-4).
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **SC-17**: Domain control verified before issuance (RFC 8555 §8.4).
    pub async fn validate(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
    ) -> Result<bool> {
        // SI-10 first: a malformed identifier never triggers any I/O.
        dns01_query_name(domain)?;

        // SEC-004: read the system configuration on the blocking pool, and only
        // when no operator upstreams are configured.
        let system = if self.upstreams.is_empty() {
            Some(system_resolver_config_off_runtime().await)
        } else {
            None
        };

        self.validate_with_system(domain, token, account_key_thumbprint, move || {
            system.unwrap_or_else(|| Err("system resolver configuration not read".to_string()))
        })
        .await
    }

    /// [`Self::validate`] with an injectable system-configuration source (test seam).
    pub(crate) async fn validate_with_system(
        &self,
        domain: &str,
        token: &str,
        account_key_thumbprint: &str,
        system: impl FnOnce() -> std::result::Result<hickory_resolver::config::ResolverConfig, String>,
    ) -> Result<bool> {
        use hickory_resolver::Resolver;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use ostrich_common::util::encoding::encode_base64url;
        use sha2::{Digest, Sha256};

        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-17 - domain control verified before certificate issuance
        // - NIST 800-53: SI-10 - identifier validated before any DNS traffic
        // - NIAP PP-CA: FPT_FLS.1 - every error path returns Err / Ok(false)
        // - RFC 8555 §8.4 - DNS-01 validation procedure

        // RFC 8555 §8.4 / RFC-004: _acme-challenge.<domain>. as an FQDN.
        let query_name = dns01_query_name(domain)?;

        // Fails closed when there are no name servers (POAM-2026-10-23-41).
        let (config, opts) = dns01_resolver_config(
            &self.upstreams,
            system,
            Duration::from_secs(self.timeout_secs),
        )?;

        // Compute expected TXT record value
        // RFC 8555 §8.4: digest = BASE64URL(SHA256(key_authorization))
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let hash = Sha256::digest(key_authorization.as_bytes());
        let expected_value = encode_base64url(&hash);

        // RFC 8555 §8.2: retry while the record propagates. A failed lookup and
        // an RRset without a matching record are both retried within the same
        // bounded budget (RFC-009); only the last round decides the outcome.
        for attempt in 1..=DNS01_MAX_RETRIES {
            let last_round = attempt == DNS01_MAX_RETRIES;

            // RFC-005: a fresh resolver per attempt cannot share a response
            // cache with the previous attempt, so a negative answer cached
            // before the record propagated is never reused. Building a resolver
            // does no I/O.
            let resolver =
                Resolver::builder_with_config(config.clone(), TokioRuntimeProvider::default())
                    .with_options(opts.clone())
                    .build()
                    .map_err(|e| {
                        tracing::error!(
                            domain = %domain,
                            error = %e,
                            "dns-01: resolver initialization failed"
                        );
                        Error::ServerInternal("dns-01 resolver initialization failed".to_string())
                    })?;

            match resolver.txt_lookup(query_name.clone()).await {
                Ok(lookup) => {
                    // RFC 8555 §8.4: owner name and concatenated value checked
                    // in `txt_answers_match` (RFC-006, RFC-007).
                    if txt_answers_match(&query_name, lookup.answers(), expected_value.as_bytes()) {
                        return Ok(true);
                    }
                    tracing::info!(
                        domain = %domain,
                        query = %query_name,
                        attempt,
                        "dns-01: no TXT record at the challenge name matched the digest"
                    );
                    if last_round {
                        return Ok(false);
                    }
                }
                Err(e) => {
                    // NIST 800-53: SI-11 - full error server-side only.
                    tracing::warn!(
                        domain = %domain,
                        query = %query_name,
                        attempt,
                        error = %e,
                        "dns-01: TXT lookup failed"
                    );
                    if last_round {
                        // All rounds used. The client-visible detail names only
                        // the query name, not the resolver or the raw error
                        // (RFC 8555 §6.7 `dns` problem type; SI-11).
                        return Err(Error::Dns(format!("DNS lookup failed for {query_name}")));
                    }
                }
            }
            tokio::time::sleep(self.retry_delay).await;
        }

        // Not reachable (the loop always returns), but fail closed regardless.
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
/// - **FDP_CER_EXT.1**: Validates domain control via TLS-ALPN challenge.
/// - **FTP_ITC.1**: Uses TLS trusted channel for validation.
/// - **FCS_COP.1**: SHA-256 hash of key authorization in certificate.
/// - **FAU_GEN.1**: Validation attempts and results are auditable.
///
/// # NIST 800-53 Controls
///
/// - **SC-17**: Domain control verified before issuance (RFC 8737).
/// - **SC-8**: Transmission confidentiality via TLS.
/// - **SI-10**: SSRF prevention via private IP blocking.
pub struct TlsAlpn01Validator {
    /// TLS connection timeout in seconds
    timeout_secs: u64,
    /// When set, permit the identifier to resolve to a private/loopback address.
    ///
    /// SECURITY: disables the SI-10 SSRF guard for TLS-ALPN-01, mirroring
    /// [`Http01Validator`]. Dev/E2E and deliberately-internal deployments only —
    /// see [`Self::insecure_allow_private_domains`].
    allow_private_domains: bool,
}

impl TlsAlpn01Validator {
    /// Create new TLS-ALPN-01 validator
    pub fn new() -> Self {
        Self {
            timeout_secs: 10,
            allow_private_domains: false,
        }
    }

    /// Disable the private-IP SSRF guard (SI-10). Dev/E2E or deliberately-internal
    /// deployments only; the name is a deploy-time review flag. Mirrors
    /// [`Http01Validator::insecure_allow_private_domains`] so the ACME server's
    /// `allow_private_ip_domains` setting applies uniformly across challenge types.
    pub fn insecure_allow_private_domains(mut self) -> Self {
        self.allow_private_domains = true;
        self
    }

    /// Validate TLS-ALPN-01 challenge
    ///
    /// # NIAP PP-CA v2.1 Compliance
    ///
    /// - **FDP_CER_EXT.1**: Proves domain control before certificate issuance.
    /// - **FTP_ITC.1**: TLS handshake establishes trusted channel.
    /// - **FCS_COP.1**: Verifies SHA-256 hash in certificate extension.
    /// - **FAU_GEN.1**: Validation outcome recorded for audit.
    ///
    /// # NIST 800-53 Controls
    ///
    /// - **SC-17**: Domain control verified before issuance (RFC 8737).
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
        // - NIST 800-53: SC-17 - domain control verified before certificate issuance
        // - RFC 8737 - TLS-ALPN-01 validation procedure
        // - RFC 8555 §8.1 - Key authorization computation
        //
        // POAM: POAM-2026-10-23-52 - tls-alpn-01 does not check acmeIdentifier criticality or single-dNSName SAN, and accepts a bare 32-byte value (RFC 8737 §3; SI-10)

        // SI-10: SSRF prevention. Resolve the domain, require every resolved
        // address to be globally routable, and connect to that VALIDATED address
        // (not a re-resolution) — closing DNS-rebinding. The TLS ServerName below
        // stays the domain so certificate validation is unaffected. When the
        // server is configured to allow private-IP identifiers, the guard is
        // bypassed uniformly (same as Http01Validator).
        let addr = resolve_pinned(domain, 443, self.allow_private_domains).await?;
        let tcp_stream = timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| {
            tracing::warn!(domain = %domain, addr = %addr, "tls-alpn-01: TCP connect timed out");
            Error::Connection(format!("TLS-ALPN-01 connection to {domain} timed out"))
        })?
        .map_err(|e| {
            tracing::warn!(
                domain = %domain,
                addr = %addr,
                error = %e,
                "tls-alpn-01: TCP connect failed"
            );
            Error::Connection(format!("TLS-ALPN-01 connection to {domain} failed"))
        })?;

        // Compute expected acmeIdentifier extension value
        // RFC 8737 §3: acmeIdentifier = SHA256(key_authorization)
        let key_authorization = format!("{}.{}", token, account_key_thumbprint);
        let expected_hash = Sha256::digest(key_authorization.as_bytes());

        // Create TLS client configuration with ALPN "acme-tls/1".
        //
        // RFC 8737 §3: the TLS-ALPN-01 challenge certificate is a SELF-SIGNED
        // certificate the ACME client generates on the fly; it does NOT chain to
        // any CA. Domain control is proven by the `id-pe-acmeIdentifier` extension
        // checked after the handshake — NOT by PKI path validation. So the peer
        // certificate MUST be accepted regardless of issuer/name; verifying it
        // against public roots (as this previously did) makes every TLS-ALPN-01
        // handshake fail with UnknownIssuer, so the challenge could never succeed.
        // The CertificateVerify signature is NOT checked either (webpki would
        // reject the critical acmeIdentifier extension); see
        // `AcmeTlsAlpnCertVerifier`. The acmeIdentifier extension check below is
        // the sole proof of control.
        // NIST 800-53: SI-10 (validation is the extension check below), SC-13.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                // Local TLS provider fault, not the subscriber's.
                tracing::error!(error = %e, "tls-alpn-01: TLS provider configuration failed");
                Error::ServerInternal(format!("TLS provider configuration failed: {e}"))
            })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcmeTlsAlpnCertVerifier))
            .with_no_client_auth();

        // Set ALPN protocols: "acme-tls/1" ONLY
        // RFC 8737 §3: Server must negotiate acme-tls/1 protocol
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name =
            rustls::pki_types::ServerName::try_from(domain.to_string()).map_err(|e| {
                tracing::warn!(domain = %domain, error = %e, "tls-alpn-01: invalid server name");
                Error::Malformed(format!(
                    "Identifier {domain} is not a valid TLS server name"
                ))
            })?;

        // Perform TLS handshake
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                tracing::warn!(domain = %domain, error = %e, "tls-alpn-01: TLS handshake failed");
                Error::Tls(format!("TLS-ALPN-01 handshake with {domain} failed"))
            })?;

        // RFC 8737 §3: Verify server negotiated "acme-tls/1" protocol
        let (_, session) = tls_stream.get_ref();
        let negotiated_protocol = session.alpn_protocol();

        match negotiated_protocol {
            Some(protocol) if protocol == b"acme-tls/1" => {
                // ALPN protocol correct, now verify certificate extension
            }
            Some(protocol) => {
                tracing::warn!(
                    domain = %domain,
                    protocol = ?String::from_utf8_lossy(protocol),
                    "tls-alpn-01: wrong ALPN protocol negotiated"
                );
                return Err(Error::Tls(format!(
                    "TLS-ALPN-01 server for {domain} did not negotiate acme-tls/1"
                )));
            }
            None => {
                return Err(Error::Tls(format!(
                    "TLS-ALPN-01 server for {domain} did not negotiate acme-tls/1"
                )));
            }
        }

        // Get peer certificate
        let peer_certs = session.peer_certificates();
        let cert_der = peer_certs.and_then(|certs| certs.first()).ok_or_else(|| {
            Error::Tls(format!(
                "TLS-ALPN-01 server for {domain} presented no certificate"
            ))
        })?;

        // Parse certificate and verify acmeIdentifier extension
        // RFC 8737 §3: Certificate must contain id-pe-acmeIdentifier extension
        // OID: 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
        let cert = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .map_err(|e| {
                tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "tls-alpn-01: challenge certificate did not parse"
                );
                Error::Tls(format!(
                    "TLS-ALPN-01 certificate from {domain} could not be parsed"
                ))
            })?
            .1;

        // Look for acmeIdentifier extension
        const ACME_IDENTIFIER_OID: &str = "1.3.6.1.5.5.7.1.31";

        for ext in cert.extensions() {
            if ext.oid.to_id_string() == ACME_IDENTIFIER_OID {
                // RFC 8737 §3: Extension value must be OCTET STRING containing SHA-256 hash
                // The value is DER-encoded OCTET STRING containing the hash
                // NIST 800-53: SI-10 - the extension value is untrusted; every
                // slice is bounds-checked (a 32- or 33-byte value with a
                // 04 20 prefix previously panicked the validation task).
                let cert_hash = acme_identifier_digest(ext.value);
                return match cert_hash {
                    // NIST 800-53: AU-3 - Audit content (successful validation)
                    Some(h) if h == expected_hash.as_slice() => Ok(true),
                    Some(_) => Ok(false),
                    None => Err(Error::IncorrectResponse(format!(
                        "TLS-ALPN-01 certificate from {domain} has a malformed \
                         acmeIdentifier extension"
                    ))),
                };
            }
        }

        // acmeIdentifier extension not found
        Err(Error::IncorrectResponse(format!(
            "TLS-ALPN-01 certificate from {domain} lacks the acmeIdentifier extension"
        )))
    }
}

impl Default for TlsAlpn01Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// The 32-byte digest carried in an `id-pe-acmeIdentifier` extension value, or
/// `None` if the value is not one.
///
/// RFC 8737 §3 encodes the value as a DER OCTET STRING (`04 20` + 32 bytes). A
/// bare 32-byte value is also accepted, as before. Any other length is `None`;
/// no input can cause an out-of-bounds slice.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - RFC 8737 §3 - acmeIdentifier extension value
fn acme_identifier_digest(value: &[u8]) -> Option<&[u8]> {
    match value {
        [0x04, 0x20, digest @ ..] if digest.len() == 32 => Some(digest),
        digest if digest.len() == 32 => Some(digest),
        _ => None,
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

/// rustls server-certificate verifier for TLS-ALPN-01 validation (RFC 8737).
///
/// The challenge certificate is self-signed and conveys no trust — control is
/// proven by the connection reaching the identifier's own `:443` and by the
/// `id-pe-acmeIdentifier` extension inspected after the handshake, NOT by PKI or
/// by the TLS CertificateVerify signature (the responder generated the ephemeral
/// cert itself). This verifier therefore accepts the presented certificate and
/// its handshake signature unconditionally. It is used ONLY by
/// [`TlsAlpn01Validator`]; it is not a general-purpose TLS client verifier.
///
/// Why the handshake signature is not checked here: per RFC 8737 §3 the
/// acmeIdentifier extension MUST be marked critical, and rustls verifies the
/// CertificateVerify signature by parsing the peer cert through `webpki`, which
/// rejects unknown critical extensions (`UnsupportedCriticalExtension`) — so any
/// spec-compliant challenge cert would fail. The domain-control proof does not
/// depend on that signature, so it is accepted and the extension check below is
/// the sole cryptographic gate (this mirrors Boulder/Pebble, which validate the
/// challenge cert out-of-band rather than as a normal TLS server certificate).
/// NIST 800-53: SI-10 (the extension check is the input validation of record).
#[derive(Debug)]
struct AcmeTlsAlpnCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcmeTlsAlpnCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // RFC 8737: accept the self-signed challenge certificate; the
        // acmeIdentifier extension check is the actual proof of control.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Advertise the standard schemes so the peer selects one for its
        // CertificateVerify; the signature itself is accepted above (see doc).
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

/// Resolve `host:port` for a pinned connection, applying the SI-10 SSRF guard
/// unless `allow_private` is set. With `allow_private` (the deploy-time
/// `allow_private_ip_domains` override) the first resolved address is returned
/// without the globally-routable requirement — for deliberately-internal
/// deployments only. Without it, this delegates to [`resolve_public`].
async fn resolve_pinned(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<std::net::SocketAddr> {
    if !allow_private {
        return resolve_public(host, port).await;
    }
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| host_resolution_error(host, &e))?
        .next()
        .ok_or_else(|| Error::Dns(format!("{host} did not resolve to any address")))
}

/// A failed host lookup for http-01 / tls-alpn-01 as the RFC 8555 §6.7 `dns`
/// problem type. The raw resolver error is logged server-side only.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - no raw resolver errors to the client
// - RFC 8555 §6.7 - registered `dns` problem type
fn host_resolution_error(host: &str, e: &std::io::Error) -> Error {
    tracing::warn!(host = %host, error = %e, "challenge target host resolution failed");
    Error::Dns(format!("DNS resolution failed for {host}"))
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
        .map_err(|e| host_resolution_error(host, &e))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::Dns(format!("{host} did not resolve to any address")));
    }
    // Fail closed: if ANY resolved address is non-public, refuse — an attacker
    // could otherwise round-robin a public and an internal address.
    //
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SI-10 (Input Validation), SI-11 (Error Handling) - the
    //   resolved address is logged server-side only; echoing it to the client
    //   would turn challenge errors into an internal-DNS oracle.
    // - RFC 8555 §6.7 - `rejectedIdentifier`: the server will not validate this
    //   identifier.
    for a in &addrs {
        if is_disallowed_ip(a.ip()) {
            tracing::warn!(
                host = %host,
                addr = %a.ip(),
                "challenge target resolves to a non-public address; refusing (SSRF prevention)"
            );
            return Err(Error::RejectedIdentifier(format!(
                "Refusing to validate {host}: it does not resolve to a publicly routable address"
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
        assert_eq!(validator.timeout_secs, 5);
        assert!(validator.upstreams.is_empty());
        let ips: Vec<IpAddr> = vec![ip("192.0.2.53"), ip("2001:db8::53")];
        assert_eq!(
            Dns01Validator::new().with_resolvers(ips.clone()).upstreams,
            ips
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP literal")
    }

    /// A system configuration as hickory would return it from resolv.conf.
    fn system_config_with(
        name_servers: Vec<hickory_resolver::config::NameServerConfig>,
    ) -> hickory_resolver::config::ResolverConfig {
        use hickory_proto::rr::Name;
        let corp = Name::from_ascii("corp.example.").expect("name");
        hickory_resolver::config::ResolverConfig::from_parts(
            Some(corp.clone()),
            vec![corp],
            name_servers,
        )
    }

    /// Acceptance criterion 2 / POAM-2026-10-23-41: an empty name-server list
    /// must be an error, never a silently non-functional resolver.
    #[test]
    fn dns01_config_rejects_empty_name_servers() {
        let result = dns01_resolver_config(
            &[],
            || {
                Ok(hickory_resolver::config::ResolverConfig::from_parts(
                    None,
                    vec![],
                    vec![],
                ))
            },
            DNS01_TIMEOUT,
        );
        assert!(
            matches!(result, Err(Error::ServerInternal(_))),
            "empty name servers must fail closed"
        );
        // hickory's own Default is the regression source: it must also be refused.
        let result = dns01_resolver_config(
            &[],
            || Ok(hickory_resolver::config::ResolverConfig::default()),
            DNS01_TIMEOUT,
        );
        assert!(matches!(result, Err(Error::ServerInternal(_))));
    }

    /// Fail closed when the system configuration cannot be read, and do not
    /// echo the platform error.
    #[test]
    fn dns01_config_rejects_system_error() {
        let result = dns01_resolver_config(
            &[],
            || Err("resolv.conf: secret-internal-detail".to_string()),
            DNS01_TIMEOUT,
        );
        match result {
            Err(Error::ServerInternal(msg)) => {
                assert!(!msg.contains("secret-internal-detail"));
            }
            other => panic!("expected ServerInternal, got {:?}", other.map(|_| ())),
        }
    }

    /// Operator upstreams take precedence and the system config is never read.
    #[test]
    fn dns01_config_uses_upstreams_and_skips_system() {
        let upstreams = [ip("192.0.2.53"), ip("2001:db8::53")];
        let (config, _opts) = dns01_resolver_config(
            &upstreams,
            || panic!("system configuration must not be read when upstreams are set"),
            DNS01_TIMEOUT,
        )
        .expect("config");
        let got: Vec<IpAddr> = config.name_servers().iter().map(|ns| ns.ip).collect();
        assert_eq!(got, upstreams);
        assert!(config.domain().is_none());
        assert!(config.search().is_empty());
    }

    /// An invalid upstream list (e.g. one that bypassed config-load checks)
    /// fails closed without leaking the address into the error.
    #[test]
    fn dns01_config_rejects_invalid_upstreams() {
        let result = dns01_resolver_config(
            &[ip("224.0.0.251")],
            || panic!("system configuration must not be read"),
            DNS01_TIMEOUT,
        );
        match result {
            Err(Error::ServerInternal(msg)) => assert!(!msg.contains("224.0.0.251")),
            other => panic!("expected ServerInternal, got {:?}", other.map(|_| ())),
        }
    }

    /// Only the system name servers are kept; `domain` / `search` are dropped.
    #[test]
    fn dns01_config_uses_system_name_servers_only() {
        let ns = hickory_resolver::config::NameServerConfig::udp_and_tcp(ip("127.0.0.53"));
        let (config, _opts) =
            dns01_resolver_config(&[], || Ok(system_config_with(vec![ns])), DNS01_TIMEOUT)
                .expect("config");
        let got: Vec<IpAddr> = config.name_servers().iter().map(|ns| ns.ip).collect();
        assert_eq!(got, vec![ip("127.0.0.53")]);
        assert!(config.domain().is_none());
        assert!(config.search().is_empty());
    }

    /// RFC-005: no response cache and zero TTL clamps, so a retry never reuses
    /// an earlier negative answer.
    #[test]
    fn dns01_opts_disable_caching() {
        let timeout = Duration::from_secs(3);
        let (_config, opts) =
            dns01_resolver_config(&[ip("192.0.2.53")], || unreachable!(), timeout).expect("config");
        assert_eq!(opts.cache_size, 0);
        assert_eq!(opts.negative_max_ttl, Some(Duration::ZERO));
        assert_eq!(opts.positive_max_ttl, Some(Duration::ZERO));
        assert_eq!(opts.timeout, timeout);
        assert_eq!(opts.attempts, 2);
        assert_eq!(
            opts.use_hosts_file,
            hickory_resolver::config::ResolveHosts::Never
        );
        assert!(opts.preserve_intermediates);
    }

    /// RFC-004: the query name is always an FQDN under `_acme-challenge`.
    #[test]
    fn dns01_query_name_is_fqdn() {
        let name = dns01_query_name("example.com").expect("valid");
        assert!(name.is_fqdn());
        assert_eq!(name.to_ascii(), "_acme-challenge.example.com.");

        // Case is preserved (no IDNA / case mapping of A-labels).
        let mixed = dns01_query_name("Sub.Example.COM").expect("valid");
        assert_eq!(mixed.to_ascii(), "_acme-challenge.Sub.Example.COM.");

        // A-labels, digits and inner hyphens are fine.
        assert!(dns01_query_name("xn--bcher-kva.example").is_ok());
        assert!(dns01_query_name("a-1.b2.example").is_ok());

        // Longest acceptable identifier still fits the 255-octet wire limit.
        let label63 = "a".repeat(63);
        let long = format!("{label63}.{label63}.{label63}.{}", "b".repeat(45));
        assert!(dns01_query_name(&long).is_ok(), "{} octets", long.len());
    }

    /// SI-10: every malformed identifier is rejected before any DNS traffic.
    #[test]
    fn dns01_query_name_rejects_bad_identifiers() {
        let label64 = "a".repeat(64);
        let too_long = format!("{}.com", "a.".repeat(130));
        let wire_overflow = {
            let l = "a".repeat(63);
            format!("{l}.{l}.{l}.{l}")
        };
        // <= 253 octets on its own, but over 255 once `_acme-challenge.` is added.
        let prefixed_overflow = {
            let l = "a".repeat(63);
            format!("{l}.{l}.{l}.{}", "b".repeat(46))
        };
        let cases: Vec<&str> = vec![
            "",
            ".",
            "..",
            "a..b",
            "example.com..",
            // RFC-008: identifiers are in certificate form, no trailing dot.
            "example.com.",
            "www.example.com.",
            ".example.com",
            "*.example.com",
            "*",
            "a.*.example.com",
            "-a.com",
            "a-.com",
            &label64,
            &too_long,
            &wire_overflow,
            &prefixed_overflow,
            "exa mple.com",
            "ex_ample.com",
            "exämple.com",
            "192.0.2.1",
            "192.0.2.1.",
            "::1",
            "[::1]",
            "2001:db8::1",
            "127.1",
            "example.123",
            "a.com\0",
            "a.com/evil",
            "a.com\n",
            "a.com:53",
        ];
        for case in cases {
            assert!(
                matches!(dns01_query_name(case), Err(Error::Malformed(_))),
                "identifier {case:?} must be rejected"
            );
        }
    }

    /// CM-6 / SI-10: resolver-IP policy at configuration load.
    #[test]
    fn validate_dns01_resolver_ips_policy() {
        // Operator-controlled loopback/private recursors are allowed.
        assert!(validate_dns01_resolver_ips(&[]).is_ok());
        assert!(
            validate_dns01_resolver_ips(&[ip("127.0.0.53"), ip("10.0.0.2"), ip("2001:db8::1")])
                .is_ok()
        );
        let max: Vec<IpAddr> = (1..=MAX_DNS01_RESOLVERS)
            .map(|i| IpAddr::from([192, 0, 2, u8::try_from(i).expect("small")]))
            .collect();
        assert!(validate_dns01_resolver_ips(&max).is_ok());

        for bad in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
        ] {
            assert!(
                validate_dns01_resolver_ips(&[ip(bad)]).is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(validate_dns01_resolver_ips(&[ip("192.0.2.53"), ip("192.0.2.53")]).is_err());
        assert!(
            validate_dns01_resolver_ips(&[ip("192.0.2.53"), ip("::ffff:192.0.2.53")]).is_err(),
            "IPv4-mapped duplicate must be rejected"
        );
        let too_many: Vec<IpAddr> = (1..=MAX_DNS01_RESOLVERS + 1)
            .map(|i| IpAddr::from([192, 0, 2, u8::try_from(i).expect("small")]))
            .collect();
        assert!(validate_dns01_resolver_ips(&too_many).is_err());
    }

    /// End-to-end fail-closed: with no name servers, validation errors before
    /// any lookup (no network, no retry sleeps) and never returns Ok(true).
    #[tokio::test]
    async fn dns01_validate_fails_closed_without_name_servers() {
        let validator = Dns01Validator::new();
        let started = std::time::Instant::now();
        let result = validator
            .validate_with_system("example.com", "token", "thumbprint", || {
                Ok(hickory_resolver::config::ResolverConfig::default())
            })
            .await;
        assert!(matches!(result, Err(Error::ServerInternal(_))));
        assert!(
            started.elapsed() < DNS01_RETRY_DELAY,
            "must short-circuit before the retry loop"
        );

        let result = validator
            .validate_with_system("example.com", "token", "thumbprint", || {
                Err("unreadable".to_string())
            })
            .await;
        assert!(matches!(result, Err(Error::ServerInternal(_))));
    }

    /// A malformed identifier is rejected before the resolver config is read.
    #[tokio::test]
    async fn dns01_validate_rejects_malformed_identifier_first() {
        let result = Dns01Validator::new()
            .validate_with_system("*.example.com", "token", "thumbprint", || {
                panic!("resolver configuration must not be read for a malformed identifier")
            })
            .await;
        assert!(matches!(result, Err(Error::Malformed(_))));
    }

    /// Fail closed at validation time when an invalid upstream list reaches the
    /// validator directly (library caller bypassing `main`'s config-load check).
    /// The system configuration is never consulted as a fallback.
    #[tokio::test]
    async fn dns01_validate_rejects_invalid_upstreams_without_fallback() {
        for bad in [
            vec![ip("0.0.0.0")],
            vec![ip("ff02::1")],
            vec![ip("192.0.2.53"), ip("192.0.2.53")],
            (1..=MAX_DNS01_RESOLVERS + 1)
                .map(|i| IpAddr::from([192, 0, 2, u8::try_from(i).expect("small")]))
                .collect(),
        ] {
            let result = Dns01Validator::new()
                .with_resolvers(bad.clone())
                .validate_with_system("example.com", "token", "thumbprint", || {
                    panic!("system configuration must not be used as a fallback")
                })
                .await;
            match result {
                Err(Error::ServerInternal(msg)) => {
                    for addr in &bad {
                        assert!(!msg.contains(&addr.to_string()), "resolver leaked: {msg}");
                    }
                }
                other => panic!(
                    "{bad:?}: expected ServerInternal, got {:?}",
                    other.map(|_| ())
                ),
            }
        }
    }

    // ------------------------------------------------------------------
    // Offline end-to-end dns-01 tests against a loopback mock DNS server.
    // The system-config seam is pointed at 127.0.0.1:<ephemeral port>, so no
    // external network is used. These exercise the real hickory resolver,
    // the on-the-wire query name, the retry loop and the digest comparison.
    // ------------------------------------------------------------------

    /// RFC 8555 §8.4 known-answer vector, computed independently of the code
    /// under test:
    /// `printf '%s' "$TOKEN.$THUMB" | openssl dgst -sha256 -binary | base64url`
    /// Token: RFC 8555 §8.4 example. Thumbprint: RFC 7638 §3.1 example.
    const KAT_TOKEN: &str = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    const KAT_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    const KAT_DIGEST: &str = "ZTRx1Ckl1-tM05o5zaizTTA0yUy5AGereMgSNWC6Ll8";

    /// Short delay between rounds for retry-path tests (production: 2 s).
    const TEST_RETRY_DELAY: Duration = Duration::from_millis(10);

    /// One answer record served by the mock. `owner: None` means the query name.
    #[derive(Clone)]
    enum MockRr {
        Txt {
            owner: Option<&'static str>,
            strings: Vec<String>,
        },
        Cname {
            owner: Option<&'static str>,
            target: &'static str,
        },
    }

    #[derive(Clone)]
    enum MockAnswer {
        NxDomain,
        /// One TXT record at the query name with these character-strings.
        Txt(Vec<String>),
        /// An arbitrary answer section.
        Records(Vec<MockRr>),
    }

    struct MockDns {
        port: u16,
        seen: std::sync::Arc<std::sync::Mutex<Vec<(String, hickory_proto::rr::RecordType)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl MockDns {
        fn queries(&self) -> Vec<(String, hickory_proto::rr::RecordType)> {
            self.seen.lock().expect("mock lock").clone()
        }
    }

    impl Drop for MockDns {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn name(s: &str) -> hickory_proto::rr::Name {
        hickory_proto::rr::Name::from_ascii(s).expect("test name")
    }

    /// Serve `script[i]` for the i-th query (the last entry repeats).
    async fn mock_dns(script: Vec<MockAnswer>) -> MockDns {
        use hickory_proto::op::{Message, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::{CNAME, TXT};
        use hickory_proto::rr::{RData, Record};

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock dns");
        let port = sock.local_addr().expect("local addr").port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut i = 0usize;
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.queries.first().cloned() else {
                    continue;
                };
                seen_task
                    .lock()
                    .expect("mock lock")
                    .push((q.name.to_ascii(), q.query_type));
                let answer = script
                    .get(i)
                    .or(script.last())
                    .cloned()
                    .unwrap_or(MockAnswer::NxDomain);
                i += 1;

                let mut resp = Message::response(req.metadata.id, OpCode::Query);
                resp.metadata.recursion_desired = req.metadata.recursion_desired;
                resp.metadata.recursion_available = true;
                resp.add_query(q.clone());
                let owner = |o: Option<&str>| o.map(name).unwrap_or_else(|| q.name.clone());
                match answer {
                    MockAnswer::NxDomain => resp.metadata.response_code = ResponseCode::NXDomain,
                    MockAnswer::Txt(strings) => {
                        resp.add_answer(Record::from_rdata(
                            q.name.clone(),
                            0,
                            RData::TXT(TXT::new(strings)),
                        ));
                    }
                    MockAnswer::Records(records) => {
                        for rr in records {
                            let record = match rr {
                                MockRr::Txt { owner: o, strings } => {
                                    Record::from_rdata(owner(o), 0, RData::TXT(TXT::new(strings)))
                                }
                                MockRr::Cname { owner: o, target } => Record::from_rdata(
                                    owner(o),
                                    0,
                                    RData::CNAME(CNAME(name(target))),
                                ),
                            };
                            resp.add_answer(record);
                        }
                    }
                }
                let Ok(bytes) = resp.to_vec() else { continue };
                let _ = sock.send_to(&bytes, peer).await;
            }
        });
        MockDns { port, seen, task }
    }

    /// A resolv.conf-style system config (with `domain`/`search` set, so any
    /// search-list rewriting would be visible) pointing at the mock server.
    fn mock_system_config(port: u16) -> hickory_resolver::config::ResolverConfig {
        let mut ns = hickory_resolver::config::NameServerConfig::udp(ip("127.0.0.1"));
        for conn in &mut ns.connections {
            conn.port = port;
        }
        system_config_with(vec![ns])
    }

    /// Run the validator for `example.com` with the KAT token against `dns`.
    async fn run_mock(dns: &MockDns, thumbprint: &str) -> Result<bool> {
        let port = dns.port;
        Dns01Validator::new()
            .with_retry_delay(TEST_RETRY_DELAY)
            .validate_with_system("example.com", KAT_TOKEN, thumbprint, || {
                Ok(mock_system_config(port))
            })
            .await
    }

    fn rounds() -> usize {
        usize::try_from(DNS01_MAX_RETRIES).expect("small")
    }

    /// Positive path (RFC 8555 §8.4): with several TXT records at the challenge
    /// name, the one holding the KAT digest validates. The wire query is exactly
    /// `_acme-challenge.example.com.` TXT, sent once, with no search-domain
    /// rewriting (RFC-004).
    #[tokio::test]
    async fn dns01_mock_valid_digest_returns_true() {
        let dns = mock_dns(vec![MockAnswer::Records(vec![
            MockRr::Txt {
                owner: None,
                strings: vec!["unrelated-record".to_string()],
            },
            MockRr::Txt {
                owner: None,
                strings: vec![KAT_DIGEST.to_string()],
            },
        ])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(true)), "got {result:?}");
        assert_eq!(
            dns.queries(),
            vec![(
                "_acme-challenge.example.com.".to_string(),
                hickory_proto::rr::RecordType::TXT
            )]
        );
    }

    /// RFC-006: a record whose character-strings concatenate to the digest
    /// validates (RFC 1035 §3.3.14).
    #[tokio::test]
    async fn dns01_mock_split_strings_joining_to_digest_returns_true() {
        let (head, tail) = KAT_DIGEST.split_at(20);
        let dns = mock_dns(vec![MockAnswer::Txt(vec![
            head.to_string(),
            tail.to_string(),
        ])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(true)), "got {result:?}");
    }

    /// RFC-006: `"junk" "<digest>"` in one record concatenates to something
    /// other than the digest, so it does not validate.
    #[tokio::test]
    async fn dns01_mock_junk_and_digest_in_one_record_returns_false() {
        let dns = mock_dns(vec![MockAnswer::Txt(vec![
            "junk".to_string(),
            KAT_DIGEST.to_string(),
        ])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(false)), "got {result:?}");
    }

    /// RFC-007 / SEC-001: a TXT record with the right digest at a foreign
    /// owner name does not validate.
    #[tokio::test]
    async fn dns01_mock_foreign_owner_txt_returns_false() {
        // Next to a non-matching record at the query name, hickory passes the
        // whole answer section through, so this exercises our owner filter.
        let dns = mock_dns(vec![MockAnswer::Records(vec![
            MockRr::Txt {
                owner: None,
                strings: vec!["unrelated-record".to_string()],
            },
            MockRr::Txt {
                owner: Some("_acme-challenge.attacker.example."),
                strings: vec![KAT_DIGEST.to_string()],
            },
        ])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(false)), "got {result:?}");

        // On its own, hickory already discards the foreign-owner record and
        // the lookup has no answer: still fail closed, never Ok(true).
        let dns = mock_dns(vec![MockAnswer::Records(vec![MockRr::Txt {
            owner: Some("_acme-challenge.attacker.example."),
            strings: vec![KAT_DIGEST.to_string()],
        }])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(
            matches!(result, Ok(false) | Err(Error::Dns(_))),
            "got {result:?}"
        );
    }

    /// RFC-007: `_acme-challenge` delegated by CNAME validates when the TXT
    /// record sits at the CNAME target in the same answer section.
    #[tokio::test]
    async fn dns01_mock_cname_delegated_txt_returns_true() {
        let dns = mock_dns(vec![MockAnswer::Records(vec![
            MockRr::Cname {
                owner: None,
                target: "example-com.acme-delegate.example.net.",
            },
            MockRr::Txt {
                owner: Some("example-com.acme-delegate.example.net."),
                strings: vec![KAT_DIGEST.to_string()],
            },
        ])])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(true)), "got {result:?}");
    }

    /// RFC-008: a trailing-dot identifier is rejected as malformed before any
    /// DNS query is sent.
    #[tokio::test]
    async fn dns01_mock_trailing_dot_identifier_is_malformed() {
        let dns = mock_dns(vec![MockAnswer::Txt(vec![KAT_DIGEST.to_string()])]).await;
        let port = dns.port;
        let result = Dns01Validator::new()
            .validate_with_system("www.example.com.", KAT_TOKEN, KAT_THUMBPRINT, || {
                Ok(mock_system_config(port))
            })
            .await;
        assert!(matches!(result, Err(Error::Malformed(_))), "got {result:?}");
        assert!(dns.queries().is_empty(), "{:?}", dns.queries());
    }

    /// Byte-exact comparison: near-miss values never validate. RFC-009: a
    /// present-but-wrong RRset is retried within the bounded budget and gives
    /// `Ok(false)` only after the last round.
    #[tokio::test]
    async fn dns01_mock_near_miss_digests_return_false() {
        let near_misses = vec![
            KAT_DIGEST.to_ascii_lowercase(),
            KAT_DIGEST.to_ascii_uppercase(),
            format!(" {KAT_DIGEST}"),
            format!("{KAT_DIGEST} "),
            format!("{KAT_DIGEST}="),
            KAT_DIGEST[..KAT_DIGEST.len() - 1].to_string(),
            // Unhashed key authorization (the http-01 value) must not pass.
            format!("{KAT_TOKEN}.{KAT_THUMBPRINT}"),
            // Standard (non-URL-safe) base64 alphabet is not equivalent.
            KAT_DIGEST.replace('-', "+").replace('_', "/"),
            String::new(),
        ];
        let records = near_misses
            .into_iter()
            .map(|v| MockRr::Txt {
                owner: None,
                strings: vec![v],
            })
            .collect();
        let dns = mock_dns(vec![MockAnswer::Records(records)]).await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(false)), "got {result:?}");
        assert_eq!(dns.queries().len(), rounds());
    }

    /// RFC-009: a stale record is retried, and the record published in a later
    /// round validates.
    #[tokio::test]
    async fn dns01_mock_mismatch_then_match_returns_true() {
        let dns = mock_dns(vec![
            MockAnswer::Txt(vec!["stale-digest-from-previous-order".to_string()]),
            MockAnswer::Txt(vec![KAT_DIGEST.to_string()]),
        ])
        .await;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        assert!(matches!(result, Ok(true)), "got {result:?}");
        assert_eq!(dns.queries().len(), 2, "{:?}", dns.queries());
    }

    /// The digest is bound to the account thumbprint: the right record for a
    /// different account key does not validate.
    #[tokio::test]
    async fn dns01_mock_wrong_thumbprint_returns_false() {
        let dns = mock_dns(vec![MockAnswer::Txt(vec![KAT_DIGEST.to_string()])]).await;
        let result = run_mock(&dns, "other-account-thumbprint").await;
        assert!(matches!(result, Ok(false)), "got {result:?}");
    }

    /// RFC-005: an NXDOMAIN seen before the record propagated is not reused;
    /// the second round issues a fresh query and validates. Uses the
    /// production retry delay.
    #[tokio::test]
    async fn dns01_mock_retry_after_nxdomain_is_not_cached() {
        let dns = mock_dns(vec![
            MockAnswer::NxDomain,
            MockAnswer::Txt(vec![KAT_DIGEST.to_string()]),
        ])
        .await;
        let port = dns.port;
        let result = Dns01Validator::new()
            .validate_with_system("example.com", KAT_TOKEN, KAT_THUMBPRINT, || {
                Ok(mock_system_config(port))
            })
            .await;
        assert!(matches!(result, Ok(true)), "got {result:?}");
        assert_eq!(dns.queries().len(), 2, "{:?}", dns.queries());
    }

    /// Fail closed after the bounded retry budget: persistent NXDOMAIN gives
    /// `Err(Dns)` after exactly `DNS01_MAX_RETRIES` queries (RFC-010), and the
    /// client-visible detail names neither the resolver nor its port.
    #[tokio::test]
    async fn dns01_mock_persistent_nxdomain_fails_closed() {
        let dns = mock_dns(vec![MockAnswer::NxDomain]).await;
        let port = dns.port;
        let result = run_mock(&dns, KAT_THUMBPRINT).await;
        match result {
            Err(e @ Error::Dns(_)) => {
                let detail = e.client_detail();
                assert_eq!(
                    detail,
                    "DNS error: DNS lookup failed for _acme-challenge.example.com."
                );
                assert!(!detail.contains("127.0.0.1"), "resolver leaked: {detail}");
                assert!(!detail.contains(&port.to_string()), "port leaked: {detail}");
                assert_eq!(e.error_type(), "urn:ietf:params:acme:error:dns");
            }
            other => panic!("expected Dns, got {other:?}"),
        }
        assert_eq!(dns.queries().len(), rounds());
    }

    // ------------------------------------------------------------------
    // `txt_answers_match` unit tests (RFC-006 / RFC-007), no network.
    // ------------------------------------------------------------------

    fn txt_rr(owner: &str, strings: &[&str]) -> hickory_proto::rr::Record {
        use hickory_proto::rr::rdata::TXT;
        hickory_proto::rr::Record::from_rdata(
            name(owner),
            0,
            hickory_proto::rr::RData::TXT(TXT::new(
                strings.iter().map(|s| (*s).to_string()).collect(),
            )),
        )
    }

    fn cname_rr(owner: &str, target: &str) -> hickory_proto::rr::Record {
        use hickory_proto::rr::rdata::CNAME;
        hickory_proto::rr::Record::from_rdata(
            name(owner),
            0,
            hickory_proto::rr::RData::CNAME(CNAME(name(target))),
        )
    }

    const QNAME: &str = "_acme-challenge.example.com.";

    #[test]
    fn txt_match_requires_concatenation_equal_to_digest() {
        let q = name(QNAME);
        let d = KAT_DIGEST.as_bytes();
        let (head, tail) = KAT_DIGEST.split_at(7);
        // Several records, one matches.
        assert!(txt_answers_match(
            &q,
            &[txt_rr(QNAME, &["other"]), txt_rr(QNAME, &[KAT_DIGEST])],
            d
        ));
        // Split strings joining to the digest.
        assert!(txt_answers_match(&q, &[txt_rr(QNAME, &[head, tail])], d));
        // "junk" "<digest>" in one record.
        assert!(!txt_answers_match(
            &q,
            &[txt_rr(QNAME, &["junk", KAT_DIGEST])],
            d
        ));
        // "<digest>" "" is still the digest; "<digest>" "x" is not.
        assert!(txt_answers_match(
            &q,
            &[txt_rr(QNAME, &[KAT_DIGEST, ""])],
            d
        ));
        assert!(!txt_answers_match(
            &q,
            &[txt_rr(QNAME, &[KAT_DIGEST, "x"])],
            d
        ));
        // Empty answer section.
        assert!(!txt_answers_match(&q, &[], d));
    }

    #[test]
    fn txt_match_requires_owner_on_cname_chain() {
        let q = name(QNAME);
        let d = KAT_DIGEST.as_bytes();
        // Foreign owner with the right digest.
        assert!(!txt_answers_match(
            &q,
            &[txt_rr("_acme-challenge.attacker.example.", &[KAT_DIGEST])],
            d
        ));
        // Owner compare is case-insensitive.
        assert!(txt_answers_match(
            &q,
            &[txt_rr("_ACME-Challenge.Example.COM.", &[KAT_DIGEST])],
            d
        ));
        // CNAME delegation in the same answer section.
        assert!(txt_answers_match(
            &q,
            &[
                cname_rr(QNAME, "a.delegate.example.net."),
                cname_rr("a.delegate.example.net.", "b.delegate.example.net."),
                txt_rr("b.delegate.example.net.", &[KAT_DIGEST]),
            ],
            d
        ));
        // A CNAME that does not start at the query name grants nothing.
        assert!(!txt_answers_match(
            &q,
            &[
                cname_rr("other.example.", "b.delegate.example.net."),
                txt_rr("b.delegate.example.net.", &[KAT_DIGEST]),
            ],
            d
        ));
        // CNAME loop terminates and grants nothing outside the loop.
        assert!(!txt_answers_match(
            &q,
            &[
                cname_rr(QNAME, "loop.example.net."),
                cname_rr("loop.example.net.", QNAME),
                txt_rr("elsewhere.example.net.", &[KAT_DIGEST]),
            ],
            d
        ));
    }

    #[test]
    fn txt_match_bounds_cname_chain_length() {
        let q = name(QNAME);
        let d = KAT_DIGEST.as_bytes();
        // hop0 = QNAME -> h1 -> ... -> hN; TXT at hN.
        let chain = |hops: usize| {
            let names: Vec<String> = std::iter::once(QNAME.to_string())
                .chain((1..=hops).map(|i| format!("h{i}.delegate.example.net.")))
                .collect();
            let mut rrs: Vec<_> = names.windows(2).map(|w| cname_rr(&w[0], &w[1])).collect();
            rrs.push(txt_rr(names.last().expect("non-empty"), &[KAT_DIGEST]));
            rrs
        };
        assert!(txt_answers_match(&q, &chain(MAX_CNAME_CHAIN), d));
        assert!(!txt_answers_match(&q, &chain(MAX_CNAME_CHAIN + 1), d));
    }

    /// SEC-004 path: `validate` checks the identifier before reading any
    /// resolver configuration (no blocking work for malformed input).
    #[tokio::test]
    async fn dns01_validate_public_rejects_malformed_identifier() {
        let result = Dns01Validator::new()
            .validate("*.example.com", "token", "thumbprint")
            .await;
        assert!(matches!(result, Err(Error::Malformed(_))), "got {result:?}");
        let result = Dns01Validator::new()
            .validate("example.com.", "token", "thumbprint")
            .await;
        assert!(matches!(result, Err(Error::Malformed(_))), "got {result:?}");
    }

    #[test]
    fn test_tls_alpn_validator_creation() {
        let validator = TlsAlpn01Validator::new();
        assert_eq!(validator.timeout_secs, 10);
        // SSRF guard on by default; the allow-private override is opt-in and
        // mirrors Http01Validator (uniform policy across challenge types).
        assert!(!validator.allow_private_domains);
        assert!(
            TlsAlpn01Validator::new()
                .insecure_allow_private_domains()
                .allow_private_domains
        );
    }

    #[test]
    fn tls_alpn_verifier_accepts_self_signed_challenge_cert() {
        use rustls::client::danger::ServerCertVerifier;
        // RFC 8737: the challenge cert is self-signed AND carries a critical
        // acmeIdentifier extension. Control is proven by that extension (checked
        // after the handshake), not by PKI or the CertificateVerify signature.
        // Both the cert and its handshake signature must therefore be accepted —
        // verifying either through webpki (as the code did before) rejected the
        // self-signed chain / the critical extension and TLS-ALPN-01 could never
        // succeed.
        let v = AcmeTlsAlpnCertVerifier;
        let cert = rustls::pki_types::CertificateDer::from(vec![0x30, 0x00]); // not CA-issued
        let name = rustls::pki_types::ServerName::try_from("acme-smoke.internal").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], rustls::pki_types::UnixTime::now())
                .is_ok(),
            "self-signed TLS-ALPN-01 challenge cert must be accepted"
        );
        // Schemes are still advertised so the peer selects one for CertificateVerify
        // (the signature itself is accepted; see the verifier doc). The end-to-end
        // handshake with a critical-extension cert is covered by the ACME smoke test.
        assert!(!v.supported_verify_schemes().is_empty());
    }

    #[tokio::test]
    async fn resolve_pinned_enforces_ssrf_guard_unless_allowed() {
        // Strict (default): a name resolving to a private address is refused.
        let strict = resolve_pinned("localhost", 443, false).await;
        let Err(e @ Error::RejectedIdentifier(_)) = strict else {
            panic!("private address must be refused when allow_private=false, got {strict:?}");
        };
        // SEC-005 / RFC-019: registered `rejectedIdentifier` type, and the client
        // detail must not reveal the resolved (internal) address.
        assert_eq!(
            e.error_type(),
            "urn:ietf:params:acme:error:rejectedIdentifier"
        );
        let detail = e.client_detail();
        assert!(
            detail.contains("does not resolve to a publicly routable address"),
            "{detail}"
        );
        for ip in ["127.0.0.1", "::1", "127."] {
            assert!(
                !detail.contains(ip),
                "detail leaked resolved address: {detail}"
            );
        }
        assert!(
            !detail
                .split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | ':'))
                .chain(detail.split_whitespace())
                .any(|w| w.parse::<std::net::IpAddr>().is_ok()),
            "detail contains an IP literal: {detail}"
        );

        // Allow-private override: the same name resolves and is returned. This is
        // the deploy-time `allow_private_ip_domains` path that TLS-ALPN-01 now
        // honors (previously it always refused, breaking internal identifiers).
        let permit = resolve_pinned("localhost", 443, true).await;
        assert!(
            matches!(permit, Ok(addr) if addr.ip().is_loopback()),
            "loopback must resolve when allow_private=true, got {permit:?}"
        );
    }

    /// Serve one canned HTTP response on a loopback port; returns the port.
    async fn one_shot_http(response: &'static str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    /// RFC-013: an unreachable http-01 target is the registered `connection`
    /// type, and the client detail has no raw reqwest/OS error text.
    #[tokio::test]
    async fn http01_connect_failure_is_connection_with_generic_detail() {
        // Bind then drop, so the port is (almost certainly) closed.
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback")
            .local_addr()
            .expect("local addr")
            .port();
        let result = Http01Validator::new()
            .with_http_port(port)
            .insecure_allow_private_domains()
            .validate("127.0.0.1", "token", "thumbprint")
            .await;
        let Err(e @ Error::Connection(_)) = result else {
            panic!("expected Err(Connection), got {result:?}");
        };
        assert_eq!(e.error_type(), "urn:ietf:params:acme:error:connection");
        assert_eq!(
            e.client_detail(),
            "Connection error: HTTP-01 request to 127.0.0.1 failed"
        );
    }

    /// RFC-018: a non-2xx http-01 response is `incorrectResponse`, reporting
    /// only the numeric status.
    #[tokio::test]
    async fn http01_non_2xx_is_incorrect_response() {
        let port = one_shot_http(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let result = Http01Validator::new()
            .with_http_port(port)
            .insecure_allow_private_domains()
            .validate("127.0.0.1", "token", "thumbprint")
            .await;
        let Err(e @ Error::IncorrectResponse(_)) = result else {
            panic!("expected Err(IncorrectResponse), got {result:?}");
        };
        assert_eq!(
            e.error_type(),
            "urn:ietf:params:acme:error:incorrectResponse"
        );
        assert!(
            e.client_detail()
                .ends_with("HTTP-01 request to 127.0.0.1 returned unexpected HTTP status 404"),
            "{e}"
        );
    }

    /// A 200 response with the wrong body is `Ok(false)`, which the REST layer
    /// reports as `incorrectResponse`.
    #[tokio::test]
    async fn http01_wrong_body_is_not_valid() {
        let port =
            one_shot_http("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnope!")
                .await;
        let result = Http01Validator::new()
            .with_http_port(port)
            .insecure_allow_private_domains()
            .validate("127.0.0.1", "token", "thumbprint")
            .await;
        assert!(matches!(result, Ok(false)), "got {result:?}");
    }

    /// RFC-013: a host that does not resolve is the registered `dns` type in
    /// both the strict and the allow-private resolution paths, with no raw
    /// resolver text (RFC 6761 reserves `.invalid`).
    #[tokio::test]
    async fn unresolvable_challenge_host_is_dns() {
        for allow_private in [false, true] {
            let result = resolve_pinned("no-such-host.invalid", 443, allow_private).await;
            let Err(e @ Error::Dns(_)) = result else {
                panic!("allow_private={allow_private}: expected Err(Dns), got {result:?}");
            };
            assert_eq!(e.error_type(), "urn:ietf:params:acme:error:dns");
            let detail = e.client_detail();
            assert!(detail.contains("no-such-host.invalid"), "{detail}");
            assert!(!detail.contains("os error"), "{detail}");
            assert!(!detail.contains("nodename"), "{detail}");
        }
    }

    /// RFC 8737 §3 acmeIdentifier value parsing never slices out of bounds;
    /// a 04 20 prefix with a short body used to panic the validation task.
    #[test]
    fn acme_identifier_digest_is_bounds_checked() {
        let digest = [0xabu8; 32];
        let mut der = vec![0x04, 0x20];
        der.extend_from_slice(&digest);
        assert_eq!(acme_identifier_digest(&der), Some(&digest[..]));
        assert_eq!(acme_identifier_digest(&digest), Some(&digest[..]));

        // 04 20 + 31 bytes (33 bytes): previously sliced [2..34] and panicked.
        assert_eq!(acme_identifier_digest(&der[..33]), None);
        // 04 20 + 30 bytes is 32 bytes long, so it is read as a bare digest,
        // which cannot equal SHA-256 of a real key authorization.
        assert_eq!(acme_identifier_digest(&der[..32]), Some(&der[..32]));
        for len in [0, 1, 2, 31, 35, 64] {
            let v = vec![0x04; len];
            assert_eq!(acme_identifier_digest(&v), None, "len {len}");
        }
    }
}
