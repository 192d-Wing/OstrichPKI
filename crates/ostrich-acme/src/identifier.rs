//! ACME order identifier validation
//!
//! Pure, database-free parsing of the `identifiers` array of a newOrder
//! request (RFC 8555 §7.4) into the authorizations the server will create.
//! Every identifier is validated before `new_order` writes anything.
//!
//! Policy:
//!
//! - `type` is compared exactly: `"dns"` and `"ip"` are supported, anything
//!   else is `unsupportedIdentifier`.
//! - `dns` values follow [`validate_dns_identifier`] (the same rules dns-01
//!   applies). A leading `*.` marks a wildcard: the authorization is for the
//!   base domain with `wildcard: true` and is offered dns-01 only. Any other
//!   use of `*`, and a wildcard over a single-label base (`*.com`), is
//!   `rejectedIdentifier`. An IP literal sent as `dns` is `malformed`.
//! - `ip` values must be the canonical text form (RFC 8738 §3), otherwise
//!   `malformed`; IPv4-mapped and IPv4-compatible IPv6 addresses are
//!   `rejectedIdentifier` (the IPv4 form must be used). IP authorizations are
//!   offered http-01 only: never dns-01 (RFC 8738 §7), and not tls-alpn-01
//!   until its RFC 8738 §6 checks exist (POAM-2026-10-23-52).
//! - A non-wildcard `dns` name too long for `_acme-challenge.<name>.` is not
//!   offered dns-01 (it could never be validated).
//! - The list must be non-empty, have at most [`MAX_ORDER_IDENTIFIERS`]
//!   entries and contain no duplicates; violations are `malformed`.

use crate::error::{Error, Result};
use crate::order::Identifier;
use crate::validation::validate_dns_identifier;
use std::collections::HashSet;
use std::net::IpAddr;

/// Maximum number of identifiers accepted in one newOrder request.
///
/// Bounds the authorizations and challenges a single request can create.
pub const MAX_ORDER_IDENTIFIERS: usize = 100;

/// The only wildcard form supported: a full leftmost `*` label.
const WILDCARD_PREFIX: &str = "*.";

/// Maximum dNSName length in octets (RFC 1035 §2.3.4, no trailing dot).
const MAX_DNS_NAME_LEN: usize = 253;

/// Challenges offered for a non-wildcard `dns` authorization.
const DNS_CHALLENGES: &[&str] = &["http-01", "dns-01", "tls-alpn-01"];

/// Challenges offered for a non-wildcard `dns` authorization whose
/// `_acme-challenge.<name>.` query name exceeds 255 wire octets (RFC 1035
/// §3.1): dns-01 could never run, and choosing it would invalidate the
/// authorization (RFC 8555 §7.1.6).
const DNS_CHALLENGES_NO_DNS01: &[&str] = &["http-01", "tls-alpn-01"];

/// Challenges offered for a wildcard `dns` authorization (RFC 8555 §7.1.3).
const WILDCARD_CHALLENGES: &[&str] = &["dns-01"];

/// Challenges offered for an `ip` authorization: http-01 only. RFC 8738 §7
/// forbids dns-01; tls-alpn-01 is withheld because the validator does not yet
/// implement RFC 8738 §6 (reverse-name SNI, single matching iPAddress SAN),
/// tracked under POAM-2026-10-23-52.
const IP_CHALLENGES: &[&str] = &["http-01"];

/// The identifier an authorization is created for.
///
/// For a wildcard order identifier `*.example.com` this is the base domain
/// `example.com` with `wildcard == true`; the order itself keeps the original
/// `*.example.com` so the finalize CSR check matches it (RFC 8555 §7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzIdentifier {
    /// Identifier type, `"dns"` or `"ip"`.
    pub id_type: String,
    /// Authorization identifier value (wildcard prefix removed).
    pub value: String,
    /// Whether this authorization was created for a `*.` order identifier.
    pub wildcard: bool,
}

impl AuthzIdentifier {
    /// Challenge types the server offers for this authorization.
    ///
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3 (Access Enforcement) - a wildcard grants a whole
    //   subtree, so only DNS-zone control (dns-01) can authorize it
    // - NIST 800-53: SC-17 (PKI Certificates)
    // - RFC 8555 §7.1.3 / §8 - wildcard authorizations use dns-01 only
    // - RFC 8738 §7 - dns-01 is not offered for IP identifiers
    // - RFC 8738 §6 - tls-alpn-01 is not offered for IP identifiers until the
    //   reverse-name SNI / iPAddress SAN checks exist (POAM-2026-10-23-52)
    // - RFC 1035 §3.1 / RFC 8555 §8.4 - dns-01 only where the query name fits
    pub fn challenge_types(&self) -> &'static [&'static str] {
        match (self.id_type.as_str(), self.wildcard) {
            ("ip", _) => IP_CHALLENGES,
            (_, true) => WILDCARD_CHALLENGES,
            _ if crate::validation::dns01_query_name(&self.value).is_err() => {
                DNS_CHALLENGES_NO_DNS01
            }
            _ => DNS_CHALLENGES,
        }
    }
}

/// Parse one newOrder identifier into the authorization identifier.
///
/// # Errors
///
/// - [`Error::UnsupportedIdentifier`] if the type is not exactly `dns` or `ip`.
/// - [`Error::RejectedIdentifier`] for a `*` anywhere other than a single
///   leftmost `*.` label, or a wildcard over a single-label base domain.
/// - [`Error::Malformed`] for a syntactically invalid DNS name or IP address,
///   a non-canonical IP address, or an IP address sent as type `dns`.
/// - [`Error::RejectedIdentifier`] for an IPv4-mapped (`::ffff:a.b.c.d`) or
///   IPv4-compatible (`::a.b.c.d`) IPv6 address.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIAP PP-CA: FDP_CER_EXT.1 (certificate profile: subject identifiers are
//   validated before authorizations are created)
// - RFC 8555 §6.7 - unsupportedIdentifier / rejectedIdentifier / malformed
// - RFC 8555 §7.1.3 / §7.1.4 - wildcard in the leftmost label; authorization
//   for the base domain with `wildcard: true`
// - RFC 8738 §3 - IPv4 dotted-decimal, IPv6 RFC 5952 canonical text
// - RFC 5280 §4.2.1.6 - dNSName / iPAddress SAN forms
pub fn parse_order_identifier(id: &Identifier) -> Result<AuthzIdentifier> {
    match id.id_type.as_str() {
        "dns" => parse_dns(&id.value),
        "ip" => parse_ip(&id.value),
        _ => Err(Error::UnsupportedIdentifier(
            "only \"dns\" and \"ip\" identifier types are supported".to_string(),
        )),
    }
}

fn parse_dns(value: &str) -> Result<AuthzIdentifier> {
    // Bound the work before any further parsing; the error does not echo
    // the value (SI-10, untrusted input kept out of responses).
    if value.len() > MAX_DNS_NAME_LEN {
        return Err(Error::Malformed(
            "dns identifier is not a valid DNS name".to_string(),
        ));
    }

    let (base, wildcard) = match value.strip_prefix(WILDCARD_PREFIX) {
        Some(base) => (base, true),
        None => (value, false),
    };

    // Policy: only a full leftmost `*` label is a wildcard. `*foo.com`,
    // `a.*.com`, `*.*.com` and a bare `*` are refused as unsupported
    // wildcard forms rather than reported as generic syntax errors.
    if base.contains('*') {
        return Err(Error::RejectedIdentifier(
            "only a single leftmost \"*.\" wildcard label is supported".to_string(),
        ));
    }

    validate_dns_identifier(base)?;

    if wildcard && !base.contains('.') {
        // POAM: POAM-2026-10-23-56 - no issuance-name policy at newOrder: wildcard base domains are not checked against the Public Suffix List (`*.co.uk` is accepted; only single-label bases are refused), and single-label, reserved (RFC 6761 / RFC 8375, e.g. `localhost`, `.internal`, `.local`, `.test`) and operator-denied names are accepted (AC-3, SI-10).
        return Err(Error::RejectedIdentifier(
            "wildcard identifiers must have at least two labels after \"*.\"".to_string(),
        ));
    }

    // dns-01 is the only challenge for a wildcard, so its base must also fit
    // the `_acme-challenge.<base>.` query name (RFC 1035 §3.1 255-octet limit);
    // otherwise the authorization could never be validated.
    if wildcard {
        crate::validation::dns01_query_name(base).map_err(|_| {
            Error::Malformed("wildcard base domain is too long for dns-01".to_string())
        })?;
    }

    Ok(AuthzIdentifier {
        id_type: "dns".to_string(),
        value: base.to_string(),
        wildcard,
    })
}

fn parse_ip(value: &str) -> Result<AuthzIdentifier> {
    let malformed = || Error::Malformed("ip identifier is not a canonical IP address".to_string());
    let ip: IpAddr = value.parse().map_err(|_| malformed())?;
    // RFC 8738 §3: the finalize check compares IP SANs as text, so only the
    // canonical form (Rust's `Display` is RFC 5952 for IPv6) is accepted.
    if ip.to_string() != value {
        return Err(malformed());
    }
    // RFC 8738 §3 / RFC 4291 §2.5.5: an IPv4 address embedded in IPv6 is the
    // same host as its IPv4 form; refuse it so one address cannot be
    // authorized under two distinct identifiers. Refused as a policy choice
    // (`rejectedIdentifier`), since the text itself is well formed.
    if let IpAddr::V6(v6) = ip
        && is_ipv4_embedded(&v6)
    {
        return Err(Error::RejectedIdentifier(
            "IPv4-mapped or IPv4-compatible IPv6 identifiers are not supported; use the IPv4 address"
                .to_string(),
        ));
    }
    Ok(AuthzIdentifier {
        id_type: "ip".to_string(),
        value: value.to_string(),
        wildcard: false,
    })
}

/// Whether `v6` is IPv4-mapped (`::ffff:0:0/96`) or IPv4-compatible
/// (`::/96`, deprecated by RFC 4291 §2.5.5.1). `::` and `::1` are excluded:
/// they are the unspecified and loopback addresses, not embedded IPv4.
fn is_ipv4_embedded(v6: &std::net::Ipv6Addr) -> bool {
    if v6.to_ipv4_mapped().is_some() {
        return true;
    }
    let s = v6.segments();
    s[..6].iter().all(|&x| x == 0) && v6.to_bits() > 1
}

/// Validate a whole newOrder identifier list.
///
/// Returns one [`AuthzIdentifier`] per order identifier, in request order.
/// Nothing is returned unless every identifier is acceptable, so the caller
/// can validate before any database write.
///
/// # Errors
///
/// [`Error::Malformed`] if the list is empty, has more than
/// [`MAX_ORDER_IDENTIFIERS`] entries, or contains a duplicate (same type and
/// value, DNS names compared case-insensitively); otherwise the first error
/// from [`parse_order_identifier`].
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - fail before any write
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded list size
// - NIAP PP-CA: FDP_CER_EXT.1
// - RFC 8555 §7.4 - newOrder identifiers
pub fn validate_order_identifiers(ids: &[Identifier]) -> Result<Vec<AuthzIdentifier>> {
    if ids.is_empty() {
        return Err(Error::Malformed(
            "Identifiers list cannot be empty".to_string(),
        ));
    }
    if ids.len() > MAX_ORDER_IDENTIFIERS {
        return Err(Error::Malformed(format!(
            "an order may contain at most {MAX_ORDER_IDENTIFIERS} identifiers"
        )));
    }

    let mut seen: HashSet<(String, String, bool)> = HashSet::with_capacity(ids.len());
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let authz = parse_order_identifier(id)?;
        // DNS names are case-insensitive (RFC 4343); IPs are already canonical.
        let key = (
            authz.id_type.clone(),
            authz.value.to_ascii_lowercase(),
            authz.wildcard,
        );
        if !seen.insert(key) {
            return Err(Error::Malformed(
                "Identifiers list contains a duplicate identifier".to_string(),
            ));
        }
        out.push(authz);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::dns01_query_name;

    fn dns(v: &str) -> Identifier {
        Identifier {
            id_type: "dns".to_string(),
            value: v.to_string(),
        }
    }

    fn ip(v: &str) -> Identifier {
        Identifier {
            id_type: "ip".to_string(),
            value: v.to_string(),
        }
    }

    fn problem_type(e: &Error) -> &'static str {
        e.error_type()
    }

    #[test]
    fn dns_identifier_accepted_with_all_challenges() {
        let a = parse_order_identifier(&dns("www.Example.com")).expect("valid");
        assert_eq!(a.id_type, "dns");
        assert_eq!(a.value, "www.Example.com", "value kept as sent");
        assert!(!a.wildcard);
        assert_eq!(a.challenge_types(), &["http-01", "dns-01", "tls-alpn-01"]);
    }

    /// RFC 8555 §7.1.3 / §7.1.4: `*.` -> base-domain authz, wildcard, dns-01 only.
    #[test]
    fn wildcard_becomes_base_domain_dns01_only() {
        let a = parse_order_identifier(&dns("*.example.com")).expect("valid");
        assert_eq!(a.value, "example.com");
        assert!(a.wildcard);
        assert_eq!(a.challenge_types(), &["dns-01"]);
        assert!(!a.challenge_types().contains(&"http-01"));
        assert!(!a.challenge_types().contains(&"tls-alpn-01"));

        // The dns-01 validator queries the base domain for a wildcard authz.
        let name = dns01_query_name(&a.value).expect("base is a valid name");
        assert_eq!(name.to_ascii(), "_acme-challenge.example.com.");

        // Longest wildcard base whose dns-01 query name still fits.
        let longest = format!("*.{l}.{l}.{l}.{}", "b".repeat(45), l = "a".repeat(63));
        assert!(parse_order_identifier(&dns(&longest)).is_ok());

        let a = parse_order_identifier(&dns("*.a.b.example")).expect("valid");
        assert_eq!(a.value, "a.b.example");
        assert!(a.wildcard);
    }

    /// RFC 8738 §7: IP identifiers are never offered dns-01; RFC 8738 §6:
    /// nor tls-alpn-01 until its IP checks exist (POAM-2026-10-23-52).
    #[test]
    fn ip_identifier_canonical_http01_only() {
        for v in ["192.0.2.1", "2001:db8::1", "::1", "::"] {
            let a = parse_order_identifier(&ip(v)).expect(v);
            assert_eq!(a.id_type, "ip");
            assert_eq!(a.value, v);
            assert!(!a.wildcard);
            assert_eq!(a.challenge_types(), &["http-01"]);
            assert!(!a.challenge_types().contains(&"dns-01"));
            assert!(!a.challenge_types().contains(&"tls-alpn-01"));
        }
    }

    /// RFC-005: IPv4-mapped and IPv4-compatible IPv6 identifiers (canonical
    /// text) are refused as `rejectedIdentifier`; the IPv4 form is accepted.
    #[test]
    fn ipv4_embedded_ipv6_is_rejected_identifier() {
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().expect("parse");
        let compat: IpAddr = "::c000:201".parse().expect("parse");
        for v in [mapped.to_string(), compat.to_string()] {
            let e = parse_order_identifier(&ip(&v)).expect_err(&v);
            assert!(matches!(e, Error::RejectedIdentifier(_)), "{v:?}: {e:?}");
            assert_eq!(
                problem_type(&e),
                "urn:ietf:params:acme:error:rejectedIdentifier"
            );
        }
        assert!(parse_order_identifier(&ip("192.0.2.1")).is_ok());
        // Unspecified, loopback and ordinary addresses are not "embedded".
        for v in ["::", "::1", "2001:db8::1", "::1:0:0:1", "64:ff9b::c000:201"] {
            let v6: std::net::Ipv6Addr = v.parse().expect(v);
            assert!(!is_ipv4_embedded(&v6), "{v}");
        }
        assert!(is_ipv4_embedded(&"::ffff:0.0.0.1".parse().expect("parse")));
        assert!(is_ipv4_embedded(&"::0.0.0.2".parse().expect("parse")));
    }

    /// RFC-003: a non-wildcard name whose `_acme-challenge.<name>.` exceeds
    /// 255 wire octets is not offered dns-01; one that fits is.
    #[test]
    fn long_dns_name_not_offered_dns01() {
        let l63 = "a".repeat(63);
        let fits = format!("{l63}.{l63}.{l63}.{}", "b".repeat(45));
        assert_eq!(fits.len(), 237);
        assert_eq!(
            parse_order_identifier(&dns(&fits))
                .expect("237")
                .challenge_types(),
            &["http-01", "dns-01", "tls-alpn-01"]
        );
        for n in [46, 61] {
            let name = format!("{l63}.{l63}.{l63}.{}", "b".repeat(n));
            assert!((238..=253).contains(&name.len()));
            let a = parse_order_identifier(&dns(&name)).expect("valid name");
            assert!(dns01_query_name(&a.value).is_err());
            assert_eq!(a.challenge_types(), &["http-01", "tls-alpn-01"]);
        }
    }

    #[test]
    fn ip_identifier_non_canonical_or_invalid_is_malformed() {
        for v in [
            "",
            "192.0.2",
            "192.0.2.256",
            "192.000.002.001",
            "2001:DB8::1",
            "2001:db8:0:0:0:0:0:1",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1 ",
            "example.com",
            "*.example.com",
        ] {
            let e = parse_order_identifier(&ip(v)).expect_err(v);
            assert!(matches!(e, Error::Malformed(_)), "{v:?}: {e:?}");
            assert_eq!(problem_type(&e), "urn:ietf:params:acme:error:malformed");
        }
    }

    /// RFC 8555 §6.7: unknown or wrongly-cased types are unsupportedIdentifier.
    #[test]
    fn unknown_type_is_unsupported_identifier() {
        for t in ["email", "DNS", "Ip", "", "uri", "dns "] {
            let id = Identifier {
                id_type: t.to_string(),
                value: "example.com".to_string(),
            };
            let e = parse_order_identifier(&id).expect_err(t);
            assert!(matches!(e, Error::UnsupportedIdentifier(_)), "{t:?}: {e:?}");
            assert_eq!(
                problem_type(&e),
                "urn:ietf:params:acme:error:unsupportedIdentifier"
            );
        }
    }

    /// Unsupported wildcard forms are a server policy refusal.
    #[test]
    fn unsupported_wildcards_are_rejected_identifier() {
        for v in [
            "*",
            "*.com",
            "*foo.example.com",
            "foo*.example.com",
            "a.*.example.com",
            "*.*.example.com",
            "**.example.com",
            "example.*",
        ] {
            let e = parse_order_identifier(&dns(v)).expect_err(v);
            assert!(matches!(e, Error::RejectedIdentifier(_)), "{v:?}: {e:?}");
            assert_eq!(
                problem_type(&e),
                "urn:ietf:params:acme:error:rejectedIdentifier"
            );
        }
    }

    /// SI-10: syntactically invalid dns values (including the base of a
    /// wildcard) are malformed; an IP literal must use type "ip".
    #[test]
    fn malformed_dns_identifiers() {
        let label64 = "a".repeat(64);
        let too_long = format!("{}.com", "a.".repeat(130));
        let wildcard_too_long = format!("*.{}", "a".repeat(63) + &".a".repeat(95));
        assert!(wildcard_too_long.len() > MAX_DNS_NAME_LEN);
        let cases: Vec<String> = vec![
            String::new(),
            ".".into(),
            "a..b".into(),
            "example.com.".into(),
            ".example.com".into(),
            "-a.com".into(),
            "a-.com".into(),
            format!("{label64}.com"),
            too_long,
            wildcard_too_long,
            "exa mple.com".into(),
            "ex_ample.com".into(),
            "exämple.com".into(),
            "example.123".into(),
            "127.1".into(),
            "a.com\0".into(),
            "a.com:443".into(),
            "*.".into(),
            "*.example.com.".into(),
            // Fits 253 octets as `*.<base>`, but `_acme-challenge.<base>.`
            // exceeds the 255-octet wire limit, so dns-01 could never run.
            format!("*.{l}.{l}.{l}.{}", "b".repeat(46), l = "a".repeat(63)),
            "*.-a.com".into(),
            "*.".to_string() + &label64 + ".com",
            "192.0.2.1".into(),
            "2001:db8::1".into(),
            "*.192.0.2.1".into(),
        ];
        for v in cases {
            let e = parse_order_identifier(&dns(&v)).expect_err(&v);
            assert!(matches!(e, Error::Malformed(_)), "{v:?}: {e:?}");
            assert_eq!(problem_type(&e), "urn:ietf:params:acme:error:malformed");
        }

        // The IP-literal case names the right identifier type.
        let e = parse_order_identifier(&dns("192.0.2.1")).expect_err("ip as dns");
        assert!(e.to_string().contains("\"ip\""), "{e}");
    }

    /// Error details never echo the untrusted identifier value.
    #[test]
    fn errors_do_not_echo_value() {
        let secret_looking = "evil<script>.example.123";
        let e = parse_order_identifier(&dns(secret_looking)).expect_err("bad");
        assert!(!e.to_string().contains("evil"), "{e}");
        let e = parse_order_identifier(&ip("evil")).expect_err("bad");
        assert!(!e.to_string().contains("evil"), "{e}");
    }

    #[test]
    fn list_empty_and_cap() {
        let e = validate_order_identifiers(&[]).expect_err("empty");
        assert!(matches!(e, Error::Malformed(_)));

        let max: Vec<Identifier> = (0..MAX_ORDER_IDENTIFIERS)
            .map(|i| dns(&format!("h{i}.example.com")))
            .collect();
        assert_eq!(
            validate_order_identifiers(&max).expect("at cap").len(),
            MAX_ORDER_IDENTIFIERS
        );

        let mut over = max;
        over.push(dns("one-more.example.com"));
        let e = validate_order_identifiers(&over).expect_err("over cap");
        assert!(matches!(e, Error::Malformed(_)), "{e:?}");
    }

    #[test]
    fn list_duplicates_are_malformed() {
        for pair in [
            [dns("example.com"), dns("example.com")],
            [dns("example.com"), dns("EXAMPLE.com")],
            [dns("*.example.com"), dns("*.Example.COM")],
            [ip("192.0.2.1"), ip("192.0.2.1")],
        ] {
            let e = validate_order_identifiers(&pair).expect_err("duplicate");
            assert!(matches!(e, Error::Malformed(_)), "{pair:?}: {e:?}");
        }
    }

    /// `example.com` and `*.example.com` are two distinct authorizations.
    #[test]
    fn list_base_and_wildcard_together() {
        let out = validate_order_identifiers(&[
            dns("example.com"),
            dns("*.example.com"),
            ip("192.0.2.1"),
        ])
        .expect("valid");
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].value, "example.com");
        assert!(!out[0].wildcard);
        assert_eq!(out[1].value, "example.com");
        assert!(out[1].wildcard);
        assert_eq!(out[2].id_type, "ip");
    }

    /// One bad identifier fails the whole list, whatever its position.
    #[test]
    fn list_fails_on_any_bad_identifier() {
        let e = validate_order_identifiers(&[dns("example.com"), dns("ex_ample.com")])
            .expect_err("bad second");
        assert!(matches!(e, Error::Malformed(_)));
        let e = validate_order_identifiers(&[dns("example.com"), ip("example.com")])
            .expect_err("bad ip");
        assert!(matches!(e, Error::Malformed(_)));
        let e = validate_order_identifiers(&[
            dns("example.com"),
            Identifier {
                id_type: "email".to_string(),
                value: "a@example.com".to_string(),
            },
        ])
        .expect_err("bad type");
        assert!(matches!(e, Error::UnsupportedIdentifier(_)));
    }

    // ---- QA additions (SA-11 / CA-2 evidence) ----

    const MALFORMED: &str = "urn:ietf:params:acme:error:malformed";

    /// RFC 1035 §2.3.4: a 63-octet label and a 253-octet name are accepted;
    /// one octet more is `malformed`.
    #[test]
    fn qa_dns_length_boundaries() {
        let l63 = "a".repeat(63);
        let ok_label = format!("{l63}.example.com");
        assert!(parse_order_identifier(&dns(&ok_label)).is_ok());

        let name253 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(61));
        assert_eq!(name253.len(), 253);
        let a = parse_order_identifier(&dns(&name253)).expect("253 octets");
        assert_eq!(a.value, name253);
        // RFC-003: `_acme-challenge.<253-octet name>.` cannot fit, so no dns-01.
        assert_eq!(a.challenge_types(), &["http-01", "tls-alpn-01"]);

        let name254 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(62));
        assert_eq!(name254.len(), 254);
        let e = parse_order_identifier(&dns(&name254)).expect_err("254 octets");
        assert!(matches!(e, Error::Malformed(_)), "{e:?}");
        assert_eq!(problem_type(&e), MALFORMED);
    }

    /// The wildcard base is bounded by `_acme-challenge.<base>.` <= 255 wire
    /// octets (base <= 237 text octets), and the full `*.<base>` value by
    /// 253 octets (checked before the prefix is stripped).
    #[test]
    fn qa_wildcard_base_length_boundaries() {
        let l63 = "a".repeat(63);
        let base237 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(45));
        assert_eq!(base237.len(), 237);
        let a = parse_order_identifier(&dns(&format!("*.{base237}"))).expect("base 237");
        assert_eq!(a.value, base237);
        assert!(a.wildcard);
        let q = dns01_query_name(&a.value).expect("query name fits");
        assert!(q.len() <= 255, "{}", q.len());

        let base238 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(46));
        // The same 238-octet name is fine as a non-wildcard identifier
        // (http-01 / tls-alpn-01 still possible) ...
        assert!(parse_order_identifier(&dns(&base238)).is_ok());
        // ... but not as a wildcard base, whose only challenge is dns-01.
        let e = parse_order_identifier(&dns(&format!("*.{base238}"))).expect_err("base 238");
        assert!(matches!(e, Error::Malformed(_)), "{e:?}");
        assert_eq!(problem_type(&e), MALFORMED);

        // `*.` + 252-octet base = 254 octets: rejected on total length.
        let base252 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(60));
        assert_eq!(base252.len(), 252);
        let e = parse_order_identifier(&dns(&format!("*.{base252}"))).expect_err("254 total");
        assert!(matches!(e, Error::Malformed(_)), "{e:?}");
    }

    /// RFC 8738 §3 / RFC 5952: canonical text accepted, every other spelling
    /// of the same address is `malformed`.
    #[test]
    fn qa_ip_canonical_forms() {
        for v in [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "2001:db8::",
            "fe80::1",
            // RFC 5952 §4.2.2: a single 16-bit 0 field is not compressed.
            "2001:db8:0:1:1:1:1:1",
            // RFC 5952 §4.2.3: the first of two equal-length zero runs is compressed.
            "2001:db8::1:0:0:1",
        ] {
            let a = parse_order_identifier(&ip(v)).expect(v);
            assert_eq!(a.value, v);
            assert!(!a.challenge_types().contains(&"dns-01"));
        }
        for v in [
            "0:0:0:0:0:0:0:1",
            "2001:0db8::1",
            "2001:db8::0:1",
            "2001:db8:0::1:1:1:1:1",
            "2001:db8:0:0:1:0:0:1",
            "2001:db8:0:0:1::1",
            "::ffff:c000:201",
            "1.2.3.4/24",
            "01.2.3.4",
            " 192.0.2.1",
        ] {
            let e = parse_order_identifier(&ip(v)).expect_err(v);
            assert!(matches!(e, Error::Malformed(_)), "{v:?}: {e:?}");
            assert_eq!(problem_type(&e), MALFORMED);
        }
    }

    /// RFC 8555 §6.7: list-level rejections carry the `malformed` URN, and
    /// the size cap is applied before any per-identifier parsing.
    #[test]
    fn qa_list_errors_problem_types_and_cap_first() {
        let e = validate_order_identifiers(&[]).expect_err("empty");
        assert_eq!(problem_type(&e), MALFORMED);

        let dup = validate_order_identifiers(&[dns("a.example.com"), dns("A.EXAMPLE.COM")])
            .expect_err("dup");
        assert_eq!(problem_type(&dup), MALFORMED);
        assert!(dup.to_string().contains("duplicate"), "{dup}");

        let over: Vec<Identifier> = (0..=MAX_ORDER_IDENTIFIERS)
            .map(|i| dns(&format!("h{i}.example.com")))
            .collect();
        assert_eq!(over.len(), 101);
        let e = validate_order_identifiers(&over).expect_err("101");
        assert_eq!(problem_type(&e), MALFORMED);
        assert!(e.to_string().contains("at most 100"), "{e}");

        // 101 identifiers of an unsupported type: the cap fires first, so the
        // request is refused without parsing (bounded work, SC-5).
        let junk: Vec<Identifier> = (0..=MAX_ORDER_IDENTIFIERS)
            .map(|_| Identifier {
                id_type: "email".to_string(),
                value: "x".to_string(),
            })
            .collect();
        let e = validate_order_identifiers(&junk).expect_err("101 junk");
        assert!(matches!(e, Error::Malformed(_)), "{e:?}");

        // 100 mixed identifiers (dns, wildcard, ip) is exactly at the cap.
        let mut mixed: Vec<Identifier> =
            (0..98).map(|i| dns(&format!("h{i}.example.com"))).collect();
        mixed.push(dns("*.example.com"));
        mixed.push(ip("2001:db8::1"));
        assert_eq!(mixed.len(), MAX_ORDER_IDENTIFIERS);
        assert_eq!(validate_order_identifiers(&mixed).expect("cap").len(), 100);
    }

    /// Distinct identifiers that look alike are not duplicates; the same
    /// wildcard in different case is.
    #[test]
    fn qa_duplicate_key_edges() {
        for list in [
            vec![dns("example.com"), dns("www.example.com")],
            vec![dns("*.example.com"), dns("*.a.example.com")],
            vec![
                dns("*.example.com"),
                dns("example.com"),
                dns("www.example.com"),
            ],
            vec![ip("192.0.2.1"), ip("192.0.2.2")],
            vec![ip("::1"), ip("127.0.0.1")],
        ] {
            assert!(validate_order_identifiers(&list).is_ok(), "{list:?}");
        }
        for list in [
            vec![
                dns("*.EXAMPLE.com"),
                dns("example.com"),
                dns("*.example.COM"),
            ],
            vec![ip("2001:db8::1"), dns("example.com"), ip("2001:db8::1")],
        ] {
            let e = validate_order_identifiers(&list).expect_err("dup");
            assert!(matches!(e, Error::Malformed(_)), "{list:?}: {e:?}");
        }
    }

    /// Challenge offering per identifier kind, including the defensive case of
    /// an `ip` authz flagged wildcard (never dns-01, never dns-only).
    #[test]
    fn qa_challenge_offering_matrix() {
        let mk = |t: &str, w: bool| AuthzIdentifier {
            id_type: t.to_string(),
            value: "x".to_string(),
            wildcard: w,
        };
        assert_eq!(
            mk("dns", false).challenge_types(),
            &["http-01", "dns-01", "tls-alpn-01"]
        );
        assert_eq!(mk("dns", true).challenge_types(), &["dns-01"]);
        assert_eq!(mk("ip", false).challenge_types(), &["http-01"]);
        assert_eq!(mk("ip", true).challenge_types(), &["http-01"]);

        // End to end through the parser for each kind.
        let out = validate_order_identifiers(&[
            dns("example.com"),
            dns("*.example.com"),
            ip("192.0.2.1"),
            ip("2001:db8::1"),
        ])
        .expect("valid");
        assert!(out[0].challenge_types().contains(&"dns-01"));
        assert_eq!(out[1].challenge_types(), &["dns-01"]);
        for a in &out[2..] {
            assert!(!a.challenge_types().contains(&"dns-01"), "{a:?}");
            assert!(!a.challenge_types().is_empty());
        }
    }

    /// `validate_dns_identifier` (shared helper) on its own.
    #[test]
    fn qa_validate_dns_identifier_shared_rules() {
        assert!(validate_dns_identifier("example.com").is_ok());
        assert!(validate_dns_identifier("xn--bcher-kva.example").is_ok());
        // It is the no-wildcard rule: `*` is not an LDH label.
        for v in ["*.example.com", "*", "", "example.com.", "example.123"] {
            let e = validate_dns_identifier(v).expect_err(v);
            assert!(matches!(e, Error::Malformed(_)), "{v:?}: {e:?}");
            assert_eq!(problem_type(&e), MALFORMED);
        }
        for v in ["192.0.2.1", "::1"] {
            let e = validate_dns_identifier(v).expect_err(v);
            assert!(e.to_string().contains("\"ip\""), "{v}: {e}");
        }
    }

    /// Rejection details are fixed strings for every error class (no echo of
    /// subscriber input into problem documents).
    #[test]
    fn qa_no_echo_for_every_error_class() {
        let marker = "zzqamarker";
        let cases = [
            Identifier {
                id_type: "email".to_string(),
                value: format!("{marker}@example.com"),
            },
            dns(&format!("*{marker}.example.com")),
            dns(&format!("*.{marker}")),
            dns(&format!("{marker}_x.example.com")),
            dns(&format!("*.{marker}.{}", "a".repeat(250))),
            ip(&format!("{marker}::1")),
        ];
        for id in &cases {
            let e = parse_order_identifier(id).expect_err("rejected");
            assert!(!e.to_string().contains(marker), "{id:?}: {e}");
        }
        let e = validate_order_identifiers(&[
            dns(&format!("{marker}.example.com")),
            dns(&format!("{marker}.example.com")),
        ])
        .expect_err("dup");
        assert!(!e.to_string().contains(marker), "{e}");
    }

    // ---- QA round 1 (RFC-001, RFC-003, RFC-005) ----

    /// RFC-005 / RFC 4291 §2.5.5: boundary addresses of the mapped
    /// (`::ffff:0:0/96`) and compatible (`::/96`) ranges are refused as
    /// `rejectedIdentifier` in canonical text, alone or inside a list with a
    /// valid peer; neighbours just outside the ranges are accepted.
    #[test]
    fn qa_ipv4_embedded_boundaries() {
        for raw in [
            "::ffff:0.0.0.0",
            "::ffff:255.255.255.255",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::2",
            "::0.0.1.0",
            "::255.255.255.255",
        ] {
            let v6: std::net::Ipv6Addr = raw.parse().expect(raw);
            let canon = v6.to_string();
            let e = parse_order_identifier(&ip(&canon)).expect_err(&canon);
            assert!(matches!(e, Error::RejectedIdentifier(_)), "{canon}: {e:?}");
            assert!(!e.to_string().contains(&canon), "no echo: {e}");
            let e =
                validate_order_identifiers(&[dns("example.com"), ip(&canon)]).expect_err(&canon);
            assert_eq!(
                problem_type(&e),
                "urn:ietf:params:acme:error:rejectedIdentifier",
                "{canon}"
            );
        }
        // Just outside both ranges: ordinary IPv6, accepted, http-01 only.
        for raw in [
            "::1:0:0",
            "::fffe:c000:201",
            "::1:ffff:c000:201",
            "1::ffff:c000:201",
        ] {
            let canon = raw.parse::<std::net::Ipv6Addr>().expect(raw).to_string();
            let a = parse_order_identifier(&ip(&canon)).expect(&canon);
            assert_eq!(a.challenge_types(), &["http-01"], "{canon}");
        }
    }

    /// RFC-001: every accepted IP identifier (IPv4 and IPv6, through the
    /// list validator too) is offered http-01 and nothing else, even if a
    /// row were (defensively) flagged wildcard.
    #[test]
    fn qa_ip_offering_is_http01_only_everywhere() {
        let ids = [
            ip("192.0.2.1"),
            ip("2001:db8::1"),
            ip("203.0.113.255"),
            ip("fe80::1"),
        ];
        for a in validate_order_identifiers(&ids).expect("valid list") {
            assert_eq!(a.challenge_types(), &["http-01"], "{a:?}");
        }
        let flagged = AuthzIdentifier {
            id_type: "ip".to_string(),
            value: "192.0.2.1".to_string(),
            wildcard: true,
        };
        assert_eq!(flagged.challenge_types(), &["http-01"]);
    }

    /// RFC-003: for every plain dns name length 200..=253 (long labels and
    /// many short labels), dns-01 is offered iff `_acme-challenge.<name>.`
    /// fits in 255 wire octets, i.e. iff the name is at most 237 octets;
    /// http-01 and tls-alpn-01 are always offered.
    #[test]
    fn qa_dns01_offered_iff_query_name_fits() {
        // A name of exactly `n` octets: labels of `label_len` octets in
        // front of a `zz`/`zzz` TLD, with one shorter label taking up the rest.
        let build = |n: usize, label_len: usize| -> String {
            let mut total = 2;
            let mut tld = "zz".to_string();
            let mut labels: Vec<String> = Vec::new();
            while total + label_len < n {
                labels.push("a".repeat(label_len));
                total += label_len + 1;
            }
            match n - total {
                0 => {}
                1 => tld.push('z'),
                r => labels.push("c".repeat(r - 1)),
            }
            labels.push(tld);
            labels.join(".")
        };
        for n in 200..=253 {
            for name in [build(n, 63), build(n, 1)] {
                assert_eq!(name.len(), n, "{name}");
                let a = parse_order_identifier(&dns(&name)).expect("valid name");
                let offered = a.challenge_types();
                assert!(offered.contains(&"http-01"));
                assert!(offered.contains(&"tls-alpn-01"));
                assert_eq!(
                    offered.contains(&"dns-01"),
                    dns01_query_name(&a.value).is_ok(),
                    "len {n}"
                );
                assert_eq!(offered.contains(&"dns-01"), n <= 237, "len {n}");
            }
        }
    }
}
