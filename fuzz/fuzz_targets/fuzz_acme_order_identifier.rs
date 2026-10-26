//! Fuzz target for ACME newOrder identifier validation
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - NIST 800-53: AC-3 (Access Enforcement) - wildcard authz offered dns-01 only
//! - RFC 8555 §7.1.3 / §7.1.4 / §7.4 - wildcard order identifiers
//! - RFC 8738 §3 / §7 - canonical `ip` identifiers, never offered dns-01
//!
//! Input: first byte selects the identifier type, the rest is the
//! subscriber-controlled value. `parse_order_identifier` must never panic and
//! every accepted identifier must satisfy the offering invariants below.
//!
//! The same value is also split on `,` into a list (each element's first
//! byte again selecting the type) and passed to `validate_order_identifiers`,
//! which must never panic and, when it accepts, return one authorization per
//! identifier, at most `MAX_ORDER_IDENTIFIERS`, with unique
//! `(type, lowercase value, wildcard)` keys.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_acme::identifier::{
    MAX_ORDER_IDENTIFIERS, parse_order_identifier, validate_order_identifiers,
};
use ostrich_acme::order::Identifier;
use ostrich_acme::validation::{dns01_query_name, validate_dns_identifier};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(value) = std::str::from_utf8(rest) else {
        return;
    };
    check_list(value);
    let id_type = id_type_for(selector);
    let id = Identifier {
        id_type: id_type.to_string(),
        value: value.to_string(),
    };
    let Ok(authz) = parse_order_identifier(&id) else {
        return;
    };
    // Only exact "dns" / "ip" types are accepted.
    assert!(id_type == "dns" || id_type == "ip");
    assert_eq!(authz.id_type, id_type);
    // Authorization values never contain a wildcard label.
    assert!(!authz.value.contains('*'));
    let offered = authz.challenge_types();
    assert!(!offered.is_empty());
    match (authz.id_type.as_str(), authz.wildcard) {
        ("ip", wildcard) => {
            assert!(!wildcard);
            // RFC 8738 §7: never dns-01; RFC 8738 §6 (POAM-2026-10-23-52):
            // no tls-alpn-01 either.
            assert_eq!(offered, &["http-01"]);
            // RFC 8738 §3: canonical text round-trips.
            let ip: std::net::IpAddr = authz.value.parse().expect("accepted ip parses");
            assert_eq!(ip.to_string(), authz.value);
        }
        ("dns", true) => {
            // RFC 8555 §7.1.4: base of `*.<base>`, dns-01 only, query fits.
            assert_eq!(value.strip_prefix("*."), Some(authz.value.as_str()));
            assert_eq!(offered, &["dns-01"]);
            assert!(authz.value.contains('.'));
            assert!(dns01_query_name(&authz.value).is_ok());
        }
        ("dns", false) => {
            assert_eq!(authz.value, value);
            assert!(validate_dns_identifier(&authz.value).is_ok());
            assert!(value.len() <= 253);
            // RFC-003: dns-01 offered exactly when its query name fits.
            assert_eq!(
                offered.contains(&"dns-01"),
                dns01_query_name(&authz.value).is_ok()
            );
        }
        _ => unreachable!("unexpected identifier type"),
    }
});

fn id_type_for(selector: u8) -> &'static str {
    match selector % 4 {
        0 => "dns",
        1 => "ip",
        2 => "DNS",
        _ => "email",
    }
}

/// `validate_order_identifiers` on the input split into a list.
fn check_list(value: &str) {
    let ids: Vec<Identifier> = value
        .split(',')
        .map(|part| {
            let (selector, rest) = match part.as_bytes().first() {
                Some(&b) if b.is_ascii() => (b, &part[1..]),
                _ => (0, part),
            };
            Identifier {
                id_type: id_type_for(selector).to_string(),
                value: rest.to_string(),
            }
        })
        .collect();
    let Ok(authzs) = validate_order_identifiers(&ids) else {
        return;
    };
    assert_eq!(authzs.len(), ids.len());
    assert!(!authzs.is_empty());
    assert!(authzs.len() <= MAX_ORDER_IDENTIFIERS);
    let mut keys = std::collections::HashSet::new();
    for (id, authz) in ids.iter().zip(&authzs) {
        assert_eq!(authz.id_type, id.id_type);
        assert!(!authz.value.contains('*'));
        assert!(
            keys.insert((
                authz.id_type.clone(),
                authz.value.to_ascii_lowercase(),
                authz.wildcard,
            )),
            "duplicate authorization key accepted"
        );
        // Each element is individually acceptable.
        assert_eq!(parse_order_identifier(id).ok().as_ref(), Some(authz));
    }
}
