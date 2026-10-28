//! Fuzz target for the ACME dns-01 query-name builder
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 8555 §8.4 - `_acme-challenge.<domain>` TXT owner name
//! - RFC 1035 §2.3.1 / §3.1 - LDH labels, 255-octet name limit
//!
//! Feeds arbitrary UTF-8 (the subscriber-controlled ACME identifier) to
//! `dns01_query_name`. It must never panic, and every accepted name must be a
//! fully qualified `_acme-challenge` name within the DNS length limit with no
//! wildcard label. Identifiers with a trailing dot are never accepted
//! (RFC 8555 §7.1.4 / RFC 5280 §4.2.1.6 certificate form; RFC-008).

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_acme::validation::dns01_query_name;

fuzz_target!(|data: &[u8]| {
    let Ok(identifier) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = dns01_query_name(identifier) {
        // RFC-008: only certificate-form identifiers (no trailing dot).
        assert!(!identifier.ends_with('.'));
        // RFC-004: always an FQDN, so search domains cannot rewrite it.
        assert!(name.is_fqdn());
        // RFC 8555 §8.4: first label is the challenge label.
        let mut labels = name.iter();
        assert_eq!(labels.next(), Some(&b"_acme-challenge"[..]));
        // RFC 1035 §3.1: 255 octets on the wire.
        assert!(name.len() <= 255);
        // Wildcards are rejected (RFC 8555 §7.1.3 handled at order level).
        assert!(name.iter().all(|label| !label.contains(&b'*')));

        // SI-10 oracle (QA): every identifier label is a non-empty LDH label of
        // at most 63 octets with no leading/trailing hyphen (RFC 1035 §2.3.1).
        let domain_labels: Vec<&[u8]> = name.iter().skip(1).collect();
        assert!(!domain_labels.is_empty());
        for label in &domain_labels {
            assert!(!label.is_empty() && label.len() <= 63);
            assert!(label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-'));
            assert!(label.first() != Some(&b'-') && label.last() != Some(&b'-'));
        }
        // RFC 3696 §2: the top-level label is never all-numeric (no IP literals).
        let tld = domain_labels.last().copied().unwrap_or_default();
        assert!(!tld.iter().all(u8::is_ascii_digit));
        // Byte-exact round trip: no case folding, IDNA mapping or label
        // rewriting between the identifier and the queried owner name.
        let joined = domain_labels.join(&b'.');
        assert_eq!(joined.as_slice(), identifier.as_bytes());
    }
});
