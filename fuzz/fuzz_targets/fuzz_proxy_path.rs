//! Fuzz target for the BFF proxy raw-path validator
//! (`ostrich_common::util::proxy_path`, POAM-2026-10-23-46).
//!
//! Invariants checked on every input:
//! - no panic on arbitrary (UTF-8) input;
//! - an accepted remainder is an unmodified suffix of the input;
//! - every accepted segment is non-empty, strictly percent-decodable, not a
//!   dot segment, and decodes to no delimiter (`/ ? # \`) or control byte.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 3986 §2.1, §3.3, §5.2.4

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_common::util::proxy_path::{percent_decode_segment, validate_backend_path};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    // Raw input plus prefixed variants so most inputs reach segment checks.
    let candidates = [
        (input.to_owned(), "ca"),
        (format!("/ca/{input}"), "ca"),
        (format!("/api/est/{input}"), "est"),
    ];
    for (path, svc) in &candidates {
        let input = path.as_str();
        if let Ok(rest) = validate_backend_path(input, svc) {
            assert!(input.ends_with(rest), "accepted remainder must be a suffix");
            for segment in rest.split('/') {
                assert!(!segment.is_empty(), "empty segment accepted");
                let decoded = percent_decode_segment(segment).expect("accepted segment decodes");
                assert!(decoded != b"." && decoded != b"..", "dot segment accepted");
                assert!(
                    !decoded
                        .iter()
                        .any(|&b| matches!(b, b'/' | b'?' | b'#' | b'\\' | 0x00..=0x1F | 0x7F)),
                    "delimiter or control byte accepted"
                );
            }
        }
    }
});
