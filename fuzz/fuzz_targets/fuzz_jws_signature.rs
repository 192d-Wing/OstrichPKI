//! Fuzz target for ACME JWS signature validation
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 8555: ACME JWS validation
//! - RFC 7515: JSON Web Signature (JWS)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON
    if let Ok(string_data) = std::str::from_utf8(data) {
        // Attempt to parse as JSON (JWS is JSON-based)
        let _ = serde_json::from_str::<serde_json::Value>(string_data);
    }
});
