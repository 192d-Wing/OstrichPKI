//! Fuzz target for PEM-encoded X.509 certificate parsing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)

#![no_main]

use libfuzzer_sys::fuzz_target;
use pem_rfc7468::decode_vec;

fuzz_target!(|data: &[u8]| {
    // Try to decode PEM data
    if let Ok(string_data) = std::str::from_utf8(data) {
        let _ = decode_vec(string_data.as_bytes());
    }
});
