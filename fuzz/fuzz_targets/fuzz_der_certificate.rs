//! Fuzz target for DER-encoded X.509 certificate parsing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//!
//! This fuzzer tests the robustness of X.509 certificate parsing against
//! malformed, malicious, or random input data.

#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::Certificate;

fuzz_target!(|data: &[u8]| {
    // Try to parse the fuzzed data as a DER-encoded certificate
    // This should never panic, even on malformed input
    let _ = Certificate::from_der(data);
});
