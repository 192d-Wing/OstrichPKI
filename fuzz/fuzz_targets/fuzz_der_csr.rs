//! Fuzz target for PKCS#10 Certificate Signing Request parsing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 2986: PKCS #10 Certificate Request Syntax

#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::request::CertReq;

fuzz_target!(|data: &[u8]| {
    // Try to parse the fuzzed data as a DER-encoded CSR
    // This should never panic, even on malformed input
    let _ = CertReq::from_der(data);
});
