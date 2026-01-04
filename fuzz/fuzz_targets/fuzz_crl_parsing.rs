//! Fuzz target for X.509 Certificate Revocation List (CRL) parsing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 5280: X.509 CRL Profile

#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::crl::CertificateList;

fuzz_target!(|data: &[u8]| {
    // Try to parse the fuzzed data as a DER-encoded CRL
    // This should never panic, even on malformed input
    let _ = CertificateList::from_der(data);
});
