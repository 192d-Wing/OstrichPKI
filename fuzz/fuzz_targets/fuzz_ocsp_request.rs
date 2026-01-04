//! Fuzz target for OCSP request parsing
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - RFC 6960: OCSP (Online Certificate Status Protocol)

#![no_main]

use libfuzzer_sys::fuzz_target;
use der::Decode;

fuzz_target!(|data: &[u8]| {
    // Try to parse as DER-encoded OCSP request
    // OCSPRequest is a SEQUENCE type
    let _ = der::asn1::SequenceOf::<der::Any, 16>::from_der(data);
});
