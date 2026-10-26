//! Fuzz target for the gRPC client-certificate subject check
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - NIST 800-53: AC-3 (Access Enforcement) - the allowlist decision input
//!
//! Feeds arbitrary bytes to `certificate_subject_dn` (the verified peer leaf
//! is attacker-chosen within a trusted CA's issuance policy) and, when a
//! subject is produced, to `ClientSubjectAllowlist::is_allowed`. Arbitrary
//! UTF-8 is also fed to `ClientSubjectAllowlist::parse` (operator config).
//! None of these may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_common::grpc_tls::{certificate_subject_dn, ClientSubjectAllowlist};

fuzz_target!(|data: &[u8]| {
    let allowlist = ClientSubjectAllowlist::parse(&["CN=acme-server".to_string()])
        .expect("static allowlist parses");
    if let Some(subject) = certificate_subject_dn(data) {
        let _ = allowlist.is_allowed(&subject);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let entries: Vec<String> = text.split(';').map(str::to_string).collect();
        if let Ok(parsed) = ClientSubjectAllowlist::parse(&entries) {
            let _ = parsed.is_allowed(text);
        }
    }
});
