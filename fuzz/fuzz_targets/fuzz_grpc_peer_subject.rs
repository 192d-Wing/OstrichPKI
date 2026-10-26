//! Fuzz target for the gRPC client-certificate subject check
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - NIST 800-53: AC-3 (Access Enforcement) - the allowlist decision input
//!
//! Feeds arbitrary bytes to `certificate_subject_dn` (the verified peer leaf
//! is attacker-chosen within a trusted CA's issuance policy) and, when a
//! subject is produced, to `ClientSubjectAllowlist::is_allowed` and
//! `GrpcClientRegistry::identity`. Arbitrary UTF-8 is also fed to
//! `ClientSubjectAllowlist::parse` and, split into three role lists, to
//! `GrpcClientRegistry::parse` (operator config). None of these may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_common::grpc_tls::{
    certificate_subject_dn, ClientSubjectAllowlist, GrpcClientRegistry,
};

fuzz_target!(|data: &[u8]| {
    let allowlist = ClientSubjectAllowlist::parse(&["CN=acme-server".to_string()])
        .expect("static allowlist parses");
    let registry = GrpcClientRegistry::parse(
        &["CN=acme-server".to_string()],
        &["CN=est-server".to_string()],
        &["CN=ops-admin".to_string()],
    )
    .expect("static registry parses");
    if let Some(subject) = certificate_subject_dn(data) {
        let _ = allowlist.is_allowed(&subject);
        let _ = registry.identity(&subject);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let entries: Vec<String> = text.split(';').map(str::to_string).collect();
        if let Ok(parsed) = ClientSubjectAllowlist::parse(&entries) {
            let _ = parsed.is_allowed(text);
        }
        // Three role lists: `|` separates the lists, `;` the entries.
        let mut lists = text
            .splitn(3, '|')
            .map(|l| l.split(';').map(str::to_string).collect::<Vec<_>>());
        let acme = lists.next().unwrap_or_default();
        let est = lists.next().unwrap_or_default();
        let admin = lists.next().unwrap_or_default();
        if let Ok(parsed) = GrpcClientRegistry::parse(&acme, &est, &admin) {
            for entry in acme.iter().chain(&est).chain(&admin) {
                let _ = parsed.identity(entry);
            }
            // QA (AC-5): an accepted registry has at least one issuer and
            // pairwise-disjoint role lists, and every canonical subject maps
            // to the identity of the list it is in.
            let summary = parsed.summary();
            let list = |k: &str| -> Vec<String> {
                summary[k]
                    .as_array()
                    .expect("array")
                    .iter()
                    .map(|v| v.as_str().expect("string").to_string())
                    .collect()
            };
            let (a, e, m) = (list("acme"), list("est"), list("admin"));
            assert!(!(a.is_empty() && e.is_empty()), "no issuer accepted");
            // RFC-006: no subject collides with another list's subject even
            // after ASCII case folding.
            for (x, y) in [(&a, &e), (&a, &m), (&e, &m)] {
                for dn in x.iter() {
                    assert!(
                        !y.iter().any(|o| o.eq_ignore_ascii_case(dn)),
                        "case-folded overlap {dn}"
                    );
                }
            }
            for dn in &a {
                assert!(!e.contains(dn) && !m.contains(dn), "overlap {dn}");
                assert_eq!(parsed.identity(dn).map(|i| i.namespace), Some("acme"));
            }
            for dn in &e {
                assert!(!m.contains(dn), "overlap {dn}");
                assert_eq!(parsed.identity(dn).map(|i| i.namespace), Some("est"));
            }
            for dn in &m {
                assert_eq!(parsed.identity(dn).map(|i| i.namespace), Some("admin"));
            }
        }
    }
});
