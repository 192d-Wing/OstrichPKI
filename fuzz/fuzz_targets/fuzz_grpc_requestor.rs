//! Fuzz target for the CA gRPC requestor binding
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Security Testing - Fuzz Testing)
//! - NIST 800-53: SI-10 (Information Input Validation)
//! - NIST 800-53: AU-3 (the bound requestor is recorded as on_behalf_of)
//! - NIAP PP-CA: FAU_GEN.2
//!
//! Feeds arbitrary UTF-8 (the client-asserted `requestor` field of
//! IssueCertificate / RevokeCertificate) to `validate_requestor` with each
//! client identity. It must never panic, and an accepted requestor must be
//! `<caller namespace>::<non-empty id>`, at most `MAX_REQUESTOR_LEN` bytes,
//! with an id of printable ASCII `0x21..=0x7E` only (SEC-002 allowlist: no
//! control, space, separator, bidi or other non-ASCII character); an admin
//! may send an empty requestor.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ostrich_common::grpc_tls::{validate_requestor, GrpcClientIdentity, MAX_REQUESTOR_LEN};

fuzz_target!(|data: &[u8]| {
    let Ok(requestor) = std::str::from_utf8(data) else {
        return;
    };
    for identity in [
        GrpcClientIdentity::ACME,
        GrpcClientIdentity::EST,
        GrpcClientIdentity::ADMIN,
    ] {
        match validate_requestor(identity, requestor) {
            Ok(Some(bound)) => {
                assert_eq!(bound, requestor);
                let (prefix, id) = bound.split_once("::").expect("namespace separator");
                assert_eq!(prefix, identity.namespace);
                assert!(!id.is_empty());
                assert!(bound.len() <= MAX_REQUESTOR_LEN);
                assert!(!bound.chars().any(char::is_control));
                // SEC-002: the whole accepted value is printable ASCII
                // (namespace prefix and `::` included), so no bidi,
                // zero-width, separator or tag character can be accepted.
                assert!(bound.bytes().all(|b| (0x21..=0x7E).contains(&b)));
                // QA: a value bound to one namespace is refused for the other
                // identities (namespaces are mutually exclusive).
                for other in [
                    GrpcClientIdentity::ACME,
                    GrpcClientIdentity::EST,
                    GrpcClientIdentity::ADMIN,
                ] {
                    if other != identity {
                        assert!(validate_requestor(other, requestor).is_err());
                    }
                }
            }
            Ok(None) => {
                assert!(requestor.is_empty());
                assert_eq!(identity, GrpcClientIdentity::ADMIN);
            }
            Err(rejection) => {
                assert!(rejection.reason().starts_with("requestor_"));
            }
        }
        // QA: the decision is deterministic.
        assert_eq!(
            validate_requestor(identity, requestor),
            validate_requestor(identity, requestor)
        );
    }
});
