//! `fips_gate()` must refuse to start when a non-FIPS rustls provider was
//! installed as the process default before it ran.
//!
//! Its own test binary (own process): the process-default provider can be set
//! only once, so this must not share a process with other tests.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, SC-13 (FIPS-only crypto), SC-24 (fail in known state)
//! - NIAP PP-CA: FPT_TST_EXT.1 (startup check), FCS_COP.1

#[test]
fn fips_gate_refuses_preinstalled_non_fips_default() {
    // aws-lc-rs provider plus plain X25519 (not FIPS-approved).
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .push(rustls::crypto::aws_lc_rs::kx_group::X25519);
    assert!(!provider.fips(), "test precondition: provider is non-FIPS");
    provider
        .install_default()
        .expect("first install in this process");

    let err = ostrich_common::tls::fips_gate().expect_err("gate must refuse");
    assert!(
        err.to_string().contains("not in FIPS mode"),
        "unexpected error: {err}"
    );
    // Still refused on a second attempt (no silent replacement).
    assert!(ostrich_common::tls::fips_gate().is_err());
}
