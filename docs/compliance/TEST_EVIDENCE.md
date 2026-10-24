# OstrichPKI Test Evidence Package

**Document Version:** 1.2
**Last Updated:** 2026-10-23
**NIAP Reference:** ATE_COV.1, ATE_FUN.1, ATE_IND.2
**Total Tests:** 256 unit tests passing (January 2026 baseline). Latest recorded run: 649 unit tests passed, 2026-10-23 (§2.3)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Test Summary](#2-test-summary)
3. [Unit Test Results](#3-unit-test-results)
4. [Integration Test Results](#4-integration-test-results)
5. [Security Test Results](#5-security-test-results)
6. [Performance Test Results](#6-performance-test-results)
7. [SFR Test Coverage](#7-sfr-test-coverage)
8. [Test Artifacts](#8-test-artifacts)

---

## 1. Overview

### 1.1 Purpose

This document provides comprehensive test evidence for OstrichPKI v1.0 in support of NIAP PP-CA v2.1 certification. All test results demonstrate compliance with Security Functional Requirements (SFRs).

### 1.2 Test Environment

| Component | Version/Configuration |
|-----------|----------------------|
| Operating System | Ubuntu 22.04 LTS |
| Rust Compiler | 1.75.0 |
| PostgreSQL | 15.4 |
| SoftHSM | 2.6.1 |
| Test Framework | Rust built-in `#[test]` |

### 1.3 Test Execution Date

**Latest Full Test Run:** January 2026

```bash
$ cargo test --workspace
   Compiling ostrich-pki v1.0.0
    Finished test [unoptimized + debuginfo] target(s) in 45.23s
     Running unittests
test result: ok. 256 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

---

## 2. Test Summary

### 2.1 Overall Results

| Category | Total | Pass | Fail | Skip |
|----------|-------|------|------|------|
| Unit Tests | 256 | 256 | 0 | 0 |
| Integration Tests | TBD | - | - | - |
| Security Tests | TBD | - | - | - |
| Performance Tests | TBD | - | - | - |

### 2.2 Test Coverage by Crate

| Crate | Tests | Status | Coverage |
|-------|-------|--------|----------|
| ostrich-db | 49 | Pass | Models, repositories |
| ostrich-common | 40 | Pass | Error, OID, types |
| ostrich-ocsp | 28 | Pass | Request, response, error |
| ostrich-crypto | 15 | Pass | Algorithms, providers |
| ostrich-x509 | 14 | Pass | Builder, CRL, extensions |
| ostrich-acme | 12 | Pass | Challenge, validation |
| ostrich-est | 12 | Pass | REST, CSR validation |
| ostrich-scms | 11 | Pass | Token lifecycle |
| ostrich-kra | 10 | Pass | Escrow, recovery |
| ostrich-audit | 5+ | Pass | Events, sinks |

### 2.3 Test Run 2026-10-23 (Dependency Advisory Remediation)

**Scope:** branch `claude/audit-advisories-clippy` (uncommitted, based on
`main` @ 88c10cd), covering dependency advisory fixes, the zip 9 migration,
and clippy fixes.
**Host:** macOS (Darwin 27.0.0, aarch64), rustc 1.99.1 stable, OpenSSL 4.0.3,
cargo-audit 0.22.2, cargo-deny 0.20.2.
**Not available on the host:** SoftHSM, PostgreSQL, Docker.
**Sources:** `qa-report.md` (QA engineer) and `fixes-round-1.md` (re-run after
the round-1 fixes), in `target/agent-workflow/20261023-185030-audit-advisories/`.
A gate that did not execute is recorded as NOT RUN, even when the test harness
printed `ok`.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Format | `cargo fmt --all --check` | PASS | exit 0 |
| Build | `cargo build --workspace` | PASS | exit 0 |
| Lint | `make clippy` (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) | PASS | exit 0 (rustc 1.99.1) |
| Unit | `make test-unit` (`cargo test --workspace --all-features --lib`) | PASS | **649 passed, 0 failed** across 16 lib targets (after fixes, `fixes-round-1.md`). QA run before the fixes: 646 passed, 0 failed, 1 ignored |
| Unit (scoped) | `cargo test -p ostrich-ca --lib` | PASS | 50 passed (after fixes); `extract_csr_entries` subset 21 passed in the QA run |
| Unit (scoped) | `cargo test -p ostrich-common --lib tls::tests` | PASS | 12 passed (7 new rustls handshake tests) |
| Unit (scoped) | `cargo test -p ostrich-crypto --lib self_test` | PASS | 11 passed (incl. new `aws_lc_module_reports_fips_mode`) |
| Doc | `make test-doc` | FAIL (environment, pre-existing) | rustdoc binaries cannot load the AWS-LC FIPS dylib on macOS; reproduces on `main` (QA-003) |
| Supply chain | `cargo audit` | PASS | 1351 advisories, 642 crates, **0 vulnerabilities, 0 warnings** (baseline on `main`: 18 vulnerabilities, 4 warnings) |
| Supply chain | `cargo deny check` | FAIL (config, pre-existing) | `deny.toml` fails validation (5 removed keys); no policy evaluated (QA-002) |
| Integration | `mtls_peercert_e2e` | PASS (executed) | 1 passed |
| Integration | `fips_signature_openssl_interop` | PASS (executed) | 1 passed |
| Integration | `mlkem_openssl_interop` | PASS (executed, OpenSSL 4.0.3) | 2 passed |
| Integration | `csr_parsing_test` | PASS | 5 passed, 1 ignored |
| Integration | `session_store_e2e`, `lockout_e2e`, `tamp_store_e2e`, `est_serverkeygen_e2e` | **NOT RUN** | Reported 14 "passed", but every test skipped early (no `DATABASE_URL` / database unreachable; QA-005) |
| Integration | `acme_full_flow_test` | **NOT RUN** | 1 ignored (needs live `ACME_URL`) |
| Integration | `est_e2e_test`, `ca_core_test`, `ocsp_e2e_test`, `acme_e2e_test` | **NOT RUN** (no Docker) | Health/readiness tests failed with `ConnectionRefused`; only `common::` helper tests passed |
| Integration | `ocsp_revocation_test` (live part) | **NOT RUN** | 9 helper tests passed; `test_ocsp_good_then_revoked` ignored |
| PKCS#11 | `cargo test -p ostrich-crypto --test pkcs11_integration_test -- --test-threads=1` | **NOT RUN** (no SoftHSM) | 0 passed, 19 failed, 1 ignored: every test panics with `SoftHSM library not found` |
| Fuzz | — | **NOT RUN** | No fuzz target exists for `extract_csr_entries` |

**QA-004: the cryptoki fix is untested.** cryptoki 0.11.0 → 0.11.1 fixes
RUSTSEC-2026-0286 (out-of-bounds read decoding `CKA_ALLOWED_MECHANISMS`). No
PKCS#11 test ran: SoftHSM was not installed, and no CI workflow runs
`pkcs11_integration_test`. The PQC reviewer found that
`crates/ostrich-crypto/src/pkcs11/mod.rs` never reads `AllowedMechanisms`. That
is a code-review finding, not test evidence. There is no SA-11 evidence for the
HSM path of this update (POA&M in NIAP_GAP_ANALYSIS.md §11). Narrowed later
on 2026-10-23: a SoftHSM CI job was added and the suite ran locally; see §2.4.

**New tests in this run:**

- `crates/ostrich-ca/src/rest.rs` (`mod tests`): ZIP extraction under zip 9.
  Covers deflate and stored entries, symlink and directory entries, size and
  count limits (with boundaries), deflate bomb, lying sizes, bad CRC, encrypted
  and unsupported entries, CP437 and UTF-8 names, traversal names as labels,
  and entry-name rejection (NUL, CRLF, ESC, DEL, C1, Unicode bidi/zero-width
  format characters such as RLO, and the 255-byte limit), with no-echo checks.
  After fix round 2: `cargo test -p ostrich-ca --lib` 54 passed; `make test-unit`
  653 passed, 0 failed, 1 ignored (`fixes-round-2.md`, re-run by orchestrator).
- `crates/ostrich-common/src/tls.rs` (`mod tests`):
  `load_builds_fips_config_with_alpn`, `mtls_handshake_accepts_trusted_client`,
  `mtls_handshake_rejects_untrusted_client`,
  `mtls_handshake_rejects_missing_client_cert`,
  `optional_mtls_allows_anonymous_but_rejects_untrusted`,
  `server_rejects_tls12_only_client`,
  `mtls_handshake_rejects_client_cert_with_server_only_eku`.
- `crates/ostrich-crypto/src/self_test.rs`: `aws_lc_module_reports_fips_mode`
  (`try_fips_mode()` and a SHA-256 KAT through AWS-LC FIPS 4.2.0).

**Not covered:** ML-DSA verification in TLS (no test); the PostgreSQL-backed
paths; the live EST/ACME/CA/OCSP stack over rustls 0.23.46; and handler tests
for the web-ui `login`/`callback`/`userinfo` attribute-only change.

### 2.4 Test Run 2026-10-23 (CI Hardening)

**Scope:** branch `claude/ci-hardening` (uncommitted, based on `main` @
48b70b4). CI, build and dev-tooling configuration only: dependency gate,
`rust-toolchain.toml`, `deny.toml`, GitLab image, SoftHSM CI job, Makefile
`install-softhsm`. No Rust source and no `Cargo.lock` change.
**Host:** macOS (Darwin, arm64), rustup 1.29.2, rustc 1.99.1 (pinned by
`rust-toolchain.toml`), cargo-audit 0.22.2, cargo-deny 0.20.2, SoftHSM 2.7.0
(Homebrew, linked to OpenSSL 4).
**Not available on the host:** Docker, PostgreSQL, actionlint, shellcheck.
**Sources:** `qa-report.md` and `fixes-round-1.md` in
`target/agent-workflow/20261023-201031-ci-hardening/`. A gate that did not
execute is recorded as NOT RUN.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Toolchain | `rustup show active-toolchain` | PASS | `1.99.1-aarch64-apple-darwin (overridden by '…/rust-toolchain.toml')`; MSRV `rust-version = "1.94"` unchanged |
| Format | `cargo fmt --all --check` | PASS | exit 0 |
| Lint | `make clippy` | PASS | exit 0 |
| Unit | `make test-unit` | PASS | 653 passed, 0 failed, 1 ignored (16 lib targets) |
| Supply chain | `cargo audit --deny warnings` | PASS | exit 0; 642 crates; 0 vulnerabilities, 0 warnings |
| Supply chain | `cargo deny check` | PASS | exit 0; `advisories ok, bans ok, licenses ok, sources ok` |
| Supply chain, negative | `cargo deny` / `cargo audit` with one exception removed (scratch copies) | PASS (gate fails as intended) | 9 cases (6 `cargo deny`, 3 `cargo audit`), each exits non-zero (`qa-report.md` gates 7-12, 14-16) |
| Toolchain-pin check | `ci.yml` job `Toolchain pin consistency`, run locally | PASS | positive exit 0; 18 positive/negative cases behave as expected (`fixes-round-1.md`) |
| Workflow YAML | Ruby YAML parse and structure check | PASS | `ci.yml`, `audit.yml`, `hsm-integration.yml`, `.gitlab-ci.yml` parse; every `uses:` SHA-pinned |
| Workflow lint | `actionlint` / `shellcheck` | **NOT RUN** | not installed |
| SoftHSM token | `make install-softhsm` (scratch `HOME`/paths, run twice) | PASS | token `OstrichPKI-Test` created, second run idempotent, dirs `0700` |
| PKCS#11 (as documented) | `make test-pkcs11` | FAIL (macOS environment) | `SIGSEGV` at test-thread exit; known SoftHSM/OpenSSL 4 issue on macOS, documented in the Makefile |
| PKCS#11 (macOS workaround) | test binary run directly with `SOFTHSM2_CONF`, `PKCS11_MODULE_PATH`, `DYLD_LIBRARY_PATH` and `DYLD_INSERT_LIBRARIES` (non-standard invocation) | FAIL (3 known) | **16 passed, 3 failed, 1 ignored**. Failed: `test_rsa_pss_signing_and_verification`, `test_multiple_keys_same_provider`, `test_deterministic_signatures_rsa_pss` (RSA-PSS signing returns `CKR_GENERAL_ERROR`). Ignored: `test_key_wrapping_and_unwrapping` |
| PKCS#11 (Linux CI) | `hsm-integration.yml` job `PKCS#11 suite (SoftHSM2)` | **NOT RUN** | needs a push; result decides whether the RSA-PSS tests get a POA&M. Later runs recorded in §2.5 (before the fix 16/3/1, exit 101; after the fix 28/0/1, exit 0, run 40063317654) |
| GitHub / GitLab pipelines | — | **NOT RUN** | needs a push |
| Docker builds | `docker build` | **NOT RUN** | Docker not available |
| Integration | `make test-integration` | **NOT RUN** | PostgreSQL and live services not available |

**QA-004 (from §2.3), narrowed.** The PKCS#11 suite now has a CI job and
executed locally against cryptoki 0.11.1 and SoftHSM 2.7.0. The local result
uses a non-standard invocation on macOS and is not a substitute for the Linux
CI result. RSA-PSS signing through PKCS#11 is not demonstrated. The run does
not exercise the `CKA_ALLOWED_MECHANISMS` decode path fixed by
RUSTSEC-2026-0286. POAM-2026-10-23-07 stays open until the Linux CI artifact
`pkcs11-softhsm-results` is attached. (Update: attached and POAM-07 closed
2026-10-23; see §2.5.)

**Tests added:** none (no Rust source changed). The evidence is the
configuration-level positive and negative checks above.

### 2.5 Test Run 2026-10-23 (PKCS#11 RSA-PSS Fix)

**Scope:** branch `claude/ci-hardening` @ db09c14 plus the changes later
committed as 44d560d (PR 181):
`crates/ostrich-crypto/src/pkcs11/mod.rs`, `crates/ostrich-crypto/src/provider.rs`
(doc comments only), `crates/ostrich-crypto/tests/pkcs11_integration_test.rs`,
`.cargo/audit.toml` and `deny.toml` (RUSTSEC-2026-0387 ignore). No
`Cargo.lock` change.
**Host:** macOS (Darwin, arm64), rustc 1.99.1, SoftHSM 2.7.0 (Homebrew), fresh
scratch token `OstrichPKI-Test`.
**Sources:** `qa-report.md`, `fixes-round-1.md`, `impl-notes.md` and
`ci-pkcs11-before.txt`, `ci-artifact-after/pkcs11.txt` and `gate.md` in
`target/agent-workflow/20261023-230002-pkcs11-rsa-pss/`. The Linux CI rows come
from the GitHub Actions job log artifact, not from `qa-report.md` (which records
that gate as NOT RUN locally). A gate that did not execute is recorded as NOT RUN.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| PKCS#11, **before fix** (Linux CI) | `hsm-integration.yml` job `PKCS#11 suite (SoftHSM2)`; ubuntu24 image 20261012.334.1, SoftHSM 2.6.1, rustc 1.99.1; commit `3943e9a` per the job log | FAIL (expected, the bug) | **16 passed, 3 failed, 1 ignored, exit 101**. Failed: `test_rsa_pss_signing_and_verification`, `test_deterministic_signatures_rsa_pss`, `test_multiple_keys_same_provider` (`CKR_GENERAL_ERROR` at `C_Sign`) |
| PKCS#11, before fix (local) | HEAD sources, same suite, macOS workaround invocation | FAIL (expected) | 16 passed, 3 failed, 1 ignored (same 3 tests) |
| PKCS#11, **after fix** (local) | test binary run directly with `SOFTHSM2_CONF`, `PKCS11_MODULE_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `--test-threads=1` (non-standard invocation) | PASS (exit 0), run twice | **28 passed, 0 failed, 1 ignored** (29 tests). Ignored: `test_key_wrapping_and_unwrapping` (needs a KEK), unchanged |
| PKCS#11 mutation check | QA: unfixed HEAD source + QA test file (27 runnable tests) in a separate worktree | FAIL as intended | 17 passed, 9 failed, 1 ignored: every RSA-PSS test fails, every non-PSS test passes |
| PKCS#11 mutation check | coder: restore the old `verify` error mapping (`Ok(false)` for every error) | FAIL as intended | 27 passed, 1 failed (failing test not named in `fixes-round-1.md`) |
| Unit (crate) | `cargo test -p ostrich-crypto --lib` | PASS | 65 passed, 0 failed |
| Unit | `make test-unit` | PASS | **661 passed, 0 failed, 1 ignored** |
| Format | `cargo fmt --all --check` | PASS | exit 0 |
| Lint | `make clippy` | PASS | exit 0 |
| Supply chain | `cargo audit --deny warnings` | FAIL before the ignore; PASS after | before: 1 vulnerability (RUSTSEC-2026-0387, `crypto-bigint` 0.5.5, published 2026-10-23, `Cargo.lock` unchanged); after the user-approved ignore (POAM-2026-10-23-16): exit 0 |
| Supply chain | `cargo deny check` | FAIL before the ignore; PASS after | before: `advisories FAILED, bans ok, licenses ok, sources ok`; after: exit 0. Ignore lists in `.cargo/audit.toml` and `deny.toml` identical (5 IDs) |
| Compliance | `make compliance-check`, `make compliance-annotations` | PASS | run by QA before round-1 fixes |
| PKCS#11 (Linux CI), **after fix** | `hsm-integration.yml` (workflow `HSM integration`) job `PKCS#11 suite (SoftHSM2)`, GitHub Actions [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654); ubuntu24 image 20261012.334.1, SoftHSM 2.6.1, rustc 1.99.1; GitHub head SHA 44d560d (PR 181 head); the artifact's `commit:` line shows the PR merge ref c67c10e | PASS (exit 0) | **28 passed, 0 failed, 1 ignored** (29 tests). All six `test_rsa_pss_*` tests ok, including `test_rsa_pss_hsm_sign_software_verify`; `test_deterministic_signatures_rsa_pss` and `test_multiple_keys_same_provider` ok. Ignored: `test_key_wrapping_and_unwrapping`. Meets the POAM-2026-10-23-17 close criterion |
| GitHub dependency gate | `audit.yml` jobs `cargo audit`, `cargo deny` (PR 181, run 40063317688) | PASS | both jobs green (`gh pr checks 181`: 12 of 12 checks pass) |
| GitLab dependency gate | `security:audit`, `security:deny` | **NOT RUN** | no GitLab pipeline result recorded for this change |
| Integration (Postgres), doc tests, fuzz | — | **NOT RUN** | not applicable to this change; no database available |

**Tests added** (`crates/ostrich-crypto/tests/pkcs11_integration_test.rs`):
`test_rsa_pss_hsm_sign_software_verify`, `test_rsa_pss_all_hashes_rsa3072_rsa4096`,
`test_rsa_pss_empty_message`, `test_rsa_pss_large_message`,
`test_rsa_pkcs1_all_hashes_hsm_sign_software_verify`,
`test_rsa_software_sign_hsm_verify`, `test_rsa_pss_verify_malformed_signature_denies`,
`test_pqc_algorithms_fail_closed_on_pkcs11`,
`test_verify_token_fault_is_error_not_rejection`. Negative HSM-verify checks now
assert exactly `Ok(false)` (SEC-003). Unit tests in
`crates/ostrich-crypto/src/pkcs11/mod.rs` `mod tests` (8):
`rsa_pss_input_is_sha2_digest_of_message`, `rsa_pss_input_hashes_digest_sized_message`,
`rsa_pss_profile_is_internally_consistent`, `rsa_pss_profile_rejects_non_pss`,
`rsa_pkcs1_input_is_message_unchanged`, `ecdsa_input_is_sha2_digest_of_message`,
`unsupported_algorithms_fail_closed`, `only_signature_rvs_are_rejections`.

**QA-004 (from §2.3/§2.4), narrowed again.** The Linux CI job has now run
before the fix (16/3/1, exit 101) and after it ([run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654), 28/0/1, exit 0).
RSA-PSS through PKCS#11 is **verified on SoftHSM 2.6.1 (Linux CI) and 2.7.0
(local), RSA-2048/3072/4096; production HSM not yet validated
(POAM-2026-10-23-21)**. POAM-2026-10-23-07 and POAM-2026-10-23-17 closed
2026-10-23. The `CKA_ALLOWED_MECHANISMS` decode path fixed by RUSTSEC-2026-0286
is still not exercised, because `ostrich-crypto/src/pkcs11` never reads that
attribute. QA-004 in this run (the
catch-all in `pkcs11_signature_input`) is fixed: the function returns an error
for unsupported algorithms and has no pass-through default.

**Not covered:** vendor HSMs (only SoftHSM); verify known-answer vectors
(NIST CAVP / RFC 8017); PSS signatures with sLen other than the hash length;
RSA-4096 software-sign → HSM-verify; the `CKA_ALLOWED_MECHANISMS` path;
provider-level audit events for sign/verify failures (QA-003); an RSA variant
of `audit_signing_e2e` (NIST-005).

---

## 3. Unit Test Results

### 3.1 ostrich-db (49 tests)

**Test File:** `crates/ostrich-db/src/models/*.rs`

#### Certificate Model Tests

```
test models::certificate::tests::test_certificate_model_new ... ok
test models::certificate::tests::test_certificate_model_with_builder ... ok
test models::certificate::tests::test_certificate_model_validity ... ok
test models::certificate::tests::test_certificate_status_enum ... ok
test models::certificate::tests::test_certificate_serialization ... ok
test models::certificate::tests::test_certificate_validity_check ... ok
test models::certificate::tests::test_certificate_expiration ... ok
test models::certificate::tests::test_certificate_revocation_info ... ok
```

#### Audit Model Tests

```
test models::audit::tests::test_audit_event_new ... ok
test models::audit::tests::test_audit_event_with_details ... ok
test models::audit::tests::test_audit_event_with_ip ... ok
test models::audit::tests::test_audit_event_with_user_agent ... ok
test models::audit::tests::test_audit_event_with_session ... ok
test models::audit::tests::test_audit_event_builder_chain ... ok
test models::audit::tests::test_audit_event_serialization ... ok
test models::audit::tests::test_audit_event_deserialization ... ok
```

#### ACME Model Tests

```
test models::acme::tests::test_acme_account_new ... ok
test models::acme::tests::test_acme_account_status ... ok
test models::acme::tests::test_acme_order_new ... ok
test models::acme::tests::test_acme_order_status_transitions ... ok
test models::acme::tests::test_acme_authorization_new ... ok
test models::acme::tests::test_acme_challenge_types ... ok
test models::acme::tests::test_acme_nonce_generation ... ok
test models::acme::tests::test_acme_nonce_expiry ... ok
test models::acme::tests::test_acme_order_finalization ... ok
test models::acme::tests::test_acme_serialization ... ok
```

#### EST Model Tests

```
test models::est::tests::test_est_enrollment_new ... ok
test models::est::tests::test_est_enrollment_status ... ok
test models::est::tests::test_est_client_model ... ok
test models::est::tests::test_est_enrollment_types ... ok
test models::est::tests::test_est_serialization ... ok
```

#### KRA Model Tests

```
test models::kra::tests::test_escrowed_key_new ... ok
test models::kra::tests::test_escrowed_key_status ... ok
test models::kra::tests::test_recovery_agent_new ... ok
test models::kra::tests::test_recovery_request_new ... ok
test models::kra::tests::test_recovery_share_validity ... ok
test models::kra::tests::test_m_of_n_threshold ... ok
test models::kra::tests::test_recovery_request_status ... ok
test models::kra::tests::test_kra_serialization ... ok
test models::kra::tests::test_share_submission ... ok
test models::kra::tests::test_threshold_validation ... ok
```

#### SCMS Model Tests

```
test models::scms::tests::test_token_model_new ... ok
test models::scms::tests::test_token_lifecycle_states ... ok
test models::scms::tests::test_token_state_transitions ... ok
test models::scms::tests::test_token_key_model ... ok
test models::scms::tests::test_token_event_logging ... ok
test models::scms::tests::test_token_activation ... ok
test models::scms::tests::test_token_suspension ... ok
test models::scms::tests::test_token_revocation ... ok
test models::scms::tests::test_token_pin_change ... ok
test models::scms::tests::test_token_unlock ... ok
test models::scms::tests::test_token_serialization ... ok
test models::scms::tests::test_token_event_types ... ok
test models::scms::tests::test_token_validity_period ... ok
test models::scms::tests::test_token_certificate_binding ... ok
```

### 3.2 ostrich-common (40 tests)

**Test File:** `crates/ostrich-common/src/*.rs`

#### Error Module Tests

```
test error::tests::test_error_display ... ok
test error::tests::test_error_constructors ... ok
test error::tests::test_is_security_relevant ... ok
test error::tests::test_public_message ... ok
test error::tests::test_error_variants ... ok
test error::tests::test_io_error_conversion ... ok
test error::tests::test_anyhow_error_conversion ... ok
test error::tests::test_security_relevant_crypto ... ok
```

#### OID Module Tests

```
test oid::tests::test_rsa_oids ... ok
test oid::tests::test_ecdsa_oids ... ok
test oid::tests::test_eddsa_oids ... ok
test oid::tests::test_hash_oids ... ok
test oid::tests::test_extension_oids ... ok
test oid::tests::test_pqc_oids ... ok
test oid::tests::test_unknown_oid ... ok
test oid::tests::test_eku_oids ... ok
test oid::tests::test_dn_attribute_oids ... ok
test oid::tests::test_aia_oids ... ok
```

#### Additional Common Tests

```
test types::tests::test_certificate_serial ... ok
test types::tests::test_distinguished_name ... ok
test encoding::tests::test_base64_encode ... ok
test encoding::tests::test_base64_decode ... ok
test encoding::tests::test_hex_encode ... ok
test random::tests::test_random_bytes ... ok
test random::tests::test_random_serial ... ok
test time::tests::test_utc_now ... ok
test time::tests::test_time_formatting ... ok
... (additional tests)
```

### 3.3 ostrich-ocsp (28 tests)

**Test File:** `crates/ostrich-ocsp/src/*.rs`

#### Request Module Tests

```
test request::tests::test_hash_algorithm_oid ... ok
test request::tests::test_ocsp_request_new ... ok
test request::tests::test_ocsp_request_with_nonce ... ok
test request::tests::test_ocsp_request_different_issuers_different_hashes ... ok
test request::tests::test_ocsp_request_same_issuer_same_hashes ... ok
test request::tests::test_hash_algorithm_equality ... ok
test request::tests::test_ocsp_request_clone ... ok
test request::tests::test_from_der_malformed ... ok
```

#### Response Module Tests

```
test response::tests::test_response_status_values ... ok
test response::tests::test_cert_status_good ... ok
test response::tests::test_cert_status_revoked ... ok
test response::tests::test_cert_status_unknown ... ok
test response::tests::test_single_response_structure ... ok
test response::tests::test_single_response_without_next_update ... ok
test response::tests::test_ocsp_response_successful ... ok
test response::tests::test_ocsp_response_error ... ok
test response::tests::test_ocsp_response_internal_error ... ok
test response::tests::test_ocsp_response_unauthorized ... ok
test response::tests::test_cert_status_revoked_reasons ... ok
test response::tests::test_cert_status_revoked_without_reason ... ok
test response::tests::test_ocsp_response_serialization ... ok
test response::tests::test_response_status_equality ... ok
test response::tests::test_cert_status_equality ... ok
test response::tests::test_multiple_responses ... ok
```

#### Error Module Tests

```
test error::tests::test_error_display ... ok
test error::tests::test_error_variants_exist ... ok
```

### 3.4 ostrich-crypto (15 tests)

```
test algorithm::tests::test_signature_algorithm_enum ... ok
test algorithm::tests::test_hash_algorithm_enum ... ok
test algorithm::tests::test_key_algorithm_enum ... ok
test algorithm::tests::test_algorithm_oid_mapping ... ok
test provider::tests::test_crypto_provider_trait ... ok
test provider::tests::test_software_provider ... ok
test key::tests::test_key_pair_generation ... ok
test key::tests::test_public_key_export ... ok
test signing::tests::test_sign_verify ... ok
test signing::tests::test_invalid_signature ... ok
test hashing::tests::test_sha256 ... ok
test hashing::tests::test_sha384 ... ok
test hashing::tests::test_sha512 ... ok
test random::tests::test_random_generation ... ok
test random::tests::test_serial_generation ... ok
```

### 3.5 ostrich-x509 (14 tests)

```
test builder::tests::test_certificate_builder ... ok
test builder::tests::test_certificate_extensions ... ok
test builder::tests::test_certificate_validity ... ok
test builder::tests::test_certificate_subject ... ok
test crl::tests::test_crl_builder ... ok
test crl::tests::test_crl_revocation_entry ... ok
test crl::tests::test_crl_extensions ... ok
test extensions::tests::test_key_usage ... ok
test extensions::tests::test_extended_key_usage ... ok
test extensions::tests::test_basic_constraints ... ok
test extensions::tests::test_subject_alt_name ... ok
test profile::tests::test_tls_server_profile ... ok
test profile::tests::test_code_signing_profile ... ok
test profile::tests::test_ca_profile ... ok
```

### 3.6 ostrich-acme (12 tests)

```
test challenge::tests::test_http_01_challenge ... ok
test challenge::tests::test_dns_01_challenge ... ok
test challenge::tests::test_tls_alpn_01_challenge ... ok
test validation::tests::test_domain_validation ... ok
test validation::tests::test_ip_validation ... ok
test jws::tests::test_jws_signing ... ok
test jws::tests::test_jws_verification ... ok
test jws::tests::test_jwk_thumbprint ... ok
test rest::tests::test_new_account ... ok
test rest::tests::test_new_order ... ok
test rest::tests::test_finalize_order ... ok
test rest::tests::test_get_certificate ... ok
```

### 3.7 ostrich-est (12 tests)

```
test rest::tests::test_simple_enroll ... ok
test rest::tests::test_simple_reenroll ... ok
test rest::tests::test_server_keygen ... ok
test rest::tests::test_ca_certs ... ok
test csr::tests::test_csr_parsing ... ok
test csr::tests::test_csr_validation ... ok
test csr::tests::test_csr_signature ... ok
test pkcs7::tests::test_pkcs7_response ... ok
test pkcs7::tests::test_certs_only ... ok
test mtls::tests::test_client_cert_validation ... ok
test mtls::tests::test_client_cert_dn_extraction ... ok
test mtls::tests::test_client_cert_attributes ... ok
```

### 3.8 ostrich-scms (11 tests)

```
test token::tests::test_token_creation ... ok
test token::tests::test_token_activation ... ok
test token::tests::test_token_suspension ... ok
test token::tests::test_token_revocation ... ok
test pin::tests::test_pin_verification ... ok
test pin::tests::test_pin_change ... ok
test pin::tests::test_pin_lockout ... ok
test lifecycle::tests::test_state_machine ... ok
test lifecycle::tests::test_valid_transitions ... ok
test lifecycle::tests::test_invalid_transitions ... ok
test events::tests::test_event_logging ... ok
```

### 3.9 ostrich-kra (10 tests)

```
test escrow::tests::test_key_escrow ... ok
test escrow::tests::test_key_retrieval ... ok
test recovery::tests::test_recovery_request ... ok
test recovery::tests::test_share_submission ... ok
test recovery::tests::test_threshold_recovery ... ok
test shamir::tests::test_secret_splitting ... ok
test shamir::tests::test_secret_reconstruction ... ok
test shamir::tests::test_insufficient_shares ... ok
test agent::tests::test_agent_creation ... ok
test agent::tests::test_agent_authorization ... ok
```

---

## 4. Integration Test Results

### 4.1 End-to-End Workflows

| Test | Description | Status |
|------|-------------|--------|
| ACME Account Creation | Create account with JWS | TBD |
| ACME Order Workflow | Full order → challenge → finalize | TBD |
| EST Simple Enroll | CSR submission via mTLS | TBD |
| Certificate Revocation | Revoke and verify in CRL | TBD |
| OCSP Query | Real-time status check | TBD |

### 4.2 Service Health Tests

| Service | Health Endpoint | Status |
|---------|-----------------|--------|
| CA | `/health` | Implemented |
| ACME | `/health` | Implemented |
| EST | `/.well-known/est/health` | Implemented |
| OCSP | `/health` | Implemented |

---

## 5. Security Test Results

### 5.1 Static Analysis (SAST)

```bash
$ cargo clippy -- -D warnings
    Checking ostrich-pki v1.0.0
    Finished dev [unoptimized + debuginfo] target(s)
# No warnings
```

### 5.2 Dependency Audit

```bash
$ cargo audit
    Fetching advisory database from https://github.com/RustSec/advisory-db
    Loaded 600 security advisories
    Scanning Cargo.lock for vulnerabilities...
# 0 vulnerabilities found
```

**2026-10-23 (latest recorded):** `cargo audit` with 1351 advisories loaded,
642 crates scanned: **0 vulnerabilities, 0 warnings**, exit 0, after
remediating 18 vulnerabilities and 4 warnings found on `main` @ 88c10cd (see
§2.3 and NIST SI-2). At that time the CI `cargo audit` job was advisory.

**2026-10-23, CI hardening:** the CI job now runs `cargo audit --deny warnings`
with no `continue-on-error`, so a new advisory fails the workflow. It is not
yet a required status check, so it does not by itself block merges (POA&M).
Local result: exit 0, 642 crates, 0 vulnerabilities, 0 warnings (§2.4).

### 5.3 License Compliance

```bash
$ cargo deny check
# All dependencies have approved licenses
```

**2026-10-23: this result can no longer be reproduced.** `cargo deny check`
fails configuration validation under cargo-deny 0.20.2 (`deny.toml` uses 5
removed keys), so no license, ban or advisory policy is evaluated (SEC-001 /
QA-002; POA&M). The output above is historical.

**2026-10-23, CI hardening: passes again.** After the `deny.toml` schema
migration, `cargo deny check` (cargo-deny 0.20.2) exits 0 with
`advisories ok, bans ok, licenses ok, sources ok`. Licenses are allow-list
only. OpenSSL, CDLA-Permissive-2.0 and MIT-0 are allowed only for named crates
(`aws-lc-fips-sys`; `webpki-roots`, `webpki-root-certs`; `borrow-or-share`). A
GitHub or GitLab CI run has not been recorded yet (§2.4; POAM-2026-10-23-06
closed pending first green CI run).

### 5.4 Fuzzing Results

| Fuzzer Target | Iterations | Crashes | Status |
|---------------|------------|---------|--------|
| DER Parser | 1,000,000 | 0 | Pass |
| CSR Parser | 1,000,000 | 0 | Pass |
| JWS Parser | 1,000,000 | 0 | Pass |
| OCSP Request | 1,000,000 | 0 | Pass |

### 5.5 Secrets Scanning

```bash
$ gitleaks detect --source . --verbose
# No secrets detected
```

---

## 6. Performance Test Results

### 6.1 Benchmark Results

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| Certificate DER encoding | < 1ms | 0.3ms | Pass |
| Certificate signing (ECDSA) | < 5ms | 2.1ms | Pass |
| OCSP response generation | < 5ms | 1.8ms | Pass |
| Database query (p99) | < 10ms | 4.2ms | Pass |

### 6.2 Load Test Results

| Scenario | Target TPS | Achieved TPS | Status |
|----------|-----------|--------------|--------|
| OCSP queries | 1,000 | TBD | Pending |
| ACME account creation | 50 | TBD | Pending |
| Certificate issuance | 100 | TBD | Pending |

---

## 7. SFR Test Coverage

### 7.1 Security Audit (FAU)

| SFR | Test Coverage | Evidence |
|-----|--------------|----------|
| FAU_GEN.1 | 8 tests | `models/audit.rs` tests |
| FAU_GEN.2 | 2 tests | Actor field tests |
| FAU_SAR.1 | Implemented | Audit query API |
| FAU_STG.1 | Implemented | Hash chain tests |

### 7.2 Cryptographic Support (FCS)

| SFR | Test Coverage | Evidence |
|-----|--------------|----------|
| FCS_CKM.1 | 15 tests | `ostrich-crypto` tests |
| FCS_COP.1 | 10 tests | Signing/hashing tests |
| FCS_RBG_EXT.1 | 2 tests | Random generation tests |

### 7.3 User Data Protection (FDP)

| SFR | Test Coverage | Evidence |
|-----|--------------|----------|
| FDP_CER_EXT.1 | 14 tests | `ostrich-x509` tests |
| FDP_CER_EXT.2 | 3 tests | CRL builder tests |

### 7.4 Identification and Authentication (FIA)

| SFR | Test Coverage | Evidence |
|-----|--------------|----------|
| FIA_X509_EXT.1 | 4 tests | Validation tests |
| FIA_UAU.2 | 2 tests | mTLS tests |
| FIA_AFL.1 | 3 tests | Lockout tests |

### 7.5 OCSP (RFC 6960)

| Feature | Test Coverage | Evidence |
|---------|--------------|----------|
| Request parsing | 8 tests | `request.rs` tests |
| Response generation | 14 tests | `response.rs` tests |
| Status codes | 6 tests | Status value tests |
| Revocation reasons | 7 tests | Reason code tests |

---

## 8. Test Artifacts

### 8.1 Test Execution Commands

```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific crate tests
cargo test -p ostrich-ocsp

# Run specific test
cargo test test_ocsp_response_successful

# Run tests with coverage
cargo tarpaulin --workspace --out Html
```

### 8.2 CI/CD Pipeline

Tests are automatically executed on:

- Every pull request
- Every merge to main branch
- Nightly builds

**Pipeline Stages:**

1. Lint (`cargo fmt --check`, `cargo clippy`)
2. Unit Tests (`cargo test`)
3. Security Scan (`cargo audit`, `cargo deny`)
4. Build (`cargo build --release`)

### 8.3 Test Output Files

| File | Location | Description |
|------|----------|-------------|
| Test results | `target/test-results.xml` | JUnit format |
| Coverage report | `target/tarpaulin/coverage.html` | HTML coverage |
| Benchmark results | `target/criterion/` | Criterion output |

---

## Appendix A: Running Tests

### A.1 Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install test dependencies
cargo install cargo-tarpaulin cargo-audit cargo-deny

# Clone repository
git clone https://github.com/ostrich-pki/ostrich-pki.git
cd ostrich-pki
```

### A.2 Running Full Test Suite

```bash
# Build and test
cargo build --workspace
cargo test --workspace

# Expected output:
# test result: ok. 274 passed; 0 failed; 0 ignored
```

### A.3 Generating Coverage Report

```bash
cargo tarpaulin --workspace --out Html --output-dir coverage/
# Open coverage/tarpaulin-report.html
```

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial test evidence package |
| 1.1 | July 2026 | OstrichPKI Team | Added Helm-render and runtime certificate-lifecycle evidence requirements for the EST external-issuer integration profile. |
| 1.2 | 2026-10-23 | OstrichPKI Team | Added §2.3, the dependency-advisory remediation test run: 649 unit tests passed; integration suites recorded as run or NOT RUN; PKCS#11 NOT RUN, so the cryptoki fix is untested (QA-004). §5.2: cargo audit 0 vulnerabilities (1351 advisories). §5.3: cargo deny marked not reproducible. |
| 1.3 | 2026-10-23 | OstrichPKI Team | Added §2.4, the CI-hardening test run: 653 unit tests passed; `cargo audit --deny warnings` and `cargo deny check` pass locally with negative checks; PKCS#11 suite run locally on macOS (non-standard invocation) 16 passed / 3 RSA-PSS failed / 1 ignored; Linux CI, pipelines and actionlint NOT RUN. QA-004 narrowed. §5.2: audit job no longer advisory (not yet a required check). §5.3: cargo deny passes locally. |
| 1.4 | 2026-10-23 | OstrichPKI Team | Added §2.5, the PKCS#11 RSA-PSS fix run: Linux CI before the fix 16 passed / 3 failed / 1 ignored (exit 101); local SoftHSM 2.7.0 after the fix 28 passed / 0 failed / 1 ignored; mutation checks; `ostrich-crypto` lib 65 passed; `make test-unit` 661 passed / 0 failed / 1 ignored; `cargo audit` / `cargo deny` failed on RUSTSEC-2026-0387 and pass after the risk-accepted ignore (POAM-16). Linux CI after the fix NOT RUN. §2.4 Linux row cross-referenced. |
| 1.5 | 2026-10-23 | OstrichPKI Team | §2.5: recorded the after-fix Linux CI result, GitHub Actions run 40063317654 (`HSM integration` / `PKCS#11 suite (SoftHSM2)`, SoftHSM 2.6.1, rustc 1.99.1, head 44d560d, artifact `commit:` merge ref c67c10e): 28 passed / 0 failed / 1 ignored, exit 0 (NOT RUN → PASS). GitHub dependency gate NOT RUN → PASS (PR 181, 12/12 checks green); GitLab still NOT RUN. QA-004 text updated (POAM-07 and POAM-17 closed; `CKA_ALLOWED_MECHANISMS` still not exercised). §2.4 cross-references updated. |
