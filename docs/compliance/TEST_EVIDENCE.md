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
HSM path of this update (POA&M in NIAP_GAP_ANALYSIS.md §11).

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
§2.3 and NIST SI-2). The CI `cargo audit` job is advisory (non-blocking).

### 5.3 License Compliance

```bash
$ cargo deny check
# All dependencies have approved licenses
```

**2026-10-23: this result can no longer be reproduced.** `cargo deny check`
fails configuration validation under cargo-deny 0.20.2 (`deny.toml` uses 5
removed keys), so no license, ban or advisory policy is evaluated (SEC-001 /
QA-002; POA&M). The output above is historical.

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
