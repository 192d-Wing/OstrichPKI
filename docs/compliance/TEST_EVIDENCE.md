# OstrichPKI Test Evidence Package

**Document Version:** 2.7
**Last Updated:** 2026-10-26
**NIAP Reference:** ATE_COV.1, ATE_FUN.1, ATE_IND.2
**Total Tests:** 256 unit tests passing (January 2026 baseline). Latest recorded run: 817 unit tests passed, 0 failed, 1 ignored, 2026-10-26 (§2.13, `make test-unit`)

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
| Supply chain | `cargo deny check` | FAIL before the ignore; PASS after | before: `advisories FAILED, bans ok, licenses ok, sources ok`; after: exit 0. Ignore lists in `.cargo/audit.toml` and `deny.toml` identical (5 IDs; 3 since 2026-10-24, §2.7) |
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

### 2.6 Test Run 2026-10-24 (PR 152, Fail-Closed FIPS TLS)

**Scope:** branch `revive-fips-tls`, head 396680c (PR 152 rebased onto `main`
@ 9000cb4) plus uncommitted round-1 fixes:
`crates/ostrich-common/src/tls.rs` (`ensure_fips`, `aws_lc_module_version`,
gate calls in `load` and `serve_with_config`, tests),
`crates/ostrich-common/Cargo.toml` (direct `aws-lc-rs` dependency, version
query only), workspace `Cargo.toml` (`aws-lc-rs` requirement 1.16 → 1.18; lock
already 1.18.2), `Cargo.lock` (new dependency edge only),
`services/npe-portal/src/main.rs`, `services/npe-portal/src/server/acme.rs`.
**Sources:** `qa-report.md` (before the fixes), `fixes-round-1.md` (after the
fixes) and `gate.md` in `target/agent-workflow/20261024-000214-pr152-fips-tls/`.
A gate that did not execute is recorded as NOT RUN.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Unit (TLS module) | `cargo test -p ostrich-common --lib tls::` | PASS | **26 passed, 0 failed** (QA before the fixes: 24 passed; +3 new tests, −1 redundant test removed) |
| Unit | `make test-unit` (`cargo test --workspace --all-features --lib`) | PASS | **667 passed, 0 failed, 1 ignored** (pre-existing ignore). QA before the fixes: 665 / 0 / 1 |
| Service binaries | `cargo test --all-features --bins -p ostrich-npe-portal -p ostrich-ca-server -p ostrich-est-server -p ostrich-web-ui` | PASS | **58 passed, 0 failed**, including `build_mtls_server_config_reports_fips_mode` |
| Integration (mTLS) | `cargo test -p ostrich-integration-tests --test mtls_peercert_e2e` | PASS | 1 passed, 0 failed |
| Mutation check | `ensure_fips` changed to `if true \|\| config.fips()` (always `Ok`) | FAIL as intended | `ensure_fips_rejects_non_fips_server_configs` and `serve_with_config_refuses_non_fips_config` failed (the second hit its 5 s timeout because it started serving); 24 others passed. Source restored, re-run 26 / 0 |
| Mutation check (QA, before the fixes) | non-FIPS key-exchange group injected into `load` | FAIL as intended | 9 `load` tests fail with a `Config` error. The PR's original test `aws_lc_rs_provider_is_in_fips_mode` stayed green, so it was removed as redundant |
| Format | `cargo fmt --all --check` | PASS | exit 0 |
| Lint | `make clippy`; `cargo clippy -p ostrich-common -p ostrich-npe-portal --all-targets --all-features -- -D warnings` | PASS | exit 0 |
| Supply chain | `cargo deny check` | PASS | exit 0 (advisories, bans, licenses, sources ok) |
| Supply chain | `cargo audit --deny warnings` | PASS | exit 0 |
| PR CI | `gh pr checks 152` (rebased head 396680c, **before** the round-1 fixes) | PASS (partial) | 10 pass; CodeQL rust pending at review time. The round-1 fixes are uncommitted: **CI NOT RUN** on them |
| Integration (Postgres), doc tests, fuzz, live service start-up | — | **NOT RUN** | No live startup log was captured, so the `aws_lc_version` value is not observed |

**Tests added or changed** (`crates/ostrich-common/src/tls.rs` `mod tests`):
`ensure_fips_rejects_non_fips_server_configs` (plain X25519 group → `Err(Config)`;
`require_ems = false` → `Err(Config)`), `ensure_fips_accepts_loaded_config`,
`serve_with_config_refuses_non_fips_config` (tokio; `Err(Config)` without
binding, 5 s timeout), plus QA's `fips_predicate_false_when_extended_master_secret_not_required`,
`fips_predicate_false_with_non_fips_kx_group` and
`fips_server_config_kx_groups_exclude_x25519_keep_mlkem_hybrid`. In
`services/npe-portal/src/server/acme.rs`: `build_mtls_server_config_reports_fips_mode`.
Removed: `aws_lc_rs_provider_is_in_fips_mode` (duplicated
`load_builds_fips_config_with_alpn`).

**QA-005 (open, not on the POA&M):** `make test-unit` runs `--lib` only and
skips the service binary tests. They were run separately here (58 passed).

**Not covered:** a refusal through a real non-FIPS build (the tests build
non-FIPS configs from the FIPS provider); a failed AWS-LC power-on self-test
(the module aborts the process, outside the gate); plain-HTTP mode; rustls
client configs; gRPC (POAM-2026-10-23-05, -08). Update 2026-10-25: gRPC and
the process-level gate are now covered, see §2.8.

### 2.7 Test Run 2026-10-24 (Dependency Cleanup)

**Scope:** branch `claude/deps-cleanup` from `main` @ 138ee83, uncommitted:
workspace `Cargo.toml` and `services/web-ui/Cargo.toml` (`openidconnect`
removed), `tests/Cargo.toml` (`p256` removed), `Cargo.lock` (`rand` 0.8.5 →
0.8.6; 28 packages removed, 642 → 614), `.cargo/audit.toml` and `deny.toml`
(RUSTSEC-2026-0097 and RUSTSEC-2026-0387 ignores removed),
`tests/integration/common/fixtures.rs` (`generate_test_p256_spki` now uses the
software `CryptoProvider` and is `async`) and `tests/integration/ca_core_test.rs`.
**Sources:** `impl-notes.md` in `target/agent-workflow/20261024-104215-deps-cleanup/`. No
`qa-report.md` was available to the compliance scribe; the gate results below
are as recorded by the implementer, except the rows marked "re-run by the
scribe" and the two supply-chain exit codes, which the compliance scribe re-ran
on 2026-10-24. A gate that did not execute is recorded as
NOT RUN.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Unit | `make test-unit` (`cargo test --workspace --all-features --lib`) | PASS | **667 passed, 0 failed, 1 ignored** (pre-existing ignore) |
| Service binaries | `cargo test --all-features --bins -p ostrich-web-ui` | PASS | **19 passed, 0 failed** |
| Service binaries | `cargo test --all-features --bins -p ostrich-npe-portal` | PASS | **30 passed, 0 failed** (re-run by the scribe 2026-10-24) |
| Integration (offline fixture tests) | `cargo test -p ostrich-integration-tests --test ca_core_test` (re-run by the scribe 2026-10-24) | PASS for the fixture tests | `test_p256_spki_fixture_well_formed` and `test_p256_spki_fixture_path_verifies_signature`: **2 passed, 0 failed**. Whole binary: 11 passed, 2 failed, 7 ignored. The 2 failures are `test_ca_health` and `test_ca_readiness`, which need a running CA (docker-compose) and fail without one (pre-existing, QA-001); the 7 ignored include `test_ca_issue_certificate_ecdsa` |
| Integration (compile) | `cargo test -p ostrich-integration-tests --no-run` | PASS | all integration test binaries compile |
| Format | `cargo fmt --all --check` | PASS | exit 0 |
| Lint | `make clippy` | PASS | exit 0 |
| Supply chain | `cargo audit --deny warnings` | PASS | exit 0 (1352 advisories, 614 crates), without the 0097 and 0387 ignores |
| Supply chain | `cargo deny check` | PASS | exit 0 (`advisories ok, bans ok, licenses ok, sources ok`); ignore lists identical (3 IDs) |
| Integration (live) | `test_ca_issue_certificate_ecdsa` (the existing caller of the fixture; `#[ignore]`) | **NOT RUN** | needs the docker-compose environment |
| CI (GitHub / GitLab gate) | `audit.yml`, `security:audit`, `security:deny` | **NOT RUN** | change not pushed |

**Tests added** (`tests/integration/ca_core_test.rs`):
`test_p256_spki_fixture_path_verifies_signature` and
`test_p256_spki_fixture_well_formed`. The second parses the fixture output with
`x509-parser` and checks: no trailing bytes, algorithm id-ecPublicKey
(1.2.840.10045.2.1), namedCurve prime256v1 (1.2.840.10045.3.1.7), a 65-byte
uncompressed point starting with 0x04, and a different key on each call.

**Not covered:** the fixture inside a live CA issuance (NOT RUN above).

### 2.8 Test Run 2026-10-25 (CA gRPC behind mTLS, aws-lc-rs FIPS)

**Scope:** branch `claude/grpc-mtls` from `main` @ c67ed7a, uncommitted
(implementation units U1-U8 plus round-1 fixes): new
`crates/ostrich-common/src/grpc_tls.rs`; `tls.rs` (`fips_gate`,
`ensure_fips_client`); `grpc_client.rs`; `ostrich-audit` `auth_hook.rs` and
`sink.rs`; `ostrich-db` `repository/audit.rs` (`begin_append`); `ostrich-ca`
`grpc.rs`; all ten service mains; new integration tests
`tests/integration/grpc_mtls_e2e.rs` and `fips_gate_preinstalled.rs`; fuzz
target `fuzz_grpc_peer_subject`; deploy and compose files.
**Sources:** `impl-notes.md`, `fixes-round-1.md` and
`fixes-round-1-deploy.md` in `target/agent-workflow/20261024-225627-grpc-mtls/`.
No `qa-report.md` was available to the compliance scribe. Rows marked
"re-run by the scribe" were executed by the compliance scribe on 2026-10-25 on
the working tree; the other rows are as recorded by the implementer. A gate
that did not execute is NOT RUN.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Integration (offline) | `cargo test -p ostrich-integration-tests --test grpc_mtls_e2e` (re-run by the scribe) | PASS | **20 passed, 0 failed** |
| Integration (offline) | `cargo test -p ostrich-integration-tests --test fips_gate_preinstalled` (re-run by the scribe) | PASS | **1 passed, 0 failed** (`fips_gate_refuses_preinstalled_non_fips_default`) |
| Unit | `cargo test -p ostrich-common --all-features --lib` (re-run by the scribe) | PASS | **229 passed, 0 failed**; of these 34 `grpc_tls::tests` |
| Unit | `cargo test -p ostrich-audit --all-features` lib (re-run by the scribe) | PASS | **13 passed, 0 failed** (incl. 4 new `auth_hook` tests and `test_memory_sink_concurrent_appends_keep_chain`) |
| Unit | `cargo test -p ostrich-db --all-features --lib` (re-run by the scribe) | PASS | **54 passed, 0 failed** |
| Unit | `cargo test -p ostrich-ca --all-features --lib` (re-run by the scribe) | PASS | **54 passed, 0 failed** |
| Unit | `cargo test -p ostrich-est --all-features --lib` (re-run by the scribe) | PASS | **43 passed, 0 failed** |
| Service binaries | `cargo test --all-features --bins -p ostrich-ca-server` / `-p ostrich-acme-server` / `-p ostrich-est-server` (re-run by the scribe) | PASS | **9 / 3 / 8 passed, 0 failed** |
| Service binaries | web-ui, npe-portal `--bins` | PASS | 19 / 30 passed (implementer) |
| Unit (workspace) | `make test-unit` | PASS | implementer reports all crates pass; no total recorded |
| Postgres audit chain | `cargo test -p ostrich-audit --test chain_concurrency` with `DATABASE_URL` | **NOT RUN** | Without `DATABASE_URL` the test returns early and cargo reports "1 passed" (0.00 s). That result is **not** evidence. The test (and `signed_chain_tamper`) runs `TRUNCATE audit_events`: use a disposable database only |
| Fuzz | `cargo +nightly fuzz run fuzz_grpc_peer_subject -- -max_total_time=60` | PASS after fix | First run found an OID-arc overflow panic in allowlist parsing; fixed (`validate_attribute_types`) with regression tests; then **237,187 runs in 61 s, no crash** (implementer; not re-run by the scribe). `fuzz/Cargo.toml` manifest repaired in the same change |
| Mutation | five hand mutations M1-M5 of the new security checks | PASS | each mutation made at least one test fail (implementer; mutation details in the implementer's report only) |
| Format / lint | `cargo fmt --all --check`, `make clippy` | PASS | implementer |
| Supply chain | `cargo deny check`, `cargo audit --deny warnings` | PASS | implementer |
| Dependency graph | `cargo tree -e features -i rustls` (re-run by the scribe) | PASS | no tonic TLS feature (`tls-ring` gone) |
| Deploy | `helm template` / `helm lint` (Helm v3.19.0), kustomize build + strict NetworkPolicy decode, compose-go loader, `bash -n`, `openssl verify` of generated dev certs | PASS | implementer (`fixes-round-1-deploy.md`) |
| Deploy | `docker compose up`, `kubectl` server-side dry run, shellcheck | **NOT RUN** | tools not available |
| Live start-up | release-build container start with gRPC mTLS | **NOT RUN** | debug-binary smoke only: no gRPC env ⇒ exits "CA gRPC requires mTLS … refusing to start" before the database (implementer) |
| CI | GitHub / GitLab pipelines | **NOT RUN** | change not committed. Wiring added in round 2: GitHub `ci.yml` job `Build & test` now runs `--test grpc_mtls_e2e --test fips_gate_preinstalled` (SA-11), and GitLab `test:integration` sets `OSTRICH_DB_TESTS=1` so the Postgres audit-chain tests are expected to execute there. No run yet |

**`grpc_mtls_e2e` cases (20):** `allowed_subject_issue_ok`,
`disallowed_subject_permission_denied_and_audited`,
`leaf_without_eku_is_permission_denied`, `no_client_cert_handshake_fails`,
`untrusted_ca_client_cert_handshake_fails`,
`server_only_eku_client_cert_rejected`, `tls12_client_rejected`,
`non_h2_alpn_client_rejected`, `x25519_only_client_rejected`,
`client_rejects_server_name_mismatch`, `server_and_client_configs_report_fips`,
`p384_chain_end_to_end_with_fips_hybrid_group`,
`connector_and_listener_refuse_non_fips_or_non_h2_configs`,
`refuses_to_start_without_config`, `access_denied_audit_is_rate_limited_and_summarised`,
`handshake_failure_audit_is_rate_limited`,
`stalled_handshake_times_out_and_is_audited`,
`handshake_concurrency_cap_applies_backpressure`,
`per_source_cap_closes_excess_idle_connections`,
`dev_cert_script_material_works_with_rust_server_and_client`.

**SFR / control mapping:** FCS_TLSS_EXT.2, FCS_TLSC_EXT.2, FTP_ITC.1,
FIA_X509_EXT.1 (no revocation), FDP_ACC.1 / FDP_ACF.1, FAU_GEN.1, FPT_FLS.1;
NIST AC-3, AC-17, IA-3, IA-5(2), SC-8, SC-13, SC-24, AU-2, AU-12, CM-6.

**Not covered:** client-certificate revocation (not implemented,
POAM-2026-10-23-27); Postgres audit-chain concurrency (NOT RUN,
POAM-2026-10-23-31); a refusal through a real non-FIPS build; release-build
container start; deployed NetworkPolicy enforcement.

### 2.9 Test Run 2026-10-25 (CA gRPC mTLS, final code after fix rounds 2-3)

**Scope:** the same branch after fix rounds 2 and 3 (trust-anchor ancestor
walk and `subscriber_issuing_ca`, spawned denial audit, audit-chain timeouts
and blocking-pool signing, checked `append`, `occurred_at`, allowlist
ASCII-only trimming and UTF-8 hex escapes, SLH-DSA audit-key refusal,
`OSTRICH_DB_TESTS` fail-on-unreachable). §2.8 records the earlier state; its
counts (`grpc_mtls_e2e` 20, 34 `grpc_tls::tests`) are superseded here.
**Sources:** `fixes-round-2.md`, `fixes-round-2-deploy.md` and
`fixes-round-3.md` in the run record. No `qa-report.md` exists. Rows marked
"re-run by the scribe" were executed by the compliance scribe on 2026-10-25 on
the final working tree; the others are as reported by the coder.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Integration (offline) | `cargo test -p ostrich-integration-tests --test grpc_mtls_e2e --test fips_gate_preinstalled` (re-run by the scribe, `OSTRICH_DB_TESTS` and `DATABASE_URL` unset) | PASS | **21 passed, 0 failed** (adds `no_alpn_refusal_sends_close_notify`); **1 passed, 0 failed** |
| Unit | `cargo test -p ostrich-common --lib grpc_tls::` (re-run by the scribe) | PASS | **41 passed, 0 failed** (incl. `dedicated_client_ca_refuses_chain_relatives`, `issued_by_checks_cover_name_and_key_id_independently`, `authorize_peer_refuses_subscriber_issuing_ca_leaf`, `access_denied_audit_survives_cancelled_request`, `allowlist_keeps_escaped_trailing_space`, `allowlist_rejects_hex_escapes_that_are_not_utf8`, `allowlist_does_not_trim_unicode_whitespace`, `suppressed_summary_source_count_is_bounded`) |
| Unit | `cargo test -p ostrich-audit --all-features --tests` lib (re-run by the scribe) | PASS | **20 passed, 0 failed** (incl. `sign_timeout_fires_for_blocking_signer`, `sign_timeout_fires_for_blocking_signer_current_thread`, `bounded_sign_succeeds_within_timeout`, `idle_in_transaction_timeout_exceeds_sign_timeout`, `apply_chain_timestamp_preserves_original_time`, `memory_sink_records_occurred_at_when_bumped`) |
| Postgres audit chain | `chain_concurrency.rs`, `signed_chain_tamper.rs`, new `sign_timeout_db.rs` with `OSTRICH_DB_TESTS=1` and a disposable `DATABASE_URL` | **NOT RUN** | Without the opt-in each test prints a skip note and cargo reports "1 passed" (scribe re-run: 1 / 1 / 1 in 0.00 s). That is **not** evidence. With `OSTRICH_DB_TESTS=1` and no reachable database the tests now **fail** (coder-checked), so a green GitLab `test:integration` job would be evidence; none has run |
| Service binaries | `cargo test -p <svc> --all-features --bins` | PASS | acme 3, ca 13 (incl. `walk_ca_ancestors_follows_parent_ca_id_and_fails_closed`, `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal`, `grpc_shutdown_follows_rest_exit`, `grpc_server_task_completes_after_shutdown`), est 8, npe-portal 30, web-ui 19 (coder) |
| Unit | `cargo test -p ostrich-ca --all-features --lib` | PASS | 54 passed (coder) |
| Unit (workspace) | `make test-unit` | PASS | **732 passed, 0 failed** (coder, round 3; 725 after round 2) |
| Fuzz | `cargo +nightly fuzz run fuzz_grpc_peer_subject -- -max_total_time=60` | PASS | 215,504 runs / 61 s, no crash (coder, round 2; not re-run after round 3) |
| Mutation | removing `close_notify`; inline (non-spawned) denial audit; removing the issuer-name or AKI = SKI branch | PASS | each mutation failed a test (coder) |
| Format / lint / supply chain | `cargo fmt --all --check`, `make clippy`, `cargo deny check`, `cargo audit --deny warnings` (614 crates) | PASS | coder |
| CI | GitHub `Build & test` (grpc_mtls_e2e, fips_gate_preinstalled), GitLab `test:integration` (`OSTRICH_DB_TESTS=1`) | **NOT RUN** | change not committed |

**Not covered:** client-certificate revocation (POAM-2026-10-23-27);
Postgres audit-chain tests including the hung-signer DB test (NOT RUN,
POAM-2026-10-23-31); sibling and grandchild CA detection (not implemented,
POAM-2026-10-23-28); a hung real HSM; release-build container start; deployed
NetworkPolicy enforcement.

### 2.10 Test Run 2026-10-26 (CA gRPC per-method authorization and verified audit actor)

**Scope:** branch `claude/grpc-per-method-authz`, uncommitted (run record
`target/agent-workflow/20261025-202226-grpc-per-method/`): per-role client
subject lists, the default-deny method table, requestor binding, issuer
profile allowlists, per-call leaf validity, the Admin direct-issuance rule,
the verified peer as audit actor, revocation and CRL Failure records, and the
const-oid fuzz fix. §2.8 and §2.9 counts are superseded for these suites.
**Sources:** `qa-report.md` (QA round, PASS WITH FINDINGS), `fixes-round-1.md`,
`fixes-round-2.md` and `fixes-nits.md` (final tree). The compliance scribe did
**not** re-run these commands; all counts below are from the final tree as
reported by the coder, except where the QA round is named.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Unit (workspace) | `make test-unit` | PASS | **782 passed, 0 failed, 1 ignored** (pre-existing ignore; 16 suites). QA round: 759; round 1: 776 |
| Unit | `cargo test -p ostrich-common --lib grpc_tls` | PASS | **66 passed, 0 failed** (QA round 59, round 1 63) |
| Unit | `cargo test -p ostrich-ca` | PASS | **78 passed, 0 failed**. The DB / PKCS#11 `*_e2e` modules (`audit_signing_e2e`, `crl_delta_e2e`, `pop_e2e`, `issuance_aia_e2e`) report `ok` but skip internally without `DATABASE_URL` / `PKCS11_*`; that is **not** evidence |
| Service binaries | `cargo test -p ostrich-ca-server --bins` | PASS | **21 passed, 0 failed** (adds `start_grpc_listener_refusal_is_audited_without_started_record` in the nit pass) |
| Unit | `cargo test -p ostrich-est` | PASS | **44 passed, 0 failed** (2 ignored doctests; incl. `ca_requestor_matches_ca_rule`) |
| Integration (offline) | `cargo test -p ostrich-integration-tests --test grpc_mtls_e2e --locked` | PASS | **39 passed, 0 failed** (#15 ran the real `scripts/gen-dev-grpc-certs.sh`) |
| Fuzz | `cargo +nightly fuzz run fuzz_grpc_requestor -- -max_total_time=60` (new target) | PASS | **246,720 runs / 61 s**, no crash (final tree) |
| Fuzz | `cargo +nightly fuzz run fuzz_grpc_peer_subject -- -max_total_time=60` | PASS after fix | First run in round 2 **crashed** after about 5.6k runs: const-oid 0.9.6 encodes the numeric OID `2.2.106.2.2.2122195112` but cannot decode it, and `Display` panics ("OID malformed: ArcTooBig") in `canonicalize_dn` on operator configuration text (pre-existing). Fixed in `check_attribute_type` (decode round trip); after the fix **135,145 runs / 61 s**, no crash, both crash artifacts replay clean; regression test `allowlist_refuses_undecodable_numeric_oid` |
| Mutation | QA script plus the coder's round 1 / round 2 / nit-pass scripts; each mutation reverted and the file hash verified | PASS except M13h | Killed: M1-M11, M14-M17 (QA round); M12, M12r, M13, M18-M22 (round 1, after QA-002 / QA-003 fixes; M12, M13, M18 had survived the QA round); M23-M29 (round 2); DN-only fallback restored in `issued_directly` (nit pass). **M13h (GenerateCrl handler passes `crl_actor(None)`) NOT RUN / survives without a database** |
| Format / lint / release | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo check --release ... --all-targets`, `cargo build --release -p ostrich-ca-server` | PASS | rc=0 |
| Supply chain | `cargo deny check`, `cargo audit` | PASS | implementer-reported (round 0); Cargo.lock gained dependency edges only (`tonic-prost`, `time` for tests) |
| Helm / compose render | scratch `helm lint` / `helm template` (v3.19, postgresql dependency stripped), compose-go loader | PASS | deploy coder; QA did not re-verify (no `helm` on the QA host). Negative cases (legacy key, no issuer, overlap, `intermediate_ca`, empty profile list) fail rendering as intended. Scripted as `scripts/helm-chart-check.sh` on 2026-10-26 (§2.14) |
| DB-gated | `ca_core_test`, `ocsp_revocation_test` (`--ignored`), `est_serverkeygen_e2e`, live `audit_signing_e2e` / `crl_delta_e2e` | **NOT RUN** | no Postgres or Docker on the host; tracked as POAM-2026-10-23-36. CI path added 2026-10-26 for all but `ca_core_test` / `ocsp_revocation_test`, still NOT RUN (§2.14) |
| CI | GitHub / GitLab pipelines | **NOT RUN** | change not committed |

**Key `grpc_mtls_e2e` additions (39 total):** `role_method_matrix`
(4 callers × 6 RPCs), `unknown_method_denied`,
`requestor_namespace_mismatch_denied_and_audited`,
`empty_requestor_denied_for_issuer`, `invalid_requestor_denied`,
`admin_revoke_without_requestor_ok`, `bound_caller_actor_is_peer`,
`admin_list_empty_default_denies_revoke_crl_status_for_all`,
`requestor_denial_audit_is_cancel_proof`, `config_errors_refuse_to_start`,
`qa_unmapped_path_variants_denied_over_the_wire` (14 paths × 4 callers),
`qa_requestor_edge_cases_denied_and_audited_per_role`,
`qa_valid_requestors_bind_to_peer_for_each_role`,
`issuer_profile_allowlist_enforced_and_audited` (#34),
`certificate_expiring_on_live_connection_is_refused` (#35, 3 s leaf on a
live HTTP/2 connection), requestor Unicode cases over the wire (#36),
`admin_under_intermediate_is_refused` (#37). The e2e suite uses a stub CA
behind the real layer and `bind_caller`; it does not exercise
`CaGrpcService` against a database.

**Not covered:** handler glue from `CaGrpcService` and the REST CRL handlers
into the audit records (M13h; POAM-2026-10-23-36); live signed records with
the peer as actor; CRL failure audits and the call-time
`ca_profile_not_permitted` refusal on the database paths; client-certificate
revocation (POAM-2026-10-23-27); issuer / SPKI binding for the Issuer roles
(POAM-2026-10-23-28); per-call validity of intermediates and the anchor; the
env-var form of the role lists (only the CLI flag, the same clap argument, is
tested); how an EST client sees a CA requestor refusal beyond the HTTP 403
pre-check; deployed NetworkPolicy and port-forward admin access.

### 2.11 Test Run 2026-10-26 (Web UI react-router v7 migration)

**Scope:** branch `claude/react-router-v7`, uncommitted, restacked on `main` @
9fad04f (run record
`target/agent-workflow/20261026-091035-react-router-v7/`): web-ui
`react-router-dom` ^6.30.6 → `react-router` ^7.18.1 (7.18.4), the same-origin
navigation guard `src/lib/safe-path.ts`, and encoded server-ID path segments.
Closes POAM-2026-10-23-39 (pending commit). No Rust code changed and no Rust
test was run.
**Sources:** `qa-report.md` (QA round on the pre-restack tree, `main` @
1294f63; PASS), `fixes-round-1.md`, the orchestrator's restack note in
`impl-notes.md`, and `smoke.md`. Rows marked "scribe" were re-run by the
compliance scribe on the restacked tree on 2026-10-26.

| Gate | Command (cwd `services/web-ui/web`, pnpm 9.15.9 via `npx --yes pnpm@9.15.9`) | Result | Counts / notes |
|------|------|--------|----------------|
| Frozen install | `pnpm install --frozen-lockfile` | PASS | QA round and restacked tree |
| Typecheck | `pnpm typecheck` (`tsc --noEmit`) | PASS | 0 errors |
| Lint | `pnpm lint` (`eslint .`) | PASS | 0 problems |
| Build | `pnpm build` | PASS | pre-existing warning: `cloudscape` vendor chunk about 945 kB, over the 500 kB limit |
| Full audit | `pnpm audit` (not `--prod`) | PASS | "No known vulnerabilities found" (restacked tree; scribe) |
| No v6 router | `grep -nE "react-router\|@remix-run" pnpm-lock.yaml`; `node -p 'require("./node_modules/react-router/package.json").version'` | PASS | only `react-router` (specifier `^7.18.1`, version 7.18.4); no `react-router-dom` or `@remix-run/router` (scribe) |
| Guard vectors (manual) | `node --experimental-strip-types safe-path-check.mjs` (run record) | PASS | **181 checks, 0 failures** after fix round 1 (scribe); QA round: 150 checks before the dot-segment fix |
| Router composition (manual) | `node router-smoke.mjs` (run record) | PASS | **5 ok, 0 failures** against react-router 7.18.4 (scribe) |
| Mutation check of the vectors | weakened copies of `safe-path.ts` (QA, scratchpad) | PASS | 3 non-equivalent mutants killed; 2 equivalent mutants survive (each of the regex and the URL-origin check rejects every protocol-relative and backslash form on its own) |
| Browser smoke | `pnpm dev` (vite 8.1.6) with a throwaway node mock BFF; built-in browser | PASS (limited) | see below |
| CI | GitHub / GitLab pipelines | **NOT RUN** | change not committed |

**What the guard vectors cover (`safe-path-check.mjs`, sections A-G):**

- A: the original accept / reject vectors and fallback behaviour (`""`,
  `//evil`, `/\evil`, `/\t/evil`, `https://…`, `http:/…`, `javascript:…`,
  `./x`, `?x`, `#x`, a leading space)
- B: percent-encoded and Unicode slash look-alikes, mixed `/\`, `///`, C0
  controls, leading NUL / TAB / LF / BOM / NBSP, mixed-case and other schemes
  (`data:`, `vbscript:`, `file:`, `mailto:`), bare hosts
- C: non-string runtime input fails closed without throwing
- D: 5 MB inputs give correct verdicts in linear time (no ReDoS)
- E: every accepted input stays same-origin after react-router 7.18.4
  `resolvePath` / `createPath`
- F: seeded property run, 100,000 random strings over a hostile alphabet
- G (fix round 1): `//` anywhere and `.` / `..` segments are rejected
  (`/..//evil.com`, `/a/./b`, `/a/..`); app routes and dot-containing names
  (`/.well-known`, `/fqdns/a.example.com`) are accepted

**Router checks (`router-smoke.mjs`):** `/certificates/abc%2Fdef` matches
`certificates/:id` and the parameter decodes to `abc/def`; the static
`certificates/issue` route outranks `:id`; special characters round-trip; a
declarative `<MemoryRouter>` with `useParams` renders the decoded parameter.

**Browser smoke (orchestrator, `smoke.md`):** unauthenticated deep link
`/static/certificates` → `/login`; internal login → `/dashboard`; side-nav
follow through `safeInternalPath` → `/fqdns` without a document reload;
`history.back()` → `/dashboard`; dashboard quick action → `/audit` without a
reload; `/certificates/abc%2Fdef` → detail route with a single-segment API
request (`GET /api/ca/api/v1/certificates/abc%2Fdef`). All PASS.

**Not covered:** OIDC SSO login and logout (server-side redirects; they need
the real BFF); the browser smoke used a mock BFF, so the BFF proxy's
percent-decoding of the forwarded path was not exercised (POAM-2026-10-23-43,
since fixed and tested in §2.12; closed 2026-10-26 on the green CI run
40360909224);
router composition is tested through `resolvePath` / `createPath`, not
through `BrowserRouter` in a real DOM; the `encodeURIComponent` in `lib/ca.ts`
is checked by review, typecheck and the one smoke request only; the
`fqdns/:fqdn` decode is not separately tested. The vectors are in run-record
scripts that are not committed and not run in CI: web-ui has no test runner
(POAM-2026-10-23-44).

### 2.12 Test Run 2026-10-26 (Web UI BFF proxy raw path)

**Scope:** branch `claude/web-ui-proxy-raw-path`, stacked on PR #188
(`claude/react-router-v7`, commit f00ddf6), merged to `main` as
[PR #191](https://github.com/192d-Wing/OstrichPKI/pull/191) on 2026-10-26T16:45:42Z (fix commit e56a09e, merge commit
635c5c3) (run record `target/agent-workflow/20261026-093447-proxy-raw-path/`). Changed files:
`services/web-ui/src/server/proxy.rs`, `services/web-ui/src/server/auth/session.rs`
and `services/web-ui/src/server/middleware/audit.rs` (visibility only). Closes
POAM-2026-10-23-43 (closed on the green CI run recorded below); also fixes SEC-003 (inbound
`Cookie` / `X-Npe-*` stripping) and QA-001 (`SessionData` `Debug` redaction).
**Sources:** `qa-report.md` (QA round, 38 / 0; PASS), `fixes-round-1.md`
(41 / 0 after the fixes). Rows marked "scribe" were re-run by the compliance
scribe on the final working tree on 2026-10-26. The CI rows come from the
GitHub Actions job log and `gh pr checks 191`, not from `qa-report.md`.

| Gate | Command | Result | Counts / notes |
|------|---------|--------|----------------|
| Format | `cargo fmt --all -- --check` | PASS | exit 0 (QA, coder, scribe) |
| Lint | `cargo clippy -p ostrich-web-ui --all-targets -- -D warnings` | PASS | 0 warnings (QA, coder, scribe) |
| Unit tests | `cargo test -p ostrich-web-ui` | PASS | **41 passed, 0 failed, 0 ignored** (coder after fix round 1; scribe). QA round before the fixes: 38 / 0 |
| Serial run | `cargo test -p ostrich-web-ui -- --test-threads=1` | PASS | 38 / 0 (QA round) |
| Flake check | `cargo test -p ostrich-web-ui` repeated | PASS | 120 / 120 (QA round, after the test-harness fix); 20 / 20 full suite and 20 / 20 for the log-capture test alone (coder, after fix round 1) |
| Doc tests | n/a | NOT RUN | binary-only crate |
| Workspace | `make clippy` / `make test-unit` | NOT RUN | scoped to one crate (local); the CI `Build & test` row below covers the workspace lib and bin tests |
| Supply chain | `make security` | NOT RUN | no `Cargo.toml` / `Cargo.lock` change |
| Fuzz | n/a | NOT RUN | no fuzz target for the validator (QA G-4) |
| CI | GitHub `CI` / `Build & test` (`cargo test --workspace --lib --bins --locked`), [run 40360909224](https://github.com/192d-Wing/OstrichPKI/actions/runs/40360909224/job/121705749851); `pull_request` event, head SHA e56a09e; ubuntu-24.04 image 20261012.334.1, rustc 1.99.1 | PASS | `ostrich_web_ui` unit tests **41 passed, 0 failed, 0 ignored**, including `router_rejects_unsafe_paths_before_contacting_backend`, `qa_rejection_emits_au3_security_event_without_secrets` and `debug_redacts_backend_token`; every test binary in the job reported `ok`. Meets the POAM-2026-10-23-43 close criterion |
| CI, other jobs | same run: Clippy (advisory), Rustfmt (advisory), Toolchain pin consistency, Web UI (React build + supply-chain) | PASS | all green (`gh pr checks 191`) |
| GitHub dependency gate and HSM job | `audit.yml` jobs `cargo audit`, `cargo deny`; `PKCS#11 suite (SoftHSM2)` (PR #191) | PASS | all green (`gh pr checks 191`) |

**New tests (22; 19 web-ui tests existed before):**

- Pure validator, `server::proxy::tests` (coder, 8):
  `normal_paths_are_forwarded_verbatim`,
  `legit_encoded_characters_are_forwarded_still_encoded` (`%20`, `%40`,
  `%C3%A9`, `%252F` forwarded raw), `encoded_slash_is_rejected`,
  `encoded_backslash_query_and_fragment_are_rejected`,
  `literal_and_encoded_dot_segments_are_rejected`,
  `empty_segments_are_rejected`,
  `control_characters_and_malformed_escapes_are_rejected`,
  `wrong_or_missing_service_prefix_is_rejected`
- Router level against a local echo backend (coder, 2):
  `router_rejects_unsafe_paths_before_contacting_backend` (13 unsafe URIs
  across all seven services: 400 `invalid_path`, backend hit count 0),
  `router_forwards_raw_path_and_query_verbatim`
- QA (9): `qa_mixed_case_and_partial_encoded_dot_segments_are_rejected`,
  `qa_lowercase_and_extra_delimiter_escapes_are_rejected`,
  `qa_overlong_utf8_slash_and_dot_are_forwarded_raw_not_decoded` (documents
  that `%C0%AF`, `%E0%80%AF`, `%C0%AE%C0%AE` and `%FF%FE` are forwarded),
  `qa_trailing_slash_and_service_prefix_edge_cases`,
  `qa_rejection_reason_tokens_are_stable`,
  `qa_router_rejects_mixed_case_and_partial_encodings_without_backend_call`
  (GET / PUT / DELETE / PATCH / POST; zero backend hits; error body does not
  reflect the path), `qa_router_forwards_overlong_utf8_and_encoded_query_verbatim`,
  `qa_router_session_bearer_forwarded_only_on_valid_path`,
  `qa_rejection_emits_au3_security_event_without_secrets` (asserts `level`,
  `security_event`, `request_id`, `actor`, `client_ip`, `method`, `service`,
  `reason`, `outcome`, `path`, `timestamp`; the backend token, the client
  `Authorization` value and the session id are absent; fix round 2 adds a
  forged `X-Forwarded-For: 198.51.100.1 actor=admin outcome=allowed` request
  and asserts `client_ip` is `-` and the forged text is absent, SEC-005)
- Fix round 1 (3): `credential_and_identity_headers_are_stripped_inbound`,
  `router_strips_cookie_and_npe_identity_headers_before_backend`
  (`server::proxy::tests`), `debug_redacts_backend_token`
  (`server::auth::session::tests`)

**Not covered:** the router tests mount the proxy routes without
`require_session` and the audit middleware, so the full `router.rs` stack and
middleware order are not exercised (QA G-2); raw non-RFC 3986 bytes from a real
TCP client through hyper (QA G-3); `..;` path-parameter segments (no test
either way, QA G-1); no fuzz or property test for the validator (QA G-4). The
rejection event is a `tracing` log line, not an `ostrich-audit` record
(POAM-2026-10-23-47).

### 2.13 Test Run 2026-10-26 (ACME dns-01 resolver fix)

**Scope:** branch `claude/dns01-resolver-fix`, uncommitted (run record
`target/agent-workflow/20261026-091032-dns01-resolver/`): the dns-01 resolver
gets real name servers (operator list or system configuration, fail closed
when empty), an FQDN query name, no in-process cache, TXT concatenation and
owner / CNAME checks, retry on mismatch, and registered RFC 8555 problem types
for http-01, dns-01 and tls-alpn-01 failures (POAM-2026-10-23-41 narrowed).
**Sources:** `qa-report.md` (QA round, PASS), `fixes-round-1.md` to
`fixes-round-3.md`. Rows marked **scribe** were re-run by the compliance
scribe on the final tree on 2026-10-26.

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Unit (workspace) | `make test-unit` | PASS (**scribe**) | **817 passed, 0 failed, 1 ignored** (pre-existing ignore; 16 suites). QA round 800; fix round 1 810 |
| Unit + bins | `cargo test -p ostrich-acme -p ostrich-acme-server --all-features` | PASS (**scribe**) | `ostrich-acme` lib **72 passed**, acme-server bins **7 passed**, 0 failed (QA round 55 / 7; fix round 1 65 / 7) |
| Fuzz | `cargo +nightly fuzz run fuzz_dns01_query_name -- -max_total_time=60` (new target) | PASS | 131,276 runs / 61 s with the QA oracle; 136,323 runs / 46 s after fix round 1 (`-max_total_time=45`); no crash (not re-run by the scribe) |
| Mutation | temporary mutations of `validation.rs`, `cargo test -p ostrich-acme --lib dns01`, restore verified with `diff -q` | PASS | 5 of 5 QA mutants killed (empty-list guard, FQDN dot, `cache_size`, original `ResolverConfig::default()` bug, case-insensitive compare); owner-filter mutation killed in fix round 1 |
| Format / lint | `cargo fmt --all -- --check`, `make clippy`, fuzz crate `rustfmt` and `clippy` | PASS | rc=0 (fix rounds 1-3) |
| Supply chain | `make security` | PASS | 614 crates, no vulnerabilities (QA round, fix round 1) |
| Helm render | `helm lint` / `helm template deploy/helm/ostrich-pki` | **NOT RUN** | helm not installed; only a Go `text/template` stub render (release engineer, REL-001) |
| Integration | `make test-integration` | **NOT RUN** | no Postgres; no dns-01 integration test exists |
| Live dns-01 E2E | real recursive / authoritative DNS | **NOT RUN** | no such test exists |
| Binary smoke | `ostrich-acme-server --dns01-resolvers ""` | **NOT RUN** | local aws-lc-fips dylib load failure, unrelated to the change |

**New tests (final tree, names checked against `cargo test` output):**

- `validation.rs` resolver configuration: `dns01_config_rejects_empty_name_servers`,
  `dns01_config_rejects_system_error`, `dns01_config_uses_upstreams_and_skips_system`,
  `dns01_config_rejects_invalid_upstreams`, `dns01_config_uses_system_name_servers_only`,
  `dns01_opts_disable_caching`, `validate_dns01_resolver_ips_policy`
- `validation.rs` query name and validator: `dns01_query_name_is_fqdn`,
  `dns01_query_name_rejects_bad_identifiers`,
  `dns01_validate_fails_closed_without_name_servers`,
  `dns01_validate_rejects_malformed_identifier_first`,
  `dns01_validate_rejects_invalid_upstreams_without_fallback`,
  `dns01_validate_public_rejects_malformed_identifier`
- `validation.rs` TXT matching: `txt_match_requires_concatenation_equal_to_digest`,
  `txt_match_requires_owner_on_cname_chain`, `txt_match_bounds_cname_chain_length`
- `validation.rs` loopback mock DNS (real hickory resolver):
  `dns01_mock_valid_digest_returns_true`,
  `dns01_mock_split_strings_joining_to_digest_returns_true`,
  `dns01_mock_junk_and_digest_in_one_record_returns_false`,
  `dns01_mock_foreign_owner_txt_returns_false`,
  `dns01_mock_cname_delegated_txt_returns_true`,
  `dns01_mock_trailing_dot_identifier_is_malformed`,
  `dns01_mock_near_miss_digests_return_false`,
  `dns01_mock_mismatch_then_match_returns_true`,
  `dns01_mock_wrong_thumbprint_returns_false`,
  `dns01_mock_retry_after_nxdomain_is_not_cached`,
  `dns01_mock_persistent_nxdomain_fails_closed`
- `validation.rs` http-01 / tls-alpn-01 error mapping:
  `http01_connect_failure_is_connection_with_generic_detail`,
  `http01_non_2xx_is_incorrect_response`, `http01_wrong_body_is_not_valid`,
  `unresolvable_challenge_host_is_dns`, `acme_identifier_digest_is_bounds_checked`;
  `resolve_pinned_enforces_ssrf_guard_unless_allowed` extended
  (`rejectedIdentifier`, no IP in the detail)
- `error.rs`: `every_error_type_is_registered`
- `rest.rs`: `challenge_error_document_uses_type_and_client_detail`,
  `challenge_error_document_only_emits_registered_types`
- `services/acme-server/src/main.rs` (bins; not run by `make test-unit`):
  `dns01_resolvers_arg_parses`, `dns01_resolvers_invalid_refuses_startup`,
  `dns01_resolvers_boundaries`, `dns01_resolvers_empty_value_means_system_resolvers`

**Not covered:** the `validate_challenge` audit record and the
`AcmeState.dns01_resolvers` → `with_resolvers` wiring (need Postgres; QA-001,
POAM-2026-10-23-51); TCP fallback, truncation and SERVFAIL against a real
server; the env-var form `ACME_DNS01_RESOLVERS=""` at runtime (the parser is
tested directly); Helm rendering; CAA and DNSSEC (not implemented,
POAM-2026-10-23-41); tls-alpn-01 RFC 8737 §3 critical-flag and SAN checks
(not implemented, POAM-2026-10-23-52).

---

### 2.14 Test Run 2026-10-26 (CI evidence gaps: live DB + SoftHSM, Helm and fuzz jobs)

**Scope:** branch `pr/hopeful-sammet-b6708c` on `main` @ 460f62c, uncommitted
and not pushed (run record
`target/agent-workflow/20261026-082358-ci-evidence-gaps/`). Test-only and
CI-only change: three new GitHub workflows, the new
`tests/integration/ca_grpc_audit_e2e.rs`, the `OSTRICH_REQUIRE_LIVE_TESTS`
fail-on-skip gate, a token-based disposable-database check, the
`migrate_test_db` example and GitLab `test:integration` fixes. The only
production-source edit is two comment-only `// POAM:` markers in
[rest.rs](../../crates/ostrich-ca/src/rest.rs). **Sources:** `qa-report.md`
(QA round) and `fixes-round-1.md` (final tree). The compliance scribe did not
re-run these commands.

**Host:** aarch64-apple-darwin, no Postgres or Docker, a scratch Helm v3.19,
Homebrew SoftHSM 2.7.0. **No live database test ran.** Every result below is
an offline gate, a skip-path run, or a negative run of the gate itself.

**Executed locally (2026-10-26, final tree):**

| Gate | Command | Result | Counts |
|------|---------|--------|--------|
| Format | `cargo fmt --all -- --check` | PASS | exit 0 |
| Lint | `cargo clippy -p ostrich-ca -p ostrich-db -p ostrich-audit -p ostrich-integration-tests --all-targets --locked -- -D warnings` | PASS | exit 0, no warnings |
| Unit | `cargo test -p ostrich-ca --lib --locked` | PASS | **85 passed, 0 failed**: includes the `live_test_env::tests::*` gate tests (among them `disposable_db_name_requires_a_test_token`); the 4 e2e modules pass on the skip path, which is **not** evidence |
| Unit | `cargo test -p ostrich-audit --locked` | PASS | lib 20; `chain_concurrency`, `sign_timeout_db`, `signed_chain_tamper` 2 each (skip path plus the DB-name guard unit test; not evidence) |
| Unit | `cargo test -p ostrich-db --locked` | PASS | lib 54; example `migrate_test_db` 1 (DB-name guard unit test) |
| Build | `cargo test -p ostrich-integration-tests --locked --no-run` | PASS | 17 test executables, including `ca_grpc_audit_e2e` |
| Live-gate unit tests | `cargo test -p ostrich-integration-tests --locked --test ca_grpc_audit_e2e --test est_serverkeygen_e2e -- --show-output` (env unset) | PASS | 7 passed per binary: 6 `live::tests::*` plus the live test on the skip path (prints the `skipped (` note) |
| Negative: require-live (lib) | `OSTRICH_REQUIRE_LIVE_TESTS=1 cargo test -p ostrich-ca --lib --locked e2e` | PASS (fails as required) | **exit 101**: 0 passed, 4 failed, 81 filtered out; each `live test required but DATABASE_URL is not set` |
| Negative: require-live (integration) | `OSTRICH_REQUIRE_LIVE_TESTS=1 cargo test --locked -p ostrich-integration-tests --test ca_grpc_audit_e2e --test est_serverkeygen_e2e --no-fail-fast` | PASS (fails as required) | **exit 101**: 6 passed, 1 failed per binary |
| Negative: no secret echo | as above with a `DATABASE_URL` containing a test password, PKCS11 module and slot set, PIN unset | PASS | exit 101, names `PKCS11_PIN`; 0 occurrences of the password in the output |
| Negative: audit opt-in | `OSTRICH_DB_TESTS=1 cargo test --locked -p ostrich-audit --test chain_concurrency --test signed_chain_tamper --test sign_timeout_db --no-fail-fast` | PASS (fails as required) | each suite 1 failed (no database) |
| Workflow check step, simulated | the "Every targeted live test ran and passed" `run:` block on captured logs (QA) | PASS | all-skipped logs → rc=1; one expected name removed → rc=1; all names, no skip → rc=0 |
| Helm script | `HELM=<scratch helm v3.19> HELM_{CACHE,CONFIG,DATA}_HOME=<scratch> bash scripts/helm-chart-check.sh <scratch chart copy + postgresql-14.3.3.tgz>` | PASS | **15 passed, 0 failed** (P1-P4, N0a-N0c, N1-N8), exit 0. Helm **3.19 on macOS, not the pinned 3.22.1** |
| Helm script, mutant chart | as above, CA gRPC TLS `required` guard replaced by a default (QA) | PASS (mutant killed) | `FAIL N0a`, 14 passed, 1 failed, exit 1 |
| Fuzz smoke | `cargo +nightly-2026-10-23 fuzz run <target> -- -max_total_time=30 -timeout=10 -rss_limit_mb=2048` (ASan) | PASS | `fuzz_grpc_requestor` **128,734 runs** / 31 s; `fuzz_grpc_peer_subject` **80,018 runs** / 31 s; no crash (§5.4) |
| Fuzz budget validator | the `Validate the time budget` step, in bash | PASS | accepts 60, 600, 3600; rejects 59, 3601, 0600, `1;id`, empty, `abc` |
| YAML / pins | Ruby `YAML.safe_load` on all workflows and `.gitlab-ci.yml`; scan for `uses:` not pinned `@<40-hex> # v` in the new workflows | PASS | all parse; 0 unpinned |
| `actionlint`, `shellcheck` | | **NOT RUN** | not installed |

**CI jobs added (not run: the change is not pushed):**

| Workflow / job | Triggers | What it runs | Artifact (retention) | Status |
|---|---|---|---|---|
| [integration-db.yml](../../.github/workflows/integration-db.yml) `DB + SoftHSM live tests` | push to `main`, pull request, dispatch | migrations via `migrate_test_db`; `ostrich-audit` Postgres suites; `ostrich-ca` lib e2e modules; `ca_grpc_audit_e2e`; `est_serverkeygen_e2e`; then fails unless all 9 expected tests report `ok` and no log reports a skip | `live-db-softhsm-results` (90 days) | **NOT RUN** |
| [helm.yml](../../.github/workflows/helm.yml) `Helm chart validation` | push to `main`, pull request, dispatch | Helm v3.22.1 (sha256-verified), `helm dependency build` plus sha256 check of `postgresql-14.3.3.tgz`, `scripts/helm-chart-check.sh` (15 cases) | `helm-chart-results` (90 days) | **NOT RUN** |
| [fuzz.yml](../../.github/workflows/fuzz.yml) `Fuzz <target>` | weekly (Monday 06:30 UTC, 600 s), dispatch (60-3600 s), path-filtered pull request (60 s) | `fuzz_grpc_requestor`, `fuzz_grpc_peer_subject` on `nightly-2026-10-23`, cargo-fuzz 0.13.2 | `fuzz-log-<target>` (30 days); `fuzz-crash-<target>` on failure (30 days) | **NOT RUN** |
| `.gitlab-ci.yml` `test:integration` | GitLab pipeline | `sslmode=disable`, `PKCS11_SLOT` by token label, `OSTRICH_REQUIRE_LIVE_TESTS=1`, `migrate_test_db`, `cargo test --test '*'` plus the `ostrich-ca --lib` e2e filters | job log | **NOT RUN** |

**DB-gated suites after this change (supersedes the §2.10 "DB-gated" row):**

| Suite | CI path | Executed |
|---|---|---|
| `chain_concurrency`, `signed_chain_tamper`, `sign_timeout_db` (`ostrich-audit`, `OSTRICH_DB_TESTS=1`) | `integration-db.yml`; GitLab `test:integration` | **NOT RUN** (POAM-2026-10-23-31) |
| `audit_signing_e2e`, `crl_delta_e2e`, `issuance_aia_e2e`, `pop_e2e` (`ostrich-ca` lib modules) | `integration-db.yml`; GitLab `test:integration` (new `--lib` filter run) | **NOT RUN** (POAM-2026-10-23-36) |
| `ca_grpc_audit_e2e` (new) | `integration-db.yml`; GitLab `test:integration` | **NOT RUN** (POAM-2026-10-23-36) |
| `est_serverkeygen_e2e` | `integration-db.yml`; GitLab `test:integration` | **NOT RUN** |
| `ca_core_test`, `ocsp_revocation_test` (`--ignored`, need the compose stack) | **none** | **NOT RUN** (POAM-2026-10-23-36 residual) |

**`ca_grpc_audit_e2e` (`grpc_handlers_record_verified_peer_as_audit_actor`,
written, NOT RUN):** serves the real `CaGrpcService` behind
`SubjectAllowlistLayer` over mTLS with a SoftHSM-backed CA key and asserts,
for IssueCertificate, RevokeCertificate and GenerateCrl, actor = verified peer
DN, `authenticated_caller` / `_issuer` / `_serial` and `on_behalf_of`; then
`verify_signed_chain` against the CA SPKI must return true, and false after one
byte of the gRPC-written `crl_generation` signature is corrupted. It asserts
one stored `access_denied` Failure record (actor `CN=acme-server`, reason
`method_not_permitted`) when an Issuer calls GenerateCrl. The denial path uses
an `AuthAuditAdapter` stack that the test assembles to mirror
`start_grpc_listener`, not `start_grpc_listener` itself. **M13h:** kill argued
by construction (the mutant writes actor `unauthenticated`); not executed.

**PR #184 release findings:** REL-002 (Helm in CI), REL-005 (DB/HSM CI path)
and REL-008 (fuzz in CI) are addressed in code by the three workflows; close
each on a linked green run.

**Not covered:** every live assertion above; the REST `generate_crl` /
`generate_delta_crl` handler glue; CRL and Revoke failure audits on the
database paths; the call-time `ca_profile_not_permitted` refusal through
`issue()`; Helm v3.22.1 on Linux; the GitLab changes. ASan with the AWS-LC
FIPS module does not build on Linux (the FIPS delocate step rejects the
instrumented C build; first PR run, 2026-10-26), so `fuzz.yml` runs with
`--sanitizer none`: libFuzzer coverage, panics and overflow checks only, no
memory sanitizer in CI.

---

### 2.15 Test Run 2026-10-26 (Web UI legacy /next open redirect)

**Scope:** branch `pr/blissful-chandrasekhar-6051b3`, uncommitted, based on
`main` @ c9a159c (v0.17.0; includes PR #191) (run record
`target/agent-workflow/20261026-113122-next-open-redirect/`). Changed file:
`services/web-ui/src/server/router.rs` (`legacy_next_router`,
`legacy_next_redirect`, `legacy_next_target` and tests). Closes
POAM-2026-10-23-45 (CWE-601, SI-10) pending the first green CI run.
**Sources:** `qa-report.md` (QA round on base 460f62c, before the rebase onto
e56a09e: 37 / 0; PASS), `fixes-round-1.md` (61 / 0 after the fixes and the
rebase). Rows marked "scribe" were re-run by the compliance scribe on the
final working tree on 2026-10-26.

| Gate | Command | Result | Counts / notes |
|------|---------|--------|----------------|
| Format | `cargo fmt -p ostrich-web-ui -- --check` | PASS | exit 0 (QA, coder, scribe) |
| Lint | `cargo clippy -p ostrich-web-ui --all-targets -- -D warnings` | PASS | 0 warnings (QA, coder, scribe) |
| Unit tests | `cargo test -p ostrich-web-ui` | PASS | **61 passed, 0 failed, 0 ignored** (coder after fix round 1; scribe). QA round before the fixes and the rebase: 37 / 0 |
| Scoped run | `cargo test -p ostrich-web-ui legacy_next` | PASS | 20 passed, 0 failed (coder after fix round 1; scribe). QA round: 18 / 0 |
| Doc tests | n/a | NOT RUN | binary-only crate |
| Workspace | `cargo fmt --all --check` / `make clippy` / `make test-unit` | NOT RUN | scoped to one crate |
| Supply chain | `make security` | NOT RUN | no `Cargo.toml` / `Cargo.lock` change |
| Fuzz | n/a | NOT RUN | no new parser; the helper is covered by a table-driven corpus test |
| CI | GitHub `CI` / `Build & test` (`cargo test --workspace --lib --bins --locked`) | **NOT RUN** | change not committed |

**New tests (20, all `server::router::tests::test_legacy_next_*`):**

- Coder (8): `test_legacy_next_encoded_slash_fails_secure` (`%2F`, `%2f`),
  `test_legacy_next_double_slash_fails_secure`,
  `test_legacy_next_encoded_backslash_upper_fails_secure`,
  `test_legacy_next_encoded_backslash_lower_fails_secure` (all 308 `/`),
  `test_legacy_next_preserves_deep_link` (`/next/certificates/abc` →
  `/certificates/abc`), `test_legacy_next_drops_query`,
  `test_legacy_next_root_redirects_to_root` (`/next` and `/next/` → `/`),
  `test_legacy_next_target_helper` (unit)
- QA (10, as revised in fix round 1):
  `test_legacy_next_double_encoded_separators_stay_in_origin` (`%252F` stays
  literal), `test_legacy_next_mixed_case_encoded_separators_anywhere_fail_secure`,
  `test_legacy_next_literal_backslash_fails_secure`,
  `test_legacy_next_dot_segments_fail_secure` (15 dot-segment variants → `/`;
  `.well-known`, `a.b`, `...` preserved),
  `test_legacy_next_prefix_must_be_exact_segment` (`/nextfoo`, `/Next` → 404,
  no `Location`), `test_legacy_next_whitespace_variants`,
  `test_legacy_next_query_and_fragment_do_not_influence_path`,
  `test_legacy_next_methods` (HEAD 308 `/`, POST 405),
  `test_legacy_next_non_visible_ascii_fails_secure` (DEL and raw UTF-8 → 308
  `/`; replaced QA's `test_legacy_next_del_byte_fails_closed`, which recorded
  a 500), `test_legacy_next_target_invariant_corpus` (18 inputs checked
  against the same-origin `Location` invariant)
- Fix round 1 (2): `test_legacy_next_inner_double_slash_fails_secure`,
  `test_legacy_next_merged_router_fails_secure` (legacy router merged before
  a fallback and wrapped in `audit_middleware`, as `create_router` does)

**Not covered:** `create_router` itself (it needs a `WebUiConfig` and a static
directory); wire-level request-target parsing through hyper / httparse (tests
build requests with `http::Uri`); no test captures the
`legacy_redirect_rejected` warn event (no tracing-capture dev-dependency; the
Ok / Err split that drives it is tested at helper level). The event is a
`tracing` log line, not an `ostrich-audit` record (POAM-2026-10-23-47).

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

**2026-10-23:** `cargo audit` with 1351 advisories loaded,
642 crates scanned: **0 vulnerabilities, 0 warnings**, exit 0, after
remediating 18 vulnerabilities and 4 warnings found on `main` @ 88c10cd (see
§2.3 and NIST SI-2). At that time the CI `cargo audit` job was advisory.

**2026-10-23, CI hardening:** the CI job now runs `cargo audit --deny warnings`
with no `continue-on-error`, so a new advisory fails the workflow. It is not
yet a required status check, so it does not by itself block merges (POA&M).
Local result: exit 0, 642 crates, 0 vulnerabilities, 0 warnings (§2.4).

**2026-10-24, dependency cleanup:** `cargo audit --deny
warnings` exit 0 (1352 advisories, 614 crates) after `rand` 0.8.5 → 0.8.6 and
the removal of `openidconnect` and `p256`. The ignore list is down to 3 IDs
(RUSTSEC-2023-0071, -2024-0436, -2025-0134). Local only (§2.7).

**2026-10-26, Dependabot alert remediation:** `cargo audit
--deny warnings` exit 0 (1378 advisories, 614 crates) and `cargo deny check`
exit 0 after hickory-resolver/-net/-proto 0.26.1 → 0.26.2. Those three GHSAs
have no RustSec alias and were found by Dependabot, not `cargo audit`. Web UI
full `pnpm audit`: 28 (1 low / 9 moderate / 18 high) → 2 moderate (react-router
v6, POAM-2026-10-23-39). Regression: `make test-unit` 782 / 0 / 1, `make clippy`
and the web-ui frozen install, typecheck, lint and build pass. No tests were
added. Local only; first CI run pending (ATO_EVIDENCE.md §2.3).

**2026-10-26, react-router v7 migration (latest recorded):** web-ui full
`pnpm audit`: 2 moderate → **0** ("No known vulnerabilities found") after
`react-router-dom` ^6.30.6 was replaced by `react-router` ^7.18.1 (7.18.4),
closing GHSA-wrjc-x8rr-h8h6 and GHSA-337j-9hxr-rhxg (POAM-2026-10-23-39). The
CI gate form `pnpm audit --prod --audit-level=high` is unchanged
(POAM-2026-10-23-42). Cargo files did not change. Local only (§2.11).

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
| gRPC peer subject / allowlist (`fuzz_grpc_peer_subject`, 2026-10-25) | 237,187 (61 s) after the fix | 1 before the fix (OID-arc overflow panic, fixed) | Pass after fix (implementer-reported, §2.8) |
| gRPC peer subject / role lists (`fuzz_grpc_peer_subject`, 2026-10-26) | 135,145 (61 s) after the fix | 1 before the fix (const-oid `Display` panic on an undecodable numeric OID, fixed) | Pass after fix (coder-reported, §2.10) |
| gRPC requestor binding (`fuzz_grpc_requestor`, new 2026-10-26) | 246,720 (61 s) | 0 | Pass (coder-reported, §2.10) |
| ACME dns-01 query name (`fuzz_dns01_query_name`, new 2026-10-26) | 131,276 (61 s, QA oracle); 136,323 (46 s) after fix round 1 | 0 | Pass (QA- and coder-reported, §2.13) |
| gRPC requestor binding (`fuzz_grpc_requestor`, 2026-10-26 smoke, `nightly-2026-10-23`, cargo-fuzz 0.13.2, ASan, aarch64-apple-darwin) | 128,734 (31 s) | 0 | Pass (coder-reported, §2.14; local smoke, not the CI job) |
| gRPC peer subject (`fuzz_grpc_peer_subject`, 2026-10-26 smoke, same toolchain) | 80,018 (31 s) | 0 | Pass (coder-reported, §2.14; local smoke, not the CI job) |
| Both gRPC targets, scheduled / dispatch / PR job ([fuzz.yml](../../.github/workflows/fuzz.yml)) | n/a | n/a | **NOT RUN** (workflow added 2026-10-26, not pushed; scheduled and dispatch runs need the workflow on `main`) |

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

Tests are executed on every pull request and every push to `main`; some
workflows also run weekly. There is no nightly build (corrected 2026-10-26:
earlier text listed one).

**Pipeline Stages:**

1. Lint (`cargo fmt --check`, `cargo clippy`)
2. Unit Tests (`cargo test`)
3. Security Scan (`cargo audit`, `cargo deny`)
4. Build (`cargo build --release`)

**GitHub Actions workflows (2026-10-26):**

| Workflow | Triggers | Test evidence | Artifact (retention) | Recorded run |
|---|---|---|---|---|
| [ci.yml](../../.github/workflows/ci.yml) `CI` | pull request, push to `main` | fmt, clippy, `cargo test --workspace --lib --bins`, offline `grpc_mtls_e2e` / `fips_gate_preinstalled` (no database), web-ui build | `web-ui-sbom` | not recorded in this document |
| [audit.yml](../../.github/workflows/audit.yml) `dependency gate` | pull request, push to `main`, weekly, dispatch | `cargo audit --deny warnings`, `cargo deny check` | none | PR 181 checks green (§2.5) |
| [hsm-integration.yml](../../.github/workflows/hsm-integration.yml) `HSM integration` | pull request, push to `main`, dispatch | PKCS#11 suite on SoftHSM2 | `pkcs11-softhsm-results` (90 days) | run 40063317654: 28 / 0 / 1 (§2.5) |
| [integration-db.yml](../../.github/workflows/integration-db.yml) `Live DB + SoftHSM tests` (added 2026-10-26) | pull request, push to `main`, dispatch | Postgres + SoftHSM live suites; fails on a skipped or missing test (§2.14) | `live-db-softhsm-results` (90 days) | **NOT RUN** |
| [helm.yml](../../.github/workflows/helm.yml) `Helm chart` (added 2026-10-26) | pull request, push to `main`, dispatch | Helm v3.22.1 lint, template and 15 positive / negative cases (§2.14) | `helm-chart-results` (90 days) | **NOT RUN** |
| [fuzz.yml](../../.github/workflows/fuzz.yml) `Fuzz` (added 2026-10-26) | weekly, dispatch, path-filtered pull request | `fuzz_grpc_requestor`, `fuzz_grpc_peer_subject` (§5.4) | `fuzz-log-<target>`, `fuzz-crash-<target>` (30 days) | **NOT RUN** |
| `docker-publish.yml` | push to `main`, tags, dispatch | image build and publish (no tests) | build output | not test evidence (tag-pinned actions, POAM-2026-10-23-15) |

GitLab `test:integration` (`.gitlab-ci.yml`) was corrected on 2026-10-26
(§2.14) and has no recorded pipeline run. A job counts as evidence only with
its run URL, the commit SHA and the sha256 of the downloaded artifact,
archived in the run record before the artifact expires (ATO_EVIDENCE.md
Appendix B).

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
| 1.6 | 2026-10-24 | OstrichPKI Team | Added §2.6, the PR 152 fail-closed FIPS TLS run: `tls::` 26 passed / 0 failed; `make test-unit` 667 / 0 / 1; service `--bins` 58 / 0; `mtls_peercert_e2e` 1 / 0; fmt, clippy, `cargo deny`, `cargo audit` pass; mutation check fails both refusal tests as intended. CI on the uncommitted round-1 fixes, Postgres integration and live start-up NOT RUN. QA-005 (`make test-unit` skips service bins) recorded. Header version 1.2 → 1.6 (1.3-1.5 had not updated it). |
| 1.7 | 2026-10-24 | OstrichPKI Team | Added §2.7, the dependency-cleanup run: `make test-unit` 667 / 0 / 1; web-ui `--bins` 19 / 0; npe-portal `--bins` 30 / 0; two new offline fixture tests 2 / 0 (`ca_core_test` health/readiness fail without docker, pre-existing QA-001); fmt, clippy pass; `cargo audit --deny warnings` and `cargo deny check` pass without the RUSTSEC-2026-0097 and RUSTSEC-2026-0387 ignores (3 IDs left); live `test_ca_issue_certificate_ecdsa` and CI NOT RUN. §5.2: 2026-10-24 result added. §2.5: ignore-count note. |
| 1.8 | 2026-10-25 | OstrichPKI Team | Added §2.8, the CA gRPC mTLS run: `grpc_mtls_e2e` 20 / 0 and `fips_gate_preinstalled` 1 / 0 (re-run by the scribe); unit `ostrich-common` 229, `ostrich-audit` 13, `ostrich-db` 54, `ostrich-ca` 54, `ostrich-est` 43 (re-run); ca/acme/est `--bins` 9 / 3 / 8 (re-run); fuzz `fuzz_grpc_peer_subject` 237,187 runs clean after the OID-overflow fix and mutations M1-M5 caught (implementer); Postgres `chain_concurrency` NOT RUN (the skip-pass without `DATABASE_URL` is not evidence); docker, kubectl, release start-up and CI NOT RUN. §2.6 "Not covered" cross-referenced. §5.4 fuzz row added. Header version 1.6 → 1.8 (1.7 had not updated it). |
| 1.9 | 2026-10-25 | OstrichPKI Team | Added §2.9, the CA gRPC mTLS final-code run after fix rounds 2-3: `grpc_mtls_e2e` 21/21, `fips_gate_preinstalled` 1/1, 41 `grpc_tls::tests`, `ostrich-audit` lib 20/20 (re-run by the scribe); `make test-unit` 732/0 and service bins (coder). Postgres tests incl. new `sign_timeout_db.rs` NOT RUN |
| 2.0 | 2026-10-26 | OstrichPKI Team | Added §2.10, the per-method CA gRPC authorization run (coder-reported, final tree; not re-run by the scribe): `make test-unit` 782 / 0 / 1, `grpc_tls` 66, `ostrich-ca` 78, ca-server bins 21, `ostrich-est` 44, `grpc_mtls_e2e` 39; fuzz `fuzz_grpc_requestor` 246,720 runs and `fuzz_grpc_peer_subject` 135,145 runs after a const-oid panic fix; mutations M1-M29 killed except M13h (NOT RUN). DB-gated suites NOT RUN (POAM-2026-10-23-36). §5.4 fuzz rows added |
| 2.1 | 2026-10-26 | OstrichPKI Team | §5.2: recorded the Dependabot alert remediation result (`cargo audit` exit 0, 1378 advisories / 614 crates; full web-ui `pnpm audit` 28 → 2 moderate; `make test-unit` 782 / 0 / 1); "latest recorded" moved to it. No new tests. Local only |
| 2.2 | 2026-10-26 | OstrichPKI Team | Added §2.11, the web-ui react-router v7 migration run: frozen install, typecheck, lint, build pass; full `pnpm audit` 0 and react-router 7.18.4 (re-run by the scribe); manual guard vectors `safe-path-check.mjs` 181 / 0 and `router-smoke.mjs` 5 / 0 (re-run by the scribe; run-record scripts, not committed); browser smoke against a mock BFF (OIDC and logout not covered); CI NOT RUN. §5.2: 2026-10-26 react-router result added and "latest recorded" moved to it. No automated test added (no web-ui test runner, POAM-2026-10-23-44) |
| 2.3 | 2026-10-26 | OstrichPKI Team | Added §2.12, the web-ui BFF proxy raw-path run (closes POAM-2026-10-23-43 pending first green CI run): `cargo test -p ostrich-web-ui` 41 / 0 / 0 with 22 new tests (validator, router-level zero-backend-hit, AU-3 log capture, inbound header stripping, `SessionData` `Debug` redaction); fmt and clippy clean (re-run by the scribe); QA flake check 120 / 120; workspace, supply-chain, fuzz and CI NOT RUN. §2.11 "Not covered" cross-referenced to §2.12 |
| 2.4 | 2026-10-26 | OstrichPKI Team | Added §2.13, the ACME dns-01 resolver fix run: `make test-unit` 817 / 0 / 1 and `ostrich-acme` lib 72 / acme-server bins 7 (re-run by the scribe); fuzz `fuzz_dns01_query_name` (new) and mutation checks recorded; Helm render, integration, live dns-01 E2E and binary smoke NOT RUN. §5.4: new fuzz row. Header "latest recorded run" updated |
| 2.5 | 2026-10-26 | OstrichPKI Team | Added §2.14, the CI evidence-gaps run (branch `pr/hopeful-sammet-b6708c`, uncommitted, not pushed; coder- and QA-reported, not re-run by the scribe): fmt / clippy clean; `ostrich-ca` lib 85 / 0; `OSTRICH_REQUIRE_LIVE_TESTS=1` negative runs exit 101; live-gate unit tests; `helm-chart-check.sh` 15 / 15 with Helm 3.19 (not the pinned 3.22.1); fuzz 30 s smoke 128,734 / 80,018 runs. New jobs `integration-db.yml`, `helm.yml`, `fuzz.yml` and the GitLab `test:integration` fixes: **NOT RUN**. All live DB + SoftHSM suites, including the new `ca_grpc_audit_e2e`, NOT RUN; M13h kill argued by construction, not executed. §2.10 Helm and DB-gated rows cross-referenced. §5.4: smoke and CI rows. §8.2: workflow table; the "nightly builds" claim removed (no such workflow) |
| 2.6 | 2026-10-26 | OstrichPKI Team | §2.12: recorded the CI result for the web-ui BFF proxy raw-path change, merged as [PR #191](https://github.com/192d-Wing/OstrichPKI/pull/191) (fix commit e56a09e, merge commit 635c5c3): GitHub Actions [run 40360909224](https://github.com/192d-Wing/OstrichPKI/actions/runs/40360909224) `Build & test` (`cargo test --workspace --lib --bins --locked`, ubuntu-24.04, rustc 1.99.1) `ostrich_web_ui` 41 passed / 0 failed / 0 ignored (CI NOT RUN → PASS); the run's other jobs and the PR's `cargo audit`, `cargo deny` and `PKCS#11 suite (SoftHSM2)` checks green. POAM-2026-10-23-43 closed. Scope line updated from "uncommitted" to the merge reference; §2.11 cross-reference updated. No GitLab pipeline result recorded; doc tests and fuzz still NOT RUN |
| 2.7 | 2026-10-26 | OstrichPKI Team | Added §2.15, the web-ui legacy `/next` open-redirect run (closes POAM-2026-10-23-45 pending first green CI run; SI-10, CWE-601): `cargo test -p ostrich-web-ui` 61 / 0 / 0 with 20 new `test_legacy_next_*` tests; `legacy_next` filter 20 / 0; fmt and clippy clean (re-run by the scribe); workspace, supply-chain, fuzz and CI NOT RUN |
