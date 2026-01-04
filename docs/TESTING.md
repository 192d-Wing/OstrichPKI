# OstrichPKI Testing Guide

> **Last Updated**: January 2026 | **Phase 14**: Testing & Hardening

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Test Categories](#test-categories)
- [Running Tests](#running-tests)
- [Integration Testing](#integration-testing)
- [Performance Benchmarking](#performance-benchmarking)
- [Security Testing](#security-testing)
- [Fuzzing](#fuzzing)
- [Coverage Analysis](#coverage-analysis)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

---

## Overview

OstrichPKI maintains comprehensive test coverage across multiple categories:

| Test Type | Coverage Target | Location | Run Time |
|-----------|----------------|----------|----------|
| Unit Tests | >80% | `crates/*/src/**/*.rs` | <5 min |
| Integration Tests | Critical paths | `tests/integration/` | <10 min |
| Benchmarks | Performance baselines | `benches/benches/` | ~5 min |
| Fuzz Tests | Parser robustness | `fuzz/fuzz_targets/` | Continuous |
| Security Scans | 0 vulnerabilities | CI/CD | <2 min |

### COMPLIANCE MAPPING

- **NIST 800-53: SA-11** - Developer Security Testing and Evaluation
- **NIST 800-53: CA-2** - Security Assessments
- **NIST 800-53: SI-7** - Software, Firmware, and Information Integrity

---

## Quick Start

```bash
# Install development tools
make install-tools

# Run all tests
make test-all

# Run security checks
make security

# Simulate full CI pipeline
make ci-full
```

---

## Test Categories

### 1. Unit Tests

**Purpose**: Test individual functions, modules, and crates in isolation.

**Location**: Inline tests and `tests/` directories within each crate.

**Example**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_serial_generation() {
        let serial = generate_serial_number();
        assert!(serial.len() <= 20); // RFC 5280: max 20 octets
    }
}
```

**Running**:

```bash
# All unit tests
cargo test --workspace --lib

# Specific crate
cargo test --package ostrich-x509 --lib

# Specific test
cargo test test_certificate_serial_generation
```

### 2. Integration Tests

**Purpose**: Test complete workflows across multiple services.

**Location**: `tests/integration/`

**Coverage**:

- ACME: Account → Order → Challenge → Finalize → Certificate
- EST: mTLS Auth → Enroll → Certificate
- CA: CSR → Issuance → Revocation → CRL
- OCSP: Certificate Status Queries

**Running**:

```bash
# All integration tests
make test-integration

# Specific test suite
cargo test --test acme_e2e_test

# With Docker Compose services
cd tests/integration
docker-compose up -d
cargo test --test acme_e2e_test
docker-compose down
```

### 3. Documentation Tests

**Purpose**: Ensure code examples in documentation compile and run.

**Running**:

```bash
make test-doc
# or
cargo test --workspace --doc
```

### 4. Property-Based Tests

**Purpose**: Test invariants with randomly generated inputs.

**Example**:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_serial_number_always_positive(serial in any::<Vec<u8>>()) {
        let cert = build_certificate_with_serial(&serial);
        assert!(!cert.serial_is_negative());
    }
}
```

---

## Running Tests

### Using Make (Recommended)

```bash
# Run all tests
make test

# Run only unit tests (fast)
make test-unit

# Run integration tests
make test-integration

# Run with verbose output
cargo test --workspace -- --nocapture

# Run tests matching a pattern
cargo test certificate
```

### Test Filters

```bash
# Run only tests containing "acme"
cargo test acme

# Run ignored tests
cargo test -- --ignored

# Run all tests including ignored
cargo test -- --include-ignored

# Single-threaded execution (for database tests)
cargo test -- --test-threads=1
```

### Environment Variables

```bash
# Database connection
export DATABASE_URL="postgresql://ostrich_test:test_password@localhost:5432/ostrich_pki_test"

# PKCS#11 HSM
export PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_SLOT_ID="0"
export PKCS11_PIN="1234"
export CRYPTO_PROVIDER="software"  # or "hsm"

# Logging
export RUST_LOG="info,ostrich=debug"
export RUST_BACKTRACE="1"
```

---

## Integration Testing

### Prerequisites

1. **PostgreSQL Database**:

   ```bash
   # Using Docker
   docker run -d \
     -e POSTGRES_USER=ostrich_test \
     -e POSTGRES_PASSWORD=test_password_insecure \
     -e POSTGRES_DB=ostrich_pki_test \
     -p 5432:5432 \
     postgres:16-alpine

   # Run migrations
   sqlx migrate run
   ```

2. **SoftHSM** (for PKCS#11 tests):

   ```bash
   make install-softhsm
   ```

### Running Integration Tests

#### Option 1: Direct Test Execution

```bash
# Set environment variables
export DATABASE_URL="postgresql://ostrich_test:test_password_insecure@localhost:5432/ostrich_pki_test"

# Run integration tests
cargo test --test acme_e2e_test
cargo test --test est_e2e_test
cargo test --test ca_core_test
```

#### Option 2: Docker Compose (Full Stack)

```bash
cd tests/integration

# Start all services
docker-compose up -d

# Wait for services to be healthy
docker-compose ps

# Run tests against running services
export ACME_BASE_URL="http://localhost:8080"
export EST_BASE_URL="https://localhost:8443"
cargo test --test acme_e2e_test

# View logs
docker-compose logs -f acme-service

# Stop services
docker-compose down
```

### Integration Test Structure

```
tests/integration/
├── acme_e2e_test.rs       # ACME workflow tests
├── est_e2e_test.rs        # EST enrollment tests
├── ca_core_test.rs        # CA operations tests
├── docker-compose.yml     # Service orchestration
└── common/
    ├── mod.rs            # Common test utilities
    ├── fixtures.rs       # Test data generators
    └── http_client.rs    # HTTP test helpers
```

---

## Performance Benchmarking

OstrichPKI uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for performance benchmarking.

### Running Benchmarks

```bash
# Run all benchmarks
make bench

# Run specific benchmark suite
cargo bench --package ostrich-benches --bench crypto_benchmarks

# Compare with baseline
cargo bench --package ostrich-benches -- --save-baseline main
# Make changes...
cargo bench --package ostrich-benches -- --baseline main
```

### Available Benchmarks

| Benchmark | Measures | Target |
|-----------|----------|--------|
| `crypto_benchmarks` | RSA/ECDSA keygen, signing, verification | <50ms signing |
| `x509_benchmarks` | Certificate building, parsing, validation | <10ms build |
| `encoding_benchmarks` | DER encoding, PEM parsing | <1ms encode |

### Performance Targets

**NIST 800-53: CP-2 - Capacity Planning Requirements**

| Operation | Target Latency (p50) | Target Latency (p99) | Target Throughput |
|-----------|---------------------|---------------------|-------------------|
| Certificate Signing (HSM) | 30ms | 50ms | 100 TPS |
| Certificate Signing (Software) | 5ms | 10ms | 500 TPS |
| OCSP Response | 10ms | 100ms | 1,000 TPS |
| CRL Generation | 100ms | 500ms | 10 TPS |
| Database Query | 2ms | 10ms | - |

### Analyzing Results

Benchmark results are saved to `target/criterion/`:

```bash
# View HTML report
open target/criterion/report/index.html

# Compare runs
criterion-compare baseline current
```

---

## Security Testing

### 1. Dependency Auditing

**Check for known vulnerabilities in dependencies:**

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
make audit

# Auto-fix vulnerabilities
make audit-fix
```

### 2. License and Supply Chain Checks

**Verify dependency licenses and sources:**

```bash
# Install cargo-deny
cargo install cargo-deny

# Run all checks
make deny

# Check advisories only
make deny-advisories

# Check licenses only
make deny-licenses
```

Configuration: [`deny.toml`](../deny.toml)

### 3. Secrets Scanning

**Detect hardcoded secrets in code:**

```bash
# Using gitleaks (in CI/CD)
gitleaks detect --source . --verbose

# Using local git history scan
gitleaks detect --source . --log-opts="--all"
```

### 4. Static Analysis

**Detect code quality issues and anti-patterns:**

```bash
# Clippy (mandatory in CI)
make clippy

# With all warnings as errors
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Specific lints
cargo clippy -- -W clippy::pedantic -W clippy::cargo
```

---

## Fuzzing

Fuzz testing discovers crashes, panics, and memory safety issues through randomized input generation.

### Setup

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Install nightly Rust
rustup install nightly
```

### Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_der_certificate` | X.509 certificate DER parsing |
| `fuzz_pem_certificate` | PEM-encoded certificate parsing |
| `fuzz_der_csr` | PKCS#10 CSR parsing |
| `fuzz_jws_signature` | ACME JWS signature validation |
| `fuzz_ocsp_request` | OCSP request parsing |
| `fuzz_ocsp_response` | OCSP response parsing |
| `fuzz_crl_parsing` | CRL parsing |

### Running Fuzz Tests

```bash
# List available targets
cargo fuzz list

# Run specific target for 60 seconds
cargo +nightly fuzz run fuzz_der_certificate -- -max_total_time=60

# Run with multiple CPU cores
cargo +nightly fuzz run fuzz_der_certificate -- -workers=4

# Run all targets (short test)
make fuzz-all
```

### Handling Fuzzing Crashes

When a crash is found:

```bash
# Reproduce the crash
cargo +nightly fuzz run fuzz_der_certificate artifacts/fuzz_der_certificate/crash-<hash>

# Debug with address sanitizer
cargo +nightly fuzz run fuzz_der_certificate --sanitizer=address artifacts/.../crash-<hash>

# After fixing, verify
cargo +nightly fuzz run fuzz_der_certificate artifacts/.../crash-<hash>
```

See [`fuzz/README.md`](../fuzz/README.md) for detailed documentation.

---

## Coverage Analysis

### Using Tarpaulin

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
make coverage

# Generate HTML report
cargo tarpaulin --workspace --all-features --timeout 300 --out Html --output-dir ./coverage

# Open report
open coverage/index.html
```

### Coverage Targets

- **Overall**: >80% line coverage
- **Critical modules** (crypto, x509, ca): >90% coverage
- **Protocol parsers** (ACME, EST, OCSP): >85% coverage

### Viewing Coverage

```bash
# Terminal output
cargo tarpaulin --workspace --all-features

# HTML report
make coverage-open

# Upload to Codecov (CI only)
bash <(curl -s https://codecov.io/bash)
```

---

## CI/CD Integration

### GitHub Actions Workflow

The CI pipeline ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs on every push and PR:

**Stages**:

1. **Lint**: Format check + Clippy
2. **Security**: `cargo audit` + `cargo deny` + Gitleaks
3. **Build & Test**: Multi-OS, multi-Rust version
4. **Integration Tests**: With PostgreSQL service
5. **Benchmarks**: Performance regression detection
6. **SBOM Generation**: Supply chain transparency
7. **Compliance Check**: Verify documentation exists

### Running CI Locally

```bash
# Simulate CI lint stage
make ci-lint

# Simulate CI security stage
make ci-security

# Simulate CI test stage
make ci-test

# Run full CI pipeline locally
make ci-full
```

### Pre-commit Hooks

```bash
# Run before every commit
make pre-commit

# Run before every push
make pre-push
```

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Failures

```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Verify DATABASE_URL
echo $DATABASE_URL

# Reset database
make db-reset
```

#### 2. SoftHSM Not Found

```bash
# Check SoftHSM installation
softhsm2-util --show-slots

# Set correct module path
export PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"  # Linux
export PKCS11_MODULE_PATH="/opt/homebrew/lib/softhsm/libsofthsm2.so"  # macOS
```

#### 3. Integration Tests Fail

```bash
# Check services are healthy
docker-compose ps

# View service logs
docker-compose logs acme-service

# Restart services
docker-compose restart
```

#### 4. Slow Tests

```bash
# Run tests in parallel (default)
cargo test --workspace

# Run serially (if tests conflict)
cargo test --workspace -- --test-threads=1

# Run only fast tests
cargo test --workspace --lib
```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG="debug"

# Enable backtraces
export RUST_BACKTRACE="full"

# Run with logging
cargo test test_name -- --nocapture
```

---

## Test Metrics

### Success Criteria for Phase 14

- [ ] >80% code coverage (unit + integration tests)
- [ ] All integration tests passing
- [ ] Zero high/critical security vulnerabilities
- [ ] All benchmarks within target latency
- [ ] Fuzzing: 1M+ iterations without crashes
- [ ] CI pipeline green on all platforms

### Tracking Progress

```bash
# Test coverage
make coverage

# Security vulnerabilities
make security

# Compliance annotations
make compliance-annotations

# Benchmark results
make bench
```

---

## References

- [Rust Testing Documentation](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion.rs Benchmarking](https://bheisler.github.io/criterion.rs/book/)
- [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [Tarpaulin Coverage](https://github.com/xd009642/tarpaulin)
- [NIST 800-53 SA-11: Developer Testing](https://nvd.nist.gov/800-53/Rev5/control/SA-11)
