# OstrichPKI Fuzzing Infrastructure

This directory contains fuzz targets for security-critical parsing and validation code.

## COMPLIANCE MAPPING

- **NIST 800-53: SA-11** - Developer Security Testing (Fuzz Testing)
- **NIST 800-53: SI-10** - Information Input Validation

## Prerequisites

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Install nightly Rust (required for fuzzing)
rustup install nightly
```

## Available Fuzz Targets

| Target | Description | RFC/Standard |
|--------|-------------|--------------|
| `fuzz_der_certificate` | X.509 certificate DER parsing | RFC 5280 |
| `fuzz_pem_certificate` | PEM-encoded certificate parsing | RFC 7468 |
| `fuzz_der_csr` | PKCS#10 CSR parsing | RFC 2986 |
| `fuzz_jws_signature` | ACME JWS signature validation | RFC 8555, RFC 7515 |
| `fuzz_ocsp_request` | OCSP request parsing | RFC 6960 |
| `fuzz_ocsp_response` | OCSP response parsing | RFC 6960 |
| `fuzz_crl_parsing` | CRL parsing | RFC 5280 §5 |

## Running Fuzz Tests

### List all fuzz targets

```bash
cargo fuzz list
```

### Run a specific fuzz target

```bash
# Run for 60 seconds
cargo +nightly fuzz run fuzz_der_certificate -- -max_total_time=60

# Run with specific number of iterations
cargo +nightly fuzz run fuzz_der_certificate -- -runs=1000000

# Run with multiple workers (parallel fuzzing)
cargo +nightly fuzz run fuzz_der_certificate -- -workers=4 -jobs=4
```

### Run all fuzz targets (short test)

```bash
make fuzz-all
```

### Continuous fuzzing (for CI/CD)

`.github/workflows/fuzz.yml` runs `fuzz_grpc_requestor` and
`fuzz_grpc_peer_subject` weekly (Monday 06:30 UTC), on manual dispatch
(`max_total_time`, 60-3600 s per target; default 600), and for a fixed 60 s
on pull requests that touch `fuzz/`, the workflow,
`crates/ostrich-common/src/{grpc_tls.rs,tls.rs,auth/**}`,
`crates/ostrich-common/Cargo.toml`, the root `Cargo.toml` or
`rust-toolchain.toml`.
It pins the toolchain to `nightly-2026-10-23` and cargo-fuzz to `0.13.2`
(`cargo install --locked`, never restored from a cache), checks
`fuzz/Cargo.lock` with `cargo fetch --locked`, keeps the corpus per target in
the Actions cache (saved by scheduled and manual runs only), and uploads the
run log plus any crash reproducers from `fuzz/artifacts/<target>/`.
Reproduce locally:

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-10-23 fuzz run fuzz_grpc_requestor -- -max_total_time=600
```

To sweep every target:

```bash
# Run each target for 5 minutes
for target in $(cargo fuzz list); do
    cargo +nightly-2026-10-23 fuzz run $target -- -max_total_time=300
done
```

## Coverage-Guided Fuzzing

```bash
# Build with coverage instrumentation
cargo +nightly fuzz coverage fuzz_der_certificate

# Generate coverage report
cargo +nightly fuzz coverage fuzz_der_certificate --html
```

## Corpus Management

The fuzzer automatically builds a corpus of interesting inputs that maximize code coverage.

- **corpus/** - Inputs that triggered new code paths (kept for regression testing)
- **artifacts/** - Inputs that caused crashes (must be investigated and fixed)

```bash
# Add seed inputs to corpus
mkdir -p corpus/fuzz_der_certificate
cp tests/fixtures/certificates/*.der corpus/fuzz_der_certificate/

# Minimize corpus (remove redundant inputs)
cargo +nightly fuzz cmin fuzz_der_certificate
```

## Handling Crashes

When fuzzing finds a crash:

1. The crashing input is saved to `artifacts/fuzz_<target>/`
2. Reproduce the crash:

   ```bash
   cargo +nightly fuzz run fuzz_der_certificate artifacts/fuzz_der_certificate/crash-<hash>
   ```

3. Debug with sanitizers:

   ```bash
   # Address sanitizer (memory safety)
   cargo +nightly fuzz run fuzz_der_certificate --sanitizer=address

   # Undefined behavior sanitizer
   cargo +nightly fuzz run fuzz_der_certificate --sanitizer=undefined
   ```

4. Fix the bug in the source code
5. Verify the fix:

   ```bash
   cargo +nightly fuzz run fuzz_der_certificate artifacts/fuzz_der_certificate/crash-<hash>
   ```

## Integration with CI/CD

The fuzzing infrastructure is integrated into the CI pipeline (`.github/workflows/fuzz.yml`) to run on a schedule:

- **Daily**: All fuzz targets run for 30 minutes each
- **Weekly**: Extended fuzzing session (4 hours per target)

## Security Targets

Fuzzing prioritizes:

1. **ASN.1/DER parsers** - Most common source of PKI vulnerabilities
2. **Cryptographic signature validation** - Critical for security
3. **Protocol parsers** (OCSP, ACME) - Network-facing attack surface

## Performance Targets

- **Executions per second**: >10,000 exec/s (depends on target complexity)
- **Total iterations**: 1,000,000+ for production readiness
- **Code coverage**: >80% of parser code

## References

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz best practices](https://google.github.io/oss-fuzz/)
