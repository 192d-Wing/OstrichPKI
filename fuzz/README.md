# OstrichPKI Fuzzing Infrastructure

This directory contains fuzz targets for security-critical parsing and validation code.

## COMPLIANCE MAPPING

- **NIST 800-53: SA-11** - Developer Security Testing (Fuzz Testing)
- **NIST 800-53: SI-10** - Information Input Validation
- **NIST 800-53: CM-2, CM-3** - One lockfile for the workspace and the fuzz harness (POAM-2026-10-23-60)

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
| `fuzz_grpc_peer_subject` | gRPC client-certificate subject, allowlist and client registry parsing | RFC 5280 §4.1.2.6 |
| `fuzz_grpc_requestor` | CA gRPC client-asserted requestor binding | - |
| `fuzz_dns01_query_name` | ACME dns-01 query name construction | RFC 8555 §8.4, RFC 1035 |
| `fuzz_proxy_path` | BFF proxy raw-path validation | RFC 3986 §2.1 / §3.3 / §5.2.4 |
| `fuzz_acme_order_identifier` | ACME newOrder identifier parsing and list validation | RFC 8555 §7.1.3 / §7.1.4 / §6.7, RFC 8738 §3 |

## Workspace Membership

`fuzz/` (package `ostrich-fuzz`) is a member of the root workspace and shares
the root `Cargo.lock`; there is no `fuzz/Cargo.lock` (CI fails if one is
committed). Consequences:

- Run `cargo fuzz` from the repository root (or from `fuzz/`; cargo-fuzz finds
  the same project). Fuzz binaries land in `target/<host-triple>/release/`,
  not `fuzz/target/`. Corpus and artifacts stay in `fuzz/corpus/` and
  `fuzz/artifacts/`.
- cargo-fuzz has no `--profile` option, so it builds with the root
  `[profile.release]` (fat LTO, `strip = true`). Set the same overrides as
  `fuzz.yml` and `make fuzz-all` to get the usual fuzz profile (much faster
  builds, symbolised crash stacks). Prefix each `cargo fuzz` command rather
  than `export`ing them, so a later `cargo build --release` in the same shell
  still uses the shipped release profile:

  ```bash
  CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=false \
    cargo +nightly-2026-10-23 fuzz run --sanitizer none fuzz_proxy_path
  ```

- Stable `cargo build/check/clippy --workspace` compile every fuzz target
  (a compile gate on all targets in `ci.yml`). `cargo test --bins` must
  `--exclude ostrich-fuzz`: `--bins` overrides `test = false`, and a fuzz
  bin's test binary is libFuzzer's `main`, which never exits. Release builds
  and coverage (tarpaulin) also exclude it (CI fails a test/coverage command
  that would select the fuzz bins). If such a run was started by mistake,
  Ctrl-C / killing `cargo` can leave the libFuzzer test binary running: kill
  its process group (`kill -- -<pgid>`) or `pkill -f 'target/debug/deps/fuzz_'`.
- One `cargo update` updates the fuzz graph together with the workspace.

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

`.github/workflows/fuzz.yml` runs `fuzz_grpc_requestor`,
`fuzz_grpc_peer_subject`, `fuzz_acme_order_identifier` and
`fuzz_dns01_query_name` weekly (Monday 06:30 UTC), on manual dispatch
(`max_total_time`, 60-3600 s per target; default 600), and for a fixed 60 s
on pull requests that touch `fuzz/`, the workflow,
`crates/ostrich-common/src/{grpc_tls.rs,tls.rs,auth/**}`,
`crates/ostrich-acme/src/{identifier.rs,validation.rs,order.rs,error.rs}`,
any `crates/*/Cargo.toml`, the root `Cargo.toml` or `Cargo.lock`, or
`rust-toolchain.toml`.
It pins the toolchain to `nightly-2026-10-23` and cargo-fuzz to `0.13.2`
(`cargo install --locked`, never restored from a cache), checks
the root `Cargo.lock` with `cargo fetch --locked`, keeps the corpus per target in
the Actions cache (saved by scheduled and manual runs only), and uploads the
run log plus any crash reproducers from `fuzz/artifacts/<target>/`.
Reproduce locally:

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-10-23 fetch --locked
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=false \
  cargo +nightly-2026-10-23 fuzz run --sanitizer none fuzz_grpc_requestor -- -max_total_time=600
```

To sweep every target:

```bash
# Run each target for 5 minutes; non-zero exit if any target fails
make fuzz-all FUZZ_TIME=300
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
