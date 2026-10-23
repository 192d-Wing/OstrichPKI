# Quality Gates

Commands come from the repo `Makefile` and `CONTRIBUTING.md`. Scope to the
touched crates (`-p <crate>`) while iterating; run the workspace-wide form
once before the final gate.

| Gate | Iterating | Final | Required |
|------|-----------|-------|----------|
| Format | `cargo fmt --all` | `cargo fmt --all --check` | Yes |
| Lint | `cargo clippy -p <crate> --all-targets -- -D warnings` | `make clippy` | Yes |
| Unit tests | `cargo test -p <crate> --lib` | `make test-unit` | Yes |
| Doc tests | `cargo test -p <crate> --doc` | `make test-doc` | When public API changed |
| Integration | `cargo test -p ostrich-integration-tests --test <name>` | `make test-integration` | When service behaviour changed (needs Postgres/SoftHSM; see `docs/TESTING.md`) |
| Supply chain | — | `make security` (`cargo audit` + `cargo deny`) | When `Cargo.toml`/`Cargo.lock` changed |
| Fuzz smoke | `cargo fuzz run <target> -- -max_total_time=60` | `make fuzz-all` | When a parser in `fuzz/fuzz_targets/` changed |
| Compliance docs | — | `make compliance-check` | Yes for code changes |
| Annotations | — | `make compliance-annotations` (count should not drop) | Yes for code changes |
| Markdown | — | `npx markdownlint-cli "docs/**/*.md"` (config: `.markdownlint.json`; not wired into CI) | When docs changed |

## Rules

- Record every command with its exit status and the last relevant lines of
  output in `qa-report.md`. "Tests pass" without the command is not evidence.
- If an environment dependency is missing (Postgres, SoftHSM, OpenSSL 3.5 for
  PQC interop), say so explicitly and mark that gate **NOT RUN**, not PASS.
- No new `#[allow(clippy::...)]`, `#[ignore]`, or `unwrap()` on untrusted input
  to get a gate green without a justification comment and a finding entry.
- Run the final workspace-wide gates in the background; they take minutes.
