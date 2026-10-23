# Report Formats

## Findings file (`findings-<role>.md`)

```markdown
# Findings — <role>

Scope: <base>...<head> (<n> files), plan: <run>/plan.md
Verdict: APPROVE | APPROVE WITH COMMENTS | CHANGES REQUESTED

## <ROLE-PREFIX>-001 [BLOCKER] <one-line title>

- **Location**: `crates/ostrich-x/src/file.rs:123`
- **Reference**: NIST 800-53 SC-13 | RFC 5280 §4.1.2.2 | FIPS 204 §5 | CWE-...
- **Problem**: what is wrong, in one or two sentences.
- **Failure scenario**: concrete input/state → concrete bad outcome.
- **Fix**: the smallest change that resolves it.
- **Confidence**: high | medium | low
```

Role prefixes: `SEC` (security), `NIST` (800-53/NIAP), `PQC` (crypto),
`RFC` (protocol), `QA` (testing), `REL` (release).

### Severity

| Severity | Meaning | Gate effect |
|----------|---------|-------------|
| BLOCKER | Exploitable vulnerability, key/secret exposure, wrong crypto, broken RFC MUST, missing authn/authz, audit bypass, data loss | Must fix |
| MAJOR | Missing required control/test, RFC SHOULD violated without reason, fail-open path, unvalidated input that does not yet reach a sink | Must fix |
| MINOR | Hardening, missing annotation, weak test, unclear error type | Advisory |
| NIT | Style, naming, comments | Advisory |

A finding without a location and a failure scenario is MINOR at most.

## Fix response (`fixes-round-<n>.md`)

```markdown
| Finding | Action | Change |
|---------|--------|--------|
| SEC-001 | Fixed | `file.rs:120-131` validate length before decode |
| PQC-002 | Rebutted | ML-DSA context string is empty by spec for X.509 (draft-ietf-lamps-dilithium-certificates §3) |
```

## Gate summary

`gate.md`, written by the orchestrator:

```markdown
# Gate — <task>

Verdict: PASS | PASS WITH POA&M | FAIL

| Gate | Result | Evidence |
|------|--------|----------|
| fmt | PASS | `cargo fmt --all --check` |
| clippy | PASS | `make clippy` |
| unit tests | PASS (412) | `make test-unit` |
| integration | NOT RUN | Postgres unavailable |
| security review | APPROVE | findings-security.md (0 open) |
| NIST 800-53 review | APPROVE WITH COMMENTS | findings-nist.md (2 MINOR) |
| PQC review | APPROVE | findings-pqc.md |
| RFC review | SKIPPED | no protocol code touched |
| compliance docs | UPDATED | docs-update.md |
| release | CHANGELOG + patch bump suggested | release-notes.md |

## Open items
- NIST-003 [MINOR] ...

## POA&M
- (none) | `// POAM:` at file:line, accepted by user on <date>

## Dropped findings
- SEC-004: not reachable; input already validated at `handler.rs:40`.
```
