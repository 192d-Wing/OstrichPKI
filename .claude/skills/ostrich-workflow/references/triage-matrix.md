# Triage Matrix — which roles run

The orchestrator picks the roster from the paths a change touches. When in
doubt, include the reviewer: a skipped reviewer is a silent gap in ATO
evidence, an extra one costs only tokens.

## Always-on for any code change

- `qa-engineer`
- `security-reviewer`
- `nist-800-53-reviewer`
- `compliance-scribe`

## Path-triggered roles

| Touched path / topic | Add |
|----------------------|-----|
| `crates/ostrich-crypto/**` (provider, algorithm, kem, key, drbg, pkcs11, self_test, verify) | `pqc-reviewer` |
| Any signature/KEM/hash algorithm choice, OID table (`ostrich-common/src/oid.rs`), key generation, key wrapping | `pqc-reviewer` |
| `crates/ostrich-kra/**`, `services/kra-server/**` (transport keys, key escrow) | `pqc-reviewer` |
| `crates/ostrich-x509/**` (certificate, CRL, CSR, extensions, path validation) | `rfc-conformance-reviewer`, `pqc-reviewer` |
| `crates/ostrich-ocsp/**`, `services/ocsp-server/**` | `rfc-conformance-reviewer` |
| `crates/ostrich-acme/**`, `services/acme-server/**` | `rfc-conformance-reviewer` |
| `crates/ostrich-est/**`, `services/est-server/**` | `rfc-conformance-reviewer` |
| `crates/ostrich-tamp/**`, `services/tamp-server/**` | `rfc-conformance-reviewer` |
| `crates/ostrich-protocol/**` (CMS, PKCS#7/#12, ASN.1 helpers) | `rfc-conformance-reviewer` |
| TLS config (`ostrich-common/src/tls.rs`, rustls setup, mTLS) | `rfc-conformance-reviewer`, `pqc-reviewer` (hybrid KEX) |
| `crates/ostrich-common/src/auth/**`, RBAC, sessions, lockout | (always-on set covers it; flag AC/IA focus in the prompt) |
| `crates/ostrich-audit/**` | (always-on set; flag AU-9/AU-10 focus) |
| `migrations/**`, `crates/ostrich-db/**` | `release-engineer` |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | `release-engineer` |
| `Dockerfile`, `docker/**`, `docker-compose*.y*ml`, `deploy/**` (Helm, k8s) | `release-engineer` |
| `.github/workflows/**`, `.gitlab-ci.yml`, `Makefile` | `release-engineer` |
| `services/web-ui/**`, `services/npe-portal/**` | (always-on set; flag XSS/CSRF/session focus) |
| `fuzz/**`, `tests/**`, `benches/**` only | `qa-engineer` only (+ scribe if TEST_EVIDENCE changes) |

## Phase skips

| Situation | Skip |
|-----------|------|
| Docs / comments only | Phases 1–4; run scribe + `markdownlint` only |
| Bug fix with an obvious one-file cause | Phase 1 may be a short inline plan written by the orchestrator into `plan.md` |
| Internal refactor, no behaviour/API change | Phase 6 |
| `review` mode | Phases 1–2 |

Record every skipped role or phase, with the reason, in `brief.md`.
