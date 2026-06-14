# EST Crate Security Review & Remediation — 2026-06-14

Scope: full security review of the `ostrich-est` crate (RFC 7030 Enrollment over
Secure Transport) and its directly-involved dependencies (`ostrich-common`
gRPC client, `ostrich-db` EST repository, `est-server` binary). All findings
below were confirmed against source and remediated in this change set.

This document is SAR (Security Assessment Report) evidence and feeds the POA&M
closure entries in `docs/compliance/NIAP_GAP_ANALYSIS.md`.

## Threat model

An authenticated-but-malicious or unauthenticated EST client (or an attacker on
the EST→CA network path) attempting to: obtain a certificate for an identity it
does not own, escalate privilege, impersonate another client, read/forge
issuance traffic, extract private key material, or evade audit.

## Findings and remediation

| ID | Sev | Finding | Fix | Control |
|----|-----|---------|-----|---------|
| C1 | Critical | EST→CA gRPC channel silently degraded to plaintext (default config had empty TLS PEMs), allowing CSR disclosure and forged issuance | `EstCaClient::new` fails closed: non-loopback endpoint without TLS material is rejected unless `--ca-insecure`. CA mTLS PEMs wired via `--ca-grpc-client-cert/-key/-ca-cert`. | SC-8, AC-17, FTP_ITC.1, SI-17 |
| C2 | Critical | Re-enroll identity binding compared only a lossy 7-field DN projection and ignored SANs; client could add `SAN: DNS:admin.internal` or unmodeled RDNs and renew for an identity it didn't own | Binding now compares the full RFC 4514 subject DN string **and** the complete SAN set (order/dup-insensitive) against the prior certificate | AC-3, FDP_ACC.1, FDP_ACF.1, SI-10 |
| H1 | High | `simpleenroll` / `serverkeygen` performed no authorization of the requested subject/SAN against the authenticated principal | Configurable `EstIdentityPolicy` (`--enroll-identity-policy`): `username` (default — CSR must name the authenticated username in CN/SAN) or `allowlist` (every asserted identity must be in the account's `est_account_identities` allow-list, for delegated enrollment). Else deny+audit. | AC-3, AC-6, FDP_ACF.1 |
| H2 | High | Issuance, PoP, parse, and validation **failures** were not audited | All such failures now emit an `AccessViolation`/`Failure` audit event with the actor | AU-2, AU-12, FAU_GEN.1 |
| H3 | High | `issue_certificate` (non-idempotent) was wrapped in blanket retry → possible duplicate issuance on lost responses | Single client-side attempt; rely on CA `request_id` dedup | SI-17 |
| M1 | Medium | Error responses returned raw `Database`/`Internal` text to clients (recon oracle) | 5xx bodies are generic; full detail logged server-side only | SI-11 |
| M2 | Medium | Bearer-token auth was the silent default when no mTLS CA configured | est-server refuses to start in bearer mode without explicit `--allow-bearer-auth` | CM-6, AC-3, RFC 7030 §3.3 |
| M3 | Medium | serverkeygen private key copied into non-zeroized `String`s in the response path | Key base64 + multipart body assembled in `Zeroizing` buffers (one unavoidable copy remains in the outbound HTTP buffer) | SC-12, SI-12, FCS_CKM.4 |
| M4 | Medium | `get_certificate` 404-vs-present existence oracle | Not reachable — method has no route/call site. No code change; noted for future routing. | — |
| L1 | Low | No explicit request body limit (relied on axum default) | `DefaultBodyLimit::max(64 KiB)` on protected routes | SC-5 |
| L2 | Low | Post-issuance writes (cert id, then status) were non-transactional | Single atomic `mark_enrollment_issued` UPDATE | SI-17 |
| L3 | Low | serverkeygen audit logged `Success` before key generation ran | Audit emitted only after generation succeeds | AU-3 |
| L4 | Low | Key-destruction (`destroy_key`) failure was swallowed | Now logged at `error` level | AU-9, FCS_CKM.4 |
| F2 | High (latent) | `ClientCertExtractor::from_header` turned an attacker HTTP header into an authenticated identity (dead code, but a loaded gun) | Compiled only under the `insecure-dev-auth` feature; off by default | AC-3, CM-6 |

## Residual / follow-up

- **M3**: one copy of the private key necessarily lives in the outbound HTTP
  body buffer (hyper/axum) when delivering a server-generated key; full
  zeroization through the response stack is not achievable without a custom body
  type. Consider password-protected PKCS#12 delivery (RFC 7030 §4.4.2) as a
  future enhancement.
- **M4**: if a certificate-retrieval endpoint is ever routed, return a uniform
  404 for both "absent" and "not authorized" to avoid an enumeration oracle.
- **H3**: confirm and document that the CA enforces idempotency on `request_id`.

## Verification

- `cargo check` / `cargo clippy` clean for `ostrich-est`, `ostrich-est-server`,
  `ostrich-db`.
- Unit tests added: re-enroll SAN set comparison (C2), identity binding (H1),
  loopback detection (C1), and existing HTTP Basic tests. `cargo test -p
  ostrich-est --lib` → 18 passed.
