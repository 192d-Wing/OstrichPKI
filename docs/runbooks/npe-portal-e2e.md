# Runbook: NPE Portal End-to-End Verification

## Overview

This runbook verifies the Non-Person Entity (NPE) enrollment portal
(`ostrich-npe-portal`) end to end: mTLS authentication with OID-derived roles,
the four role workspaces, and the security boundary. It maps to the verification
plan for the portal and to the controls in
[`docs/compliance/`](../compliance/).

**NIST 800-53 Controls:** IA-2, AC-3, AC-5, AC-6, AC-8, AC-12, AU-2, SC-8
**NIAP PP-CA SFRs:** FIA_X509_EXT.1/.2, FMT_SMR.2, FDP_CER_EXT.3, FDP_SEPP.1,
FMT_SMF.1

> The portal authenticates operators by **mTLS client certificate only** and
> derives the role from the certificate's policy OIDs. Every scenario below
> requires a client certificate issued under the configured `allowedIssuers`
> carrying the appropriate role OID (see `oidMapping` in the portal config).

---

## 1. Prerequisites

- A running stack: `postgres`, `ca-service`, `est-service`, and `npe-portal`
  (the in-repo dev stack: `docker compose up -d postgres ca-init ca-service
  est-service npe-portal`).
- Four client certificates, one per role, each issued under the portal's
  `allowedIssuers` and carrying the role OID from `oidMapping`:
  - PKI Sponsor — `sponsorOids`
  - Administrator — Sponsor cert **plus** the `adminOid`
  - Registration Authority — `raOids`
  - CA Admin (CAA) — `caaOids`
- `curl` with client-cert support, or a browser with the client cert imported.

> The dev `docker-compose` entry runs the portal with `NPE_ALLOW_INSECURE=true`
> (no client-CA) for smoke testing only — role-based flows require real certs and
> a production-style config with `tls.*` set.

Base URL (dev): `https://localhost:9443` (host `9443` → container `8443`).

---

## 2. Authentication & consent (IA-2, AC-8, FIA_X509_EXT.1)

```bash
# No / wrong client cert -> rejected at the TLS handshake (no HTTP response).
curl -k https://localhost:9443/            # fails: no client certificate

# Valid Sponsor cert -> first response is the USG consent interstitial; the
# session is not authenticated until consent is accepted.
curl -k --cert sponsor.crt --key sponsor.key https://localhost:9443/auth/login

# An Admin cert (Sponsor + adminOid) resolves to the Administrator role.
```

**Expected:** no/invalid cert is rejected; a valid cert reaches the consent gate;
the mapped role matches the cert's OID (Sponsor/Admin/RA/CAA). Session locks after
30 minutes idle (AC-12).

Backing tests: `cargo test -p ostrich-npe-portal` (OID→role mapping, session
timeout, consent gate), `cargo test -p ostrich-common auth::` (role permissions).

---

## 3. Sponsor / Administrator — Certificate Management

- **Submit Application** (Sponsor): queued → returns a Request ID.
- **EFS profile**: server-side keygen returns a one-time PKCS#12 password +
  `.p12` download (auto-issued, not queued).
- **Submit Bulk** (Administrator): upload a ZIP of CSRs under one profile →
  Bulk Identifier + per-CSR results + downloadable CSV.

```bash
# EFS server-side keygen (no CSR; subject = the authenticated identity):
curl -k --cert sponsor.crt --key sponsor.key \
  -H "Content-Type: application/json" -d '{"keyStrength":2048}' \
  https://localhost:9443/api/est/.well-known/est/PTEFS/serverkeygen
# -> {"format":"pkcs12","certificateId":"...","pkcs12":"<base64>","password":"<one-time>"}
```

Backing tests: `cargo test -p ostrich-x509` (encrypted PKCS#12 round-trip),
`cargo test -p ostrich-est` (EFS serverkeygen, label routing),
`cargo test -p ostrich-ca` (bulk validate/queue).

---

## 4. Registration Authority — approve / override / revoke (FDP_SEPP.1)

- **Manage Applications**: the RA sees the **whole** pending queue (gated on
  `ApproveRequest` at both the REST layer and the approval engine).
- **Approve / Reject** with a justification/reason.
- **Approve with override** (`?override=true`): requires `OverrideValidation`;
  the override is recorded on the decision and audited.
- Self-approval is rejected (requestor ≠ approver).
- **Revoke Certificates**: look up a cert, revoke with an RFC 5280 reason.

```bash
# Approve with override (RA cert with OverrideValidation):
curl -k --cert ra.crt --key ra.key -H "Content-Type: application/json" \
  -d '{"justification":"waiver: validity advisory acknowledged"}' \
  "https://localhost:9443/api/ca/api/v1/approvals/<id>/approve?override=true"
```

**Expected:** an RA without `OverrideValidation` gets 403 on the override path; a
Sponsor gets 403 on the approve path entirely.

---

## 5. CA Admin (CAA) — users / namespaces / config (AC-2, AC-5, CM-3)

- **Manage Users & Roles**: create cert users, assign roles, enable/disable,
  delete. **Self-action block**: a CAA cannot modify/disable/delete their own
  account (the UI disables the row; the API returns 403). Only the four NPE roles
  are assignable (privilege ceiling).
- **Namespaces & Wildcards**: add/delete allow/deny DNS-pattern rules.
- **System Configuration**: edit seeded settings (value type-validated).

```bash
# Self-action block (CAA acting on their own account) -> 403:
curl -k --cert caa.crt --key caa.key -X DELETE \
  https://localhost:9443/api/ca/api/v1/users/<own-id>     # -> 403

# Assigning a non-NPE (legacy) role -> 400 (privilege ceiling):
curl -k --cert caa.crt --key caa.key -H "Content-Type: application/json" \
  -d '{"roles":["administrator"]}' \
  https://localhost:9443/api/ca/api/v1/users/<id>/roles    # -> 400
```

---

## 6. Security boundary (AC-3)

The BFF proxy is allowlisted to **CA + EST only**; even with a valid session a
client cannot reach admin-only services (audit, KRA), and inbound `X-Npe-*`
identity headers are **stripped** so a client cannot spoof its identity/role.

```bash
# Non-allowlisted path -> 404 (not proxied):
curl -k --cert sponsor.crt --key sponsor.key \
  https://localhost:9443/api/kra/...        # -> 404

# Spoofed identity header is ignored (stripped before forwarding):
curl -k --cert sponsor.crt --key sponsor.key \
  -H "X-Npe-Roles: caa_admin" \
  https://localhost:9443/api/ca/api/v1/users    # -> 403 (still a Sponsor)
```

Backing test: `cargo test -p ostrich-npe-portal server::proxy`
(`inbound_identity_headers_are_stripped`).

---

## 7. Quick all-up test command

```bash
# Backend + boundary unit/integration coverage (run in WSL per the build workflow):
scripts/build-wsl.sh test -p ostrich-npe-portal -p ostrich-ca -p ostrich-est \
  -p ostrich-x509 -p ostrich-common
# Frontend type + build:
(cd services/npe-portal/web && npm run build)
```

## Troubleshooting

- **Pod CrashLoopBackOff at startup**: the portal fails closed without mTLS
  material. Provide `npePortal.tls.existingSecret` (Helm) or `--allow-insecure`
  (dev). The log says *"refusing to start without mandatory mTLS"*.
- **All requests 401/403 behind an ingress**: the ingress is terminating TLS
  instead of passing it through — the portal never sees the client cert. Enable
  ssl-passthrough and remove any `ingress.tls` block.
- **EST/CA proxy calls fail**: check `backend.caUrl` / `backend.estUrl` in the
  portal config resolve on the cluster network, and (production) that the backend
  mTLS material (`mtlsClientCert`/`Key`/`CaCert`) is mounted.
