# OstrichPKI Administrative Guidance

**Document Version:** 1.6
**Last Updated:** 2026-10-26
**NIAP Reference:** AGD_OPE.1 - Operational User Guidance
**Audience:** CA Administrators, Operations Staff, Security Officers

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Roles and Responsibilities](#2-security-roles-and-responsibilities)
3. [System Configuration](#3-system-configuration)
4. [Certificate Lifecycle Operations](#4-certificate-lifecycle-operations)
5. [Key Management](#5-key-management)
6. [Audit Log Management](#6-audit-log-management)
7. [User Management](#7-user-management)
8. [Security Monitoring](#8-security-monitoring)
9. [Backup and Recovery](#9-backup-and-recovery)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

### 1.1 Purpose

This document provides operational guidance for administrators and operators of OstrichPKI. It covers secure configuration, daily operations, and security management procedures required for NIAP PP-CA v2.1 compliance.

### 1.2 Scope

This guide covers:

- Role-based access control configuration
- Certificate Authority operations
- Key management procedures
- Audit log review and management
- Security monitoring and incident response
- Backup and disaster recovery

### 1.3 Prerequisites

Before using this guide, ensure:

- OstrichPKI is installed per [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)
- HSM is initialized and configured
- Database is operational
- TLS certificates are deployed
- Initial administrator account is created

### 1.4 Document Conventions

| Convention | Meaning |
|------------|---------|
| `command` | Command to execute |
| `<variable>` | Replace with actual value |
| **Warning** | Security-critical information |
| **Note** | Additional information |

---

## 2. Security Roles and Responsibilities

### 2.1 Role Definitions

OstrichPKI implements five security roles per NIAP PP-CA v2.1:

| Role | Description | Primary Responsibilities |
|------|-------------|-------------------------|
| **Administrator** | System configuration and user management | Install, configure, maintain system; manage users; backup keys |
| **Operations Staff** | Certificate lifecycle operations | Issue, revoke, renew certificates; generate CRLs |
| **Auditor** | Security monitoring and log review | Review audit logs; generate compliance reports |
| **RA Staff** | Registration authority functions | Verify identity; approve certificate requests |
| **AOR** | Policy authority | Define certificate policies; approve policy changes |

### 2.2 Separation of Duties

**Critical Requirement:** The following role combinations are prohibited:

| Prohibited Combination | Reason |
|-----------------------|--------|
| Administrator + Operations Staff | Prevents single person from configuring system and issuing certificates |
| Auditor + Operations Staff | Prevents hiding certificate operations from audit |
| AOR + Operations Staff | Prevents policy maker from executing operations |

### 2.3 Role Assignment

**Administrator Only:** Role assignment requires Administrator privileges.

```bash
# Assign role to user
ostrich-admin user add-role --user <username> --role <role>

# Available roles: administrator, operations, auditor, ra_staff, aor

# List user roles
ostrich-admin user list-roles --user <username>

# Remove role from user
ostrich-admin user remove-role --user <username> --role <role>
```

### 2.4 Role Permissions Matrix

| Operation | Admin | Ops | Auditor | RA | AOR |
|-----------|-------|-----|---------|----|----|
| Issue Certificate | - | Yes | - | - | - |
| Revoke Certificate | - | Yes | - | - | - |
| Generate CRL | - | Yes | - | - | - |
| View Audit Logs | Yes | - | Yes | - | Yes |
| Export Audit Logs | - | - | Yes | - | - |
| Modify Configuration | Yes | - | - | - | - |
| Manage Users | Yes | - | - | - | - |
| Backup CA Key | Yes | - | - | - | - |
| Approve Requests | - | - | - | Yes | - |
| Modify Policy | - | - | - | - | Yes |

---

## 3. System Configuration

### 3.1 Configuration Files

| File | Purpose | Access |
|------|---------|--------|
| `/etc/ostrich-pki/config.yaml` | Main configuration | Administrator |
| `/etc/ostrich-pki/ca-policy.yaml` | Certificate policies | AOR |
| `/etc/ostrich-pki/profiles/*.yaml` | Certificate profiles | Administrator |
| `/etc/ostrich-pki/hsm.yaml` | HSM configuration | Administrator |

### 3.2 Main Configuration

```yaml
# /etc/ostrich-pki/config.yaml

# Service configuration
service:
  name: "OstrichPKI CA"
  environment: production
  log_level: info

# Database configuration
database:
  host: localhost
  port: 5432
  name: ostrich_pki
  ssl_mode: require
  max_connections: 50

# HSM configuration
hsm:
  provider: pkcs11
  library_path: /usr/lib/softhsm/libsofthsm2.so
  slot: 0
  # PIN stored in environment variable OSTRICH_HSM_PIN

# TLS configuration
tls:
  min_version: "1.3"
  cert_path: /etc/ostrich-pki/tls/server.crt
  key_path: /etc/ostrich-pki/tls/server.key
  client_ca_path: /etc/ostrich-pki/tls/client-ca.crt
  require_client_cert: true

# Audit configuration
audit:
  storage_path: /var/log/ostrich-pki/audit
  max_size_gb: 100
  retention_days: 365
  alert_threshold_percent: 80

# Time synchronization
time:
  ntp_servers:
    - ntp1.example.com
    - ntp2.example.com
  max_drift_seconds: 5
```

### 3.3 Modifying Configuration

**Warning:** Configuration changes require service restart and are audited.

```bash
# Validate configuration before applying
ostrich-admin config validate --file /etc/ostrich-pki/config.yaml

# Apply configuration (requires restart)
sudo systemctl restart ostrich-ca

# View current configuration
ostrich-admin config show

# View configuration history
ostrich-admin config history
```

### 3.4 Certificate Profiles

Certificate profiles define the content and constraints for issued certificates.

```yaml
# /etc/ostrich-pki/profiles/tls-server.yaml

name: TLS Server Certificate
description: Standard TLS server certificate for web servers

# Validity
validity:
  max_days: 398  # Per CA/B Forum baseline requirements
  default_days: 365

# Key constraints
key_constraints:
  algorithms:
    - rsa:2048
    - rsa:3072
    - rsa:4096
    - ecdsa:p256
    - ecdsa:p384
  min_rsa_bits: 2048
  min_ec_bits: 256

# Extensions
extensions:
  key_usage:
    critical: true
    values:
      - digitalSignature
      - keyEncipherment

  extended_key_usage:
    critical: false
    values:
      - serverAuth

  basic_constraints:
    critical: true
    ca: false

  subject_alt_name:
    required: true
    allowed_types:
      - dnsName
      - ipAddress

# Subject DN requirements
subject:
  required_fields:
    - commonName
  optional_fields:
    - organizationName
    - countryName
  max_cn_length: 64
```

### 3.5 Secure Defaults

**Warning:** The following settings must not be modified to maintain security compliance:

| Setting | Required Value | Reason |
|---------|---------------|--------|
| `tls.min_version` | "1.3" | NIAP PP-CA requirement |
| `tls.require_client_cert` | true | mTLS required for admin access |
| `key_constraints.min_rsa_bits` | 2048 | NIST minimum |
| `audit.retention_days` | >= 365 | Compliance requirement |
| `CA_GRPC_INSECURE_DEV_PLAINTEXT` (ca-server) | unset / `false` | Release builds refuse it; never set it in a deployment |
| `CA_GRPC_INSECURE` (acme-server, est-server) | unset / `false` | Release builds refuse plaintext gRPC to the CA |

### 3.6 CA gRPC Issuance Channel (mTLS)

*Added 2026-10-25 (branch `claude/grpc-mtls`, uncommitted). NIST 800-53:
AC-3, AC-6, AC-17, IA-3, IA-5(2), SC-8, SC-12, SC-13, CM-6. NIAP PP-CA:
FTP_ITC.1, FCS_TLSS_EXT.2, FCS_TLSC_EXT.2, FIA_X509_EXT.1, FDP_ACF.1.*

The RA front ends (acme-server, est-server) call the CA issuance API over gRPC
(port 50051). ca-server serves it only over TLS 1.3 with mandatory client
certificates and refuses to start without that configuration. The full
procedure, exact error messages and verification steps are in the runbook
[docs/runbooks/ca-grpc-mtls.md](../runbooks/ca-grpc-mtls.md).

**1. Dedicated service-identity CA (required).** Before the first install,
create or choose a CA (normally an offline intermediate with `pathlen:0`) that
issues **only** the gRPC service certificates: ca-server's gRPC server
certificate, the acme-server and est-server client certificates, and the
operator (Admin) client certificates. It must not
be the CA that this ca-server operates, and it must not issue certificates to
subscribers, devices or users. Record it and its owner in the system inventory
(CM-8).

- Why: the role lists match the client subject DN only. If the client trust
  anchor also issues subscriber certificates, anyone who can enroll for
  `CN=est-server` gets past both the handshake and the role lookup and holds
  the Issuer role.
- What ca-server checks: after it loads the CA, it walks the issuing CA's
  ancestors in the CA database and refuses to start the listener if a
  client-CA anchor has the issuing certificate's public key or subject, was
  issued by the issuing CA, is its issuer, or matches a database ancestor. The
  refusal is written as a `grpc_listener_refused` audit record. It warns if the
  file holds more than one anchor, and refuses to start with more than one
  distinct anchor when the admin list is non-empty. Per call, it denies client certificates
  issued directly by the issuing CA or an ancestor
  (`reason=subscriber_issuing_ca`). It cannot detect sibling subordinate CAs,
  CAs issued by a subordinate of this CA, or roots outside its database
  lineage; keeping those out is your responsibility (POAM-2026-10-23-28).
- Audit signing: ca-server signs audit records with the CA key and does not
  support an SLH-DSA CA key (it will not start; POAM-2026-10-23-34). Audit
  writes fail closed on timeout; alert on the log field
  `alert="audit_write_failed"` (see the runbook section "Operations: audit
  write failures").
- Signatures: sign with ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 or RSA-PSS.
  RSA PKCS#1 v1.5 (the OpenSSL default for RSA) and curve/hash mismatches are
  refused at the handshake.

**2. Bootstrap.** ca-server cannot issue its own gRPC certificates, so the
service-identity CA must exist before the first install (POAM-2026-10-23-29).
Issue the three certificates from it (client certificates with an
extendedKeyUsage extension that includes `clientAuth`; the server certificate
with `serverAuth` and a SAN for the host the clients dial).

**3. Secrets.** Store keys and certificates as Kubernetes secrets (or files
readable only by the service user), never as environment values; the
`CA_GRPC_*` variables carry file paths only.

| Secret (Helm value) | Keys | Mounted at |
|---|---|---|
| `ca.grpc.tls.existingSecret` | `tls.crt` (server chain), `tls.key`, `client-ca.crt` (service-identity CA only) | `/app/grpc-tls` |
| `acme.caGrpc.clientTls.existingSecret` | `tls.crt`, `tls.key`, `ca.crt` | `/app/ca-grpc-client` |
| `est.caGrpc.clientTls.existingSecret` | `tls.crt`, `tls.key`, `ca.crt` | `/app/ca-grpc-client` |

The chart refuses to render without these secrets. Delete private keys from
workstations after creating the secrets. For compose, use per-service
directories outside `./certs` (`CA_GRPC_TLS_DIR`, `ACME_CA_GRPC_CLIENT_DIR`,
`EST_CA_GRPC_CLIENT_DIR`); `make dev-grpc-certs` writes DEV ONLY material to
`.dev-grpc-certs/` and must never be used for a persistent environment.

**4. Roles and methods.** Three `;`-separated lists of RFC 4514 subject DNs
(Helm takes lists) give each client certificate subject exactly one role:

| Variable (Helm `ca.grpc.*`) | Role, requestor namespace | RPCs | Deployment default |
|---|---|---|---|
| `CA_GRPC_ACME_CLIENT_SUBJECTS` (`acmeClientSubjects`) | Issuer, `acme::` | IssueCertificate, GetCaInfo, ListProfiles | `CN=acme-server` |
| `CA_GRPC_EST_CLIENT_SUBJECTS` (`estClientSubjects`) | Issuer, `est::` | IssueCertificate, GetCaInfo, ListProfiles | `CN=est-server` |
| `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (`adminClientSubjects`) | Admin (CA Operations Staff), `admin::` | RevokeCertificate, GenerateCrl, CheckRevocationStatus, GetCaInfo, ListProfiles; never IssueCertificate | **empty** |

- Any other RPC, including RPCs added later, is denied (`PERMISSION_DENIED`,
  audited). An RA service cannot revoke or generate CRLs over gRPC.
- Matching is exact and case-sensitive on the RFC 4514 form, most specific RDN
  first (as printed by `openssl x509 -noout -subject -nameopt RFC2253`).
- A subject may be in one list only (also no case variants across lists).
  ca-server refuses to start if the ACME and EST lists are both empty, if an
  entry cannot be parsed, or if the removed `CA_GRPC_ALLOWED_CLIENT_SUBJECTS`
  (Helm `ca.grpc.allowedClientSubjects`) is still set; see the runbook
  section "Upgrade from the single allowlist (PR #183)".
- **Issuable profiles.** `CA_GRPC_ACME_ALLOWED_PROFILES` (default
  `acme-default`) and `CA_GRPC_EST_ALLOWED_PROFILES` (default
  `tls_client;tls_server;tls_server_client;efs`) limit which end-entity
  profiles each namespace may request. CA profiles are never allowed; an
  unknown or CA profile, or an empty list for a namespace with subjects,
  refuses startup. If est-server issues another profile (`EST_ENROLL_PROFILE`
  or a per-user profile), add it before you upgrade.
- **Requestor.** acme-server and est-server already send `acme::<id>` /
  `est::<id>`; the CA refuses other namespaces, non-printable-ASCII ids and
  values over 255 bytes. EST usernames must therefore be 1-250 printable
  ASCII characters (est-server returns HTTP 403 otherwise). The audit actor is
  the client certificate subject; the requestor is recorded as
  `on_behalf_of`.
- **Admin identities.** Issue one short-lived admin certificate per named CA
  Operations Staff operator (for example `CN=ops-alice`); shared admin
  certificates are prohibited, because the certificate subject is the audit
  actor. Admin certificates must be issued **directly** by the single
  service-identity CA in `client-ca.crt` (issuer DN and authorityKeyIdentifier
  matching that CA's subject and subjectKeyIdentifier), not by an
  intermediate; that CA must carry a subjectKeyIdentifier. The chart and the
  kustomize NetworkPolicy admit only acme/est pods to the gRPC port, so
  operators connect with `kubectl port-forward` (needs RBAC `create` on
  `pods/portforward`) or through a NetworkPolicy you add. Authorized
  `CheckRevocationStatus` calls are not audited (reads); revocations and CRL
  generations are.
- Changes take effect at restart. Treat every role-list or profile-list
  change as a CM-3 change; the start-up audit record `grpc_listener_started`
  records the effective `clients`, `method_rules` and `issuer_profiles`.

**5. Revoking a service identity.** Revocation is not checked on this channel
(POAM-2026-10-23-27). To lock out a compromised client at once, remove its
subject from its role list and restart ca-server, then reissue under a **new**
subject, or rotate the service-identity CA and remove the old anchor. While
the admin list is non-empty, ca-server will not start with two anchors, so
empty the admin list for the duration of a CA rotation.

**6. Upgrade.** Stop all audit writers before starting a version that changes
audit-chain locking, then verify the chain (see runbook "Upgrade note").

**7. Monitoring.** Review `access_denied`, `tls_handshake_failed` and their
`*_suppressed` summary records (Section 6.2). A burst of
`per_source_handshake_limit` or `handshake_timeout` reasons indicates scanning
or a stuck client.

### 3.7 ACME dns-01 Resolvers

acme-server validates dns-01 challenges by looking up the TXT record at
`_acme-challenge.<domain>.` (RFC 8555 §8.4). Since 2026-10-26 the resolvers
it uses are a deployment setting (NIST 800-53 CM-6):

| Setting | Default | Values |
|---------|---------|--------|
| `ACME_DNS01_RESOLVERS` / `--dns01-resolvers` | unset: the host's system resolver configuration (`/etc/resolv.conf`; in Kubernetes, cluster DNS) | Comma-separated IPv4 / IPv6 literals, no spaces, at most 8. Port 53, UDP with TCP fallback. `""` is the same as unset |
| Helm `acme.dns01Resolvers` | `[]` | A YAML list of plain IP literals, at most 8. A non-empty list is passed as `ACME_DNS01_RESOLVERS` and, when `networkPolicy.enabled`, opens UDP and TCP 53 egress to exactly these addresses |

No public third-party resolver is ever used implicitly.

**Production guidance.**

1. Point the setting at the enclave's **DNSSEC-validating recursive
   resolver(s)**. acme-server does not validate DNSSEC itself and does not
   check the AD bit; DNSSEC protection of dns-01 relies on that resolver
   (Security Target A.DNS_RESOLVER / OE.DNS_RESOLVER; POAM-2026-10-23-41).
2. Place the resolver on a **trusted network segment**. The acme-server to
   resolver traffic is plain DNS (no TSIG or DoT) and is not authenticated.
3. **Cap the resolver's negative-cache TTL** (RFC 2308), for example unbound
   `cache-max-negative-ttl: 5`. acme-server makes up to 5 lookup rounds, 2 s
   apart, when a lookup fails or does not match, with its own caching
   disabled; a long
   negative-cache TTL on the resolver can replay an NXDOMAIN cached before the
   subscriber's TXT record was published.
4. Use IPv4 literals, not IPv4-mapped IPv6 (`::ffff:10.0.0.53`), so the
   NetworkPolicy matches the traffic. The chart refuses mapped entries.

**Refusals.** acme-server refuses to start if an entry is not an IP literal,
is unspecified (`0.0.0.0`, `::`), multicast or broadcast, is listed twice
(also after IPv4-mapped canonicalisation), if there are more than 8 entries,
or if the list has spaces or empty items. `helm install` / `helm template`
fail earlier for a value that is not a list, more than 8 entries, a
duplicate, an entry that is not a plain IP literal, or an IPv4-mapped entry.
If the variable is unset and the host has
no name servers, acme-server starts with a warning
(`dns-01 validation will fail closed: no system name servers`) and every
dns-01 challenge becomes invalid.

**Verification.** At startup acme-server logs `dns-01 resolver configuration`
with `source = "configured"` (and the resolver addresses) or
`source = "system"` (and the number of name servers). Changes take effect at
restart; treat them as CM-3 changes.

**Subscriber-visible behaviour (2026-10-26).** dns-01 identifiers must be
plain DNS names without a trailing dot. A stale or missing TXT record is retried for about 8 s
before the challenge becomes invalid. TXT records at names other than the
challenge name or its CNAME target are ignored, and a record's strings are
joined before comparison. Challenge errors now carry RFC 8555 types such as
`dns`, `incorrectResponse`, `connection`, `tls`, `rejectedIdentifier`,
`malformed` or `serverInternal` instead of `unauthorized`, with a generic
detail; the full cause is in the acme-server log.

**Order identifiers (2026-10-26, wildcard-identifier change, not yet
released).** acme-server checks every identifier in a newOrder before it
stores anything:

- Wildcard orders are supported. `*.example.com` is authorized for
  `example.com` by **dns-01 only** (TXT at `_acme-challenge.example.com.`).
  Only one leftmost `*.` label is accepted, and not over a single-label base
  (`*.com`); other forms are refused with `rejectedIdentifier`.
- IP identifiers (type `ip`, canonical text such as `192.0.2.1` or
  `2001:db8::1`) are validated by **http-01 only**. tls-alpn-01 for IP
  identifiers is withheld until its RFC 8738 §6 checks exist
  (POAM-2026-10-23-52), and dns-01 is never used for them. IPv4-mapped IPv6
  addresses (`::ffff:192.0.2.1`) are refused; use the IPv4 address.
- An order may hold at most 100 identifiers; duplicates and malformed names
  are refused with `malformed`, unknown identifier types with
  `unsupportedIdentifier`.
- **No issuance-name policy yet (POAM-2026-10-23-55).** acme-server does not
  check the Public Suffix List and has no deny list, so `*.co.uk`,
  single-label names such as `localhost` and reserved names such as `.test`
  or `.internal` are accepted at newOrder; issuance then depends only on the
  challenge. Restrict which names can pass a challenge at the network and DNS
  level until this item is closed.
- Authorizations and orders created before the upgrade for a `*.` name, or an
  IP authorization proven by tls-alpn-01 or dns-01, cannot be used to
  finalize; they expire within 7 days and the client must place a new order.
- Each created order and each refused newOrder or finalize request writes an
  `ostrich-audit` record (actor = ACME account id). Source IP and request id
  are not in these records. If the audit sink fails, the error is logged and
  the request still proceeds, so monitor acme-server logs for
  `failed to record ACME audit event`.

**Not provided:** CAA checking (RFC 8659) and multi-perspective validation
(POAM-2026-10-23-41).

---

## 4. Certificate Lifecycle Operations

### 4.1 Certificate Issuance

**Role Required:** Operations Staff

#### Via ACME (Automated)

```bash
# ACME clients automatically obtain certificates
# No manual intervention required

# View pending ACME orders
ostrich-admin acme orders list --status pending

# View issued certificates
ostrich-admin acme orders list --status valid
```

#### Via EST (Enrollment over Secure Transport)

```bash
# EST enrollment requires mTLS client certificate
# Clients submit CSR via EST protocol

# View pending EST enrollments
ostrich-admin est enrollments list --status pending
```

#### Manual Issuance (CA CLI)

```bash
# Issue certificate from CSR file
ostrich-admin cert issue \
  --csr /path/to/request.csr \
  --profile tls-server \
  --validity-days 365 \
  --output /path/to/certificate.pem

# Issue certificate with SAN
ostrich-admin cert issue \
  --csr /path/to/request.csr \
  --profile tls-server \
  --san "DNS:www.example.com,DNS:example.com" \
  --output /path/to/certificate.pem
```

### 4.2 Certificate Revocation

**Role Required:** Operations Staff

```bash
# Revoke by serial number
ostrich-admin cert revoke \
  --serial <serial_number> \
  --reason keyCompromise \
  --comment "Private key compromised"

# Revoke by certificate file
ostrich-admin cert revoke \
  --cert /path/to/certificate.pem \
  --reason superseded

# Available revocation reasons:
# - unspecified
# - keyCompromise
# - cACompromise
# - affiliationChanged
# - superseded
# - cessationOfOperation
# - certificateHold
```

### 4.3 CRL Generation

**Role Required:** Operations Staff

```bash
# Generate new CRL
ostrich-admin crl generate

# View CRL information
ostrich-admin crl info

# List revoked certificates in current CRL
ostrich-admin crl list

# CRL is automatically published to distribution points
```

### 4.4 Certificate Search and Export

```bash
# Search certificates by subject
ostrich-admin cert search --subject "CN=example.com"

# Search by serial number
ostrich-admin cert search --serial <serial_number>

# Export certificate
ostrich-admin cert export --serial <serial_number> --format pem

# List all active certificates
ostrich-admin cert list --status valid
```

---

## 5. Key Management

### 5.1 CA Key Operations

**Role Required:** Administrator

**Warning:** CA key operations are security-critical and fully audited.

#### View CA Key Information

```bash
# List CA keys
ostrich-admin key list

# View key details (public key only)
ostrich-admin key info --key-id <key_id>

# Key information includes:
# - Algorithm (RSA, ECDSA, EdDSA, ML-DSA)
# - Key size
# - Creation date
# - Usage statistics
```

#### Generate New CA Key

```bash
# Generate new CA signing key (stored in HSM)
ostrich-admin key generate \
  --algorithm ecdsa-p384 \
  --label "CA-Signing-Key-2026" \
  --usage sign

# For post-quantum:
ostrich-admin key generate \
  --algorithm ml-dsa-65 \
  --label "CA-Signing-Key-PQ-2026" \
  --usage sign
```

#### Key Backup (KRA Integration)

```bash
# Initiate key backup (escrow)
# Requires M-of-N key recovery agents
ostrich-admin key backup \
  --key-id <key_id> \
  --agents agent1,agent2,agent3 \
  --threshold 2

# Key is split using Shamir Secret Sharing
# Each agent receives one share
```

#### Key Recovery

```bash
# Initiate key recovery request
ostrich-admin key recover \
  --key-id <key_id> \
  --reason "HSM failure"

# Agents submit their shares
ostrich-admin key recover-submit \
  --request-id <request_id> \
  --agent <agent_name> \
  --share <share_data>

# After threshold shares submitted, key is recovered
```

### 5.2 HSM Operations

```bash
# Check HSM status
ostrich-admin hsm status

# List objects in HSM
ostrich-admin hsm list-objects

# HSM session information
ostrich-admin hsm session-info
```

---

## 6. Audit Log Management

### 6.1 Audit Log Access

**Role Required:** Auditor or Administrator

```bash
# View recent audit events
ostrich-admin audit list --limit 100

# Filter by event type
ostrich-admin audit list --type CertificateIssued

# Filter by actor
ostrich-admin audit list --actor "admin@example.com"

# Filter by time range
ostrich-admin audit list \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z"

# Filter by outcome
ostrich-admin audit list --outcome failure
```

### 6.2 Audit Event Types

| Event Type | Description |
|------------|-------------|
| `ServiceStartup` | Service started |
| `ServiceShutdown` | Service stopped |
| `AuthenticationSuccess` | Successful authentication |
| `AuthenticationFailure` | Failed authentication attempt |
| `CertificateIssued` | Certificate was issued |
| `CertificateRevoked` | Certificate was revoked |
| `CrlGenerated` | CRL was generated |
| `KeyGenerated` | CA key was generated |
| `KeyBackupInitiated` | Key backup started |
| `KeyRecovered` | Key was recovered |
| `ConfigurationChanged` | Configuration modified |
| `UserCreated` | User account created |
| `UserDeleted` | User account deleted |
| `RoleAssigned` | Role assigned to user |
| `RoleRemoved` | Role removed from user |
| `SelfTestCompleted` | Self-test executed |
| `SelfTestFailed` | Self-test failed |

### 6.3 Audit Log Export

**Role Required:** Auditor

```bash
# Export audit logs to file
ostrich-admin audit export \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z" \
  --format json \
  --output /path/to/audit-export.json

# Export with signature for integrity verification
ostrich-admin audit export \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z" \
  --format json \
  --sign \
  --output /path/to/audit-export.json
```

### 6.4 Audit Log Integrity Verification

```bash
# Verify audit log hash chain integrity
ostrich-admin audit verify

# Output:
# Audit log integrity: VERIFIED
# Records checked: 15,234
# Hash chain valid: Yes
# First record: 2026-01-01T00:00:00Z
# Last record: 2026-01-04T15:30:00Z
```

### 6.5 Audit Storage Management

```bash
# Check audit storage usage
ostrich-admin audit storage

# Output:
# Storage used: 45.2 GB / 100 GB (45.2%)
# Records: 1,234,567
# Oldest record: 2025-01-15T00:00:00Z
# Alert threshold: 80%

# Archive old audit logs (preserves integrity)
ostrich-admin audit archive \
  --before "2025-12-31T23:59:59Z" \
  --destination /archive/audit/
```

---

## 7. User Management

### 7.1 User Account Operations

**Role Required:** Administrator

```bash
# Create new user
ostrich-admin user create \
  --username jsmith \
  --email jsmith@example.com \
  --full-name "John Smith"

# User receives enrollment invitation via email
# Must complete mTLS certificate enrollment

# List all users
ostrich-admin user list

# View user details
ostrich-admin user info --username jsmith

# Disable user account
ostrich-admin user disable --username jsmith

# Enable user account
ostrich-admin user enable --username jsmith

# Delete user account
ostrich-admin user delete --username jsmith
```

### 7.2 User Certificate Enrollment

```bash
# Generate enrollment invitation
ostrich-admin user enroll --username jsmith

# User receives:
# - Enrollment URL
# - One-time enrollment code
# - Instructions for certificate request

# Check enrollment status
ostrich-admin user enrollment-status --username jsmith
```

### 7.3 Account Lockout

```bash
# View locked accounts
ostrich-admin user list --locked

# Unlock account (after failed authentication lockout)
ostrich-admin user unlock --username jsmith

# Lockout settings are in configuration:
# max_failures: 5
# lockout_duration: 15m
```

---

## 8. Security Monitoring

### 8.1 Health Checks

```bash
# Check overall system health
ostrich-admin health

# Output:
# Service Status: HEALTHY
# HSM: Connected
# Database: Connected
# Time Sync: OK (drift: 0.3s)
# Audit Storage: OK (45.2%)
# Self-Tests: PASS
```

### 8.2 Self-Tests

**Role Required:** Administrator

```bash
# Run self-tests on demand
ostrich-admin self-test run

# Output:
# Cryptographic KAT (RSA): PASS
# Cryptographic KAT (ECDSA): PASS
# Cryptographic KAT (SHA-256): PASS
# DRBG Health Test: PASS
# HSM Connectivity: PASS
# Database Connectivity: PASS
# Time Source Verification: PASS
# Overall: PASS

# View self-test history
ostrich-admin self-test history
```

### 8.3 Security Alerts

```bash
# View active security alerts
ostrich-admin alerts list

# Alert types:
# - HIGH: Self-test failure, HSM disconnection
# - MEDIUM: Authentication failures, certificate expiration
# - LOW: Configuration changes, high audit storage

# Acknowledge alert
ostrich-admin alerts acknowledge --id <alert_id>
```

### 8.4 Metrics and Monitoring

```bash
# Prometheus metrics endpoint
curl https://ca.example.com:9090/metrics

# Key metrics:
# ostrich_certificates_issued_total
# ostrich_certificates_revoked_total
# ostrich_authentication_failures_total
# ostrich_hsm_operations_total
# ostrich_audit_storage_bytes
# ostrich_self_test_last_result
```

---

## 9. Backup and Recovery

### 9.1 Database Backup

**Role Required:** Administrator

```bash
# Create database backup
ostrich-admin backup create \
  --type database \
  --destination /backup/ostrich-pki/

# Backup includes:
# - Certificate database
# - Revocation information
# - User accounts and roles
# - Configuration (encrypted)
# - Audit log references

# List available backups
ostrich-admin backup list

# Verify backup integrity
ostrich-admin backup verify --backup-id <backup_id>
```

### 9.2 CA Key Backup

See [Section 5.1 - Key Backup](#key-backup-kra-integration)

**Warning:** CA private keys are backed up through the KRA service using Shamir Secret Sharing. Direct key export is not supported.

### 9.3 Disaster Recovery

```bash
# Recovery procedure:
# 1. Install OstrichPKI on new system
# 2. Restore database backup
ostrich-admin backup restore \
  --backup-id <backup_id> \
  --type database

# 3. Initialize HSM on new system
# 4. Recover CA key using KRA shares
ostrich-admin key recover --key-id <key_id>

# 5. Verify system health
ostrich-admin health

# 6. Run self-tests
ostrich-admin self-test run
```

### 9.4 Backup Schedule

| Backup Type | Frequency | Retention |
|-------------|-----------|-----------|
| Database (full) | Daily | 30 days |
| Database (incremental) | Hourly | 7 days |
| Configuration | On change | 90 days |
| Audit logs | Monthly archive | 7 years |

---

## 10. Troubleshooting

### 10.1 Common Issues

#### HSM Connection Failed

```bash
# Check HSM status
ostrich-admin hsm status

# Common causes:
# - HSM library path incorrect
# - HSM slot not initialized
# - PIN incorrect (check OSTRICH_HSM_PIN env var)
# - HSM hardware failure

# Restart HSM service
sudo systemctl restart softhsm2
```

#### Database Connection Failed

```bash
# Check database connectivity
ostrich-admin db status

# Common causes:
# - PostgreSQL not running
# - Network connectivity
# - SSL certificate issues
# - Connection pool exhausted

# Check PostgreSQL logs
sudo journalctl -u postgresql
```

#### Time Synchronization Failed

```bash
# Check time sync status
ostrich-admin time status

# Common causes:
# - NTP servers unreachable
# - Time drift exceeds threshold
# - Firewall blocking NTP

# Force time sync
sudo ntpdate -u ntp1.example.com
```

#### Self-Test Failure

```bash
# View self-test results
ostrich-admin self-test history --limit 10

# If cryptographic KAT fails:
# - HSM may be in error state
# - Restart HSM and retry
# - Contact vendor if persists

# Service will not start if self-tests fail
```

### 10.2 Log Files

| Log File | Purpose |
|----------|---------|
| `/var/log/ostrich-pki/ca.log` | CA service logs |
| `/var/log/ostrich-pki/acme.log` | ACME service logs |
| `/var/log/ostrich-pki/est.log` | EST service logs |
| `/var/log/ostrich-pki/ocsp.log` | OCSP service logs |
| `/var/log/ostrich-pki/audit/` | Audit logs |

```bash
# View recent CA logs
sudo journalctl -u ostrich-ca -f

# Search logs for errors
grep -i error /var/log/ostrich-pki/ca.log
```

### 10.3 Support

For issues not covered in this guide:

1. Check documentation at https://docs.ostrich-pki.io
2. Search issues at https://github.com/ostrich-pki/issues
3. Contact support with:
   - OstrichPKI version (`ostrich-admin version`)
   - Error messages and logs
   - Steps to reproduce

---

## Appendix A: Quick Reference

### Common Commands

```bash
# Certificate operations
ostrich-admin cert issue --csr <file> --profile <profile>
ostrich-admin cert revoke --serial <serial> --reason <reason>
ostrich-admin cert search --subject <subject>

# CRL operations
ostrich-admin crl generate
ostrich-admin crl info

# User operations
ostrich-admin user create --username <user>
ostrich-admin user add-role --user <user> --role <role>
ostrich-admin user list

# Audit operations
ostrich-admin audit list --limit 100
ostrich-admin audit export --from <date> --to <date>
ostrich-admin audit verify

# System operations
ostrich-admin health
ostrich-admin self-test run
ostrich-admin backup create
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OSTRICH_HSM_PIN` | HSM user PIN |
| `OSTRICH_DB_PASSWORD` | Database password |
| `OSTRICH_CONFIG_PATH` | Configuration file path |
| `OSTRICH_LOG_LEVEL` | Logging level (debug, info, warn, error) |
| `CA_GRPC_TLS_CERT_FILE`, `CA_GRPC_TLS_KEY_FILE`, `CA_GRPC_TLS_CLIENT_CA_FILE` | ca-server gRPC server chain, key and client trust anchor (file paths; Section 3.6) |
| `CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS`, `CA_GRPC_ADMIN_CLIENT_SUBJECTS` | ca-server: `;`-separated client subject DNs per role (Issuer ACME, Issuer EST, Admin; Section 3.6) |
| `CA_GRPC_ACME_ALLOWED_PROFILES`, `CA_GRPC_EST_ALLOWED_PROFILES` | ca-server: `;`-separated end-entity profiles each issuer namespace may request |
| `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` | removed; ca-server refuses to start if it is set |
| `CA_GRPC_CLIENT_CERT_FILE`, `CA_GRPC_CLIENT_KEY_FILE`, `CA_GRPC_CA_CERT_FILE` | acme-server / est-server gRPC client certificate, key and CA trust anchor |
| `CA_GRPC_SERVER_NAME` | acme-server / est-server: TLS server name override (default: the URL host) |
| `ACME_DNS01_RESOLVERS` | acme-server: comma-separated dns-01 recursive resolver IP literals, at most 8; unset or `""` uses the system resolver configuration (Section 3.7) |

---

## Appendix B: NIAP Compliance Procedures

This appendix documents specific procedures required for NIAP PP-CA v2.1 compliance.

### B.1 Role Separation Enforcement (FMT_SMR.2)

**Requirement:** Security roles must be separated to prevent conflicts of interest.

**Prohibited Role Combinations:**

| Role 1 | Role 2 | Reason |
|--------|--------|--------|
| Administrator | Operations Staff | Configuration vs. operations separation |
| Auditor | Operations Staff | Audit independence |
| AOR | Operations Staff | Policy vs. execution separation |

**Verification Procedure:**

```bash
# Check for role conflicts
ostrich-admin user audit-roles

# Output shows any users with conflicting roles
# Users with Role Conflicts:
# - jsmith: administrator + operations (CONFLICT)
```

**Remediation:**

```bash
# Remove conflicting role
ostrich-admin user remove-role --user jsmith --role operations
```

### B.2 Security Function Authorization (FMT_MOF.1)

**Requirement:** All security functions must be protected by authorization checks.

**Security Function Matrix:**

| Function | Endpoint | Required Role | Audit Event |
|----------|----------|---------------|-------------|
| Issue Certificate | `POST /api/ca/certificates` | Operations Staff | CertificateIssued |
| Revoke Certificate | `POST /api/ca/revoke` | Operations Staff | CertificateRevoked |
| Generate CRL | `POST /api/ca/crl/generate` | Operations Staff | CrlGenerated |
| View Audit Logs | `GET /api/audit/events` | Auditor, Admin | AuditAccessed |
| Change Configuration | `PUT /api/admin/config` | Administrator | ConfigurationChanged |
| Manage Users | `POST /api/admin/users` | Administrator | UserCreated |
| Backup CA Key | `POST /api/admin/key/backup` | Administrator | KeyBackupInitiated |
| Modify Policy | `PUT /api/admin/policy` | AOR | PolicyModified |

**Verification Procedure:**

```bash
# Test authorization enforcement
ostrich-admin security verify-authorization

# Expected output:
# Authorization Matrix Verification
# ================================
# Issue Certificate: PROTECTED (Operations Staff only)
# Revoke Certificate: PROTECTED (Operations Staff only)
# View Audit Logs: PROTECTED (Auditor, Administrator only)
# ...
# All security functions properly protected: YES
```

### B.3 Self-Test Procedures (FPT_TST_EXT.1)

**Requirement:** The TOE must perform self-tests at startup and on administrator demand.

**Startup Self-Tests:**

1. Cryptographic KAT (Known Answer Tests)
2. DRBG health tests
3. HSM connectivity
4. Database connectivity
5. Time synchronization verification

**On-Demand Self-Tests:**

```bash
# Run complete self-test suite
ostrich-admin self-test run --full

# Output:
# ============================================
# OstrichPKI Self-Test Results
# Test Time: 2026-01-04T15:30:00Z
# ============================================
#
# Cryptographic Tests:
#   RSA-2048 Sign/Verify KAT: PASS (3ms)
#   RSA-3072 Sign/Verify KAT: PASS (5ms)
#   ECDSA P-256 Sign/Verify KAT: PASS (2ms)
#   ECDSA P-384 Sign/Verify KAT: PASS (2ms)
#   SHA-256 KAT: PASS (1ms)
#   SHA-384 KAT: PASS (1ms)
#   AES-256-GCM KAT: PASS (1ms)
#   HMAC-SHA-256 KAT: PASS (1ms)
#
# DRBG Health Tests:
#   Startup Health Test: PASS
#   Continuous Health Test: PASS
#   Entropy Source Validation: PASS
#
# System Tests:
#   HSM Connectivity: PASS (session established)
#   Database Connectivity: PASS (query successful)
#   Time Synchronization: PASS (drift: 0.2s)
#   Audit System: PASS (write successful)
#
# ============================================
# Overall Result: PASS
# All 15 tests passed
# ============================================
```

**Self-Test Failure Handling:**

If any self-test fails:

1. Service enters maintenance mode
2. All CA operations are blocked
3. Alert sent to administrators
4. Audit event recorded (if possible)

```bash
# Check self-test status after failure
ostrich-admin self-test status

# If failed:
# Self-Test Status: FAILED
# Failed Tests: ECDSA P-256 KAT
# Service Mode: MAINTENANCE
# CA Operations: BLOCKED
```

### B.4 Audit Overflow Handling (FAU_STG.4)

**Requirement:** The TOE must prevent auditable events when audit storage is full.

**Storage Monitoring:**

```bash
# Check audit storage status
ostrich-admin audit storage

# Output:
# Audit Storage Status
# ====================
# Total Capacity: 100 GB
# Used: 45.2 GB (45.2%)
# Available: 54.8 GB
# Alert Threshold: 80%
# Status: NORMAL
```

**Alert Thresholds:**

| Threshold | Action |
|-----------|--------|
| 80% | Warning alert to administrators |
| 90% | Critical alert, prepare archival |
| 95% | Emergency alert, archive required |
| 100% | Operations blocked, audit preserved |

**When Storage Reaches 100%:**

1. All CA operations are blocked
2. Error returned: "Audit storage exhausted"
3. Only audit archival operations permitted
4. Administrator must archive old logs

**Archival Procedure:**

```bash
# Archive old audit logs to external storage
ostrich-admin audit archive \
  --before "2025-12-31T23:59:59Z" \
  --destination /archive/audit/2025/ \
  --verify

# After archival, verify storage freed
ostrich-admin audit storage

# Resume operations (automatic when storage < 95%)
```

### B.5 Session Timeout Configuration (FTA_SSL.1)

**Requirement:** Sessions must be terminated after configurable inactivity period.

**Default Configuration:**

| Setting | Default | Range |
|---------|---------|-------|
| Session Timeout | 15 minutes | 5-60 minutes |
| Maximum Session Duration | 8 hours | 1-24 hours |
| Session Lock Timeout | 5 minutes | 1-30 minutes |

**Configuration:**

```yaml
# /etc/ostrich-pki/config.yaml
session:
  idle_timeout_minutes: 15
  max_duration_hours: 8
  lock_timeout_minutes: 5
  require_reauthentication: true
```

**Session Management Commands:**

```bash
# View active sessions
ostrich-admin session list

# Terminate specific session
ostrich-admin session terminate --session-id <uuid>

# Terminate all sessions for user
ostrich-admin session terminate-user --username jsmith

# View session configuration
ostrich-admin session config
```

---

## Appendix C: Operational Environment Checklist

Complete this checklist before placing OstrichPKI into production:

### C.1 Hardware Security

- [ ] HSM is FIPS 140-2 Level 2 or higher validated
- [ ] HSM is physically secured in locked cabinet
- [ ] Server is in access-controlled facility
- [ ] Tamper-evident seals applied (if required)

### C.2 Network Security

- [ ] Firewall configured per Section 11.2 (SECURITY_TARGET.md)
- [ ] Admin interfaces on internal network only
- [ ] TLS 1.3 enforced for all connections
- [ ] Network monitoring enabled

### C.3 Time Synchronization

- [ ] NTP configured with at least 2 servers
- [ ] NTP servers authenticated (if available)
- [ ] Time drift alert configured (<5 seconds)

### C.4 Backup Configuration

- [ ] Database backup schedule configured
- [ ] Backup encryption enabled
- [ ] Backup verification tested
- [ ] Offsite backup storage configured

### C.5 Monitoring and Alerting

- [ ] Audit storage alerts configured
- [ ] Self-test failure alerts configured
- [ ] Authentication failure alerts configured
- [ ] HSM connectivity alerts configured

### C.6 Access Control

- [ ] Initial administrator created
- [ ] Role separation verified
- [ ] No conflicting role assignments
- [ ] mTLS certificates deployed
- [ ] CA gRPC client trust anchor is a dedicated service-identity CA (Section 3.6), not the CA's issuing CA or any subscriber-issuing CA
- [ ] `CA_GRPC_ACME_CLIENT_SUBJECTS` / `CA_GRPC_EST_CLIENT_SUBJECTS` list only the RA services; `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` is unset
- [ ] `CA_GRPC_ADMIN_CLIENT_SUBJECTS` is empty, or lists one subject per named CA Operations Staff operator with short-lived certificates issued directly by the service-identity CA
- [ ] `CA_GRPC_EST_ALLOWED_PROFILES` covers every profile est-server issues and contains no CA profile
- [ ] `ACME_DNS01_RESOLVERS` (Helm `acme.dns01Resolvers`) lists the enclave's DNSSEC-validating recursive resolver(s) on a trusted network segment, with a capped negative-cache TTL (Section 3.7)

### C.7 Documentation

- [ ] Procedures documented for all roles
- [ ] Emergency contacts documented
- [ ] Incident response plan available
- [ ] Backup recovery tested

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial release |
| 1.1 | January 2026 | OstrichPKI Team | Added NIAP compliance appendix |
| 1.2 | 2026-10-25 | OstrichPKI Team | Section 3.6 CA gRPC issuance channel (dedicated service-identity CA, bootstrap, secrets, allowlist, revocation compensating control, upgrade, monitoring); Section 3.5 dev plaintext flags; Appendix A `CA_GRPC_*` variables; Appendix C checklist items. Branch `claude/grpc-mtls`, uncommitted |
| 1.3 | 2026-10-25 | OstrichPKI Team | Section 3.6 trust-anchor check updated to the final code (CA-database ancestor walk, subject alone, issued-by, audited refusal, per-call `subscriber_issuing_ca`; residual POAM-28); audit-signing note (SLH-DSA CA key unsupported, POAM-34; `audit_write_failed` alert) |
| 1.4 | 2026-10-26 | OstrichPKI Team | Section 3.6 item 4 rewritten for per-method gRPC authorization (three role lists, method table, profile allowlists, requestor and EST username rule, admin identities: one per named operator, issued directly by the single anchor, port-forward / NetworkPolicy access); item 5 role-list removal and CA-rotation note; Appendix A and C.6 updated. Branch `claude/grpc-per-method-authz`, uncommitted |
| 1.5 | 2026-10-26 | OstrichPKI Team | New Section 3.7 ACME dns-01 resolvers (`ACME_DNS01_RESOLVERS` / `--dns01-resolvers`, Helm `acme.dns01Resolvers`, defaults, refusals, DNSSEC-validating resolver on a trusted segment, negative-cache TTL cap, subscriber-visible behaviour changes); Appendix A variable and Appendix C.6 checklist item. Header version 1.3 → 1.5 (1.4 had not updated it). Branch `claude/dns01-resolver-fix`, uncommitted |
| 1.6 | 2026-10-26 | OstrichPKI Team | Section 3.7: wildcard orders now supported (dns-01 only), IP identifiers http-01 only, 100-identifier cap, no issuance-name policy yet (POAM-2026-10-23-55), pre-upgrade authorizations unusable, ACME audit records and best-effort sink. Branch `claude/acme-wildcard-identifiers`, uncommitted |
