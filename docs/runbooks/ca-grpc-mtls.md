# Runbook: CA gRPC Issuance API over mTLS

**Purpose:** provision, verify, rotate and troubleshoot the mutually
authenticated TLS channel that the RA front ends (acme-server, est-server) and
named CA operators use to call the CA gRPC API
(`ostrich.ca.v1.CertificateAuthorityService`, port 50051), and the per-role,
per-method authorization on that channel.

**Symptoms that bring you here:**

- ca-server exits at startup with `CA gRPC requires mTLS: set CA_GRPC_TLS_CERT_FILE, ...; refusing to start`;
- ca-server exits at startup with `CA_GRPC_ALLOWED_CLIENT_SUBJECTS is no longer
  supported: ...` (see [Upgrade from the single allowlist](#upgrade-from-the-single-allowlist-pr-183));
- ca-server exits at startup because `CA_GRPC_TLS_CLIENT_CA_FILE` contains a
  certificate from the CA's own chain (a dedicated service-identity CA is
  required), with a `grpc_listener_refused` audit record;
- ACME order finalization or EST enrollment fails with a TLS handshake error,
  `PermissionDenied` or `Unauthenticated`;
- an operator's `RevokeCertificate` / `GenerateCrl` call gets `PermissionDenied`;
- `helm template` / `helm install` fails with
  `ca.grpc.tls.existingSecret is required`,
  `<acme|est>.caGrpc.clientTls.existingSecret is required` or
  `ca.grpc.allowedClientSubjects was removed: ...`.

**Compliance:** AC-3, AC-4, AC-5, AC-6, AC-6(9), AC-6(10), AC-17, CM-6, CM-7,
IA-3, IA-5(2), IA-9, SC-7, SC-8, SC-8(1), SC-12, SC-13, SC-23,
AU-2/AU-3/AU-10/AU-12, SI-10. NIAP PP-CA: FTP_ITC.1, FCS_TLSS_EXT.1/.2,
FCS_TLSC_EXT.2, FIA_X509_EXT.1, FDP_ACC.1, FDP_ACF.1, FAU_GEN.1, FAU_GEN.2,
FMT_SMR.2, FMT_MTD.1. RFC 8446, RFC 9325, RFC 5280 §6, RFC 4514, RFC 7301. See
`docs/compliance/ATO_EVIDENCE.md`.

## The one rule: a dedicated service-identity CA

The gRPC client trust anchor (`CA_GRPC_TLS_CLIENT_CA_FILE`, `client-ca.crt`)
**MUST be a dedicated service-identity CA or intermediate that issues nothing
except the gRPC service certificates** (the acme-server, est-server and
ca-server identities, plus any test client you deliberately allow).

Never use the CA that this ca-server operates (its subscriber-issuing CA), and
never use any other CA that issues certificates to subscribers, devices or
users. The role lists match the client **subject DN only** (an admin
certificate must also be issued directly by the single client trust anchor,
see [Admin access](#admin-access)). If the client CA also issues end-entity
certificates, anyone who can enroll for a listed subject (for example
`CN=est-server` over EST or the REST API) gets a certificate that passes the
TLS handshake **and** the role lookup, and inherits that role:

- an **Issuer** subject (`CN=acme-server`, `CN=est-server`) can call
  `IssueCertificate` with any subject in that namespace and with any profile
  in that namespace's profile allowlist, skipping the ACME/EST policy;
- an **Admin** subject can call `RevokeCertificate`, `GenerateCrl` and
  `CheckRevocationStatus` (unless the per-call `admin_issuer_not_anchor`
  check catches it, which it does when the forged certificate does not come
  directly from the anchor).

ca-server enforces part of this rule (`ensure_dedicated_client_ca` in
`crates/ostrich-common/src/grpc_tls.rs`, called from `check_grpc_trust_anchors`
in `services/ca-server/src/main.rs`). After it connects to the database and
loads its CA, and before it opens the gRPC listener, it walks the issuing CA's
ancestors in the CA database (`ca_certificates.parent_ca_id`, up to 16 levels)
and **refuses to start** if any certificate in `CA_GRPC_TLS_CLIENT_CA_FILE`:

- has the same public key (SubjectPublicKeyInfo) as its issuing certificate;
- has the same **subject** as its issuing certificate (subject alone, so a
  re-keyed or re-issued CA certificate with the same name is also refused);
- was **issued by** its issuing certificate (anchor issuer = issuing subject,
  or anchor authorityKeyIdentifier = issuing subjectKeyIdentifier), for
  example a subordinate CA of this CA;
- is the issuer named in its issuing certificate (refused on the name match
  unless both key identifiers are present and differ); or
- matches (public key or subject) any **ancestor** of the issuing CA found in
  the CA database.

The ancestor walk fails closed: a missing parent row, a cycle, a chain deeper
than 16 levels or an unparsable ancestor certificate also stops startup. Every
refusal (from the walk or from the anchor check) is written as a
`grpc_listener_refused` audit record (`event_type=configuration_change`,
`outcome=failure`, `details.check=client_ca_trust_anchor_separation`,
`details.reason`) before the process exits. Writing that record is best effort:
if the audit write itself fails, the refusal is still enforced and only logged.

It also logs a warning when the file contains more than one trust anchor.
With a non-empty admin list, more than one **distinct** anchor (duplicate PEM
blocks count once) is a startup refusal, not a warning (see
[Admin access](#admin-access)).

**Per-call check.** On every RPC, ca-server also denies a client leaf whose
issuer DN equals the subject of its issuing CA or of any database ancestor, or
whose authorityKeyIdentifier equals one of their subjectKeyIdentifiers
(`PERMISSION_DENIED`, `access_denied` with `reason=subscriber_issuing_ca`).
This catches a subscriber certificate that reached a configured anchor by
another path. It compares the leaf's **direct** issuer only.

What it does **not** detect (residual, POAM-2026-10-23-28):

- CAs that are not in this CA's database lineage: a **sibling** subordinate CA
  (another CA under the same root) or any other platform CA that issues
  subscriber certificates;
- **grandchildren**: a CA issued by a subordinate of this CA. The startup
  check refuses only anchors issued directly by the issuing CA, and the
  per-call check only looks at the leaf's direct issuer;
- an external root above the top of the database lineage, if that root is not
  itself stored in `ca_certificates`.

Issuer-role entries still bind the subject DN only, not an issuer or key.
Admin-role entries additionally require the leaf to be issued directly by the
single anchor (issuer DN and AKI = anchor SKI). Keeping such CAs out of
`client-ca.crt` is the operator's job (A1 checklist).

Order matters for troubleshooting: the gRPC settings themselves are checked
**before** the database connects, but the ancestor walk and the trust-anchor
check run **after** the database connects and the CA loads.

The server-side anchor that the clients use (`CA_GRPC_CA_CERT_FILE`, `ca.crt`)
may be the same service-identity CA. That is the recommended setup.

## How it works

1. **FIPS gate.** Every service checks at startup, before any listener or client
   exists, that the AWS-LC module is in FIPS mode and that the aws-lc-rs rustls
   provider is the process default. If it is not, the service exits.
2. **Fail-closed configuration.** ca-server resolves its gRPC settings before it
   connects to the database. It exits if:
   - the removed `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` is set to anything
     non-blank (checked first, in every mode);
   - any of cert, key or client CA is missing or only partly set;
   - both `CA_GRPC_ACME_CLIENT_SUBJECTS` and `CA_GRPC_EST_CLIENT_SUBJECTS`
     are empty (no issuer client), or an entry in any of the three role lists
     cannot be parsed unambiguously (see [Subject list syntax](#subject-list-syntax));
   - a subject is in more than one role list, also when the two entries
     differ only in ASCII letter case;
   - the admin list is non-empty and `CA_GRPC_TLS_CLIENT_CA_FILE` holds more
     than one distinct trust anchor;
   - a profile allowlist (`CA_GRPC_ACME_ALLOWED_PROFILES`,
     `CA_GRPC_EST_ALLOWED_PROFILES`) names an unknown profile or a CA profile
     (`basic_constraints_ca`, for example `intermediate_ca`), or is empty for
     a namespace that has client subjects;
   - the dev flag `CA_GRPC_INSECURE_DEV_PLAINTEXT` is set in a release build.
     **All container images are release builds**, so plaintext gRPC cannot be
     enabled in any compose or Kubernetes deployment;
   - the dev flag is combined with any gRPC TLS option or with any of the
     three role lists (ambiguous: in plaintext mode the lists would be
     silently ignored).

   These refusals are written to the service log only (no audit record; the
   database is not connected yet, POAM-2026-10-23-05 (d)).
3. **Trust-anchor and authorization-layer checks.** Once the CA is loaded,
   ca-server walks its database ancestors and refuses to start the gRPC
   listener if the client-CA file contains a certificate from its own chain
   (see above), after writing a `grpc_listener_refused` audit record
   (`details.check=client_ca_trust_anchor_separation`). It warns if the file
   has more than one anchor. It then builds the authorization layer **before**
   it binds the socket. With a non-empty admin list, the layer refuses an
   anchor file that does not hold exactly one distinct, parsable anchor, and
   an anchor without a subjectKeyIdentifier; an unparsable subscriber-issuing
   CA certificate is refused too. Each such refusal writes
   `grpc_listener_refused` with `details.check=grpc_authorization_layer` and
   `details.reason` (configuration error text, no key material); no
   `grpc_listener_started` record is written and the socket is never bound.
4. **TLS 1.3 handshake** (rustls with the aws-lc-rs FIPS provider; `fips()` is
   asserted on both the server and client configs):
   - TLS 1.3 only, AES-GCM suites, ALPN `h2` only;
   - key exchange: hybrid ML-KEM-768 groups or P-256/P-384 ECDHE;
   - the client certificate is **mandatory**. It must chain to
     `CA_GRPC_TLS_CLIENT_CA_FILE` and be in its validity period. If it has an
     extendedKeyUsage extension, that extension must include `clientAuth`.

   Connection limits (SC-5): a handshake must finish within 10 s
   (`reason=handshake_timeout`); at most 256 handshakes run at once per
   listener (further connections wait in the kernel accept queue); at most 8
   per source, where a source is one IPv4 address or one IPv6 /64 (further
   connections from that source are closed at once,
   `reason=per_source_handshake_limit`). A connection that completes TLS
   without negotiating `h2` gets a best-effort `close_notify` and is closed
   (`reason=no_alpn_h2`).

   A failed handshake produces a `tls_handshake_failed` audit record
   (Authentication / Failure). Connections that close before sending a
   ClientHello (port scans, TCP probes) are only logged at debug level.
5. **Per-RPC authorization.** This runs on every RPC, including RPCs added
   later, in this order (the first failing check gives the denial reason, see
   [Denial reasons](#denial-reasons)):
   - **Leaf validity.** The leaf must be inside notBefore..notAfter at the
     time of the call, not only at the handshake, so a long-lived HTTP/2
     connection cannot keep using an expired certificate (`UNAUTHENTICATED`,
     `reason=certificate_not_valid_now`). Only the leaf is re-checked;
     intermediates and the anchor are checked at the handshake only.
   - **EKU.** The verified client leaf **must have an extendedKeyUsage
     extension, and it must include `clientAuth`**. The TLS layer only checks
     the EKU when the extension is present, so ca-server also requires that the
     extension exists. A certificate with no EKU extension gets
     `PERMISSION_DENIED` and an `access_denied` audit record with
     `reason=missing_client_auth_eku`.
   - **Subscriber-issuing CA.** A leaf issued directly by this CA or by one of
     its database ancestors (issuer DN or authorityKeyIdentifier match) gets
     `PERMISSION_DENIED` and `access_denied` with
     `reason=subscriber_issuing_ca`, even if it is allow-listed.
   - **Role lookup.** ca-server renders the verified subject DN in its
     RFC 4514 form and looks it up in the three role lists. A subject in no
     list gets `PERMISSION_DENIED` and an `access_denied` audit record
     (Authorization / Failure) with the peer DN, the gRPC method, the remote
     IP and `reason=subject_not_allowlisted`.
   - **Method table.** The exact gRPC path (case-sensitive, no
     normalisation) must have a rule that grants the caller's role (see
     [Roles and methods](#roles-and-methods)). A path with no rule is
     `method_not_mapped`; a rule without the caller's role is
     `method_not_permitted`. Both are `PERMISSION_DENIED` and audited.
   - **Admin issuer.** An Admin call is admitted only if the leaf was issued
     directly by the single client trust anchor (`admin_issuer_not_anchor`
     otherwise).
   - **In the service.** `IssueCertificate` and `RevokeCertificate` bind the
     client-supplied `requestor` to the caller's namespace
     (`requestor_*` reasons), and `IssueCertificate` checks the requested
     profile against the namespace's profile allowlist
     (`profile_not_permitted`). These denials use the same rate limiter and
     are written before the response.
   - **Audit actor.** For an admitted call the audit actor of issuance,
     revocation and CRL records is the verified peer subject DN, never the
     client-supplied `requestor` (see [Audit records](#audit-records)).
   - **Audit rate limits.** `tls_handshake_failed` and `access_denied` records
     are each limited to 60 per 60 s per listener. Beyond that, one summary per
     window is written: `tls_handshake_failures_suppressed` or
     `access_denied_suppressed` (`details.count`, `details.window_secs`). The
     summary is flushed by a timer at the end of each window and when the
     listener shuts down.
6. **Clients** (acme-server, est-server) dial `https://...`. They present their
   client certificate, check the CA server certificate against
   `CA_GRPC_CA_CERT_FILE` and the server name (the URL host, or
   `CA_GRPC_SERVER_NAME`), and require TLS 1.3 and `h2`. In release builds the
   clients refuse plaintext: acme-server refuses `CA_GRPC_INSECURE` /
   `--ca-insecure`, and est-server refuses `--ca-insecure` / `caInsecure` and
   its loopback plaintext exception. Partial client material (one or two of
   the three files) is always refused.
7. **Network layer.** Only acme and est pods may reach the gRPC port. In Helm,
   the CA NetworkPolicy allows pods labelled
   `app.kubernetes.io/component in (acme, est)`. In the kustomize base,
   `deploy/kubernetes/ca-networkpolicy.yaml` allows pods labelled
   `app in (acme-server, est-server)`. REST access is unchanged. Admin tools
   are not admitted by either policy (see [Admin access](#admin-access)).

## Roles and methods

Each verified client subject maps to exactly one role and one requestor
namespace, taken from the list it is in. The method table
(`CA_GRPC_METHOD_RULES` in `crates/ostrich-ca/src/grpc_authz.rs`) is fixed in
code; it is logged and audited at startup (`method_rules`).

| RPC | Issuer: ACME (`acme::`) | Issuer: EST (`est::`) | Admin (`admin::`) |
|---|---|---|---|
| `IssueCertificate` | allow | allow | **deny** |
| `GetCaInfo` | allow | allow | allow |
| `ListProfiles` | allow | allow | allow |
| `RevokeCertificate` | deny | deny | allow |
| `GenerateCrl` | deny | deny | allow |
| `CheckRevocationStatus` | deny | deny | allow |
| any other path (including future RPCs, health, reflection, case or encoding variants) | deny (`method_not_mapped`) | deny (`method_not_mapped`) | deny (`method_not_mapped`) |

- Admin may not issue: a stolen admin key cannot mint certificates, and
  human-driven issuance goes through the REST approval workflow.
- A stolen issuer key cannot revoke or generate CRLs.
- **Requestor rules.** ACME must send `acme::<id>` and EST `est::<id>`; Admin
  sends `admin::<id>` or nothing. The namespace prefix is case-sensitive, the
  id must be non-empty printable ASCII (`0x21`-`0x7E`, no space), and the
  whole value at most 255 bytes. An issuer with an empty requestor is
  refused. The validated requestor is stored and recorded as `on_behalf_of`.
- **Profile allowlists.** Issuer clients may request only the end-entity
  profiles listed for their namespace. CA profiles are never allowed. Anything
  else is `profile_not_permitted` before issuance starts. As defence in depth,
  `issue()` also refuses a CA profile to any authenticated gRPC caller at call
  time (`ca_profile_not_permitted` Failure record, gRPC `PERMISSION_DENIED`
  "certificate profile is not permitted for this client").
- **Residual (POAM-2026-10-23-35).** The CA cannot verify ACME account or EST
  client binding. A compromised acme-server can still claim any `acme::<id>`
  (est-server any `est::<id>`); its blast radius is its own namespace, its
  namespace's allowed end-entity profiles, and the two read RPCs. The audit
  actor is always the verified peer, so forensics attribute the calls to the
  service certificate.

### Certificate path validation limits (rustls-webpki)

The TLS layer uses rustls-webpki. Plan your service-identity CA around what it
does not do:

- **Name constraints:** if a CA certificate in the path has nameConstraints
  with `directoryName` subtrees (permitted or excluded), the chain is
  **rejected** (`NameConstraintViolation`). Do not try to
  restrict the service-identity CA by subject DN through name constraints. A
  dedicated CA is the control.
- **Certificate policies:** there is **no policy processing**.
  certificatePolicies, policyMappings, policyConstraints and inhibitAnyPolicy
  are not evaluated, so do not depend on a policy OID to separate service
  certificates from subscriber certificates.
- **Revocation:** no CRL/OCSP checking on this channel (see Known limitations).

### Known limitations (tracked as POA&M items)

- **No revocation checking** (CRL/OCSP) for gRPC client certificates
  (POAM-2026-10-23-27).
  Compensating control: a compromised or retired client identity must stop
  matching at once. Do one of the following:
  1. remove its subject from its role list and restart ca-server (the lists
     are read at startup only), then reissue the replacement under a **new
     subject** (for example `CN=est-server-2026b`) and add that subject to the
     same role list; or
  2. rotate the trust anchor: move every legitimate client to a new
     service-identity CA, then remove the old CA from `client-ca.crt`.

  Reissuing under the **same** subject from the **same** CA does not lock out
  the old certificate. It would still pass both the handshake and the role
  lookup until it expires. Admin-role impact: a compromised operator
  certificate keeps `RevokeCertificate`, `GenerateCrl` and
  `CheckRevocationStatus` until you remove its subject or until its notAfter
  (the per-call validity check ends it then at the latest). Keep admin
  certificates short-lived.
- **Issuer-role entries are not bound to an issuer or key** (subject DN only).
  The dedicated service-identity CA, the startup trust-anchor check (issuing
  CA, CAs it issued directly, and its database ancestors) and the per-call
  `subscriber_issuing_ca` check compensate. Sibling subordinate CAs,
  grandchildren of this CA and CAs outside its database lineage are not
  detected. Issuer or SPKI binding is still pending (POAM-2026-10-23-28).
  Admin-role entries are narrower: one distinct anchor only, and the leaf
  must be issued directly by it (issuer DN and AKI = anchor SKI).
- **RA namespace confused deputy** (POAM-2026-10-23-35): see
  [Roles and methods](#roles-and-methods).
- **`CheckRevocationStatus` is an unaudited admin read.** Admitted calls to it
  (and to `GetCaInfo` / `ListProfiles`) are not audited; their denials are.
  `RevokeCertificate` and `GenerateCrl` are audited with the verified admin
  peer as actor.
- **Per-call validity is leaf only.** Intermediates and the anchor are
  checked at the handshake; a long-lived connection is not re-validated
  against an anchor that expires mid-connection.
- **Live-database evidence is pending** (POAM-2026-10-23-36). The handler
  wiring from `CaGrpcService` and the REST CRL handlers into the audit
  records, the CRL failure records and the call-time CA-profile refusal are
  covered by pure-builder unit tests; the Postgres- and SoftHSM-gated suites
  (`ca_core_test`, `ocsp_revocation_test`, `audit_signing_e2e`,
  `crl_delta_e2e`) were not run for this change.
- **First install:** ca-server cannot issue its own first gRPC certificates
  (A1; POAM-2026-10-23-29).
- The trust-anchor and authorization-layer refusals are audited
  (`grpc_listener_refused`, best effort). The FIPS gate refusal and the gRPC
  configuration refusals that happen before the database connects (role
  lists, legacy variable, admin with several anchors, profile lists) are
  written to the service log only (POAM-2026-10-23-05).
- **Hung HSM during audit signing** (POAM-2026-10-23-31). Each timed-out
  audit signature leaves one tokio blocking-pool thread stuck until the HSM
  call returns. The tokio runtime waits for these threads when it shuts down,
  so ca-server shutdown can stall until Kubernetes kills the pod after
  `terminationGracePeriodSeconds` (no manifest sets it, so the Kubernetes
  default of 30 s applies). If the HSM stays hung, these threads can fill the
  blocking pool (tokio default: 512 threads). Audit integrity is not affected:
  each timed-out record fails closed and is not written. See
  [Operations: audit write failures](#operations-audit-write-failures).
- Denial audit records are written by detached tasks that are not tracked
  at shutdown, so a few `access_denied` records still in flight when the
  process exits can be lost (minor AU-2 residual).

## Configuration reference

| Setting | ca-server env | Helm value | Default |
|---|---|---|---|
| Server cert chain (PEM) | `CA_GRPC_TLS_CERT_FILE` | `ca.grpc.tls.certFile` | `/app/grpc-tls/tls.crt` |
| Server key (PEM) | `CA_GRPC_TLS_KEY_FILE` | `ca.grpc.tls.keyFile` | `/app/grpc-tls/tls.key` |
| Client trust anchor (dedicated service-identity CA) | `CA_GRPC_TLS_CLIENT_CA_FILE` | `ca.grpc.tls.clientCaFile` | `/app/grpc-tls/client-ca.crt` |
| Secret | (mounted at `/app/grpc-tls`) | `ca.grpc.tls.existingSecret` | **required** |
| ACME client subjects (Issuer, `acme::`) | `CA_GRPC_ACME_CLIENT_SUBJECTS` / `--grpc-acme-client-subjects` (`;`-delimited) | `ca.grpc.acmeClientSubjects` (list) | `CN=acme-server` |
| EST client subjects (Issuer, `est::`) | `CA_GRPC_EST_CLIENT_SUBJECTS` / `--grpc-est-client-subjects` | `ca.grpc.estClientSubjects` (list) | `CN=est-server` |
| Admin client subjects (Admin, `admin::`) | `CA_GRPC_ADMIN_CLIENT_SUBJECTS` / `--grpc-admin-client-subjects` | `ca.grpc.adminClientSubjects` (list) | **empty** (nobody may revoke, generate CRLs or query status) |
| ACME issuable profiles | `CA_GRPC_ACME_ALLOWED_PROFILES` / `--grpc-acme-allowed-profiles` | `ca.grpc.acmeAllowedProfiles` (list) | `acme-default` |
| EST issuable profiles | `CA_GRPC_EST_ALLOWED_PROFILES` / `--grpc-est-allowed-profiles` | `ca.grpc.estAllowedProfiles` (list) | `tls_client;tls_server;tls_server_client;efs` |
| Removed single allowlist | `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` (hidden flag `--grpc-allowed-client-subjects`) | `ca.grpc.allowedClientSubjects` | must be unset or blank: any value refuses startup; the Helm key fails rendering, also as `[]` |
| Dev plaintext (debug builds only) | `CA_GRPC_INSECURE_DEV_PLAINTEXT` | not exposed | `false` |

Subject defaults are those of the compose files, `.env.example`, Helm and the
Kustomize base. ca-server itself has no built-in subject defaults, and an empty
or blank value means "no subjects" (at least one ACME or EST subject is
required). The profile defaults are built into ca-server. The dev compose file
and `tests/integration/docker-compose.yml` use ACME
`CN=acme-server;CN=integration-tests`, EST `CN=est-server`, Admin
`CN=integration-admin`, and ACME profiles `acme-default;tls_client` (the live
tests issue `tls_client` as `CN=integration-tests`).

**Profile allowlist upgrade note.** The EST default covers the built-in
end-entity profiles. If est-server issues any other profile
(`EST_ENROLL_PROFILE`, or a per-user profile), add it to
`CA_GRPC_EST_ALLOWED_PROFILES` before you upgrade, or those enrollments get
`profile_not_permitted`. Helm rendering fails on `intermediate_ca` in either
list (compared after trim and lowercase), on an empty entry or one containing
`;`, and on an empty list for a namespace that has subjects. In the EST-only CI
profile (`acmeClientSubjects: []`) an empty or default ACME profile list is
accepted.

**`docker run --env-file`.** `.env.example` quotes
`CA_GRPC_EST_ALLOWED_PROFILES="tls_client;..."` so that `set -a; . .env` in a
shell does not split on `;`. Docker Compose strips the quotes; `docker run
--env-file` does **not**, so the value would start with a literal `"` and
ca-server refuses to start on an unknown profile. For `docker run
--env-file`, remove the quotes (the value then has no shell-special
characters other than `;`, which `--env-file` does not interpret).

| Setting | acme-server / est-server env | Helm value (`acme.` / `est.`) | Default |
|---|---|---|---|
| CA gRPC URL | `CA_GRPC_URL` | derived: `https://<fullname>-ca:50051` | |
| Client cert (PEM) | `CA_GRPC_CLIENT_CERT_FILE` | `caGrpc.clientTls.certFile` | `/app/ca-grpc-client/tls.crt` |
| Client key (PEM) | `CA_GRPC_CLIENT_KEY_FILE` | `caGrpc.clientTls.keyFile` | `/app/ca-grpc-client/tls.key` |
| CA server trust anchor | `CA_GRPC_CA_CERT_FILE` | `caGrpc.clientTls.caFile` | `/app/ca-grpc-client/ca.crt` |
| Secret | (mounted at `/app/ca-grpc-client`) | `caGrpc.clientTls.existingSecret` | **required** if enabled |
| TLS server name override | `CA_GRPC_SERVER_NAME` | `caGrpc.serverName` | the URL host |
| Plaintext client (dev only) | `CA_GRPC_INSECURE` | never set by the chart | `false` |

`CA_GRPC_SERVER_NAME` is CLI/env only. The EST JSON config file has **no**
server-name field (`caGrpcServerName` / `caBackends[].serverName` were not
added); named EST backends verify against the host of their `grpcUrl`.

The server-name override decouples the certificate check from the HTTP/2
`:authority` the client sends. Use it only when the certificate SAN cannot
contain the dialled host.

### Subject list syntax

`CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS` and
`CA_GRPC_ADMIN_CLIENT_SUBJECTS` each hold a list of RFC 4514 DNs separated by
`;`, parsed by the same rules. Commas separate the RDNs inside one DN. Helm
takes a YAML list per key and joins the items with `;`. Errors name the
variable and the entry number (`CA_GRPC_ADMIN_CLIENT_SUBJECTS entry #1 is
invalid: ...`).

- **One role per subject.** A canonical subject in two lists refuses startup
  (`gRPC client subject <DN> is listed in both <A> and <B>; a client identity
  may hold one role`). So do two entries in different lists that differ only
  in ASCII letter case. Within one list, case variants are two separate
  exact-match entries.

- **Exact, case-sensitive match.** Attribute values are compared octet for
  octet after canonical RFC 4514 rendering. This is **not** the X.500
  caseIgnoreMatch rule: `CN=EST-Server` does not match a certificate with
  `CN=est-server`. Attribute type names (`CN`, `O`, ...) are canonicalised and
  whitespace after a comma is ignored.
- **RDN order:** the most specific RDN comes first, the same as
  `openssl x509 -noout -subject -nameopt RFC2253`, for example
  `CN=acme-server,O=Example,C=US`.
- **`;` is always a separator.** An escaped `\;` is split like any other
  `;`, which leaves an entry ending in a dangling `\` (`CN=a\;CN=b` becomes
  `CN=a\` and `CN=b`), so ca-server refuses to start. If a subject really
  contains `;`, write it as the hex escape `\3B` (for example `CN=a\3Bb`).
  Better: issue service certificates whose subjects have no `;`.
- **Backslash before a comma:** a value with an escaped backslash directly
  followed by an escaped `,` or `+` is refused as ambiguous to the DN parser,
  **also when hex-escaped**. Such a subject is **not allow-listable** (fails
  closed); do not issue service certificates with it.
- **Spaces:** leading and unescaped trailing ASCII space, tab, CR and LF are
  trimmed from each entry and around `,` / `=`. A value that must end in a
  space is written `\20` or as a backslash followed by a space (both are accepted and kept).
- **Non-ASCII whitespace is never trimmed.** An entry or attribute that starts
  or ends with non-ASCII whitespace (for example U+00A0 no-break space or
  U+3000) is refused at startup.
- **Hex escapes must decode to valid UTF-8.** `CN=\FF` or `CN=\C3\28` is
  refused; `CN=\C3\A9` (é) is accepted.
- **Dangling escapes are rejected.** An entry that ends in a lone `\` (for
  example `CN=a\`), or any escape sequence whose canonical form does not
  round-trip, makes ca-server refuse to start. It never truncates the entry to
  something shorter.
- **Numeric attribute types must be decodable OIDs.** A dotted OID type (for
  example `2.5.4.3=x`) is accepted only if it decodes again from its own DER
  encoding; some very large arcs do not, and are refused at startup with
  `invalid numeric attribute type (OID)` (this used to panic; found by
  `fuzz_grpc_peer_subject`).
- **Empty entries are ignored.** A trailing `;` or `;;` is harmless
  (`CN=a;CN=b;` means `CN=a` and `CN=b`). A list whose entries are all blank
  means "no subjects" for that role. If the ACME and EST lists are both
  empty, ca-server refuses to start (fail closed).

## What lives where

| Artifact | Location | In git? |
|---|---|---|
| Helm wiring (secrets, env, NetworkPolicy, NOTES) | `deploy/helm/ostrich-pki/` | Yes |
| Kustomize base wiring | `deploy/kubernetes/{ca,acme,est}-deployment.yaml`, `deploy/kubernetes/ca-networkpolicy.yaml` | Yes |
| Compose wiring | `docker-compose*.y*ml`, `tests/integration/docker-compose.yml` | Yes |
| Dev cert generator | `scripts/gen-dev-grpc-certs.sh`, `make dev-grpc-certs` | Yes |
| Generated dev certs | `.dev-grpc-certs/` (flat files plus `ca-server/`, `acme-server/`, `est-server/`; outside `./certs` on purpose) | No (gitignored, and in `.dockerignore`) |
| Service-identity CA key | offline / HSM, owned by the PKI operators, **not** this ca-server | No |
| CA server secret: `tls.crt`, `tls.key`, `client-ca.crt` | cluster only (`ca-grpc-tls`, or the Helm `ca.grpc.tls.existingSecret`) | No |
| ACME client secret: `tls.crt`, `tls.key`, `ca.crt` | cluster only (`acme-ca-grpc-client`) | No |
| EST client secret: `tls.crt`, `tls.key`, `ca.crt` | cluster only (`est-ca-grpc-client`) | No |
| Cluster-local overlay | `deploy/cluster/ostrich-test-ca.yaml` | No (gitignored). Add the same `CA_GRPC_*` env, mount and secret by hand |

## Certificate requirements

| Certificate | Issued by | Subject | EKU | SAN | Key |
|---|---|---|---|---|---|
| Service-identity CA | your offline root or enterprise PKI | e.g. `CN=OstrichPKI gRPC Service Identity CA` | n/a. Constrain it with `pathlen:0` and issue nothing but the leaves below | n/a | ECDSA P-384 (signing with SHA-384), or RSA ≥ 3072 signing with **RSA-PSS** |
| CA gRPC server | service-identity CA | e.g. `CN=ca-service` | extension present, includes `serverAuth` | **must contain the host clients dial**: Helm `<fullname>-ca` (e.g. `ostrich-pki-ca` for release `ostrich`); kustomize `ca-service`; compose `ca-service` / `ca` | ECDSA P-256/P-384 or RSA ≥ 2048 (ML-DSA once issuance supports it) |
| ACME client | service-identity CA | must equal a `CA_GRPC_ACME_CLIENT_SUBJECTS` entry exactly (default `CN=acme-server`) | **extension required**, must include `clientAuth` | optional | same |
| EST client | service-identity CA | must equal a `CA_GRPC_EST_CLIENT_SUBJECTS` entry exactly (default `CN=est-server`) | **extension required**, must include `clientAuth` | optional | same |
| Admin (one per named operator) | **directly** by the single service-identity CA in `client-ca.crt` (no intermediate) | must equal a `CA_GRPC_ADMIN_CLIENT_SUBJECTS` entry exactly, e.g. `CN=ops-alice` | **extension required**, must include `clientAuth` | optional | same; short validity |

- `client-ca.crt` (server side): the service-identity CA, and nothing else.
  Do not add the OstrichPKI issuing CA, a public CA or a general enterprise
  issuing CA. Keep it to one anchor; ca-server warns when it finds more, and
  refuses to start with more than one distinct anchor while the admin list is
  non-empty. Expect a second anchor only during a CA rotation (see Rotation).
- Every client leaf should carry an authorityKeyIdentifier (RFC 5280
  §4.2.1.1); admin leaves **must** (see [Admin access](#admin-access)).
- `ca.crt` (client side): the CA that issued the **server** certificate. This
  is normally the same service-identity CA.
- The service-identity CA itself may be an intermediate under your offline
  root. rustls accepts an intermediate as the anchor. Put only the
  intermediate in `client-ca.crt`, not the root, because the root also signs
  other issuing CAs.
- Do **not** put directoryName name constraints on the service-identity CA or
  on its parents in the path (webpki rejects them). No policy processing is
  done.

### Accepted signature algorithms

The gRPC listener and its clients accept only these signatures, on every
certificate in the chain and in the TLS CertificateVerify
(`GRPC_SIGNATURE_ALGORITHMS` in `crates/ostrich-common/src/grpc_tls.rs`):

| Accepted | Notes |
|---|---|
| ECDSA P-256 with SHA-256 | key curve and hash must match |
| ECDSA P-384 with SHA-384 | key curve and hash must match |
| RSA-PSS, 2048-8192 bit, SHA-256 / SHA-384 / SHA-512 | key with an `rsaEncryption` SPKI |
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | for future use; OstrichPKI does not issue ML-DSA yet |

Refused at the handshake: **RSA PKCS#1 v1.5** (the OpenSSL default for RSA
keys), a curve/hash mismatch (for example a P-384 key signed with `-sha256`),
Ed25519, P-521, SLH-DSA and composite signatures. Check before you deploy:

```bash
openssl x509 -in acme-server.crt -noout -text | grep 'Signature Algorithm' | head -1
# OK:  ecdsa-with-SHA384 (P-384 issuer), ecdsa-with-SHA256 (P-256 issuer), rsassaPss
# BAD: sha256WithRSAEncryption, ecdsa-with-SHA256 from a P-384 issuer, ED25519
```

## Procedure A: production / persistent cluster

### A1. Service-identity CA and first install

ca-server will not start without its gRPC certificates, so it can never issue
them to itself. It must not issue them anyway, because its issuing CA cannot be
the gRPC client CA. Before the first install:

1. Create (or pick) a **dedicated service-identity CA**: an intermediate under
   your offline root, kept offline or in an HSM, with `pathlen:0`, that only
   ever issues the gRPC service certificates in the table above.
2. Confirm that it is **not** the CA this ca-server will load
   (`CA_CERT_FILE`, the HSM-backed issuing CA), and that it issues no
   subscriber certificates. ca-server checks the first point at startup. The
   second point is your responsibility.
3. Record the CA and its owner in the system inventory (CM-8). The issuance of
   every service certificate is a CM-3 change.

### A2. Generate keys and CSRs, issue from the service-identity CA

```bash
export MSYS_NO_PATHCONV=1   # Git Bash only
openssl ecparam -name secp384r1 -genkey -noout -out ca-grpc-server.key
openssl req -new -key ca-grpc-server.key -subj "/CN=ca-service" \
  -addext "subjectAltName=DNS:ca-service,DNS:ostrich-pki-ca" -out ca-grpc-server.csr
for c in acme-server est-server; do
  openssl ecparam -name secp384r1 -genkey -noout -out "$c.key"
  openssl req -new -key "$c.key" -subj "/CN=$c" -out "$c.csr"
done
```

Have the service-identity CA sign them with an accepted algorithm (see
[Accepted signature algorithms](#accepted-signature-algorithms)). With
OpenSSL as the CA, for a P-384 service-identity CA add `-sha384`
(`openssl x509 -req ... -sha384` or `openssl ca -md sha384`); for an RSA
service-identity CA add `-sigopt rsa_padding_mode:pss` (and, for example,
`-sigopt rsa_pss_saltlen:digest -sha256`), otherwise OpenSSL signs with RSA
PKCS#1 v1.5 and the handshake fails. Certificates above the configured anchor
are not checked (the anchor's own signature is not verified). The
server certificate needs EKU `serverAuth`. The client certificates need an EKU **extension** containing
`clientAuth`, together with `keyUsage=critical,digitalSignature` and
`basicConstraints=critical,CA:FALSE`. Do **not** issue them through this
OstrichPKI CA's REST, ACME or EST interfaces. Save `ca-grpc-server.crt`,
`acme-server.crt`, `est-server.crt` and the service-identity CA certificate as
`service-id-ca.pem`.

Check the files before you load them:

```bash
openssl verify -x509_strict -partial_chain -CAfile service-id-ca.pem \
  -purpose sslserver ca-grpc-server.crt
openssl verify -x509_strict -partial_chain -CAfile service-id-ca.pem \
  -purpose sslclient acme-server.crt est-server.crt
openssl x509 -in ca-grpc-server.crt -noout -ext subjectAltName,extendedKeyUsage
# Must print "TLS Web Client Authentication"; no output = no EKU = denied.
openssl x509 -in acme-server.crt -noout -subject -nameopt RFC2253 -ext extendedKeyUsage
# The service-identity CA must NOT be the CA ca-server issues from:
diff <(openssl x509 -in service-id-ca.pem -noout -pubkey) \
     <(openssl x509 -in ca.pem -noout -pubkey) >/dev/null \
  && echo "STOP: client CA is the issuing CA" || echo "ok: distinct CAs"
```

(`ca.pem` is the ca-server issuing CA certificate.)

### A3. Create the secrets

Kustomize base (`namespace ostrich-pki`, fixed secret names):

```bash
NS=ostrich-pki
cat ca-grpc-server.crt service-id-ca.pem > ca-grpc-tls.crt   # leaf + intermediate
kubectl -n $NS create secret generic ca-grpc-tls \
  --from-file=tls.crt=ca-grpc-tls.crt \
  --from-file=tls.key=ca-grpc-server.key \
  --from-file=client-ca.crt=service-id-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS create secret generic acme-ca-grpc-client \
  --from-file=tls.crt=acme-server.crt --from-file=tls.key=acme-server.key \
  --from-file=ca.crt=service-id-ca.pem --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS create secret generic est-ca-grpc-client \
  --from-file=tls.crt=est-server.crt --from-file=tls.key=est-server.key \
  --from-file=ca.crt=service-id-ca.pem --dry-run=client -o yaml | kubectl apply -f -
# Do not leave private keys on the workstation (GNU shred, or BSD/macOS rm -P).
shred -u ca-grpc-server.key acme-server.key est-server.key 2>/dev/null \
  || rm -P ca-grpc-server.key acme-server.key est-server.key
```

For Helm, use any secret names and reference them in values:

```yaml
ca:
  grpc:
    tls:
      existingSecret: ca-grpc-tls
    acmeClientSubjects: ["CN=acme-server"]
    estClientSubjects: ["CN=est-server"]
    adminClientSubjects: []          # see "Admin access"
    acmeAllowedProfiles: ["acme-default"]
    estAllowedProfiles: ["tls_client", "tls_server", "tls_server_client", "efs"]
acme:
  caGrpc:
    clientTls:
      existingSecret: acme-ca-grpc-client
est:
  caGrpc:
    clientTls:
      existingSecret: est-ca-grpc-client
```

If the server certificate SAN does not contain `<fullname>-ca`, set
`acme.caGrpc.serverName` / `est.caGrpc.serverName` to a name it does contain.

### A4. Deploy and confirm

Run `helm upgrade --install ...` (or `kubectl apply -k deploy/kubernetes/`),
then check the logs. The exact wording comes from the services. Look for:

- every service: `FIPS gate passed: aws-lc-rs provider installed as process default`;
- ca-server: **no** trust-anchor refusal and no multiple-anchor warning;
- ca-server: the gRPC mTLS listener started with TLS 1.3 and FIPS, logging
  `clients`, `method_rules` and `issuer_profiles`, plus a
  `grpc_listener_started` audit record (System / Success) with the same
  fields (see [Audit records](#audit-records)). Check that `clients.admin`
  lists exactly the operators you intend;
- acme-server / est-server: the CA gRPC client is configured with
  `fips=true tls="1.3" mtls=true` and the expected `server_name`.

## Admin access

`RevokeCertificate`, `GenerateCrl` and `CheckRevocationStatus` are reachable
only by subjects in `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (Helm
`ca.grpc.adminClientSubjects`). The list is **empty by default**, so nobody
can call them over gRPC until you name an operator. The gRPC Admin role is the
CA Operations Staff role (NIAP FMT_SMR.2) on this interface.

**One certificate per named operator.** Issue one short-lived admin
certificate per named CA Operations Staff member (for example `CN=ops-alice`,
`CN=ops-bob`), and list each subject. Shared admin certificates are
prohibited: the audit actor is the certificate subject, so a shared subject
makes the audit trail unattributable (IA-2, AU-3). Keep the validity short
(days, not years): client-certificate revocation is not checked on this
channel (POAM-2026-10-23-27), so notAfter is the backstop.

**Issued directly by the single anchor.** With a non-empty admin list:

- `CA_GRPC_TLS_CLIENT_CA_FILE` must hold exactly **one distinct** trust
  anchor (duplicate PEM blocks count once), or ca-server refuses to start;
- that anchor must carry a **subjectKeyIdentifier**, or ca-server refuses to
  start (`grpc_listener_refused`, `check=grpc_authorization_layer`);
- each admin leaf must be issued **directly** by that anchor: its issuer DN
  must equal the anchor subject, and its **authorityKeyIdentifier**
  keyIdentifier must be present and equal the anchor SKI. There is no
  DN-only fallback. A leaf issued by an intermediate under the anchor, a leaf
  without an AKI, or a leaf from a look-alike anchor with the same DN and a
  different key is denied per call with `admin_issuer_not_anchor`
  (`PERMISSION_DENIED`, audited with `peer_issuer` and `peer_serial`).

Issuer roles (ACME, EST) are not affected and may still chain through
intermediates of the anchor.

```bash
cat > admin-ext.cnf <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
authorityKeyIdentifier = keyid:always
subjectKeyIdentifier = hash
EOF
openssl ecparam -name secp384r1 -genkey -noout -out ops-alice.key
openssl req -new -key ops-alice.key -subj "/CN=ops-alice" -out ops-alice.csr
# Signed by the service-identity CA itself (the anchor in client-ca.crt), not by an intermediate:
openssl x509 -req -in ops-alice.csr -CA service-id-ca.pem -CAkey service-id-ca.key \
  -sha384 -days 7 -extfile admin-ext.cnf -out ops-alice.crt
# The AKI must equal the anchor SKI:
openssl x509 -in service-id-ca.pem -noout -ext subjectKeyIdentifier
openssl x509 -in ops-alice.crt -noout -ext authorityKeyIdentifier
```

Then add `CN=ops-alice` to the admin list and restart ca-server (the lists are
read at startup only). Check `clients.admin` in the `grpc_listener_started`
record.

**Reaching the port.** Neither the chart NetworkPolicy nor
`deploy/kubernetes/ca-networkpolicy.yaml` admits an admin pod to port 50051.
Use one of:

- `kubectl port-forward svc/<fullname>-ca 50051:50051` from the operator
  workstation. Port-forward traffic reaches the pod through the kubelet and,
  with common CNI plugins, is not filtered by the pod NetworkPolicy (verify
  this for your CNI). The operator needs the
  Kubernetes RBAC permission `create` on `pods/portforward` in the namespace
  (plus `get` on the pod or service). Grant that only to CA Operations Staff,
  and treat the grant as a CM-3 change; or
- an additional NetworkPolicy that you add for a dedicated operator pod
  (by label), reviewed as a CM-3 change.

**Requestor.** Admin calls may send `requestor = "admin::<id>"` (for example a
ticket number) or nothing; any other namespace is
`requestor_namespace_mismatch`. The audit actor is the admin certificate
subject either way.

**Compromise or departure.** Remove the subject from
`CA_GRPC_ADMIN_CLIENT_SUBJECTS` and restart ca-server at once. Reissuing under
the same subject does not lock out the old certificate.

## Upgrade from the single allowlist (PR #183)

PR #183 shipped one listener-wide list, `CA_GRPC_ALLOWED_CLIENT_SUBJECTS`
(Helm `ca.grpc.allowedClientSubjects`), which admitted every listed subject to
every RPC. It was never in a tagged release. It is replaced by the three role
lists above. ca-server refuses to start while the old variable is set to a
non-blank value, and Helm rendering fails while the old key exists (also as
`[]`). The compose files forward the old variable (default empty) so that a
stale `.env` triggers the refusal instead of being silently ignored.

1. Split the old list by service: acme-server subjects into
   `CA_GRPC_ACME_CLIENT_SUBJECTS` / `acmeClientSubjects`, est-server subjects
   into `CA_GRPC_EST_CLIENT_SUBJECTS` / `estClientSubjects`. A subject may be
   in one list only.
2. Any other subject in the old list (for example `CN=integration-tests`)
   must go into exactly one role list, or be dropped. Do not put an RA
   identity in the admin list.
3. Decide whether anyone needs `RevokeCertificate` / `GenerateCrl` /
   `CheckRevocationStatus` over gRPC. If yes, follow
   [Admin access](#admin-access). If not, leave the admin list empty.
4. Check the profile allowlists (`CA_GRPC_EST_ALLOWED_PROFILES` must cover
   every profile est-server issues, see the upgrade note above).
5. Unset `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` and remove
   `ca.grpc.allowedClientSubjects` from your values files.
6. EST usernames that enroll through the CA must be 1-250 printable ASCII
   characters; others now get HTTP 403 from est-server (audited
   `client_identifier_not_issuable`).
7. For local and test stacks, re-run `make dev-grpc-certs` (it now writes the
   `CN=integration-admin` identity and `CA_GRPC_ADMIN_CLIENT_{CERT,KEY}_FILE`
   to `integration-tests.env`).
8. Deploy and confirm (A4): the `grpc_listener_started` record shows the
   three lists, the method rules and the profile lists.

Rollback across this change means restoring the old variable together with
the old image; do not mix them (the new image refuses the old variable).

## Procedure B: development (compose) and disposable CI clusters

### B1. Compose

```bash
make dev-grpc-certs            # writes .dev-grpc-certs/ (DEV ONLY, CA key discarded)
docker compose up -d           # or -f docker-compose.dev.yml / tests/integration/docker-compose.yml
```

- The generator creates a throwaway **dedicated** dev service-identity CA
  (`CN=OstrichPKI Dev gRPC CA`). It is separate from the ca-server issuing CA,
  so the startup trust-anchor check passes. The dev CA is valid one day longer
  than its leaves (30 days). Its private key is deleted once the leaves are
  signed.
- `docker-compose.yml` mounts **one directory per service**, so each container
  sees only its own key: `.dev-grpc-certs/ca-server` at `/app/grpc-tls` (`tls.crt`,
  `tls.key`, `client-ca.crt`), and `.dev-grpc-certs/acme-server` /
  `.dev-grpc-certs/est-server` at `/app/ca-grpc-client` (`tls.crt`, `tls.key`,
  `ca.crt`). Override the directories with `CA_GRPC_TLS_DIR`,
  `ACME_CA_GRPC_CLIENT_DIR` and `EST_CA_GRPC_CLIENT_DIR` (see `.env.example`).
  **Never put these directories under `./certs`.** The ca, est and ocsp
  containers mount `./certs` wholesale, so anything under it is readable by all
  three. The default `.dev-grpc-certs/` is outside `./certs` for this reason,
  and the generator prints a warning if you point it at a directory under
  `./certs`.
- `docker-compose.yaml`, `docker-compose.dev.yml` and
  `tests/integration/docker-compose.yml` are **dev only**. They bind-mount the
  whole `.dev-grpc-certs` read-only at `/app/grpc-tls`, which means every gRPC
  container sees every dev key.
- Compose refuses to start if a mounted directory is missing.
- Role lists: `docker-compose.yml` / `docker-compose.yaml` use ACME
  `CN=acme-server`, EST `CN=est-server` and an empty admin list. The dev and
  integration compose files use ACME `CN=acme-server;CN=integration-tests`,
  EST `CN=est-server` and Admin `CN=integration-admin`. The generator issues
  `integration-admin` directly from the dev CA (SKI on the CA, AKI on every
  client leaf), so it meets the admin-issuer rule.
- To regenerate, for example after expiry, run
  `make dev-grpc-certs GRPC_CERT_ARGS=--force` and restart ca/acme/est. Sets
  made before the per-service directories existed are regenerated
  automatically.

Host-side live integration tests use the generated client identities
(`integration-tests` issues in the `acme::` namespace; `integration-admin`
revokes, generates CRLs and checks status):

```bash
set -a; . .dev-grpc-certs/integration-tests.env; set +a
cargo test -p ostrich-integration-tests --test ca_core_test -- --ignored
```

### B2. Disposable CI clusters (`values-est-issuer-ci.yaml`)

The CI profile references `ostrich-ci-ca-grpc-tls` and
`ostrich-ci-est-grpc-client` and lists only `CN=est-server` (EST; acme is
disabled, `acmeClientSubjects: []`, admin empty).
**The CI pipeline must create both secrets before `helm install`.** For release
`ostrich-ci`, the gRPC host is `ostrich-ci-ostrich-pki-ca`:

```bash
scripts/gen-dev-grpc-certs.sh --force --san DNS:ostrich-ci-ostrich-pki-ca .dev-grpc-certs-ci
kubectl -n ostrich-ci create secret generic ostrich-ci-ca-grpc-tls \
  --from-file=.dev-grpc-certs-ci/ca-server/
kubectl -n ostrich-ci create secret generic ostrich-ci-est-grpc-client \
  --from-file=.dev-grpc-certs-ci/est-server/
```

The per-service directories already use the secret key names (`tls.crt`,
`tls.key`, `client-ca.crt` / `ca.crt`). The dev CA is dedicated to these
certificates, so it meets the service-identity CA rule. Never use the generator
for a persistent environment.

## Verification

Port-forward the gRPC port, then call the read-only `GetCaInfo` RPC with
[`grpcurl`](https://github.com/fullstorydev/grpcurl). grpcurl negotiates TLS 1.3
and h2. Use `-servername` to match the server SAN.

```bash
kubectl -n "$NS" port-forward svc/ostrich-pki-ca 50051:50051 &   # Helm; kustomize: svc/ca-service
G="grpcurl -import-path proto -proto ca_service.proto -cacert service-id-ca.pem -servername ostrich-pki-ca"
M=ostrich.ca.v1.CertificateAuthorityService/GetCaInfo

# 1. Allow-listed client: succeeds and returns the CA info JSON
$G -cert acme-server.crt -key acme-server.key localhost:50051 $M

# 2. No client certificate: handshake fails (certificate required alert)
$G localhost:50051 $M

# 3. Certificate from a CA outside client-ca.crt, e.g. an end-entity cert
#    issued by this OstrichPKI CA with CN=est-server: handshake fails (unknown CA)
$G -cert subscriber-est-server.crt -key subscriber-est-server.key localhost:50051 $M

# 4. Service-identity CA, EKU clientAuth, subject not allow-listed (CN=intruder):
#    ERROR: Code: PermissionDenied
$G -cert intruder.crt -key intruder.key localhost:50051 $M

# 5. Service-identity CA, allow-listed subject, but NO EKU extension:
#    ERROR: Code: PermissionDenied
$G -cert no-eku.crt -key no-eku.key localhost:50051 $M

# 6. TLS 1.2 is refused (protocol_version alert)
openssl s_client -connect localhost:50051 -tls1_2 -alpn h2 </dev/null

# 7. Issuer client calling an admin RPC: ERROR: Code: PermissionDenied
#    (denied by the layer before the handler runs; no CRL is generated)
$G -cert acme-server.crt -key acme-server.key localhost:50051 \
  ostrich.ca.v1.CertificateAuthorityService/GenerateCrl

# 8. Admin client (if configured) calling IssueCertificate: ERROR: Code: PermissionDenied
$G -cert ops-alice.crt -key ops-alice.key -d '{}' localhost:50051 \
  ostrich.ca.v1.CertificateAuthorityService/IssueCertificate

# 9. Admin client on a read RPC: succeeds
$G -cert ops-alice.crt -key ops-alice.key localhost:50051 $M
```

Case 3 is the important one. It proves that subscriber certificates cannot
reach the API. If it **succeeds**, `client-ca.crt` is wrong: stop and fix it.
Cases 7 and 8 prove the method table: if either **succeeds**, stop and check
the `method_rules` in the `grpc_listener_started` record.

Expected audit records in the CA database (`audit_events`):

- case 4: `event_type=authorization`, `action=access_denied`, `outcome=failure`,
  `actor=CN=intruder`, target = the gRPC method path,
  `details.reason=subject_not_allowlisted`;
- case 5: as case 4, with `details.reason=missing_client_auth_eku`;
- cases 7 and 8: as case 4, with `details.reason=method_not_permitted` and
  `details.role` / `details.namespace` of the caller;
- cases 2, 3 and 6: `action=tls_handshake_failed`;
- startup trust-anchor refusal (below): `event_type=configuration_change`,
  `action=grpc_listener_refused`, `outcome=failure`,
  `details.check=client_ca_trust_anchor_separation`.

Both `tls_handshake_failed` and `access_denied` are rate-limited to 60 records
per 60 s per listener. Beyond that, one `tls_handshake_failures_suppressed` or
`access_denied_suppressed` summary is written per window, with
`details.count` and `details.window_secs`.

Audit-chain tests: `crates/ostrich-audit/tests/chain_concurrency.rs`,
`signed_chain_tamper.rs` and `sign_timeout_db.rs` run only with
`OSTRICH_DB_TESTS=1`. Without it they are skipped and still show as passed,
so a green run without the opt-in is **not** database evidence. With
`OSTRICH_DB_TESTS=1` they **fail** if `DATABASE_URL` is unset, unusable or
unreachable, and refuse to run unless the database name contains `test`.
`chain_concurrency.rs` and `signed_chain_tamper.rs` run
`TRUNCATE audit_events`. Point `DATABASE_URL` at a **disposable** test
database only, never at a CA database.

To check the startup trust-anchor guard in a disposable environment, put the
ca-server issuing CA certificate into `client-ca.crt`. ca-server must exit
before the gRPC listener starts and write a `grpc_listener_refused` record.

For local compose, use `-cacert .dev-grpc-certs/ca.crt -servername localhost` and
the `.dev-grpc-certs/integration-tests.{crt,key}` client (ACME role) or
`.dev-grpc-certs/integration-admin.{crt,key}` (Admin role).

## Denial reasons

Every denial is answered **after** its `access_denied` audit record
(Authorization / Failure) is written, through one rate limiter per listener.
The status message never says which check failed.

| `details.reason` | gRPC status / message | Where | Meaning and fix |
|---|---|---|---|
| `no_client_certificate` | `UNAUTHENTICATED` "client certificate required" | layer | No verified client certificate reached the layer. |
| `unparsable_certificate` | `UNAUTHENTICATED` "client certificate not accepted" | layer | The leaf could not be parsed (was `PERMISSION_DENIED` before this change). |
| `certificate_not_valid_now` | `UNAUTHENTICATED` "client certificate not accepted" | layer | The leaf is outside notBefore..notAfter at call time (for example it expired on a long-lived connection). Renew it; check clocks (AU-8). |
| `missing_client_auth_eku` | `PERMISSION_DENIED` "client is not authorised for this call" | layer | No EKU extension. Reissue with `extendedKeyUsage=clientAuth`. |
| `subscriber_issuing_ca` | `PERMISSION_DENIED` (same message) | layer | Leaf issued by this CA or a database ancestor. Use the service-identity CA. |
| `subject_not_allowlisted` | `PERMISSION_DENIED` | layer | Subject in no role list. |
| `method_not_mapped` | `PERMISSION_DENIED` | layer | The exact path has no rule (unknown or future RPC, case or encoding variant). The raw path is the audit target. Deliberately not `UNIMPLEMENTED`, to avoid method enumeration. |
| `method_not_permitted` | `PERMISSION_DENIED` | layer | The rule exists but not for this role (issuer calling Revoke / CRL / Status; admin calling Issue). |
| `admin_issuer_not_anchor` | `PERMISSION_DENIED` | layer | Admin leaf not issued directly by the single anchor (issuer DN or AKI/SKI mismatch, missing AKI), or no anchor configured. See [Admin access](#admin-access). |
| `requestor_missing` | `PERMISSION_DENIED` | service (Issue, Revoke) | Issuer sent an empty `requestor`. |
| `requestor_namespace_mismatch` | `PERMISSION_DENIED` | service | Prefix is not the caller's namespace (for example acme-server sent `est::x`, or an admin sent `acme::x`). |
| `requestor_invalid` | `PERMISSION_DENIED` | service | Empty id, a character outside `0x21`-`0x7E`, or more than 255 bytes. |
| `profile_not_permitted` | `PERMISSION_DENIED` "certificate profile is not permitted for this client" | service (Issue) | Requested profile not in the namespace's allowlist. Add it (end-entity profiles only) or fix the client. |

Denial `details` carry `listener`, and for a parsed leaf `peer_issuer` and
`peer_serial`; for a known subject also `role` and `namespace`. Requestor
denials add `claimed_namespace` (at most 32 characters, escaped) and
`expected_namespace`; profile denials add `requested_profile` (at most 64
characters, escaped) and `namespace`.

## Audit records

- **Issuance, revocation, CRL (gRPC):** `actor` = the verified peer subject
  DN. `details.authenticated_caller` (same DN),
  `details.authenticated_caller_issuer` and
  `details.authenticated_caller_serial` identify the client certificate;
  `details.on_behalf_of` is the validated `requestor` (absent for an admin
  call without one).
- **Serial format** (`peer_serial`, `authenticated_caller_serial`): lowercase
  hex of the DER INTEGER content octets, sign byte included. Serial 0x8001
  (DER content `00 80 01`) is written `008001`, while `openssl x509 -serial`
  prints `8001`; strip a leading `00` when you compare.
- **REST CRL:** full and delta CRLs generated through REST record the
  authenticated user as actor (`generate` / `generate_delta`); the scheduler
  records `system`.
- **Failure records:** revocation failures carry `details.failure`
  (`invalid_certificate_id`, `invalid_reason`, `certificate_not_found`,
  `lookup_failed`, `database_error`, `already_revoked`); CRL generation
  failures carry `details.failure` (`revoked_lookup_failed`,
  `crl_number_failed`, `unsupported_ca_key_type`, `crl_build_failed`,
  `signing_failed`, `crl_encoding_failed`, `crl_store_failed`,
  `base_crl_lookup_failed`, `no_base_crl`); a CA profile requested by a gRPC
  caller is recorded with `failure: ca_profile_not_permitted`. Success CRL
  records carry `crl_number`, `revoked_count` and, for a delta,
  `base_crl_number`.
- **Not audited:** admitted `CheckRevocationStatus`, `GetCaInfo` and
  `ListProfiles` calls (reads). Their denials are audited.
- **Startup:** `grpc_listener_started` (System / Success) with `mode`, `tls`,
  `fips`, `aws_lc_version`, `clients` (`{acme, est, admin}`), `method_rules`
  (`[{path, roles}]`), `issuer_profiles` and `address`.
  `grpc_listener_refused` (ConfigurationChange / Failure) with
  `details.check` = `client_ca_trust_anchor_separation` or
  `grpc_authorization_layer`, and `details.reason`.

## Rotation

The certificates are read at process start.

1. **Leaf rotation** (same service-identity CA): issue the new certificates
   (A2), update the secrets (A3; `kubectl apply` is idempotent) and restart.
   If the old leaf might be compromised, reissue under a **new subject** and
   swap the role-list entry (see Known limitations), because the old
   certificate stays valid until it expires.
2. **Service-identity CA rotation:**
   - **with a non-empty admin list, ca-server refuses to start while
     `client-ca.crt` holds two distinct anchors.** Empty
     `CA_GRPC_ADMIN_CLIENT_SUBJECTS` for the rotation window (no gRPC
     revocation or CRL generation during it; use the REST API), then re-issue
     the admin certificates directly from the new CA and restore the list
     after the old CA is removed;
   - append the new service-identity CA to `client-ca.crt` and to every client
     `ca.crt` (ca-server warns about two anchors during this window; that is
     expected);
   - restart all three components;
   - swap the leaves to ones issued by the new CA;
   - **remove the old CA** from `client-ca.crt` and every `ca.crt`, then
     restart again. Only after this step are the old certificates locked out.
3. Restart:
   `kubectl rollout restart deploy/<fullname>-ca deploy/<fullname>-acme deploy/<fullname>-est`.
   Restart ca-server first if only its server certificate changed.
4. Verify again (cases 1, 3 and 4).

**Compromised client, right away:** remove its subject from its role list
(`CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS` or
`CA_GRPC_ADMIN_CLIENT_SUBJECTS`) and restart ca-server. Then either reissue under a new subject or rotate the
service-identity CA. Revocation checking is not enforced on this channel yet
(POA&M).

## Rollback

There is **no plaintext rollback** in release builds. `CA_GRPC_INSECURE_DEV_PLAINTEXT`
is rejected at startup, and the chart never sets `CA_GRPC_INSECURE`. If mTLS is
broken, fix the material: reissue the certificates, correct the SAN or EKU, fix
the trust anchor or the role lists. Do not fall back to plaintext. Do not get
past the trust-anchor refusal by putting the issuing CA back into
`client-ca.crt`.

Rolling the **image and chart** back to a release from before mTLS would bring
back plaintext gRPC (POAM-2026-10-23-08). Treat that as an emergency change
that needs CM-3 approval and a documented risk acceptance.

## Upgrade note: audit chain

This release serialises audit-chain appends with a database advisory lock.
Older pods append without the lock. If old and new pods write audit records at
the same time (a rolling upgrade), the chain can fork. To upgrade:

1. Stop **every** audit writer of the old version: use the `Recreate`
   strategy, or scale ca, acme, est, ocsp, scms, kra, tamp, npe-portal and
   web-ui to 0.
2. Start the new version.
3. Verify the chain (`GET /api/v1/audit/verify` as an auditor) and record the
   result.

The same applies when rolling back across this release.

## Operations: audit write failures

Audit-chain appends are time-bounded and fail closed. A record that cannot be
written within the bounds below is **not** written; nothing is appended
outside the chain.

| Bound | Value | Where |
|---|---|---|
| Wait for the chain lock (`lock_timeout`) | 5 s | `AUDIT_CHAIN_LOCK_TIMEOUT_MS`, `crates/ostrich-db/src/repository/audit.rs` |
| Each append statement (`statement_timeout`) | 10 s | `AUDIT_CHAIN_STATEMENT_TIMEOUT_MS` |
| Idle in transaction (`idle_in_transaction_session_timeout`, server-side backstop) | 7 s | `AUDIT_CHAIN_IDLE_TIMEOUT_MS` |
| Begin (pool, BEGIN, lock) / sign / commit, client side | 10 s / 5 s / 10 s | `AUDIT_BEGIN_TIMEOUT`, `AUDIT_SIGN_TIMEOUT`, `AUDIT_COMMIT_TIMEOUT`, `crates/ostrich-audit/src/sink.rs` |

Alert on the log field `alert="audit_write_failed"` (error level):

- `audit record NOT written (fail closed)` with `stage`: the record was not
  written (begin, sign or insert failed or timed out);
- `stage=commit outcome=unknown`, message `audit record commit timed out:
  outcome unknown (record may or may not be written)`: the COMMIT may or may
  not have been applied. Check `audit_events` for the record (by
  `event_type`, `action`, `target`) and verify the chain.

A hung HSM: the audit signature runs on the tokio blocking pool, so the 5 s
sign timeout fires and the chain lock is released (the 7 s idle timeout is
the server-side backstop). The HSM call itself cannot be cancelled. Each hung
call keeps one blocking-pool thread busy until the HSM returns. Shutdown can
then stall until Kubernetes kills the pod, and a long outage can exhaust the
blocking pool (default 512). Restore the HSM, then restart ca-server. Expect
the restart to end in a SIGKILL after the grace period.

When the chain timestamp of a record has to be moved after the head (it waited
for the lock, or clocks differ), the original time is kept in
`details.occurred_at`. That key is reserved for the sink. A value a caller put
there is moved to `details.caller_occurred_at`, with a warning in the log.

**SLH-DSA CA keys.** ca-server signs audit records with the CA key and refuses
SLH-DSA for audit signing. A CA whose key is SLH-DSA therefore does not start
(`Unsupported algorithm: CA key cannot sign audit records: Audit signing
error: SLH-DSA-... is not supported for audit record signing ...`). No
provider signs SLH-DSA today, so this does not affect any deployment yet.
Separating the audit key from the CA key is tracked as POAM-2026-10-23-34.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| ca-server: `CA gRPC requires mTLS: set CA_GRPC_TLS_CERT_FILE, CA_GRPC_TLS_KEY_FILE, CA_GRPC_TLS_CLIENT_CA_FILE and CA_GRPC_ACME_CLIENT_SUBJECTS and/or CA_GRPC_EST_CLIENT_SUBJECTS; refusing to start` | None of the three `CA_GRPC_TLS_*` files is set. Set all three and at least one issuer subject. |
| ca-server: `CA_GRPC_ALLOWED_CLIENT_SUBJECTS is no longer supported: the CA gRPC listener authorizes per method and role. List acme-server identities in CA_GRPC_ACME_CLIENT_SUBJECTS, est-server identities in CA_GRPC_EST_CLIENT_SUBJECTS and operator (revocation / CRL) identities in CA_GRPC_ADMIN_CLIENT_SUBJECTS, then unset CA_GRPC_ALLOWED_CLIENT_SUBJECTS; refusing to start` | The removed single allowlist is still set (environment, `.env`, or the hidden `--grpc-allowed-client-subjects` flag). See [Upgrade from the single allowlist](#upgrade-from-the-single-allowlist-pr-183). |
| ca-server: `partial CA gRPC TLS configuration: CA_GRPC_TLS_CERT_FILE, CA_GRPC_TLS_KEY_FILE and CA_GRPC_TLS_CLIENT_CA_FILE are all required; refusing to start` | One or two of the files are set. Set all three. |
| ca-server: `no issuer client configured: set CA_GRPC_ACME_CLIENT_SUBJECTS and/or CA_GRPC_EST_CLIENT_SUBJECTS; refusing to start` | Both issuer lists are unset or blank. An admin list alone is not enough. |
| ca-server: `gRPC client subject <DN> is listed in both <A> and <B>; a client identity may hold one role` or `gRPC client subjects <DN> (<A>) and <DN2> (<B>) differ only in letter case; a client identity may hold one role, refusing to start` | One identity in two role lists. Keep it in one list. |
| ca-server: `CA_GRPC_ADMIN_CLIENT_SUBJECTS is set but CA_GRPC_TLS_CLIENT_CA_FILE holds N distinct trust anchors (duplicates counted once): with an admin role the gRPC client CA file must contain exactly one dedicated service-identity CA (any anchor could issue an admin subject); refusing to start` | Before the database connects. Remove every anchor except the service-identity CA, or empty the admin list (for example during a CA rotation). |
| ca-server: `CA_GRPC_ADMIN_CLIENT_SUBJECTS is set but the CA_GRPC_TLS_CLIENT_CA_FILE trust anchor has no subjectKeyIdentifier: admin certificates are matched to the anchor by authorityKeyIdentifier (RFC 5280 §4.2.1.1/§4.2.1.2); refusing to start` (under `CA gRPC listener configuration rejected`) | The service-identity CA lacks an SKI. Reissue it with `subjectKeyIdentifier = hash` (RFC 5280 requires an SKI in CA certificates), then reissue the admin leaves with `authorityKeyIdentifier = keyid:always`. A `grpc_listener_refused` record with `check=grpc_authorization_layer` is written. |
| ca-server: `CA_GRPC_ADMIN_CLIENT_SUBJECTS is set but CA_GRPC_TLS_CLIENT_CA_FILE holds N distinct trust anchors: admin certificates must be issued directly by a single client trust anchor; refusing to start` or `subscriber-issuing CA certificate #N cannot be parsed` (under `CA gRPC listener configuration rejected`) | Authorization-layer refusal after the database connects; the socket is not bound. Fix as above. A `grpc_listener_refused` record with `check=grpc_authorization_layer` is written. |
| ca-server: `CA_GRPC_ACME_ALLOWED_PROFILES lists "<name>", which is not a registered certificate profile; refusing to start`, `... lists the CA profile <name>: CA certificates are never issuable over gRPC by an issuer client; refusing to start` or `... is empty but <ns> client subjects are configured; list the end-entity profiles they may request; refusing to start` (same for `CA_GRPC_EST_ALLOWED_PROFILES`) | Fix the profile list: registered end-entity profiles only, non-empty when that namespace has subjects. With `docker run --env-file`, remove the quotes around the value (see the configuration reference). |
| ca-server: `CA_GRPC_INSECURE_DEV_PLAINTEXT is set together with gRPC TLS options or a client subject list (CA_GRPC_ACME_CLIENT_SUBJECTS, CA_GRPC_EST_CLIENT_SUBJECTS, CA_GRPC_ADMIN_CLIENT_SUBJECTS); the configuration is ambiguous, refusing to start` | Debug build with the dev flag plus TLS files or a role list. Use one mode only. |
| Every service: `AWS-LC is not in FIPS mode (...); refusing to start`, `rustls aws-lc-rs provider is not in FIPS mode; refusing to start` or `process-default rustls CryptoProvider is not in FIPS mode; refusing to start` | Non-FIPS build or linkage (missing `fips` feature, non-FIPS AWS-LC, sanitizer build), or a non-FIPS provider was installed before the gate. Rebuild from the pinned FIPS configuration. |
| ca-server: `CA_GRPC_TLS_CLIENT_CA_FILE certificate #N has the same public key (SPKI) as this CA's issuing certificate` / `... has the same subject as this CA's issuing certificate` / `... was issued by this CA's issuing certificate` / `... is the issuer of this CA's issuing certificate` / `... matches (public key or subject) ancestor #M of this CA's issuing certificate in the CA database`, followed by `. The gRPC client CA must be a dedicated service-identity CA that issues nothing else: ... Refusing to start the gRPC listener` (under `CA gRPC listener configuration rejected`) | `client-ca.crt` holds a certificate from this ca-server's own chain: its issuing CA (same key or same subject), a CA it issued, its issuer or a database ancestor. Replace it with the dedicated service-identity CA (A1) and reissue the gRPC client certificates from that CA. This check runs after the database connects and the CA loads, and writes a `grpc_listener_refused` audit record. |
| ca-server: `CA hierarchy in ca_certificates has a cycle at <id>`, `CA hierarchy in ca_certificates is deeper than 16 levels`, `parent CA certificate <id> not found in ca_certificates` or `ancestor #M of the CA issuing certificate cannot be parsed; cannot check the gRPC client CA` (under `CA gRPC listener configuration rejected`) | The ancestor walk failed closed: the `ca_certificates.parent_ca_id` chain is broken, cyclic or too deep, or a stored ancestor certificate is corrupt. Repair the CA rows. A `grpc_listener_refused` record is written. |
| `PermissionDenied`, audit `reason=subscriber_issuing_ca` | The client leaf was issued by this CA or by one of its ancestors: a subscriber certificate, not a service identity. Issue the client certificate from the service-identity CA and fix `client-ca.crt` (it must not let subscriber chains through). |
| ca-server exits: `Unsupported algorithm: CA key cannot sign audit records: Audit signing error: SLH-DSA-... is not supported for audit record signing (signing runs under the audit chain lock); use ECDSA, Ed25519 or ML-DSA` | The CA key is SLH-DSA, and ca-server signs audit records with the CA key. Not supported yet (POAM-2026-10-23-34). |
| Log: `alert="audit_write_failed"` (`audit record NOT written (fail closed)`, or `stage=commit outcome=unknown`) | An audit-chain append failed or timed out. See [Operations: audit write failures](#operations-audit-write-failures). |
| ca-server shutdown hangs until the pod is killed | A hung HSM left audit-signing threads blocked. See [Operations: audit write failures](#operations-audit-write-failures). |
| ca-server warns: `CA_GRPC_TLS_CLIENT_CA_FILE contains more than one trust anchor: every anchor can issue a certificate for any allow-listed subject; use a single dedicated service-identity CA` | Expected only while a service-identity CA is being rotated. Otherwise remove every anchor except the service-identity CA. |
| ca-server: `CA_GRPC_<ACME\|EST\|ADMIN>_CLIENT_SUBJECTS entry #N is invalid: <why>` (for example `dangling escape: the subject ends with a backslash`, `incomplete hex escape ...`, `invalid escape sequence`, `a value with a backslash directly followed by ',' or '+' is not supported in allowlist entries (ambiguous to the DN parser, also when hex-escaped)`, `hex escapes do not decode to valid UTF-8`, `subject starts or ends with non-ASCII whitespace`, `attribute starts or ends with non-ASCII whitespace`, `invalid numeric attribute type (OID)`, `subject does not round-trip through its canonical form`) | Fix the entry (see [Subject list syntax](#subject-list-syntax)). Remove trailing `\`, never escape `;`, and remove invisible non-ASCII spaces (for example a pasted U+00A0). |
| ca-server: `CA_GRPC_INSECURE_DEV_PLAINTEXT is not available in release builds; configure gRPC mTLS (...); refusing to start` | `CA_GRPC_INSECURE_DEV_PLAINTEXT=true` in a container. Remove it. |
| acme-server: `CA_GRPC_INSECURE / --ca-insecure is not available in release builds; ... refusing to start` | Remove `CA_GRPC_INSECURE`; configure the three `CA_GRPC_*` client files. |
| est-server: `--ca-insecure / caInsecure is a development escape hatch and is not available in release builds ...` or `refusing a plaintext gRPC channel to CA endpoint '...' in a release build (the loopback exception is debug-only) ...` | Configure CA mTLS for EST (client cert, key and CA cert); a loopback URL does not allow plaintext in release builds. |
| acme/est: `refusing a plaintext gRPC channel to '...': ...` or `partial gRPC mTLS configuration: client certificate, client key and CA certificate are all required` | Client material missing or incomplete. Set all three files. |
| acme/est: `gRPC mTLS requires an https:// endpoint, got '...'` | `CA_GRPC_URL` uses `http://` while mTLS material is configured. Use `https://`. |
| Audit: many `tls_handshake_failed` with `reason=per_source_handshake_limit` | More than 8 concurrent handshakes from one IPv4 address or IPv6 /64 (a scanner, or many pods behind one NAT address). |
| Audit: `reason=handshake_timeout` | The client did not finish the handshake within 10 s (stalled client, or a TCP check that opens and holds the port). |
| Handshake fails although the chain and EKU look right | The certificate is signed with RSA PKCS#1 v1.5 or a curve/hash mismatch. See [Accepted signature algorithms](#accepted-signature-algorithms). |
| ca-server: an error reading a file under `/app/grpc-tls` | Secret key names are wrong (they must be `tls.crt`, `tls.key`, `client-ca.crt`), or the secret is missing (the pod stays in `ContainerCreating`). |
| Client: `certificate not valid for name ...` / `NotValidForName` | The server SAN lacks the URL host. Add `DNS:<fullname>-ca` (Helm) or `DNS:ca-service` (kustomize), or set `caGrpc.serverName` / `CA_GRPC_SERVER_NAME`. |
| Client: `UnknownIssuer` | The client `ca.crt` does not contain the CA that issued the server certificate. |
| CA log / audit: handshake failed `UnknownIssuer` | `client-ca.crt` does not contain the client's issuing CA. The client certificate must come from the service-identity CA. |
| Handshake failed: `NameConstraintViolation` | A CA in the path has directoryName name constraints (permitted or excluded). webpki rejects every such chain; reissue the service-identity CA without them. |
| Handshake failed: `InvalidPurpose` / EKU | The client certificate has an EKU without `clientAuth`, or the server certificate lacks `serverAuth`. |
| `PermissionDenied`, audit `reason=missing_client_auth_eku` | The client certificate has **no** EKU extension. Reissue it with `extendedKeyUsage=clientAuth`. |
| Handshake failed: `NoApplicationProtocol` / protocol version | The client is not offering `h2` or TLS 1.3 (an old or custom client). |
| `PermissionDenied`, audit `reason=subject_not_allowlisted` with a valid certificate | The subject DN does not match an entry in any role list **exactly**. Matching is case-sensitive and uses the RFC 4514 form with the most specific RDN first, the same as `openssl x509 -noout -subject -nameopt RFC2253`, e.g. `CN=acme-server,O=Example,C=US`. Copy the `actor` from the `access_denied` audit record. Separate multiple DNs with `;`, never `,`. |
| `helm template`: `... existingSecret is required` | Expected fail-closed behaviour. Create the secret and set the value (A3). |
| `helm template`: `ca.grpc.<key> entry "..." is empty or contains ';' (the list delimiter)` | Use one list item per DN or profile. The chart joins them with `;`. |
| `helm template`: `ca.grpc.allowedClientSubjects was removed: split it into ca.grpc.acmeClientSubjects, ca.grpc.estClientSubjects and ca.grpc.adminClientSubjects ...` | Remove the old key (also `[]`) and use the three role keys. |
| `helm template`: `ca.grpc.acmeClientSubjects and ca.grpc.estClientSubjects are both empty: ...`, `gRPC client subject "<DN>" is listed in both ca.grpc.<a> and ca.grpc.<b>; ...`, `ca.grpc.<ns>ClientSubjects is set but ca.grpc.<ns>AllowedProfiles is empty: ...` or `ca.grpc.<key> must not list "intermediate_ca": CA profiles are never allowed for gRPC Issuer clients` | Fix the values as named. The chart check is exact-string; ca-server additionally refuses canonical and case-variant overlaps. |
| `PermissionDenied`, audit `reason=method_not_permitted` | The caller's role may not call that RPC (issuer → Revoke / CRL / Status, admin → Issue). See [Roles and methods](#roles-and-methods). An RA cannot revoke over gRPC. |
| `PermissionDenied`, audit `reason=method_not_mapped` | The exact path is not in the method table: wrong package or service name, a case or encoding variant, or a client built against a newer proto. |
| `PermissionDenied`, audit `reason=admin_issuer_not_anchor` | Admin certificate issued by an intermediate, missing an AKI, or AKI not equal to the anchor SKI. Issue it directly from the anchor (see [Admin access](#admin-access)). |
| `PermissionDenied`, audit `reason=requestor_missing` / `requestor_namespace_mismatch` / `requestor_invalid` | The client `requestor` is empty (issuer), in another namespace, or has characters outside printable ASCII or more than 255 bytes. acme-server and est-server send valid values; check for a custom client or an EST username outside 1-250 printable ASCII characters. |
| `PermissionDenied` "certificate profile is not permitted for this client", audit `reason=profile_not_permitted` | The profile is not in `CA_GRPC_<ACME\|EST>_ALLOWED_PROFILES`. Add the end-entity profile (for example the `EST_ENROLL_PROFILE` value) and restart. |
| `Unauthenticated` "client certificate not accepted", audit `reason=certificate_not_valid_now` or `unparsable_certificate` | The client leaf has expired (or is not yet valid) at call time, possibly on a long-lived connection, or cannot be parsed. Renew the certificate and check the clocks. |
| est-server: HTTP 403, audit `client_identifier_not_issuable` | The EST username is not 1-250 printable ASCII characters, so the CA would refuse its `est::<id>` requestor. Rename the EST user. |
| compose: `bind source path does not exist: .../.dev-grpc-certs` (or `.../.dev-grpc-certs/<service>`) | Run `make dev-grpc-certs` (it also creates the per-service directories), or fix `CA_GRPC_TLS_DIR` / `*_CA_GRPC_CLIENT_DIR`. |
| ACME/EST pods cannot connect at all (timeout) | NetworkPolicy. Helm: only pods with `app.kubernetes.io/component` = `acme` or `est` of the same release may reach 50051. Kustomize: only pods labelled `app=acme-server` / `app=est-server` (`ca-networkpolicy.yaml`). |
