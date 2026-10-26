# Runbook: CA gRPC Issuance API over mTLS

**Purpose:** provision, verify, rotate and troubleshoot the mutually
authenticated TLS channel that the RA front ends (acme-server, est-server) use to
call the CA gRPC issuance API (`ostrich.ca.v1.CertificateAuthorityService`,
port 50051).

**Symptoms that bring you here:**

- ca-server exits at startup with `CA gRPC requires mTLS: set CA_GRPC_TLS_CERT_FILE, ...; refusing to start`;
- ca-server exits at startup because `CA_GRPC_TLS_CLIENT_CA_FILE` contains a
  certificate from the CA's own chain (a dedicated service-identity CA is
  required), with a `grpc_listener_refused` audit record;
- ACME order finalization or EST enrollment fails with a TLS handshake error or
  `PermissionDenied`;
- `helm template` / `helm install` fails with
  `ca.grpc.tls.existingSecret is required` or
  `<acme|est>.caGrpc.clientTls.existingSecret is required`.

**Compliance:** AC-3, AC-4, AC-6, AC-17, IA-3, IA-5(2), SC-7, SC-8, SC-8(1),
SC-12, SC-13, SC-23, AU-2/AU-3/AU-12, CM-6. NIAP PP-CA: FTP_ITC.1,
FCS_TLSS_EXT.1/.2, FCS_TLSC_EXT.2, FIA_X509_EXT.1, FDP_ACF.1, FAU_GEN.1.
RFC 8446, RFC 9325, RFC 5280 §6, RFC 4514, RFC 7301. See
`docs/compliance/ATO_EVIDENCE.md`.

## The one rule: a dedicated service-identity CA

The gRPC client trust anchor (`CA_GRPC_TLS_CLIENT_CA_FILE`, `client-ca.crt`)
**MUST be a dedicated service-identity CA or intermediate that issues nothing
except the gRPC service certificates** (the acme-server, est-server and
ca-server identities, plus any test client you deliberately allow).

Never use the CA that this ca-server operates (its subscriber-issuing CA), and
never use any other CA that issues certificates to subscribers, devices or
users. The allowlist matches the client **subject DN only**. If the client CA
also issues end-entity certificates, anyone who can enroll for
`CN=est-server` (for example over EST or the REST API) gets a certificate that
passes the TLS handshake **and** the allowlist. That client can then call
`IssueCertificate` with any subject and skip the ACME/EST policy, and it can
also call `RevokeCertificate` and `GenerateCrl`.

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

Allowlist entries still bind the subject DN only, not an issuer or key.
Keeping such CAs out of `client-ca.crt` is the operator's job (A1 checklist).

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
   - any of cert, key or client CA is missing or only partly set;
   - the allowlist is empty, or an entry cannot be parsed unambiguously (see
     [Allowlist syntax](#allowlist-syntax));
   - the dev flag `CA_GRPC_INSECURE_DEV_PLAINTEXT` is set in a release build.
     **All container images are release builds**, so plaintext gRPC cannot be
     enabled in any compose or Kubernetes deployment;
   - the dev flag is combined with any gRPC TLS option or with
     `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` (ambiguous: in plaintext mode the
     allowlist would be silently ignored).
3. **Trust-anchor check.** Once the CA is loaded, ca-server walks its database
   ancestors and refuses to start the gRPC listener if the client-CA file
   contains a certificate from its own chain (see above), after writing a
   `grpc_listener_refused` audit record. It warns if the file has more than
   one anchor.
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
   later:
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
   - **Subject allowlist.** ca-server renders the verified subject DN in its
     RFC 4514 form and compares it with `CA_GRPC_ALLOWED_CLIENT_SUBJECTS`.
     If it is **not listed**, the RPC gets `PERMISSION_DENIED` and an
     `access_denied` audit record (Authorization / Failure) with the peer DN,
     the gRPC method, the remote IP and `reason=subject_not_allowlisted`.
     If it is **listed**, the request runs, and the CA logs `peer_subject` next
     to `request_id`.
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
   `app in (acme-server, est-server)`. REST access is unchanged.

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
  1. remove its subject from the allowlist and restart ca-server, then reissue
     the replacement under a **new subject** (for example
     `CN=est-server-2026b`) and allow-list that subject; or
  2. rotate the trust anchor: move every legitimate client to a new
     service-identity CA, then remove the old CA from `client-ca.crt`.

  Reissuing under the **same** subject from the **same** CA does not lock out
  the old certificate. It would still pass both the handshake and the
  allowlist until it expires.
- **Allowlist entries are not bound to an issuer or key** (subject DN only).
  The dedicated service-identity CA, the startup trust-anchor check (issuing
  CA, CAs it issued directly, and its database ancestors) and the per-call
  `subscriber_issuing_ca` check compensate. Sibling subordinate CAs,
  grandchildren of this CA and CAs outside its database lineage are not
  detected. Issuer or SPKI binding is still pending (POAM-2026-10-23-28).
- The allowlist covers the whole listener: an allow-listed client may also call
  `RevokeCertificate` / `GenerateCrl` (POAM-2026-10-23-26).
- The issuance audit `actor` is still the client-asserted `requestor`. The
  authenticated peer is logged next to it (POAM-2026-10-23-25).
- **First install:** ca-server cannot issue its own first gRPC certificates
  (A1; POAM-2026-10-23-29).
- The trust-anchor refusal is audited (`grpc_listener_refused`, best effort).
  The FIPS gate refusal and the gRPC configuration refusals that happen
  before the database connects are written to the service log only
  (POAM-2026-10-23-05).
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
| Allowed client subjects | `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` (`;`-delimited) | `ca.grpc.allowedClientSubjects` (list) | `CN=acme-server`, `CN=est-server` |
| Dev plaintext (debug builds only) | `CA_GRPC_INSECURE_DEV_PLAINTEXT` | not exposed | `false` |

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

### Allowlist syntax

`CA_GRPC_ALLOWED_CLIENT_SUBJECTS` is a list of RFC 4514 DNs separated by `;`.
Commas separate the RDNs inside one DN. Helm takes a YAML list and joins the
items with `;`.

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
- **Empty entries are ignored.** A trailing `;` or `;;` is harmless
  (`CN=a;CN=b;` means `CN=a` and `CN=b`). If every entry is blank, the
  allowlist counts as unset and ca-server refuses to start (fail closed).

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
| ACME client | service-identity CA | must equal an allowlist entry exactly (default `CN=acme-server`) | **extension required**, must include `clientAuth` | optional | same |
| EST client | service-identity CA | must equal an allowlist entry exactly (default `CN=est-server`) | **extension required**, must include `clientAuth` | optional | same |

- `client-ca.crt` (server side): the service-identity CA, and nothing else.
  Do not add the OstrichPKI issuing CA, a public CA or a general enterprise
  issuing CA. Keep it to one anchor; ca-server warns when it finds more.
  Expect a second anchor only during a CA rotation (see Rotation).
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
    allowedClientSubjects: ["CN=acme-server", "CN=est-server"]
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
- ca-server: the gRPC mTLS listener started with TLS 1.3, FIPS and the
  allowlist, plus a `grpc_listener_started` audit record (System / Success);
- acme-server / est-server: the CA gRPC client is configured with
  `fips=true tls="1.3" mtls=true` and the expected `server_name`.

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
- The allowlist is `CN=acme-server;CN=est-server`. The dev and integration
  compose files also allow `CN=integration-tests`.
- To regenerate, for example after expiry, run
  `make dev-grpc-certs GRPC_CERT_ARGS=--force` and restart ca/acme/est. Sets
  made before the per-service directories existed are regenerated
  automatically.

Host-side live integration tests use the generated client identity:

```bash
set -a; . .dev-grpc-certs/integration-tests.env; set +a
cargo test -p ostrich-integration-tests --test ca_core_test -- --ignored
```

### B2. Disposable CI clusters (`values-est-issuer-ci.yaml`)

The CI profile references `ostrich-ci-ca-grpc-tls` and
`ostrich-ci-est-grpc-client` and allows only `CN=est-server` (acme is disabled).
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
```

Case 3 is the important one. It proves that subscriber certificates cannot
reach the API. If it **succeeds**, `client-ca.crt` is wrong: stop and fix it.

Expected audit records in the CA database (`audit_events`):

- case 4: `event_type=authorization`, `action=access_denied`, `outcome=failure`,
  `actor=CN=intruder`, target = the gRPC method path,
  `details.reason=subject_not_allowlisted`;
- case 5: as case 4, with `details.reason=missing_client_auth_eku`;
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
the `.dev-grpc-certs/integration-tests.{crt,key}` client.

## Rotation

The certificates are read at process start.

1. **Leaf rotation** (same service-identity CA): issue the new certificates
   (A2), update the secrets (A3; `kubectl apply` is idempotent) and restart.
   If the old leaf might be compromised, reissue under a **new subject** and
   swap the allowlist entry (see Known limitations), because the old
   certificate stays valid until it expires.
2. **Service-identity CA rotation:**
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

**Compromised client, right away:** remove its subject from the allowlist and
restart ca-server. Then either reissue under a new subject or rotate the
service-identity CA. Revocation checking is not enforced on this channel yet
(POA&M).

## Rollback

There is **no plaintext rollback** in release builds. `CA_GRPC_INSECURE_DEV_PLAINTEXT`
is rejected at startup, and the chart never sets `CA_GRPC_INSECURE`. If mTLS is
broken, fix the material: reissue the certificates, correct the SAN or EKU, fix
the trust anchor or the allowlist. Do not fall back to plaintext. Do not get
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
| ca-server: `CA gRPC requires mTLS: set CA_GRPC_TLS_CERT_FILE, CA_GRPC_TLS_KEY_FILE, CA_GRPC_TLS_CLIENT_CA_FILE and CA_GRPC_ALLOWED_CLIENT_SUBJECTS; refusing to start` | None of the three `CA_GRPC_TLS_*` files is set. Set all three and at least one subject. |
| ca-server: `partial CA gRPC TLS configuration: CA_GRPC_TLS_CERT_FILE, CA_GRPC_TLS_KEY_FILE and CA_GRPC_TLS_CLIENT_CA_FILE are all required; refusing to start` | One or two of the files are set. Set all three. |
| ca-server: `gRPC client-subject allowlist is empty; no client would be authorised` | `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` is unset or every entry is blank. |
| ca-server: `CA_GRPC_INSECURE_DEV_PLAINTEXT is set together with gRPC TLS options or CA_GRPC_ALLOWED_CLIENT_SUBJECTS; the configuration is ambiguous, refusing to start` | Debug build with the dev flag plus TLS files or an allowlist. Use one mode only. |
| Every service: `AWS-LC is not in FIPS mode (...); refusing to start`, `rustls aws-lc-rs provider is not in FIPS mode; refusing to start` or `process-default rustls CryptoProvider is not in FIPS mode; refusing to start` | Non-FIPS build or linkage (missing `fips` feature, non-FIPS AWS-LC, sanitizer build), or a non-FIPS provider was installed before the gate. Rebuild from the pinned FIPS configuration. |
| ca-server: `CA_GRPC_TLS_CLIENT_CA_FILE certificate #N has the same public key (SPKI) as this CA's issuing certificate` / `... has the same subject as this CA's issuing certificate` / `... was issued by this CA's issuing certificate` / `... is the issuer of this CA's issuing certificate` / `... matches (public key or subject) ancestor #M of this CA's issuing certificate in the CA database`, followed by `. The gRPC client CA must be a dedicated service-identity CA that issues nothing else: ... Refusing to start the gRPC listener` (under `CA gRPC listener configuration rejected`) | `client-ca.crt` holds a certificate from this ca-server's own chain: its issuing CA (same key or same subject), a CA it issued, its issuer or a database ancestor. Replace it with the dedicated service-identity CA (A1) and reissue the gRPC client certificates from that CA. This check runs after the database connects and the CA loads, and writes a `grpc_listener_refused` audit record. |
| ca-server: `CA hierarchy in ca_certificates has a cycle at <id>`, `CA hierarchy in ca_certificates is deeper than 16 levels`, `parent CA certificate <id> not found in ca_certificates` or `ancestor #M of the CA issuing certificate cannot be parsed; cannot check the gRPC client CA` (under `CA gRPC listener configuration rejected`) | The ancestor walk failed closed: the `ca_certificates.parent_ca_id` chain is broken, cyclic or too deep, or a stored ancestor certificate is corrupt. Repair the CA rows. A `grpc_listener_refused` record is written. |
| `PermissionDenied`, audit `reason=subscriber_issuing_ca` | The client leaf was issued by this CA or by one of its ancestors: a subscriber certificate, not a service identity. Issue the client certificate from the service-identity CA and fix `client-ca.crt` (it must not let subscriber chains through). |
| ca-server exits: `Unsupported algorithm: CA key cannot sign audit records: Audit signing error: SLH-DSA-... is not supported for audit record signing (signing runs under the audit chain lock); use ECDSA, Ed25519 or ML-DSA` | The CA key is SLH-DSA, and ca-server signs audit records with the CA key. Not supported yet (POAM-2026-10-23-34). |
| Log: `alert="audit_write_failed"` (`audit record NOT written (fail closed)`, or `stage=commit outcome=unknown`) | An audit-chain append failed or timed out. See [Operations: audit write failures](#operations-audit-write-failures). |
| ca-server shutdown hangs until the pod is killed | A hung HSM left audit-signing threads blocked. See [Operations: audit write failures](#operations-audit-write-failures). |
| ca-server warns: `CA_GRPC_TLS_CLIENT_CA_FILE contains more than one trust anchor: every anchor can issue a certificate for any allow-listed subject; use a single dedicated service-identity CA` | Expected only while a service-identity CA is being rotated. Otherwise remove every anchor except the service-identity CA. |
| ca-server: `gRPC allowed client subject #N is invalid: <why>` (for example `dangling escape: the subject ends with a backslash`, `incomplete hex escape ...`, `invalid escape sequence`, `a value with a backslash directly followed by ',' or '+' is not supported in allowlist entries (ambiguous to the DN parser, also when hex-escaped)`, `hex escapes do not decode to valid UTF-8`, `subject starts or ends with non-ASCII whitespace`, `attribute starts or ends with non-ASCII whitespace`, `invalid numeric attribute type (OID)`, `subject does not round-trip through its canonical form`) | Fix the entry (see [Allowlist syntax](#allowlist-syntax)). Remove trailing `\`, never escape `;`, and remove invisible non-ASCII spaces (for example a pasted U+00A0). |
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
| `PermissionDenied`, audit `reason=subject_not_allowlisted` with a valid certificate | The subject DN does not match an allowlist entry **exactly**. Matching is case-sensitive and uses the RFC 4514 form with the most specific RDN first, the same as `openssl x509 -noout -subject -nameopt RFC2253`, e.g. `CN=acme-server,O=Example,C=US`. Copy the `actor` from the `access_denied` audit record. Separate multiple DNs with `;`, never `,`. |
| `helm template`: `... existingSecret is required` | Expected fail-closed behaviour. Create the secret and set the value (A3). |
| `helm template`: `allowedClientSubjects ... contains ';'` | Use one list item per DN. The chart joins them with `;`. |
| compose: `bind source path does not exist: .../.dev-grpc-certs` (or `.../.dev-grpc-certs/<service>`) | Run `make dev-grpc-certs` (it also creates the per-service directories), or fix `CA_GRPC_TLS_DIR` / `*_CA_GRPC_CLIENT_DIR`. |
| ACME/EST pods cannot connect at all (timeout) | NetworkPolicy. Helm: only pods with `app.kubernetes.io/component` = `acme` or `est` of the same release may reach 50051. Kustomize: only pods labelled `app=acme-server` / `app=est-server` (`ca-networkpolicy.yaml`). |
