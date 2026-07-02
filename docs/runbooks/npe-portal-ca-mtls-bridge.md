# Runbook: NPE Portal → CA mTLS Identity Bridge

**Purpose:** provision (or re-provision) the mutually-authenticated channel that
lets the NPE portal forward operator identity to the CA. Without it, every
authenticated portal→CA request returns **401** (symptom: the CAA "Namespaces &
Wildcards" page shows *"Could not load namespaces — Request failed (401)"*, and
the whole authenticated portal→CA surface is affected).

**Compliance:** AC-17, SC-8, IA-2, AC-3 (see `docs/compliance/ATO_EVIDENCE.md`).

## How the bridge works

The portal authenticates operators via their mTLS client certificate, maps the
cert's policy OIDs to an NPE role, and proxies API calls to the CA with
`X-Npe-User` / `X-Npe-Subject` / `X-Npe-Roles` headers. The CA
(`TrustedProxyAuthLayer`) accepts those headers **only** when:

1. the request arrives over TLS **and** the portal presents a client certificate
   whose subject DN is in `CA_TRUSTED_PROXY_SUBJECTS`, and
2. the forwarded role is a *bridgeable* NPE role (`is_bridgeable_role`).

Otherwise the CA falls back to bearer auth and returns 401. Client auth on the
CA is **optional**, so bearer/admin clients (no cert) still work over `https://`.

TLS applies to the CA **REST** listener only — gRPC:50051 (EST, acme) stays
plaintext and is unaffected.

## What lives where

| Artifact | Location | In git? |
|----------|----------|---------|
| ca-server TLS + `CA_TRUSTED_PROXY_SUBJECTS` + HTTPS probes | `deploy/cluster/ostrich-test-ca.yaml` | ❌ gitignored (cluster-local) |
| portal `caUrl: https://…` + `mtls*` + secret mount | `deploy/kubernetes/npe-portal-acme/` | ✅ |
| `ca-mtls` secret (server cert/key + client-CA) | cluster only | ❌ |
| `npe-backend-mtls` secret (portal client cert/key + backend-CA) | cluster only | ❌ |

## Prerequisites

- `kubectl` with the cluster kubeconfig (repo `ostrich.kubeconfig`), namespace `ostrich-pki`.
- `openssl` and `node` on the workstation (Git Bash `openssl` needs
  `MSYS_NO_PATHCONV=1` for `-subj`; Windows `curl` is Schannel and cannot use
  PEM `--cert`, so use `node` to test client-cert mTLS).
- CA admin credentials: user `admin`, password in secret `ostrich-secrets` key
  `CA_ADMIN_PASSWORD`.

## Procedure

### 1. Generate keypairs + CSRs

```bash
export MSYS_NO_PATHCONV=1
openssl ecparam -name prime256v1 -genkey -noout -out portal-client.key
openssl req -new -key portal-client.key -subj "/CN=npe-portal" -out portal-client.csr
openssl ecparam -name prime256v1 -genkey -noout -out ca-server.key
openssl req -new -key ca-server.key -subj "/CN=ca-service" \
  -addext "subjectAltName=DNS:ca-service" -out ca-server.csr
```

### 2. Issue both certs from the running OstrichPKI Intermediate CA (dogfood)

Issuance requires the `IssueCertificate` permission, held by role
`operations_staff` (the `admin` account has only `administrator`, deliberately —
AC-5). REST `create_user` makes certificate-only users and `ostrich-init`
hardcodes Administrator, so a **bearer-capable** issuer must be inserted directly
into the `users` table, then removed:

```bash
POD=$(kubectl -n ostrich-pki get pods -l app=postgres -o name | head -1)
# Create throwaway issuer sharing the admin password hash
kubectl -n ostrich-pki exec "$POD" -- psql -U ostrich -d ostrich_pki -c \
 "INSERT INTO users (username, display_name, password_hash, roles, status)
  SELECT 'svc-issuer','temp issuer', password_hash, ARRAY['operations_staff']::text[], 'active'
  FROM users WHERE username='admin';"
```

Then port-forward the CA, log in as `svc-issuer` (password = admin password),
POST each CSR to `/api/v1/certificates` with **profile keys `tls_client` /
`tls_server`** (NOT the display names "TLS Client"/"TLS Server" — those 404), and
fetch the CA chain from `/api/v1/ca/info` (`chain_pem`). See the issuance script
in the session history / memory `npe-portal-ca-mtls-bridge`. Save
`portal-client.crt`, `ca-server.crt`, and the intermediate as `intermediate-ca.pem`.

**Clean up the issuer immediately:**

```bash
kubectl -n ostrich-pki exec "$POD" -- psql -U ostrich -d ostrich_pki -c \
 "DELETE FROM users WHERE username='svc-issuer';"
```

> `/api/v1/ca/info` returns only the Intermediate (no root). That's fine: rustls
> uses the intermediate as the trust anchor for both directions. Verify with
> `openssl verify -partial_chain -CAfile intermediate-ca.pem <leaf>.crt`.

### 3. Create the secrets

```bash
cat ca-server.crt intermediate-ca.pem > ca-tls.crt   # server presents leaf+intermediate
kubectl -n ostrich-pki create secret generic ca-mtls \
  --from-file=tls.crt=ca-tls.crt \
  --from-file=tls.key=ca-server.key \
  --from-file=client-ca.pem=intermediate-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n ostrich-pki create secret generic npe-backend-mtls \
  --from-file=portal-client.crt=portal-client.crt \
  --from-file=portal-client.key=portal-client.key \
  --from-file=backend-ca.pem=intermediate-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 4. ca-server deployment (cluster overlay)

In `deploy/cluster/ostrich-test-ca.yaml`, on the `ca-server` container add env:

```yaml
- { name: TLS_CERT_FILE,           value: /app/tls/tls.crt }
- { name: TLS_KEY_FILE,            value: /app/tls/tls.key }
- { name: TLS_CLIENT_CA_FILE,      value: /app/tls/client-ca.pem }
- { name: CA_TRUSTED_PROXY_SUBJECTS, value: "CN=npe-portal" }
```

mount the secret, and **switch both probes to HTTPS** (REST now serves TLS —
plain-HTTP probes would fail and crashloop the pod):

```yaml
volumeMounts:
  - { name: ca-mtls, mountPath: /app/tls, readOnly: true }
readinessProbe: { httpGet: { path: /ready,  port: 8080, scheme: HTTPS } }
livenessProbe:  { httpGet: { path: /health, port: 8080, scheme: HTTPS } }
volumes:
  - name: ca-mtls
    secret: { secretName: ca-mtls }
```

Apply and confirm the log shows `Serving HTTPS (TLS 1.3) … mtls=true` and
`Identity bridge enabled … subjects=[CN=npe-portal]`.

### 5. Portal overlay (git-tracked)

In `npe-portal-acme-configmap.yaml`, set `caUrl` to `https://ca-service:8080` and
add `mtlsClientCert` / `mtlsClientKey` / `mtlsCaCert` under `/etc/ostrich/npe`.
In `npe-portal-acme-deployment.yaml`, mount `npe-backend-mtls` at
`/etc/ostrich/npe`. Apply and `rollout restart deploy/npe-portal`. Confirm the
log shows `Backend proxy: mTLS enabled (presenting portal client certificate)`.

## Verification

Replay the portal's exact request to the CA (skip *server* verify since the local
trust store lacks the root; the **client** cert is what exercises the bridge):

```bash
kubectl -n ostrich-pki port-forward svc/ca-service 18080:8080 &
node -e '
const https=require("https"),fs=require("fs");
function call(useCert,roles){return new Promise(r=>{
 const o={host:"127.0.0.1",port:18080,servername:"ca-service",path:"/api/v1/namespaces",
   rejectUnauthorized:false,
   headers:{"x-npe-user":"CAA","x-npe-subject":"CN=CAA","x-npe-roles":roles,"x-npe-session-id":"t"}};
 if(useCert){o.cert=fs.readFileSync("portal-client.crt");o.key=fs.readFileSync("portal-client.key");}
 https.request(o,x=>{console.log(roles,useCert?"+cert":"-cert","→",x.statusCode);r();}).on("error",e=>{console.log("ERR",e.message);r();}).end();
})}
(async()=>{await call(true,"caa_admin");await call(false,"caa_admin");await call(true,"pki_sponsor");})();'
```

Expected: `caa_admin +cert → 200`, `caa_admin -cert → 401`, `pki_sponsor +cert → 403`.

Final check (needs an operator cert in a browser): log in with a CAA cert, accept
consent, open **Namespaces & Wildcards** — the table loads (empty until rules are
added) instead of 401.

## Rollback

Revert the ca-server env/probes to plain HTTP (remove the TLS_* vars and the
`scheme: HTTPS`), re-apply, and point the portal `caUrl` back to
`http://ca-service:8080`. The bridge goes dark and the portal→CA calls 401 again
— so only roll back if you're also standing the bridge back up another way.

## Certificate renewal

The issued leaf certs are short-lived (tls_client ≈ 365d, tls_server ≈ 397d).
Before expiry, repeat steps 1–3 (re-issue, recreate the two secrets) and
`rollout restart` both ca-server and npe-portal. Consider automating via the same
ACME path the portal uses for its front-door cert.
