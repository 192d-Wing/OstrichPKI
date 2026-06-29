# NPE Portal — ACME production overlay

These manifests flip the NPE portal from the smoke deploy (plain HTTP,
`NPE_ALLOW_INSECURE=true`, in `deploy/kubernetes/npe-portal-*.yaml`) to the
production posture: it **auto-enrolls and auto-renews its own TLS server
certificate** via ACME (RFC 8555 HTTP-01) and serves **mTLS** at
`npe-portal.oopl.dev.mil`, deriving the operator role from the client
certificate's OIDs.

They are intentionally **separate** from the smoke manifests and **not** wired
into the root `kustomization.yaml`, so applying them is a deliberate cutover.

## What changes vs. smoke

| Aspect | Smoke | ACME overlay |
|---|---|---|
| Listener | plain HTTP `:8443` | mTLS HTTPS `:8443` (TLS 1.3) |
| Server cert | none | ACME-issued, auto-renewed |
| Client auth | none | **required** (operator client CA) |
| Replicas | 2 | **1** (see below) |
| `NPE_ALLOW_INSECURE` | `true` | removed |
| Cert cache | — | PVC `npe-portal-acme-cache` |

## Why replicas: 1

The HTTP-01 challenge store is in-memory per pod. With >1 replica behind the
service, the ACME server's validation fetch
(`http://npe-portal.oopl.dev.mil/.well-known/acme-challenge/{token}`) may land
on a different pod than the one that created the order, 404, and fail
validation. Running a single replica makes enrollment deterministic. Restoring
active-active requires a shared challenge store (or DNS-01); tracked as a
follow-up.

## Why challengePort: 8080 (not 80)

The pod runs as non-root (UID 1000) and cannot bind `:80`. The portal's HTTP-01
responder listens on `:8080`; Traefik's `web` entrypoint (external `:80`) routes
`/.well-known/acme-challenge/` to it. The ACME server still fetches on port 80
of the domain, as the protocol requires.

## Prerequisites (operator-supplied)

1. **Operator client CA** — a Secret `npe-operator-client-ca` (key `ca.pem`)
   holding the CA bundle every operator's client cert chains to. Mounted as
   `TLS_CLIENT_CA_FILE`. Operators must already hold client certs issued by this
   CA carrying the role OIDs in `oidMapping`, or the portal is unreachable for
   them.
2. **ACME directory CA bundle** — a ConfigMap `npe-acme-ca-bundle` (key
   `acme-ca-bundle.pem`) with the CA cert(s) that signed the ACME directory's
   own HTTPS endpoint (`https://acme.oopl.dev.mil`).
3. **`oidMapping.allowedIssuers`** in the configmap set to the real operator
   issuing-CA subject DN(s).

## Apply (cutover)

```sh
# 1. Create the prerequisite secret + configmap (operator-supplied material):
kubectl -n ostrich-pki create secret generic npe-operator-client-ca \
  --from-file=ca.pem=/path/to/operator-client-ca.pem
kubectl -n ostrich-pki create configmap npe-acme-ca-bundle \
  --from-file=acme-ca-bundle.pem=/path/to/ostrich-ca-bundle.pem

# 2. Apply the overlay (replaces the smoke configmap/deployment/service):
kubectl apply -f deploy/kubernetes/npe-portal-acme/

# 3. Watch enrollment:
kubectl -n ostrich-pki logs deploy/npe-portal -f | grep -i acme
# expect: "ACME HTTP-01 challenge responder listening" then
#         "obtained ACME certificate" then the HTTPS serve line.

# 4. Verify mTLS (with an operator client cert):
curl --resolve npe-portal.oopl.dev.mil:443:10.10.10.61 \
  --cert operator.crt --key operator.key \
  https://npe-portal.oopl.dev.mil/health
```

## Rollback

Re-apply the smoke manifests:

```sh
kubectl apply -f deploy/kubernetes/npe-portal-configmap.yaml \
              -f deploy/kubernetes/npe-portal-deployment.yaml \
              -f deploy/kubernetes/npe-portal-service.yaml
kubectl -n ostrich-pki delete ingressroute npe-portal-acme-challenge
```
