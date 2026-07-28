# EST External-Issuer Integration Profile

## Purpose and boundary

The profile at
`deploy/helm/ostrich-pki/values-est-issuer-ci.yaml` provisions only the
OstrichPKI components required for automated RFC 7030 external-issuer
conformance testing: PostgreSQL, a SoftHSM-backed P-384 CA, and the EST
service. It is intended only for disposable Kubernetes clusters.

The profile does not weaken production defaults. CA bootstrap remains disabled
unless explicitly enabled, CA approval remains required by default, and EST
Basic authentication remains disabled by default. Enabling bootstrap requires
an operator-supplied Secret and a persistent HSM token volume; missing inputs
cause Helm rendering or workload startup to fail closed.

## Security boundaries

- The bootstrap Job creates a non-extractable P-384 CA key inside SoftHSM and
  stores only token state on the dedicated PVC.
- PKCS#11 and administrator authenticators enter Pods through Secret references;
  they are not Helm values, command-line arguments, ConfigMaps, or log fields.
- The CA Deployment waits for a valid CA database record before starting and
  mounts the same token PVC read/write.
- Database readiness containers use a multi-architecture digest-pinned
  PostgreSQL client image so a mutable registry tag cannot alter startup code.
- EST Basic authentication is permitted only on the TLS listener with a client
  CA configured, matching the server's existing fail-closed startup checks.
- The integration profile disables CA approval only because cert-manager
  approval is independently enforced by `usg-est-issuer`; this setting is not a
  production recommendation.

## Control and protocol mapping

| Requirement | Evidence |
|---|---|
| NIST 800-53 CM-2, CM-6 | Explicit opt-in profile and convergent bootstrap Job |
| NIST 800-53 IA-5, IA-7 | Secret-backed administrator and PKCS#11 authenticators |
| NIST 800-53 SC-12, SC-17 | P-384 CA key and certificate bootstrapped in SoftHSM |
| NIST 800-53 SA-11, CA-2 | Repeatable external-issuer integration assessment |
| NIAP FCS_CKM.1, FCS_STG_EXT.1 | Non-extractable CA key in a PKCS#11 token |
| RFC 7030 sections 3.2.3 and 4.2 | TLS-protected Basic bootstrap and simple enrollment |
| RFC 8446 | TLS listener used for all EST traffic |

## Validation

The chart must pass:

```sh
helm dependency build deploy/helm/ostrich-pki
helm lint deploy/helm/ostrich-pki \
  --values deploy/helm/ostrich-pki/values-est-issuer-ci.yaml \
  --set postgresql.auth.password=ci-only-placeholder
helm template ostrich-ci deploy/helm/ostrich-pki \
  --namespace ostrich-ci \
  --values deploy/helm/ostrich-pki/values-est-issuer-ci.yaml \
  --set postgresql.auth.password=ci-only-placeholder >/dev/null
```

Runtime certificate-lifecycle evidence is produced by the consumer repository's
kind workflow and must include certificate-chain, P-384 key, SAN-boundary,
failure-condition, and secret-leakage assertions.
