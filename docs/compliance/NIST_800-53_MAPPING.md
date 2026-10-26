# NIST 800-53 Rev 5 Security Control Mapping

**Document Version:** 3.2
**Date:** 2026-10-26
**OstrichPKI Version:** 0.15.0
**Standard:** NIST SP 800-53 Revision 5
**Compliance Status:** Enhanced (75-80%)
**Last Updated:** Phase 20 completion - Web UI with OIDC, CSP, and session management

## Executive Summary

This document maps NIST 800-53 Revision 5 security controls to OstrichPKI implementation and NIAP PP-CA v2.1 Security Functional Requirements (SFRs). It provides a comprehensive view of security control compliance for Authority to Operate (ATO) certification.

**Control Families Covered:**

- AC (Access Control)
- AU (Audit and Accountability)
- CM (Configuration Management)
- CP (Contingency Planning)
- IA (Identification and Authentication)
- IR (Incident Response)
- RA (Risk Assessment)
- SC (System and Communications Protection)
- SI (System and Information Integrity)

---

## Access Control (AC)

### AC-2: Account Management

**Control:** The organization manages information system accounts.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- FMT_SMR.2 - Restrictions on Security Roles
- FIA_UAU_EXT.1 - Authentication Mechanism

**Implementation:**

- [services/web-ui/src/server/auth/oidc.rs](../../services/web-ui/src/server/auth/oidc.rs) - OIDC/OAuth 2.0 integration with Keycloak
- User account management delegated to Keycloak Identity Provider
- Role mapping from Keycloak claims (realm_access.roles, resource_access)

**Evidence:**

- ✅ User authentication via OIDC with PKCE
- ✅ User roles extracted from Keycloak tokens
- ✅ Account lifecycle managed in Keycloak (create, modify, disable)
- 🔴 Internal service accounts not yet managed

**Gaps:**

- Internal service-to-service authentication not using OIDC
- SCMS/ACME account management separate from OIDC
- Periodic account review requires Keycloak configuration

**Code References:**

- [services/web-ui/src/server/auth/oidc.rs:270](../../services/web-ui/src/server/auth/oidc.rs#L270) - Role extraction from Keycloak claims
- [services/web-ui/src/server/auth/handlers.rs](../../services/web-ui/src/server/auth/handlers.rs) - OAuth callback and session management

**Remediation:** Configure Keycloak policies for periodic review and automatic disablement

**Evidence Required for ATO:**

- Keycloak realm configuration export
- Role mapping documentation
- Account review logs from Keycloak

---

### AC-3: Access Enforcement

**Control:** The information system enforces approved authorizations for logical access.

**Implementation Status:** 🟢 **Implemented** (Phase 1a gap-closure)

**NIAP Mapping:**

- FMT_MOF.1 - Management of Security Functions Behavior
- FMT_MTD.1 - Management of TSF Data
- FDP_CER_EXT.3 - Certificate Issuance Approval
- FDP_ACC.1 / FDP_ACF.1 - Access Control Policy / Functions (CA gRPC subject allowlist, 2026-10-25; per-role method table, 2026-10-26)

**Implementation:**

- `RbacPolicy` engine at `crates/ostrich-common/src/auth/rbac.rs` evaluates every
  authorization decision against the 33-permission enum in
  `crates/ostrich-common/src/auth/permissions.rs`. The role→permission matrix lives in
  `permissions_for_role()` and is enforced by `permissions.rs` + `roles.rs`.
- `AuthLayer` (authentication) and `AuthzLayer` (authorization) middleware in
  `crates/ostrich-common/src/auth/middleware.rs` apply RBAC enforcement to all
  service routers.
- Per-endpoint permission wiring:
  - `crates/ostrich-ca/src/rest.rs` — IssueCertificate, RevokeCertificate, GenerateCrl,
    ApproveRequest, RejectRequest, SubmitRequest, ViewRequests, ViewConfig (profiles),
    ViewCertificate (GET `/api/v1/certificates` list + GET `/api/v1/certificates/{id}`
    detail + GET `/api/v1/certificates/{id}/pkcs7` certs-only `.p7b` download
    (RFC 5652 §5; own-scoped, AU-2/AU-3 audited) + GET `/api/v1/certificates/stats`
    inventory-wide status counts — read access to the issued-certificate
    inventory, distinct from the IssueCertificate POST on the same path; the list
    accepts an `expiringInDays` filter backing the dashboard "Expiring soon"
    drill-down),
    ReadAuditLog (GET `/api/v1/audit` paginated/filtered audit review — AU-6 /
    FAU_SAR.1; GET `/api/v1/audit/verify` recomputes the hash chain and verifies
    each signed record against the CA public key — AU-9/AU-9(3)/AU-10, FAU_STG.1.2)
    — granted to the NPE `RegistrationAuthority`, `CaaAdmin`, and the dedicated
    read-only `NpeAuditor` roles (`crates/ostrich-common/src/auth/permissions.rs`)
    and surfaced as the NPE-portal Audit Log page (`/audit`). Audit-log ACCESS is
    itself audited — both `audit.review` (list) and `audit.verify` append a
    hash-chained record (`record_audit_access`, AU-2/AU-6/AU-9) — and the
    integrity-verify recompute is rate-limited (30 s result cache) so it cannot be
    abused as a full-table-rehash DoS (SC-5)
  - `crates/ostrich-est/src/rest.rs` — SubmitRequest, RenewCertificate,
    GenerateEstToken (mint/list/revoke device enrollment tokens — POST/GET
    `/api/v1/est/enrollment-tokens`, DELETE `…/{id}`; single-use, time-limited;
    the token bearer authenticates as a least-privilege `EstEnrollee` principal
    holding only SubmitRequest, AC-6; mint/consume/revoke all audited, AU-2;
    the operator may pin the issuance profile per token from an allowlist
    validated at mint and re-validated at issuance — SI-10/CM-6/AC-3,
    `OFFERABLE_EST_PROFILES` + `resolve_enroll_profile` in `…/est/src/rest.rs`)
  - `crates/ostrich-scms/src/rest.rs` — CreateUser, ModifyUser, DeleteUser,
    ViewUsers, UnlockAccount, ViewConfig, ModifyConfig, ReadAuditLog
    (see the route→permission mapping table in `create_router`)
- Web UI proxy (`services/web-ui/src/server/middleware/session.rs`) rejects any
  `/api/*` request that lacks the configured session cookie (fail-closed).
- Intentionally public endpoints are explicitly allowlisted with RFC / NIAP
  justifications at `crates/ostrich-ocsp/src/rest.rs::create_router` (RFC 6960,
  NIAP FDP_IFC.1) and `crates/ostrich-acme/src/rest.rs::create_router`
  (RFC 8555 JWS-per-request authentication model).
- `DisabledAuthProvider` at `crates/ostrich-common/src/auth/provider.rs` provides
  a fail-closed placeholder: any service running without a real `AuthProvider`
  wired in returns 401 for every protected route.
- **CA gRPC API (2026-10-25, branch `claude/grpc-mtls`; per-method since
  2026-10-26, branch `claude/grpc-per-method-authz`, uncommitted):**
  `SubjectAllowlistLayer` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) is a tower layer
  on the ca-server gRPC listener
  ([services/ca-server/src/main.rs](../../services/ca-server/src/main.rs)
  `start_grpc_listener`). Each verified client subject maps to exactly one
  role from three lists: `CA_GRPC_ACME_CLIENT_SUBJECTS` /
  `CA_GRPC_EST_CLIENT_SUBJECTS` (Issuer, namespaces `acme` / `est`) and
  `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (Admin, empty by default). The method table
  `CA_GRPC_METHOD_RULES` in
  [grpc_authz.rs](../../crates/ostrich-ca/src/grpc_authz.rs) grants Issuer
  IssueCertificate, GetCaInfo and ListProfiles, and Admin RevokeCertificate,
  GenerateCrl, CheckRevocationStatus, GetCaInfo and ListProfiles (never
  IssueCertificate). A call is admitted only if the leaf is valid at call
  time, carries an EKU extension with `clientAuth`, was not issued by the
  subscriber-issuing CA, its subject is in a role list, and the exact gRPC
  path has a rule for that role; Admin leaves must also be issued directly by
  the single client trust anchor. Everything else is denied by default,
  including RPCs added later: `UNAUTHENTICATED` (`no_client_certificate`,
  `unparsable_certificate`, `certificate_not_valid_now`) or
  `PERMISSION_DENIED` (`missing_client_auth_eku`, `subscriber_issuing_ca`,
  `subject_not_allowlisted`, `method_not_mapped`, `method_not_permitted`,
  `admin_issuer_not_anchor`). In the service, Issue and Revoke bind the
  client `requestor` to the caller's namespace (`requestor_missing`,
  `requestor_namespace_mismatch`, `requestor_invalid`) and Issue checks the
  namespace's profile allowlist (`profile_not_permitted`). The
  `access_denied` audit record is written before the status is returned.
  Startup is refused with no issuer subject, a subject in two lists, the
  removed `CA_GRPC_ALLOWED_CLIENT_SUBJECTS`, or an invalid profile list.
  Evidence: `authorize_peer_method_matrix`, `rules_cover_every_proto_rpc`,
  e2e `role_method_matrix` and `unknown_method_denied` (TEST_EVIDENCE.md).
  This is per-method, per-service-identity RBAC; it is not per-user
  `Permission` RBAC.

**Gaps:**

- CA gRPC: Issuer-role entries bind the subject DN only, not the issuer or
  key (POAM-2026-10-23-28, open for Issuer roles; Admin requires direct
  issuance by the single anchor); a dedicated service-identity client CA,
  enforced in part at startup, compensates. A compromised RA can still issue
  under any id of its own namespace with that namespace's profiles
  (POAM-2026-10-23-35). The per-method split (POAM-2026-10-23-26) is closed
  pending commit.
- Real `AuthProvider` implementations (password DB, mTLS, OIDC) are not yet wired
  into `services/ca-server`, `services/scms-server`, `services/kra-server`.
  The enforcement scaffolding is complete and fail-closed; a follow-up PR
  connects an actual user store. No production deployment can bypass RBAC.
- Web UI proxy currently validates session-cookie *presence*; full server-side
  session validation against `SessionManager` is a follow-up (the type exists at
  `services/web-ui/src/server/auth/session.rs`).

**Code References:**

- `crates/ostrich-common/src/auth/rbac.rs:130` - `RbacPolicy::authorize`
- `crates/ostrich-common/src/auth/middleware.rs:138` - `AuthzLayer::authorize`
- `crates/ostrich-common/src/auth/permissions.rs:240` - `permissions_for_role`
- `crates/ostrich-ca/src/rest.rs:95-160` - CA route authorization wiring
- `crates/ostrich-scms/src/rest.rs:68-165` - SCMS route→permission mapping table
- `crates/ostrich-est/src/rest.rs:202-235` - EST route authorization wiring
- `services/web-ui/src/server/middleware/session.rs` - proxy session gate
- Tests: `crates/ostrich-common/src/auth/rbac.rs` — `rbac_matrix_*` and
  `separation_of_duties_*` tests exercise the matrix end-to-end.

**Evidence Required for ATO:**

- ✅ Access control policy documentation (role-permission matrix in source + this file)
- ✅ Authorization test results (7 new `rbac_matrix_*` tests pass; see `cargo test
  -p ostrich-common --lib auth::rbac`)
- ✅ Privilege escalation testing (negative tests):
  `separation_of_duties_auditor_cannot_modify_and_admin_cannot_audit` asserts
  that Auditor cannot mutate state and Admin cannot read audit logs

---

### AC-4: Information Flow Enforcement

**Control:** The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems.

**Implementation Status:** 🟡 **Partial** (added 2026-10-25; scoped to ingress to the CA gRPC port)

**NIAP Mapping:**

- No TOE SFR. Maps to the operational-environment objective **OE.NETWORK**
  ([SECURITY_TARGET.md §4.2](SECURITY_TARGET.md)): NetworkPolicy is enforced
  by the cluster CNI, not by the TOE. The policy files annotate FDP_IFC.1 /
  FDP_IFF.1, but those SFRs are not in the Security Target; that annotation is
  not carried here
- Supports FTP_ITC.1 (network layer in front of the trusted channel)

**Implementation:**

- Helm: the CA NetworkPolicy in
  [deploy/helm/ostrich-pki/templates/networkpolicy.yaml](../../deploy/helm/ostrich-pki/templates/networkpolicy.yaml)
  admits traffic to the gRPC port (`ca.grpc.port`, default 50051) only from
  pods of the same release labelled `app.kubernetes.io/component` `acme` or
  `est` (`networkPolicy.enabled: true` by default). The REST rule is unchanged.
- Kustomize base: new
  [deploy/kubernetes/ca-networkpolicy.yaml](../../deploy/kubernetes/ca-networkpolicy.yaml)
  (`ca-restrict-grpc-port`, listed in `kustomization.yaml`) admits port 50051
  only from pods with `app` in (`acme-server`, `est-server`). Port 8080 stays
  open to any source, as before. Ingress only; egress is unchanged.
- The policy is defence in depth in front of TLS 1.3 mTLS and the per-role
  client-subject lists and method table (AC-3, IA-3). Admin (operator) tools
  are not admitted by either policy; they reach the port through
  `kubectl port-forward` or an operator-added policy (runbook, Admin access). It also keeps other in-cluster pods
  from holding the listener's pre-handshake connection slots (SC-5).

**Evidence:**

- ✅ `helm template` / `helm lint` (Helm v3.19.0): the chart renders, lint
  reports 0 failures (`impl-notes-u8.md`, `fixes-round-1-deploy.md`)
- ✅ Kustomize build (kustomize api v0.20.1 `krusty`) with strict decoding into
  `networking/v1.NetworkPolicy`: selector `app=ca-server`; rule 0 port 50051
  from `app In [acme-server est-server]`; rule 1 port 8080 from any source
  (`fixes-round-1-deploy.md`)
- 🔴 No live enforcement evidence: no `kubectl` server-side dry run and no
  cluster test of a denied connection. Enforcement depends on a CNI that
  implements NetworkPolicy

**Gaps:**

- Only ingress to the CA gRPC port is restricted. REST ingress, egress and the
  other services are not covered by this change
- compose deployments have no network-layer restriction (Docker networks only)
- No deployed-cluster verification yet

---

### AC-5: Separation of Duties

**Control:** The organization separates duties of individuals to reduce the risk of malevolent activity.

**Implementation Status:** 🟢 **Implemented** (Phase 1a gap-closure)

**NIAP Mapping:**

- FMT_SMR.2 - Restrictions on Security Roles (mandatory separation)

**Implementation:**

- Role set and separation rules defined in
  `crates/ostrich-common/src/auth/roles.rs`: Administrator, Auditor,
  OperationsStaff, RaStaff, Aor. `validate_role_set()` rejects conflicting
  assignments (Auditor ⊕ Admin, Auditor ⊕ Operations).
- Permission matrix in `permissions_for_role()` at
  `crates/ostrich-common/src/auth/permissions.rs:240` enforces that:
  - Only **Auditor** holds `ReadAuditLog` / `ExportAuditLog` / `SearchAuditLog`
  - Only **OperationsStaff** holds `IssueCertificate` / `RevokeCertificate`
  - **Administrator** cannot issue certificates or read audit logs
  - **RaStaff / Aor** approve requests but cannot issue certificates directly
- `RbacPolicy::verify_can_approve` at `crates/ostrich-common/src/auth/rbac.rs:237`
  enforces requestor ≠ approver for certificate request approvals
  (NIAP FDP_CER_EXT.3).
- Self-approval is blocked at the CA REST handler via the same policy method;
  `Error::SelfApprovalProhibited` surfaces as HTTP 403.
- **Live evidence (the secure-default issuance path, verified end to end):**
  with `CA_REQUIRE_APPROVAL=true` (the default), a 3-actor flow was exercised
  against a SoftHSM-backed CA - submit (RaStaff) -> approve (AOR, a *different*
  user) -> issue (OperationsStaff, referencing `approval_request_id`). The
  issued certificate `openssl verify`s against the root, and the approval
  request is marked `completed` and linked to the certificate (FDP_CER_EXT.2).
  Verified negative cases: issuance with no approval id is rejected (the secure
  default blocks unapproved issuance); a requestor approving their own request
  is denied 403 (FDP_SEPP.1 separation of duties); and re-issuing against an
  already-completed approval is rejected (single-use). The issuer is wired with
  the approval engine + repository at bootstrap when require_approval is true
  (services/ca-server `bootstrap_ca`), and the REST issue handler now accepts
  `approval_request_id` (previously hardcoded to None, which made the
  secure-default path always fail).
- **CA gRPC service identities (2026-10-26, branch
  `claude/grpc-per-method-authz`, uncommitted):** issuance and revocation are
  held by disjoint identities. `GrpcClientRegistry::parse`
  ([grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)) refuses startup
  when a subject is in more than one of `CA_GRPC_ACME_CLIENT_SUBJECTS`,
  `CA_GRPC_EST_CLIENT_SUBJECTS` and `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (also for
  ASCII case variants), and the method table gives Issuer no revocation /
  CRL / status RPC and Admin no IssueCertificate. The gRPC Admin role is the
  CA Operations Staff role on this interface (FMT_SMR.2); one admin
  certificate per named operator is required by the runbook
  (`docs/runbooks/ca-grpc-mtls.md`, Admin access). Tests:
  `registry_rejects_overlap_canonical`, `registry_refuses_case_variant_overlap`,
  `rules_match_policy_table`, e2e `role_method_matrix`.

**Gaps:**

- None at the policy / enforcement layer. Operational role assignment to
  real users depends on the follow-up that wires a real `AuthProvider`.

**Code References:**

- `crates/ostrich-common/src/auth/roles.rs` - `Role` enum, `validate_role_set`
- `crates/ostrich-common/src/auth/permissions.rs:240` - `permissions_for_role`
- `crates/ostrich-common/src/auth/rbac.rs:237` - `verify_can_approve`
- `crates/ostrich-ca/src/approval.rs` - ApprovalEngine uses separation checks
- Tests: `separation_of_duties_auditor_cannot_modify_and_admin_cannot_audit`,
  `test_self_approval_prohibited`, `test_approval_by_different_user` in
  `crates/ostrich-common/src/auth/rbac.rs`

**Evidence Required for ATO:**

- Role separation matrix
- Separation enforcement test results
- Configuration showing separation rules

---

### AC-6: Least Privilege

**Control:** The organization employs the principle of least privilege.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- FMT_MOF.1 - Management of Security Functions Behavior
- FDP_ACC.1 / FDP_ACF.1 - Access Control Policy / Functions (CA gRPC per-role method table, 2026-10-26)

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Key handles prevent direct key access (least privilege for key operations)

**Evidence:**

- ✅ Cryptographic operations use key handles, not direct key material
- ✅ HSM design enforces least privilege (keys never leave HSM)
- ✅ CA gRPC per-method least privilege (2026-10-26, branch
  `claude/grpc-per-method-authz`, uncommitted; see AC-3): ACME and EST may call
  only IssueCertificate, GetCaInfo and ListProfiles; Admin may not issue; the
  admin list is empty by default. Tests: `authorize_peer_method_matrix`,
  e2e `role_method_matrix`, `admin_list_empty_default_denies_revoke_crl_status_for_all`
- ✅ AC-6(10) (prohibit non-privileged users from executing privileged
  functions): issuer identities cannot revoke or generate CRLs, and may
  request only the end-entity profiles listed for their namespace
  (`CA_GRPC_ACME_ALLOWED_PROFILES` default `acme-default`,
  `CA_GRPC_EST_ALLOWED_PROFILES` default
  `tls_client;tls_server;tls_server_client;efs`); CA profiles
  (`basic_constraints_ca`) refuse startup and are refused again at call time
  in `issue()` (`ca_profile_not_permitted`). Tests:
  `profile_policy_refuses_bad_configuration`,
  `caller_profile_refusal_blocks_ca_profiles_for_service_callers`, e2e
  `issuer_profile_allowlist_enforced_and_audited`
- 🟡 AC-6(9) (log use of privileged functions): RevokeCertificate and
  GenerateCrl are audited with the verified admin peer as actor;
  CheckRevocationStatus is an unaudited admin read (only its denials are
  audited). Handler-level live evidence is pending (POAM-2026-10-23-36)
- 🔴 No user privilege levels

**Gaps:**

- No user role privilege restrictions
- All operations available to all users
- CA gRPC: authorized `CheckRevocationStatus` reads are not audited
  (accepted); RA namespace confused deputy (POAM-2026-10-23-35)

**Remediation:** Phase 16 - Assign minimum necessary permissions to each role

---

### AC-7: Unsuccessful Logon Attempts

**Control:** The information system enforces a limit of consecutive invalid logon attempts.

**Implementation Status:** 🟢 **Implemented**

**NIAP Mapping:**

- FIA_AFL.1 - Authentication Failure Handling

**Implementation:**

- [crates/ostrich-common/src/auth/lockout.rs](../../crates/ostrich-common/src/auth/lockout.rs) - `AuthLockout` policy (threshold, lockout duration, failure window, optional permanent lockout) from `LockoutConfig`
- [crates/ostrich-db/src/repository/users.rs](../../crates/ostrich-db/src/repository/users.rs) - `record_failed_attempt` atomically increments `failed_attempts` and sets `locked_until` at the threshold; **thresholds come from `LockoutConfig`** (no longer hardcoded). Persists across restart (enforced at [password.rs](../../crates/ostrich-common/src/auth/password.rs) login).
- [crates/ostrich-common/src/auth/audit.rs](../../crates/ostrich-common/src/auth/audit.rs) + [crates/ostrich-audit/src/auth_hook.rs](../../crates/ostrich-audit/src/auth_hook.rs) - `AuthAuditHook` / `AuthAuditAdapter`: emit audit records for failed login, account lockout, and unlock (wired into ca/est/scms providers).

**Evidence:**

- ✅ Configurable lockout policy (default 5 attempts / 15 min; `LockoutConfig::high_security` = 3 / 30 min)
- ✅ Failed-attempt count + timed lock persisted in the DB (survives restart)
- ✅ Failed login / lockout / unlock audited (AU-2); unit test `password::tests::test_failed_login_emits_audit`

**Gaps / follow-up:**

- Dual enforcement (in-memory `AuthLockout` + DB) is retained; collapsing to a single DB-authoritative source — plus DB-backed lockout for the mTLS (certificate) auth path and a persisted permanent-lockout counter — is a tracked follow-up.

**Remediation:** consolidate to DB-authoritative lockout (cert-auth + permanent-lockout schema).

---

### AC-12: Session Termination

**Control:** The information system automatically terminates a user session after defined conditions.

**Implementation Status:** 🟢 **Implemented**

**NIAP Mapping:**

- FTA_SSL.3 - TSF-Initiated Termination
- FTA_SSL.4 - User-Initiated Termination

**Implementation:**

- [crates/ostrich-common/src/auth/session.rs](../../crates/ostrich-common/src/auth/session.rs) - Core `SessionManager` (timeouts, lock-on-inactivity, user/admin termination) over a pluggable `SessionStore`
- [crates/ostrich-db/src/repository/session.rs](../../crates/ostrich-db/src/repository/session.rs) - `DbSessionStore`: Postgres-backed session persistence (ca-server, est-server, scms-server)
- [migrations/00011_session_persistence.sql](../../migrations/00011_session_persistence.sql) - termination states + metadata; sessions are durable across restart
- [services/web-ui/src/server/auth/session.rs](../../services/web-ui/src/server/auth/session.rs) - Web UI session management with timeouts. Web-UI sessions are ephemeral **by design** (stateless BFF: users re-auth via OIDC on restart, and the per-login proxy `backend_token` cannot be persisted); storage sits behind the `WebUiSessionStore` trait so a durable backend can be added for multi-instance deployments without changing session policy.
- [services/web-ui/src/server/auth/handlers.rs:178](../../services/web-ui/src/server/auth/handlers.rs#L178) - Logout handler
- Session cookies with configurable expiration
- Inactivity timeout and absolute session timeout support

**Evidence:**

- ✅ Configurable session inactivity timeout
- ✅ Configurable absolute session lifetime
- ✅ User-initiated logout endpoint (/auth/logout)
- ✅ Secure cookie settings (HttpOnly, Secure, SameSite)

**Code References:**

- [services/web-ui/src/server/config.rs](../../services/web-ui/src/server/config.rs) - Session configuration options
- [services/web-ui/src/server/auth/session.rs:62](../../services/web-ui/src/server/auth/session.rs#L62) - Session locking on inactivity
- [services/web-ui/src/server/auth/session.rs:57](../../services/web-ui/src/server/auth/session.rs#L57) - Session expiration check

**Remediation:** None required - session termination fully implemented

---

### AC-17: Remote Access

**Control:** The organization establishes usage restrictions for remote access.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- FTP_TRP.1 - Trusted Path
- FTP_ITC.1 - Inter-TSF Trusted Channel
- FCS_TLSS_EXT.1 - TLS Server Protocol
- FCS_TLSS_EXT.2 - TLS Server Protocol with Mutual Authentication (CA gRPC listener)
- FCS_TLSC_EXT.2 - TLS Client Protocol with Mutual Authentication (acme/est gRPC clients)

**Implementation:**

- REST endpoints support TLS for remote access. **CA gRPC (2026-10-25,
  branch `claude/grpc-mtls`, uncommitted):** the ca-server gRPC issuance
  listener now requires TLS 1.3 mutual authentication and refuses to start
  without its mTLS configuration; the acme-server and est-server clients
  present client certificates over TLS 1.3. Before this change the listener was
  plaintext. See SC-8, IA-3 and the runbook
  [docs/runbooks/ca-grpc-mtls.md](../runbooks/ca-grpc-mtls.md)
- **NPE portal → CA identity bridge over mTLS (deployed):** the ca-server REST
  listener serves TLS 1.3 with optional client authentication
  (`TLS_CERT_FILE`/`TLS_KEY_FILE`/`TLS_CLIENT_CA_FILE`); the portal presents a
  client certificate (`CN=npe-portal`, issued by the OstrichPKI Intermediate CA)
  and the CA accepts its forwarded `X-Npe-*` identity ONLY for the configured
  trusted-proxy subject (`CA_TRUSTED_PROXY_SUBJECTS=CN=npe-portal`). Bearer/admin
  clients present no certificate and still connect (client auth is optional).

**Evidence:**

- ✅ TLS support for REST (axum via `ostrich_common::tls`). tonic is now built
  with `features = ["channel"]` only; gRPC TLS is OstrichPKI's own rustls
  acceptor and connector in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)
- ✅ CA gRPC mTLS: `tests/integration/grpc_mtls_e2e.rs` 21/21 passed
  2026-10-25 on the final code (allow-listed client succeeds; missing, untrusted, server-only-EKU
  client certificates and TLS 1.2 clients fail the handshake; see
  [TEST_EVIDENCE.md](TEST_EVIDENCE.md))
- ✅ [services/ca-server/src/main.rs](../../services/ca-server/src/main.rs) - `TLS_CLIENT_CA_FILE` + `CA_TRUSTED_PROXY_SUBJECTS`, `with_optional_client_auth(trusted_proxy.is_some())`
- ✅ [crates/ostrich-common/src/auth/middleware.rs](../../crates/ostrich-common/src/auth/middleware.rs) - `TrustedProxyAuthLayer` bridges identity only when the peer cert subject is allow-listed; `is_bridgeable_role` caps bridged roles to NPE roles (AC-6 defense in depth)
- ✅ [services/npe-portal/src/server/backend_client.rs](../../services/npe-portal/src/server/backend_client.rs) - portal presents its client certificate to the CA (mTLS)
- ✅ Live verification: client cert + `caa_admin` → 200; no client cert → 401; client cert + `pki_sponsor` → 403 (see [docs/runbooks/npe-portal-ca-mtls-bridge.md](../runbooks/npe-portal-ca-mtls-bridge.md))
- ✅ TLS 1.3 minimum is set explicitly in [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) (`with_protocol_versions(&[&TLS13])`), not left to rustls defaults. 2026-10-23 in-memory handshake tests (rustls 0.23.46): `server_rejects_tls12_only_client`, `mtls_handshake_rejects_untrusted_client`, `mtls_handshake_rejects_missing_client_cert`, `optional_mtls_allows_anonymous_but_rejects_untrusted` (see [TEST_EVIDENCE.md §2.3](TEST_EVIDENCE.md#23-test-run-2026-10-23-dependency-advisory-remediation))

**Gaps:**

- Bearer/admin REST access is not yet mTLS-required (client auth is optional so
  the identity bridge and bearer clients can share the listener)
- Client-certificate revocation is not checked on the gRPC or REST mTLS
  listeners (POAM-2026-10-23-27)

---

## Audit and Accountability (AU)

### AU-2: Auditable Events

**Control:** The information system generates audit records for defined auditable events.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- FAU_GEN.1 - Audit Data Generation
- FAU_ADP_EXT.1 - Audit Dependencies

**Implementation:**

- [crates/ostrich-audit/src/event.rs:15-45](../../crates/ostrich-audit/src/event.rs#L15-L45) - `EventType` enum with comprehensive event types
- [crates/ostrich-scms/src/rest.rs](../../crates/ostrich-scms/src/rest.rs) — `audit_token_event` helper called by every state-changing SCMS handler (Phase 1b). 11 distinct token lifecycle actions audited.
- [crates/ostrich-audit/src/session_hook.rs](../../crates/ostrich-audit/src/session_hook.rs) — `SessionAuditAdapter` emits an `Authentication` audit record for every session lifecycle transition (session_created / session_terminated / session_admin_terminated). Wired into ca/est/scms `SessionManager` via `with_audit_hook`. The seam is `ostrich_common::auth::SessionAuditHook` (the auth layer cannot depend on `ostrich-audit`).

**Evidence:**

- ✅ Certificate issuance, revocation, renewal events
- ✅ Session lifecycle events: login (create), logout (user terminate), admin termination — `session_hook.rs`; covered by `tests/integration/session_store_e2e.rs::session_create_emits_audit_event`
- ⏳ Login *failure* and account-lockout auditing (separate auth code paths) remains a follow-up
- ✅ Configuration changes
- ✅ Cryptographic operations
- ✅ Access control decisions
- ✅ Token lifecycle (Phase 1b): create, revoke, initialize, personalize, suspend, resume, unblock, verify-pin (success + failure), change-pin, generate-key, delete-key, create-model
- ✅ **CA gRPC listener events (2026-10-25, branch `claude/grpc-mtls`,
  uncommitted).** Written through `AuthAuditHook` →
  [auth_hook.rs](../../crates/ostrich-audit/src/auth_hook.rs) `AuthAuditAdapter`,
  or directly by ca-server `audit_grpc_listener`:
  - `access_denied` (Authorization / Failure): actor = peer DN (or `unknown`),
    target = gRPC method path, remote IP, `details.reason` one of
    `subject_not_allowlisted`, `unparsable_certificate`,
    `no_client_certificate`, `certificate_not_valid_now`,
    `missing_client_auth_eku`, `subscriber_issuing_ca` (leaf issued by this
    CA or a database ancestor), `method_not_mapped`, `method_not_permitted`,
    `admin_issuer_not_anchor` (layer), and `requestor_missing`,
    `requestor_namespace_mismatch`, `requestor_invalid`,
    `profile_not_permitted` (service, same limiter; 2026-10-26), plus
    `details.listener`, `peer_issuer` / `peer_serial` for a parsed leaf, and
    `role` / `namespace` for a known subject; requestor denials add
    `claimed_namespace` / `expected_namespace`, profile denials
    `requested_profile` / `namespace`;
  - `access_denied_suppressed` (Authorization / Failure): summary
    `{count, window_secs, window_start, window_end, distinct_sources,
    distinct_sources_capped}` when denials exceed the per-listener limit;
  - `tls_handshake_failed` (Authentication / Failure): `details.reason` is the
    handshake failure class, for example `untrusted_client_certificate`,
    `client_certificate_wrong_eku`, `expired_client_certificate`,
    `peer_incompatible`, `no_application_protocol`, `handshake_timeout`,
    `per_source_handshake_limit`, `no_alpn_h2` (the last with the verified
    peer subject as actor);
  - `tls_handshake_failures_suppressed` (Authentication / Failure): summary
    with the same fields;
  - `grpc_listener_started` (System / Success): `{mode: "mtls", tls: "1.3",
    fips: true, aws_lc_version, clients: {acme, est, admin}, method_rules:
    [{path, roles}], issuer_profiles, address}` (2026-10-26; replaces
    `allowed_subjects`);
  - `grpc_insecure_dev_plaintext_enabled` (ConfigurationChange / Success,
    debug builds only): `{build: "debug", address}`;
  - `grpc_listener_refused` (ConfigurationChange / Failure, round 2):
    `{check: "client_ca_trust_anchor_separation", reason}` when the ca-server
    trust-anchor check or the CA-database ancestor walk refuses startup
    (`check_grpc_trust_anchors` in
    [main.rs](../../services/ca-server/src/main.rs); test
    `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal`), and
    `{check: "grpc_authorization_layer", reason}` (2026-10-26) when building
    the authorization layer fails (admin list with an anchor file that is not
    one distinct parsable anchor, an anchor without SKI, or an unparsable
    subscriber-issuing CA); the socket is not bound and no
    `grpc_listener_started` is written (test
    `start_grpc_listener_refusal_is_audited_without_started_record`). Best
    effort: a failed write is logged and the refusal still applies;
  - gRPC issuance, revocation and CRL records (2026-10-26): actor = verified
    peer DN (AU-3 below). Revocation Failure records carry `details.failure`
    (`invalid_certificate_id`, `invalid_reason`, `certificate_not_found`,
    `lookup_failed`, `database_error`, `already_revoked`); full and delta CRL
    generation Failure records carry `details.failure`
    (`revoked_lookup_failed`, `crl_number_failed`, `unsupported_ca_key_type`,
    `crl_build_failed`, `signing_failed`, `crl_encoding_failed`,
    `crl_store_failed`, `base_crl_lookup_failed`, `no_base_crl`); issuance of
    a CA profile by a gRPC caller writes a Failure record with
    `failure: ca_profile_not_permitted`. Tests (pure builders):
    `revocation_failure_event_contents`, `crl_failure_event_contents`,
    `caller_profile_refusal_blocks_ca_profiles_for_service_callers`; the
    database paths were not executed (POAM-2026-10-23-36). Authorized
    `CheckRevocationStatus`, `GetCaInfo` and `ListProfiles` calls are not
    audited (reads)

  Both failure kinds are limited to 60 records per 60 s per listener. The
  suppressed count is flushed by a timer every window and when the accept loop
  exits. TCP connections that close before a ClientHello are logged at debug
  level only. Tests: `access_denied_audit_is_rate_limited_and_summarised`,
  `handshake_failure_audit_is_rate_limited`,
  `disallowed_subject_permission_denied_and_audited`,
  `stalled_handshake_times_out_and_is_audited`,
  `per_source_cap_closes_excess_idle_connections` (`grpc_mtls_e2e`, 21/21
  passed 2026-10-25), `access_denied_audit_survives_cancelled_request`,
  `authorize_peer_refuses_subscriber_issuing_ca_leaf` (`grpc_tls` unit tests)
  and the 4 new `auth_hook` tests in `ostrich-audit`. Denial records are
  written by a spawned task that is awaited before the response, so a
  cancelled request still produces its record; these detached tasks are not
  tracked at process exit, so a few in-flight denial records can be lost at
  shutdown (minor residual, SEC-015)
- ⏳ The FIPS gate refusal and the gRPC configuration refusals that happen
  before the database connects are error logs only: no database pool exists
  yet, so no `ostrich-audit` record is written (POAM-2026-10-23-05 (d),
  narrowed: the trust-anchor refusal is now audited)

**Code Annotation:** NIAP PP-CA v2.1: FAU_GEN.1 — Phase 1b SCMS coverage complete

**Evidence Required for ATO:**

- List of auditable events
- Sample audit logs
- Audit log review procedures

---

### AU-3: Content of Audit Records

**Control:** The information system generates audit records containing defined information.

**Implementation Status:** ✅ **Compliant (Enhanced in Phase 12)**

**NIAP Mapping:**

- FAU_GEN.1 - Audit Data Generation
- FAU_GEN.2 - User Identity Association

**Implementation:**

- [crates/ostrich-audit/src/event.rs:47-110](../../crates/ostrich-audit/src/event.rs#L47-L110) - `AuditEvent` struct
- **Phase 12 Enhancement**: Certificate metadata tracking for service integration audit trails

**Evidence:**

- ✅ Event type (what happened)
- ✅ Timestamp (when)
- ✅ Subject identity (who - actor field)
- ✅ Outcome (success/failure via event type)
- ✅ Objects accessed (resource field)
- ✅ Event ID (request_id for correlation)
- ✅ Additional details (JSON field)
- ✅ **AU-3(1)**: Service tracking (`issuer_service` field in certificates)
- ✅ **AU-3(b)**: Requestor identity tracking (`requestor` field in certificates)
- ✅ **AU-3(1)**: Service-specific metadata (ACME order ID, EST enrollment ID)
- ✅ CA gRPC calls (2026-10-26, branch `claude/grpc-per-method-authz`,
  uncommitted; closes POAM-2026-10-23-25 pending commit): the `actor` of
  issuance, revocation and CRL records written for `IssueCertificate`,
  `RevokeCertificate` and `GenerateCrl` in
  [grpc.rs](../../crates/ostrich-ca/src/grpc.rs) is the verified mTLS peer
  subject DN (`issuance_request`, `revocation_request`, `crl_actor`;
  `audit_identity` in [issuance.rs](../../crates/ostrich-ca/src/issuance.rs)).
  Details add `authenticated_caller`, `authenticated_caller_issuer`,
  `authenticated_caller_serial` (lowercase hex of the DER INTEGER content
  octets, sign byte included) and `on_behalf_of` (the requestor, validated
  against the caller's namespace). The stored `certificates.requestor` stays
  the validated requestor. REST full and delta CRL records carry the
  authenticated user (`generate` / `generate_delta`); `system` is the
  scheduler only. Tests: `issuance_request_carries_verified_caller`,
  `revocation_request_carries_verified_caller`, `crl_actor_is_verified_peer`,
  `audit_identity_with_caller_uses_peer_as_actor`,
  `delta_crl_audit_event_actor` (mutations M11-M13, M12r, M26 killed).
  Residuals: handler glue (M13h) and the live `audit_signing_e2e` assertions
  NOT RUN (POAM-2026-10-23-36); `on_behalf_of` is a namespace-bound claim,
  not a verified account (POAM-2026-10-23-35)

**Phase 12 Enhancements:**

- Certificate audit trail: `issuer_service`, `requestor`, `profile_name`, `metadata` fields
- Database schema: [migrations/00002_add_certificate_metadata.sql](../../migrations/00002_add_certificate_metadata.sql)
- ACME integration metadata: order ID, account ID
- EST integration metadata: enrollment ID, client ID

**Code Annotation:** NIAP PP-CA v2.1: FAU_GEN.2 - Required in Phase 15

**Evidence Required for ATO:**

- ✅ Audit record format specification (Phase 9)
- ✅ Certificate metadata tracking (Phase 12)
- ✅ Sample audit records showing all required fields

---

### AU-5: Response to Audit Processing Failures

**Control:** The information system alerts appropriate personnel in the event of an audit processing failure.

**Implementation Status:** 🔴 **Not Implemented**

**NIAP Mapping:**

- FAU_STG.4 - Prevention of Audit Data Loss

**Implementation:**

- None for storage capacity. Supporting only (2026-10-25, branch
  `claude/grpc-mtls`, uncommitted): every failed or timed-out audit-chain
  write in `DatabaseAuditSink::record`
  ([sink.rs](../../crates/ostrich-audit/src/sink.rs)) logs an error with the
  stable field `alert="audit_write_failed"` and the failing `stage`; the
  record is not written (fail closed, no unchained fallback). A commit
  timeout is logged with `stage=commit`, `outcome=unknown` ("record may or may
  not be written"). Writes are time-bounded (lock 5 s, statement 10 s,
  idle-in-transaction 7 s; begin / sign / commit 10 s / 5 s / 10 s; see AU-9).
  This is a log hook for alerting; no alert routing to personnel is
  configured, so the status is not raised

**Gaps:**

- No alert routing for `alert="audit_write_failed"` (log-based alerting must be
  configured in the deployment)
- No audit storage capacity monitoring
- No alerts when audit trail approaching full
- No configurable action (alert vs. block) when full

**Remediation:** Phase 15 - Implement audit storage monitoring with alerts

**Evidence Required for ATO:**

- Audit storage monitoring configuration
- Alert notification procedures
- Tested alert scenarios

---

### AU-6: Audit Review, Analysis, and Reporting

**Control:** The organization reviews and analyzes information system audit records.

**Implementation Status:** 🔴 **Not Implemented**

**NIAP Mapping:**

- FAU_SAR.1 - Audit Review
- FAU_SAR.2 - Restricted Audit Review

**Implementation:**

- Database contains audit events but no review interface

**Gaps:**

- No audit review UI or API
- No automated analysis tools
- No report generation
- No access control on audit review

**Remediation:** Phase 16 - Implement audit review API with Auditor role restriction

**Evidence Required for ATO:**

- Audit review procedures
- Review frequency schedule
- Sample audit review reports

---

### AU-8: Time Stamps

**Control:** The information system uses internal system clocks to generate time stamps.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- FPT_STM.1 - Reliable Time Stamps

**Implementation:**

- [crates/ostrich-common/src/util/time.rs](../../crates/ostrich-common/src/util/time.rs) - Time utilities using `chrono::Utc`

**Evidence:**

- ✅ All timestamps use UTC
- ✅ Consistent time source (system clock)
- ✅ Audit events include timestamps
- ✅ Certificates include validity timestamps
- ⚠️ Audit chain order (2026-10-25): to keep chain order equal to timestamp
  order, `DatabaseAuditSink` and `MemoryAuditSink` move a record that waited
  for the chain lock to just after the head's timestamp (`chain_timestamp` in
  [sink.rs](../../crates/ostrich-audit/src/sink.rs)). The shift is **not
  bounded**: it grows with lock wait time and with clock skew between the
  writing services, so a stored audit timestamp can be later than the moment
  the event happened. When the timestamp is moved, the original time is kept
  in `details.occurred_at` (RFC 3339, microseconds), set before hashing so it
  is covered by the hash and the signature (`apply_chain_timestamp`; tests
  `apply_chain_timestamp_preserves_original_time`,
  `memory_sink_records_occurred_at_when_bumped`). `occurred_at` is reserved
  for the sink: a value set by the caller is moved to
  `details.caller_occurred_at` with a warning (POAM-2026-10-23-31)

**Deployment Requirement:**

- System must synchronize with authoritative time source (NTP)

**Code Annotation:** NIAP PP-CA v2.1: FPT_STM.1 - Required in Phase 15

**Evidence Required for ATO:**

- NTP configuration documentation
- Time synchronization testing

---

### AU-9: Protection of Audit Information

**Control:** The information system protects audit information and audit tools from unauthorized access, modification, and deletion.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- FAU_STG.1 - Protected Audit Trail Storage
- FAU_SAR.2 - Restricted Audit Review

**Implementation:**

- [crates/ostrich-audit/src/sink.rs:15-50](../../crates/ostrich-audit/src/sink.rs#L15-L50) - `DatabaseAuditSink`
- PostgreSQL database storage

**Evidence:**

- ✅ Audit events stored in database
- 🟡 **Atomic hash-chain append (2026-10-25, branch `claude/grpc-mtls`,
  uncommitted; NIST-002).** `DatabaseAuditSink::record` previously read the
  last hash and inserted without a lock, so concurrent writers (for example
  many unauthenticated peers producing `tls_handshake_failed` records) could
  fork the chain and cause false tamper alarms. It now reads the chain head and
  inserts in one transaction under
  `pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)`
  (`AuditRepository::begin_append` in
  [crates/ostrich-db/src/repository/audit.rs](../../crates/ostrich-db/src/repository/audit.rs)),
  and a record that waited for the lock gets a chain timestamp just after the
  head (`chain_timestamp`, original time in `details.occurred_at`; AU-8).
  Rounds 2 and 3 added:
  - `AuditRepository::append` (and `Repository::create`) goes through the same
    lock as a checked append. It is refused unless the record links to the
    head and is later than it, so no writer path can fork the chain;
  - transaction-local `lock_timeout` 5 s, `statement_timeout` 10 s and
    `idle_in_transaction_session_timeout` 7 s (`AUDIT_CHAIN_*_TIMEOUT_MS`). The
    idle timeout is the server-side backstop that releases the lock if the
    client stalls while holding it;
  - client-side bounds of 10 s / 5 s / 10 s on begin / sign / commit
    (`AUDIT_BEGIN_TIMEOUT`, `AUDIT_SIGN_TIMEOUT`, `AUDIT_COMMIT_TIMEOUT`). The
    signature runs on the tokio blocking pool (`sign_bounded`), so the timeout
    fires even for a PKCS#11 provider that blocks its thread. On failure the
    record is not written and `alert="audit_write_failed"` is logged (AU-5);
  - the audit sink refuses SLH-DSA signing keys
    (`ensure_audit_signing_algorithm`). The CA key signs audit records, so a CA
    with an SLH-DSA key fails to start (POAM-2026-10-23-34).

  Unit tests (offline, passed 2026-10-25): `sign_timeout_fires_for_blocking_signer`
  (multi- and current-thread runtimes), `bounded_sign_succeeds_within_timeout`
  and `idle_in_transaction_timeout_exceeds_sign_timeout`. Status:
  **Implemented, not Tested** on Postgres. The opt-in tests
  `crates/ostrich-audit/tests/chain_concurrency.rs`, `signed_chain_tamper.rs`
  and `sign_timeout_db.rs` have **not been executed** against a database.
  Without `OSTRICH_DB_TESTS=1` they skip and are reported as passed, so those
  results are not evidence. With the opt-in they now fail if the database is
  unreachable, so a green GitLab `test:integration` job (which sets it) will
  be evidence once it has run (POAM-2026-10-23-31). The in-memory
  `MemoryAuditSink` concurrency test is not evidence for the database path.
  Residuals: signing still happens under the global lock, so signer latency
  serialises every audit writer of every service. A hung HSM call cannot be
  cancelled, so each timeout leaves one blocking-pool thread busy until the
  HSM returns. That can stall shutdown until the pod is killed, and a long
  outage can fill the blocking pool (SEC-017)
- 🔴 No explicit deletion prevention (needs database permissions)
- 🔴 No access control on audit queries

**Gaps:**

- Database permissions not configured in code
- Any database user can query audit_events table
- Concurrent-append correctness on Postgres not yet demonstrated
  (POAM-2026-10-23-31)

**Remediation:** Phase 15 - Add database migration to REVOKE DELETE/UPDATE on audit_events table

**Evidence Required for ATO:**

- Database permission configuration
- Audit protection test results

---

### AU-9(3): Cryptographic Protection

**Control:** The information system implements cryptographic mechanisms to protect the integrity of audit information.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- FAU_GEN.1(d) - Hash chain for integrity

**Implementation:**

- [crates/ostrich-audit/src/event.rs](../../crates/ostrich-audit/src/event.rs) - Hash chain fields (previous_hash, event_hash) and SHA-256 `compute_hash()`
- [crates/ostrich-audit/src/sink.rs](../../crates/ostrich-audit/src/sink.rs) - `DatabaseAuditSink::record()` links `previous_hash` BEFORE hashing so the chain link is covered by `event_hash`
- [crates/ostrich-db/src/repository/audit.rs](../../crates/ostrich-db/src/repository/audit.rs) - `verify_chain()` recomputes every event hash and checks continuity; `append()` is a checked append under the chain lock (since 2026-10-25: refused unless it links to the current head and is later than it)
- Signed verification: `DatabaseAuditSink::verify_signed_chain()` (see AU-10)

**Evidence:**

- ✅ Each audit event includes hash of previous event
- ✅ Chain integrity verifiable end-to-end (`verify_chain()` / `verify_integrity()`)
- ✅ SHA-256 hashing (FIPS 180-4)
- ✅ Live integrity test against Postgres: [crates/ostrich-audit/tests/signed_chain_tamper.rs](../../crates/ostrich-audit/tests/signed_chain_tamper.rs) (earlier result; since 2026-10-25 the test is opt-in, `OSTRICH_DB_TESTS=1`, and no run of the current version is recorded)

**Integrity fixes (chain now verifiable for DB-backed sinks):**

- Timestamp precision: `record()` truncates to microseconds (`trunc_subsecs(6)`) before hashing so the stored hash matches the value recomputed after the Postgres `timestamptz` round-trip (previously nanosecond `Utc::now()` made every DB-backed hash unverifiable).
- Chain linkage: the sink now sets `previous_hash` before computing `event_hash` (previously the hash was computed with `previous_hash=None` while the verifier recomputed with the stored link, so verification failed for every event after the first).
- **Concurrent appends (2026-10-25, branch `claude/grpc-mtls`, uncommitted;
  NIST-002):** read-link-hash-sign-insert now runs in one transaction under
  `pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)` (`AuditRepository::begin_append`),
  shared by every service that writes the chain. **Implemented; Tested is
  pending** a Postgres run of `crates/ostrich-audit/tests/chain_concurrency.rs`
  and `sign_timeout_db.rs` (not executed: they skip without
  `OSTRICH_DB_TESTS=1`; POAM-2026-10-23-31). The lock is held across the audit
  signature. The wait is bounded by the 5 s sign timeout (blocking pool) and by
  the 7 s `idle_in_transaction_session_timeout` backstop, with lock and
  statement timeouts on the transaction. See AU-9
- Upgrade note: a rolling upgrade can run old (unlocked) and new pods side by
  side and fork the chain. Stop all audit writers (Recreate strategy, or scale
  to 0) before starting the new version, then run the chain verification
  (`GET /api/v1/audit/verify`)

**Evidence Required for ATO:**

- Hash chain algorithm specification ✅ (documented above)
- Integrity verification test results ✅ (signed_chain_tamper.rs passes against live DB)

---

### AU-10: Non-repudiation

**Control:** The information system protects against an individual falsely denying having performed a particular action.

**Implementation Status:** 🟢 **Compliant** (mechanism + production wiring)

**NIAP Mapping:**

- FCO_NRO_EXT.2 - Proof of Origin
- FDP_CER_EXT.2 - Certificate Request Matching

**Implementation:**

- Digital signatures on all issued certificates, CRLs, OCSP responses
- Audit trail with actor identity
- **Signed audit records**: each record's `event_hash` is signed with a key an attacker does not hold, making the audit trail tamper-evident even against database write access (the SHA-256 chain alone is not — an attacker can recompute it).
  - [crates/ostrich-audit/src/sink.rs](../../crates/ostrich-audit/src/sink.rs) - `DatabaseAuditSink::with_signing_key()` signs `event_hash` at write time; `verify_signed_chain(spki, algorithm)` verifies the chain AND every record's signature
  - [migrations/00007_audit_signature.sql](../../migrations/00007_audit_signature.sql) - `signature`, `signing_key_id` columns (nullable; signing is opt-in)
  - **Production wiring**: [crates/ostrich-ca/src/ca.rs](../../crates/ostrich-ca/src/ca.rs) - `CertificateAuthority::new` constructs signed sinks for both the issuer and revocation manager, signing each audit record's `event_hash` with the HSM-backed CA key. Relying parties verify with the CA certificate's public key (already published).

**Evidence:**

- ✅ All CA-signed objects provide proof of origin
- ✅ Audit events link actions to actors
- ✅ **Live tamper-detection proof (mechanism)**: [crates/ostrich-audit/tests/signed_chain_tamper.rs](../../crates/ostrich-audit/tests/signed_chain_tamper.rs) writes signed records to Postgres, forges the last record's content and recomputes its `event_hash` (which fools the hash-only `verify_chain`), and shows `verify_signed_chain` still detects it because the stale signature no longer verifies over the forged hash.
- ✅ **Live end-to-end proof (production wiring)**: [crates/ostrich-ca/src/audit_signing_e2e.rs](../../crates/ostrich-ca/src/audit_signing_e2e.rs) builds a `CertificateAuthority` backed by a SoftHSM (PKCS#11) ECDSA key, performs a real revocation, and asserts the resulting audit record is signed (`signature` non-null, `signing_key_id` = CA key) and that `verify_signed_chain` accepts it against the CA public key — and rejects it after a signature byte is corrupted.
- 🟡 **RSA PKCS#11 CA keys (added 2026-10-23, NIST-005):** audit records are signed with `ca_key.algorithm` ([crates/ostrich-ca/src/ca.rs](../../crates/ostrich-ca/src/ca.rs), `CertificateAuthority::new`). For an RSA key generated through `Pkcs11Provider` that algorithm is `RsaPssSha256`. Before the 2026-10-23 fix, PKCS#11 RSA-PSS `C_Sign` failed (`CKR_GENERAL_ERROR`), so **audit-record signing with an RSA PKCS#11 CA key did not work**. X.509 certificate, CRL and OCSP signing with RSA CA keys uses PKCS#1 v1.5 (`recommended_signature_algorithm`, [crates/ostrich-x509/src/signing.rs](../../crates/ostrich-x509/src/signing.rs)) and was not affected. The provider fix is verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654): 28 passed / 0 failed / 1 ignored, exit 0) and SoftHSM 2.7.0 (local, 28/0/1); POAM-2026-10-23-17 closed 2026-10-23. SoftHSM is a test double; the production HSM is not yet validated (POAM-2026-10-23-21). `audit_signing_e2e` covers an EC P-256 CA key only; there is no RSA variant yet, so this bullet stays 🟡
- 🟡 **CA gRPC actor in signed records (2026-10-26, branch
  `claude/grpc-per-method-authz`, uncommitted):** the signed issuance,
  revocation and CRL records for gRPC calls now name the verified mTLS peer
  as actor, with its certificate issuer and serial, instead of the
  client-asserted `requestor` (see AU-3; POAM-2026-10-23-25 closed pending
  commit). `audit_signing_e2e` now also asserts actor `CN=ops-admin` and
  `on_behalf_of = admin::audit-e2e` on the signed revocation record, but that
  test needs Postgres and SoftHSM and was **NOT RUN** for this change
  (POAM-2026-10-23-36). The mechanism status above is unchanged
- 🔴 No CSR→Certificate linkage (missing request_id)

**Gaps / POA&M:**

- `on_behalf_of` on gRPC records is a namespace-bound claim of the RA, not a
  verified ACME account or EST client (POAM-2026-10-23-35)
- Cannot prove which CSR led to which certificate (Phase 15 - add request_id to certificates table)
- Audit records are signed with the CA key itself, and since 2026-10-25 the audit sink refuses SLH-DSA signing keys (`ensure_audit_signing_algorithm` in [sink.rs](../../crates/ostrich-audit/src/sink.rs); signing runs under the audit chain lock), so a CA with an SLH-DSA key cannot run ca-server. Decoupling the audit signing key (dedicated ML-DSA or ECDSA key; `signing_key_id` already records the key per row) is POAM-2026-10-23-34. Currently moot: no provider signs SLH-DSA
- No end-to-end test of signed audit records with an RSA (RSA-PSS) PKCS#11 CA key (NIST-005, follow-up). The RSA-PSS provider fix now has Linux CI evidence ([run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654); POAM-2026-10-23-17 closed 2026-10-23), but AU-10 with RSA HSM CA keys is demonstrated at the provider level on SoftHSM only, not end to end

**Evidence Required for ATO:**

- Non-repudiation mechanisms documentation ✅ (signed audit records documented above)
- Digital signature verification procedures ✅ (`verify_signed_chain` + signed_chain_tamper.rs)

---

### AU-12: Audit Generation

**Control:** The information system provides audit record generation capability.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- FAU_GEN.1 - Audit Data Generation

**Implementation:**

- [crates/ostrich-audit/src/lib.rs:25-85](../../crates/ostrich-audit/src/lib.rs#L25-L85) - `AuditLogger` implementation
- [crates/ostrich-audit/src/sink.rs](../../crates/ostrich-audit/src/sink.rs) - Database and console sinks

**Evidence:**

- ✅ Audit logger available to all services
- ✅ Database persistence
- ✅ Real-time emission
- ✅ CA gRPC listener (2026-10-25): handshake failures, access denials,
  listener start and the debug-only plaintext mode generate records (event
  list under AU-2). `start_grpc_listener` takes an injected `AuditSink`, and
  the ca-server bin tests assert the `grpc_listener_started` and
  `grpc_insecure_dev_plaintext_enabled` record contents with
  `MemoryAuditSink` (9 ca-server bin tests passed 2026-10-25)
- ✅ CA gRPC per-method authorization (2026-10-26, branch
  `claude/grpc-per-method-authz`, uncommitted): method-table, admin-issuer,
  requestor and profile denials generate `access_denied` records through the
  listener's rate limiter before the response (including from the service,
  via `AuthorizedGrpcPeer::deny`), and an authorization-layer build failure
  generates `grpc_listener_refused` (`check=grpc_authorization_layer`) with no
  `grpc_listener_started`. Tests: `qa_layer_denies_and_audits_unmapped_paths`,
  `peer_deny_record_survives_dropped_future`, e2e
  `requestor_denial_audit_is_cancel_proof`, bin
  `start_grpc_listener_refusal_is_audited_without_started_record`
  (ca-server bins 21/21, `grpc_mtls_e2e` 39/39, 2026-10-26)

**Evidence Required for ATO:**

- Audit generation architecture diagram
- Audit event catalog

---

## Configuration Management (CM)

### CM-2: Baseline Configuration

**Control:** The organization develops, documents, and maintains a current baseline configuration.

**Implementation Status:** 🟡 **Partial**

**Implementation:**

- [CLAUDE.md](../../CLAUDE.md) - Project development guidance
- [ROADMAP.md](../../ROADMAP.md) - Implementation phases and status
- Configuration planned via environment variables and TOML files

**Evidence:**

- ✅ Code baseline in git version control
- ✅ Database schema migrations tracked
- ✅ Dependency baseline pinned in `Cargo.lock`; changes recorded in [CHANGELOG.md](../../CHANGELOG.md)
- 🟡 **Build toolchain and crypto-module baseline (recorded 2026-10-23):**
  - Toolchain: pinned to rustc **1.99.1** by
    [rust-toolchain.toml](../../rust-toolchain.toml) (components `rustfmt`,
    `clippy`; profile `minimal`). Workspace MSRV is unchanged at
    `rust-version = "1.94"`. GitHub CI installs the pinned toolchain with
    `rustup toolchain install` (the floating `dtolnay/rust-toolchain@stable`
    was removed). Both Dockerfiles and the GitLab `.rust-base` job use
    `rust:1.99.1-bookworm`. The CI job `Toolchain pin consistency`
    ([.github/workflows/ci.yml](../../.github/workflows/ci.yml)) fails if any
    tracked `*Dockerfile*` or `.gitlab-ci.yml` names a `rust:` image that does
    not start with `rust:<channel>-` (local positive and negative checks:
    `fixes-round-1.md`, 18 cases). Change not yet merged; branch
    `claude/ci-hardening`.
  - **Pin inventory (CI tooling, 2026-10-23):** cargo-audit **0.22.2** and
    cargo-deny **0.20.2** (GitHub: `taiki-e/install-action` at a pinned SHA
    with checksum-verified manifests and `fallback: none`; GitLab:
    `cargo install --locked --version`); GitHub runners `ubuntu-24.04`. Every
    `uses:` in `ci.yml`, `audit.yml` and `hsm-integration.yml` is a full commit
    SHA: `actions/checkout` v7.0.1 `3d3c42e5…`, `Swatinem/rust-cache` v2.9.3
    `d1527c8f…`, `taiki-e/install-action` v2.87.31 `1e29709c…`,
    `actions/setup-node` v4.4.0 `49933ea5…`, `actions/upload-artifact` v4.6.2
    `ea165f8d…`. Container images are tag-pinned (`rust:1.99.1-bookworm`), not
    digest-pinned. Not covered: `docker-publish.yml`, `cargo-chef` and several
    GitLab tools and images (POAM-2026-10-23-15).
  - FIPS cryptographic module: **AWS-LC FIPS 4.2.0** built from source by
    `aws-lc-fips-sys` **0.14.2** (previously AWS-LC FIPS 3.3.0 via 0.13.14),
    reached through `aws-lc-rs` 1.18.2 (`fips` feature). TLS: `rustls` 0.23.46,
    `rustls-webpki` 0.103.16. CMVP certificate for 4.2.0 pending
    confirmation (POA&M, see [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md#fips-140-2--fips-140-3-security-requirements-for-cryptographic-modules)).
  - Module-source pin: [.cargo/config.toml](../../.cargo/config.toml) sets
    `AWS_LC_FIPS_SYS_USE_SYSTEM = "0"` (`force = true`) so the build uses the
    bundled, `Cargo.lock`-pinned module and never auto-links a system AWS-LC
    (see CM-6). The file is committed on `main` (commit 05ea47a, PR #180).
- 🔴 No deployment baseline configuration documented

**Gaps:**

- No formal configuration baseline documentation
- No configuration item inventory (the CI pin inventory above covers build tooling only)
- `docker-publish.yml`, `cargo-chef` and several GitLab tools and images are not version- or SHA-pinned (POAM-2026-10-23-15)
- The pin inventory is not yet merged to `main` and no CI run has executed it

**Remediation:** Phase 16 - Document baseline configuration for production deployment

**Evidence Required for ATO:**

- Configuration baseline document
- Configuration item list
- Change control procedures

---

### CM-3: Configuration Change Control

**Control:** The organization implements change control procedures for changes to the information system.

**Implementation Status:** 🟡 **Partial**

**Implementation:**

- Git version control for all code changes
- Database migrations for schema changes
- AI-assisted multi-role review workflow ([.claude/skills/ostrich-workflow/SKILL.md](../../.claude/skills/ostrich-workflow/SKILL.md)):
  each change is planned, implemented, tested, and independently reviewed by
  security, NIST 800-53/NIAP, PQC/FIPS crypto, and RFC conformance roles before
  a recorded PASS/FAIL gate (role definitions in [.claude/agents/](../../.claude/agents/))

**Evidence:**

- ✅ All code changes tracked in git
- ✅ Database migrations numbered and ordered
- 🟡 Per-change review record (`gate.md`, `findings-*.md`) produced by the
  workflow; it is a developer-side review aid, not a substitute for human
  change approval
- 🔴 No formal change approval process
- 🟡 **Crypto-module changes need PQC/FIPS review:** any change to
  `aws-lc-fips-sys`, `aws-lc-rs`, or the rustls crypto provider changes the
  FIPS 140-3 module or its boundary. Such a change must be reviewed by the
  PQC/FIPS crypto role (FIPS-mode and self-test behaviour) and approved by
  the user before merge, and must be recorded in
  [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md).
- 🟡 **CM-4 (Impact Analyses) note, 2026-10-23:** the module change AWS-LC
  FIPS 3.3.0 → 4.2.0 (`aws-lc-fips-sys` 0.13.14 → 0.14.2) was required by the
  rustls/rustls-webpki advisory fixes. Its security impact was analysed by the
  PQC/FIPS reviewer (FIPS build from source confirmed, `fips()` logic and
  ML-KEM code unchanged, ML-DSA newly verifiable in TLS). The user approved the
  change on 2026-10-23, and on the same day accepted ML-DSA signature
  verification in TLS. The record is in the run directory
  `target/agent-workflow/20261023-185030-audit-advisories/` (`brief.md`,
  `fix-request-round-1.md`, `findings-pqc.md`). No separate CM-4 section exists
  in this document yet.

**Gaps:**

- No change control board
- No formal change request process
- No rollback procedures documented

**Remediation:** Document change control procedures in ATO package

---

### CM-6: Configuration Settings

**Control:** The organization establishes and documents configuration settings.

**Implementation Status:** 🟡 **Partial**

**Implementation:**

- [crates/ostrich-common/src/config.rs](../../crates/ostrich-common/src/config.rs) - Configuration structures
- Environment variables for deployment-specific settings

**Evidence:**

- ✅ Configuration structures defined
- ✅ **Build setting `AWS_LC_FIPS_SYS_USE_SYSTEM = "0"`** in
  [.cargo/config.toml](../../.cargo/config.toml) (`[env]`, `force = true`):
  keeps the FIPS module identity fixed to the bundled AWS-LC FIPS 4.2.0 source
  build (also SC-13, SI-7). Verified 2026-10-23: the `aws-lc-fips-sys` build
  output shows `Environment Variable found 'AWS_LC_FIPS_SYS_USE_SYSTEM': '0'`
  and `Building with: CMake` (`fixes-round-1.md`). Limits: `force = true`
  overrides a plain environment value but not the target-suffixed
  `AWS_LC_FIPS_SYS_USE_SYSTEM_<target>` variable, and the file is not yet
  committed.
- 🟡 Container builds: the working tree also sets
  `ENV AWS_LC_FIPS_SYS_USE_SYSTEM=0` in the builder stages of `Dockerfile` and
  `services/web-ui/Dockerfile`, because `.cargo/` is not copied into those
  stages. No container build was run on 2026-10-23 (Docker not available), so
  this is not verified.
- ✅ **CA gRPC configuration baseline (2026-10-25, branch `claude/grpc-mtls`,
  uncommitted).** Secure defaults, validated at startup before the database
  connects (`GrpcServerOptions::resolve` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)):

  | Service | Env / CLI | Default | Behaviour |
  |---------|-----------|---------|-----------|
  | ca-server | `CA_GRPC_TLS_CERT_FILE` / `--grpc-tls-cert` | none | server chain PEM |
  | ca-server | `CA_GRPC_TLS_KEY_FILE` / `--grpc-tls-key` | none | server key PEM |
  | ca-server | `CA_GRPC_TLS_CLIENT_CA_FILE` / `--grpc-tls-client-ca` | none | required; must be a dedicated service-identity CA (startup refuses an anchor with this CA's issuing SPKI or subject, issued by it, its issuer, or matching a CA-database ancestor; refusal audited as `grpc_listener_refused`; warns on more than one anchor) |
  | ca-server | `CA_GRPC_ACME_CLIENT_SUBJECTS` / `--grpc-acme-client-subjects` | none (compose / Helm / kustomize / `.env.example`: `CN=acme-server`) | Issuer, namespace `acme`; `;`-delimited RFC 4514 DNs; blank = no subjects; dangling or ambiguous escapes and undecodable numeric OIDs refused (2026-10-26) |
  | ca-server | `CA_GRPC_EST_CLIENT_SUBJECTS` / `--grpc-est-client-subjects` | none (deployments: `CN=est-server`) | Issuer, namespace `est`; same syntax; ACME and EST both empty ⇒ refuse to start |
  | ca-server | `CA_GRPC_ADMIN_CLIENT_SUBJECTS` / `--grpc-admin-client-subjects` | **empty** | Admin, namespace `admin`; non-empty requires exactly one distinct client trust anchor with an SKI, and admin leaves issued directly by it |
  | ca-server | `CA_GRPC_ACME_ALLOWED_PROFILES` / `--grpc-acme-allowed-profiles` | `acme-default` | unknown or CA profile, or empty while ACME subjects exist ⇒ refuse to start |
  | ca-server | `CA_GRPC_EST_ALLOWED_PROFILES` / `--grpc-est-allowed-profiles` | `tls_client;tls_server;tls_server_client;efs` | same rules |
  | ca-server | `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` (removed; hidden flag) | unset | any non-blank value ⇒ refuse to start with a migration message (Helm key fails rendering) |
  | ca-server | `CA_GRPC_INSECURE_DEV_PLAINTEXT` / `--grpc-insecure-dev-plaintext` | `false` | debug builds only; refused in release builds; refused together with any TLS option or role list (ambiguous) |
  | acme-server, est-server | `CA_GRPC_CLIENT_CERT_FILE`, `CA_GRPC_CLIENT_KEY_FILE`, `CA_GRPC_CA_CERT_FILE` | none | all or none; none ⇒ plaintext refused unless the dev flag is set in a debug build |
  | acme-server, est-server | `CA_GRPC_SERVER_NAME` | URL host | TLS server name to verify |
  | acme-server | `CA_GRPC_INSECURE` / `--ca-insecure` | `false` | refused in release builds |
  | est-server | `CA_GRPC_INSECURE` / `--ca-insecure` / file `caInsecure`, and the loopback plaintext exception | `false` | both refused in release builds |

  Values are file paths and DNs only, never secrets. Refusals are unit- and
  bin-tested (`grpc_defaults_refuse_to_start`,
  `grpc_insecure_flag_is_debug_only`,
  `grpc_insecure_with_allowlist_is_ambiguous`,
  `grpc_client_ca_must_not_be_the_issuing_ca` in ca-server; `plan_channel`
  release-plaintext test in `grpc_client.rs`; `plaintext_policy_is_debug_only`
  in `ostrich-est`; `ca_insecure_allowed` test in acme-server; since
  2026-10-26 also `grpc_legacy_allowed_subjects_refuses_to_start`,
  `grpc_overlapping_role_lists_refuse_to_start`,
  `grpc_blank_role_values_are_no_subjects`, `grpc_profile_lists_refuse_to_start`,
  `grpc_admin_requires_single_client_anchor` and
  `start_grpc_listener_refusal_is_audited_without_started_record`; ca-server
  bins 21/21). A subject in two role lists (also differing only in ASCII
  case) refuses startup. Deployment
  wiring: Helm `ca.grpc.*`, `acme.caGrpc.*`, `est.caGrpc.*` (secrets required;
  rendering fails without them), kustomize base, compose files and
  `.env.example`. Exact startup messages are in
  [docs/runbooks/ca-grpc-mtls.md](../runbooks/ca-grpc-mtls.md)
- 🔴 No documented secure baseline settings for the other services

**Gaps:**

- Default configuration values not security-hardened
- No configuration validation on startup (outside the CA gRPC and TLS settings)
- ~~`docker-compose.yml` `./certs` exposure of the dev gRPC keys~~:
  remediated 2026-10-25 in the working tree by moving the generator's default
  output to `.dev-grpc-certs/`, outside the wholesale `./certs` mount
  (POAM-2026-10-23-32, closed pending commit)

**Remediation:** Phase 16 - Document secure configuration baselines

**Evidence Required for ATO:**

- Configuration settings guide
- Security configuration checklist
- Configuration validation test results

---

### CM-7: Least Functionality

**Control:** The organization configures the system to provide only essential capabilities and prohibits or restricts functions, ports, protocols, software and services that are not needed.

**Implementation Status:** 🟡 **Partial** (unused dependencies are being removed; one known unused dependency remains, and there is no automated unused-dependency check)

**NIAP Mapping:**

- No PP-CA SFR

**Implementation:**

- Dependencies are declared in workspace `Cargo.toml` and per-crate manifests and reviewed through the CM-3 workflow; `cargo deny check` enforces the ban, license and source policy ([deny.toml](../../deny.toml))

**Evidence:**

- ✅ 2026-10-24 dependency cleanup (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`): `openidconnect` (no call sites in `ostrich-web-ui`) removed from workspace `Cargo.toml` and `services/web-ui/Cargo.toml`, and the integration-test crate's `p256` dependency removed (the fixture now uses the software `CryptoProvider`). 28 packages left `Cargo.lock` (642 → 614 `[[package]]` entries); no production code changed. This also reduces the supply-chain surface (SR-3) and removed `crypto-bigint` 0.5.5 and its advisory (RA-5, SI-2). `cargo audit --deny warnings`, `cargo deny check`, `make test-unit` (667 / 0 / 1) and the web-ui and npe-portal `--bins` tests (19 / 0 and 30 / 0) pass locally

**Gaps:**

- `oauth2` 5.0.0 is a declared but unused dependency of `ostrich-web-ui`; its default features link `reqwest` 0.12 and enable the `rustls` `ring` feature in the web-ui binary (POAM-2026-10-23-23; `ring` paths also POAM-2026-10-23-08)
- No automated check for unused dependencies (for example `cargo machete` or `cargo udeps`) in CI
- Ports, protocols and services per deployment are not yet documented against this control

**CA gRPC (2026-10-26, branch `claude/grpc-per-method-authz`, uncommitted):**

- ✅ Only the RPCs in `CA_GRPC_METHOD_RULES`
  ([grpc_authz.rs](../../crates/ostrich-ca/src/grpc_authz.rs)) are reachable,
  each only for its roles; any other path (future RPCs, health, reflection,
  case or encoding variants) is denied `method_not_mapped`. Tests:
  `rules_cover_every_proto_rpc` (ties the table to `proto/ca_service.proto`),
  `qa_authorize_peer_non_canonical_paths_are_not_mapped`, e2e
  `qa_unmapped_path_variants_denied_over_the_wire`
- ✅ Issuer clients may request only the end-entity profiles listed for their
  namespace; CA profiles are never issuable over gRPC (see AC-6(10))
- ✅ The plaintext dev constructor (`CaGrpcService::new_insecure_dev_plaintext`)
  exists only in debug builds; release builds refuse peerless calls
  (`grpc_service_peer_requirement_follows_mode`)

**Remediation (POA&M, see [NIAP_GAP_ANALYSIS.md §11](NIAP_GAP_ANALYSIS.md#11-plan-of-action-and-milestones-poam--open-items)):**

- Remove `oauth2` (POAM-23)

**Evidence Required for ATO:**

- Dependency inventory (SBOM) per release
- Ports, protocols and services list per service

---

## Contingency Planning (CP)

### CP-9: System Backup

**Control:** The organization conducts backups of information system documentation, software, and data.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- Operational environment responsibility

**Implementation:**

- Database supports standard PostgreSQL backup tools
- KRA supports key escrow and recovery

**Evidence:**

- ✅ Database backup capability via `pg_dump`
- ✅ KRA module for cryptographic key backup/recovery
- 🔴 No documented backup procedures

**Gaps:**

- No automated backup scheduling
- No backup verification procedures
- No offsite storage

**Remediation:** Document backup procedures in deployment guide (operational environment)

**Evidence Required for ATO:**

- Backup procedures documentation
- Backup frequency schedule
- Backup test/restore procedures

---

### CP-10: Information System Recovery and Reconstitution

**Control:** The organization provides for the recovery and reconstitution of the information system.

**Implementation Status:** 🔴 **Not Implemented**

**Implementation:**

- None documented

**Gaps:**

- No disaster recovery plan
- No recovery time objective (RTO) defined
- No recovery point objective (RPO) defined
- No tested recovery procedures

**Remediation:** Document recovery procedures in ATO package (operational environment)

**Evidence Required for ATO:**

- Disaster recovery plan
- Recovery procedures
- Recovery test results

---

## Identification and Authentication (IA)

### IA-2: Identification and Authentication (Organizational Users)

**Control:** The information system uniquely identifies and authenticates organizational users.

**Implementation Status:** ✅ **Implemented (password-based)**

**NIAP Mapping:**

- FIA_UAU_EXT.1 - Authentication Mechanism
- FIA_UIA_EXT.1 - User Identification and Authentication
- FIA_AFL.1 - Authentication Failure Handling

**Implementation:**

- `crates/ostrich-common/src/auth/password.rs` - `PasswordAuthProvider`:
  Argon2id verification (RFC 9106), account-status enforcement, lockout
  integration, bearer-token sessions
- `crates/ostrich-db/src/repository/users.rs` - `DbUserRepository` against the
  `users` table (migration 00003): unique UUID identifiers (FIA_UID.1),
  failed-attempt counter with atomic 15-minute lock at 5 failures (AC-7)
- `crates/ostrich-common/src/auth/routes.rs` - shared
  `POST /api/v1/auth/login` / `logout` endpoints; error responses do not
  enumerate accounts (SI-11)
- Wired into ca-server and scms-server (replaces the fail-closed
  `DisabledAuthProvider` placeholder)
- `crates/ostrich-common/src/auth/basic.rs` - EST HTTP Basic authentication
  (RFC 7030 §3.2.3): `Authorization: Basic` credentials are verified through the
  same `PasswordAuthProvider` (Argon2id + lockout). `MtlsOrBasicAuthLayer`
  prefers the TLS client certificate and falls back to Basic for bootstrap
  enrollment; the est-server only enables it alongside `--tls-ca-cert` (SC-8:
  Basic never offered without TLS)
- `crates/ostrich-est/src/device_cert.rs` - `EstDeviceCertAuthProvider`
  (RFC 7030 §3.3 re-enrollment, AC-17 / AC-6): a device re-enrolling over mTLS
  is identified by the certificate it presents. The certificate is matched by
  exact DER against the certificate store, rejected if revoked/expired, and
  resolved to the `client_identifier` of its issuing enrollment; the device is
  then authenticated as a least-privilege `EstDevice` principal whose only
  permission is `RenewCertificate`. No user-table account is required, so a
  token-bootstrapped device can renew its own certificate and nothing else
  (fail-secure on any unrecognised/invalid certificate)
- Initial Administrator provisioned via
  `ostrich-init --admin-username/--admin-password` (CM-6: the previous
  hardcoded seed user was removed from migration 00003)
- **Live evidence**: login → 200 + token; no token → 401; Administrator
  token on `GET /api/v1/profiles` → 200 (ViewConfig); same token on
  `POST /api/v1/certificates` → 403 (AC-5 separation of duties); 5 bad
  passwords → locked (403, timed); logout → token invalid (401)
- **NPE operator identity via the trusted-proxy bridge**: NPE operators
  authenticate to the portal with their mTLS client certificate; the portal
  resolves the role from the cert's policy OIDs and forwards the identity to the
  CA over its own mTLS channel (`TrustedProxyAuthLayer`). The CA honours the
  forwarded identity ONLY from the allow-listed portal subject and only for
  bridgeable NPE roles. Live: portal cert + `caa_admin` → 200; no portal cert
  → 401; portal cert + `pki_sponsor` on a CAA route → 403

**Gaps:**

- Certificate-based (mTLS) user authentication: provider exists but subject
  DN extraction is a placeholder
- Multi-factor authentication for privileged users

**Closed:** Sessions are now persisted in Postgres (`DbSessionStore`,
migrations 00003 + 00011); they survive a restart and are shared across
instances, with the database as the single source of truth. See AC-12 / SC-23.

**Remediation:** mTLS DN extraction + MFA tracked as follow-ups

**Evidence Required for ATO:**

- ✅ Authentication mechanism description (this section + code references)
- ✅ User identification procedures (unique UUIDs, ostrich-init provisioning)
- ⏳ Multi-factor authentication for privileged users

---

### IA-3: Device Identification and Authentication

**Control:** The information system uniquely identifies and authenticates defined devices and/or types of devices before establishing a connection.

**Implementation Status:** 🟡 **Partial** (added 2026-10-25; scoped to the CA gRPC issuance channel)

**NIAP Mapping:**

- FIA_X509_EXT.1 - X.509 Certificate Validation (revocation is a gap)
- FCS_TLSS_EXT.2 / FCS_TLSC_EXT.2 - TLS with mutual authentication
- FTP_ITC.1 - Inter-TSF Trusted Channel
- FMT_SMR.2 - Security Roles (gRPC Issuer / Admin identities, 2026-10-26)

Related: IA-9 (Service Identification and Authentication), cited with IA-3 in
the code annotations since 2026-10-26.

**Implementation:**

- The ca-server gRPC listener authenticates each connecting service
  (acme-server, est-server) by its X.509 client certificate before any RPC
  runs: `WebPkiClientVerifier` on the aws-lc-rs FIPS provider, mandatory
  client authentication, path validation to `CA_GRPC_TLS_CLIENT_CA_FILE`,
  validity period and EKU (`grpc_server_config` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)). The service is
  then identified by its exact subject DN against the three role lists
  (2026-10-26), which fix its role and requestor namespace, and the leaf must
  carry an EKU extension with `clientAuth` (`authorize_peer_at`). The leaf
  validity period is re-checked on every call (RFC 5280 §4.1.2.5;
  `certificate_not_valid_now`, `UNAUTHENTICATED`), so a long-lived HTTP/2
  connection cannot outlive the leaf; intermediates and the anchor are checked
  at the handshake only. An Admin identity is accepted only for a leaf issued
  directly by the single client trust anchor (issuer DN = anchor subject and
  AKI = anchor SKI; `admin_issuer_not_anchor`), and ca-server refuses to start
  with admin subjects and more than one distinct anchor or an anchor without
  SKI. The verified peer subject, issuer and serial become the audit identity
  (AU-3).
- Trust-anchor separation: after the CA loads, ca-server walks the issuing
  CA's ancestors in the CA database (`walk_ca_ancestors` over
  `ca_certificates.parent_ca_id`; fails closed on a missing row, a cycle or
  depth > 16) and refuses to start the listener if any anchor in the client-CA
  file has the issuing certificate's SPKI or **subject (subject alone)**, was
  **issued by** the issuing CA (issuer name, or AKI = issuing SKI), is its
  issuer, or matches (SPKI or subject) a database ancestor
  (`ensure_dedicated_client_ca`). Each refusal is audited as
  `grpc_listener_refused` before exit (`check_grpc_trust_anchors` in
  [main.rs](../../services/ca-server/src/main.rs)). It warns when the file
  holds more than one anchor. Per call, a leaf whose issuer DN or AKI matches
  the issuing CA or a database ancestor is denied (`subscriber_issuing_ca`,
  `SubjectAllowlistLayer::with_subscriber_issuing_cas`). Without this, any subscriber certificate with an
  allow-listed subject (for example `CN=est-server` enrolled over EST) would
  identify as that service.
- The clients authenticate the CA server: certificate chain to
  `CA_GRPC_CA_CERT_FILE` and server name (URL host or `CA_GRPC_SERVER_NAME`)
  (`grpc_client_config`, `GrpcTlsConnector`).

**Evidence:**

- ✅ `grpc_mtls_e2e` 21/21 passed 2026-10-25 (re-run by the compliance scribe
  on the final working tree): `allowed_subject_issue_ok`,
  `no_client_cert_handshake_fails`, `untrusted_ca_client_cert_handshake_fails`,
  `server_only_eku_client_cert_rejected`,
  `leaf_without_eku_is_permission_denied`,
  `disallowed_subject_permission_denied_and_audited`,
  `client_rejects_server_name_mismatch`
- ✅ ca-server bin tests `grpc_client_ca_must_not_be_the_issuing_ca`,
  `walk_ca_ancestors_follows_parent_ca_id_and_fails_closed` and
  `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal` (13 ca-server
  bin tests passed, coder-reported after round 3), and the `grpc_tls` unit
  tests `dedicated_client_ca_refuses_chain_relatives`,
  `issued_by_checks_cover_name_and_key_id_independently` and
  `authorize_peer_refuses_subscriber_issuing_ca_leaf` (41 `grpc_tls::tests`
  passed 2026-10-25, re-run by the compliance scribe)
- ✅ Per-method change (2026-10-26, branch `claude/grpc-per-method-authz`,
  uncommitted; final tree after the nit pass): `grpc_tls` unit tests 66/66
  (`authorize_peer_refuses_leaf_outside_validity`,
  `admin_requires_leaf_issued_directly_by_anchor`,
  `layer_admin_anchor_builder_and_denial`,
  `resolve_refuses_admin_with_several_client_anchors`,
  `authorize_peer_records_issuer_and_serial`); `grpc_mtls_e2e` 39/39
  (`certificate_expiring_on_live_connection_is_refused`,
  `admin_under_intermediate_is_refused`); ca-server bins 21/21
  (`grpc_admin_requires_single_client_anchor`); mutations M20, M21, M23, M24,
  M28 killed. Counts are coder-reported from the final tree (`fixes-nits.md`)

**Gaps:**

- No revocation checking of client certificates (no CRL in the verifier;
  same on REST mTLS) (POAM-2026-10-23-27). Compensating control in the
  runbook: remove the subject from its role list and reissue under a new
  subject, or rotate the service-identity CA; admin certificates short-lived,
  one per named operator
- Issuer-role entries are not bound to an issuer or SPKI
  (POAM-2026-10-23-28; Admin entries are bound to direct issuance by the
  single anchor)
- Per-call validity covers the leaf only
- The trust-anchor guard covers the issuing CA's database lineage only.
  Sibling subordinate CAs, grandchildren (CAs issued by a subordinate of this
  CA; the per-call check compares the leaf's direct issuer only) and an
  external root not stored in `ca_certificates` are not detected if placed in
  the client-CA file. The dedicated service-identity CA is an operator
  responsibility (ADMIN_GUIDE, runbook A1; residual tracked in
  POAM-2026-10-23-28). The guard runs after
  the database connects and the CA loads, unlike the gRPC configuration checks,
  which run before the database
- The REST trusted-proxy bridge (`CA_TRUSTED_PROXY_SUBJECTS`) uses the same
  subject-only pattern without the trust-anchor check (POAM-2026-10-23-33)
- Only the CA gRPC channel is covered; other inter-service links are out of
  scope of this change

---

### IA-5: Authenticator Management

**Control:** The organization manages information system authenticators.

**Implementation Status:** 🟡 **Partial**

**NIAP Mapping:**

- FIA_PMG_EXT.1 - Password Management
- FCS_CKM_EXT.4 - Cryptographic Key Destruction
- FIA_X509_EXT.1 - X.509 Certificate Validation

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Zeroizing for cryptographic authenticators
- Certificate validation stub ([parser.rs:96-99](../../crates/ostrich-x509/src/parser.rs#L96-L99))

**Evidence:**

- ✅ Cryptographic key material properly zeroized
- 🟡 IA-5(2) PKI-based authentication on the CA gRPC channel (2026-10-25):
  path validation to a configured anchor, validity and EKU through rustls-webpki
  on the aws-lc-rs FIPS provider; no revocation checking
  (POAM-2026-10-23-27). gRPC client private keys are read into
  `Zeroizing<String>` (`read_private_key_pem` in
  [grpc_client.rs](../../crates/ostrich-common/src/grpc_client.rs)) and
  `GrpcClientConfig`'s `Debug` redacts them (SI-12). See IA-3
- 🔴 No password management
- 🔴 Certificate validation not implemented (outside the TLS peer paths)

**Gaps:**

- No password complexity requirements
- No password change enforcement
- No certificate-based authentication

**Remediation:** Phase 16 - Implement password management per NIST SP 800-63B, certificate validation

**Evidence Required for ATO:**

- Authenticator management procedures
- Password policy documentation
- Certificate validation test results

---

### IA-7: Cryptographic Module Authentication

**Control:** The information system implements mechanisms for authentication to a cryptographic module.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- PKCS#11 authentication (SO-PIN, User-PIN)
- FIA_UAU_EXT.1 - Authentication Mechanism

**Implementation:**

- [crates/ostrich-crypto/src/pkcs11/mod.rs:58-142](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L58-L142) - PKCS#11 provider initialization with PIN authentication
- [crates/ostrich-crypto/src/pkcs11/mod.rs:155-172](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L155-L172) - Per-session authentication
- [crates/ostrich-crypto/tests/pkcs11_integration_test.rs:80-106](../../crates/ostrich-crypto/tests/pkcs11_integration_test.rs#L80-L106) - Authentication testing (`init_test_provider` user-PIN login and `test_pkcs11_provider_initialization`; positive path only)

**Evidence:**

- ✅ PKCS#11 PIN-based authentication fully implemented
- ✅ Secure PIN storage with zeroization (Arc<Mutex<Zeroizing<String>>>)
- ✅ Session-based authentication (login per operation)
- ✅ Test suite validates authentication with SoftHSM
- ✅ Automatic session logout after operations
- ✅ Error handling for invalid PINs
- ✅ Thread-safe authentication for concurrent operations

**Code Annotations:**

- `NIST 800-53: IA-7 - Cryptographic module authentication` (mod.rs:48)
- `NIST 800-53: IA-5(1) - Password-based authentication for HSM access` (mod.rs:49)
- `FIPS 140-3: User authentication required before cryptographic operations` (mod.rs:50)

**Testing:**

- Integration test: `test_pkcs11_provider_initialization()` verifies successful HSM authentication

**Evidence Required for ATO:**

- ✅ HSM authentication procedures (documented in tests/README.md)
- ⚠️  PIN management policy (production deployment guide needed)

---

## Risk Assessment (RA)

### RA-5: Vulnerability Monitoring and Scanning

**Control:** The organization monitors and scans for vulnerabilities in the system and hosted applications, analyzes scan reports, and remediates legitimate vulnerabilities in organization-defined response times.

**Implementation Status:** 🟡 **Partial** (the cargo scan fails CI on new RustSec advisories, but GitHub-only advisories and npm development-dependency or medium advisories do not fail CI, response times are not approved, and the gate is not a required check)

**NIAP Mapping:**

- No PP-CA SFR. Supports the assurance measures AVA_VAN.2 and ALC_FLR.2 ([SECURITY_TARGET.md §10](SECURITY_TARGET.md#10-assurance-measures))

**Implementation:**

- [.github/workflows/audit.yml](../../.github/workflows/audit.yml) - "dependency gate" workflow (CI hardening, 2026-10-23; branch `claude/ci-hardening`, not yet merged). Job `cargo audit` runs `cargo audit --deny warnings` (cargo-audit 0.22.2), so vulnerabilities and unmaintained, unsound or yanked warnings all fail the job. The gate fails on any new **RustSec** advisory; GitHub-only advisories (no RustSec alias) are found by Dependabot and do not fail CI (NIST-002, 2026-10-26; POAM-2026-10-23-42). Job `cargo deny` runs `cargo deny check` (cargo-deny 0.20.2: advisories, bans, licenses, sources). No `continue-on-error`. Least-privilege token (`contents: read`), `persist-credentials: false`, SHA-pinned actions
- **Scan frequency (RA-5(a)):** every pull request (no path filter), every push to `main`, weekly (Monday 06:00 UTC), and manual dispatch. GitLab: `security:audit` and `security:deny` per merge request and on `main`/`develop`; `scheduled:security-scan` (audit and deny) on pipeline schedules
- [.github/dependabot.yml](../../.github/dependabot.yml) - Dependabot dependency-update PRs, weekly, for `cargo` (workspace root), `npm` (`/services/web-ui/web` only), `github-actions` and `docker`. Dependabot alerts are currently the only source that reports GitHub-only advisories for `Cargo.lock`. The npe-portal SPA (`services/npe-portal/web`) has no Dependabot entry and no lockfile (POAM-2026-10-23-40)
- **Web UI (npm):** [.github/workflows/ci.yml](../../.github/workflows/ci.yml) job `web-ui-react` runs `pnpm audit --prod --audit-level=high` (line 96; production dependencies, high/critical only). Development/build dependencies and medium/low advisories do not fail CI; they are found by Dependabot (npm entry above, weekly). Not every JavaScript dependency tree in the repository is monitored (npe-portal, POAM-40)
- [.cargo/audit.toml](../../.cargo/audit.toml) - **authoritative risk-acceptance record** and the only exception path for the gate: 3 ignored advisories, each with a rationale and a grep-able `# POAM:` tag (RUSTSEC-2023-0071 `rsa` Marvin, POAM-09; RUSTSEC-2024-0436 `paste` and RUSTSEC-2025-0134 `rustls-pemfile`, both unmaintained, SA-22, POAM-12). [deny.toml](../../deny.toml) `[advisories].ignore` mirrors the same 3 IDs. RUSTSEC-2026-0387 (added 2026-10-23, user decision: ignore + POA&M) and RUSTSEC-2026-0097 were removed on 2026-10-24 (dependency cleanup; POAM-16 and POAM-11)

**Evidence:**

- ✅ 2026-10-23 scan of `main` @ 88c10cd: **18 vulnerabilities, 4 warnings** (baseline saved in the run record)
- ✅ 2026-10-23 scan after remediation (branch `claude/audit-advisories-clippy`): `cargo audit` with 1351 advisories loaded, 642 crates scanned, **0 vulnerabilities, 0 warnings**, exit 0 (cargo-audit 0.22.2). See SI-2 and [ATO_EVIDENCE.md §2.3](ATO_EVIDENCE.md#23-vulnerability-scan-results)
- ✅ 2026-10-23 CI-hardening branch, local run: `cargo audit --deny warnings` exit 0 (642 crates); `cargo deny check` exit 0 (`advisories ok, bans ok, licenses ok, sources ok`); ignore lists identical in both files. No unused exception (no `advisory-not-detected` / `license-not-encountered` warnings). Negative checks: each of the 4 ignores was shown load-bearing in at least one of the two tools, and removing the `aws-lc-fips-sys`, `webpki-roots` or `borrow-or-share` license exception fails `cargo deny` (`qa-report.md` gates 6-16)
- ✅ 2026-10-23, later (PKCS#11 RSA-PSS fix, same branch): RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, timing variability, published 2026-10-23) made `cargo audit --deny warnings` and `cargo deny check` fail with `Cargo.lock` unchanged. That shows the gate catches a new advisory on an unchanged lockfile. No compatible fix exists (fixed only in ≥0.7.6). After the user-approved ignore (POAM-2026-10-23-16), both commands pass locally (run record `target/agent-workflow/20261023-230002-pkcs11-rsa-pss/`, `fixes-round-1.md`)
- ✅ 2026-10-24, dependency cleanup (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`): `rand` 0.8.5 → 0.8.6, `openidconnect` removed from `ostrich-web-ui`, and the integration-test crate's `p256` dependency removed; 28 packages left `Cargo.lock` (642 → 614). `crypto-bigint` 0.5.5 and `rand` 0.8.5 are no longer in the resolved graph (`cargo tree -i … --target all -e all` → "did not match any packages"). With the RUSTSEC-2026-0097 and RUSTSEC-2026-0387 ignores removed: `cargo audit --deny warnings` exit 0 (1352 advisories, 614 crates) and `cargo deny check` exit 0; ignore lists identical (3 IDs). Re-run by the compliance scribe on 2026-10-24 with the same exit codes. Local only
- ✅ 2026-10-26, Dependabot alert remediation (branch `claude/dependabot-remediation`, uncommitted; run record `target/agent-workflow/20261026-dependabot-remediation/`): Dependabot reported 21 open alerts (GitHub API, 2026-10-26; 3 Rust, 18 npm). The 3 hickory-resolver GHSAs have no RustSec alias, and `cargo audit` on `main` @ 1294f63 did not report them. After the change: `cargo audit --deny warnings` exit 0 (1378 advisories loaded, 614 crates; final re-run) and `cargo deny check` exit 0; full `pnpm audit` (web-ui) 28 vulnerabilities (1 low / 9 moderate / 18 high) before, 2 moderate after (the two react-router advisories, POAM-2026-10-23-39). `pnpm audit --prod --audit-level=high` returned exit 0 both before and after, so it does not discriminate (NIST-003). Local only; first CI run pending. Per-advisory detail: SI-2
- ✅ 2026-10-26, react-router v7 migration (branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`): web-ui `react-router-dom` ^6.30.6 replaced by `react-router` ^7.18.1 (resolves to 7.18.4). Full `pnpm audit` (`services/web-ui/web`): **"No known vulnerabilities found"** (2 moderate before; re-run by the compliance scribe on the restacked tree, `main` @ 9fad04f plus the working-tree diff). `pnpm-lock.yaml` has no `react-router-dom`, `react-router` 6.x or `@remix-run/router`. The CI gate form (`pnpm audit --prod --audit-level=high`) is unchanged and would not have reported these medium advisories (POAM-2026-10-23-42). Local only; after merge, the Dependabot auto-close of alerts 27 and 28 is the CI-side evidence
- 🟡 No CI run of the new gate has been recorded for the dependency-cleanup change (the 2026-10-23 gate passed on PR 181, run 40063317688)

**Gaps:**

- **The gate is not a required check.** The workflow fails on a new advisory, but `main` has no branch protection (verified 2026-10-23), so a failing gate does not block a merge (POAM-2026-10-23-14). The gate workflow and exception files have no `CODEOWNERS` review (POAM-2026-10-23-13)
- No documented procedure for a scheduled run that fails on an unchanged `Cargo.lock` (who triages, by when) (POAM-2026-10-23-03)
- **Response times are not defined.** Exposure on `main` before the 2026-10-23 fix: h2 RUSTSEC-2026-0258 and quinn-proto RUSTSEC-2026-0339/0341/0342 (published 2026-08-17) were open 67 days. zip RUSTSEC-2026-0369 (CVSS 9.1, critical; published 2026-10-10) was open 13 days
- Proposed remediation timeframes, **proposed — pending AO approval**: critical 15 days, high 30 days, medium and low 90 days, counted from advisory publication
- **The cargo gate is RustSec-only.** GitHub-only advisories (GHSA-6w6g-hm98-mhgm, GHSA-5j98-2g5x-46v6, GHSA-6f2x-v7q7-m7m5 in hickory-resolver, 2026-10-05) pass CI and are seen only through Dependabot (POAM-2026-10-23-42)
- **The npm gate does not cover development/build dependencies or medium/low advisories.** It could see none of the 18 npm alerts open on 2026-10-26 (15 development scope; the 3 runtime react-router alerts are medium) (POAM-2026-10-23-42)
- **The npe-portal SPA is unscanned:** no lockfile, no Dependabot entry, no audit job, and its image build runs `npm install --no-audit` (POAM-2026-10-23-40)
- **Dependabot alerts are not triaged on a schedule.** On 2026-10-26, 9 npm advisories (10 alerts) were past the proposed windows. The last 2 of them (react-router GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg) were remediated later on 2026-10-26, on day 95 (POAM-2026-10-23-39, closed pending commit); no triage schedule exists yet (POAM-2026-10-23-42). See the SI-2 table

**Remediation (POA&M, see [NIAP_GAP_ANALYSIS.md §11](NIAP_GAP_ANALYSIS.md#11-plan-of-action-and-milestones-poam--open-items)):**

- Obtain AO approval of the remediation timeframes and document the red-scheduled-run procedure (POAM-03, narrowed)
- Protect `main` and make `cargo audit`, `cargo deny` and `Toolchain pin consistency` required checks (POAM-14); add `CODEOWNERS` for the gate files (POAM-13)
- Confirm the first green CI run of `cargo deny` on GitHub and GitLab (POAM-06, closed pending CI)
- ~~Bump `rand` to 0.8.6 and drop RUSTSEC-2026-0097 (POAM-11)~~ done 2026-10-24, closed pending first green CI run; keep the `rsa` (POAM-09) and SA-22 (POAM-12) acceptances under review
- ~~Remove the RUSTSEC-2026-0387 ignore (POAM-16) and the unused `openidconnect` dependency (POAM-22)~~ done 2026-10-24 by removing `crypto-bigint` 0.5.5 from the graph, both closed pending first green CI run. The RustCrypto 0.3 migration (issue #21) no longer blocks any advisory
- Remove the unused `oauth2` dependency from `ostrich-web-ui` (CM-7; POAM-23)
- Add an OSV/GHSA-aware scan of `Cargo.lock` or a release-gate check on open high/critical Dependabot alerts; gate npm development dependencies at `high`; schedule Dependabot triage (POAM-42)
- Pin, monitor and audit the npe-portal SPA (POAM-40)
- ~~Migrate web-ui to `react-router` >= 7.18 (POAM-39)~~ done 2026-10-26 (react-router 7.18.4; branch `claude/react-router-v7`, uncommitted), closed pending commit

**Evidence Required for ATO:**

- AO-approved remediation timeframes
- Scan reports per release (cargo-audit JSON and a full `pnpm audit` of each committed JavaScript lockfile)
- Risk-acceptance record for each ignored advisory

---

## System and Communications Protection (SC)

### SC-4: Information in Shared Resources

**Control:** The information system prevents unauthorized information transfer via shared system resources.

**Implementation Status:** 🟢 **Compliant**

**NIAP Mapping:**

- FDP_RIP.1 - Subset Residual Information Protection

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs:10](../../crates/ostrich-crypto/src/provider.rs#L10) - Zeroizing wrapper
- Rust memory safety guarantees

**Evidence:**

- ✅ Sensitive data zeroized on deallocation
- ✅ Rust prevents use-after-free
- ✅ No memory disclosure vulnerabilities

**Code Annotation:** NIAP PP-CA v2.1: FDP_RIP.1 - Required in Phase 15

---

### SC-8: Transmission Confidentiality and Integrity

**Control:** The information system protects the confidentiality and integrity of transmitted information.

**Implementation Status:** ✅ **Implemented (Phase 12)**

**NIAP Mapping:**

- FTP_TRP.1 - Trusted Path
- FTP_ITC.1 - Inter-TSF Trusted Channel
- FCS_TLSS_EXT.1 - TLS Server Protocol
- FCS_TLSC_EXT.2 - TLS Client Protocol

**Implementation:**

- ✅ **SC-8(1)**: Cryptographic protection via TLS 1.3 mTLS for the CA gRPC
  issuance channel (acme-server / est-server → ca-server), **as of 2026-10-25**
  (branch `claude/grpc-mtls`, uncommitted). Corrected: before this change the
  ca-server gRPC listener was plaintext and the clients used tonic `tls-ring`
  with TLS 1.2 allowed, so earlier ✅ claims for gRPC overstated the state
- ✅ gRPC server: `grpc_server_config` + `bind_mtls_incoming` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs): TLS 1.3 only,
  mandatory client certificate, ALPN `h2` only, `ensure_fips` asserted; a
  connection that completes TLS without `h2` is closed (best-effort
  `close_notify`) and audited (`no_alpn_h2`). 10 s handshake timeout,
  256 handshakes in flight per listener, 8 per source (IPv4 address or IPv6
  /64)
- ✅ gRPC clients: `grpc_client_config` + `GrpcTlsConnector`; `plan_channel`
  in [grpc_client.rs](../../crates/ostrich-common/src/grpc_client.rs) refuses
  plaintext unless explicitly allowed in a debug build, and refuses partial
  material
- ✅ Client and server certificate validation (webpki on the FIPS provider)
- ✅ Server identity: SAN check against the URL host (no SNI for IP
  literals), or `CA_GRPC_SERVER_NAME`
- REST: TLS 1.3 only (`ostrich_common::tls`) **when a certificate is
  configured**. REST still falls back to plain HTTP (with a startup warning)
  when no certificate is configured, so SC-8 does not hold for such a
  deployment (POAM-2026-10-23-05 (a)); gRPC: TLS 1.3 only, no fallback in
  release builds

**Evidence:**

- ✅ `grpc_mtls_e2e` 21/21 passed 2026-10-25: `tls12_client_rejected`,
  `non_h2_alpn_client_rejected`, `server_and_client_configs_report_fips`,
  `p384_chain_end_to_end_with_fips_hybrid_group`,
  `x25519_only_client_rejected`, `stalled_handshake_times_out_and_is_audited`,
  `handshake_concurrency_cap_applies_backpressure`,
  `per_source_cap_closes_excess_idle_connections` and others (see
  [TEST_EVIDENCE.md](TEST_EVIDENCE.md))
- ✅ mTLS for the CA gRPC channel (2026-10-25) and the NPE portal → CA REST
  bridge
- ✅ GrpcClientConfig with certificate-based authentication
- ✅ **NPE portal → CA REST over mTLS (deployed):** the portal's forwarded
  `X-Npe-*` identity is carried over a TLS 1.3 mTLS channel, not plaintext HTTP.
  The portal dials `https://ca-service:8080` presenting its client certificate;
  the ca-server serves REST with TLS + optional client auth. See AC-17 and
  [docs/runbooks/npe-portal-ca-mtls-bridge.md](../runbooks/npe-portal-ca-mtls-bridge.md).

**Code References:**

- [crates/ostrich-common/src/grpc_client.rs](../../crates/ostrich-common/src/grpc_client.rs) - `GrpcClientConfig` (cert, `Zeroizing` key, CA, `server_name`, `allow_plaintext`), `plan_channel`, `read_private_key_pem`
- [crates/ostrich-common/src/grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) - gRPC server/client rustls configs, `grpc_crypto_provider`, `bind_mtls_incoming`, `SubjectAllowlistLayer`, `GrpcTlsConnector`
- [services/ca-server/src/main.rs](../../services/ca-server/src/main.rs) - `start_grpc_listener`, `grpc_server_options`, `ensure_dedicated_grpc_client_ca`
- `crates/ostrich-common/src/tls.rs` - Shared TLS 1.3 server module: rustls
  with the explicitly selected aws-lc-rs provider (`fips` feature; AWS-LC FIPS
  4.2.0 module, CMVP certificate for 4.2.0 pending confirmation), optional mTLS
  client verification, fail-fast on partial configuration, plain-HTTP fallback
  with prominent startup warning, and the fail-closed FIPS gate `ensure_fips`
  (called by `TlsSettings::load` and first in `serve_with_config`)
- `crates/ostrich-acme/src/ca_integration.rs:32-41` - CA client with mTLS
- `crates/ostrich-est/src/ca_integration.rs:30-39` - EST client with mTLS
- Nine service binaries (acme, ca, est, kra, npe-portal, ocsp, scms, tamp,
  web-ui; `services/*/src/main.rs`) build `TlsSettings::from_options` and serve
  HTTPS via `ostrich_common::tls::serve` (corrected 2026-10-24: earlier text
  said "all seven ... via `serve`"). npe-portal ACME mode builds its own
  `ServerConfig` (`build_mtls_server_config`) and serves it via
  `ostrich_common::tls::serve_with_config`

**Implementation Update (Phase 14):**

- ✅ Native TLS 1.3 serving on every service binary (ca, acme, est, ocsp,
  scms, kra, web-ui) - TLS 1.3 only, enforced in
  `crates/ostrich-common/src/tls.rs` via
  `ServerConfig::builder_with_provider(...).with_protocol_versions(&[&TLS13])`
- ✅ Optional mTLS: `TLS_CLIENT_CA_FILE` enables WebPkiClientVerifier
  (AC-17 inter-service authentication)
- ✅ Fail-secure configuration: cert-without-key (or client CA without server
  TLS) aborts startup instead of downgrading (CM-6)
- ✅ Unit tests: `crates/ostrich-common/src/tls.rs` (partial-config rejection,
  missing-file rejection)

**Dependency flaw remediation (2026-10-23, SI-2):**

- ✅ rustls 0.23.41 → 0.23.46 fixes RUSTSEC-2026-0285 (TLS 1.3 handshake
  messages accepted across encryption-level boundaries), RUSTSEC-2026-0349
  (unauthenticated ServerHello downgrade to classical key exchange),
  RUSTSEC-2026-0348 (pre-authentication Brotli allocation) and
  RUSTSEC-2026-0346 (`Debug` output exposing TLS secrets). h2 0.4.20 fixes
  RUSTSEC-2026-0258. See SI-2.
- ✅ In-memory rustls handshake tests added in `crates/ostrich-common/src/tls.rs`
  (12 `tls::tests` passed, per `qa-report.md`): `load()` yields a config with
  `fips() == true`; trusted client accepted; untrusted, missing, and
  serverAuth-only-EKU client certificates rejected; TLS 1.2-only client
  rejected.
- ✅ **Fail-closed FIPS-mode gate on HTTPS listeners (2026-10-24, PR 152,
  branch `revive-fips-tls`):** `ensure_fips` in
  [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs)
  returns `Error::Config` unless `ServerConfig::fips()` is true. It runs in
  `TlsSettings::load` and before any bind in `serve_with_config`, so every
  HTTPS listener served through `ostrich_common::tls` (`serve` and
  `serve_with_config`, including npe-portal ACME mode, which also calls it
  before spawning its renewal task) refuses to start on a non-FIPS TLS stack.
  The startup log records `fips = true` and `aws_lc_version`. Tests:
  `ensure_fips_rejects_non_fips_server_configs`,
  `ensure_fips_accepts_loaded_config`,
  `serve_with_config_refuses_non_fips_config`, npe-portal
  `build_mtls_server_config_reports_fips_mode` (see SC-13, SC-24). Not covered
  at the time: plain-HTTP mode, rustls client configs, and gRPC. **Update
  2026-10-25:** gRPC is now covered (TLS 1.3 mTLS, `fips()` asserted on the
  server and client configs) and a process-level `fips_gate` runs in all ten
  service mains. Still not covered: plain-HTTP REST mode and rustls client
  configs outside gRPC (POAM-2026-10-23-05).
- ℹ️ Under the `fips` feature, rustls offers only TLS_AES_256_GCM_SHA384 and
  TLS_AES_128_GCM_SHA256 for TLS 1.3 (ChaCha20-Poly1305 is excluded). Since
  0.23.46 the aws-lc-rs provider also advertises and verifies ML-DSA-44/65/87
  peer signatures; the user accepted this on 2026-10-23 (see SC-13).

**Web console transport-integrity hardening (SC-8 / SC-18 / SI-10):**

- ✅ **web-ui → CA internal hop is TLS 1.3** (not just edge TLS). The BFF reaches
  the CA's REST API over `https://ca-service:8080` through a pooled `hyper-rustls`
  client (aws-lc-rs/FIPS provider) built once with the CA's issuing certificate as
  a trust anchor (`services/web-ui/src/server/backend_client.rs`, wired via
  `AppState.ca_client`); the `/api/*` proxy and the internal login/logout-all
  calls all use it. Config: `backend.tlsCaCert` (+ optional `tlsClientCert`/
  `tlsClientKey` for a CA that mandates mTLS). This closed a gap where the BFF
  dialed the CA over plaintext `http://` after the CA REST endpoint moved to
  TLS 1.3 (optional mTLS), which had broken all admin authentication.
- ✅ Per-request Content-Security-Policy with a fresh cryptographic nonce
  (`services/web-ui/src/server/middleware/csp.rs`): `script-src` is nonce-strict
  (+ `'wasm-unsafe-eval'` for the Yew WASM client); `default-src`, `connect-src`,
  `base-uri`, and `form-action` are `'self'`; `frame-ancestors 'none'` and
  `upgrade-insecure-requests` are set. Defends transmitted-page integrity against
  injected/mobile code (SC-18) and XSS (SI-10).
- ✅ Hardening headers on every response: `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  strict-origin-when-cross-origin`, `Permissions-Policy` (sensors/camera/geo/mic
  denied).
- ✅ React `/next` route-splitting (PR #109, `web-ui:sha-4f64ef4`) keeps all JS
  chunks same-origin under `/static/assets/`, so lazy loading adds **no CSP
  exceptions**; deployed-header capture and same-origin chunk verification are in
  `ATO_EVIDENCE.md` (Appendix B → "Web console CSP deployment capture").
- ⚠️ `style-src 'unsafe-inline'` is retained for Cloudscape dynamic inline
  styles; scoped to styles only — `script-src` stays nonce-strict.
- ✅ Unit tests (3): `services/web-ui/src/server/middleware/csp.rs` (nonce
  uniqueness/length, header contents).

**Remaining Gaps:**

- ~~gRPC (tonic) listener TLS configuration on ca-server~~ and ~~tonic
  `tls-ring`~~: resolved 2026-10-25 in the working tree (tonic
  `features = ["channel"]` only; `cargo tree -e features -i rustls` shows no
  tonic TLS feature). The rustls `ring` feature is still compiled into other
  binaries through lettre, reqwest 0.12 and async-nats / tokio-websockets
  (POAM-2026-10-23-08, narrowed)
- No revocation checking on mTLS peers (POAM-2026-10-23-27)
- Plain-HTTP REST mode is still permitted when no certificate is configured
  (POAM-2026-10-23-05)
- TLS scan results (deployment evidence)

**Evidence Required for ATO:**

- ✅ mTLS configuration documentation (Phase 12)
- ✅ Inter-service authentication test results
- ✅ External TLS configuration (TLS_CERT_FILE/TLS_KEY_FILE, Phase 14)
- ⏳ TLS scan results (deployment)

---

### SC-12: Cryptographic Key Establishment and Management

**Control:** The organization establishes and manages cryptographic keys.

**Implementation Status:** 🟢 **Excellent (90%)**

**NIAP Mapping:**

- FCS_CKM.1 - Cryptographic Key Generation
- FCS_CKM.4 - Cryptographic Key Destruction (key escrow)
- FCS_STG_EXT.1 - Cryptographic Key Storage
- FPT_KST_EXT.1/2 - Key Protection
- FPT_SKP_EXT.1 - Protection of Keys

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - CryptoProvider abstraction
- [crates/ostrich-crypto/src/pkcs11/mod.rs:466-557](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L466-L557) - HSM key pair generation
- [crates/ostrich-crypto/src/pkcs11/mod.rs:890-1111](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L890-L1111) - Key wrapping/unwrapping for KRA
- [crates/ostrich-crypto/tests/pkcs11_integration_test.rs](../../crates/ostrich-crypto/tests/pkcs11_integration_test.rs) - Comprehensive key management tests
- [crates/ostrich-kra/](../../crates/ostrich-kra/) - Key Recovery Authority
- [crates/ostrich-x509/src/pkcs12.rs](../../crates/ostrich-x509/src/pkcs12.rs) - Encrypted PKCS#12 (RFC 7292) builder for EFS key delivery: PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) shrouded key bag + HMAC-SHA256 MAC
- [crates/ostrich-est/src/rest.rs](../../crates/ostrich-est/src/rest.rs) `server_key_gen` - EFS server-side keygen wraps the escrowed RSA key in a PKCS#12 protected by a CSPRNG-derived one-time password returned exactly once and never persisted (SC-12, SI-12)
- [services/npe-portal/src/server/acme.rs](../../services/npe-portal/src/server/acme.rs) - NPE portal TLS server-certificate lifecycle is fully automated (SC-8/SC-12): the portal enrolls its own cert via ACME (RFC 8555 HTTP-01) on a FIPS/aws-lc-rs backend, caches the cert+key as a single atomic, owner-only (0600) PEM bundle, and a background task renews ahead of expiry, hot-swapping the new key/cert into the live rustls listener (`ResolvesServerCert`) with no restart and no operator action (also CP-10 self-recovery)

**Evidence:**

- ✅ Excellent key management architecture
- ✅ HSM-based key generation (RSA 2048/3072/4096, ECDSA P-256/P-384/P-521)
- ✅ Private keys never leave HSM (non-extractable by default)
- ✅ Public key export in SPKI format for certificate issuance
- ✅ AES Key Wrap (NIST SP 800-38F) for key escrow
- ✅ Key wrapping/unwrapping for KRA integration
- ✅ Unique 32-byte key IDs (cryptographically random)
- ✅ Thread-safe concurrent key operations
- ✅ KRA for key escrow and recovery
- ✅ Shamir secret sharing for split knowledge
- ✅ **KRA key wrapping uses AES-256-GCM (SP 800-38D) with per-escrow random
  KEK** (`crates/ostrich-kra/src/wrap.rs`); the previous placeholder XOR
  encryption is removed. The escrow record's certificate ID is bound as AEAD
  associated data; the KEK is Shamir-split, never persisted, and zeroized
  after use (FCS_CKM.4). Recovery (`complete_recovery`) reconstructs the KEK,
  unwraps the escrowed key, and returns it in a `Zeroizing` buffer; unwrap
  failures are audited as Failure outcomes (AU-2)
- ✅ **Escrow → recover round-trip verified live** (SC-12(1) availability,
  FCS_CKM.2): a known key is escrowed (KEK split into 5 shares), recovery is
  initiated, and a 3-of-5 threshold of shares recovers the key
  byte-identically; 2 shares are insufficient. Test:
  `crates/ostrich-kra/tests/recovery_roundtrip.rs`. Two bugs were fixed to
  make this work: `escrow_key` split the KEK but **dropped the shares** (only
  audit-logging them), leaving every escrowed key permanently unrecoverable -
  it now returns the shares for secure distribution; and
  `escrowed_keys.wrapping_key_id` was a `NOT NULL` FK to `kra_storage_keys`
  that no escrow ever populated (the KEK is ephemeral, not a stored key), so
  every escrow insert failed the FK - migration 00006 makes it nullable and
  drops the FK. POAM: shares are not yet persisted/distributed to specific
  recovery agents (`recovery_agents`/`recovery_shares` tables); the caller
  owns distribution today.
- ✅ CA bootstrap from database: `ca_keys`/`ca_certificates` repository
  (`crates/ostrich-db/src/repository/ca.rs`), loaded by
  `services/ca-server/src/main.rs::bootstrap_ca` with FCS_STG_EXT.1 HSM
  validation; `tools/ostrich-init` generates and registers the root CA
- ✅ Comprehensive integration test suite (18 tests) plus 6 KEK wrap/unwrap
  unit tests (roundtrip, wrong-KEK, tamper, AAD mismatch, nonce uniqueness)
- ✅ **Post-quantum key establishment (FIPS 203 ML-KEM)** implemented in
  [crates/ostrich-crypto/src/kem.rs](../../crates/ostrich-crypto/src/kem.rs):
  ML-KEM-512/768/1024 KeyGen/Encaps/Decaps plus raw `dk` escrow export/import for
  KRA recovery, on the FIPS-track aws-lc-rs `kem` backend. Verified by live
  cross-implementation interop with OpenSSL 3.6 in both directions
  ([tests/integration/mlkem_openssl_interop.rs](../../tests/integration/mlkem_openssl_interop.rs)).
- ⚠️  Key destruction not yet implemented
- ⚠️  Key lifecycle procedures partially documented

**Key Generation Capabilities:**

- RSA-2048, RSA-3072, RSA-4096 (FIPS 186-5)
- ECDSA P-256, P-384, P-521 (FIPS 186-5)
- ML-KEM-512/768/1024 key encapsulation (FIPS 203)
- Extractable/non-extractable key control
- Persistent token storage in HSM
- Public exponent 65537 for RSA (FIPS 186-5)

**Code Annotations:**

- `NIST 800-53: SC-12 - Cryptographic key establishment and management` (multiple locations)
- `FIPS 186-5: RSA key generation` (mod.rs:499-502)
- `FIPS 186-5: ECDSA key generation` (mod.rs:504-507)

**Testing:**

- `test_rsa2048_key_generation()`, `test_rsa3072_key_generation()`, `test_rsa4096_key_generation()`
- `test_ecp256_key_generation()`, `test_ecp384_key_generation()`, `test_ecp521_key_generation()`
- `test_multiple_keys_same_provider()` - validates key coexistence
- `test_concurrent_operations()` - validates thread-safe key generation

**Gaps:**

- Key destruction (C_DestroyObject) not implemented
- Key rotation procedures not documented
- Key backup/disaster recovery procedures needed

**Remediation:** Phase 11 - Implement key destruction, document key lifecycle procedures

**Evidence Required for ATO:**

- ✅ Key generation procedures (documented in Phase 10 summary)
- ✅ Key escrow/recovery procedures (wrap_key/unwrap_key implemented)
- ✅ Split knowledge procedures (KRA Shamir secret sharing)
- ⚠️  Key management policy document needed
- ⚠️  Key rotation policy needed

---

### SC-13: Cryptographic Protection

**Control:** The information system implements required cryptographic protections.

**Implementation Status:** 🟢 **Excellent (98%)**

**NIAP Mapping:**

- FCS_COP.1 - Cryptographic Operations
- FCS_CDP_EXT.1 - Cryptographic Dependencies
- FCS_RBG_EXT.1 - Random Bit Generation

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm definitions
- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Crypto operations
- [crates/ostrich-crypto/src/pkcs11/mod.rs:559-680](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L559-L680) - HSM signing operations
- [crates/ostrich-crypto/src/pkcs11/mod.rs:682-797](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L682-L797) - HSM verification operations
- [crates/ostrich-crypto/src/drbg/ctr_drbg.rs](../../crates/ostrich-crypto/src/drbg/ctr_drbg.rs) - **NIST SP 800-90A DRBG**
- [crates/ostrich-crypto/src/drbg/health_tests.rs](../../crates/ostrich-crypto/src/drbg/health_tests.rs) - **FIPS 140-3 health tests**
- [crates/ostrich-x509/src/signing.rs](../../crates/ostrich-x509/src/signing.rs) - **Classical signature-algorithm agility** (RFC 5280 §4.1.1.2): maps CA key type to signature algorithm, emits matching AlgorithmIdentifier (RSA NULL params per RFC 4055; ECDSA/Ed25519 absent params per RFC 5758 §3.2 / RFC 8410), and re-encodes ECDSA fixed r||s into DER Ecdsa-Sig-Value
- [crates/ostrich-x509/src/builder/certificate.rs](../../crates/ostrich-x509/src/builder/certificate.rs) - Certificate DER encoding and signing (signature_algorithm threaded into TBS)
- [crates/ostrich-x509/src/builder/crl.rs](../../crates/ostrich-x509/src/builder/crl.rs) - CRL DER encoding and signing (signature_algorithm threaded into TBS)
- [crates/ostrich-ca/src/issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - Certificate signing operations (RSA/ECDSA/Ed25519 CA keys)
- [crates/ostrich-ca/src/revocation.rs](../../crates/ostrich-ca/src/revocation.rs) - CRL signing operations (RSA/ECDSA/Ed25519 CA keys)
- [crates/ostrich-ocsp/src/responder.rs](../../crates/ostrich-ocsp/src/responder.rs) - OCSP response signing (signatureAlgorithm AlgorithmIdentifier flows from chosen algorithm, RFC 6960 §4.2.1)

**Evidence:**

- ✅ **All classical algorithms in `ostrich-crypto` run inside the AWS-LC FIPS
  module** (AWS-LC FIPS 4.2.0 via `aws-lc-fips-sys` 0.14.2, since 2026-10-23;
  CMVP certificate for 4.2.0 pending confirmation, POA&M) via
  `aws-lc-rs` (workspace `fips` feature): RSA (PKCS#1/PSS), ECDSA P-256/P-384,
  Ed25519, SHA-2, and the SP 800-90A DRBG. The non-FIPS `ring` and pure-Rust
  `rsa` backends were removed from `ostrich-crypto`
  ([crates/ostrich-crypto/src/software/mod.rs](../../crates/ostrich-crypto/src/software/mod.rs),
  [verify.rs](../../crates/ostrich-crypto/src/verify.rs)). Verified by live
  OpenSSL interop for RSA-2048/3072 and ECDSA P-256/P-384
  ([tests/integration/fips_signature_openssl_interop.rs](../../tests/integration/fips_signature_openssl_interop.rs)).
- ✅ ML-KEM-512/768/1024 (FIPS 203) key encapsulation runs inside the AWS-LC
  FIPS 4.2.0 module via aws-lc-rs (CMVP certificate for 4.2.0 pending
  confirmation, POA&M). OpenSSL 4.0.3 interop passed 2026-10-23
  (`mlkem_openssl_interop`, 2 tests).
- ✅ Runtime module check: `aws_lc_module_reports_fips_mode`
  ([crates/ostrich-crypto/src/self_test.rs](../../crates/ostrich-crypto/src/self_test.rs))
  asserts `aws_lc_rs::try_fips_mode() == Ok(())` and a SHA-256 KAT through the
  module (passed 2026-10-23, `qa-report.md`). This is a unit test.
- 🟡 **Start-up FIPS-mode assertion, scoped to HTTPS listeners (2026-10-24,
  PR 152):** `ostrich_common::tls::ensure_fips` refuses to serve any HTTPS
  listener served via `ostrich_common::tls` (`serve`, `serve_with_config`,
  including npe-portal ACME mode) unless `ServerConfig::fips()` is true, in the
  AWS-LC FIPS 4.2.0 module (FIPS mode / approved algorithms; CMVP certificate
  pending confirmation, POAM-2026-10-23-01). `fips()` reflects build and
  linkage (AWS-LC `FIPS_mode()` is a build-time constant in 4.2.0) plus the
  rustls allowlist and `require_ems`. It does not detect a failed power-on
  self-test; the module aborts the process itself in that case. Tests: 26
  `tls::` unit tests passed, including
  `ensure_fips_rejects_non_fips_server_configs`,
  `ensure_fips_accepts_loaded_config`,
  `serve_with_config_refuses_non_fips_config` and
  `fips_server_config_kx_groups_exclude_x25519_keep_mlkem_hybrid`. Mutation
  check (gate forced to `Ok`): two of these fail. Still open at the time
  (POAM-2026-10-23-05): no process-level gate, no client-config or gRPC check,
  no audit event on refusal, KATs not through AWS-LC.
- 🟡 **Process-level FIPS gate and gRPC assertions (2026-10-25, branch
  `claude/grpc-mtls`, uncommitted).** `ostrich_common::tls::fips_gate`
  ([tls.rs](../../crates/ostrich-common/src/tls.rs)) asserts
  `aws_lc_rs::try_fips_mode()`, asserts the rustls aws-lc-rs provider reports
  `fips()`, installs it as the process default and then checks that the
  effective default is FIPS, so a non-FIPS provider installed earlier makes the
  process exit. It is the first call after tracing setup in all ten service
  mains (acme, ca, est, kra, notify, npe-portal, ocsp, scms, tamp, web-ui),
  before the database, NATS, listeners or clients. The ca-server gRPC listener
  now starts only after the gate and after its configuration resolves, which
  removes the earlier "gRPC briefly up on a non-FIPS build" ordering gap.
  `ensure_fips` is asserted on the gRPC `ServerConfig` and `ensure_fips_client`
  on the gRPC `ClientConfig`. Tests: `fips_gate_preinstalled` 1/1
  (`fips_gate_refuses_preinstalled_non_fips_default`),
  `server_and_client_configs_report_fips` and
  `connector_and_listener_refuse_non_fips_or_non_h2_configs` in
  `grpc_mtls_e2e`, all passed 2026-10-25. The gate detects build and linkage
  problems; it does not run self-tests (the module runs its own power-on
  self-tests and aborts on failure), so it supports FPT_TST_EXT.1 rather than
  meeting it. Still open (POAM-2026-10-23-05): plain-HTTP REST mode; rustls
  `ClientConfig`s outside gRPC (web-ui and npe-portal backend clients, ACME
  tls-alpn-01 validator) not asserted; clients that build their TLS config from
  the process default (async-nats, lettre, instant-acme) rely on the gate only;
  no audit record on a startup refusal; KATs not through AWS-LC; second
  non-FIPS `aws-lc-sys` copy linked.
- 🟡 **gRPC TLS provider (2026-10-25).** `grpc_crypto_provider` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) is the aws-lc-rs
  FIPS provider with key exchange groups in this order: `SECP256R1MLKEM768`
  (ECDH P-256 + ML-KEM-768, FIPS 203; both components are FIPS-approved
  algorithms), `X25519MLKEM768`, P-256, P-384. Plain X25519 is not offered.
  Suites: TLS13_AES_256_GCM_SHA384 and TLS13_AES_128_GCM_SHA256. Signature
  verification is narrowed to ECDSA P-256/SHA-256, ECDSA P-384/SHA-384,
  RSA-PSS (2048-8192 bit, SHA-256/384/512) and ML-DSA-44/65/87; P-521,
  mismatched curve/hash pairs, Ed25519 and RSA PKCS#1 v1.5 are refused.
  `fips()` stays true. Tests: `p384_chain_end_to_end_with_fips_hybrid_group`
  (asserts the negotiated group and `conn.fips()`) and
  `x25519_only_client_rejected` (`grpc_mtls_e2e`, passed 2026-10-25). Wording
  limits: the module is AWS-LC FIPS 4.2.0 in FIPS mode, **CMVP certificate
  pending confirmation** (POAM-2026-10-23-01). That `X25519MLKEM768` counts as
  FIPS rests on rustls's FIPS-pending interpretation (ML-KEM share first; X25519
  is not an approved algorithm). For `SECP256R1MLKEM768` both components are
  approved, which is why it is offered first (PQC-002). Not claimed: an
  assessed FIPS 140-3 status for either hybrid combination.
- 🟡 ML-DSA (FIPS 204): **TLS verification only.** ML-DSA is in the AWS-LC FIPS
  4.2.0 module and, from aws-lc-rs 1.18, exposed under `fips`. rustls 0.23.46 /
  rustls-webpki 0.103.16 therefore verify ML-DSA-44/65/87 peer signatures and
  certificate chains on every rustls endpoint. The user accepted this on
  2026-10-23. ML-DSA key generation, signing and X.509 issuance stay disabled
  (`crates/ostrich-x509/src/secure_defaults.rs`). POA&M: enable issuance once
  CMVP confirms the AWS-LC 4.2.0 module. SLH-DSA (FIPS 205) remains
  unimplemented.
- ✅ **NIST SP 800-90A Rev 1 CTR_DRBG (AES-256) fully implemented**
- ✅ **FIPS 140-3 health tests (repetition count, adaptive proportion)**
- ✅ **Certificate serial number generation with ≥20 bits random (RFC 5280)**
- ✅ PKCS#11 HSM integration complete with FIPS 140-3 module support
- ✅ RSA-PSS SHA-256/384/512 via PKCS#11 — verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), RSA-2048/3072/4096; production HSM not yet validated (POAM-2026-10-23-21). Provider level only. Software provider: AWS-LC FIPS 4.2.0 module (CMVP certificate for 4.2.0 pending confirmation, POA&M). POAM-2026-10-23-17 closed 2026-10-23. RSA-PSS is the default algorithm for RSA keys generated through `Pkcs11Provider`, and its only production user is AU-10 audit-record signing. X.509 certificates, CRLs and OCSP responses with RSA CA keys are signed with PKCS#1 v1.5, not PSS, and the X.509 layer cannot encode RSASSA-PSS parameters (POAM-2026-10-23-20)
- ✅ RSA PKCS#1 v1.5 with SHA-256/384/512 (legacy compatibility)
- ✅ ECDSA with SHA-256/384/512
- ✅ **Classical CA signing agility**: certificates, CRLs, and OCSP responses can be signed with RSA-PKCS1, ECDSA P-256/P-384, or Ed25519 CA keys (no longer RSA-only); declared and actual algorithms always match per RFC 5280 §4.1.1.2 (`crates/ostrich-x509/src/signing.rs`)
- ✅ ECDSA fixed r||s signatures from the software and PKCS#11 (CKM_ECDSA) providers re-encoded to DER Ecdsa-Sig-Value for X.509/CMS/OCSP (RFC 5758 §3.2)
- ✅ DER/ASN.1 encoding fully implemented for X.509 certificates and CRLs
- ✅ Cryptographic signing operations integrated with CryptoProvider trait
- ✅ Key usage enforcement through certificate extensions (FCS_COP.1)
- ✅ OCSP request/response cryptographic operations (RFC 6960)
- ✅ PKCS#7/CMS message signing for EST protocol
- ✅ Signature verification with tamper detection
- ✅ Algorithm mismatch detection (RSA key with ECDSA algorithm fails gracefully)
- ✅ PKCS#11 integration suite `pkcs11_integration_test.rs` (SoftHSM only): 29 tests (28 run, 1 ignored: `test_key_wrapping_and_unwrapping`). 2026-10-23 Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) (SoftHSM 2.6.1, rustc 1.99.1): 28 passed, 0 failed, 1 ignored, exit 0. Local SoftHSM 2.7.0: 28 passed, 0 failed, 1 ignored. (The earlier "18 + 21 = 39 tests" count could not be traced to current files and was removed)

**Cryptographic Operations Implemented:**

1. **Digital Signatures (FIPS 186-5)**:
   - RSA-PSS 2048/3072/4096 with SHA-256/384/512 (provider level; through PKCS#11 tested on SoftHSM 2.6.1 in Linux CI and SoftHSM 2.7.0 locally; not used for X.509 signing)
   - RSA PKCS#1 v1.5 with SHA-256/384/512
   - ECDSA P-256 with SHA-256
   - ECDSA P-384 with SHA-384
   - ECDSA P-521 with SHA-512

2. **Key Wrapping (NIST SP 800-38F)**:
   - AES Key Wrap for key escrow/recovery

3. **Public Key Export**:
   - SPKI (SubjectPublicKeyInfo) format (RFC 5280)
   - RSA and EC public keys

**Code Annotations:**

Line numbers were removed on 2026-10-23 because the PKCS#11 fix moved them. Locate by function name in [crates/ostrich-crypto/src/pkcs11/mod.rs](../../crates/ostrich-crypto/src/pkcs11/mod.rs):

- `pkcs11_signature_input`: COMPLIANCE MAPPING SC-13, FCS_COP.1(1), FCS_COP.1(2), FIPS 186-5 §5.4/§6.4, RFC 8017 §8.1/§9.1, PKCS#11 v3.0 §2.1.14/§2.3.6, plus the split-boundary statement (host digest in AWS-LC; EMSA-PSS encoding and private-key operation in the HSM)
- `rsa_pss_profile` / `pkcs11_signature_mechanism`: one RSA-PSS profile (digest, `hashAlg`, MGF1, `sLen` = hash length) shared by the digest step and both mechanism selections
- `sign()` / `verify()`: FCS_COP.1(1); `verify` returns `Ok(false)` only for `CKR_SIGNATURE_INVALID` / `CKR_SIGNATURE_LEN_RANGE` (`is_signature_rejection`); other token errors are `Err` (fail closed)
- `NIST 800-53: SC-13 - Use FIPS-approved key wrapping` (key-wrap path)

**Testing:**

- `test_rsa_pss_signing_and_verification()` - RSA-PSS with tamper detection
- `test_rsa_pkcs1_signing_and_verification()` - RSA PKCS#1 v1.5
- `test_ecdsa_p256_signing_and_verification()` - ECDSA P-256 with tamper detection
- `test_ecdsa_p384_signing_and_verification()` - ECDSA P-384
- `test_ecdsa_p521_signing_and_verification()` - ECDSA P-521
- `test_deterministic_signatures_rsa_pss()` - Validates RSA-PSS randomness
- `test_rsa_pss_hsm_sign_software_verify()` - HSM RSA-PSS SHA-256/384/512 signatures verified by an independent AWS-LC software verifier over the exported SPKI (RFC 8017 encoding, not only HSM self-consistency); wrong message, tampered signature and wrong hash rejected
- `test_rsa_pss_all_hashes_rsa3072_rsa4096()` - RSA-3072/4096 × PSS SHA-256/384/512, software cross-verified
- `test_rsa_software_sign_hsm_verify()` - Software-signed PSS and PKCS#1 v1.5 (RSA-2048/3072) accepted by HSM verify; cross-algorithm presentation rejected
- `test_rsa_pss_empty_message()`, `test_rsa_pss_large_message()` (> 1 MiB), `test_rsa_pkcs1_all_hashes_hsm_sign_software_verify()` (PKCS#1 v1.5 regression guard)
- `test_rsa_pss_verify_malformed_signature_denies()` - SI-10 fail secure on empty/truncated/oversized/zero signatures
- `test_verify_token_fault_is_error_not_rejection()` - a token fault is `Err`, not `Ok(false)`
- `test_pqc_algorithms_fail_closed_on_pkcs11()` - ML-DSA / SLH-DSA return `Err` on the PKCS#11 provider
- Unit tests in `pkcs11/mod.rs` `mod tests` (8): digest input lengths and values, PSS profile consistency, PKCS#1 v1.5 pass-through, unsupported algorithms fail closed, signature-rejection RV mapping
- `test_signature_with_wrong_algorithm_fails()` - Algorithm mismatch detection
- `test_public_key_export_rsa()`, `test_public_key_export_ec()` - Public key export

**Gaps:**

- SLH-DSA CA keys are not supported by ca-server: the CA key signs audit records and the audit sink refuses SLH-DSA (POAM-2026-10-23-34, FIPS 205). Currently moot, since no provider signs SLH-DSA
- Post-quantum cryptography implementation pending (waiting for HSM vendor support)
- EdDSA (Ed25519/Ed448) not universally supported in PKCS#11 HSMs
- CMVP certificate for AWS-LC FIPS 4.2.0 not yet confirmed (POA&M, see
  [NIAP_GAP_ANALYSIS.md §11](NIAP_GAP_ANALYSIS.md#11-plan-of-action-and-milestones-poam--open-items))
- `ring` (no CMVP certificate) is still used outside the AWS-LC module:
  AES-256-GCM key wrapping and `SystemRandom` in
  `crates/ostrich-kra/src/wrap.rs`; the rustls `ring` feature is compiled in
  through lettre, reqwest 0.12 and async-nats / tokio-websockets; async-nats
  uses `ring` for SHA-256 (POAM-2026-10-23-08, narrowed 2026-10-25;
  POAM-2026-10-23-30). gRPC TLS no longer uses `ring` (tonic `tls-ring`
  removed 2026-10-25)
- PKCS#11 test evidence is SoftHSM only (a test double, not a production
  HSM). The CI job `PKCS#11 suite (SoftHSM2)`
  ([.github/workflows/hsm-integration.yml](../../.github/workflows/hsm-integration.yml))
  ran on Linux (SoftHSM 2.6.1) before the RSA-PSS fix: 16 passed, 3 failed,
  1 ignored, exit 101. The 3 failures were RSA-PSS signing (`CKR_GENERAL_ERROR`):
  raw `CKM_RSA_PKCS_PSS` was given the whole message instead of its digest.
  After the fix, Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) (PR head 44d560d; the artifact's `commit:`
  line shows the PR merge ref c67c10e) gave 28 passed / 0 failed / 1 ignored,
  exit 0; local SoftHSM 2.7.0 also gave 28/0/1 (non-standard macOS invocation:
  test binary run directly with `DYLD_INSERT_LIBRARIES`). POAM-2026-10-23-07
  and POAM-2026-10-23-17 closed 2026-10-23 with this caveat: no run exercises
  the `CKA_ALLOWED_MECHANISMS` decode path fixed by cryptoki 0.11.1
  (RUSTSEC-2026-0286), because `ostrich-crypto/src/pkcs11` never reads that
  attribute
- PKCS#11 RSA-PSS and ECDSA are split operations: the digest is computed in
  the AWS-LC FIPS module on the host; EMSA-PSS encoding and the private-key
  operation run in the HSM. The production HSM's security policy must approve
  raw `CKM_RSA_PKCS_PSS` / `CKM_ECDSA` with host-supplied digests (not yet
  checked; no production HSM selected) (POAM-2026-10-23-21)
- PKCS#11 `sign`/`verify` do not check that the requested algorithm matches
  the key type, and key generation does not set `CKA_ALLOWED_MECHANISMS`
  (SEC-001, POAM-2026-10-23-18)
- Only SoftHSM has been tested; no vendor HSM, no verify known-answer vectors,
  and sLen is fixed at the hash length (QA coverage gaps)
- Pre-existing (PQC-001, 2026-10-24): some CSPs are drawn from `rand` 0.10
  `ThreadRng`, not the AWS-LC SP 800-90A DRBG: Shamir KEK share coefficients
  (`ostrich-kra`), `secure_random_bytes` (PKCS#12 PBES2 salt and IV), the EST
  PKCS#12 one-time password and enrollment token, and web session tokens.
  CA serial numbers already use `fips_random_bytes`. FCS_RBG_EXT.1 /
  POAM-2026-10-23-24

**Remediation:** Phase 12+ - Add post-quantum cryptography when HSM vendors provide support

**Evidence Required for ATO:**

- 🟡 Cryptographic module inventory (SoftHSM for testing, production HSM TBD)
- ⚠️  FIPS 140-2/140-3 validation certificates (production HSM vendor to provide)
- ✅ Algorithm usage matrix (documented in algorithm.rs and Phase 10 summary)
- ✅ DER encoding test results (completed in Phase 8)
- ✅ Signature generation/verification tests (SoftHSM only): `pkcs11_integration_test.rs` has 29 tests; after the 2026-10-23 RSA-PSS fix, Linux CI (SoftHSM 2.6.1) and local SoftHSM 2.7.0 both ran 28 passed, 0 failed, 1 ignored (before the fix: Linux CI 16 passed / 3 RSA-PSS failed / 1 ignored, exit 101)
- ✅ HSM integration test results (SoftHSM only; production HSM not yet validated, POAM-2026-10-23-21): `hsm-integration.yml` job `PKCS#11 suite (SoftHSM2)`, [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654), artifact `pkcs11-softhsm-results`: SoftHSM 2.6.1, 28 passed / 0 failed / 1 ignored, all six `test_rsa_pss_*` tests ok including `test_rsa_pss_hsm_sign_software_verify`, exit 0, PR head 44d560d (artifact `commit:` = merge ref c67c10e). Meets the NIST-review close criterion

---

### SC-17: Public Key Infrastructure Certificates

**Control:** The organization issues public key certificates under an appropriate certificate policy.

**Implementation Status:** 🟢 **Excellent (98%)**

**NIAP Mapping:**

- FDP_CER_EXT.1 - Certificate Profiles
- FCS_COP.1 - Cryptographic Operations (key usage enforcement)
- FIA_X509_EXT.1 - X.509 Certificate Validation

**Implementation:**

- [crates/ostrich-x509/src/profile.rs](../../crates/ostrich-x509/src/profile.rs) - Certificate profiles
- [crates/ostrich-x509/src/builder/certificate.rs:488-759](../../crates/ostrich-x509/src/builder/certificate.rs#L488-L759) - X.509 extension building
- [crates/ostrich-x509/src/builder/crl.rs:392-451](../../crates/ostrich-x509/src/builder/crl.rs#L392-L451) - CRL extension building
- [crates/ostrich-x509/src/validation/](../../crates/ostrich-x509/src/validation/) - **Path validation (Phase 15)**
- [crates/ostrich-ca/src/issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - Certificate issuance
- [crates/ostrich-acme/src/rest.rs:791](../../crates/ostrich-acme/src/rest.rs#L791) - ACME order finalization issues certificates via CA gRPC (`AcmeCaClient`); fails closed (SI-17) when CA integration is not configured
- **ACME end-to-end (Phase 16, verified live)**: full RFC 8555 flow -
  new-account -> new-order -> http-01 challenge validation
  ([crates/ostrich-acme/src/rest.rs](../../crates/ostrich-acme/src/rest.rs)
  `run_challenge_validation`) -> finalize -> certificate download, issuing a
  leaf that verifies against the root. Test:
  `tests/integration/acme_full_flow_test.rs`
- **OCSP responder (Phase 16, verified live)**: signs status responses with
  the real CA key
  ([services/ocsp-server/src/main.rs](../../services/ocsp-server/src/main.rs)
  `bootstrap_ocsp`); `openssl ocsp` confirms good->revoked transitions with
  the correct CRLReason. Test: `tests/integration/ocsp_revocation_test.rs`
- **External signature verification** (ACME JWS, CSR proof-of-possession) is
  a stateless operation over the request-supplied public key
  ([crates/ostrich-crypto/src/verify.rs](../../crates/ostrich-crypto/src/verify.rs)),
  never importing attacker-supplied keys into the provider keystore (SI-10)
- [crates/ostrich-acme/src/rest.rs:916](../../crates/ostrich-acme/src/rest.rs#L916) - ACME certificate download serves issued PEM chain from certificate store (RFC 8555 §7.4.2)

**Evidence:**

- ✅ RFC 5280 §4.2 compliant certificate extensions fully implemented:
  - **Key Usage** (§4.2.1.3, critical): Digital signature, key encipherment, key cert sign, CRL sign
  - **Basic Constraints** (§4.2.1.9, critical): CA flag, path length constraint
  - **Extended Key Usage** (§4.2.1.12): Server auth, client auth, code signing, email protection, OCSP signing, custom OIDs
  - **Subject Alternative Name** (§4.2.1.6): DNS names, emails, URIs, IP addresses
  - **Authority Key Identifier** (§4.2.1.1): Links cert to issuing CA
  - **Subject Key Identifier** (§4.2.1.2): Unique public key identifier
  - **CRL Distribution Points** (§4.2.1.13): CRL download URLs
  - **Authority Information Access** (§4.2.2.1): OCSP and CA issuer URLs
  - **Certificate Policies** (§4.2.1.4): Policy OIDs and qualifiers
- ✅ RFC 5280 §5 compliant CRL extensions:
  - **CRL Number** (§5.2.3, critical): Monotonic CRL versioning
  - **Authority Key Identifier** (§5.2.1): Links CRL to CA
  - **Revocation Reason** (§5.3.1, per-entry): All 11 reason codes with proper ASN.1 ENUMERATED encoding
- ✅ **RFC 5280 §6 Path Validation (Phase 15)**:
  - **Certificate chain building** to trust anchor
  - **Signature verification** framework
  - **Validity period** checking
  - **Basic constraints** enforcement (CA flag, path length)
  - **Key usage** validation for CA certificates
  - **Name constraints** processing framework
  - **Certificate policy** framework (simplified any-policy mode)
  - **Revocation checking** framework (OCSP/CRL integration points)
  - **CSR signature verification** (proof-of-possession)
  - **80 unit tests** covering all validation steps
- ✅ Multiple profile types (Root CA, Intermediate CA, TLS Server, TLS Client, Code Signing, OCSP Signing)
- ✅ Profile validation ensures CA certs have keyCertSign usage
- ✅ All extensions properly marked as critical/non-critical per RFC 5280
- ℹ️ TLS peer certificates (mTLS listeners and rustls clients) are validated by
  rustls-webpki 0.103.16, not by `ostrich-x509`. That path additionally rejects
  certificates whose SPKI is on webpki's built-in distrust list (emSign G3;
  `CertDistrusted`), independent of configured trust anchors. It does no
  CRL/OCSP revocation checking.

**Gaps:**

- No formal Certificate Policy (CP) or Certificate Practice Statement (CPS) documented

**Remediation:** Document CP/CPS for production deployment (Phase 16)

**Evidence Required for ATO:**

- Certificate Policy document
- Certificate Practice Statement
- Profile specifications
- ✅ X.509 extension implementation (COMPLETED)

---

### SC-23: Session Authenticity

**Control:** The information system protects the authenticity of communications sessions.

**Implementation Status:** 🟢 **Implemented**

**NIAP Mapping:**

- ACME nonce-based replay protection
- Web UI CSP nonces for script authenticity
- PKCE for OAuth flow authenticity

**Implementation:**

- [crates/ostrich-acme/src/rest.rs:127](../../crates/ostrich-acme/src/rest.rs#L127) - ACME nonce generation and validation
- [crates/ostrich-db/src/repository/session.rs](../../crates/ostrich-db/src/repository/session.rs) - durable session store; Postgres is the authoritative source of session state (survives restart, shared across instances)
- [services/web-ui/src/server/middleware/csp.rs](../../services/web-ui/src/server/middleware/csp.rs) - CSP nonce middleware
- [services/web-ui/src/server/auth/oidc.rs:118](../../services/web-ui/src/server/auth/oidc.rs#L118) - PKCE challenge generation
- TLS provides transport-level session authenticity

**Evidence:**

- ✅ ACME nonces prevent replay attacks (RFC 8555 compliance)
- ✅ Server-side sessions persisted in Postgres: a token's validity is decided
  by authoritative state, not process memory, so termination/expiry hold across
  a restart (`DbSessionStore`, migration 00011)
- ✅ CSP nonces per-request prevent XSS attacks (NIST 800-53 SC-18 Mobile Code)
- ✅ PKCE (S256) prevents authorization code interception
- ✅ OAuth state parameter prevents CSRF attacks
- ✅ Secure session cookies with SameSite attribute
- ✅ TLS session binding for TLS-protected communication. Qualified
  2026-10-25 (NIST-023): REST listeners still run plain HTTP when no
  certificate is configured (POAM-2026-10-23-05 (a)), so this does not hold
  for "all communication" in that mode
- ✅ CA gRPC (2026-10-25): TLS 1.3 mutual authentication with ALPN `h2`
  required on both ends; authorization is taken from the certificate of the
  same TLS connection (`GrpcPeerInfo` via tonic `Connected`), not from request
  metadata. Corrected 2026-10-25: before this change the gRPC channel was
  plaintext, so "all communication" did not hold for gRPC

**Code References:**

- [services/web-ui/src/server/middleware/csp.rs:35](../../services/web-ui/src/server/middleware/csp.rs#L35) - Cryptographic nonce generation (128-bit)
- [services/web-ui/src/server/auth/oidc.rs:319](../../services/web-ui/src/server/auth/oidc.rs#L319) - PKCE challenge (SHA-256)
- [services/web-ui/src/server/auth/handlers.rs:73](../../services/web-ui/src/server/auth/handlers.rs#L73) - CSRF state cookie

**Remediation:** Refuse or retire plain-HTTP REST mode (POAM-2026-10-23-05 (a)); otherwise implemented

---

### SC-24: Fail in Known State

**Control:** The information system fails to a known state for defined failure types, preserving defined system state information.

**Implementation Status:** 🟡 **Partial** (added 2026-10-24; extended 2026-10-25 to the process start-up gate and the CA gRPC channel)

**NIAP Mapping:**

- FPT_FLS.1 - Failure with Preservation of Secure State

**Implementation:**

- [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - `ensure_fips`: a `ServerConfig` that does not report FIPS mode is refused with `Error::Config` and a `tracing::error!` record; the listener never binds (refuse to serve, never degrade). Called from `TlsSettings::load` and first in `serve_with_config`; npe-portal ACME mode also calls it before spawning background work ([services/npe-portal/src/main.rs](../../services/npe-portal/src/main.rs))
- 2026-10-25 (branch `claude/grpc-mtls`, uncommitted):
  - `fips_gate` (same file): every service `main` exits before any database,
    NATS, listener or client starts if AWS-LC or the process-default rustls
    provider is not in FIPS mode; `ensure_fips_client` refuses a non-FIPS
    gRPC `ClientConfig`
  - ca-server gRPC: `GrpcServerOptions::resolve` exits before the database
    connects on missing, partial or ambiguous configuration, an empty or
    unparsable allowlist, or the dev flag in a release build;
    after the CA loads, `check_grpc_trust_anchors` exits (after writing a
    `grpc_listener_refused` record) if the CA-database ancestor walk fails or a
    client-CA anchor belongs to the CA's own chain (see IA-3); a bind failure
    is fatal
  - audit sink: an SLH-DSA audit signing key is refused at construction, so a
    CA with an SLH-DSA key does not start (POAM-2026-10-23-34); a failed or
    timed-out audit-chain write is not written and is reported (AU-5, AU-9)
  - `SubjectAllowlistLayer`: any authorization failure denies; an audit-write
    failure never turns a denial into an allow
  - acme-server / est-server: plaintext or partial client configuration is
    refused (plaintext only as an explicit debug-build escape hatch)

**Evidence:**

- ✅ `ensure_fips_rejects_non_fips_server_configs`, `serve_with_config_refuses_non_fips_config` (returns `Err(Config)` without binding), `ensure_fips_accepts_loaded_config` (2026-10-24); mutation check: forcing the gate to `Ok` fails the first two
- ✅ 2026-10-25: `fips_gate_preinstalled` 1/1; `grpc_mtls_e2e` 21/21 (incl.
  `refuses_to_start_without_config`,
  `connector_and_listener_refuse_non_fips_or_non_h2_configs`), re-run by the
  compliance scribe on the final working tree; ca-server bin tests (13 after
  round 3, coder-reported; 9/9 re-run by the scribe before round 2) incl.
  `grpc_defaults_refuse_to_start`, `grpc_insecure_with_allowlist_is_ambiguous`,
  `grpc_client_ca_must_not_be_the_issuing_ca`,
  `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal`. Coder smoke test of the debug binary without a
  database: no gRPC env ⇒ exits with "CA gRPC requires mTLS … refusing to
  start" before the database connects (`impl-notes.md`)

**Gaps (POAM-2026-10-23-05):**

- Plain-HTTP REST mode is still allowed (the process gate runs, but the listener has no TLS); rustls client configs outside gRPC are not asserted
- No `ostrich-audit` event on refusal (error log only; no database pool exists at that point)
- No live evidence from a release (container) build

---

## System and Information Integrity (SI)

### SI-2: Flaw Remediation

**Control:** The organization identifies, reports, and corrects system flaws, and installs security-relevant software updates within organization-defined time periods.

**Implementation Status:** 🟡 **Partial** (flaws are corrected and the CI gate fails on new advisories, but there are no approved time periods and the gate is not yet merge-blocking)

**NIAP Mapping:**

- No PP-CA SFR. Supports ALC_FLR.2 ([SECURITY_TARGET.md §10](SECURITY_TARGET.md#10-assurance-measures))

**Implementation:**

- Flaws are found by RA-5 (`cargo audit`, `pnpm audit`, Dependabot) and fixed by dependency updates, mostly `cargo update -p <crate> --precise <version>` or `pnpm update` (lockfile only, with `package.json` floors raised where needed)
- Each fix is recorded in [CHANGELOG.md](../../CHANGELOG.md) (`### Security`) and reviewed through the CM-3 workflow

**Evidence: 2026-10-23 remediation (RUSTSEC → fixed version)**

| Advisory | Crate | Before → After | cargo-audit severity | Reachability note |
|----------|-------|----------------|----------------------|-------------------|
| RUSTSEC-2026-0285 | rustls | 0.23.41 → 0.23.46 | 5.3 (medium) | All rustls TLS endpoints |
| RUSTSEC-2026-0346 | rustls | 0.23.41 → 0.23.46 | 4.0 (medium) | All rustls TLS endpoints |
| RUSTSEC-2026-0348 | rustls | 0.23.41 → 0.23.46 | 3.7 (low) | All rustls TLS endpoints |
| RUSTSEC-2026-0349 | rustls | 0.23.41 → 0.23.46 | 3.7 (low) | All rustls TLS endpoints |
| RUSTSEC-2026-0382 | rustls-webpki | 0.103.13 → 0.103.16 | not scored | TLS peer path validation |
| RUSTSEC-2026-0381 | webpki-roots | 1.0.5 → 1.0.11 | not scored | Transitive; the workspace-level declaration is unused by members (RFC-004) |
| RUSTSEC-2026-0383 | webpki-root-certs | 1.0.5 → 1.0.11 | not scored | Transitive |
| RUSTSEC-2026-0286 | cryptoki | 0.11.0 → 0.11.1 | not scored | PKCS#11 provider; `pkcs11/mod.rs` does not read `CKA_ALLOWED_MECHANISMS` (PQC review); no PKCS#11 test run at remediation time (QA-004). Later on 2026-10-23: SoftHSM runs 16 passed / 3 RSA-PSS failed / 1 ignored (local macOS, and Linux CI on SoftHSM 2.6.1, exit 101); after the RSA-PSS fix, local SoftHSM 2.7.0 and Linux CI (SoftHSM 2.6.1, run 40063317654, exit 0) both 28 passed / 0 failed / 1 ignored; the `CKA_ALLOWED_MECHANISMS` decode path is still not exercised |
| RUSTSEC-2026-0385 | ctutils | 0.4.2 → 0.4.5 | not scored | sqlx-postgres SCRAM path only (PQC review) |
| RUSTSEC-2026-0258 | h2 | 0.4.15 → 0.4.20 | not scored | HTTP/2 via hyper |
| RUSTSEC-2026-0338 | quinn-proto | 0.11.15 → 0.11.19 | not scored | Target-specific transitive |
| RUSTSEC-2026-0339 | quinn-proto | 0.11.15 → 0.11.19 | not scored | Target-specific transitive |
| RUSTSEC-2026-0340 | quinn-proto | 0.11.15 → 0.11.19 | 7.5 (high) | Target-specific transitive |
| RUSTSEC-2026-0341 | quinn-proto | 0.11.15 → 0.11.19 | 7.5 (high) | Target-specific transitive |
| RUSTSEC-2026-0342 | quinn-proto | 0.11.15 → 0.11.19 | not scored | Target-specific transitive |
| RUSTSEC-2026-0367 | zip | 2.4.2 → 9.0.5 | 7.3 (high) | Not reachable: bulk enrollment never calls `extract()` |
| RUSTSEC-2026-0368 | zip | 2.4.2 → 9.0.5 | not scored | Not reachable (as above) |
| RUSTSEC-2026-0369 | zip | 2.4.2 → 9.0.5 | 9.1 (critical) | Not reachable (as above) |
| RUSTSEC-2026-0386 (unsound) | tokio | 1.50.0 → 1.54.1 | warning | `AsyncFd::new` not called in the workspace |
| RUSTSEC-2026-0221 (unsound) | event-listener | 5.4.1 → 5.4.2 | warning | Transitive |
| yanked | chacha20 | 0.10.0 → 0.10.2 | warning | Transitive |
| yanked | spin | 0.9.8 → 0.9.9 | warning | Transitive |

"Not scored" means the cargo-audit output on 2026-10-23 had no CVSS score for the advisory. Severity values are copied from that output, not assessed here.

- ✅ Result: 0 vulnerabilities, 0 warnings (RA-5 evidence). No advisory was added to `.cargo/audit.toml` by this remediation. (Later on 2026-10-23, RUSTSEC-2026-0387 was added as a risk-accepted ignore, POAM-2026-10-23-16; it was removed on 2026-10-24, see below)
- ✅ zip 9 migration keeps the bulk-enrollment ZIP limits and adds entry-name validation (SI-10; [ATO_EVIDENCE.md](ATO_EVIDENCE.md#bulk-enrollment-zip-hardening-2026-10-23-si-10--si-2))
- ✅ Required side effect: AWS-LC FIPS module 3.3.0 → 4.2.0 (`aws-lc-fips-sys` 0.14.2), approved by the user 2026-10-23 (CM-3 / CM-4 note; SC-13)

**Evidence: 2026-10-24 dependency cleanup (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`)**

| Advisory | Crate | Before → After | Status | Note |
|----------|-------|----------------|--------|------|
| RUSTSEC-2026-0097 (unsound) | rand | 0.8.5 → 0.8.6 | ✅ Remediated 2026-10-24 (target was 2026-11-06); ignore removed from `.cargo/audit.toml` and `deny.toml` | POAM-2026-10-23-11, closed pending first green CI run |
| RUSTSEC-2026-0387 | crypto-bigint | 0.5.5 → removed | ✅ Remediated 2026-10-24 by removing the dependency (no fixed version was compatible); ignore removed from both files | Both roots removed: `openidconnect` (unused in `ostrich-web-ui`, POAM-22) and the integration-test crate's `p256` 0.13 (fixture now uses the software `CryptoProvider`). POAM-2026-10-23-16, closed pending first green CI run |

- ✅ Result: `cargo audit --deny warnings` and `cargo deny check` exit 0 with 3 ignores (RUSTSEC-2023-0071, -2024-0436, -2025-0134). Local only; no CI run recorded for this change

**Evidence: 2026-10-26 Dependabot remediation (branch `claude/dependabot-remediation`, uncommitted; run record `target/agent-workflow/20261026-dependabot-remediation/`)**

Scope: runtime = shipped code (acme-server, web-ui SPA bundle); build = web-ui build tool chain; dev tooling = linting (eslint chain). Windows are the proposed RA-5 values (pending AO approval), counted from publication; days open are as of 2026-10-26. Advisory data (severity, publication date, first patched version, scope) is from the GitHub Dependabot alerts API on 2026-10-26.

| GHSA | Package | Scope | Before → After | First patched | Severity | Published | Days open | Window | Status |
|------|---------|-------|----------------|---------------|----------|-----------|-----------|--------|--------|
| GHSA-6w6g-hm98-mhgm | hickory-resolver | runtime | 0.26.1 → 0.26.2 (with hickory-net, hickory-proto) | 0.26.2 | high | 2026-10-05 | 21 | 30 | ✅ Remediated, within window. Reachable (dns-01 TXT lookup); the truncation retry is now bounded and fails closed |
| GHSA-5j98-2g5x-46v6 | hickory-resolver | runtime | 0.26.1 → 0.26.2 | 0.26.2 | high | 2026-10-05 | 21 | 30 | ✅ Remediated, within window. Not reachable (DNSSEC feature not enabled) |
| GHSA-6f2x-v7q7-m7m5 | hickory-resolver | runtime | 0.26.1 → 0.26.2 | 0.26.2 | medium | 2026-10-05 | 21 | 90 | ✅ Remediated, within window. Not reachable (`recursor` feature not enabled) |
| GHSA-jjmj-jmhj-qwj2 | react-router-dom | runtime | 6.30.4 → 6.30.6 | 6.30.6 | medium | 2026-07-23 | 95 | 90 | ✅ Remediated, overdue |
| GHSA-wrjc-x8rr-h8h6 | react-router | runtime | 6.30.4 → 6.30.6 (still affected); 7.18.4 on 2026-10-26 | 7.18.0 | medium | 2026-07-23 | 95 | 90 | ✅ Remediated 2026-10-26 (react-router v7 migration), overdue (window ended 2026-10-21) (POAM-2026-10-23-39, closed pending commit) |
| GHSA-337j-9hxr-rhxg | react-router | runtime | 6.30.4 → 6.30.6 (still affected); 7.18.4 on 2026-10-26 | 7.18.0 | medium | 2026-07-23 | 95 | 90 | ✅ Remediated 2026-10-26 (react-router v7 migration), overdue (window ended 2026-10-21); was not reachable (Declarative Mode) (POAM-2026-10-23-39, closed pending commit) |
| GHSA-587h-7wmj-h5pm | vite | build | 8.1.3 → 8.1.6 | 8.1.6 | high | 2026-10-20 | 6 | 30 | ✅ Remediated, within window |
| GHSA-698v-4r3x-3vcv | vite | build | 8.1.3 → 8.1.6 | 8.1.6 | medium | 2026-10-20 | 6 | 90 | ✅ Remediated, within window |
| GHSA-r825-w8mm-5pxw | vite | build | 8.1.3 → 8.1.6 | 8.1.6 | medium | 2026-10-20 | 6 | 90 | ✅ Remediated, within window |
| GHSA-rq7h-c2jc-7f22 | vite | build | 8.1.3 → 8.1.6 | 8.1.6 | medium | 2026-10-21 | 5 | 90 | ✅ Remediated, within window |
| GHSA-9jrq-w75r-8gcw | vite | build | 8.1.3 → 8.1.6 | 8.1.6 | low | 2026-10-21 | 5 | 90 | ✅ Remediated, within window |
| GHSA-68fv-2mgg-jv7q | source-map-js | build | 1.2.1 → 1.2.2 | 1.2.2 | high | 2026-09-18 | 38 | 30 | ✅ Remediated, overdue |
| GHSA-r28c-9q8g-f849 | postcss | build | 8.5.16 → 8.5.31 | 8.5.18 | high | 2026-07-24 | 94 | 30 | ✅ Remediated, overdue |
| GHSA-fxqj-rqcc-2cmp | postcss | build | 8.5.16 → 8.5.31 | 8.5.23 | medium | 2026-08-03 | 84 | 90 | ✅ Remediated, within window |
| GHSA-3jxr-9vmj-r5cp | brace-expansion | dev tooling | 1.1.15 → 1.1.21; 5.0.6 → 5.0.12 | 1.1.16 / 5.0.7 | high | 2026-07-20 | 98 | 30 | ✅ Remediated, overdue |
| GHSA-q2hr-2g5m-vwhr | brace-expansion | dev tooling | 1.1.15 → 1.1.21; 5.0.6 → 5.0.12 | 1.1.21 / 5.0.12 | medium | 2026-09-29 | 27 | 90 | ✅ Remediated, within window |
| GHSA-52cp-r559-cp3m | js-yaml | dev tooling | 4.2.0 → 4.3.2 | 4.3.0 | high | 2026-07-20 | 98 | 30 | ✅ Remediated, overdue |
| GHSA-5p4m-2wfm-xmqj | js-yaml | dev tooling | 4.2.0 → 4.3.2 | 4.3.1 | high | 2026-08-06 | 81 | 30 | ✅ Remediated, overdue |
| GHSA-2883-xcg3-v3hh | js-yaml | dev tooling | 4.2.0 → 4.3.2 | 4.3.2 | high | 2026-09-08 | 48 | 30 | ✅ Remediated, overdue |

- ✅ Result: 19 GHSAs, 21 open Dependabot alerts (brace-expansion has one alert per major line). 17 GHSAs (19 alerts) remediated; 2 GHSAs (alerts 27, 28) remain. Also updated as dependencies of vite: rolldown 1.1.4 → 1.1.5 and lightningcss; `@remix-run/router` 1.23.3 → 1.23.4 with react-router. `package.json` floors raised: `vite` ^8.1.6, `react-router-dom` ^6.30.6. No other `Cargo.lock` entry changed (an unplanned socket2 downgrade was reverted, SEC-001 / NIST-001)
- ✅ Regression gates (local only; first CI run pending): `make security` (`cargo audit --deny warnings`, `cargo deny check`), `make clippy` and `make test-unit` (782 passed / 0 failed / 1 ignored) pass; web-ui `pnpm install --frozen-lockfile`, typecheck, lint and build pass; full `pnpm audit` 28 → 2 moderate. Integration tests were not run (no database on the host; no code path changed). After merge, cite the Dependabot auto-close of the 19 alerts as CI-side evidence
- ✅ ~~Residual: react-router v6 GHSA-wrjc-x8rr-h8h6 and GHSA-337j-9hxr-rhxg → POAM-2026-10-23-39~~ closed by the react-router v7 migration on 2026-10-26 (next record)

**Evidence: 2026-10-26 react-router v7 migration (branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`)**

| GHSA | Package | Scope | Before → After | First patched | Severity | Published | Days open | Window | Status |
|------|---------|-------|----------------|---------------|----------|-----------|-----------|--------|--------|
| GHSA-wrjc-x8rr-h8h6 | react-router | runtime | 6.30.6 (via `react-router-dom` 6.30.6) → 7.18.4 | 7.18.0 | medium | 2026-07-23 | 95 | 90 | ✅ Remediated, overdue |
| GHSA-337j-9hxr-rhxg | react-router | runtime | 6.30.6 → 7.18.4 | 7.18.0 | medium | 2026-07-23 | 95 | 90 | ✅ Remediated, overdue (was not reachable) |

- ✅ Change: `services/web-ui/web/package.json` (line 24) `react-router-dom` ^6.30.6 → `react-router` ^7.18.1 (v7 is a single package). `pnpm-lock.yaml`: removed `react-router-dom` 6.30.6, `react-router` 6.30.6 and `@remix-run/router` 1.23.4; added `react-router` 7.18.4, `cookie` 1.1.1 and `set-cookie-parser` 2.7.3; no other package changed. The development-dependency fixes (brace-expansion, js-yaml, picomatch, vite 8.1.6) came with the earlier Dependabot remediation on `main` and are not part of this change. Imports moved from `react-router-dom` to `react-router` in 11 source files; the app stays in Declarative Mode (`<BrowserRouter basename>`)
- ✅ Defence in depth for the CWE-601 class (SI-10): non-literal navigation targets go through `safeInternalPath`, and server-returned IDs are encoded as one path segment (see SI-10)
- ✅ Gates (local, 2026-10-26): `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm build` pass (pre-existing >500 kB chunk warning); full `pnpm audit` "No known vulnerabilities found" (re-run by the compliance scribe). [TEST_EVIDENCE.md §2.11](TEST_EVIDENCE.md#211-test-run-2026-10-26-web-ui-react-router-v7-migration)
- 🟡 Timeliness: remediated on day 95 against the proposed 90-day window (SI-2(c) missed). No CI run yet; after merge, cite the Dependabot auto-close of alerts 27 and 28

**Gaps:**

- No AO-approved flaw-remediation time periods (proposed values in RA-5, pending AO approval)
- The dependency gate fails in CI, but merge-blocking is pending required checks on `main` (POAM-2026-10-23-14); until then a vulnerable dependency can still be merged past a red check (RA-5)
- The cryptoki fix has SoftHSM test evidence only. The SoftHSM CI job ran on Linux before the RSA-PSS fix (16 passed / 3 RSA-PSS failed / 1 ignored, exit 101) and after it ([run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654): 28 passed / 0 failed / 1 ignored, exit 0); local SoftHSM 2.7.0 also gives 28/0/1. POAM-2026-10-23-07 and POAM-2026-10-23-17 closed 2026-10-23. No run exercises the `CKA_ALLOWED_MECHANISMS` decode path, because `ostrich-crypto/src/pkcs11` never reads that attribute
- The 2026-10-24 removals of RUSTSEC-2026-0097 and RUSTSEC-2026-0387 (POAM-11, POAM-16, POAM-22) are verified locally only; they stay on the POA&M until a CI run of the gate records the same result
- `oauth2` 5.0.0 is a declared but unused dependency of `ostrich-web-ui` (no call sites); removal tracked as POAM-2026-10-23-23 (CM-7)
- **SI-2(c) timeliness was missed** for 9 of the 19 npm and Rust advisories in the 2026-10-26 table (measured against the proposed windows). The last 2 (react-router, POAM-2026-10-23-39) were remediated on 2026-10-26 on day 95 and stay in this count. Dependabot alerts are not triaged on a schedule (POAM-2026-10-23-42)
- The 2026-10-26 remediation is verified locally only; no CI run is recorded yet

**Remediation:** see RA-5 and the POA&M in [NIAP_GAP_ANALYSIS.md §11](NIAP_GAP_ANALYSIS.md#11-plan-of-action-and-milestones-poam--open-items)

---

### SI-7: Software, Firmware, and Information Integrity

**Control:** The organization employs integrity verification tools to detect unauthorized changes.

**Implementation Status:** 🔴 **Not Implemented**

**NIAP Mapping:**

- FPT_TST_EXT.1 - TSF Self-Test (TOE Integrity)
- FPT_TST_EXT.2 - TSF Self-Test (TSF Data Integrity)

**Implementation:**

- None

**Gaps:**

- No software integrity verification
- No Trust Anchor Database integrity checking
- Audit hash chain defined but verification not implemented

**Remediation:**

- Phase 15 - Create integrity verification stub module
- Phase 13 - Implement audit hash chain verification
- Phase 16 - Implement binary signature verification

**Evidence Required for ATO:**

- Code signing procedures
- Integrity verification test results
- Trust anchor integrity verification

---

### SI-10: Information Input Validation

**Control:** The information system checks the validity of information inputs.

**Implementation Status:** 🟢 **Good (85%)**

**NIAP Mapping:**

- FIA_X509_EXT.1 - X.509 Certificate Validation
- FCO_NRO_EXT.2 - Proof of Origin (CSR validation)
- FDP_ITC.1 - Import of user data (DN and SAN extraction)

**Implementation:**

- [crates/ostrich-x509/src/parser.rs:11-91](../../crates/ostrich-x509/src/parser.rs#L11-L91) - **CSR SAN extraction**
- [crates/ostrich-x509/src/parser.rs:93-174](../../crates/ostrich-x509/src/parser.rs#L93-L174) - **DN parsing**
- [crates/ostrich-x509/src/parser.rs:326-355](../../crates/ostrich-x509/src/parser.rs#L326-L355) - **CSR signature verification (centralized)**
- [crates/ostrich-x509/src/validation/](../../crates/ostrich-x509/src/validation/) - **Path validation (Phase 15)**
- [crates/ostrich-acme/src/ca_integration.rs:153-177](../../crates/ostrich-acme/src/ca_integration.rs#L153-L177) - ACME DN validation
- [crates/ostrich-est/src/ca_integration.rs:197-221](../../crates/ostrich-est/src/ca_integration.rs#L197-L221) - EST DN validation

**Evidence:**

- ✅ **Subject DN parsing from CSRs** (RFC 5280 §4.1.2.4, RFC 4514)
  - OID-based attribute extraction (CN, O, OU, L, ST, C, serialNumber)
  - Multi-valued RDN support
  - ASN.1 string type handling (UTF8String, PrintableString, IA5String, etc.)
  - Security: Prevents DN spoofing through proper parsing
  - Test coverage: 2 unit tests with real OpenSSL CSRs
- ✅ **SAN extraction from CSR extension requests** (RFC 5280 §4.2.1.6)
  - Parses OID 2.5.29.17 from CSR attributes
  - Supports all 9 GeneralName types (Phase 15 enhancement)
  - Used by ACME and EST for certificate issuance
  - Test coverage: 1 integration test + 5 unit tests with all GeneralName types
- ✅ **Resilient PKCS#10 acceptance** (RFC 2986 §4, RFC 2985 §5.4.1) — accept
  well-formed input, do not reject over-strictly (SI-10 intent)
  - `parse_csr` / `parse_csr_subject_dn` / `verify_csr_signature` fall back to a
    der-based (`x509-cert`) decode when x509-parser deep-parses a
    `challengePassword` and rejects the whole request with `InvalidAttributes`
    (IA5String, or PrintableString with out-of-repertoire characters — common
    from device/NPE enrollment clients). See `parse_csr_der_fallback`,
    `extract_cert_req_info_tbs`, `der_tlv` in `crates/ostrich-x509/src/parser.rs`.
  - The same fallback also accepts a CSR that OMITS the mandatory-but-emptyable
    `attributes [0]` field (RFC 2986 §4.1) — `normalize_missing_attributes`
    injects an empty `SET OF` (only when absent). pkijs (the NPE portal in-browser
    generator) and other lightweight clients emit these; OpenSSL accepts them but
    strict Rust decoders do not. The generator was also fixed to always emit the
    field (`services/npe-portal/web/src/lib/csr.ts`).
  - Fail-safe: the fallback only runs after the strict parse fails, so it cannot
    change results for CSRs that parse today; PoP signature verification is still
    enforced over the byte-exact (original) CertificationRequestInfo, and the
    subject DN is rendered/decoded via x509-parser (identical to the primary path,
    so EST re-enrollment identity binding is unaffected).
  - Test coverage: `test_parse_csr_ia5_challenge_password_fallback`,
    `test_parse_csr_printable_challenge_password_fallback`
    (`tests/integration/csr_parsing_test.rs`),
    `test_parse_csr_missing_attributes_field`
    (`crates/ostrich-x509/src/parser.rs`).
- ✅ **CSR signature verification** (RFC 2986 §4.2, FCO_NRO_EXT.2)
  - Centralized implementation in ostrich-x509/src/parser.rs:326-355
  - Verifies proof-of-possession before certificate issuance
  - Supports RSA (PKCS#1, PSS), ECDSA (P-256, P-384, P-521), EdDSA (Ed25519). For id-RSASSA-PSS the parser does not read RSASSA-PSS-params and assumes SHA-256 (`parser.rs`, `path_validator.rs`; PQC-002, POAM-2026-10-23-20)
  - Used by ACME (rest.rs:806-814), EST simpleenroll (rest.rs:268-276), EST simplereenroll (rest.rs:360-368)
  - Algorithm OID mapping: parser.rs:422-444
  - Public key import: parser.rs:357-419
  - Integration tested via ACME/EST endpoints
- ✅ **RFC 5280 §6 Path Validation** (Phase 15)
  - Certificate chain building to trust anchor
  - Signature verification framework
  - Validity period checking
  - Basic constraints enforcement
  - Key usage validation
  - 80 unit tests covering all validation steps
- ✅ ACME JWS validation implemented (Phase 11)
- ✅ CA gRPC allowlist and peer-certificate parsing (2026-10-25, branch
  `claude/grpc-mtls`, uncommitted): `ClientSubjectAllowlist::parse` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) rejects dangling
  or incomplete escapes, an escaped backslash before an escaped `,`/`+`,
  invalid attribute types and numeric OIDs whose arcs overflow, entries over
  512 bytes, and any entry whose canonical form does not round-trip to the
  same DER; blank entries are dropped and an all-blank list is refused. Peer
  certificates that cannot be parsed are denied (`unparsable_certificate`).
  The fuzz target `fuzz/fuzz_targets/fuzz_grpc_peer_subject.rs` found an
  OID-arc overflow panic in allowlist parsing, which was fixed
  (`validate_attribute_types`, with regression tests); after the fix the
  coder reports 237,187 runs in 61 s with no crash (`fixes-round-1.md`; not
  re-run by the compliance scribe). Unit test
  `subject_parsing_never_panics_on_mutated_input` (3000 deterministic
  iterations) is part of the 34 passing `grpc_tls::tests`
- ✅ CA gRPC requestor and role-list validation (2026-10-26, branch
  `claude/grpc-per-method-authz`, uncommitted): `validate_requestor` in
  [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) accepts a
  `requestor` only with the caller's exact namespace prefix (`acme::`,
  `est::`, `admin::`), a non-empty id of printable ASCII `0x21`-`0x7E`, and at
  most 255 bytes (`MAX_REQUESTOR_LEN`, the `certificates.requestor` column
  width); the claimed namespace is truncated to 32 characters and escaped in
  the denial record, the requested profile to 64. The gRPC method path is
  matched exactly (no case folding or percent-decoding). est-server applies
  the same rule before enrollment (EST ids 1-250 printable ASCII, HTTP 403,
  `ca_requestor_matches_ca_rule`). Numeric OID attribute types in the role
  lists must decode again under const-oid: `fuzz_grpc_peer_subject` found a
  `Display` panic ("OID malformed: ArcTooBig") on operator configuration text,
  now refused (`check_attribute_type`; test
  `allowlist_refuses_undecodable_numeric_oid`). Fuzz (coder-reported, final
  tree, 60 s each): `fuzz_grpc_requestor` 246,720 runs, `fuzz_grpc_peer_subject`
  135,145 runs, no crash after the fix. Unit: `validate_requestor_cases`,
  `qa_validate_requestor_boundaries`; e2e requestor-edge-case tests
  (`grpc_mtls_e2e` 39/39)
- ✅ Web UI client-side navigation guard (2026-10-26, branch `claude/react-router-v7`, uncommitted; defence in
  depth, CWE-601). [safe-path.ts](../../services/web-ui/web/src/lib/safe-path.ts)
  `isSafeInternalPath` accepts a navigation target only if it starts with one
  `/` not followed by `/` or `\`, contains no `\` and no C0 / DEL control
  character, has no empty (`//`) or `.` / `..` segment, and still has the probe
  origin under the WHATWG URL parser; `safeInternalPath` otherwise returns
  `/dashboard`. Call sites: the Cloudscape `onFollow` handlers in
  `src/components/layout/cloudscape-layout.tsx` (line 68) and
  `src/pages/dashboard.tsx` (line 65), after `preventDefault()`. Server-returned
  IDs are encoded with `encodeURIComponent` as one path segment in route
  targets (`certificate-issue.tsx` line 139, `certificates.tsx` line 213,
  `fqdn-detail.tsx` lines 162 and 239, `fqdns.tsx` line 64) and in the CA API
  paths (`src/lib/ca.ts` lines 65 and 166; `src/lib/fqdn.ts` already did this).
  **Standing rule:** every web-ui navigation target that is not a compile-time
  literal goes through `safeInternalPath`, and every server-derived path
  segment is encoded. Server-side validation in the BFF and the backends
  remains the control; the BFF proxy still forwards a percent-decoded path
  (POAM-2026-10-23-43). Evidence: run-record script `safe-path-check.mjs`
  181 checks / 0 failures and `router-smoke.mjs` 5 / 0 (manual; no web-ui
  test runner, POAM-2026-10-23-44); browser smoke against a mock BFF
  ([TEST_EVIDENCE.md §2.11](TEST_EVIDENCE.md#211-test-run-2026-10-26-web-ui-react-router-v7-migration))
- 🟡 Related SI-11 (error handling), 2026-10-26: gRPC errors that are not
  client-correctable return `INTERNAL` "<op> failed: internal error" with the
  detail logged (`grpc_status`, test `grpc_status_hides_internal_errors`);
  CSR parse / verify errors and the missing approval repository use fixed
  messages. REST 5xx bodies still carry internal error text
  (POAM-2026-10-23-37). No separate SI-11 section is added here

**Gaps:**

- ⚠️ No comprehensive malformed CSR rejection testing
- ⚠️ Need dedicated unit tests for CSR signature verification with test vectors

**Remediation:** Phase 16 - Add fuzzing tests for malformed input rejection, expand test vectors

**Evidence Required for ATO:**

- Input validation procedures
- Fuzzing test results
- Invalid input rejection tests
- DN/SAN parsing test results (✅ COMPLETED)
- CSR signature verification test results (✅ Integration tested via ACME/EST endpoints)

---

### SI-12: Information Handling and Retention

**Control:** The organization handles and retains information within the information system.

**Implementation Status:** 🟡 **Partial**

**Implementation:**

- Database persistence for all critical data
- Audit trail retention

**Evidence:**

- ✅ Certificates, CRLs, audit events persisted
- ✅ gRPC client private keys (2026-10-25): read straight into
  `Zeroizing<String>` (`read_private_key_pem`), held only until rustls parses
  them; `GrpcClientConfig`'s `Debug` output redacts the key
  ([grpc_client.rs](../../crates/ostrich-common/src/grpc_client.rs))
- 🔴 No retention policy defined
- 🔴 No data disposal procedures

**Gaps:**

- No documented retention periods
- No automatic data archival/deletion

**Remediation:** Document data retention policy in ATO package

**Evidence Required for ATO:**

- Data retention policy
- Data classification guide
- Disposal procedures

---

### SI-17: Fail-Safe Procedures

**Control:** The information system implements fail-safe procedures to preserve system state information in the event of a system failure.

**Implementation Status:** ✅ **Implemented (Phase 12)**

**NIAP Mapping:**

- FPT_FLS.1 - Failure with Preservation of Secure State

**Implementation:**

- ✅ Circuit breaker pattern for service resilience ([crates/ostrich-common/src/grpc_client.rs:91-163](../../crates/ostrich-common/src/grpc_client.rs#L91-L163))
- ✅ Three states: Closed (normal) → Open (failed) → HalfOpen (testing recovery)
- ✅ Automatic failure detection (5 consecutive failures trigger circuit open)
- ✅ Timed recovery testing (60-second timeout before half-open)
- ✅ Safe failure mode: Requests blocked when circuit is open
- ✅ Prevents cascading failures across services

**Evidence:**

- ✅ Circuit breaker implementation with failure tracking
- ✅ Configurable failure threshold and timeout
- ✅ Fail-secure behavior (block requests rather than risk data corruption)
- ✅ Service health state preservation

**Code References:**

- `crates/ostrich-common/src/grpc_client.rs:91-163` - CircuitBreaker implementation
- `crates/ostrich-common/src/grpc_client.rs:165-240` - Circuit state management
- `crates/ostrich-acme/src/ca_integration.rs:100-110` - Usage in ACME service
- `crates/ostrich-est/src/ca_integration.rs:98-108` - Usage in EST service

**Testing Evidence:**

- Circuit breaker state transitions tested (Closed → Open → HalfOpen)
- Failure threshold enforcement verified
- Recovery behavior validated

**Evidence Required for ATO:**

- ✅ Circuit breaker configuration documentation (Phase 12)
- ✅ Failure handling test results
- ⏳ Chaos engineering results (Phase 14)

---

## Control Implementation Summary

| Control Family | Total Controls | Compliant 🟢 | Partial 🟡 | Missing 🔴 | Compliance % |
|----------------|----------------|-------------|-----------|-----------|--------------|
| AC (Access Control) | 8 | 0 | 3 | 5 | 19% |
| AU (Audit) | 10 | 4 | 4 | 2 | 60% |
| CM (Configuration) | 4 | 0 | 4 | 0 | 50% |
| CP (Contingency) | 2 | 0 | 1 | 1 | 25% |
| IA (Identification/Auth) | 4 | 0 | 3 | 1 | 38% |
| RA (Risk Assessment) | 1 | 0 | 1 | 0 | 50% |
| SC (System Protection) | 8 | 2 | 5 | 1 | 56% |
| SI (System Integrity) | 4 | 0 | 3 | 1 | 38% |
| **TOTAL** | **41** | **6** | **24** | **11** | **44%** |

Compliance % = (Compliant + 0.5 × Partial) / Total. On 2026-10-23 only the
RA row (new: RA-5, Partial), the SI row (SI-2 added as Partial) and the TOTAL
row were recalculated. The SI row now counts 4 controls: SI-2 plus the 3
previously counted. The previous TOTAL of 40% did not match its own counts
((6 + 9) / 35 = 42.9%). The new TOTAL is (6 + 10) / 37 = 43.2%, of which the
two added Partial controls contribute +0.3 points. The other rows have not been
reconciled with the per-control statuses above (for example, SC-8 and SC-23 are
marked Implemented in their sections, and SI-10, SI-12 and SI-17 have sections
but only 3 SI controls were counted before). This table is not an assessed
compliance figure.

On 2026-10-24 SC-24 (new, Partial) was added to the SC row and TOTAL. SC row:
(2 + 0.5 × 5) / 8 = 56.3%. The previous 43% did not match its own counts
((2 + 0.5 × 4) / 7 = 57.1%); with the new Partial control the row is 56%. No
other SC status changed, and the SC row is still not reconciled with the SC
sections (SC-8 and SC-23 marked Implemented). TOTAL: (6 + 0.5 × 21) / 38 =
16.5 / 38 = 43.4%, shown as 43% (was 43.2%).

Later on 2026-10-24 CM-7 (new, Partial) was added to the CM row and TOTAL. CM
row: (0 + 0.5 × 4) / 4 = 50% (unchanged). TOTAL: (6 + 0.5 × 22) / 39 = 17 / 39
= 43.6%, shown as 44% (was 43.4%). The +0.2 points come only from counting one
more Partial control; no existing status changed.

On 2026-10-25 AC-4 (new, Partial) was added to the AC row and IA-3 (new,
Partial) to the IA row. AC row: (0 + 0.5 × 4) / 9 = 2 / 9 = 22.2%, shown as
22% (was (0 + 0.5 × 2) / 7 = 14.3%). IA row: (0 + 0.5 × 3) / 4 = 1.5 / 4 =
37.5%, shown as 38% (was 33%). TOTAL: (6 + 0.5 × 24) / 41 = 18 / 41 = 43.9%,
shown as 44% (was 43.6%). No existing control status changed; the rows are
still not reconciled with the per-control sections (for example AC-3, AC-5,
AC-7 and AC-12 are marked Implemented in their sections but counted as 0
Compliant here).

Correction later on 2026-10-25 (final refresh, NIST-019): the AC row above
was wrong. AC-4 is the only control added to the AC family (AC-17 and AC-3
already had sections and were already counted), so the row is 7 + 1 = 8
controls (sections AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-12, AC-17), Compliant
0, Partial 2 + 1 = 3, Missing 5. AC row: (0 + 0.5 × 3) / 8 = 1.5 / 8 = 18.75%,
shown as 19% (the 22% shown before, (0 + 0.5 × 4) / 9, counted one Partial
control too many). The TOTAL row did not carry the error: the rows sum to
8 + 10 + 4 + 2 + 4 + 1 + 8 + 4 = 41 controls, Compliant
0 + 4 + 0 + 0 + 0 + 0 + 2 + 0 = 6, Partial 3 + 4 + 4 + 1 + 3 + 1 + 5 + 3 = 24,
Missing 5 + 2 + 0 + 1 + 1 + 0 + 1 + 1 = 11, so TOTAL stays
(6 + 0.5 × 24) / 41 = 18 / 41 = 43.9%, shown as 44%. No control status changed
in the final refresh.

On 2026-10-26 (per-method CA gRPC authorization) no control was added and no
control status changed, so the table is unchanged: AC-3 stays 🟢 Implemented,
AC-5 🟢, AC-6 🟡 Partial (the REST user-privilege gaps remain), AU-3 ✅, AU-10
🟢, AU-12 🟢, CM-6 🟡, CM-7 🟡, IA-3 🟡 (revocation and Issuer-role binding
gaps), SI-10 as before. SI-11 and IA-9 are cited as related controls inside
existing sections, not counted as new rows. TOTAL stays
(6 + 0.5 × 24) / 41 = 18 / 41 = 43.9%, shown as 44%.

---

## Cross-Reference: NIAP SFR ↔ NIST 800-53

| NIAP SFR | NIST 800-53 Controls |
|----------|---------------------|
| FAU_GEN.1 | AU-2, AU-3, AU-12 |
| FAU_GEN.2 | AU-3 |
| FAU_SAR.1 | AU-6 |
| FAU_SAR.2 | AU-6, AU-9 |
| FAU_STG.1 | AU-9 |
| FAU_STG.4 | AU-5 |
| FCS_CKM.1 | SC-12, SC-13 |
| FCS_CKM_EXT.4 | SC-12, SI-12 |
| FCS_COP.1 | SC-13 |
| FCS_RBG_EXT.1 | SC-13 |
| FCS_STG_EXT.1 | SC-12, SC-13 |
| FCS_TLSC_EXT.2 | SC-8, AC-17, IA-3 |
| FCS_TLSS_EXT.1 | SC-8, AC-17 |
| FCS_TLSS_EXT.2 | SC-8, AC-17, IA-3 |
| FCO_NRO_EXT.2 | AU-10, SI-10 |
| FDP_CER_EXT.1 | SC-17 |
| FDP_CER_EXT.2 | AU-10 |
| FDP_ACC.1 | AC-3, AC-6 |
| FDP_ACF.1 | AC-3, AC-6 |
| FDP_CER_EXT.3 | AC-3 |
| FDP_RIP.1 | SC-4 |
| FIA_AFL.1 | AC-7 |
| FIA_PMG_EXT.1 | IA-5 |
| FIA_UAU_EXT.1 | IA-2, IA-5 |
| FIA_UIA_EXT.1 | IA-2 |
| FIA_X509_EXT.1 | IA-3, IA-5(2), SC-17, SI-10 |
| FIA_X509_EXT.2 | IA-2, IA-5 |
| FMT_MOF.1 | AC-3, AC-6 |
| FMT_MTD.1 | AC-3 |
| FMT_SMR.2 | AC-2, AC-5, IA-3 |
| FPT_FLS.1 | SC-24 (Fail in Known State), SI-13 (Predictable Failure Prevention), SI-17 (Fail-Safe Procedures) |
| FPT_KST_EXT.1 | SC-12 |
| FPT_KST_EXT.2 | SC-12 |
| FPT_STM.1 | AU-8 |
| FPT_TST_EXT.1 | SI-7 |
| FPT_TST_EXT.2 | SI-7 |
| FTA_SSL.3 | AC-12 |
| FTA_SSL.4 | AC-12 |
| FTP_ITC.1 | SC-8, AC-17, IA-3 |
| FTP_TRP.1 | SC-8, AC-17 |

---

## ATO Evidence Collection Guide

### System Security Plan (SSP) Mapping

For each control family, the SSP must document:

1. **Control Implementation Status**: Compliant, Partial, Not Implemented
2. **Control Description**: How OstrichPKI implements the control
3. **Implementation Details**: Code references, configuration settings
4. **Responsible Role**: Which organizational role manages the control
5. **Test Evidence**: How compliance is verified

**Example SSP Entry for AU-3:**

```
Control: AU-3 - Content of Audit Records
Implementation Status: Compliant
Responsible Role: System Administrator
Implementation: OstrichPKI audit system (ostrich-audit module) generates audit records
containing: event type, timestamp, subject identity (actor), outcome, object accessed
(resource), event correlation ID (request_id), and additional context (details field).

Evidence:
- Code: crates/ostrich-audit/src/event.rs:47-110 (AuditEvent struct)
- Test: tests/audit_content_test.rs (validates all required fields present)
- Log Sample: See Appendix A for sample audit log entries
```

### Security Assessment Report (SAR) Evidence

For each control, provide:

- Test procedures
- Test results (pass/fail)
- Screen captures or log excerpts
- Mitigations for partial implementations

### Plan of Action and Milestones (POA&M)

For each missing or partial control:

- Control identifier
- Description of gap
- Remediation plan (mapped to development phases)
- Responsible party
- Target completion date
- Risk level (High, Moderate, Low)

**Example POA&M Entry:**

```
Control: AC-3 - Access Enforcement
Status: Not Implemented
Gap: No role-based access control (RBAC) system
Risk: HIGH
Remediation: Implement RBAC with role-based authorization checks on all endpoints
Phase: 15 (Foundation), 16 (Full Implementation)
Target Date: 2026-03-15
Responsible: Development Team
Mitigation: System deployed in trusted environment with network access controls
```

---

## Trust Anchor Management Protocol (RFC 5934) — Control Evidence

The `ostrich-tamp` crate and `ostrich-tamp-server` (TAMP manager role)
implement the following controls:

- **SC-12 (Cryptographic Key Establishment and Management):** durable
  authoritative trust-anchor store; trust anchors added / removed / changed and
  the apex rotated via signed TAMP messages.
  [crates/ostrich-tamp/src/manager.rs](../../crates/ostrich-tamp/src/manager.rs),
  [crates/ostrich-db/src/repository/tamp.rs](../../crates/ostrich-db/src/repository/tamp.rs).
- **SC-13 (Cryptographic Protection):** messages protected with CMS `SignedData`
  using signing/verification in the AWS-LC FIPS 4.2.0 module via
  `ostrich-crypto` (CMVP certificate for 4.2.0 pending confirmation, POA&M).
  [crates/ostrich-tamp/src/cms.rs](../../crates/ostrich-tamp/src/cms.rs).
- **SC-23 (Session Authenticity):** monotonic per-signer sequence numbers with a
  transactional, row-locked check-and-advance reject replays (RFC 5934 §4.1).
  `TampRepository::check_and_advance_seq`.
- **SI-10 (Information Input Validation):** strict DER decoding of all received
  CMS / TAMP structures; malformed input is rejected with `decodeFailure`.
- **SI-12 (Information Handling and Retention):** contingency-key plaintext
  material is held in `zeroize`-backed buffers.
- **AU-2 / AU-3 / AU-12 (Audit):** every issued message, ingested confirmation,
  and trust-anchor state change emits an `EventType::TampProtocol` audit event
  (actor, target, action, outcome, sequence number, signer SKI).
- **IA-7 (Cryptographic Module Authentication):** the apex/management signing
  key is provided by the crypto provider (HSM/PKCS#11 in production).
- **AC-3 (Access Enforcement):** REST endpoints require `ModifyConfig`
  (mutating) / `ViewConfig` (read) RBAC permissions.
  [crates/ostrich-tamp/src/rest.rs](../../crates/ostrich-tamp/src/rest.rs).

---

## NPE Portal (Non-Person Entity enrollment)

The `ostrich-npe-portal` service (standalone Axum BFF + React/Cloudscape SPA)
adds a self-service enrollment portal authenticated by mTLS client certificate.

- **IA-2 / IA-5(2) (Identification & PKI-Based Authentication):** operators
  authenticate passwordlessly by client certificate; the verified leaf is
  surfaced via `ostrich_common::tls::PeerCertificate` and mapped to an NPE role
  from its certificate-policy OIDs — `services/npe-portal/src/server/oid.rs`
  (`authenticate`).
- **CM-6 (Secure Defaults / Fail Secure):** the service refuses to start without
  mandatory mTLS (server cert/key + client CA) unless `--allow-insecure` is set
  for development — `services/npe-portal/src/main.rs`.
- **AC-3 / AC-6 / AC-5 (Access Enforcement / Least Privilege / SoD):** five
  OID-derived roles (PkiSponsor, PkiSponsorAdmin, RegistrationAuthority, CaaAdmin,
  and a read-only NpeAuditor for independent audit review) with a
  least-privilege permission map —
  `crates/ostrich-common/src/auth/{roles.rs,permissions.rs}`. The proxy forwards
  the authenticated identity (`X-Npe-*` headers, with inbound spoofs stripped)
  and is allowlisted to CA/EST only — `services/npe-portal/src/server/proxy.rs`.
  Issuer scoping (`allowed_issuers`) prevents a role-granting OID asserted by an
  unauthorized CA in the trusted bundle from conferring privilege. The approval
  queue handlers gate "see all pending / view any request" on the `ApproveRequest`
  permission (not a hardcoded role set), so every approver role — including the
  NPE `RegistrationAuthority` — sees the queue it is authorized to act on
  (`crates/ostrich-ca/src/rest.rs` `list_approval_requests` / `get_approval_request` /
  `bulk_approval_status`). The approval engine's segregation-of-duties check
  (`ApprovalRequest::can_approve`, used by both approve and reject) likewise gates
  on the `ApproveRequest` permission, so the REST and engine layers agree.
  Sponsor self-service inventory views are explicitly scoped to the authenticated
  requestor: certificate list/detail/stats, FQDN history, and EST token metadata
  use repository-level owner predicates (`crates/ostrich-ca/src/rest.rs`,
  `crates/ostrich-db/src/repository/{certificate,fqdn,est}.rs`). Token list and
  revoke in EST are likewise scoped to `created_by` for NPE sponsors while legacy
  CA operator/admin token managers retain global visibility (`crates/ostrich-est/src/rest.rs`).
- **AC-3 / AU-2 (Override of validation):** approving despite validation advisories
  (`POST /api/v1/approvals/{id}/approve?override=true`) requires the distinct
  `OverrideValidation` permission on top of `ApproveRequest`; the override is
  recorded on the decision (`metadata.validation_overridden`, annotated
  justification) and emitted as a high-signal audit log line —
  `crates/ostrich-ca/src/rest.rs` `approve_request`.
- **AC-2 / AC-5 (Account Management / Separation of Duties):** the CAA user
  management API (`crates/ostrich-ca/src/rest.rs` `list_users` / `create_user` /
  `set_user_roles` / `set_user_status` / `delete_user`) is gated per-verb by the
  `ViewUsers` / `CreateUser` / `AssignRoles` / `ModifyUser` / `DeleteUser`
  permissions, and enforces a self-action block: a CAA may never modify, disable,
  or delete their own account (`load_target_user_guarded`), so a privileged admin
  cannot remove the controls on themselves. Unknown role names are rejected
  (SI-10) rather than silently dropped.
- **AC-8 (System Use Notification):** mandatory USG consent gate before any
  proxied API call — `services/npe-portal/src/server/{router.rs,middleware.rs}`
  and `web/src/components/consent-modal.tsx`.
- **AC-12 (Session Termination):** 30-minute inactivity lock; the timer is
  refreshed only on genuine API activity, not passive session probes —
  `services/npe-portal/src/server/session.rs`.
- **SC-23 (Session Authenticity):** sessions are bound to the SHA-256 fingerprint
  of the authenticating certificate and re-verified on every API and authenticated
  session endpoint (`/auth/userinfo`, `/auth/consent`), so a copied cookie cannot
  read session metadata or acknowledge consent without the same client certificate.
- **SC-8 (Transmission Confidentiality):** TLS 1.3 / mTLS via `ostrich_common::tls`.
- **AU-2 / AU-3 / AU-12 (Audit):** login success/failure, USG consent, and logout
  emit structured `EventType::Authentication` records with actor/outcome/IP/
  session — `services/npe-portal/src/server/audit.rs`. POAM: records are emitted
  to the audit pipeline via the `ostrich_audit` tracing target; attach a
  `DatabaseAuditSink` (AU-9(3)/AU-10 hash chain + signing) once the portal is
  provisioned with the audit store.

### Identity bridge (portal → CA/EST)

The portal proxies an allow-listed set of CA/EST routes; the backends consume the
forwarded identity so they enforce RBAC as the actual NPE operator.

- **IA-2 / AC-17 / SC-8 (mTLS-gated trust):** the portal dials the backends over
  mTLS, presenting its service client certificate
  (`services/npe-portal/src/server/backend_client.rs`). The CA/EST trust the
  forwarded `X-Npe-*` identity ONLY when the verified TLS peer-certificate subject
  is in a configured allow-list —
  `crates/ostrich-common/src/auth/middleware.rs` (`TrustedProxyAuthLayer`,
  `TrustedProxyConfig`). A composite layer accepts the portal identity OR a bearer
  token, so the admin console keeps working on the same listener.
- **AC-3 / AC-6 (Access Enforcement / Least Privilege):** the proxied request is
  authenticated as a synthetic `AuthenticatedUser` whose roles come from the
  forwarded role names and whose id is a stable UUIDv5 of the subject DN
  (`AuthenticatedUser::from_trusted_proxy`), so own-scope checks (e.g. "my
  applications") resolve consistently across requests. The portal strips any
  inbound `X-Npe-*` headers so the identity cannot be spoofed.
- **CM-6 (Fail Secure):** `ca-server` refuses to start when
  `CA_TRUSTED_PROXY_SUBJECTS` is set without a client CA; `est-server` refuses to
  start when `EST_TRUSTED_PROXY_SUBJECTS` is set without a portal/enrollment
  client CA. The trusted-proxy path is disabled entirely when the allow-list is
  empty.
- **EST token management:** `est-server` wires the bridge on the
  token-management endpoints in bearer-enrollment mode via
  `EST_TRUSTED_PROXY_SUBJECTS` + `EST_PORTAL_CLIENT_CA` (a portal client CA kept
  separate from the EST enrollment client CA so enabling the bridge does not flip
  enrollment to mTLS mode). The portal's "Generate Single/Multi-Use Token" pages
  thus authenticate as the requesting NPE operator.

---

## Document Change History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-03 | OstrichPKI Team | Initial NIST 800-53 mapping based on v0.10.0 codebase |
| 1.5 | 2026-01-04 | OstrichPKI Team | HSM enforcement and 98% NIAP compliance |
| 1.6 | 2026-01-07 | OstrichPKI Team | Web UI: AC-2 partial (OIDC), AC-12 implemented (sessions), SC-23 implemented (CSP nonces, PKCE) |
| 1.7 | 2026-06-23 | OstrichPKI Team | TAMP (RFC 5934) manager: SC-12/SC-13/SC-23/SI-10/SI-12/AU-2/AU-3/AU-12/IA-7/AC-3 evidence (`ostrich-tamp`) |
| 1.8 | 2026-06-26 | OstrichPKI Team | NPE Portal (`ostrich-npe-portal`): IA-2/IA-5(2) mTLS OID→role auth, CM-6 fail-closed mTLS, AC-3/AC-6 four NPE roles + identity-forwarding allowlisted proxy, AC-8 USG consent, AC-12 30-min inactivity, SC-23 cert-bound sessions, AU-2/AU-3/AU-12 auth audit |
| 1.9 | 2026-06-26 | OstrichPKI Team | CM-6 secure config: serverAuth (TLS server) certificate profiles capped at 397 days in `ostrich-x509` secure-defaults validation (Apple/iOS / CA-Browser Forum); NPE portal surfaces the advisory 397-day warning. |
| 2.0 | 2026-07-27 | OstrichPKI Team | CM-2/CM-6/IA-5/IA-7/SC-12/SC-17/SA-11: explicit SoftHSM-backed EST external-issuer integration profile and fail-closed CA bootstrap. See `EST_ISSUER_INTEGRATION.md`. |
| 2.1 | 2026-10-23 | OstrichPKI Team | CM-3/SA-11: added multi-agent development workflow (`.claude/skills/ostrich-workflow`, `.claude/agents/`) with independent security, NIST 800-53/NIAP, PQC/FIPS, and RFC review roles and a recorded quality gate. CM-3 status unchanged (Partial). |
| 2.2 | 2026-10-23 | OstrichPKI Team | Dependency advisory remediation (cargo audit 18 vulnerabilities + 4 warnings → 0/0). New RA-5 and SI-2 sections (both Partial: the scan is advisory and response times are proposed, pending AO approval). Summary table: RA row added, SI and TOTAL rows recalculated. AWS-LC FIPS 4.2.0 (`aws-lc-fips-sys` 0.14.2) recorded in CM-2/SC-8/SC-13/TAMP, with the CMVP certificate for 4.2.0 pending confirmation (POA&M). CM-3 crypto-module review rule and CM-4 approval note. CM-6 `.cargo/config.toml` module pin. ML-DSA verification in TLS accepted (issuance still disabled). AC-17 stale TLS 1.3 gap removed. Cross-references: FTP_ITC.1 → SC-8, AC-17; FIA_X509_EXT.1 → IA-5(2), SC-17, SI-10. No status changes to existing controls. |
| 2.3 | 2026-10-23 | OstrichPKI Team | CI hardening (branch `claude/ci-hardening`, not yet merged). CM-2: toolchain pinned by `rust-toolchain.toml` (1.99.1; MSRV 1.94 unchanged), CI pin inventory added, "not pinned" gap removed; module-pin file recorded as committed (05ea47a). RA-5: dependency-gate description (`cargo audit --deny warnings` + `cargo deny check`, fails on new advisories), scan frequency, 4 ignores with `# POAM:` IDs; obsolete deny/ignore-mismatch gaps removed; required-check and CODEOWNERS caveats added. SI-2: gate fails in CI, merge-blocking pending required checks. SC-13: PKCS#11 CI job exists, local 16/3/1, Linux pending; HSM evidence items ✅ → 🟡. IA-7: test line reference corrected to `:80-106`. **No control status changes; RA-5, SI-2, CM-2 stay Partial; SI-7 unchanged.** Summary table not recalculated. |
| 2.4 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS fix (branch `claude/ci-hardening`, uncommitted; run record `target/agent-workflow/20261023-230002-pkcs11-rsa-pss/`). SC-13: RSA-PSS ✅ → 🟡 with the impact corrected (X.509/CRL/OCSP RSA signing is PKCS#1 v1.5 and was not affected; the broken path was AU-10 audit-record signing with RSA PKCS#11 CA keys); PKCS#11 status "Fixed; local SoftHSM 2.7.0 28/0/1; Linux CI pending"; Linux CI before-fix result 16/3/1 (exit 101) recorded; stale `mod.rs` line references replaced by function names; new tests listed; split-boundary, algorithm-key binding and vendor-HSM gaps added; untraceable "39 tests" count removed. AU-10: RSA PKCS#11 audit-signing note and gap (NIST-005). RA-5 / SI-2: 5 ignored advisories (RUSTSEC-2026-0387 `crypto-bigint` 0.5.5 added, POAM-16; openidconnect recorded as declared but unused in web-ui). SI-10: RSASSA-PSS CSR parameter caveat (POAM-20). New "PKCS#11 RSA-PSS digest input" section. **No control status or percentage changed** (SC-13 stays 98%, AU-10 Compliant, RA-5 / SI-2 Partial). |
| 2.5 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS fix, Linux CI evidence (commit 44d560d, PR 181). Recorded GitHub Actions run 40063317654 (`HSM integration` / `PKCS#11 suite (SoftHSM2)`; SoftHSM 2.6.1, rustc 1.99.1; 28 passed / 0 failed / 1 ignored, exit 0; artifact `commit:` = PR merge ref c67c10e). SC-13: RSA-PSS via PKCS#11 🟡 → ✅ **scoped to SoftHSM** 2.6.1 / 2.7.0 and RSA-2048/3072/4096; production HSM not validated (POAM-21); AWS-LC 4.2.0 CMVP caveat kept. SC-13 suite, signature-test and HSM-test evidence items 🟡 → ✅ (SoftHSM only). AU-10 RSA bullet stays 🟡 (no RSA end-to-end test). SI-2 cryptoki row and gap updated. POAM-07 and POAM-17 recorded as closed; `CKA_ALLOWED_MECHANISMS` caveat kept. **No control status or percentage changed** (SC-13 stays 🟢 98%, AU-10 Compliant, SI-2 Partial). |
| 2.6 | 2026-10-24 | OstrichPKI Team | PR 152 (fail-closed FIPS TLS, branch `revive-fips-tls`, uncommitted round-1 fixes; run record `target/agent-workflow/20261024-000214-pr152-fips-tls/`). SC-8: fail-closed FIPS gate (`ensure_fips`) added as evidence; "all seven service binaries ... via `serve`" corrected to nine binaries via `from_options` + `serve` plus npe-portal ACME mode via `serve_with_config` (now gated). SC-13: "services do not assert FIPS mode at startup" rescoped to a 🟡 HTTPS-listener-only assertion; `fips()` reflects build and linkage, not a failed self-test (PQC-009); gRPC ordering gap in ca-server recorded. New SC-24 section (🟡 Partial, HTTPS listeners only). Cross-reference FPT_FLS.1 → SC-24, SI-13, SI-17 (SI-17 already mapped FPT_FLS.1 in its own section). Summary table: SC row 7/2/4/1 43% → 8/2/5/1 56% and TOTAL 37 → 38 controls, 43% → 43% (arithmetic under the table). **No existing control status raised** (SC-8 Implemented, SC-13 🟢 98% unchanged). Header version 2.2 → 2.6 (2.3-2.5 had not updated it). |
| 2.7 | 2026-10-24 | OstrichPKI Team | Dependency cleanup (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`). RA-5: ignore count 5 → 3 (RUSTSEC-2026-0097 and RUSTSEC-2026-0387 removed); 2026-10-24 local gate evidence added; remediation items for POAM-11/-16/-22 marked done, POAM-23 (unused `oauth2`) added. SI-2: new 2026-10-24 evidence table (RUSTSEC-2026-0097 `rand` 0.8.5 → 0.8.6 and RUSTSEC-2026-0387 `crypto-bigint` 0.5.5 removed, both remediated); the two corresponding gaps replaced by a CI-pending note and the `oauth2` item. CM-7: new section, 🟡 Partial (openidconnect and p256 removal as evidence, 28 crates; gap POAM-23 `oauth2`; SR-3 noted). SC-13: added a pre-existing gap (PQC-001, CSPs from `rand` `ThreadRng`; POAM-24). RA-5 and SI-2 stay 🟡 Partial; SC-13 status unchanged. Control Implementation Summary: CM row 3 → 4 controls (50% unchanged), TOTAL 38 → 39 controls, (6 + 0.5 × 22) / 39 = 43.6% → 44% (was 43%) |
| 2.8 | 2026-10-25 | OstrichPKI Team | CA gRPC behind mTLS with the aws-lc-rs FIPS provider (branch `claude/grpc-mtls`, uncommitted; run record `target/agent-workflow/20261024-225627-grpc-mtls/`). New sections AC-4 (🟡 Partial; Helm and kustomize CA NetworkPolicy for the gRPC port; maps to OE.NETWORK, no TOE SFR) and IA-3 (🟡 Partial; CA gRPC client-certificate authentication, trust-anchor separation; revocation and issuer binding are gaps). AC-3 (gRPC subject allowlist, default deny), AC-6 (listener-wide only, POAM-26), AC-17 (gRPC mTLS; FCS_TLSS_EXT.2 / FCS_TLSC_EXT.2 added), AU-2 (new gRPC events), AU-3 (peer subject logged only, POAM-25), AU-8 (unbounded chain-order timestamp shift), AU-9 / AU-9(3) (atomic chain append Implemented, Postgres test not run, POAM-31; lock held across signing; upgrade note), AU-12, CM-6 (CA_GRPC_* baseline, release-build refusals incl. clients; compose `./certs` exposure POAM-32), IA-5 (IA-5(2) on gRPC), SC-8 (gRPC TLS 1.3 mTLS; earlier gRPC ✅ claims corrected; tonic `tls-ring` gap resolved, ring remains elsewhere), SC-13 (process `fips_gate`, gRPC `fips()` assertions, gRPC provider with SECP256R1MLKEM768 first and narrowed signature algorithms; CMVP pending; ring gap narrowed), SC-23 (gRPC claim corrected), SC-24 (start-up gate and gRPC refusals), SI-10 (allowlist parsing, fuzz), SI-12 (gRPC client key zeroize). Cross-reference: FCS_TLSS_EXT.2, FDP_ACC.1, FDP_ACF.1 added; IA-3 added to FCS_TLSC_EXT.2, FIA_X509_EXT.1 and FTP_ITC.1. POA&M IDs 25-33 referenced. **No existing control status raised.** Summary table: AC 7 → 9 controls (14% → 22%), IA 3 → 4 (33% → 38%), TOTAL 39 → 41, 18 / 41 = 43.9% → 44% (arithmetic under the table). Header version 2.6 → 2.8 (2.7 had not updated it) |
| 2.9 | 2026-10-25 | OstrichPKI Team | CA gRPC mTLS final refresh after fix round 3 (same branch and run record). Summary table AC row corrected to 8 / 0 / 3 / 5 = 19% (was shown as 9 / 0 / 4 / 5 = 22%; AC-4 is the only added AC control); TOTAL unchanged at 18 / 41 = 44% (arithmetic under the table). IA-3: trust-anchor guard now walks the CA-database lineage (subject alone, issued-by, issuer, ancestors), refusal audited as `grpc_listener_refused`, per-call `subscriber_issuing_ca`; residual siblings / grandchildren / external roots (POAM-28). AU-2: `grpc_listener_refused`, `subscriber_issuing_ca`, summary fields, cancelled-request and shutdown residuals; pre-database startup refusals still log-only. AU-5: `alert="audit_write_failed"` and commit `outcome=unknown` recorded as supporting only (status stays 🔴, no alert routing). AU-8: `details.occurred_at` / `caller_occurred_at`. AU-9 / AU-9(3): checked `append`, lock / statement / idle-in-transaction timeouts, sign on the blocking pool, SLH-DSA audit key refused; Postgres tests (incl. new `sign_timeout_db.rs`) NOT RUN, `OSTRICH_DB_TESTS` opt-in now fails when the DB is unreachable; hung-HSM thread / shutdown residual (SEC-017). AU-10, SC-13: SLH-DSA CA keys unsupported (POAM-2026-10-23-34, new). SC-8 / SC-23: REST plain-HTTP qualifier (NIST-023). SC-24: trust-anchor and SLH-DSA refusals. CM-6 client-CA row. Test counts: `grpc_mtls_e2e` 21/21, 41 `grpc_tls::tests`. **No control status changed** |
| 3.0 | 2026-10-26 | OstrichPKI Team | Per-method CA gRPC authorization and verified audit actor (branch `claude/grpc-per-method-authz`, uncommitted; run record `target/agent-workflow/20261025-202226-grpc-per-method/`). AC-3: three role lists, default-deny method table, admin-issuer, requestor and profile checks. AC-5: disjoint issuer / admin identities, one admin certificate per named operator. AC-6: per-method least privilege (✅), AC-6(10) profile allowlists and CA-profile refusal (✅), AC-6(9) Revoke / GenerateCrl audited, CheckRevocationStatus unaudited read (🟡); stale POAM-26 gap removed. AU-2: new denial reasons and detail fields, `grpc_listener_started` `clients` / `method_rules` / `issuer_profiles`, `grpc_listener_refused` `grpc_authorization_layer`, revocation and CRL Failure records. AU-3: gRPC actor = verified peer DN with `authenticated_caller*` and `on_behalf_of` (POAM-25 closed pending commit). AU-10: signed records attribute the peer; `audit_signing_e2e` actor assertion NOT RUN. AU-12, CM-6 (role-list, profile and legacy-variable rows), CM-7 (method table, profiles, debug-only plaintext constructor), IA-3 (per-call leaf validity, admin direct-issuance, IA-9 related), SI-10 (requestor validation, const-oid fuzz finding fixed; related SI-11 note). Cross-reference: FMT_SMR.2 → IA-3 added. POA&M IDs 35-38 referenced. Test counts (coder-reported, final tree): `grpc_tls` 66, `grpc_mtls_e2e` 39, `ostrich-ca` 78, ca-server bins 21, `make test-unit` 782. **No control status changed; summary table unchanged (18 / 41 = 44%)** |
| 3.1 | 2026-10-26 | OstrichPKI Team | Dependabot alert remediation (branch `claude/dependabot-remediation`, uncommitted; run record `target/agent-workflow/20261026-dependabot-remediation/`). RA-5: "fails on any new advisory" qualified as RustSec-only (GitHub-only advisories reach us only through Dependabot); npm gate described with its limits (`--prod --audit-level=high`); Dependabot ecosystems listed (npe-portal not covered); 2026-10-26 evidence (21 open alerts; full `pnpm audit` 28 → 2 moderate); new gaps for GHSA-only coverage, npm dev/medium not gated, npe-portal unscanned and untriaged alerts (POAM-39, -40, -42). SI-2: `pnpm audit` named in Implementation; new 2026-10-26 evidence table (19 GHSAs, scope, first-patched version, days open against proposed windows); residual react-router → POAM-39; timeliness gap. Local gates only. **No control status or percentage changed** (RA-5 and SI-2 stay 🟡 Partial; summary table not recalculated) |
| 3.2 | 2026-10-26 | OstrichPKI Team | react-router v7 migration in web-ui (branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`). SI-2: GHSA-wrjc-x8rr-h8h6 and GHSA-337j-9hxr-rhxg marked remediated (react-router 7.18.4), overdue; residual line closed; new 2026-10-26 evidence record; both stay in the SI-2(c) missed count. RA-5: 2026-10-26 full `pnpm audit` = 0 recorded; POAM-39 migration marked done; triage gap reworded. SI-10: web-ui same-origin navigation guard and encoded path segments added as client-side defence in depth, with the standing rule; BFF proxy decode gap → POAM-43, no web-ui test runner → POAM-44. CA-5: POAM-39 closure recorded in NIAP_GAP_ANALYSIS.md §11 (no CA-5 section exists here; none added). Local evidence only. **No control status or percentage changed** (SI-2 and RA-5 stay 🟡 Partial; SI-10 stays 🟢 Good (85%); summary table not recalculated) |

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 21)

### PKCS#11 ECDSA mechanism portability

**Controls:** SC-12, SC-13
**Status:** Implemented and integration-tested

`crates/ostrich-crypto/src/pkcs11/mod.rs` hashes ECDSA messages with the
FIPS-enabled AWS-LC SHA-2 implementation and sends the digest to the mandatory
PKCS#11 `CKM_ECDSA` mechanism. This avoids relying on optional combined
`CKM_ECDSA_SHA*` token mechanisms while keeping private-key operations inside
the configured HSM boundary.

### PKCS#11 RSA-PSS digest input

**Controls:** SC-13, AU-10
**Status:** ✅ Fixed; verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), 28 passed / 0 failed / 1 ignored, RSA-2048/3072/4096; production HSM not yet validated (POAM-2026-10-23-21)

`crates/ostrich-crypto/src/pkcs11/mod.rs` hashes RSA-PSS messages with the
AWS-LC FIPS SHA-2 implementation and sends the digest to raw
`CKM_RSA_PKCS_PSS` (hashAlg = MGF1 hash = signature hash, sLen = hash length),
the same pattern as ECDSA. Before 2026-10-23 the whole message was sent, and
`C_Sign` failed. The affected production path was AU-10 audit-record signing
with RSA PKCS#11 CA keys. X.509 certificate, CRL and OCSP RSA signing uses
PKCS#1 v1.5 and was not affected (POAM-2026-10-23-17, closed 2026-10-23).

### EST mTLS workload probes

**Controls:** SC-8, SC-23, SI-4

The Helm deployment uses TCP socket probes for an EST listener configured with
a client CA. Kubernetes native HTTP probes cannot present a client certificate;
the chart therefore verifies listener availability without weakening mandatory
mTLS or adding an unauthenticated HTTP exception.

### EST Basic bootstrap TLS negotiation

**Controls:** AC-3, IA-2, SC-8

When HTTP Basic bootstrap is explicitly enabled, the TLS 1.3 listener requests
and validates a client certificate when presented but permits a
certificate-less handshake so HTTP authentication can execute. Requests
without a valid client certificate or valid Basic credential remain denied.
