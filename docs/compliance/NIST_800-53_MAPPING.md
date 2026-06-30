# NIST 800-53 Rev 5 Security Control Mapping

**Document Version:** 1.8
**Date:** 2026-01-07
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

**Gaps:**

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

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Key handles prevent direct key access (least privilege for key operations)

**Evidence:**

- ✅ Cryptographic operations use key handles, not direct key material
- ✅ HSM design enforces least privilege (keys never leave HSM)
- 🔴 No user privilege levels

**Gaps:**

- No user role privilege restrictions
- All operations available to all users

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
- FCS_TLSS_EXT.1 - TLS Server Protocol

**Implementation:**

- REST and gRPC endpoints support TLS for remote access
- mTLS planned for inter-service communication

**Evidence:**

- ✅ TLS support in frameworks (axum, tonic)
- 🔴 TLS not configured in application code

**Gaps:**

- TLS configuration delegated to deployment
- No enforcement of TLS 1.3 minimum
- mTLS not enforced for administrative access

**Remediation:** Phase 16 - Configure TLS 1.3+ in application, enforce mTLS for admin endpoints

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

- None

**Gaps:**

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
- 🔴 No explicit deletion prevention (needs database permissions)
- 🔴 No access control on audit queries

**Gaps:**

- Database permissions not configured in code
- Any database user can query audit_events table

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
- [crates/ostrich-db/src/repository/audit.rs](../../crates/ostrich-db/src/repository/audit.rs) - `verify_chain()` recomputes every event hash and checks continuity; `append()` persists the caller-supplied `previous_hash` verbatim
- Signed verification: `DatabaseAuditSink::verify_signed_chain()` (see AU-10)

**Evidence:**

- ✅ Each audit event includes hash of previous event
- ✅ Chain integrity verifiable end-to-end (`verify_chain()` / `verify_integrity()`)
- ✅ SHA-256 hashing (FIPS 180-4)
- ✅ Live integrity test against Postgres: [crates/ostrich-audit/tests/signed_chain_tamper.rs](../../crates/ostrich-audit/tests/signed_chain_tamper.rs)

**Integrity fixes (chain now verifiable for DB-backed sinks):**

- Timestamp precision: `record()` truncates to microseconds (`trunc_subsecs(6)`) before hashing so the stored hash matches the value recomputed after the Postgres `timestamptz` round-trip (previously nanosecond `Utc::now()` made every DB-backed hash unverifiable).
- Chain linkage: the sink now sets `previous_hash` before computing `event_hash` (previously the hash was computed with `previous_hash=None` while the verifier recomputed with the stored link, so verification failed for every event after the first).

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
- 🔴 No CSR→Certificate linkage (missing request_id)

**Gaps / POA&M:**

- Cannot prove which CSR led to which certificate (Phase 15 - add request_id to certificates table)

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
- 🔴 No deployment baseline configuration documented

**Gaps:**

- No formal configuration baseline documentation
- No configuration item inventory

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

**Evidence:**

- ✅ All code changes tracked in git
- ✅ Database migrations numbered and ordered
- 🔴 No formal change approval process

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
- 🔴 No documented secure baseline settings

**Gaps:**

- Default configuration values not security-hardened
- No configuration validation on startup

**Remediation:** Phase 16 - Document secure configuration baselines

**Evidence Required for ATO:**

- Configuration settings guide
- Security configuration checklist
- Configuration validation test results

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
- 🔴 No password management
- 🔴 Certificate validation not implemented

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
- [crates/ostrich-crypto/tests/pkcs11_integration_test.rs:56-64](../../crates/ostrich-crypto/tests/pkcs11_integration_test.rs#L56-L64) - Authentication testing

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
- FCS_TLSS_EXT.1 - TLS Server Protocol
- FCS_TLSC_EXT.2 - TLS Client Protocol

**Implementation:**

- ✅ **SC-8(1)**: Cryptographic protection via mTLS for gRPC service-to-service communication
- ✅ gRPC client infrastructure with mTLS authentication ([crates/ostrich-common/src/grpc_client.rs](../../crates/ostrich-common/src/grpc_client.rs))
- ✅ Client certificate validation
- ✅ Server certificate validation
- ✅ SNI hostname verification
- REST and gRPC frameworks support TLS 1.2/1.3

**Evidence:**

- ✅ TLS 1.2/1.3 support in libraries
- ✅ mTLS implemented for inter-service communication (Phase 12)
- ✅ GrpcClientConfig with certificate-based authentication

**Code References:**

- `crates/ostrich-common/src/grpc_client.rs:41-89` - GrpcClientConfig with TLS
- `crates/ostrich-common/src/tls.rs` - Shared TLS 1.3 server module: rustls
  (ring provider), optional mTLS client verification, fail-fast on partial
  configuration, plain-HTTP fallback with prominent startup warning
- `crates/ostrich-acme/src/ca_integration.rs:32-41` - CA client with mTLS
- `crates/ostrich-est/src/ca_integration.rs:30-39` - EST client with mTLS
- All seven service binaries (`services/*/src/main.rs`) accept
  `TLS_CERT_FILE`/`TLS_KEY_FILE`/`TLS_CLIENT_CA_FILE` and serve HTTPS via
  `ostrich_common::tls::serve`

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

**Web console transport-integrity hardening (SC-8 / SC-18 / SI-10):**

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

- gRPC (tonic) listener TLS configuration on ca-server (REST is covered;
  gRPC mTLS via tonic TLS config or service mesh)
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

- ✅ **All classical algorithms run inside the AWS-LC FIPS 140-3 module** via
  `aws-lc-rs` (workspace `fips` feature): RSA (PKCS#1/PSS), ECDSA P-256/P-384,
  Ed25519, SHA-2, and the SP 800-90A DRBG. The non-FIPS `ring` and pure-Rust
  `rsa` backends were removed from `ostrich-crypto`
  ([crates/ostrich-crypto/src/software/mod.rs](../../crates/ostrich-crypto/src/software/mod.rs),
  [verify.rs](../../crates/ostrich-crypto/src/verify.rs)). Verified by live
  OpenSSL interop for RSA-2048/3072 and ECDSA P-256/P-384
  ([tests/integration/fips_signature_openssl_interop.rs](../../tests/integration/fips_signature_openssl_interop.rs)).
- ✅ ML-KEM-512/768/1024 (FIPS 203) key encapsulation, FIPS-validated via aws-lc-rs.
- ⛔ ML-DSA (FIPS 204) **removed**: its aws-lc-rs `unstable` API is mutually
  exclusive with `fips`, and AWS-LC's FIPS module does not yet include ML-DSA.
  SLH-DSA (FIPS 205) remains unimplemented.
- ✅ **NIST SP 800-90A Rev 1 CTR_DRBG (AES-256) fully implemented**
- ✅ **FIPS 140-3 health tests (repetition count, adaptive proportion)**
- ✅ **Certificate serial number generation with ≥20 bits random (RFC 5280)**
- ✅ PKCS#11 HSM integration complete with FIPS 140-3 module support
- ✅ RSA-PSS with SHA-256/384/512 (preferred for new signatures)
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
- ✅ Comprehensive integration test suite (18 + 21 tests = 39 tests covering all algorithms and DRBG)

**Cryptographic Operations Implemented:**

1. **Digital Signatures (FIPS 186-5)**:
   - RSA-PSS 2048/3072/4096 with SHA-256/384/512
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

- `NIST 800-53: SC-13 - Cryptographic protection using FIPS 140-3 module` (mod.rs:562)
- `FIPS 186-5: Digital signature generation in FIPS 140-3 module` (mod.rs:662)
- `NIST 800-53: SC-13 - Use FIPS-approved key wrapping` (mod.rs:168)

**Testing:**

- `test_rsa_pss_signing_and_verification()` - RSA-PSS with tamper detection
- `test_rsa_pkcs1_signing_and_verification()` - RSA PKCS#1 v1.5
- `test_ecdsa_p256_signing_and_verification()` - ECDSA P-256 with tamper detection
- `test_ecdsa_p384_signing_and_verification()` - ECDSA P-384
- `test_ecdsa_p521_signing_and_verification()` - ECDSA P-521
- `test_deterministic_signatures_rsa_pss()` - Validates RSA-PSS randomness
- `test_signature_with_wrong_algorithm_fails()` - Algorithm mismatch detection
- `test_public_key_export_rsa()`, `test_public_key_export_ec()` - Public key export

**Gaps:**

- Post-quantum cryptography implementation pending (waiting for HSM vendor support)
- EdDSA (Ed25519/Ed448) not universally supported in PKCS#11 HSMs

**Remediation:** Phase 12+ - Add post-quantum cryptography when HSM vendors provide support

**Evidence Required for ATO:**

- ✅ Cryptographic module inventory (SoftHSM for testing, production HSM TBD)
- ⚠️  FIPS 140-2/140-3 validation certificates (production HSM vendor to provide)
- ✅ Algorithm usage matrix (documented in algorithm.rs and Phase 10 summary)
- ✅ DER encoding test results (completed in Phase 8)
- ✅ Signature generation/verification tests (18 integration tests in Phase 10)
- ✅ HSM integration test results (SoftHSM validation complete)

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
- ✅ TLS session binding for all communication

**Code References:**

- [services/web-ui/src/server/middleware/csp.rs:35](../../services/web-ui/src/server/middleware/csp.rs#L35) - Cryptographic nonce generation (128-bit)
- [services/web-ui/src/server/auth/oidc.rs:319](../../services/web-ui/src/server/auth/oidc.rs#L319) - PKCE challenge (SHA-256)
- [services/web-ui/src/server/auth/handlers.rs:73](../../services/web-ui/src/server/auth/handlers.rs#L73) - CSRF state cookie

**Remediation:** None required - session authenticity fully implemented

---

## System and Information Integrity (SI)

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
  - Fail-safe: the fallback only runs after the strict parse fails, so it cannot
    change results for CSRs that parse today; PoP signature verification is still
    enforced over the byte-exact CertificationRequestInfo, and the subject DN is
    rendered/decoded via x509-parser (identical to the primary path, so EST
    re-enrollment identity binding is unaffected).
  - Test coverage: `test_parse_csr_ia5_challenge_password_fallback`,
    `test_parse_csr_printable_challenge_password_fallback`
    (`tests/integration/csr_parsing_test.rs`).
- ✅ **CSR signature verification** (RFC 2986 §4.2, FCO_NRO_EXT.2)
  - Centralized implementation in ostrich-x509/src/parser.rs:326-355
  - Verifies proof-of-possession before certificate issuance
  - Supports RSA (PKCS#1, PSS), ECDSA (P-256, P-384, P-521), EdDSA (Ed25519)
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
| AC (Access Control) | 7 | 0 | 2 | 5 | 14% |
| AU (Audit) | 10 | 4 | 4 | 2 | 60% |
| CM (Configuration) | 3 | 0 | 3 | 0 | 50% |
| CP (Contingency) | 2 | 0 | 1 | 1 | 25% |
| IA (Identification/Auth) | 3 | 0 | 2 | 1 | 33% |
| SC (System Protection) | 7 | 2 | 4 | 1 | 43% |
| SI (System Integrity) | 3 | 0 | 2 | 1 | 33% |
| **TOTAL** | **35** | **6** | **18** | **11** | **40%** |

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
| FCS_TLSC_EXT.2 | SC-8 |
| FCS_TLSS_EXT.1 | SC-8, AC-17 |
| FCO_NRO_EXT.2 | AU-10, SI-10 |
| FDP_CER_EXT.1 | SC-17 |
| FDP_CER_EXT.2 | AU-10 |
| FDP_CER_EXT.3 | AC-3 |
| FDP_RIP.1 | SC-4 |
| FIA_AFL.1 | AC-7 |
| FIA_PMG_EXT.1 | IA-5 |
| FIA_UAU_EXT.1 | IA-2, IA-5 |
| FIA_UIA_EXT.1 | IA-2 |
| FIA_X509_EXT.1 | IA-5, SI-10 |
| FIA_X509_EXT.2 | IA-2, IA-5 |
| FMT_MOF.1 | AC-3, AC-6 |
| FMT_MTD.1 | AC-3 |
| FMT_SMR.2 | AC-2, AC-5 |
| FPT_FLS.1 | SI-13 (Predictable Failure Prevention) |
| FPT_KST_EXT.1 | SC-12 |
| FPT_KST_EXT.2 | SC-12 |
| FPT_STM.1 | AU-8 |
| FPT_TST_EXT.1 | SI-7 |
| FPT_TST_EXT.2 | SI-7 |
| FTA_SSL.3 | AC-12 |
| FTA_SSL.4 | AC-12 |
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
  using FIPS-validated signing/verification (AWS-LC via `ostrich-crypto`).
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
- **AC-3 / AC-6 (Access Enforcement / Least Privilege):** four OID-derived roles
  (PkiSponsor, PkiSponsorAdmin, RegistrationAuthority, CaaAdmin) with a
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

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 21)
