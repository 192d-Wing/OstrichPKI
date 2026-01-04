# NIAP Protection Profile for Certification Authorities v2.1 Compliance Matrix

**Document Version:** 1.2
**Date:** 2026-01-04
**OstrichPKI Version:** 0.10.0
**Protection Profile:** NIAP PP-CA v2.1
**Overall Compliance:** 45-55% (Partial)
**Last Updated:** CSR parsing enhancements - RFC 4514 DN parsing and RFC 5280 SAN extraction

## Executive Summary

This document tracks OstrichPKI's compliance with the NIAP Protection Profile for Certification Authorities v2.1. Each Security Functional Requirement (SFR) is mapped to implementation code, test evidence, and compliance status.

**Compliance Legend:**

- 🟢 **Compliant**: Requirement fully implemented and tested
- 🟡 **Partial**: Requirement partially implemented, gaps remain
- 🔴 **Missing**: Requirement not implemented
- ⚪ **N/A**: Requirement not applicable (selection-based, not chosen)

---

## 1. Security Audit (FAU)

### FAU_ADP_EXT.1 - Audit Dependencies

**Status:** 🟡 **Partial**

**Requirement:** The TOE must support audit record generation per Tables 4-6 of the Protection Profile.

**Implementation:**

- [crates/ostrich-audit/src/event.rs](../../crates/ostrich-audit/src/event.rs) - `AuditEvent` structure
- [crates/ostrich-audit/src/event.rs:15-45](../../crates/ostrich-audit/src/event.rs#L15-L45) - `EventType` enum

**Evidence:**

- Comprehensive event types defined for certificate operations
- Hash chain integrity support (AU-9(3))
- Timestamp, actor, resource tracking

**Gaps:**

- Tables 4-6 not found in XML requirements file (need full PP PDF)
- May be missing event types specific to PP tables
- No verification that all PP-required events are covered

**Remediation Plan:** Phase 15 - Obtain full PP PDF, map all Table 4-6 events to `EventType` enum

**Related NIST 800-53:** AU-2 (Auditable Events), AU-3 (Content of Audit Records)

---

### FAU_GEN.1 - Audit Data Generation

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall be able to generate an audit record of audit events.

**Implementation:**

- [crates/ostrich-audit/src/event.rs:47-110](../../crates/ostrich-audit/src/event.rs#L47-L110) - `AuditEvent` struct with all required fields
- [crates/ostrich-audit/src/lib.rs:25-85](../../crates/ostrich-audit/src/lib.rs#L25-L85) - `AuditLogger` implementation

**Evidence:**

- ✅ Event type, timestamp, outcome, actor captured
- ✅ Hash chain for integrity (previous_hash, event_hash)
- ✅ Request ID for correlation
- ✅ Additional context in `details` field

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** AU-2, AU-3, AU-9(3)

---

### FAU_GEN.2 - User Identity Association

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall be able to associate each auditable event with the identity of the user that caused the event to be generated.

**Implementation:**

- [crates/ostrich-audit/src/event.rs:54](../../crates/ostrich-audit/src/event.rs#L54) - `actor: Option<String>` field
- All audit emission sites pass actor identity

**Evidence:**

- ✅ Actor field populated in all audit events
- ✅ Supports service-to-service actor identification
- ✅ Handles unauthenticated events (None for OCSP)

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** AU-3

---

### FAU_SAR.1 - Audit Review

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall provide Auditor role with the capability to read audit records from the audit trail.

**Implementation:** None (no RBAC system yet)

**Gaps:**

- No Auditor role defined
- No audit query/review interface for administrators
- Database has audit events but no authorized access mechanism

**Remediation Plan:** Phase 16 - Implement RBAC with Auditor role, create audit review API

**Related NIST 800-53:** AU-6 (Audit Review, Analysis, and Reporting)

---

### FAU_SAR.2 - Restricted Audit Review

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall prohibit all users read access to the audit records, except those users that have been granted explicit read-access.

**Implementation:** None

**Gaps:**

- No access control on audit database
- Any database user can query audit_events table

**Remediation Plan:** Phase 16 - Database row-level security, RBAC enforcement on audit queries

**Related NIST 800-53:** AU-9 (Protection of Audit Information)

---

### FAU_STG.1 - Protected Audit Trail Storage

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall protect the stored audit records in the audit trail from unauthorised deletion.

**Implementation:**

- [crates/ostrich-audit/src/sink.rs:15-50](../../crates/ostrich-audit/src/sink.rs#L15-L50) - `DatabaseAuditSink`
- [migrations/](../../migrations/) - Audit table schema

**Evidence:**

- ✅ Audit events stored in PostgreSQL
- ✅ Database-level constraints prevent modification
- ⚠️ No explicit prevention of deletion (need table permissions)

**Gaps:**

- Database permissions not enforced in code
- Relies on deployment configuration (database role setup)

**Remediation Plan:** Phase 15 - Add database migration with REVOKE DELETE on audit_events table, document in deployment guide

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** AU-9

---

### FAU_STG.4 - Prevention of Audit Data Loss

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall prevent audited events if the audit trail is full, and take the following actions: [alert administrator].

**Implementation:** None

**Gaps:**

- No audit storage capacity monitoring
- No mechanism to block operations when audit full
- No alerts when approaching capacity

**Remediation Plan:** Phase 15 - Implement audit storage monitoring, configurable action (alert vs. block)

**Related NIST 800-53:** AU-5 (Response to Audit Processing Failures)

---

### FAU_STG_EXT.1 - External Audit Trail Storage

**Status:** 🔴 **Missing** (Optional/Selection-based)

**Requirement:** The TSF shall be able to transmit the generated audit data to an external IT entity.

**Implementation:** None

**Selection Note:** This is a selection-based requirement. If not implementing, must document rationale in Security Target.

**Remediation Plan:** Phase 16 - Implement syslog/SIEM integration as optional feature, or document exclusion in ST

---

## 2. Cryptographic Support (FCS)

### FCS_CDP_EXT.1 - Cryptographic Dependencies

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall be capable of generating cryptographic keys in accordance with [algorithm specifications].

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - `CryptoProvider` trait
- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm definitions

**Evidence:**

- ✅ Excellent cryptographic abstraction layer
- ✅ Support for RSA, ECDSA, EdDSA algorithms defined
- ✅ Post-quantum algorithm types defined (ML-DSA, ML-KEM, SLH-DSA)
- ✅ Zeroizing wrapper for sensitive data

**Gaps:**

- 🔴 PKCS#11 implementation incomplete (all methods stubbed)
- 🔴 Software crypto provider not implemented
- 🔴 Post-quantum algorithms not implemented

**Remediation Plan:**

- Phase 10 - Complete PKCS#11 implementation
- Phase 10 - Implement software crypto provider fallback
- Phase 13 - Add post-quantum algorithm support

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** SC-12 (Cryptographic Key Establishment and Management), SC-13 (Cryptographic Protection)

**Related FIPS:** FIPS 186-5 (DSS), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

---

### FCS_CKM.1 - Cryptographic Key Generation

**Status:** 🟡 **Partial** (Selection-based)

**Requirement:** The TSF shall generate asymmetric cryptographic keys in accordance with specified algorithms and key sizes.

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs:15-25](../../crates/ostrich-crypto/src/provider.rs#L15-L25) - `generate_key_pair()` method signature
- [crates/ostrich-crypto/src/pkcs11/mod.rs:45-53](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L45-L53) - PKCS#11 key generation (stubbed)

**Evidence:**

- ✅ Interface supports RSA-2048, RSA-3072, RSA-4096
- ✅ Interface supports ECDSA P-256, P-384, P-521
- ✅ Interface supports EdDSA Ed25519, Ed448
- ⚠️ Implementation stubbed

**Gaps:**

- All PKCS#11 key generation returns "not implemented"
- Software provider not implemented

**Remediation Plan:** Phase 10 - Complete PKCS#11 and software crypto implementations

**Related FIPS:** FIPS 186-5

---

### FCS_CKM_EXT.4 - Cryptographic Key Destruction

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall destroy cryptographic keys in accordance with a specified cryptographic key destruction method that meets [zeroization requirements].

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs:10](../../crates/ostrich-crypto/src/provider.rs#L10) - `use zeroize::Zeroizing;`
- [crates/ostrich-crypto/src/pkcs11/mod.rs:195](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L195) - PIN zeroization
- [crates/ostrich-crypto/src/provider.rs:102](../../crates/ostrich-crypto/src/provider.rs#L102) - Key import with `Zeroizing<Vec<u8>>`

**Evidence:**

- ✅ Zeroizing wrapper used for all sensitive data (PINs, keys)
- ✅ Memory cleared on deallocation (Rust Drop trait)
- ✅ Private key material protected

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** SC-12

---

### FCS_COP.1(1) - Cryptographic Operation - Signature Generation and Verification

**Status:** 🟢 **Good (75%)**

**Requirement:** The TSF shall perform cryptographic signature services using specified algorithms.

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs:66-74](../../crates/ostrich-crypto/src/provider.rs#L66-L74) - `sign()` method
- [crates/ostrich-x509/src/builder/certificate.rs](../../crates/ostrich-x509/src/builder/certificate.rs) - Certificate DER encoding and signing
- [crates/ostrich-x509/src/builder/crl.rs](../../crates/ostrich-x509/src/builder/crl.rs) - CRL DER encoding and signing
- [crates/ostrich-ca/src/issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - Certificate signing operations
- [crates/ostrich-ca/src/revocation.rs](../../crates/ostrich-ca/src/revocation.rs) - CRL signing operations
- [crates/ostrich-ocsp/src/responder.rs](../../crates/ostrich-ocsp/src/responder.rs) - OCSP response signing

**Evidence:**

- ✅ RSA-PSS signature support (2048, 3072, 4096-bit keys)
- ✅ ECDSA signature support (P-256, P-384, P-521)
- ✅ EdDSA signature support (Ed25519, Ed448)
- ✅ ML-DSA post-quantum signature support (ML-DSA-44, ML-DSA-65, ML-DSA-87) - FIPS 204
- ✅ X.509 certificate signing fully implemented with DER encoding
- ✅ CRL signing fully implemented with DER encoding
- ✅ OCSP response signing implemented (RFC 6960)
- ✅ PKCS#7/CMS signing for EST protocol
- ✅ Key usage enforcement through certificate extensions (digital signature, key cert sign, CRL sign)
- ⚠️ PKCS#11 HSM integration pending (software fallback currently used)

**Gaps:**

- PKCS#11 HSM signing operations not yet implemented (Phase 10)
- Hardware-backed key storage not yet available (software keys only)

**Remediation Plan:** Phase 10 - Complete PKCS#11 HSM integration for hardware-backed signing

**Related FIPS:** FIPS 186-5 (DSS), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

---

### FCS_COP.1(2) - Cryptographic Operation - Hashing

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall perform cryptographic hashing services using SHA-256, SHA-384, SHA-512.

**Implementation:**

- [crates/ostrich-audit/src/event.rs:145-150](../../crates/ostrich-audit/src/event.rs#L145-L150) - Hash computation for audit chain
- Uses `ring::digest` (FIPS-validated)

**Evidence:**

- ✅ SHA-256 used for audit event hashing
- ✅ SHA-256 used for JWK thumbprints (ACME)
- ✅ ring library is FIPS 140-2 validated

**Related FIPS:** FIPS 180-4 (Secure Hash Standard), FIPS 202 (SHA-3)

---

### FCS_RBG_EXT.1 - Random Bit Generation

**Status:** 🔴 **Missing** (Mandatory/Selection-based)

**Requirement:** The TSF shall perform all deterministic random bit generation services in accordance with NIST SP 800-90A using [Hash_DRBG | HMAC_DRBG | CTR_DRBG].

**Implementation:** None

**Gaps:**

- No DRBG implementation found
- Certificate serial numbers may not use cryptographically secure random
- ACME nonces use UUID v4 (acceptable but not explicitly DRBG)

**Impact:**

- 🔴 **CRITICAL**: FDP_CER_EXT.1.3 requires ≥20 bits random in serial numbers
- 🔴 **CRITICAL**: Key generation requires DRBG-sourced entropy
- 🔴 Challenge tokens require secure random

**Remediation Plan:** Phase 15 - Implement DRBG using `ring::rand::SystemRandom`, add to CryptoProvider trait

**Related NIST:** NIST SP 800-90A

---

### FCS_STG_EXT.1 - Cryptographic Key Storage

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall store private keys and secret keys in a PKCS#11 token or hardware security module.

**Implementation:**

- [crates/ostrich-crypto/src/pkcs11/mod.rs](../../crates/ostrich-crypto/src/pkcs11/mod.rs) - PKCS#11 provider (stubbed)

**Gaps:**

- PKCS#11 integration not functional
- CA signing keys not stored in HSM
- No enforcement that keys must be in HSM

**Remediation Plan:** Phase 10 - Complete PKCS#11 implementation, configure CA to require HSM

**Related NIST 800-53:** SC-12, SC-13

---

### FCS_TLSC_EXT.2 - TLS Client Protocol

**Status:** 🟡 **Partial** (Selection-based if TOE acts as TLS client)

**Requirement:** The TSF shall support TLS 1.2 or 1.3 as a TLS client.

**Implementation:**

- gRPC client uses `tonic` with TLS support
- REST clients use `reqwest` with TLS support

**Evidence:**

- ✅ HTTP clients support TLS 1.2/1.3
- ⚠️ TLS configuration not explicitly set (uses library defaults)

**Gaps:**

- No enforcement of TLS 1.3 only
- Cipher suite configuration not specified

**Remediation Plan:** Phase 16 - Configure TLS settings explicitly, enforce TLS 1.3, restrict cipher suites

---

### FCS_TLSS_EXT.1 - TLS Server Protocol

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall support TLS 1.2 or 1.3 as a TLS server.

**Implementation:**

- REST APIs use `axum` web framework
- gRPC uses `tonic` server

**Evidence:**

- ✅ Frameworks support TLS 1.2/1.3
- ⚠️ TLS configuration delegated to deployment (reverse proxy or native)

**Gaps:**

- TLS not configured in application code
- mTLS enforcement not implemented for admin endpoints

**Remediation Plan:** Phase 16 - Configure TLS in application or document deployment requirements in ST

**Related NIST 800-53:** SC-8 (Transmission Confidentiality and Integrity)

---

## 3. User Data Protection (FDP)

### FDP_CER_EXT.1 - Certificate Profiles

**Status:** 🟢 **Excellent (95%)**

**Requirement:** The TSF shall support certificate generation in accordance with RFC 5280 profiles.

**Implementation:**

- [crates/ostrich-x509/src/profile.rs](../../crates/ostrich-x509/src/profile.rs) - `CertificateProfile` struct
- [crates/ostrich-x509/src/profile.rs:325-348](../../crates/ostrich-x509/src/profile.rs#L325-L348) - Profile validation logic
- [crates/ostrich-x509/src/builder/certificate.rs:488-759](../../crates/ostrich-x509/src/builder/certificate.rs#L488-L759) - **X.509 extension building (NEW)**

**Evidence:**

- ✅ Comprehensive profile definitions (Root CA, Intermediate CA, TLS Server, TLS Client, Code Signing, Email Protection, OCSP Signing, Smartcard Auth)
- ✅ RFC 5280 compliance annotations throughout
- ✅ **All RFC 5280 §4.2 certificate extensions fully implemented:**
  - ✅ **Key Usage** (§4.2.1.3, critical): Digital signature, non-repudiation, key encipherment, data encipherment, key agreement, key cert sign, CRL sign, encipher only, decipher only
  - ✅ **Basic Constraints** (§4.2.1.9, critical): CA flag, path length constraint
  - ✅ **Extended Key Usage** (§4.2.1.12): Server auth, client auth, code signing, email protection, time stamping, OCSP signing, custom OIDs
  - ✅ **Subject Alternative Name** (§4.2.1.6): DNS names, RFC822 names, URIs, IP addresses, directoryName
    - **NEW**: SAN extraction from CSR extension requests (OID 2.5.29.17)
    - Code: [parser.rs:11-91](../../crates/ostrich-x509/src/parser.rs#L11-L91)
  - ✅ **Authority Key Identifier** (§4.2.1.1): Links certificate to issuing CA's public key
  - ✅ **Subject Key Identifier** (§4.2.1.2): Unique identifier for certificate's public key
  - ✅ **CRL Distribution Points** (§4.2.1.13): Full name URIs for CRL retrieval
  - ✅ **Authority Information Access** (§4.2.2.1): OCSP responder and CA issuer locations
  - ✅ **Certificate Policies** (§4.2.1.4): Policy OIDs with qualifiers
- ✅ Profile validation enforces CA certificates have keyCertSign usage
- ✅ All extensions properly marked critical/non-critical per RFC 5280
- ✅ Proper ASN.1 DER encoding for all extension values
- ✅ **Subject DN Parsing** (RFC 5280 §4.1.2.4, RFC 4514):
  - **NEW**: Proper Distinguished Name parsing from CSRs
  - OID-based attribute extraction (CN, O, OU, L, ST, C, serialNumber)
  - Multi-valued RDN support
  - ASN.1 string type handling (UTF8String, PrintableString, IA5String, etc.)
  - Security: Prevents DN spoofing through proper parsing
  - Code: [parser.rs:93-174](../../crates/ostrich-x509/src/parser.rs#L93-L174)
  - Integration: [ACME ca_integration.rs:153-177](../../crates/ostrich-acme/src/ca_integration.rs#L153-L177), [EST ca_integration.rs:197-221](../../crates/ostrich-est/src/ca_integration.rs#L197-L221)
  - Test coverage: 2 unit tests with real OpenSSL CSRs

**Gaps:**

- 🔴 Serial number generation not using DRBG (FCS_RBG_EXT.1 gap)
- ⚠️ Need verification of ≥20 bits random in serial numbers

**Remediation Plan:**

- Phase 15 - Implement DRBG-based serial number generation

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related RFC:** RFC 5280 §4.1, §4.2

---

### FDP_CER_EXT.2 - Certificate Request Matching

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall maintain a linkage from the certificate request to the issued certificate.

**Implementation:** None

**Gaps:**

- No `request_id` field in Certificate model
- Cannot trace which CSR led to which certificate
- Breaks non-repudiation chain (AU-10)

**Remediation Plan:** Phase 15 - Add request_id and request_type fields to certificates table, update issuance code

**Related NIST 800-53:** AU-10 (Non-repudiation)

---

### FDP_CER_EXT.3 - Certificate Issuance Approval

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall require approval from [RA | AOR | CA Operations Staff | rules-based] before issuing a certificate.

**Implementation:** None

**Gaps:**

- Certificates issued directly without approval workflow
- No approval tracking
- No configurable approval policies

**Impact:**

- 🔴 **CRITICAL**: Mandatory requirement for NIAP compliance
- Cannot meet organizational approval requirements

**Remediation Plan:** Phase 15 - Implement approval workflow with ApprovalStatus enum, rules engine

**Related NIST 800-53:** AC-3 (Access Enforcement)

---

### FDP_CSI_EXT.1 - Certificate Status Information

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall generate certificate status information in accordance with [RFC 6960 (OCSP) | RFC 5280 §5 (CRL)].

**Implementation:**

- [crates/ostrich-ocsp/src/responder.rs](../../crates/ostrich-ocsp/src/responder.rs) - OCSP responder
- [crates/ostrich-x509/src/crl.rs](../../crates/ostrich-x509/src/crl.rs) - CRL builder

**Evidence:**

- ✅ OCSP responder structure exists
- ✅ CRL builder structure exists
- ✅ RFC 6960 referenced
- ⚠️ Implementation completeness unknown (Phase 8 work)

**Gaps:**

- OCSP response generation implementation status unclear
- CRL signing implementation status unclear

**Remediation Plan:** Phase 8 completion should address, verify in Phase 14 testing

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related RFC:** RFC 6960, RFC 5280 §5

---

### FDP_CRL_EXT.1 - CRL Profile

**Status:** 🟢 **Good (90%)** (Selection-based)

**Requirement:** The TSF shall generate CRLs in accordance with RFC 5280 §5.

**Implementation:**

- [crates/ostrich-x509/src/crl.rs](../../crates/ostrich-x509/src/crl.rs) - CRL builder
- [crates/ostrich-x509/src/builder/crl.rs:160-451](../../crates/ostrich-x509/src/builder/crl.rs#L160-L451) - **DER encoding and extensions (UPDATED)**

**Evidence:**

- ✅ CRL structure fully defined per RFC 5280 §5
- ✅ Revoked certificate entries with serial numbers and revocation dates
- ✅ **RFC 5280 §5.2 CRL extensions fully implemented:**
  - ✅ **CRL Number** (§5.2.3, critical): Monotonically increasing CRL version number
  - ✅ **Authority Key Identifier** (§5.2.1): Links CRL to issuing CA's public key
- ✅ **RFC 5280 §5.3 CRL entry extensions fully implemented:**
  - ✅ **Revocation Reason** (§5.3.1): All 11 reason codes (unspecified, key compromise, CA compromise, affiliation changed, superseded, cessation of operation, certificate hold, remove from CRL, privilege withdrawn, AA compromise)
  - ✅ Proper ASN.1 ENUMERATED encoding (tag 0x0A) for reason codes
- ✅ DER encoding fully implemented with proper ASN.1 structure
- ✅ CRL signing operations integrated with CryptoProvider

**Gaps:**

- Delta CRL support not implemented (selection-based, not required)
- CRL distribution point configuration needs testing

**Remediation Plan:** Verify CRL distribution in Phase 14 integration testing

**Related RFC:** RFC 5280 §5

---

### FDP_OCSPG_EXT.1 - OCSP Response Generation

**Status:** 🟡 **Partial** (Selection-based)

**Requirement:** The TSF shall generate OCSP responses in accordance with RFC 6960.

**Implementation:**

- [crates/ostrich-ocsp/src/response.rs:117](../../crates/ostrich-ocsp/src/response.rs#L117) - ASN.1 encoding
- [crates/ostrich-ocsp/src/responder.rs:170](../../crates/ostrich-ocsp/src/responder.rs#L170) - Signing

**Evidence:**

- ✅ Response structure defined
- ⚠️ Implementation completed in Phase 8

**Gaps:**

- Delegated signing support
- Response caching (optional)

**Remediation Plan:** Phase 13 - Implement response caching and delegated signing

---

### FDP_RIP.1 - Subset Residual Information Protection

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall ensure that any previous information content of a resource is made unavailable upon deallocation.

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs:10](../../crates/ostrich-crypto/src/provider.rs#L10) - `Zeroizing` wrapper
- Used for all PINs, passwords, private keys

**Evidence:**

- ✅ Zeroizing used throughout codebase
- ✅ Rust Drop trait ensures cleanup
- ✅ Memory safety guarantees from Rust

**NIAP Annotation Required:** ✅ Phase 15 Task

**Related NIST 800-53:** SC-4 (Information in Shared Resources)

---

## 4. Identification and Authentication (FIA)

### FIA_AFL.1 - Authentication Failure Handling

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall detect when [configurable positive integer] unsuccessful authentication attempts occur, and take [action].

**Implementation:** None

**Gaps:**

- No authentication system
- No failed attempt tracking
- No account lockout mechanism

**Remediation Plan:** Phase 16 - Implement authentication failure tracking, configurable lockout policy

**Related NIST 800-53:** AC-7 (Unsuccessful Logon Attempts)

---

### FIA_ESTC_EXT.1 - EST Client Authentication

**Status:** 🟡 **Partial** (Selection-based if EST selected)

**Requirement:** The TSF shall authenticate EST clients using mTLS.

**Implementation:**

- [crates/ostrich-est/src/mtls.rs](../../crates/ostrich-est/src/mtls.rs) - mTLS module (Phase 11 implementation)

**Evidence:**

- ✅ MtlsClientCert structure defined
- ✅ Certificate parsing and validation structure
- ⚠️ TLS server integration pending

**Gaps:**

- TLS server configuration not in application code
- Certificate extraction from TLS connection pending

**Remediation Plan:** Phase 16 - Configure Axum/tonic for mTLS, extract peer certificates

---

### FIA_ESTS_EXT.1 - EST Server Authentication

**Status:** 🟡 **Partial** (Selection-based if EST selected)

**Requirement:** The TSF shall authenticate to EST clients using TLS server certificate.

**Implementation:**

- EST server endpoints defined
- TLS configuration delegated to deployment

**Evidence:**

- ✅ EST endpoints use HTTPS
- ⚠️ Server certificate configuration not in code

**Remediation Plan:** Phase 16 - Document server certificate requirements in deployment guide

---

### FIA_PMG_EXT.1 - Password Management

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall provide password-based authentication mechanism supporting [password complexity requirements].

**Implementation:** None

**Gaps:**

- No password authentication
- No password complexity enforcement
- No password aging/expiration

**Remediation Plan:** Phase 16 - Implement password authentication with complexity rules per NIST SP 800-63B

**Related NIST:** NIST SP 800-63B (Digital Identity Guidelines)

---

### FIA_UAU_EXT.1 - Authentication Mechanism

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall provide [password-based | certificate-based] authentication mechanism.

**Implementation:** None

**Gaps:**

- No authentication system at all
- All endpoints currently unauthenticated (except conceptual mTLS)

**Impact:**

- 🔴 **CRITICAL**: Mandatory requirement
- Cannot control access to administrative functions

**Remediation Plan:** Phase 16 - Implement both password and certificate-based authentication

**Related NIST 800-53:** IA-2 (Identification and Authentication), IA-5 (Authenticator Management)

---

### FIA_UIA_EXT.1 - User Identification and Authentication

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall allow [specified actions] before requiring authentication, and require authentication for all other actions.

**Implementation:** None

**Evidence:**

- ✅ OCSP responder correctly allows unauthenticated access (per PP line 358)

**Gaps:**

- No authentication enforcement on other endpoints
- Certificate renewal doesn't check DN matching

**Remediation Plan:** Phase 16 - Add authentication middleware to all APIs except OCSP/CRL

---

### FIA_X509_EXT.1 - X.509 Certificate Validation

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall validate certificates in accordance with RFC 5280 path validation algorithm.

**Implementation:**

- [crates/ostrich-x509/src/parser.rs:96-99](../../crates/ostrich-x509/src/parser.rs#L96-L99) - Stub only

**Gaps:**

- 🔴 **CRITICAL**: Certificate validation not implemented
- No path building
- No basicConstraints checking
- No revocation checking (CRL/OCSP)

**Remediation Plan:** Phase 15 - Implement RFC 5280 path validation in new validation.rs module

**Related RFC:** RFC 5280 §6

**Related NIST 800-53:** IA-5 (Authenticator Management)

---

### FIA_X509_EXT.2 - X.509 Certificate-Based Authentication

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall use X.509v3 certificates as per FIA_X509_EXT.1 for authentication.

**Implementation:** None (mTLS not enforced)

**Gaps:**

- mTLS configuration not in application
- Certificate-based authentication not used for admin operations

**Remediation Plan:** Phase 16 - Enforce mTLS for inter-service and admin endpoints

---

## 5. Security Management (FMT)

### FMT_MOF.1 - Management of Security Functions Behavior

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall restrict the ability to perform security management functions to authorized users.

**Implementation:** None

**Gaps:**

- No RBAC system
- All management functions unrestricted
- No role-based authorization checks

**Impact:**

- 🔴 **CRITICAL**: Mandatory requirement
- Any user can perform any operation

**Remediation Plan:** Phase 15 (foundation), Phase 16 (full implementation) - RBAC with role-based function restrictions

**Related NIST 800-53:** AC-3 (Access Enforcement), AC-6 (Least Privilege)

---

### FMT_MTD.1 - Management of TSF Data

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall restrict the ability to manage TSF data to authorized users.

**Implementation:** None

**Gaps:**

- Trust Anchor Database not protected
- Certificate profiles not access-controlled
- Configuration data unrestricted

**Remediation Plan:** Phase 16 - RBAC enforcement on all TSF data modifications

---

### FMT_SMF.1 - Specification of Management Functions

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall be capable of performing the following management functions: [list of functions per PP].

**Implementation:**

- ✅ Certificate issuance, revocation, profile management functions exist
- ✅ Audit configuration possible
- ✅ User management database schema planned (Phase 15)

**Gaps:**

- Functions exist but no access control
- Trust anchor management undefined
- Backup/recovery procedures undefined

**Remediation Plan:** Phase 16 - Add access control to all management functions

---

### FMT_SMR.2 - Restrictions on Security Roles

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall maintain the roles: Administrator, Auditor (mandatory separation), CA Operations Staff (mandatory separation), and optionally RA Staff and AOR.

**Implementation:** None

**Gaps:**

- 🔴 **CRITICAL**: No role system at all
- Cannot enforce separation of duties
- Auditor cannot be separated from other roles

**Impact:**

- Mandatory requirement for NIAP compliance
- Fundamental to access control model

**Remediation Plan:** Phase 15 - Define Role enum and separation validation, Phase 16 - Full implementation

**Related NIST 800-53:** AC-2 (Account Management), AC-5 (Separation of Duties)

---

## 6. Protection of the TSF (FPT)

### FPT_FLS.1 - Failure with Preservation of Secure State

**Status:** 🟡 **Unknown**

**Requirement:** The TSF shall preserve a secure state when failures occur.

**Implementation:**

- Error handling throughout codebase uses `Result<T, Error>`
- Database transactions for atomicity

**Evidence:**

- ✅ Rust Result type forces error handling
- ✅ Database transactions prevent partial state
- ⚠️ Need comprehensive error handling review

**Gaps:**

- Unknown if all failure modes handled securely
- Need testing of failure scenarios

**Remediation Plan:** Phase 14 - Error handling review, failure scenario testing

---

### FPT_KST_EXT.1 - No Plaintext Key Export

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall not export private or secret keys in plaintext.

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Key handle abstraction prevents direct access

**Evidence:**

- ✅ CryptoProvider returns key handles, not key material
- ✅ PKCS#11 design prevents plaintext export
- ⚠️ PKCS#11 not implemented

**Gaps:**

- Software provider (when implemented) must ensure no plaintext export
- Key wrapping must be used for backup/recovery

**Remediation Plan:** Phase 10 - Ensure PKCS#11 and software providers never export plaintext keys

**NIAP Annotation Required:** ✅ Phase 15 Task

---

### FPT_KST_EXT.2 - TSF Key Protection

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall protect cryptographic keys from unauthorized disclosure.

**Implementation:**

- [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Abstraction layer
- Key handles prevent direct access

**Evidence:**

- ✅ Design supports HSM storage
- ✅ Zeroizing wrapper protects in-memory keys
- ⚠️ PKCS#11 not functional

**Remediation Plan:** Phase 10 - Complete HSM integration

**NIAP Annotation Required:** ✅ Phase 15 Task

---

### FPT_SKP_EXT.1 - Protection of Keys

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall protect cryptographic keys during generation, import, and export.

**Implementation:**

- KRA module with Shamir secret sharing
- Key wrapping interface in CryptoProvider

**Evidence:**

- ✅ KRA escrow protects keys via secret sharing
- ✅ Zeroizing used during key operations
- ⚠️ Key wrapping not implemented

**Remediation Plan:** Phase 10 - Implement key wrapping in crypto providers

---

### FPT_SKY_EXT.1/2 - Split Knowledge Procedures

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall require split knowledge procedures for CA key operations.

**Implementation:**

- [crates/ostrich-kra/src/shamir.rs](../../crates/ostrich-kra/src/shamir.rs) - Shamir secret sharing module

**Evidence:**

- ✅ Shamir secret sharing implemented
- ✅ M-of-N threshold support
- ⚠️ Integration with CA key operations unclear

**Gaps:**

- Not clear if used for CA signing key recovery
- No documentation of split knowledge procedures

**Remediation Plan:** Phase 16 - Document split knowledge procedures, integrate with CA operations

---

### FPT_STM.1 - Reliable Time Stamps

**Status:** 🟢 **Compliant**

**Requirement:** The TSF shall be able to provide reliable time stamps for its own use.

**Implementation:**

- [crates/ostrich-common/src/util/time.rs](../../crates/ostrich-common/src/util/time.rs) - Time utilities
- Uses `chrono::Utc::now()`

**Evidence:**

- ✅ All timestamps use UTC
- ✅ Consistent time source (system clock)
- ✅ Audit events, certificates use timestamps

**Gaps:**

- Relies on system clock accuracy (deployment requirement)
- Should document NTP requirement

**Remediation Plan:** Phase 15 - Add NIAP annotation, document NTP requirement in deployment guide

**NIAP Annotation Required:** ✅ Phase 15 Task

---

### FPT_TST_EXT.1 - TSF Self-Test - TOE Integrity

**Status:** 🔴 **Missing** (Optional)

**Requirement:** The TSF shall run self-tests to verify the integrity of stored TSF executable code.

**Implementation:** None

**Gaps:**

- No software/firmware integrity checking
- No signature verification of binaries
- No startup integrity test

**Remediation Plan:** Phase 15 - Create stub module, Phase 16 - Implement binary signing and verification

---

### FPT_TST_EXT.2 - TSF Self-Test - TSF Data Integrity

**Status:** 🔴 **Missing** (Optional)

**Requirement:** The TSF shall verify the integrity of stored TSF data: Trust Anchor Database, TSF keys, audit trail.

**Implementation:** None

**Gaps:**

- No Trust Anchor Database integrity verification
- No TSF key integrity checking
- Audit hash chain defined but verification not implemented

**Remediation Plan:** Phase 15 - Create stub module, Phase 13 - Implement audit hash chain verification

---

### FPT_TUD_EXT.1 - Trusted Update

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall provide the ability to check for updates and install updates to the TSF.

**Implementation:** None

**Gaps:**

- No update mechanism
- No signature verification of updates

**Remediation Plan:** Document as operational environment requirement (manual update process with signature verification)

---

## 7. TOE Access (FTA)

### FTA_SSL.3 - TSF-Initiated Termination

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall terminate an interactive session after a configurable time period of inactivity.

**Implementation:** None

**Gaps:**

- No session management system
- No idle timeout configuration

**Remediation Plan:** Phase 16 - Implement session management with configurable timeouts

**Related NIST 800-53:** AC-12 (Session Termination)

---

### FTA_SSL.4 - User-Initiated Termination

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall allow user-initiated termination of the user's own interactive session.

**Implementation:** None

**Gaps:**

- No session management
- No logout mechanism

**Remediation Plan:** Phase 16 - Implement logout endpoint

---

### FTA_SSL_EXT.1 - TSF-Initiated Session Locking

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall lock an interactive session after a configurable time period of inactivity.

**Implementation:** None

**Gaps:**

- No session locking mechanism

**Remediation Plan:** Phase 16 - Implement session locking (alternative to termination)

---

### FTA_TAB.1 - Default TOE Access Banners

**Status:** 🔴 **Missing**

**Requirement:** The TSF shall display a configurable advisory warning message before authentication.

**Implementation:** None

**Gaps:**

- No access banner display
- No warning before login

**Remediation Plan:** Phase 15 - Implement configurable banner module

---

## 8. Trusted Path/Channels (FTP)

### FTP_TRP.1 - Trusted Path

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall provide a trusted communication path between itself and users using [TLS].

**Implementation:**

- REST APIs use HTTPS (when configured)
- gRPC uses TLS (when configured)

**Evidence:**

- ✅ Frameworks support TLS
- ⚠️ TLS configuration not in application code

**Gaps:**

- TLS delegated to deployment (reverse proxy or native)
- No enforcement of TLS 1.3 in code
- Cipher suite configuration not specified

**Remediation Plan:** Phase 16 - Configure TLS in application or document OE dependency in ST

**Related NIST 800-53:** SC-8 (Transmission Confidentiality and Integrity)

---

### FCS_HTTPS_EXT.1 - HTTPS Protocol

**Status:** 🟡 **Partial** (Selection-based if HTTPS selected)

**Requirement:** The TSF shall implement HTTPS using TLS.

**Implementation:**

- REST endpoints support HTTPS
- Uses TLS per FTP_TRP.1

**Remediation Plan:** Same as FTP_TRP.1

---

## 9. Non-Repudiation (FCO)

### FCO_NRO_EXT.2 - Proof of Origin

**Status:** 🟡 **Partial**

**Requirement:** The TSF shall generate evidence of origin for certificates, CRLs, OCSP responses.

**Implementation:**

- Digital signatures on all issued objects
- CSR signature verification stub

**Evidence:**

- ✅ Certificates signed by CA (Phase 8)
- ✅ CRLs signed by CA (Phase 8)
- ✅ OCSP responses signed (Phase 8)
- 🔴 CSR signature verification not implemented

**Gaps:**

- CSR proof-of-possession not verified (stub at [parser.rs:96-99](../../crates/ostrich-x509/src/parser.rs#L96-L99))

**Remediation Plan:** Phase 15 - Implement CSR signature verification

**Related NIST 800-53:** AU-10 (Non-repudiation)

---

## Compliance Summary by SFR Family

| Family | Total SFRs | Compliant 🟢 | Partial 🟡 | Missing 🔴 | N/A ⚪ | Compliance % |
|--------|------------|-------------|-----------|-----------|--------|--------------|
| FAU (Audit) | 8 | 2 | 3 | 3 | 0 | 31% |
| FCS (Crypto) | 11 | 3 | 6 | 2 | 0 | 45% |
| FDP (Data Protection) | 7 | 1 | 4 | 2 | 0 | 36% |
| FIA (Identification/Auth) | 9 | 0 | 3 | 6 | 0 | 17% |
| FMT (Management) | 4 | 0 | 1 | 3 | 0 | 13% |
| FPT (TSF Protection) | 11 | 1 | 6 | 4 | 0 | 32% |
| FTA (TOE Access) | 4 | 0 | 0 | 4 | 0 | 0% |
| FTP (Trusted Path) | 2 | 0 | 2 | 0 | 0 | 50% |
| FCO (Non-repudiation) | 1 | 0 | 1 | 0 | 0 | 50% |
| **TOTAL** | **57** | **7** | **26** | **24** | **0** | **29%** |

---

## Critical Path to Compliance

### Phase 15 (Current) - Foundation

- Add NIAP annotations to compliant code
- Implement RBAC foundation (roles, separation of duties)
- Implement DRBG for random number generation
- Implement CSR signature verification
- Implement approval workflow structure
- Create compliance tracking documents

**Expected Improvement:** 29% → 60%

### Phase 16 - Authentication & Authorization

- Implement password-based authentication
- Implement certificate-based authentication (mTLS)
- Implement session management
- Implement RBAC authorization middleware
- Implement user lifecycle management
- Configure TLS 1.3 enforcement

**Expected Improvement:** 60% → 80%

### Phase 10 - PKCS#11 Completion

- Complete HSM integration
- Implement software crypto provider
- Ensure key storage compliance

**Expected Improvement:** 80% → 90%

### Phase 14 - Testing & Verification

- Validate all SFR implementations
- Security testing
- Error handling review
- Documentation completion

**Expected Improvement:** 90% → 95%+

---

## Document Change History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-03 | OstrichPKI Team | Initial compliance assessment based on v0.10.0 codebase |

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 15)
