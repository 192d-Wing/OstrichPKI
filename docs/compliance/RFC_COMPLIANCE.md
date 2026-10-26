# RFC Standards Compliance Matrix

**Document Version:** 2.10
**Date:** 2026-10-26
**OstrichPKI Version:** 0.15.0
**Compliance Status:** Excellent (85%)
**Last Updated:** Phase 19 completion - HSM enforcement and 98% NIAP compliance

## Executive Summary

This document tracks OstrichPKI's compliance with core PKI and protocol RFCs as required by NIAP PP-CA v2.1 and industry best practices. RFC compliance is essential for interoperability with standard PKI clients and services.

**Key RFCs Covered:**

- **Core PKI**: RFC 5280 (X.509), RFC 6818 (X.509 updates)
- **Certificate Status**: RFC 6960 (OCSP), RFC 5280 §5 (CRL)
- **Enrollment**: RFC 8555 (ACME), RFC 7030 (EST)
- **Cryptography**: RFC 5652 (CMS), RFC 5958 (PKCS#8)
- **Transport**: RFC 8446 (TLS 1.3)

---

## Core PKI Standards

### RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile

**Status:** 🟢 **Excellent** (95% compliant) - **UPDATED: Phase 8 Complete**

**Sections:**

#### §4.1: Basic Certificate Fields

**Status:** 🟢 **Compliant**

**Implementation:**

- [crates/ostrich-x509/src/profile.rs](../../crates/ostrich-x509/src/profile.rs) - Certificate profile definitions
- [crates/ostrich-x509/src/builder/certificate.rs](../../crates/ostrich-x509/src/builder/certificate.rs) - Certificate builder

**Evidence:**

- ✅ §4.1.1.1 - Version: v3 certificates (version field = 2)
- ✅ §4.1.1.2 - Serial Number: Unique positive integer
- ✅ §4.1.1.2/§4.1.1.3 - **Inner/outer AlgorithmIdentifier coherence fixed**:
  `tbsCertificate.signature` and `signatureAlgorithm` are identical, and the
  CA signing path now signs with the scheme the TBS declares
  (sha256WithRSAEncryption / PKCS#1 v1.5). The previous implementation
  declared PKCS#1 v1.5 but signed with RSA-PSS, producing certificates and
  CRLs that fail verification ([issuance.rs](../../crates/ostrich-ca/src/issuance.rs),
  [revocation.rs](../../crates/ostrich-ca/src/revocation.rs)). Non-RSA CA keys
  are rejected with a clean error until algorithm agility lands (POAM)
- ✅ §4.1.1.3 - Signature Algorithm: Matches public key algorithm
- ✅ §4.2.1.12 - **Extended Key Usage encoding fixed**: ExtKeyUsageSyntax is
  SEQUENCE OF KeyPurposeId; the builder previously emitted SET OF (tag 0x31),
  a malformed extension OpenSSL rejects during chain validation
  ([builder/certificate.rs](../../crates/ostrich-x509/src/builder/certificate.rs))
- ✅ §7.1 - **Issuer name chaining fixed**: issued certificates' issuer field
  is now the CA certificate's structured subject DN parsed from DER
  (`parse_subject_dn`); previously the rendered RFC 4514 string was wrapped
  in a CN attribute, producing `CN=CN=...` and breaking path validation
- ✅ End-to-end evidence: `openssl verify -CAfile root-ca.pem issued.pem: OK`
  against a SoftHSM-backed root (E2E suite `tests/integration/ca_core_test.rs`,
  7/7 passing)
- ✅ §4.1.2.4 - Issuer: Distinguished Name present with proper RFC 4514 parsing
- ✅ §4.1.2.5 - Validity: notBefore and notAfter fields
- ✅ §4.1.2.6 - Subject: Distinguished Name present with proper RFC 4514 parsing
- ✅ §4.1.2.7 - Subject Public Key Info: Algorithm and key

**Gaps:**

- 🔴 §4.1.1.2 - Serial number MUST be ≤20 octets and contain ≥20 bits random (FCS_RBG_EXT.1 gap)
- ⚠️ No explicit validation that issuer field is non-empty

**Code References:**

- [profile.rs:60-150](../../crates/ostrich-x509/src/profile.rs#L60-L150) - Profile structures
- [builder/certificate.rs:275](../../crates/ostrich-x509/src/builder/certificate.rs#L275) - DER encoding (Phase 8)
- [parser.rs:93-174](../../crates/ostrich-x509/src/parser.rs#L93-L174) - **DN parsing (RFC 4514 compliant, NEW)**

**DN Parsing Implementation (RFC 5280 §4.1.2.4, RFC 4514):**

- ✅ Proper ASN.1 RDN (Relative Distinguished Name) iteration
- ✅ OID-based attribute extraction (CN, O, OU, L, ST, C, serialNumber)
- ✅ Multi-valued RDN support
- ✅ ASN.1 string type handling (UTF8String, PrintableString, IA5String, etc.)
- ✅ Security: Prevents DN spoofing through proper parsing
- ✅ Used by ACME and EST services for CSR subject extraction
- ✅ Test coverage: 2 unit tests with real OpenSSL-generated CSRs

**Remediation:** Phase 15 - DRBG-based serial number generation with ≥20 bits random

---

#### §4.2: Certificate Extensions

**Status:** 🟢 **Excellent (100%)** - **Phase 8 Complete**

**Implementation:**

- [crates/ostrich-x509/src/extensions.rs](../../crates/ostrich-x509/src/extensions.rs) - Extension definitions
- [crates/ostrich-x509/src/builder/certificate.rs:488-759](../../crates/ostrich-x509/src/builder/certificate.rs#L488-L759) - **Extension building with DER encoding (NEW)**

**Standard Extensions Fully Implemented:**

**Mandatory Extensions (CA Certificates):**

- ✅ §4.2.1.1 - **Authority Key Identifier**: Links cert to issuing CA's public key (keyIdentifier = issuer's method-1 key id), properly DER encoded. Computed and applied to issued leaves and to subordinate CA certificates from the issuer's SubjectPublicKeyInfo (`signing::key_identifier`)
- ✅ §4.2.1.2 - **Subject Key Identifier**: RFC 5280 method (1) - 160-bit SHA-1 of the subjectPublicKey BIT STRING contents (`signing::key_identifier`, `crates/ostrich-x509/src/signing.rs`). Applied to issued leaves (`ostrich-ca/src/issuance.rs`) and subordinate CA certs (`tools/ostrich-init`)
- ✅ §4.2.1.3 - **Key Usage** (CRITICAL): All 9 usages (digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly), proper BitString encoding
- ✅ §4.2.1.9 - **Basic Constraints** (CRITICAL): CA boolean flag, optional pathLenConstraint, DER encoded

**Common Extensions:**

- ✅ §4.2.1.4 - **Certificate Policies**: Policy OIDs with optional qualifiers, SetOfVec DER encoding
- ✅ §4.2.1.6 - **Subject Alternative Name**: Complete RFC 5280 GeneralName support
  - **CSR SAN Parsing**: Extracts SANs from CSR extension requests (OID 2.5.29.17)
  - ✅ Parses SANs from CSR attributes for certificate issuance
  - ✅ **Requested-SAN precedence (NPE approval flow):** for a certificate issued
    from an approved application, the requester's explicitly-submitted
    `subject_alt_names` take precedence over the CSR's embedded SANs, with the CSR
    as fallback — `resolve_approval_sans` in `crates/ostrich-ca/src/rest.rs`,
    mirroring `issue_certificate`. This keeps the approval-issuance and direct-issue
    paths consistent so a SAN-required profile (e.g. `tls_server`) does not reject
    an application whose SAN was supplied on the form but absent from a CN-only CSR.
    Resolved names are still profile/namespace-validated in `issue()` (SI-10) and
    PoP is verified over the CSR. Test: `resolve_approval_sans_prefers_form_over_csr`.
  - ✅ **COMPLETE RFC 5280 SUPPORT: All 9 GeneralName types implemented**:
    - ✅ otherName: Custom identifiers (e.g., UPN) - Format: `otherName:OID:hex-value`
    - ✅ rfc822Name: Email addresses - Format: `email:user@example.com`
    - ✅ dNSName: DNS hostnames - Format: `DNS:www.example.com`
    - ✅ x400Address: X.400 addresses (ORAddress) - Format: `x400Address:hex-value`
    - ✅ directoryName: X.500 Distinguished Names - Format: `DirName:CN=...`
    - ✅ ediPartyName: EDI party names - Format: `ediPartyName:hex-value`
    - ✅ uniformResourceIdentifier: URIs - Format: `URI:https://example.com`
    - ✅ iPAddress: IPv4/IPv6 addresses - Format: `IP:192.0.2.1` or `IP:2001:db8::1`
    - ✅ registeredID: Registered OIDs - Format: `registeredID:1.2.3.4.5`
  - ✅ Used by ACME and EST services for SAN extraction
  - ✅ Code: [parser.rs:185-324](../../crates/ostrich-x509/src/parser.rs#L185-L324) - extract_sans_from_csr()
  - ✅ Test coverage: 1 integration test + 5 unit tests validating all GeneralName types
  - ✅ Phase 15 Update: Added otherName, registeredID, x400Address, ediPartyName support
- ✅ §4.2.1.12 - **Extended Key Usage**: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, custom OIDs, SetOfVec encoding
- ✅ §4.2.1.13 - **CRL Distribution Points**: Full name URIs as GeneralName, DistributionPoint structure with optional reasons
- ✅ §4.2.2.1 - **Authority Information Access**: id-ad-ocsp and id-ad-caIssuers with URI locations, AccessDescription sequence

**Critical Extensions Handling:**

- ✅ Key Usage: CRITICAL (required by §4.2.1.3)
- ✅ Basic Constraints: CRITICAL (required by §4.2.1.9)
- ✅ Extended Key Usage: NON-CRITICAL (per §4.2.1.12)
- ✅ Subject Alternative Name: NON-CRITICAL (per §4.2.1.6, becomes critical if subject is empty per §4.1.2.6)
- ✅ All other extensions: NON-CRITICAL per RFC 5280 defaults

**ASN.1 DER Encoding:**

- ✅ All extensions properly encoded using `der` crate
- ✅ Extension OIDs from const-oid::db::rfc5280
- ✅ Extension values wrapped in OCTET STRING per §4.1
- ✅ Extensions sequence properly ordered

**Evidence:**

- [builder/certificate.rs:488-759](../../crates/ostrich-x509/src/builder/certificate.rs#L488-L759) - Complete build_extensions() implementation
- [profile.rs:82-106](../../crates/ostrich-x509/src/profile.rs#L82-L106) - KeyUsage enum with all 9 flags
- [profile.rs:111-142](../../crates/ostrich-x509/src/profile.rs#L111-L142) - ExtendedKeyUsage enum with OID mappings

**Gaps:**

- ⚠️ Policy mapping extension not implemented (§4.2.1.5 - rarely used, selection-based)
- ⚠️ Name constraints extension not implemented (§4.2.1.10 - rarely used, CA-specific)

---

#### §5: CRL and CRL Extensions Profile

**Status:** 🟢 **Excellent (95%)** - **Phase 8 Complete**

**Implementation:**

- [crates/ostrich-x509/src/crl.rs](../../crates/ostrich-x509/src/crl.rs) - CRL structure
- [crates/ostrich-x509/src/builder/crl.rs:160-451](../../crates/ostrich-x509/src/builder/crl.rs#L160-L451) - **CRL builder with full extension support (UPDATED)**

**Basic CRL Fields:**

- ✅ §5.1.2.1 - **Version**: v2 CRLs (version = 1)
- ✅ §5.1.2.2 - **Signature Algorithm**: Matches signature field
- ✅ §5.1.2.3 - **Issuer**: Issuing CA distinguished name
- ✅ §5.1.2.4 - **thisUpdate**: CRL issue time in GeneralizedTime
- ✅ §5.1.2.5 - **nextUpdate**: Next CRL scheduled time (SHOULD be present - implemented)
- ✅ §5.1.2.6 - **Revoked Certificates**: Sequence of revoked certificate entries

**CRL Extensions (§5.2):**

- ✅ §5.2.1 - **Authority Key Identifier**: Links CRL to issuing CA's public key, DER encoded with KeyIdentifier
- ✅ §5.2.3 - **CRL Number** (CRITICAL): Monotonically increasing integer for CRL versioning, properly encoded as INTEGER wrapped in OCTET STRING
- ✅ §5.2.4 - **Delta CRL Indicator**: emitted (critical) by `CrlBuilder::delta_crl_indicator(base)`; openssl-verified
- ✅ §5.2.5 - **Issuing Distribution Point**: emitted (critical, indirectCRL) by `CrlBuilder::indirect_crl()`; openssl-verified
- ✅ §5.2.6 - **Freshest CRL**: emitted by `CrlBuilder::freshest_crl(url)` to locate the delta CRL; openssl-verified

**CRL Entry Extensions (§5.3):**

- ✅ §5.3.1 - **Revocation Reason** (non-critical): All 11 RFC 5280 reason codes implemented:
  - 0: unspecified
  - 1: keyCompromise
  - 2: cACompromise
  - 3: affiliationChanged
  - 4: superseded
  - 5: cessationOfOperation
  - 6: certificateHold
  - 8: removeFromCRL (7 is reserved)
  - 9: privilegeWithdrawn
  - 10: aACompromise
- ✅ **ASN.1 ENUMERATED encoding**: Manual encoding with tag 0x0A for reason codes
- ⚪ §5.3.2 - Invalidity Date: Not implemented (rarely used)
- ⚪ §5.3.3 - Certificate Issuer: Not implemented (for indirect CRLs)

**ASN.1 DER Encoding:**

- ✅ TBSCertList structure properly encoded
- ✅ CRL extensions sequence with proper OIDs
- ✅ Revoked certificate entries with optional extensions
- ✅ Signature algorithm and signature value fields
- ✅ All encodings use `der` crate for spec compliance

**Code References:**

- [crl.rs:15-100](../../crates/ostrich-x509/src/crl.rs#L15-L100) - CRL and RevokedCertificate structures
- [crl.rs:45-66](../../crates/ostrich-x509/src/crl.rs#L45-L66) - RevocationReason enum with all 11 codes
- [rest.rs](../../crates/ostrich-ca/src/rest.rs) - `POST /api/v1/certificates/{id}/revoke` accepts a §5.3.1 reason code (PascalCase variant name on the wire) plus optional justification; the requestor is server-derived from the authenticated identity (AC-3), never client-supplied
- [builder/crl.rs:160-230](../../crates/ostrich-x509/src/builder/crl.rs#L160-L230) - CRL entry building with revocation reasons
- [builder/crl.rs:392-451](../../crates/ostrich-x509/src/builder/crl.rs#L392-L451) - CRL extension building (CRL Number, AKI)

**CRL persistence, distribution, and CDP (implemented):**

- ✅ §5.2.3 - CRL number is now DB-derived (`MAX(crl_number)+1` per CA) so it is
  monotonic and restart-stable, enforced by `UNIQUE(ca_id, crl_number)`:
  - [repository/crl.rs](../../crates/ostrich-db/src/repository/crl.rs) - `CrlRepository::next_crl_number` / `create_crl` / `find_latest_crl`
  - [revocation.rs](../../crates/ostrich-ca/src/revocation.rs) - `generate_crl` derives the number from the DB and persists the signed CRL (signing/encoding unchanged)
- ✅ §5 - Latest signed CRL served at a **public** distribution point
  `GET /api/v1/crl` with `Content-Type: application/pkix-crl` (404 when none yet):
  - [rest.rs](../../crates/ostrich-ca/src/rest.rs) - `get_crl` handler (public route)
- ✅ §4.2.1.13 - Issued leaves carry a CRL Distribution Points extension pointing
  at the public CRL endpoint when the CA is configured with a public CRL URL:
  - [issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - `set_crl_distribution_url` + `add_crl_distribution_point` in `issue`
  - [services/ca-server/src/main.rs](../../services/ca-server/src/main.rs) - `--crl-distribution-url` / `CA_CRL_URL`
- ✅ §4.2.2.1 - Issued leaves carry an **Authority Information Access** extension
  (id-ad-ocsp + id-ad-caIssuers) so relying parties can discover the OCSP
  responder and fetch the issuing CA certificate, when the CA is configured with
  those URLs:
  - [issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - `set_ocsp_responder_url` / `set_ca_issuers_url` + `add_authority_info_access` in `issue`
  - [services/ca-server/src/main.rs](../../services/ca-server/src/main.rs) - `--ocsp-responder-url` / `CA_OCSP_URL`, `--ca-issuers-url` / `CA_ISSUERS_URL`
  - **Live proof (openssl)**: [crates/ostrich-ca/src/issuance_aia_e2e.rs](../../crates/ostrich-ca/src/issuance_aia_e2e.rs) issues a leaf through the real issuer and asserts `openssl x509 -text` shows the AIA extension with both URIs.

**Gaps:**

- ✅ Delta CRL extension encoding (§5.2.4 Delta CRL Indicator, §5.2.6 Freshest CRL) — `CrlBuilder`, openssl-verified
- ✅ Indirect CRL marking (§5.2.5 Issuing Distribution Point, indirectCRL) — `CrlBuilder::indirect_crl()`
- ✅ **CA-level delta-CRL generation lifecycle**: `RevocationManager::generate_delta_crl` issues a delta listing entries revoked since the latest full (base) CRL with the Delta CRL Indicator; full CRLs carry a Freshest CRL pointer (`set_delta_crl_url` / `CA_DELTA_CRL_URL`); persisted with `is_delta`/`base_crl_number` (migration 00009) and served at `GET /api/v1/crl/delta`. **Live proof:** [crates/ostrich-ca/src/crl_delta_e2e.rs](../../crates/ostrich-ca/src/crl_delta_e2e.rs) — openssl confirms the Freshest CRL on the full CRL and the Delta CRL Indicator on a delta that lists only the change since the base.
- ⚪ §5.3.3 Certificate Issuer entry extension (per-entry issuer for indirect CRLs) — rarely needed

**Remediation:** delta CRL extensions, generation lifecycle, and serving are
implemented and openssl-verified; only the §5.3.3 per-entry Certificate Issuer
extension (uncommon) remains.

---

#### §6: Certification Path Validation

**Status:** 🟢 **Implemented** - **Phase 15 Complete**

**Requirement:** Path validation algorithm per §6.1

**Implementation:**

- [validation/mod.rs](../../crates/ostrich-x509/src/validation/mod.rs) - Complete validation module
- [validation/path_validator.rs](../../crates/ostrich-x509/src/validation/path_validator.rs) - RFC 5280 §6.1 algorithm
- [validation/trust_anchor.rs](../../crates/ostrich-x509/src/validation/trust_anchor.rs) - Trust anchor management
- [validation/path_builder.rs](../../crates/ostrich-x509/src/validation/path_builder.rs) - Chain building
- [validation/extensions.rs](../../crates/ostrich-x509/src/validation/extensions.rs) - Extension helpers
- [validation/name_constraints.rs](../../crates/ostrich-x509/src/validation/name_constraints.rs) - Name constraints
- [validation/policy.rs](../../crates/ostrich-x509/src/validation/policy.rs) - Policy processing
- [validation/revocation.rs](../../crates/ostrich-x509/src/validation/revocation.rs) - OCSP/CRL integration

**RFC 5280 §6.1 Algorithm Steps:**

✅ **§6.1.1 - Inputs**: ValidationContext with trust anchors, validation time, policy parameters

✅ **§6.1.2 - Initialization**: ValidationState with working issuer name, public key, path length

✅ **§6.1.3 - Basic Certificate Processing**:
- (a) Signature verification (crypto provider integration ready)
- (b) Validity period checking
- (c) Revocation checking (OCSP/CRL framework)
- (d) Issuer name verification
- (e) Name constraints processing
- (f) Policy processing (simplified any-policy mode)
- (g) Unknown critical extension detection
- (j) Basic constraints validation
- (k) Key usage validation for CA certificates

✅ **§6.1.4 - Preparation for Next Certificate**: Working public key update

✅ **§6.1.5 - Wrap-Up Procedure**: Final policy tree validation

✅ **§6.1.6 - Outputs**: ValidationResult with chain, trust anchor, errors

**Features Implemented:**

- ✅ Trust anchor store (in-memory with database-ready design)
- ✅ Certificate chain building
- ✅ **CA hierarchy issuance** (root → intermediate → leaf): a root CA can sign a
  subordinate (intermediate) CA certificate via `ostrich-init --subordinate-of`
  (basicConstraints CA=true with pathLenConstraint per §4.2.1.9, AKI=parent SKI),
  and issued leaves carry SKI (own key id) + AKI (issuer key id) so paths build
  reliably (`tools/ostrich-init/src/main.rs`, `ostrich-ca/src/issuance.rs`)
- ✅ Path validation with multiple validation steps
- ✅ Basic constraints enforcement (CA flag, pathLenConstraint)
- ✅ Key usage validation
- ✅ Validity period checking
- ✅ Name constraints framework
- ✅ Certificate policy framework (any-policy mode)
- ✅ Revocation checking framework (OCSP/CRL ready)
- ✅ Configurable AIA fetching (default: disabled per user requirement)
- ✅ CRL size limits (10MB max per user requirement)

**Test Coverage:**

- 80 unit tests covering all validation steps
- Trust anchor CRUD operations
- Chain building scenarios
- Validity period edge cases
- Error handling for all failure modes

**Compliance Notes:**

- User-approved design decisions implemented:
  - Trust anchors: Both API and config file support
  - AIA fetching: Configurable (default disabled)
  - Policy processing: Simplified any-policy mode with future enhancement path
- NIAP PP-CA FIA_X509_EXT.1 gap CLOSED
- NIST 800-53 SC-17 requirement MET

**TLS peer path validation (separate code path):** mTLS listeners
(`crates/ostrich-common/src/tls.rs`, `WebPkiClientVerifier`) and rustls clients
validate peer chains with **rustls-webpki 0.103.16**, not with the
`ostrich-x509` validator above. Since 2026-10-23:

- RUSTSEC-2026-0382 is fixed (0.103.13 accepted some distrusted intermediates)
- TLS peer path validation additionally rejects certificates whose SPKI is on
  webpki's built-in distrust list (emSign G3; `CertDistrusted`), independent of
  configured trust anchors
- ML-DSA-44/65/87 certificate signatures are verified (RFC 9881 algorithm
  identifiers; accepted by the user 2026-10-23)
- **No revocation checking** (no CRL or OCSP) is done on this path, so RFC 5280
  §6.1.3(a)(3) revocation status is not checked for TLS peers (pre-existing gap)
- Tests (2026-10-23): `mtls_handshake_rejects_untrusted_client`,
  `mtls_handshake_rejects_client_cert_with_server_only_eku` (§4.2.1.12)
- **CA gRPC listener and clients (2026-10-25, branch `claude/grpc-mtls`,
  uncommitted):** [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)
  uses the same webpki verifiers on `grpc_crypto_provider()`, with these
  additions and limits:
  - **Dedicated trust anchor (§6.1 input; updated after fix round 2):**
    ca-server walks its issuing CA's ancestors in the CA database
    (`ca_certificates.parent_ca_id`, fails closed on a missing row, a cycle or
    depth > 16) and refuses to start the listener if an anchor in
    `CA_GRPC_TLS_CLIENT_CA_FILE` has the issuing certificate's SPKI, has its
    **subject (subject alone)**, was **issued by** it (anchor issuer = issuing
    subject, or anchor authorityKeyIdentifier = issuing subjectKeyIdentifier,
    §4.2.1.1 / §4.2.1.2), is its issuer (name match unless both key
    identifiers are present and differ), or matches (SPKI or subject) a
    database ancestor (`ensure_dedicated_client_ca`). A refusal is audited as
    `grpc_listener_refused` before exit. It warns on more than one anchor;
    since 2026-10-26 it **refuses** to start with more than one distinct
    anchor (duplicate PEM blocks counted once) when
    `CA_GRPC_ADMIN_CLIENT_SUBJECTS` is non-empty, and refuses an anchor
    without a subjectKeyIdentifier (§4.2.1.2) in that case
  - **Admin issuer (2026-10-26, branch `claude/grpc-per-method-authz`,
    uncommitted):** an Admin-role leaf is admitted only if it was issued
    directly by the single anchor: issuer DN = anchor subject (§4.1.2.4) and
    the leaf authorityKeyIdentifier keyIdentifier present and equal to the
    anchor subjectKeyIdentifier (§4.2.1.1 / §4.2.1.2), with no DN-only
    fallback; otherwise `admin_issuer_not_anchor`. Issuer roles may still
    chain through intermediates. §4.2.1.1 requires an AKI in every
    non-self-signed certificate, so conforming admin leaves meet this
  - **Per-call leaf validity (2026-10-26):** the leaf validity period
    (§4.1.2.5, inclusive bounds) is re-checked on every call against the
    system clock, so a long-lived HTTP/2 connection or TLS session cannot
    keep using an expired leaf (`certificate_not_valid_now`,
    `UNAUTHENTICATED`). Only the leaf is re-checked; intermediates and the
    anchor are validated at the handshake only (narrower than re-running
    §6.1.3(a)(2) on the whole path)
  - **Peer serial format (§4.1.2.2):** audit records carry the peer
    certificate serial as lowercase hex of the DER INTEGER content octets,
    sign byte included (serial 0x8001 is `008001`; OpenSSL prints `8001`)
  - **Per-call check:** a client leaf whose issuer DN equals the subject of
    the issuing CA or of a database ancestor, or whose AKI equals one of their
    SKIs, is denied (`subscriber_issuing_ca`). Only the leaf's direct issuer
    is compared
  - Not detected: sibling subordinate CAs, grandchildren (CAs issued by a
    subordinate of this CA) and roots outside the database lineage
    (POAM-2026-10-23-28; RFC-017)
  - **EKU (§4.2.1.12):** webpki enforces `clientAuth` only when the EKU
    extension is present; ca-server additionally requires the extension
    (`missing_client_auth_eku`). This is stricter than §4.2.1.12, which
    treats an absent EKU as unrestricted
  - **Signature algorithms:** chain and CertificateVerify signatures are
    limited to ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA-PSS
    (rsaEncryption SPKI, 2048-8192 bit, SHA-256/384/512) and ML-DSA-44/65/87.
    RSA PKCS#1 v1.5, curve/hash mismatches, P-521 and Ed25519 are refused.
    Documented deviation: narrower than what RFC 5280 / RFC 5758 permit
  - **Server identity:** the client checks the server certificate SAN against
    the URL host (no SNI for IP literals) or `CA_GRPC_SERVER_NAME`
  - Not done: revocation (§6.3; POAM-2026-10-23-27); directoryName name
    constraints (webpki rejects such chains, `NameConstraintViolation`);
    certificate-policy processing
  - Tests: `grpc_mtls_e2e` 21/21 passed 2026-10-25 on the final code (incl.
    `untrusted_ca_client_cert_handshake_fails`,
    `server_only_eku_client_cert_rejected`,
    `leaf_without_eku_is_permission_denied`,
    `client_rejects_server_name_mismatch`); `grpc_tls` unit tests
    `dedicated_client_ca_refuses_chain_relatives`,
    `issued_by_checks_cover_name_and_key_id_independently` (issuer-name and
    AKI = SKI branches tested separately) and
    `authorize_peer_refuses_subscriber_issuing_ca_leaf`; ca-server bin tests
    `walk_ca_ancestors_follows_parent_ca_id_and_fails_closed` and
    `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal`. Added
    2026-10-26 (coder-reported, final tree): `grpc_mtls_e2e` 39/39 (incl.
    `certificate_expiring_on_live_connection_is_refused`,
    `admin_under_intermediate_is_refused`), `grpc_tls` unit tests 66/66 (incl.
    `authorize_peer_refuses_leaf_outside_validity`,
    `admin_requires_leaf_issued_directly_by_anchor`,
    `resolve_refuses_admin_with_several_client_anchors`,
    `authorize_peer_records_issuer_and_serial`)

---

### RFC 4514: LDAP: String Representation of Distinguished Names

**Status:** 🟢 **Compliant**

**Implementation:**

- [crates/ostrich-x509/src/parser.rs:93-174](../../crates/ostrich-x509/src/parser.rs#L93-L174) - DN parsing function

**Evidence:**

- ✅ §2.1 - Converting AttributeTypeAndValue
  - Proper OID-to-attribute mapping (CN, O, OU, L, ST, C, serialNumber)
  - Handles ASN.1 string types (UTF8String, PrintableString, IA5String, etc.)
- ✅ §2.2 - Converting the RDNSequence
  - Iterates through RDNs in correct order
  - Handles multi-valued RDNs (comma-separated within RDN)
- ✅ §2.3 - Parsing a String Back to a Distinguished Name
  - Extracts structured DN data from ASN.1 X.509 Name structures
  - Converts to structured DistinguishedName type (not string)
- ✅ §3 - Parsing a Distinguished Name
  - OID matching for standard attribute types (2.5.4.x)

**Standard Attribute Types Supported:**

- 2.5.4.3 - CN (Common Name)
- 2.5.4.6 - C (Country)
- 2.5.4.7 - L (Locality)
- 2.5.4.8 - ST (State or Province)
- 2.5.4.10 - O (Organization)
- 2.5.4.11 - OU (Organizational Unit)
- 2.5.4.5 - serialNumber

**Security Benefits:**

- Prevents DN spoofing attacks through proper ASN.1 parsing
- Validates attribute structure before certificate issuance
- Used by ACME (RFC 8555) and EST (RFC 7030) for CSR validation

**CA gRPC client-subject lists (2026-10-25, branch `claude/grpc-mtls`;
three role lists since 2026-10-26, branch `claude/grpc-per-method-authz`,
uncommitted):** [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)
`certificate_subject_dn` renders the peer certificate subject with `x509-cert`'s
RFC 4514 `Display` (§2: last RDN first, §2.4 escaping), and
`ClientSubjectAllowlist::parse` canonicalises each configured entry the same
way. The REST `peer_cert_subject` now delegates to the same function.

- Claimable: strict §2.4 escape validation (dangling `\`, incomplete hex
  escapes and invalid escapes are refused; an escaped backslash directly before
  an escaped `,` or `+` is refused as ambiguous), attribute-type validation
  including numeric OIDs, and a DER round-trip check (the canonical form must
  re-parse to the same `Name`)
- Claimable (rounds 2-3): hex escapes must decode to valid UTF-8 (§3 /
  RFC 5280 §4.1.2.4 UTF8String; `CN=\FF`, `CN=\C3\28` refused, `CN=\C3\A9`
  accepted)
- 2026-10-26: the same parser is applied to each of
  `CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS` and
  `CA_GRPC_ADMIN_CLIENT_SUBJECTS` (the single
  `CA_GRPC_ALLOWED_CLIENT_SUBJECTS` is removed and refused). A canonical
  subject in two lists, or two entries in different lists that differ only in
  ASCII letter case, refuses startup (runtime matching stays exact). A
  numeric attribute type (§3 `numericoid`) must also decode again from its
  own DER encoding: const-oid 0.9.6 encodes some large arcs that its decoder
  refuses, and its `Display` panicked on them (found by
  `fuzz_grpc_peer_subject`); such entries are now refused at startup (test
  `allowlist_refuses_undecodable_numeric_oid`; 135,145 fuzz runs / 61 s
  clean after the fix, coder-reported)
- Deviations:
  - `;` is the list separator and is never part of a DN (an escaped `\;`
    leaves a dangling `\` and is refused; `\3B` is accepted);
  - a value with an escaped backslash directly followed by an escaped `,` or
    `+` cannot be allow-listed, **also when hex-escaped** (fails closed);
  - trimming is ASCII-only: leading and unescaped trailing ASCII space, tab, CR
    and LF are removed, and an escaped trailing space is kept, written either
    `\20` or as a backslash followed by a space (both accepted);
  - non-ASCII whitespace (for example U+00A0, U+3000) at either end of an
    entry, attribute type or value is **rejected**, not trimmed (RFC 4514 §3
    insignificant spaces are ASCII SPACE only);
  - matching is exact octet comparison of the canonical string, **not** X.500
    caseIgnoreMatch
- Tests: 41 `grpc_tls::tests` passed 2026-10-25 (re-run by the compliance
  scribe on the final code; incl. allowlist escape and round-trip tests,
  `allowlist_keeps_escaped_trailing_space`,
  `allowlist_rejects_hex_escapes_that_are_not_utf8`,
  `allowlist_does_not_trim_unicode_whitespace` and
  `subject_parsing_never_panics_on_mutated_input`); fuzz target
  `fuzz_grpc_peer_subject` found and drove the fix of an OID-arc overflow
  panic, then ran clean (237,187 runs after round 1, 215,504 runs / 61 s after
  round 2; coder-reported, `fixes-round-1.md`, `fixes-round-2.md`)

**Robust PKCS#10 attribute handling (RFC 2986 §4 / RFC 2985 §5.4.1 / NIST 800-53 SI-10):**

- `parse_csr` parses with x509-parser first, then falls back to a der-based
  (`x509-cert`) decode when x509-parser rejects a request while deep-parsing its
  attributes. x509-parser 0.18 decodes `challengePassword` only as UTF8/Printable/
  Universal/BMP/T61String and fails the **entire** request with `InvalidAttributes`
  for other valid encodings — e.g. an IA5String challengePassword, or a
  PrintableString containing characters outside the PrintableString repertoire
  (`!`, `_`, `@`) — which device/NPE enrollment clients commonly emit.
- The fallback models attribute values as opaque `Any`, so it accepts these
  requests without interpreting the challengePassword value. It only runs after
  the strict parse already failed, so it cannot change results for CSRs that
  parse today (fail-safe, not fail-open — the signature/PoP check still applies).
- `parse_csr_subject_dn` (identity binding) and `verify_csr_signature` (PoP over
  the raw `CertificationRequestInfo`) use the same fallback so the whole
  enrollment path is consistent for these CSRs.
- **Missing `attributes` field (RFC 2986 §4.1):** `attributes` is `[0] IMPLICIT
  SET OF Attribute` — mandatory but permitted to be empty. Some clients (notably
  pkijs, used by the NPE portal in-browser generator, and other lightweight
  tooling) OMIT the field entirely when there are no attributes. OpenSSL accepts
  such requests, but both strict decoders reject them (x509-parser →
  `InvalidAttributes`; RustCrypto `der` → malformed context-[0]). The fallback's
  `normalize_missing_attributes` injects an empty `SET OF` (`A0 00`) — and only
  when the field is genuinely absent — so these requests enroll. The self-signature
  is verified over the **original** (attribute-less) `CertificationRequestInfo`
  bytes, so PoP is unaffected. The NPE portal generator was also fixed to always
  emit the field ([csr.ts](../../services/npe-portal/web/src/lib/csr.ts)).
- **Evidence:** [parser.rs `parse_csr_der_fallback` / `normalize_missing_attributes` / `extract_cert_req_info_tbs`](../../crates/ostrich-x509/src/parser.rs),
  regression tests `test_parse_csr_ia5_challenge_password_fallback` and
  `test_parse_csr_printable_challenge_password_fallback` in
  [csr_parsing_test.rs](../../tests/integration/csr_parsing_test.rs), and
  `test_parse_csr_missing_attributes_field` in
  [parser.rs](../../crates/ostrich-x509/src/parser.rs).

**Proof-of-Possession enforcement (RFC 2986 / NIST 800-53 SI-10):**

- The CA issuance path (`CertificateIssuer::issue`) verifies the CSR signature
  (stateless `verify_with_spki` over the CertificationRequestInfo) and that the
  CSR public key matches the request, proving the requester holds the private key.
- The direct CA API now carries the CSR end-to-end: `csr_der` added to the gRPC
  `IssueCertificateRequest` (proto) and the REST issuance body; the ACME and EST
  CA clients forward the client's CSR instead of only the extracted public key.
- End-entity issuance **requires** a CSR by default (`CA_REQUIRE_POP=true`); CA
  certificates are exempt. Configurable via `services/ca-server` `--require-proof-of-possession` / `CA_REQUIRE_POP`.
- **Live evidence:** `pop_e2e` proves all three outcomes against a SoftHSM-backed
  CA — no CSR → rejected, valid CSR+matching key → issued, CSR+wrong key → rejected.

**Test Evidence:**

- [parser.rs:417-510](../../crates/ostrich-x509/src/parser.rs#L417-L510) - 2 unit tests with OpenSSL CSRs
  - test_parse_distinguished_name_full() - Complete DN with all attributes
  - test_parse_distinguished_name_minimal() - Minimal DN (CN + C only)

**Integration:**

- ACME: [ca_integration.rs:153-177](../../crates/ostrich-acme/src/ca_integration.rs#L153-L177)
- EST: [ca_integration.rs:197-221](../../crates/ostrich-est/src/ca_integration.rs#L197-L221)

---

### RFC 6818: Updates to RFC 5280

**Status:** 🟡 **Partial**

**Key Updates:**

- Clarifications on certificate policy processing
- Updates to AIA extension usage
- Path validation algorithm clarifications

**Implementation:**

- Followed where RFC 5280 implementation exists
- Not all clarifications explicitly addressed

**Remediation:** Review during Phase 14 testing, update path validation per RFC 6818

---

### RFC 5758: Additional Algorithms for X.509 (SHA-2)

**Status:** 🟢 **Compliant**

**Algorithms:**

- ✅ SHA-256 with RSA
- ✅ SHA-384 with RSA
- ✅ SHA-512 with RSA
- ✅ SHA-256 with ECDSA
- ✅ SHA-384 with ECDSA
- ✅ SHA-512 with ECDSA

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm enum includes all SHA-2 combinations

---

### RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, X448

**Status:** 🟢 **Compliant**

**Algorithms:**

- ✅ Ed25519 signatures
- ✅ Ed448 signatures
- ✅ X25519 ECDH (future use)
- ✅ X448 ECDH (future use)

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - EdDSA support defined

**OID Compliance:**

- ✅ id-Ed25519: 1.3.101.112
- ✅ id-Ed448: 1.3.101.113

---

## Certificate Status Protocols

### RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)

**Status:** 🟢 **Compliant** (signed responses verified by `openssl ocsp`)

**End-to-end evidence (Phase 16):** a live `openssl ocsp` round-trip against
the responder (signing with the real CA key in SoftHSM) returns `Cert
Status: good` before revocation and `Cert Status: revoked` /
`Revocation Reason: keyCompromise` after — OpenSSL independently parses the
responderID, certStatus CHOICE, thisUpdate/nextUpdate, nonce, and embedded
responder certificate. Test: `tests/integration/ocsp_revocation_test.rs`.

Key corrections in this phase:
- Responses are signed with the **real CA key** (was a placeholder KeyHandle).
- TBS is encoded **once** and the exact signed bytes are embedded (was a
  divergent second encoding, so signatures never verified).
- Signing algorithm now matches the declared `sha256WithRSAEncryption` OID
  (was RSA-PSS — mismatched and unverifiable).
- certStatus is the real context-tagged **CHOICE** (good `[0]`, revoked `[1]`,
  unknown `[2]`); nextUpdate has its `[0] EXPLICIT` wrapper; CertID echoes the
  request hashes (placeholder zero hashes removed).
- **SHA-1 CertIDs** accepted (RFC 6960 §4.3 mandatory; OpenSSL default).
- **RFC 8954 nonce** parsed from the request and echoed in responseExtensions;
  nonced requests bypass the cache. The nonce length is bounded to 1..=32 octets
  per RFC 8954 §2.1 — a request with a nonce outside that range is rejected with
  the `malformedRequest` response status, so the responder cannot be turned into
  a signing oracle by echoing an oversized attacker-controlled nonce.

**Sections:**

#### §2.1: Request Syntax

**Status:** 🟢 **Compliant**

**Implementation:**

- [crates/ostrich-ocsp/src/request.rs](../../crates/ostrich-ocsp/src/request.rs) - OCSP request parsing

**Evidence:**

- ✅ §2.1 - OCSPRequest ASN.1 structure
- ✅ §2.1 - TBSRequest with version, requestorName, requestList
- ✅ §2.1 - CertID with hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber
- ✅ §2.2 - Request extensions support
- ✅ **OCSP client** (NPE-portal status checker): a browser-side RFC 6960 client
  (`services/npe-portal/web/src/lib/ocsp.ts`, page `/ocsp`) builds the SHA-1
  CertID request, sends it via the BFF `/ocsp` proxy
  (`services/npe-portal/src/server/proxy.rs`) to the responder, and — per
  §3.2 — **verifies the signed response against the issuing CA's public key**
  before trusting the status (Good / Revoked / Unknown, with revocation time +
  RFC 5280 §5.3.1 reason). Accepts either a pasted certificate or a hex serial.

**Code References:**

- [request.rs:15-60](../../crates/ostrich-ocsp/src/request.rs#L15-L60) - Request structures
- [request.rs:43](../../crates/ostrich-ocsp/src/request.rs#L43) - ASN.1 parsing (Phase 8)

---

#### §2.2: Response Syntax

**Status:** 🟢 **Compliant**

**Implementation:**

- [crates/ostrich-ocsp/src/response.rs](../../crates/ostrich-ocsp/src/response.rs) - OCSP response encoding

**Evidence:**

- ✅ §2.2 - OCSPResponse with responseStatus, ResponseBytes
- ✅ §2.3 - BasicOCSPResponse structure
- ✅ §2.4 - Produced At field (RFC 6960 §4.2.2.1 - mandatory)
- ✅ §2.4 - Responses array with CertStatus
- ✅ §2.5 - SingleResponse with certStatus, thisUpdate, nextUpdate

**CertStatus Values:**

- ✅ good (no revocation)
- ✅ revoked (with revocationTime and revocationReason)
- ✅ unknown

**Code References:**

- [response.rs:15-150](../../crates/ostrich-ocsp/src/response.rs#L15-L150) - Response structures
- [response.rs:117](../../crates/ostrich-ocsp/src/response.rs#L117) - ASN.1 encoding (Phase 8)

---

#### §4.2: OCSP Response

**Status:** 🟡 **Partial**

**Requirements:**

**Mandatory Fields:**

- ✅ §4.2.1 - producedAt MUST be present
- ✅ §4.2.2.1 - thisUpdate MUST be present
- ✅ §4.2.2.1 - nextUpdate SHOULD be present (verify implementation)

**Response Signing:**

- ✅ §4.2.2.2 - Signature over response data
- ⚠️ §4.4 - Delegated signing support (not implemented - optional)

**Code References:**

- [responder.rs:170](../../crates/ostrich-ocsp/src/responder.rs#L170) - Response signing (Phase 8)

**Gaps:**

- Delegated OCSP signing not implemented (optional feature)
- Response caching not implemented (Phase 13 enhancement)

---

### RFC 5019: Lightweight OCSP Profile for High-Volume Environments

**Status:** ⚪ **Not Applicable** (optional optimization)

**Features:**

- Pre-computed OCSP responses
- Short nextUpdate intervals
- Optimized for CDN distribution

**Planned:** Phase 13 - OCSP response caching aligns with this profile

---

### RFC 6277: Online Certificate Status Protocol Algorithm Agility

**Status:** 🟢 **Compliant**

**Requirement:** Support multiple hash algorithms in OCSP requests/responses

**Implementation:**

- [crates/ostrich-ocsp/src/request.rs](../../crates/ostrich-ocsp/src/request.rs) - Hash algorithm support in CertID

**Evidence:**

- ✅ SHA-1 (legacy, discouraged)
- ✅ SHA-256 (recommended)
- ✅ SHA-384
- ✅ SHA-512

---

## Enrollment Protocols

### RFC 8555: Automatic Certificate Management Environment (ACME)

**Status:** 🟢 **Good** (85% compliant)

**§7.6 revocation (noted 2026-10-26):** the ACME directory advertises a
`revokeCert` URL, but acme-server has no revocation route, and since the
per-method CA gRPC authorization (branch `claude/grpc-per-method-authz`) the
acme-server identity (Issuer role) is not permitted to call
`RevokeCertificate` on the CA. A future scoped grant would add the Issuer role
to that rule plus a check that the target certificate's stored requestor
namespace is `acme`. §7.6 is not implemented; no status change.

**ACME client (NPE portal, HTTP-01):** In addition to the OstrichPKI ACME
*server* below, the NPE portal embeds an ACME *client* (`instant-acme`, FIPS /
aws-lc-rs backend) so it auto-enrolls and auto-renews **its own TLS server
certificate** from an ACME directory using the HTTP-01 challenge (§8.3):

- [services/npe-portal/src/server/acme.rs](../../services/npe-portal/src/server/acme.rs) -
  account creation (§7.1.2), order + authorization handling (§7.1.3/§7.1.4),
  HTTP-01 key-authorization responder at `/.well-known/acme-challenge/{token}`
  (§8.1/§8.3), `finalize` + certificate download (§7.4), and a background
  renewal loop. Served challenge tokens are removed after every order (success
  or failure); terminal (non-pending) authorizations are not re-answered.
- The issued cert is swapped into the live rustls listener via a dynamic
  `ResolvesServerCert` resolver — renewal takes effect without a restart.
- The directory's own private-CA HTTPS endpoint is trusted via a configured CA
  bundle (`acme.caBundle`), not the public web-PKI roots.

**Sections:**

#### §7.1: Resources

**Status:** 🟡 **Partial** (corrected 2026-10-26, was "🟢 Compliant"; POAM-2026-10-23-49)

**Implementation:**

- [crates/ostrich-acme/src/rest.rs](../../crates/ostrich-acme/src/rest.rs) - ACME REST endpoints

**Resources:**

Section numbers corrected 2026-10-26 (RFC 8555 §7.1.1 is the directory; the
list previously numbered accounts as §7.1.1 through challenges as §7.1.4).

- ✅ §7.1.2 - Account objects
- 🟡 §7.1.3 - Order objects: `new_order` does not validate identifiers, and a
  `*.` identifier is stored as a literal name with `wildcard = false`, so
  wildcard orders cannot complete (POAM-2026-10-23-49)
- 🟡 §7.1.4 - Authorization objects: the `wildcard` field is always present,
  including `false`, although §7.1.4 says it MUST be absent unless true; all
  three challenge types are offered for every identifier, including dns-01
  for IP identifiers (RFC 8738 §7 forbids it) (POAM-2026-10-23-49)
- ✅ §7.1.5 - Challenge objects. Since 2026-10-26 a failed challenge's `error`
  is a problem document with a registered type (see §7.5)

**Code References:**

- [rest.rs:145-187](../../crates/ostrich-acme/src/rest.rs#L145-L187) - Account management
- [rest.rs:237-362](../../crates/ostrich-acme/src/rest.rs#L237-L362) - Order lifecycle
- [rest.rs:305-424](../../crates/ostrich-acme/src/rest.rs#L305-L424) - Authorizations
- [rest.rs:464-522](../../crates/ostrich-acme/src/rest.rs#L464-L522) - Challenges

---

#### §7.2: Getting a Nonce

**Status:** 🟢 **Compliant**

**Requirement:** Server provides fresh nonce in Replay-Nonce header

**Implementation:**

- [crates/ostrich-acme/src/rest.rs:127](../../crates/ostrich-acme/src/rest.rs#L127) - Nonce generation

**Evidence:**

- ✅ Cryptographically random nonces (UUID v4)
- ✅ Database storage with expiration (5 minutes)
- ✅ Replay-Nonce header on all responses
- ✅ **Single-use enforced (RFC 8555 §6.5):** `consume_nonce` atomically deletes
  the nonce and returns whether one was actually consumed; the JWS validation
  path now rejects a request whose nonce was unknown/expired/already used
  (`badNonce`). **Fixed:** previously the boolean result was ignored, so a
  replayed (already-consumed) nonce was accepted — a replay-protection bypass.
- ✅ **Method-specific status codes (RFC 8555 §7.2):** `get_new_nonce` now returns
  **200 (OK)** for `HEAD` and **204 (No Content)** for `GET` (both with a fresh
  `Replay-Nonce`). **Fixed:** previously it returned `204` for both; the §7.2
  SHOULD-200 for HEAD was not honored, which strictly-conformant clients (e.g.
  `instant-acme`) reject with "error response from newNonce resource". The route
  remains GET/HEAD only — any other method is `405` (no POST tolerance).

---

#### §7.4: Finalizing an Order

**Status:** 🟢 **Compliant**

**Requirement:** The CSR submitted at finalization MUST request exactly the set
of identifiers authorized in the order.

**Evidence:**

- ✅ CSR signature verified (proof-of-possession) before issuance
- ✅ Order ownership checked against the authenticated account
- ✅ All authorizations must be `valid` before issuance (§7.1.6)
- ✅ **Identifier binding (RFC 8555 §7.4):** `validate_csr_identifiers` enforces
  set equality between the order's authorized identifiers and the CSR's
  Subject Alternative Names (DNS case-insensitive; non-DNS/IP SANs rejected).
  **Fixed:** this check was previously commented out (`_order_identifiers`
  unused), so a client that validated one identifier could submit a CSR for
  arbitrary OTHER identifiers and obtain a certificate — a domain-control /
  authorization bypass. Unit-tested (`test_validate_csr_identifiers`).
- ✅ **Empty-subject handling (RFC 5280 §4.1.2.6):** ACME CSRs typically carry an
  empty subject and convey identifiers only via the SAN. When the CSR subject DN
  is empty, `finalize_order` (`crates/ostrich-acme/src/ca_integration.rs`,
  `resolve_proto_subject`) derives the subject CN from the first DNS SAN whose
  length is a valid common name (`1..=64`, X.520 `ub-common-name`, RFC 5280
  Appendix A); over-long or empty DNS SANs are skipped so no non-conformant CN is
  emitted, and if none qualifies the subject is left empty. The SAN extension
  remains non-critical (§4.2.1.6). Unit-tested (`test_derived_cn_prefers_first_usable_dns`,
  `test_derived_cn_skips_over_long_dns`, `test_derived_cn_skips_empty_dns`,
  `test_resolve_proto_subject_empty_derives_cn`).

---

#### §7.3: Account Management

**Status:** 🟢 **Compliant**

**Endpoints:**

- ✅ §7.3.1 - newAccount (account creation)
- ✅ §7.3.1 - newAccount **idempotency**: a request whose key already has an
  account returns `200 (OK)` with the existing account (never a duplicate), for
  both a plain newAccount and an `onlyReturnExisting` key-lookup. **Fixed:** the
  handler previously only looked up an existing account when `onlyReturnExisting`
  was set, so a returning client's plain newAccount hit the
  `acme_accounts_jwk_thumbprint` unique constraint and got a `500 serverInternal`
  (duplicate-key). The lookup now runs first for all requests, and a concurrent
  insert race is recovered by re-fetching (`new_account` / `existing_account_response`).
- ✅ **Problem-document sanitization (§6.7; NIST SI-11):** internal-class errors
  (`Database`, `Common`, `ServerInternal`) now return a generic `"Internal server
  error"` detail with the real cause logged server-side, instead of echoing raw
  DB/SQLx text to the client. **Fixed:** the duplicate-key 500 above previously
  leaked `duplicate key value violates unique constraint "acme_accounts_jwk_thumbprint_key"`
  (schema/constraint names) in the problem `detail`. See `Error::client_detail`;
  client-class errors keep their descriptive detail. Tested
  (`internal_errors_do_not_leak_detail`, `client_errors_keep_descriptive_detail`).
  **Challenge errors (2026-10-26):** a failed challenge's stored `error` is now
  built by `challenge_error_document`
  ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 1017) from
  `Error::error_type()` and `Error::client_detail()`, so it carries a type
  registered in §6.7 and no internal text (previously always `unauthorized`
  with the raw error string). `Error::ChallengeValidation` and
  `Error::ChallengeFailed` (unregistered `challengeFailed`) were removed.
  Tested (`every_error_type_is_registered` in
  [error.rs](../../crates/ostrich-acme/src/error.rs),
  `challenge_error_document_only_emits_registered_types` and
  `challenge_error_document_uses_type_and_client_detail` in `rest.rs`)
- ✅ §7.3.2 - Account update
- ✅ §7.3.5 - Account key rollover (structure exists)

**Evidence:**

- [rest.rs:145](../../crates/ostrich-acme/src/rest.rs#L145) - Account creation
- [rest.rs:187](../../crates/ostrich-acme/src/rest.rs#L187) - Account updates

**Gaps:**

- ⚠️ Account deactivation endpoint not visible
- ⚠️ Account key rollover may need completion

---

#### §7.4: Applying for Certificate Issuance

**Status:** 🟢 **Compliant**

**Order Lifecycle:**

- ✅ §7.1.3 - Order status: pending → ready → processing → valid
- ✅ §7.4.1 - newOrder endpoint
- ✅ §7.4.2 - Authorization resource created
- ✅ §7.4 - Finalization performs real certificate issuance via CA gRPC service
- ✅ §7.4.2 - Certificate download returns issued PEM chain (`application/pem-certificate-chain`)
- ✅ §7.5.1 - Challenge validation

**Evidence:**

- [rest.rs:237](../../crates/ostrich-acme/src/rest.rs#L237) - Order creation
- [rest.rs:305](../../crates/ostrich-acme/src/rest.rs#L305) - Authorization handling
- [rest.rs:791](../../crates/ostrich-acme/src/rest.rs#L791) - Order finalization with CSR; issues certificate through `AcmeCaClient` (fails closed when CA integration is not configured — no fake certificates)
- [rest.rs:916](../../crates/ostrich-acme/src/rest.rs#L916) - Certificate download: order id → certificate_id → PEM chain from certificate store
- [ca_integration.rs](../../crates/ostrich-acme/src/ca_integration.rs) - CA gRPC client (`AcmeCaClient::finalize_order`) updates order with certificate id and "valid" status
- [services/acme-server/src/main.rs](../../services/acme-server/src/main.rs) - `CA_GRPC_URL` configuration; warns and fails finalization closed when absent. Since 2026-10-25 the CA channel is TLS 1.3 mTLS (`CA_GRPC_CLIENT_CERT_FILE`, `CA_GRPC_CLIENT_KEY_FILE`, `CA_GRPC_CA_CERT_FILE`, optional `CA_GRPC_SERVER_NAME`); `CA_GRPC_INSECURE` plaintext is refused in release builds

**Code References (Phase 11):**

- [validation.rs](../../crates/ostrich-acme/src/validation.rs) - Challenge validators (HTTP-01, DNS-01, TLS-ALPN-01)

---

#### §7.5: Identifier Validation Challenges

**Status:** 🟡 **Partial** (HTTP-01, DNS-01 and TLS-ALPN-01 functional; no CAA check, no DNSSEC validation in the TOE, no wildcard orders; POAM-2026-10-23-41, -49, -52. Updated 2026-10-26: DNS-01 was "implemented but non-functional")

**Challenges:**

- ✅ §8.3 - HTTP-01 Challenge (validator implemented)
- 🟡 §8.4 - DNS-01 Challenge: implemented and functional since 2026-10-26
  (branch `claude/dns01-resolver-fix`, uncommitted). Stays partial: no CAA
  check (RFC 8659), no DNSSEC validation (RFC 8555 §11.2) and wildcard
  identifiers are rejected (POAM-2026-10-23-41, -49)
- 🟡 §8.5 - TLS-ALPN-01 Challenge (RFC 8737; self-signed challenge cert
  accepted, acmeIdentifier digest verified; §3 critical-flag and single-SAN
  checks missing, POAM-2026-10-23-52)

**Implementation:**

- [crates/ostrich-acme/src/validation.rs](../../crates/ostrich-acme/src/validation.rs) - Validators

**Evidence:**

- ✅ HTTP-01: Fetch token from `http://<domain>/.well-known/acme-challenge/<token>`
- ✅ HTTP-01: Verify response = `<token>.<account_key_thumbprint>`
- ✅ **SSRF / DNS-rebinding prevention (SI-10):** HTTP-01 and TLS-ALPN-01 resolve
  the target, reject the validation if ANY resolved address is non-globally-
  routable (`is_disallowed_ip`: loopback, private, link-local, CGNAT, cloud
  metadata, IPv4-mapped, etc.), and **pin the connection to the validated
  address** (closing the rebinding TOCTOU window). HTTP-01 follows redirects
  MANUALLY so each redirect hop is re-resolved and re-validated. **Fixed:** the
  previous check only string-matched literal private-IP hostnames, so a public
  name resolving to an internal address bypassed it. Since 2026-10-26 a refusal
  is `rejectedIdentifier` with a generic detail; the resolved address is logged
  server-side only (test `resolve_pinned_enforces_ssrf_guard_unless_allowed`).
  Which names resolve to internal addresses can still be inferred from which
  challenges fail (POAM-2026-10-23-49)
- ✅ **Uniform allow-private policy:** the deploy-time `allow_private_ip_domains`
  override (dev/E2E or deliberately-internal deployments) is now honored by
  **both** HTTP-01 and TLS-ALPN-01 via a shared `resolve_pinned` helper.
  **Fixed:** TLS-ALPN-01 previously always called the strict resolver and
  ignored the flag, so an internal identifier that validated over HTTP-01 was
  refused over TLS-ALPN-01 ("resolves to non-public address … SSRF prevention").
- ✅ DNS-01 (§8.4): the TXT value is base64url(SHA-256(key authorization)),
  and the lookup is for `_acme-challenge.<domain>.`
- ✅ **DNS-01 resolver (2026-10-26):** `dns01_resolver_config`
  ([validation.rs](../../crates/ostrich-acme/src/validation.rs) line 511) uses
  the operator list `--dns01-resolvers` / `ACME_DNS01_RESOLVERS` (at most 8 IP
  literals, port 53, UDP with TCP fallback) or, when it is unset or `""`, the
  host's system resolver configuration. An empty name-server list, a
  system-configuration read error or an invalid list fails closed with a
  generic `serverInternal`; there is no fallback to a public resolver. Tests:
  `dns01_config_rejects_empty_name_servers`,
  `dns01_validate_fails_closed_without_name_servers`,
  `dns01_config_uses_upstreams_and_skips_system`,
  `dns01_validate_rejects_invalid_upstreams_without_fallback`
- ✅ **DNS-01 query name (RFC 8555 §7.1.4, RFC 1035 §2.3.1):**
  `dns01_query_name` (line 384) builds the name as an FQDN, so search domains
  and `ndots` cannot rewrite it (the system `domain` and `search` list are also
  dropped). The identifier must be an LDH name without a trailing dot (labels
  1-63 octets, no edge hyphens, non-numeric last label, wire length checked);
  wildcards, IP literals and anything else are `malformed` before any query.
  Tests: `dns01_query_name_is_fqdn`, `dns01_query_name_rejects_bad_identifiers`,
  `dns01_mock_trailing_dot_identifier_is_malformed`; fuzz target
  `fuzz_dns01_query_name`
- ✅ **DNS-01 TXT matching (§8.4, RFC 1035 §3.3.14):** a TXT record matches only
  if the concatenation of its character-strings equals the expected digest byte
  for byte (no case folding or trimming), and only records whose owner is the
  query name or a CNAME target reached from it in the same answer (at most 8
  hops, loops rejected) count (`txt_answers_match`, line 593). Tests:
  `txt_match_requires_concatenation_equal_to_digest`,
  `txt_match_requires_owner_on_cname_chain`,
  `txt_match_bounds_cname_chain_length`,
  `dns01_mock_split_strings_joining_to_digest_returns_true`,
  `dns01_mock_junk_and_digest_in_one_record_returns_false`,
  `dns01_mock_foreign_owner_txt_returns_false`,
  `dns01_mock_cname_delegated_txt_returns_true`,
  `dns01_mock_near_miss_digests_return_false`,
  `dns01_mock_wrong_thumbprint_returns_false`
- ✅ **DNS-01 retries (§8.2):** up to 5 rounds 2 s apart. NXDOMAIN, lookup errors
  and a non-matching answer are all retried; a fresh resolver with caching
  disabled (`cache_size` 0, positive and negative TTL 0, no hosts file) is
  built for each round, so an in-process cached negative answer is never
  reused. Tests: `dns01_opts_disable_caching`,
  `dns01_mock_retry_after_nxdomain_is_not_cached`,
  `dns01_mock_mismatch_then_match_returns_true`,
  `dns01_mock_persistent_nxdomain_fails_closed`. **Scope (RFC-005):** this
  covers only the resolver inside acme-server. The upstream recursor's own
  negative cache (RFC 2308) can still return an NXDOMAIN cached before the
  record was published; operators are told to cap it (ADMIN_GUIDE Section 3.7)
- ✅ **Challenge failure types (§6.7):** the challenge `error` type follows the
  failure (see the §7.3 sanitization item):

  | Challenge | Failure | Type |
  |-----------|---------|------|
  | all | Retrieved response or record does not match | `incorrectResponse` |
  | all | Identifier not usable (bad DNS name, URL or TLS server name) | `malformed` |
  | all | Local configuration error (resolver, HTTP client, TLS provider) | `serverInternal` (generic detail) |
  | http-01 | Connect, timeout or body read failure | `connection` |
  | http-01 | Non-2xx status; bad, missing or disallowed redirect | `incorrectResponse` |
  | http-01, tls-alpn-01 | Host does not resolve | `dns` |
  | http-01, tls-alpn-01 | Host resolves to a non-public address | `rejectedIdentifier` |
  | tls-alpn-01 | TCP connect failure or timeout | `connection` |
  | tls-alpn-01 | Handshake failure, `acme-tls/1` not negotiated, no or unparsable certificate | `tls` |
  | tls-alpn-01 | acmeIdentifier missing or malformed | `incorrectResponse` |
  | dns-01 | All 5 lookup rounds failed | `dns` |

- ℹ️ **RFC 8738 §7:** dns-01 MUST NOT be used for IP identifiers. The dns-01
  validator refuses IP literals (`malformed`), but `new_order` still offers
  dns-01 for IP identifiers (POAM-2026-10-23-49)
- ⚠️ **Gap: no CAA check (RFC 8659 §3).** Issuance does not check CAA
  records. `urn:ietf:params:acme:error:caa` is defined
  ([error.rs](../../crates/ostrich-acme/src/error.rs) line 135) but never
  raised, and the directory `caaIdentities` is always absent
  ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 496). When
  implemented, a DNS error during the CAA check must deny issuance
  (POAM-2026-10-23-41)
- ⚠️ **Gap: no DNSSEC validation (RFC 8555 §11.2).** hickory is built
  without its DNSSEC feature, and the AD bit is not checked. DNSSEC
  validation is delegated to the operator's validating recursive resolver,
  an operational-environment assumption (SECURITY_TARGET A.DNS_RESOLVER). The
  path from acme-server to that resolver is not authenticated (no TSIG or
  DoT) (POAM-2026-10-23-41)
- ⚠️ **Gap: wildcard identifiers** cannot be validated until `new_order` stores
  the base domain with `wildcard: true` (POAM-2026-10-23-49)
- ⚠️ No live dns-01 end-to-end test against a real DNS server; the offline
  tests use a loopback mock DNS server that drives the real hickory resolver

**Remediation:** add the CAA check; decide on in-process DNSSEC versus the
environment assumption; fix wildcard and IP-identifier handling in
`new_order`; add a live dns-01 integration test (POAM-2026-10-23-41, -49)

---

#### §6: Message Format and Transport

**Status:** 🟢 **Compliant**

**JWS (JSON Web Signature):**

- ✅ §6.2 - Request authentication via JWS
- ✅ §6.2 - Protected header with "alg", "nonce", "url"
- ✅ §6.2 - JWK or "kid" in protected header

**Implementation (Phase 11):**

- [crates/ostrich-acme/src/jws.rs](../../crates/ostrich-acme/src/jws.rs) - JWS parsing and validation

**Evidence:**

- ✅ JWS signature verification (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA)
- ✅ JWK thumbprint computation (RFC 7638)
- ✅ Nonce freshness verification
- ✅ URL binding validation

---

#### §9: IANA Considerations

**Status:** 🟢 **Compliant**

**Content Types:**

- ✅ application/jose+json for JWS requests
- ✅ application/pem-certificate-chain for certificate downloads

**Well-Known URI:**

- ✅ /.well-known/acme-challenge/ for HTTP-01

---

### RFC 8737: ACME TLS-ALPN-01 Challenge

**Status:** 🟡 **Partial** (corrected 2026-10-26, was "🟢 Implemented": the §3 certificate checks are incomplete, POAM-2026-10-23-52)

**Requirement:** TLS-ALPN-01 challenge validation

**Implementation:**

- [crates/ostrich-acme/src/validation.rs](../../crates/ostrich-acme/src/validation.rs) - `TlsAlpn01Validator`

**Evidence:**

- ✅ acmeIdentifier hash computation (SHA-256 of `<token>.<thumbprint>`)
- ✅ TLS client with ALPN `acme-tls/1`; verifies the server negotiated
  `acme-tls/1` and that the peer cert carries the `id-pe-acmeIdentifier`
  extension (OID 1.3.6.1.5.5.7.1.31) matching the expected hash.
- ✅ **Self-signed, critical-extension challenge cert accepted (RFC 8737 §3):**
  the validator uses a custom rustls `ServerCertVerifier` (`AcmeTlsAlpnCertVerifier`)
  that accepts the peer certificate and its CertificateVerify signature without
  any PKI/webpki parsing. Per §3 the acmeIdentifier extension MUST be critical,
  and rustls verifies both the chain and the CertificateVerify signature through
  `webpki`, which rejects a self-signed chain (`UnknownIssuer`) and unknown
  critical extensions (`UnsupportedCriticalExtension`). Control is proven by the
  connection reaching the identifier's `:443` and by the acmeIdentifier extension
  check after the handshake — not by the TLS certificate — so both webpki gates
  are bypassed (mirroring Boulder/Pebble). **Fixed:** TLS-ALPN-01 previously
  verified the peer cert against public `webpki-roots` and could never complete a
  handshake with a spec-compliant challenge cert. Tested
  (`tls_alpn_verifier_accepts_self_signed_challenge_cert`) and end-to-end via the
  in-cluster ACME smoke test.
- ✅ SSRF policy honors `allow_private_ip_domains` uniformly with HTTP-01 (see SI-10 above).
- ✅ **Bounds-checked acmeIdentifier parsing (2026-10-26):** `acme_identifier_digest`
  ([validation.rs](../../crates/ostrich-acme/src/validation.rs) line 1140)
  replaces an index slice that could panic the validation task on a 32- or
  33-octet extension value beginning `04 20`; a value that is neither
  `04 20` + 32 octets nor exactly 32 octets is `incorrectResponse`
  (test `acme_identifier_digest_is_bounds_checked`). Failure types: see the
  RFC 8555 §7.5 table.

**Gaps (POAM-2026-10-23-52):**

- ⚠️ §3: the acmeIdentifier extension MUST be critical; the validator does not
  check the critical flag
- ⚠️ §3: the certificate MUST contain exactly one dNSName SAN, equal to the
  identifier; the SAN is not checked
- ⚠️ The extension value is accepted either as a DER OCTET STRING
  (`04 20` + 32 octets) or as a bare 32-octet value; §3 requires the DER form

---

### RFC 7030: Enrollment over Secure Transport (EST)

**Status:** 🟢 **Enrollment working** (simpleenroll issues real certificates)

**Client identifier rule (2026-10-26, branch `claude/grpc-per-method-authz`,
uncommitted; RFC-104):** the CA now binds the EST requestor to the `est::`
namespace with a printable-ASCII id of at most 250 characters (255 bytes in
total). est-server applies the same rule (`ca_requestor` in
[ca_integration.rs](../../crates/ostrich-est/src/ca_integration.rs)) before
any enrollment row or CA call on `simpleenroll`, `simplereenroll` and
`serverkeygen`, and refuses other client ids with HTTP 403 (§4.2.3 permits an
error response for an unauthorised client), audited
`client_identifier_not_issuable`. The 403 body is the EST service's JSON
error object (`error: "forbidden"`, a fixed `error_description`), not a
PKCS#7 or CMC structure. Usernames with spaces or non-ASCII characters can no
longer enroll through the CA. Test: `ca_requestor_matches_ca_rule`.

**Live evidence (Phase 16):** an EST client (authenticated bearer session,
RaStaff role) POSTed a PKCS#10 CSR to `/.well-known/est/simpleenroll` and
received a `200 OK` PKCS#7 (RFC 5652 certs-only SignedData) containing the
issued certificate (subject `CN=est-client.example.com`, issuer
`CN=OstrichPKI EST Root`), which `openssl verify` accepts against the root.
`/.well-known/est/cacerts` returns the CA certificate as PKCS#7.

A public `GET /.well-known/est/catalog` endpoint
(`crates/ostrich-est/src/rest.rs`) publishes the profile-label scheme
(RFC 7030 §3.2.2) as discovery metadata — the valid `PT`/`AK` tokens, validity
and CC/S/A bounds, and example labels — sourced from `ostrich_est::label::catalog`
so it stays in lockstep with what `parse_label` accepts (SI-10). It backs the
NPE-portal "EST / enrollment catalog" page; it carries no certificate or key
material and requires no authentication.

The certs-only PKCS#7 encoder (RFC 5652 §5 degenerate `SignedData`) is now a
shared primitive, `ostrich_x509::pkcs7::encode_certs_only_pkcs7`
(`crates/ostrich-x509/src/pkcs7.rs`), used by both the EST responses above and a
management-API download endpoint `GET /api/v1/certificates/{id}/pkcs7`
(`crates/ostrich-ca/src/rest.rs`), which returns the leaf plus its issuing CA
certificate as a base64 `.p7b`. Per RFC 5652 §5.1 the `certificates` field is a
`SET OF`, so certificate order is not positional. NPE-portal certificate detail
offers PEM/DER/full-chain (derived client-side from the leaf PEM + CA chain) and
this PKCS#7 form. (Chain depth is currently the single issuing CA; a full chain
to the trust anchor is a POAM pending the CA holding its own issuer chain.)

The enrollment handlers now call the CA gRPC service via `EstCaClient`
(crates/ostrich-est/src/rest.rs, services/est-server/src/main.rs; since
2026-10-25 over TLS 1.3 mTLS, with plaintext, including the loopback
exception, refused in release builds) instead of returning an empty 202
placeholder; they fail closed when CA integration is
unconfigured. CSR proof-of-possession uses the stateless `verify_with_spki`
path (§4.2.1). Authorization bug fixed: chained `Router::route_layer` calls
stacked /simplereenroll's RenewCertificate check onto /simpleenroll, 403-ing
RaStaff enrollers; permission layers are now per-route (AC-3).

**Bearer-token bootstrap (§3.2.3, non-mTLS client auth):** operators may mint
single-use, time-limited enrollment tokens (`POST /api/v1/est/enrollment-tokens`,
`Permission::GenerateEstToken`). A device presents the token as
`Authorization: Bearer …` to `/simpleenroll` (or `/serverkeygen`); it resolves
to a least-privilege `EstEnrollee` principal whose identity is pinned by the
token, the §3.x identity binding (H1) forces the CSR CN/SAN to equal that
identity, and the token is consumed on first successful issuance (single-use).
Only the token's SHA-256 is stored. See `crates/ostrich-est/src/enrollment_token.rs`
and `migrations/00013_est_enrollment_tokens.sql`.

Token-management metadata endpoints (`GET/DELETE /api/v1/est/enrollment-tokens`)
are outside RFC 7030 but support the bootstrap extension operationally. NPE
Sponsor callers are scoped to tokens they created (`created_by`), while legacy CA
operator/admin token managers retain global review/revocation. This preserves the
RFC enrollment behavior while enforcing AC-3/AC-6 on the management API.

**Certificate-profile selection (§4.2):** when minting a token the operator may
pin the issuance profile the enrolled certificate is cut under, chosen from an
allowlist (`OFFERABLE_EST_PROFILES` = `tls_client`, `tls_server`,
`tls_server_client`) validated at mint time (SI-10) and persisted on the token
row (`profile` column). At enrollment `resolve_enroll_profile`
(crates/ostrich-est/src/rest.rs) reads the pinned profile, re-validates it
against the allowlist (fail-secure to the configured default if the allowlist
changed under a live token), and drives both `/simpleenroll` and `/serverkeygen`
issuance with it; session/mTLS enrollments keep the server default. The
`tls_server_client` profile carries both `serverAuth` and `clientAuth` EKU for
devices that act as both TLS client and server (registered in
`services/ca-server/src/main.rs` `default_profiles`).

Re-enrollment subject binding (RFC 7030 §4.2.2): `simplereenroll` now requires
the CSR subject to structurally match a certificate previously issued to the
same client (resolved from this client's prior issued enrollments, since the
EST server authenticates by account rather than mTLS). A mismatch — or a client
with no existing certificate to renew — is denied (403) and audited as an
AccessViolation. Structured DN comparison (`parse_csr_subject_dn` vs.
`parse_subject_dn`) avoids string-format false mismatches.

Server-side key generation (RFC 7030 §4.4): `/serverkeygen` is implemented. The
server parses the client's CSR for the requested subject/SANs, generates an
ECDSA P-256 key pair, builds a CSR signed by that key (so the CA verifies
proof-of-possession, RFC 2986), issues via the CA gRPC service, destroys the
server-held key handle (FCS_CKM.4), and returns an RFC 7030 §4.4.2
`multipart/mixed` response carrying the private key (`application/pkcs8`,
RFC 5958) and the certificate (`application/pkcs7-mime`, certs-only). The
private key is exported via `CryptoProvider::export_private_key` (software
provider only) and zeroized after the response is built.

**EFS delivery variant (RFC 7292 PKCS#12):** when the resolved profile is `efs`
(Microsoft Encrypting File System), `/serverkeygen` generates an RSA-2048 key
(Windows EFS requires RSA), and instead of the `multipart/mixed` PKCS#8 + PKCS#7
response it wraps the key and the issued certificate in an encrypted PKCS#12
(RFC 7292) built by `ostrich_x509::pkcs12::build_encrypted_pkcs12` — PBES2
(PBKDF2-HMAC-SHA256 + AES-256-CBC) shrouded key bag, HMAC-SHA256 integrity MAC,
matching `localKeyId` on both bags. The PKCS#12 is protected by a freshly
generated, CSPRNG-derived one-time password (~144 bits) returned exactly once in
the JSON response (`{format, certificateId, pkcs12, password}`) and never stored
server side (SC-12 key management, SI-12 sensitive-output handling). Builder
implementation: [crates/ostrich-x509/src/pkcs12.rs](../../crates/ostrich-x509/src/pkcs12.rs);
delivery path: [crates/ostrich-est/src/rest.rs](../../crates/ostrich-est/src/rest.rs)
`server_key_gen`.

For the portal EFS flow the request MAY instead be an `application/json` body
(`{sans, keyStrength}`) with no PKCS#10 CSR: the subject is taken from the
mTLS-authenticated identity rather than a client-supplied CSR, so no untrusted
ASN.1 is parsed and no throwaway client key is generated (attack-surface
reduction; SI-10 input validation — requested SANs are still checked against the
caller's allowlist). The RFC 7030 §4.4.1 base64-CSR input remains supported for
standard EST clients. The EFS profile is reached via the `PTEFS` label
(`ParsedLabel::profile_name`).

**Live full-stack proof:** [tests/integration/est_serverkeygen_e2e.rs](../../tests/integration/est_serverkeygen_e2e.rs)
spins up the CA gRPC service (SoftHSM-backed) and the EST HTTP server in-process,
POSTs a CSR to `/.well-known/est/serverkeygen` over real HTTP, and verifies with
`openssl` that the returned PKCS#8 private key's public key matches the public
key of the returned (PKCS#7) certificate — i.e. the server delivered a key pair
plus a CA-issued certificate for it, end to end.

**Sections:**

#### §3.1: EST Functions

**Functions:**

- ✅ §3.2.2 - CA Certificates (/cacerts)
- ✅ §3.3.1 - Simple Enrollment (/simpleenroll)
- ✅ §3.3.2 - Simple Re-enrollment (/simplereenroll)
- ✅ §3.4 - Server-Side Key Generation (/serverkeygen) - implemented (ECDSA P-256; CSR-based PoP; PKCS#8 + PKCS#7 multipart per §4.4.2; EFS profile → RSA-2048 delivered as an encrypted PKCS#12 (RFC 7292) with a one-time password)

**Implementation:**

- [crates/ostrich-est/src/rest.rs](../../crates/ostrich-est/src/rest.rs) - EST endpoints

**Evidence:**

- [rest.rs:50-63](../../crates/ostrich-est/src/rest.rs#L50-L63) - cacerts endpoint
- [rest.rs:72-103](../../crates/ostrich-est/src/rest.rs#L72-L103) - simpleenroll endpoint
- [rest.rs:107-141](../../crates/ostrich-est/src/rest.rs#L107-L141) - simplereenroll endpoint
- [serverkeygen.rs](../../crates/ostrich-est/src/serverkeygen.rs) + [rest.rs](../../crates/ostrich-est/src/rest.rs) `server_key_gen` - server-side key generation (RFC 7030 §4.4)

---

#### §3.2.3: Client Authentication

**Status:** 🟢 **Compliant** (TLS client certificate + HTTP Basic)

**Requirement:** RFC 7030 §3.2.3 - the EST server authenticates the client by a
TLS client certificate (§3.3) and/or by HTTP-based client authentication, which
the server MAY request "in addition to or instead of" the TLS client
certificate.

**Implementation:** the EST server selects a client-authentication mode for the
protected enrollment endpoints (`EstAuthMode`):

- **mTLS (§3.3):** the verified TLS client certificate is mapped to an account
  (`MtlsAuthLayer`). Default when a TLS client CA (`--tls-ca-cert`) is set.
- **mTLS + HTTP Basic fallback (§3.2.3):** the verified client certificate is
  preferred; when no client certificate is presented, the request must carry
  `Authorization: Basic` (`MtlsOrBasicAuthLayer`). Enabled with
  `--allow-basic-auth` (requires `--tls-ca-cert`; rejected otherwise, since
  Basic transmits a reusable password and is only safe on a TLS listener). This
  is intended for **bootstrap enrollment** — a client without a certificate
  authenticates its first enrollment with a username/password, then uses mTLS.
- **mTLS + bearer enrollment-token bootstrap (§3.3):** the verified client
  certificate is preferred (`MtlsOrBearerAuthLayer`); when none is presented, a
  single-use bearer enrollment token bootstraps the first enrollment. Enabled
  with `--mtls-token-bootstrap`. This is the shared-port re-enrollment posture:
  a device bootstraps with a token, then **re-enrolls over mTLS with the
  certificate it was issued**. Because such a device has no provisioned
  user-table account, `EstDeviceCertAuthProvider` recognises its presented
  certificate by an exact DER match against the certificate store, confirms it
  is neither revoked nor expired, resolves it back to the `client_identifier` of
  the enrollment that produced it, and authenticates it as a least-privilege
  `EstDevice` principal (sole permission `RenewCertificate`). Unrecognised
  certificates fall through to account mapping, so operator certificates keep
  working. This is what makes `/simplereenroll` return `200` for a freshly
  bootstrapped device (RFC 7030 §3.3).
- **Bearer session token:** non-RFC backward-compatibility fallback when no TLS
  client CA is configured.

Basic credentials are verified through the same `AuthProvider` used for password
login (Argon2id, account lockout / AC-7), and a failed/missing Basic challenge
returns `401` with `WWW-Authenticate: Basic realm="EST"` (RFC 7235 §4.1). On
success the resolved identity flows through the same RBAC permission checks
(`AuthzLayer`) as mTLS.

**Implementation:**

- [crates/ostrich-common/src/auth/basic.rs](../../crates/ostrich-common/src/auth/basic.rs) - `BasicAuthLayer`, `MtlsOrBasicAuthLayer`
- [crates/ostrich-common/src/auth/middleware.rs](../../crates/ostrich-common/src/auth/middleware.rs) - `MtlsOrBearerAuthLayer` (cert-preferred, bearer-token bootstrap fallback)
- [crates/ostrich-est/src/device_cert.rs](../../crates/ostrich-est/src/device_cert.rs) - `EstDeviceCertAuthProvider` (re-enrollment by existing CA-issued certificate)
- [crates/ostrich-est/src/rest.rs](../../crates/ostrich-est/src/rest.rs) - `EstAuthMode` + protected-route layer selection
- [services/est-server/src/main.rs](../../services/est-server/src/main.rs) - `--allow-basic-auth`, `--mtls-token-bootstrap`, composite provider, TLS-only guard

**Evidence:**

- Unit tests: [crates/ostrich-common/src/auth/basic.rs](../../crates/ostrich-common/src/auth/basic.rs) `mod tests` - valid/invalid credentials, missing header → challenge, malformed base64, missing colon, locked account → 403, RFC 7617 first-colon split
- Unit test: [crates/ostrich-common/src/auth/permissions.rs](../../crates/ostrich-common/src/auth/permissions.rs) `test_est_device_permissions` - `EstDevice` grants exactly `RenewCertificate` (AC-6 least privilege), unblocking `/simplereenroll`

---

#### §3.2: PKCS#7 Encoding

**Status:** 🟢 **Compliant** (Phase 15)

**Requirement:** EST responses use PKCS#7 ContentInfo (RFC 7030 §4.1.3, RFC 5652 §5)

**Implementation:**

- [rest.rs:165-221](../../crates/ostrich-est/src/rest.rs#L165-L221) - encode_certs_only_pkcs7() helper
- [rest.rs:146](../../crates/ostrich-est/src/rest.rs#L146) - PKCS#7 for CA certs (/cacerts)
- [rest.rs:294](../../crates/ostrich-est/src/rest.rs#L294) - PKCS#7 for enrollment response (/simpleenroll)
- [rest.rs:391](../../crates/ostrich-est/src/rest.rs#L391) - PKCS#7 for re-enrollment response (/simplereenroll)
- [ca_integration.rs:295-296](../../crates/ostrich-est/src/ca_integration.rs#L295-L296) - PKCS#7 for certificate retrieval

**Content-Type:**

- ✅ application/pkcs7-mime for responses

**Test Coverage:**

- [rest.rs:580-600](../../crates/ostrich-est/src/rest.rs#L580-L600) - PKCS#7 encoding validation

---

#### §3.6: Mutual TLS Authentication

**Status:** 🟢 **Implemented**

**Requirement:** EST server MUST authenticate clients via TLS client certificates

**Implementation:**

- [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - the TLS listener requires a client certificate when a client CA is configured (`WebPkiClientVerifier`), and a custom axum-server `Accept` surfaces the verified certificate to handlers as a `PeerCertificate` request extension.
- [crates/ostrich-common/src/auth/middleware.rs](../../crates/ostrich-common/src/auth/middleware.rs) - `MtlsAuthLayer` authenticates the request by that certificate via the certificate `AuthProvider`, mapping the subject to an account and injecting the `AuthenticatedUser` (so the same RBAC permission checks apply).
- [crates/ostrich-common/src/auth/mtls.rs](../../crates/ostrich-common/src/auth/mtls.rs) - `CertificateAuthProvider`; [crates/ostrich-db/src/repository/users.rs](../../crates/ostrich-db/src/repository/users.rs) - `DbUserRepository: CertificateUserRepository` (subject → account via `certificate_subject`).
- [services/est-server/src/main.rs](../../services/est-server/src/main.rs) - selects mTLS authentication when `--tls-ca-cert` is configured; EST router applies `MtlsAuthLayer` (`EstState::with_mtls_auth`).

**Evidence:**

- ✅ TLS server requires + verifies client certificates (WebPkiClientVerifier)
- ✅ Verified client certificate extracted from the TLS connection and surfaced to handlers
- ✅ Certificate subject mapped to an account; request authenticated as that user
- ✅ **Live proof:** [tests/integration/mtls_peercert_e2e.rs](../../tests/integration/mtls_peercert_e2e.rs) — over real TLS, the handler receives the verified client certificate's subject, and a connection without a client certificate is rejected at the handshake.

---

### RFC 8295: EST Extensions (CSR Attributes)

**Status:** 🟡 **Partial**

**Endpoint:** /csrattrs

**Implementation:**

- [crates/ostrich-est/src/rest.rs](../../crates/ostrich-est/src/rest.rs) - CSR attributes parsing

**Evidence:**

- ⚠️ CSR attributes parsing incomplete (line 76-79 comments)

**Gaps:**

- CSR attribute response not fully implemented

**Remediation:** Phase 16 - Complete CSR attributes endpoint

---

## Cryptographic Message Syntax

### RFC 5652: Cryptographic Message Syntax (CMS)

**Status:** 🟡 **Partial** (Phase 8 dependent)

**Usage:**

- PKCS#7 for EST responses (CMS is PKCS#7 v1.5+)
- Certificate chains
- Signed data

**Implementation:**

- Phase 8 implementation for PKCS#7 encoding

**Sections:**

- ✅ §3 - General Syntax (ContentInfo)
- ✅ §5 - Signed-data Content Type
- ⚠️ §6 - Enveloped-data (not used in current scope)

**Evidence Required:** Phase 14 - Verify CMS structures parse correctly with OpenSSL

---

### RFC 6268: Additional New ASN.1 Modules for CMS

**Status:** ⚪ **Not Applicable** (optional enhancements)

**Features:**

- Additional algorithm identifiers
- Algorithm parameter structures

---

### RFC 8933: CMS Algorithm Identifier Protection Attribute

**Status:** ⚪ **Not Applicable** (optional security enhancement)

**Feature:** Protects algorithm identifiers from substitution attacks

**Consideration:** Evaluate for Phase 16 security hardening

---

## Key Management

### RFC 5958: Asymmetric Key Packages

**Status:** 🟡 **Partial**

**Usage:** PKCS#8 format for private key storage/transport

**Implementation:**

- Used in KRA for key escrow
- Used for EST server-side key generation (when implemented)

**Evidence:**

- ✅ PrivateKeyInfo structure support in crypto libraries
- ⚠️ Encrypted PrivateKeyInfo for EST §4.3 pending

---

### RFC 7292: PKCS #12: Personal Information Exchange Syntax

**Status:** ⚪ **Not Applicable** (not in scope)

**Usage:** Client certificate bundles with private keys

**Note:** OstrichPKI is server-side; PKCS#12 is client responsibility

---

### RFC 5915: Elliptic Curve Private Key Structure

**Status:** 🟢 **Compliant**

**Usage:** EC private key format

**Implementation:**

- Handled by crypto libraries (ring, RustCrypto)

---

## Transport Security

### RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3

**Status:** 🟡 **Partial** (REST listeners, internal HTTPS clients and, since 2026-10-25, the CA gRPC channel use TLS 1.3; no deployed-endpoint scan; no peer revocation checking)

**Requirement:** All administrative and inter-service communication uses TLS 1.3

**Implementation:**

- [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - shared listener for all service binaries: **rustls 0.23.46** with the aws-lc-rs FIPS provider selected explicitly, **TLS 1.3 only** (`with_protocol_versions(&[&TLS13])`), and optional or mandatory mTLS via `WebPkiClientVerifier`
- `services/web-ui/src/server/backend_client.rs`, `services/npe-portal/src/server/backend_client.rs` - internal HTTPS clients on the same provider
- CA gRPC (2026-10-25, branch `claude/grpc-mtls`, uncommitted): tonic is built with `features = ["channel"]` only; [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) builds the server and client configs on the aws-lc-rs FIPS provider, TLS 1.3 only, client certificate mandatory (§4.3.2 CertificateRequest; §4.4.2 client Certificate), ALPN `h2` only (RFC 7301; gRPC over HTTP/2, RFC 9113), `fips()` asserted. A connection that completes the handshake without `h2` gets a best-effort `close_notify` (§6.1, 1 s bound) before it is dropped, on server and client. Corrected: before this change the gRPC server was plaintext and the clients used tonic `tls-ring` with TLS 1.2 allowed

**Evidence:**

- ✅ TLS 1.3 minimum enforced in application code. Test `server_rejects_tls12_only_client` passed (2026-10-23)
- ✅ mTLS implemented: mandatory by default, optional for bootstrap. Tests `mtls_handshake_accepts_trusted_client`, `mtls_handshake_rejects_missing_client_cert` and `optional_mtls_allows_anonymous_but_rejects_untrusted` passed (2026-10-23)
- ✅ rustls 0.23.46 (2026-10-23) fixes RUSTSEC-2026-0285 (handshake messages accepted across encryption-level boundaries), RUSTSEC-2026-0349 (unauthenticated ServerHello downgrade to classical key exchange) and RUSTSEC-2026-0348 (pre-authentication certificate-decompression allocation). These fixes tighten conformance with §5.1, §4.4.2, §4.1.3, §4.1.4 and §5.5
- ℹ️ **Signature algorithms (§4.2.3):** since rustls 0.23.46 the aws-lc-rs provider also advertises and verifies ML-DSA-44/65/87 (draft-ietf-tls-mldsa code points 0x0904–0x0906) under `fips`. Accepted by the user 2026-10-23
- ℹ️ Key exchange: the provider's `fips`-filtered default groups (`default_kx_groups()` keeps only groups whose `fips()` is true); the resulting group list was not re-verified in this review
- ✅ CA gRPC (2026-10-25): `grpc_mtls_e2e` 21/21 passed (final code; incl. `no_alpn_refusal_sends_close_notify`): `tls12_client_rejected`, `no_client_cert_handshake_fails`, `non_h2_alpn_client_rejected`, `x25519_only_client_rejected`, `p384_chain_end_to_end_with_fips_hybrid_group` (negotiated group `SECP256R1MLKEM768` and `conn.fips()` asserted), `server_and_client_configs_report_fips`. gRPC groups (§4.2.7): SECP256R1MLKEM768, X25519MLKEM768, secp256r1, secp384r1
- ⚠️ **Deviation (CA gRPC client):** `CA_GRPC_SERVER_NAME` overrides the name used for the server-certificate check, independent of the HTTP/2 `:authority` the client sends. The certificate check is then decoupled from `:authority`; this is a deliberate operator override for service names that are not in the URL

**Cipher suites in effect (`fips` feature; NIST SP 800-52 Rev 2):**

- TLS_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_CHACHA20_POLY1305_SHA256 is **not offered**: rustls removes it under `fips`. Corrected 2026-10-23: the list here previously included it

**Gaps:**

- No TLS scan of a deployed endpoint
- No revocation checking of TLS peer certificates (see RFC 5280 §6)

**Remediation:** capture a deployment TLS scan; add revocation checking for TLS peers (POAM-2026-10-23-27). (gRPC TLS on the aws-lc-rs provider: done 2026-10-25 in the working tree)

---

### RFC 9325: Recommendations for Secure Use of TLS and DTLS

**Status:** 🟡 **Partial**

**Recommendations:**

- ✅ Use TLS 1.3: the shared listener is TLS 1.3 only (`crates/ostrich-common/src/tls.rs`)
- ✅ TLS 1.2 and earlier refused by the shared listener (test `server_rejects_tls12_only_client`, 2026-10-23). Corrected 2026-10-23: this item previously said "not explicitly configured"
- ✅ Strong AEAD suites only: AES-GCM under `fips` (see RFC 8446 above)
- ✅ Certificate-based authentication for mTLS: implemented and tested (see RFC 8446 above), including the CA gRPC channel since 2026-10-25 (TLS 1.3 only, AEAD only, `grpc_mtls_e2e` 21/21)
- 🔴 TLS peer certificate revocation not checked (REST and gRPC; POAM-2026-10-23-27)

**Remediation:** add revocation checking for TLS peers. Corrected 2026-10-25: "configure gRPC TLS" is done in the working tree

---

### gRPC over HTTP/2 (RFC 9113): CA gRPC authorization and status semantics (2026-10-26)

Branch `claude/grpc-per-method-authz`, uncommitted. gRPC status codes are
defined by the gRPC protocol specification, not an RFC; the transport is
HTTP/2 (RFC 9113).

- ✅ **Method matching:** the authorization layer matches the HTTP/2
  `:path` exactly (case-sensitive, no percent-decoding or segment
  normalisation) against `CA_GRPC_METHOD_RULES`
  ([grpc_authz.rs](../../crates/ostrich-ca/src/grpc_authz.rs)), which agrees
  with tonic routing. Query strings are not an authorization input (they do
  not affect tonic routing either). Default deny: every path without a rule
  is refused before the service runs
- ✅ **Denials are trailers-only responses** written after the audit record
- ✅ **Status mapping:** no verified certificate → `UNAUTHENTICATED`
  "client certificate required"; an unparsable leaf or a leaf outside its
  validity at call time → `UNAUTHENTICATED` "client certificate not
  accepted"; every authorization failure → `PERMISSION_DENIED` "client is not
  authorised for this call" (a profile refusal: "certificate profile is not
  permitted for this client"). Non-client-correctable server errors →
  `INTERNAL` "<op> failed: internal error"
- ⚠️ **Deviation (RFC-003):** an unknown or unmapped method returns
  `PERMISSION_DENIED` (`method_not_mapped`), not `UNIMPLEMENTED`, so that
  callers cannot enumerate methods
- ⚠️ **Deviation (RFC-004):** a malformed `requestor` (empty for an issuer,
  wrong namespace, non-printable-ASCII id or more than 255 bytes) returns
  `PERMISSION_DENIED`, not `INVALID_ARGUMENT`: the requestor is the caller's
  authorization claim, so all rejections share one deny path
- Tests: `authorize_peer_method_matrix`,
  `qa_authorize_peer_non_canonical_paths_are_not_mapped`,
  `authorize_peer_decisions`, `grpc_status_hides_internal_errors`; e2e
  `qa_unmapped_path_variants_denied_over_the_wire`, `unknown_method_denied`
  (`grpc_mtls_e2e` 39/39, coder-reported)

---

### Dependency protocol conformance fixes (2026-10-23)

Lockfile updates that fix advisories in protocol implementations (see NIST SI-2):

- RFC 9113 (HTTP/2): h2 0.4.15 → 0.4.20 (RUSTSEC-2026-0258, unbounded empty DATA frames)
- RFC 9000 (QUIC): quinn-proto 0.11.15 → 0.11.19 (RUSTSEC-2026-0338 to 0342). Target-specific transitive dependency
- RFC 1951 (DEFLATE): zip 2.4.2 → 9.0.5 with the zlib-rs backend for bulk-enrollment ZIP reading. Inflate is bounded per entry (tests `extract_csr_entries_rejects_deflate_bomb` and `extract_csr_entries_rejects_corrupt_deflate_and_bad_crc`)

---

### Dependency protocol conformance fixes (2026-10-26)

Lockfile update (branch `claude/dependabot-remediation`, uncommitted; see NIST SI-2):

- RFC 1035 / RFC 8555 §8.4 (DNS, ACME dns-01): hickory-resolver, hickory-net and hickory-proto 0.26.1 → 0.26.2. hickory is used only by the dns-01 TXT lookup in [validation.rs](../../crates/ostrich-acme/src/validation.rs) (default features `system-config` and `tokio`; no DNSSEC or `recursor` feature). Reachability in this build:
  - GHSA-6w6g-hm98-mhgm (unbounded truncation retry): reachable through the applicant-controlled zone. The retry is now bounded, the lookup returns an error, and the challenge fails closed
  - GHSA-5j98-2g5x-46v6 (DNSSEC failures hidden): not reachable; needs the DNSSEC feature, which is not enabled
  - GHSA-6f2x-v7q7-m7m5 (irrelevant CNAME records followed): not reachable; the fix is in the `recursor` module, which is not enabled. Stub-resolver CNAME handling is unchanged, so `_acme-challenge` CNAME delegation behaves as before
- Other changes in the bump are neutral or improve conformance: answers with the wrong DNS class are rejected, compressed names are decoded without recursion, and the TXT parsing API used by the validator is unchanged
- This bump does not make dns-01 work: the resolver has no name servers (POAM-2026-10-23-41, pre-existing). **Update 2026-10-26:** fixed by the dns-01 resolver change (branch `claude/dns01-resolver-fix`, uncommitted); see RFC 8555 §7.5. POAM-41 stays open, narrowed to CAA, DNSSEC and the other residuals

### RFC 3986: URI path handling in the BFF proxies (web-ui and npe-portal, 2026-10-26)

web-ui: commit e56a09e, merged by PR #191 (see NIST SI-10; POAM-2026-10-23-43
closed pending first green CI run). npe-portal: branch
`claude/npe-portal-proxy-raw-path`, uncommitted (POAM-2026-10-23-46 closed
pending first green CI run). Both proxies forward `/api/{svc}/...` requests to
the backends, and both now treat the path as RFC 3986 data instead of using
axum's decoded capture. The rules below are implemented by the canonical shared
module [proxy_path.rs](../../crates/ostrich-common/src/util/proxy_path.rs)
(`ostrich_common::util::proxy_path`), which npe-portal calls from
`checked_backend_path` in
[proxy.rs](../../services/npe-portal/src/server/proxy.rs). web-ui still runs
an identical local copy in
[proxy.rs](../../services/web-ui/src/server/proxy.rs); switching it to the
shared module is a follow-up.

- §2.1 percent-encoding: `percent_decode_segment` decodes strictly. A `%`
  not followed by two hex digits is refused. Decoding is only used to check
  each segment; the backend receives the original, still-encoded bytes, so the
  encoding is not changed in transit (no decode-then-re-encode)
- §3.3 path segments: a segment that decodes to `/`, `?`, `#` or `\` is
  refused, so an encoded delimiter cannot change the request target. Empty
  segments are refused too. This is stricter than RFC 3986, which allows empty
  segments; as a result a trailing slash now gets 400
- §5.2.4 dot segments: literal or encoded `.` and `..` segments are refused
  rather than removed, so the proxy never resolves a relative reference on the
  client's behalf. `...` and `..a` are not dot segments and are forwarded
- Not checked: the query (§3.4) is appended verbatim; double encoding
  (`%252F`) is forwarded as is; decoded octets >= 0x80, including overlong
  UTF-8, are not validated (RFC 3986 defines no UTF-8 rule for them); `;`
  path parameters (`..;`) are forwarded. These residuals are the same in
  both proxies. In npe-portal, an empty remainder (`/api/ca/`) is answered
  404 by the axum router and is not proxied
- Evidence: the 17 `proxy_path` unit tests check all 256 single-byte escapes
  against these rules. The fuzz target `fuzz_proxy_path` ran 259,220 runs with
  no crash. npe-portal router tests show 400 and zero backend hits for unsafe
  paths, and verbatim forwarding of the raw path and query (local;
  TEST_EVIDENCE.md §2.15)

---

## Post-Quantum Cryptography (Draft RFCs)

### RFC 9881 (formerly draft-ietf-lamps-dilithium-certificates): ML-DSA in X.509

**Status:** 🟡 **Partial** — verification only (TLS peer certificates); issuance disabled

**Implementation:**

- [crates/ostrich-common/src/oid.rs:74](../../crates/ostrich-common/src/oid.rs#L74) - ML-DSA OID placeholder
- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm enum includes ML-DSA variants
- [crates/ostrich-x509/src/signing.rs](../../crates/ostrich-x509/src/signing.rs) - id-ml-dsa-44/65/87 OIDs (2.16.840.1.101.3.4.3.17/.18/.19, parameters absent), reserved

**Evidence:**

- ✅ Algorithm types defined (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- 🟡 **Verification (since 2026-10-23):** rustls-webpki 0.103.16 on aws-lc-rs 1.18.2 (`fips`, AWS-LC FIPS 4.2.0) verifies ML-DSA-44/65/87 certificate signatures during TLS peer path building. This is upstream behaviour, accepted by the user on 2026-10-23. No OstrichPKI test exercises it
- 🔴 **Issuance:** ML-DSA certificate, CRL and OCSP signing is disabled (`crates/ostrich-x509/src/secure_defaults.rs`)

**Remediation:**

- POA&M: enable ML-DSA issuance once CMVP confirms the AWS-LC FIPS 4.2.0 module (see FIPS_COMPLIANCE.md)
- Add an ML-DSA chain test when issuance is enabled

---

### draft-ietf-lamps-kyber-certificates: ML-KEM in X.509

**Status:** 🟢 **Partial** — FIPS 203 KEM operations implemented; X.509
SubjectPublicKey/OID encoding pending.

**Implementation:**

- [crates/ostrich-crypto/src/kem.rs](../../crates/ostrich-crypto/src/kem.rs) - ML-KEM-512/768/1024 KeyGen/Encaps/Decaps and raw `ek`/`dk` (the values the draft's SubjectPublicKey/private-key carry)
- [crates/ostrich-common/src/oid.rs:80](../../crates/ostrich-common/src/oid.rs#L80) - ML-KEM OID placeholder

**Evidence:** the raw `ek` exported by `public_key_bytes()` is the exact
SubjectPublicKey body OpenSSL 3.6 emits/consumes for ML-KEM — confirmed by
splicing it into an OpenSSL SPKI for bidirectional interop
([tests/integration/mlkem_openssl_interop.rs](../../tests/integration/mlkem_openssl_interop.rs)).

**Usage:** Key encapsulation for KRA transport keys, hybrid TLS

**Remediation:** wrap raw `ek`/`dk` in the draft's SPKI/PKCS#8 with the NIST
`id-alg-ml-kem-*` OIDs (2.16.840.1.101.3.4.4.1–3) for X.509 certificate use.

---

### draft-ietf-pquip-hybrid-signature-spectrums: Hybrid Signatures

**Status:** 🟡 **Designed** (not implemented)

**Concept:** Certificates with both classical and PQC signatures

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Hybrid algorithm types defined

**Example:** `EcdsaP256_MlDsa44` for dual signature

**Remediation:** Phase 13 - Implement hybrid certificates for transition period

---

## RFC Compliance Summary

| RFC Category | RFCs Covered | Compliant 🟢 | Partial 🟡 | Missing 🔴 | N/A ⚪ | Compliance % |
|--------------|--------------|-------------|-----------|-----------|--------|--------------|
| Core PKI (X.509) | 5 | 5 | 0 | 0 | 0 | 100% |
| Certificate Status | 4 | 2 | 2 | 0 | 0 | 75% |
| Enrollment (ACME) | 2 | 0 | 2 | 0 | 0 | 50% |
| Enrollment (EST) | 2 | 0 | 2 | 0 | 0 | 70% |
| Cryptography (CMS) | 3 | 0 | 1 | 0 | 2 | 50% |
| Key Management | 3 | 2 | 1 | 0 | 0 | 83% |
| Transport (TLS) | 2 | 0 | 2 | 0 | 0 | 50% |
| Post-Quantum (Draft) | 3 | 0 | 3 | 0 | 0 | 30% |
| **TOTAL** | **24** | **9** | **13** | **0** | **2** | **70%** |

Recalculated 2026-10-26 (RFC 8737 🟢 → 🟡, POAM-2026-10-23-52) with the rule
the Core PKI, Certificate Status, CMS, Key Management and Transport rows
follow: Compliance % = (Compliant + 0.5 × Partial) / (RFCs − N/A). ACME row:
(0 + 0.5 × 2) / 2 = 50% (the 90% shown before did not follow that rule:
(1 + 0.5 × 1) / 2 = 75%). TOTAL: (9 + 0.5 × 13) / (24 − 2) = 15.5 / 22 =
70.5%, shown as 70% (the 75% shown before did not match its own counts:
(10 + 0.5 × 12) / 22 = 72.7%). The EST and Post-Quantum rows still do not
follow the rule and were not changed. This table is not an assessed
compliance figure.

---

## Critical Gaps Requiring Remediation

### Priority 1 (Mandatory, Blocking)

1. **RFC 5280 §4.1.1.2 - Random Serial Numbers** (🔴 Critical)
   - Impact: Predictable serial numbers (security risk)
   - Phase: 16 (DRBG implementation)
   - Effort: 2-3 days

2. **RFC 7030 §3.6 - EST mTLS** (🟢 Implemented)
   - EST client authentication is enforced on the protected enrollment
     endpoints: mTLS client certificate (§3.3), or mTLS with an HTTP Basic
     fallback for bootstrap enrollment (§3.2.3). See §3.2.3 above.
   - Phase: 16

### Priority 2 (Important, Non-blocking)

1. **RFC 8446 - TLS 1.3 Configuration** (🟡 Partial)
   - REST listeners and internal HTTPS clients: TLS 1.3 only with mTLS (done; tested 2026-10-23)
   - CA gRPC channel: TLS 1.3 mTLS on the aws-lc-rs provider (done 2026-10-25, uncommitted; `grpc_mtls_e2e` 21/21)
   - Remaining: revocation checking of TLS peers (POAM-2026-10-23-27); deployment TLS scan
   - Corrected 2026-10-23: this item previously said "Weak TLS configuration possible", which no longer describes the REST listeners

2. **RFC 8555 - ACME Challenge Validators** (🟡 Partial)
   - Impact: no CAA check (RFC 8659) and no DNSSEC validation in the TOE (RFC 8555 §11.2) (POAM-2026-10-23-41); wildcard orders and dns-01 offered for IP identifiers (POAM-2026-10-23-49); RFC 8737 §3 certificate checks incomplete (POAM-2026-10-23-52)
   - Updated 2026-10-26: DNS-01 is functional (resolver built from `ACME_DNS01_RESOLVERS` or the system configuration; fails closed with no name servers). It was previously listed here as not functional
   - Corrected 2026-10-26: this item previously also listed TLS-ALPN-01, which was fixed by commits 5b1a034 (self-signed challenge certificate accepted, RFC 8737) and 5e8ab3f (critical acmeIdentifier extension accepted)
   - Phase: 16
   - Effort: 1 week

3. **RFC 6960 - OCSP Delegated Signing** (⚪ Optional)
   - Impact: CA signing key used for all OCSP responses
   - Phase: 13
   - Effort: 3-5 days

---

## Testing & Verification

### Interoperability Testing

For each RFC, conduct interoperability testing with standard tools:

**RFC 5280 (X.509):**

```bash
# Verify certificate with OpenSSL
openssl x509 -in cert.pem -text -noout
openssl verify -CAfile ca.pem cert.pem

# Verify CRL
openssl crl -in crl.pem -text -noout
```

**RFC 6960 (OCSP):**

```bash
# Test OCSP responder
openssl ocsp -issuer ca.pem -cert cert.pem -url http://ocsp.example.com -resp_text
```

**RFC 8555 (ACME):**

- Use certbot for end-to-end ACME testing
- Use Pebble (Let's Encrypt test server) for validation
- Test with acme.sh client

**RFC 7030 (EST):**

- Use libest client for EST testing
- Use Cisco EST client for interoperability
- Test with OpenSSL EST commands

### Conformance Testing Tools

- **X.509**: NIST PKITS (Public Key Interoperability Test Suite)
- **ACME**: Boulder (Let's Encrypt CA software) test cases
- **TLS**: TLS-Attacker, testssl.sh
- **OCSP**: OCSP test vectors

---

## Trust Anchor Management

### RFC 5934: Trust Anchor Management Protocol (TAMP)

**Status:** 🟢 **Implemented (manager / authority role)**

OstrichPKI implements the TAMP **manager** role: it composes, CMS-signs, and
distributes trust-anchor management messages to remote cryptographic modules,
and verifies and records the targets' signed confirmations and status
responses. The crate is `ostrich-tamp`; the service is `ostrich-tamp-server`.

**Implementation:**

- [crates/ostrich-tamp/src/asn1.rs](../../crates/ostrich-tamp/src/asn1.rs) -
  DER message structures (App. A.1): all message types and `TrustAnchorChoice`.
- [crates/ostrich-tamp/src/oids.rs](../../crates/ostrich-tamp/src/oids.rs) -
  `id-tamp` content-type arc (`2.16.840.1.101.2.1.2.77`) and attribute OIDs.
- [crates/ostrich-tamp/src/statuscode.rs](../../crates/ostrich-tamp/src/statuscode.rs) -
  full `StatusCode` ENUMERATED (§5).
- [crates/ostrich-tamp/src/cms.rs](../../crates/ostrich-tamp/src/cms.rs) -
  CMS `SignedData` protection (§2.2): one SignerInfo, subjectKeyIdentifier sid,
  `content-type` + `message-digest` signed attributes.
- [crates/ostrich-tamp/src/manager.rs](../../crates/ostrich-tamp/src/manager.rs) -
  message composition and the update state machine (§4).
- [crates/ostrich-db/src/repository/tamp.rs](../../crates/ostrich-db/src/repository/tamp.rs)
  and [migrations/00014_tamp_trust_anchor_store.sql](../../migrations/00014_tamp_trust_anchor_store.sql) -
  durable trust-anchor store and per-signer sequence numbers (§4.1).

**Evidence:**

- ✅ §2.2.1 - CMS protection: exactly one SignerInfo, subjectKeyIdentifier
  signer form, mandatory `content-type` / `message-digest` signed attributes.
  Inbound responses are verified against the target's registered signing key
  resolved by SKI (`tamp_target_signers`), never a caller-supplied key.
- ✅ §4.1 - Sequence numbers strictly increasing per signer; replay rejected
  via a row-locked check-and-advance (`check_and_advance_seq`). NIST SC-23.
- ✅ §4.1/§4.2 - `TAMPStatusQuery` / `TAMPStatusResponse` (terse + verbose).
- ✅ §4.3/§4.4 - `TAMPUpdate` / `TAMPUpdateConfirm` (add / remove / change),
  with re-add of an existing public key rejected (`improperTAAddition`).
- ✅ §4.5/§4.6 - `TAMPApexUpdate` / `TAMPApexUpdateConfirm` (operational +
  contingency apex, optional clear of subordinate TAs / communities).
- ✅ §4.7/§4.8 - `TAMPCommunityUpdate` / confirm (atomic remove-then-add).
- ✅ §4.9/§4.10 - `SequenceNumberAdjust` / confirm.
- ✅ §4.11 - `TAMPError` with `StatusCode` mapping from every processing error.
- ✅ §5 - complete `StatusCode` enumeration, DER round-trip tested.
- ✅ §2.2.4.1 - Contingency-key unsigned attribute
  (`id-aa-TAMP-contingencyPublicKeyDecryptKey`): an apex update can carry the
  plaintext symmetric unwrap key as a CMS unsigned attribute
  (`sign_message_with_unsigned_attrs`); the key material is held in `Zeroizing`
  (SI-12) and the attachment is round-trip tested. Wrapping the contingency
  *public* key into the `id-pe-wrappedApexContinKey` extension is delegated to
  the caller/HSM (`ApexContingencyKey` type provided).
- ℹ️ Target (recipient) role is out of scope; OstrichPKI is the manager.

**DER tagging note:** the RFC 5934 / 5914 modules are `IMPLICIT TAGS`; per
X.680 §31.2.7 an implicit tag on a `CHOICE` (e.g. `add [1] TrustAnchorChoice`,
`issuer [n] Name`) is promoted to EXPLICIT. This is reflected in the type
definitions and validated by round-trip tests.

### RFC 5914: Trust Anchor Format

**Status:** 🟢 **Implemented**

`TrustAnchorChoice` (`certificate` / `tbsCert` / `taInfo`), `TrustAnchorInfo`,
and `CertPathControls` are implemented in
[crates/ostrich-tamp/src/asn1.rs](../../crates/ostrich-tamp/src/asn1.rs) and
consumed by the TAMP messages above.

---

## Document Change History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-03 | OstrichPKI Team | Initial RFC compliance assessment based on v0.10.0 codebase |
| 1.2 | 2026-01-04 | OstrichPKI Team | Added RFC 4514 DN parsing implementation, documented SAN parsing from CSR extensions, updated compliance to 70% |
| 1.7 | 2026-06-23 | OstrichPKI Team | Added RFC 5934 (TAMP manager role) and RFC 5914 (Trust Anchor Format) implementation in the `ostrich-tamp` crate and `ostrich-tamp-server` |
| 1.8 | 2026-06-26 | OstrichPKI Team | NPE Portal (`ostrich-npe-portal`): RFC 8446 (TLS 1.3) + RFC 9325 (TLS client authentication / mTLS) for operator auth; RFC 5280 §4.2.1.4 certificate-policy OIDs consumed for role mapping. (RFC 7030 §3.2.2 EST label routing is planned for a later milestone.) |
| 1.9 | 2026-06-26 | OstrichPKI Team | RFC 7030 §3.2.2: EST arbitrary-label routing implemented in `ostrich-est` — `/.well-known/est/{label}/...` with the `PTptval[-AKakval][-VPvpval][-CCccval]` scheme; the label selects the certificate profile and (by key algorithm) the issuing CA backend, enabling one EST instance to front multiple CAs (e.g. EC and RSA). |
| 2.0 | 2026-06-29 | OstrichPKI Team | RFC 7030 §4.4 + RFC 7292: EFS server-side key generation delivers the key + certificate as an encrypted PKCS#12 (PBES2 PBKDF2-HMAC-SHA256 / AES-256-CBC + HMAC-SHA256 MAC) under a one-time password — `crates/ostrich-x509/src/pkcs12.rs`. The EFS portal flow uses a CSR-free JSON `/serverkeygen` input (subject from the mTLS identity; no untrusted PKCS#10 parsed) alongside the standard §4.4.1 CSR path. RFC 5754 (SHA-2 AlgorithmIdentifiers omit NULL params) observed in the PKCS#12 structure. |
| 2.1 | 2026-07-27 | OstrichPKI Team | Added Kubernetes integration profile for RFC 7030 §3.2.3 TLS-protected Basic bootstrap and §4.2 enrollment through an external cert-manager issuer. |
| 2.2 | 2026-10-23 | OstrichPKI Team | Dependency advisory remediation (rustls 0.23.46, rustls-webpki 0.103.16, h2, quinn-proto, zip 9). RFC 8446 / RFC 9325: rewrote stale statements (TLS 1.3 minimum and mTLS are enforced in `tls.rs`; ChaCha20-Poly1305 is not offered under `fips`); status stays Partial (gRPC, revocation). RFC 5280 §6: added the TLS-peer path (webpki emSign SPKI distrust, no revocation). ML-DSA in X.509 is now RFC 9881: verification in TLS accepted by the user 2026-10-23, issuance disabled; status Designed → Partial (both 🟡, summary counts unchanged). Added RFC 9113/9000/1951 dependency fixes. |
| 2.3 | 2026-10-25 | OstrichPKI Team | CA gRPC behind mTLS (branch `claude/grpc-mtls`, uncommitted). RFC 8446: stale "gRPC TLS not configured / tonic `tls-ring`" text replaced; CA gRPC TLS 1.3 mTLS, ALPN `h2`, `fips()`, close_notify on post-handshake ALPN refusal (§6.1) and gRPC groups recorded with `grpc_mtls_e2e` evidence; `CA_GRPC_SERVER_NAME` override recorded as a deviation; status stays 🟡 Partial. RFC 9325: gRPC covered, remediation corrected. RFC 5280 TLS peer path validation: gRPC trust-anchor separation (one level), required clientAuth EKU extension (stricter than §4.2.1.12), narrowed signature set (deviation), limits (no revocation, no directoryName name constraints, no policy processing). RFC 4514: gRPC allowlist canonicalisation, strict escape validation with DER round-trip, and deviations (`;` separator, `\3B`, backslash-comma values, trimming, exact match not caseIgnoreMatch). ACME / EST: CA channel now mTLS. Not claimed: revocation, issuer/SPKI-bound allowlist, ancestor detection beyond one level, name-constraint or policy processing, caseIgnoreMatch. No status raised |
| 2.4 | 2026-10-25 | OstrichPKI Team | CA gRPC mTLS final refresh after fix round 3 (same branch). RFC 5280 §6.1 trust-anchor input: guard now refuses an anchor with the issuing CA's subject alone, one issued by the issuing CA (issuer name or AKI = SKI), its issuer, or any CA-database ancestor; refusal audited (`grpc_listener_refused`); per-call `subscriber_issuing_ca` (direct issuer only). Now claimed: ancestor detection within the CA-database lineage (revision 2.3 did not claim any ancestor detection). Still not claimed: siblings, grandchildren, roots outside the lineage (POAM-28), revocation, issuer binding, name-constraint and policy processing, caseIgnoreMatch, `:authority` coupling under `CA_GRPC_SERVER_NAME`. RFC 4514: UTF-8 hex-escape requirement claimed; deviations updated (ASCII-only trim, non-ASCII whitespace rejected, `\20` and backslash-space both accepted, backslash-comma not allow-listable even hex-escaped). Test counts: `grpc_mtls_e2e` 20/20 → 21/21 (incl. `no_alpn_refusal_sends_close_notify`), `grpc_tls::tests` 34 → 41. No status changed |
| 2.3 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS fix: added "RFC 8017 / RFC 4055 — RSASSA-PSS" note. PKCS#11 RSA-PSS now follows RFC 8017 §8.1/§9.1 (mHash = Hash(M) computed on the host), verified against an independent software verifier locally; Linux CI pending. Recorded the pre-existing RFC 4055 deviation: the X.509 layer does not encode or parse RSASSA-PSS-params (POAM-2026-10-23-20). No RFC section status changed. |
| 2.4 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS Linux CI evidence (commit 44d560d, PR 181): "RFC 8017 / RFC 4055 — RSASSA-PSS" status updated with GitHub Actions run 40063317654 (SoftHSM 2.6.1, 28 passed / 0 failed / 1 ignored, exit 0); scoped to SoftHSM and the PKCS#11 provider. RFC 4055 deviation (POAM-20) unchanged. No RFC section status changed. |
| 2.5 | 2026-10-26 | OstrichPKI Team | Per-method CA gRPC authorization (branch `claude/grpc-per-method-authz`, uncommitted). RFC 5280: admin list requires one distinct anchor with SKI (refusal, not warning); Admin leaf issued directly by the anchor (§4.1.2.4, §4.2.1.1 / §4.2.1.2, no DN-only fallback); per-call leaf validity (§4.1.2.5, leaf only); peer serial format (§4.1.2.2). RFC 4514: three role lists, case-variant overlap refusal, undecodable numeric OIDs refused (const-oid fuzz finding). New "gRPC over HTTP/2" subsection: exact path matching, status mapping, deviations RFC-003 (unknown method → PERMISSION_DENIED) and RFC-004 (malformed requestor → PERMISSION_DENIED). RFC 7030: EST client-identifier rule and HTTP 403 JSON body (RFC-104). ACME RFC 8555 §7.6 revocation still does not reach the CA. Counts: `grpc_mtls_e2e` 39, `grpc_tls` 66 (coder-reported). Version numbers 2.3 / 2.4 appear twice in this table (2026-10-23 and 2026-10-25); this entry continues from 2.4. No status change |
| 2.6 | 2026-10-26 | OstrichPKI Team | Dependabot alert remediation (branch `claude/dependabot-remediation`, uncommitted). Added "Dependency protocol conformance fixes (2026-10-26)": hickory 0.26.2 with per-advisory reachability (GHSA-6w6g reachable, now fails closed; GHSA-5j98 and GHSA-6f2x feature-gated, not reachable). RFC 8555 §7.5 / §8.4: stale "DNS resolver TODO/pending" replaced by "implemented, non-functional" (POAM-2026-10-23-41); §7.5 status corrected 🟢 → 🟡 (subsection only). Added CAA (RFC 8659 §3) and DNSSEC (RFC 8555 §11.2) as gaps. Priority 2 item 2: stale TLS-ALPN-01 statement removed (fixed by 5b1a034 / 5e8ab3f). RFC 8555 85% and the summary table not recalculated (no change claimed) |
| 2.7 | 2026-10-26 | OstrichPKI Team | web-ui BFF proxy raw path (branch `claude/web-ui-proxy-raw-path`, uncommitted). Added "RFC 3986: URI path handling in the web-ui BFF proxy": strict §2.1 decoding for checks only, raw path forwarded, §3.3 encoded delimiters and empty segments refused (stricter than RFC 3986), §5.2.4 dot segments refused rather than removed; query, `%252F`, octets >= 0x80 and `;` parameters not checked; npe-portal pending (POAM-46). No compliance percentage changed |
| 2.8 | 2026-10-26 | OstrichPKI Team | ACME dns-01 resolver fix (branch `claude/dns01-resolver-fix`, uncommitted; run record `target/agent-workflow/20261026-091032-dns01-resolver/`). RFC 8555 §7.5 / §8.4: dns-01 now functional (operator or system name servers, fails closed when empty; FQDN query name; no in-process cache; TXT strings concatenated, owner / CNAME chain checked; mismatch retried per §8.2); stale "non-functional" text, line references and remediation replaced; §8.4 stays 🟡 and §7.5 stays 🟡 (CAA, DNSSEC, wildcards; POAM-41, -49). Added the RFC-005 scope note (upstream recursor negative cache, RFC 2308), the RFC 8738 §7 note and a challenge failure-type table. §7.1: section numbers corrected (§7.1.2 Account, §7.1.3 Order, §7.1.4 Authorization, §7.1.5 Challenge); Order and Authorization ✅ → 🟡 and §7.1 🟢 → 🟡 (POAM-49). §7.3 §6.7 sanitization extended to challenge errors (`challenge_error_document`; registered types only). RFC 8737 🟢 → 🟡 (critical flag, single dNSName SAN, bare 32-octet value; POAM-52). Summary table: ACME 1/1 → 0/2 (90% → 50%), TOTAL 10/12 → 9/13 (75% → 70%), arithmetic under the table. RFC 8555 header "85%" not recalculated (not derived from a section list). Priority 2 item 2 and the 2026-10-26 dependency note updated |
| 2.10 | 2026-10-26 | OstrichPKI Team | npe-portal BFF proxy raw path (branch `claude/npe-portal-proxy-raw-path`, uncommitted; run record `target/agent-workflow/20261026-113138-npe-proxy-raw-path/`). The RFC 3986 section now covers both BFF proxies (renamed "RFC 3986: URI path handling in the BFF proxies"). It names the canonical shared module `ostrich_common::util::proxy_path` and notes that web-ui keeps an identical copy until a follow-up. The "npe-portal not yet" deviation was removed. Added the npe-portal empty-remainder 404 and the test and fuzz evidence. The web-ui reference was updated to commit e56a09e / PR #191. No status change |

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 15)

### RFC 5758 §3.2 — ECDSA with SHA-2

PKCS#11 ECDSA operations hash the complete signed input with the SHA-2 function
selected by the certificate signature algorithm, then submit that digest to
`CKM_ECDSA`. The returned fixed-width `r || s` value continues through the
existing X.509 DER conversion path.

### RFC 8017 / RFC 4055 — RSASSA-PSS

PKCS#11 RSA-PSS signing now computes mHash = Hash(M) on the host (RFC 8017
§9.1, EMSA-PSS) and passes it to raw `CKM_RSA_PKCS_PSS`; the token performs
the encoding with MGF1 using the same hash and a salt length equal to the hash
length. HSM-produced signatures verify with an independent AWS-LC RSASSA-PSS
verifier (`test_rsa_pss_hsm_sign_software_verify`). Status: ✅ Fixed;
verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), 28 passed /
0 failed / 1 ignored, RSA-2048/3072/4096 with SHA-256/384/512. Production HSM
not yet validated (POAM-2026-10-23-21). This covers the PKCS#11 provider only;
the RFC 4055 deviation below is unchanged.

**Deviation (pre-existing, RFC 4055 §3.1):** RSA-PSS is not used for X.509
signing. RSA CA keys sign certificates, CRLs and OCSP responses with
sha256WithRSAEncryption (PKCS#1 v1.5). The X.509 layer cannot encode
RSASSA-PSS-params, and the parser and path validator map id-RSASSA-PSS to
RSA-PSS SHA-256 without reading the parameters
([parser.rs](../../crates/ostrich-x509/src/parser.rs),
[path_validator.rs](../../crates/ostrich-x509/src/validation/path_validator.rs)).
POA&M: POAM-2026-10-23-20.

### RFC 7030 mTLS health-probe boundary

When EST client-certificate authentication is configured, Kubernetes uses TCP
socket probes because native HTTP probes cannot supply an enrollment client
certificate. RFC 7030 authentication remains enforced for all HTTP requests.

### RFC 7030 §3.2.3 — HTTP Basic bootstrap

With Basic bootstrap explicitly enabled, the EST TLS listener requests but does
not require a client certificate during negotiation. The application then
requires either verified mTLS identity or valid Basic credentials before
enrollment, allowing bootstrap without anonymous access.
