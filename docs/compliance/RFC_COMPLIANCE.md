# RFC Standards Compliance Matrix

**Document Version:** 1.9
**Date:** 2026-01-04
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

**Sections:**

#### §7.1: Resources

**Status:** 🟢 **Compliant**

**Implementation:**

- [crates/ostrich-acme/src/rest.rs](../../crates/ostrich-acme/src/rest.rs) - ACME REST endpoints

**Resources:**

- ✅ §7.1.1 - Account objects
- ✅ §7.1.2 - Order objects
- ✅ §7.1.3 - Authorization objects
- ✅ §7.1.4 - Challenge objects

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

**Enhancement Needed:** Phase 15 - Use FIPS-validated DRBG instead of UUID

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

---

#### §7.3: Account Management

**Status:** 🟢 **Compliant**

**Endpoints:**

- ✅ §7.3.1 - newAccount (account creation)
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
- [services/acme-server/src/main.rs](../../services/acme-server/src/main.rs) - `CA_GRPC_URL` configuration; warns and fails finalization closed when absent

**Code References (Phase 11):**

- [validation.rs](../../crates/ostrich-acme/src/validation.rs) - Challenge validators (HTTP-01, DNS-01, TLS-ALPN-01)

---

#### §7.5: Identifier Validation Challenges

**Status:** 🟢 **Good** (infrastructure complete)

**Challenges:**

- ✅ §8.3 - HTTP-01 Challenge (validator implemented)
- ✅ §8.4 - DNS-01 Challenge (infrastructure ready, DNS resolver TODO)
- ⚠️ §8.5 - TLS-ALPN-01 Challenge (infrastructure ready, TLS client TODO)

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
  name resolving to an internal address bypassed it.
- ✅ DNS-01: Compute `_acme-challenge.<domain>` TXT record value
- ⚠️ DNS-01: DNS resolver implementation pending

**Remediation:** Phase 16 - Complete DNS-01 validator

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

**Status:** 🟡 **Partial**

**Requirement:** TLS-ALPN-01 challenge validation

**Implementation:**

- [crates/ostrich-acme/src/validation.rs](../../crates/ostrich-acme/src/validation.rs) - TlsAlpn01Validator structure

**Evidence:**

- ✅ acmeIdentifier hash computation (SHA-256 of `<token>.<thumbprint>`)
- ⚠️ TLS client implementation pending

**Gaps:**

- TLS client with ALPN "acme-tls/1" not implemented
- Certificate extraction from TLS handshake pending

**Remediation:** Phase 16 - Implement TLS client for TLS-ALPN-01

---

### RFC 7030: Enrollment over Secure Transport (EST)

**Status:** 🟢 **Enrollment working** (simpleenroll issues real certificates)

**Live evidence (Phase 16):** an EST client (authenticated bearer session,
RaStaff role) POSTed a PKCS#10 CSR to `/.well-known/est/simpleenroll` and
received a `200 OK` PKCS#7 (RFC 5652 certs-only SignedData) containing the
issued certificate (subject `CN=est-client.example.com`, issuer
`CN=OstrichPKI EST Root`), which `openssl verify` accepts against the root.
`/.well-known/est/cacerts` returns the CA certificate as PKCS#7.

The enrollment handlers now call the CA gRPC service via `EstCaClient`
(crates/ostrich-est/src/rest.rs, services/est-server/src/main.rs) instead of
returning an empty 202 placeholder; they fail closed when CA integration is
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
- ✅ §3.4 - Server-Side Key Generation (/serverkeygen) - implemented (ECDSA P-256; CSR-based PoP; PKCS#8 + PKCS#7 multipart per §4.4.2)

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

**Status:** 🟡 **Partial**

**Requirement:** All administrative and inter-service communication uses TLS 1.3

**Implementation:**

- REST and gRPC frameworks support TLS 1.3
- Configuration delegated to deployment

**Evidence:**

- ✅ axum (REST) supports TLS 1.3 via rustls
- ✅ tonic (gRPC) supports TLS 1.3
- 🔴 TLS configuration not in application code

**Gaps:**

- No explicit TLS 1.3 minimum enforcement
- No cipher suite restriction
- mTLS not configured

**Remediation:** Phase 16 - Configure TLS 1.3+ in application with approved cipher suites

**Approved Cipher Suites (NIST SP 800-52 Rev 2):**

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

---

### RFC 9325: Recommendations for Secure Use of TLS and DTLS

**Status:** 🟡 **Partial**

**Recommendations:**

- ✅ Use TLS 1.3 (or 1.2 minimum)
- 🔴 Disable TLS 1.1 and earlier (not explicitly configured)
- 🔴 Restrict cipher suites to strong AEAD ciphers
- ✅ Use certificate-based authentication for mTLS (designed)

**Remediation:** Phase 16 - Apply all TLS best practices

---

## Post-Quantum Cryptography (Draft RFCs)

### draft-ietf-lamps-dilithium-certificates: ML-DSA in X.509

**Status:** 🟡 **Designed** (not implemented)

**Implementation:**

- [crates/ostrich-common/src/oid.rs:74](../../crates/ostrich-common/src/oid.rs#L74) - ML-DSA OID placeholder
- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm enum includes ML-DSA variants

**Evidence:**

- ✅ Algorithm types defined (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- 🔴 No implementation

**Remediation:**

- Phase 13 - Monitor IETF LAMPS WG for OID finalization
- Phase 13 - Implement ML-DSA signing when draft standardizes

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
| Enrollment (ACME) | 2 | 1 | 1 | 0 | 0 | 90% |
| Enrollment (EST) | 2 | 0 | 2 | 0 | 0 | 70% |
| Cryptography (CMS) | 3 | 0 | 1 | 0 | 2 | 50% |
| Key Management | 3 | 2 | 1 | 0 | 0 | 83% |
| Transport (TLS) | 2 | 0 | 2 | 0 | 0 | 50% |
| Post-Quantum (Draft) | 3 | 0 | 3 | 0 | 0 | 30% |
| **TOTAL** | **24** | **10** | **12** | **0** | **2** | **75%** |

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
   - Impact: Weak TLS configuration possible
   - Phase: 16
   - Effort: 3-5 days

2. **RFC 8555 - ACME Challenge Validators** (🟡 Partial)
   - Impact: DNS-01 and TLS-ALPN-01 not fully functional
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

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 15)
