# OstrichPKI Security Target

**Document Version:** 1.0
**Document Date:** January 2026
**Protection Profile:** NIAP Protection Profile for Certification Authorities (PP-CA) v2.1
**Common Criteria Version:** 3.1 Release 5
**Assurance Level:** EAL2+ (ALC_FLR.2)

---

## 1. Security Target Introduction

### 1.1 ST Reference

| Property | Value |
|----------|-------|
| **ST Title** | OstrichPKI Security Target |
| **ST Version** | 1.0 |
| **ST Date** | January 2026 |
| **ST Author** | OstrichPKI Development Team |
| **TOE Reference** | OstrichPKI v1.0 |
| **TOE Developer** | OstrichPKI Project |
| **Keywords** | PKI, Certificate Authority, X.509, ACME, EST, OCSP, CRL |

### 1.2 TOE Reference

| Property | Value |
|----------|-------|
| **TOE Name** | OstrichPKI |
| **TOE Version** | 1.0 |
| **TOE Type** | Public Key Infrastructure / Certificate Authority |

### 1.3 TOE Overview

OstrichPKI is a comprehensive Public Key Infrastructure (PKI) system written in Rust, designed for government and enterprise environments requiring high security assurance. The system provides:

- **Certificate Authority (CA)** - X.509 certificate issuance, revocation, and lifecycle management
- **ACME Service** - RFC 8555 compliant automated certificate management
- **EST Service** - RFC 7030 compliant enrollment over secure transport
- **OCSP Responder** - RFC 6960 compliant real-time certificate status
- **CRL Service** - RFC 5280 compliant certificate revocation lists
- **Key Recovery Agent (KRA)** - Secure key escrow with Shamir secret sharing
- **SCMS Service** - Smartcard/token lifecycle management
- **Audit Service** - Tamper-evident logging with hash chain integrity

**Security Focus:**

- NIST 800-53 Rev 5 control compliance
- FIPS 140-3 cryptographic module integration (via PKCS#11 HSM)
- Post-quantum cryptography readiness (ML-DSA, ML-KEM per FIPS 203/204/205)
- Crypto-agility for algorithm migration

### 1.4 TOE Description

#### 1.4.1 Physical Scope

The TOE consists of:

1. **Software Components:**
   - OstrichPKI executable binaries (Rust compiled)
   - Configuration files
   - Database schemas (PostgreSQL)
   - Container images (Docker)

2. **External Interfaces:**
   - REST APIs (ACME, EST, SCMS, Health)
   - gRPC APIs (inter-service communication)
   - PKCS#11 interface (HSM communication)
   - PostgreSQL database connection

3. **Excluded from TOE (Operational Environment):**
   - Hardware Security Module (HSM) - FIPS 140-2 Level 2+ validated
   - PostgreSQL database server
   - Operating system and container runtime
   - Network infrastructure (firewalls, load balancers)
   - NTP time source

#### 1.4.2 Logical Scope

The TOE provides the following security functions:

| Security Function | Description |
|-------------------|-------------|
| **Certificate Management** | Issue, renew, revoke X.509 certificates per RFC 5280 |
| **Cryptographic Operations** | Key generation, signing, verification via HSM |
| **Access Control** | Role-based access control for CA operations |
| **Audit** | Security event logging with integrity protection |
| **Identification & Authentication** | mTLS client certificate authentication |
| **Certificate Status** | OCSP responses and CRL generation |
| **Secure Communication** | TLS 1.3 for all external interfaces |

#### 1.4.3 Microservice Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        External Clients                          │
│            (ACME clients, EST clients, Browsers)                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │ TLS 1.3
┌─────────────────────────▼───────────────────────────────────────┐
│                     API Gateway / Load Balancer                  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
    ┌─────────┬───────────┼───────────┬─────────┐
    │         │           │           │         │
    ▼         ▼           ▼           ▼         ▼
┌───────┐ ┌───────┐ ┌─────────┐ ┌───────┐ ┌───────┐
│ ACME  │ │  EST  │ │   CA    │ │ OCSP  │ │ SCMS  │
│Service│ │Service│ │ Service │ │Service│ │Service│
└───┬───┘ └───┬───┘ └────┬────┘ └───┬───┘ └───┬───┘
    │         │          │          │         │
    └─────────┴────┬─────┴──────────┴─────────┘
                   │ gRPC + mTLS
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌───────┐    ┌─────────┐    ┌─────────┐
│ Audit │    │Database │    │   HSM   │
│Service│    │(PostgreSQL)│  │(PKCS#11)│
└───────┘    └─────────┘    └─────────┘
```

---

## 2. Conformance Claims

### 2.1 CC Conformance Claim

This Security Target claims conformance to:

- **Common Criteria for Information Technology Security Evaluation:**
  - Part 1: Introduction and General Model, Version 3.1 Revision 5
  - Part 2: Security Functional Components, Version 3.1 Revision 5
  - Part 3: Security Assurance Components, Version 3.1 Revision 5

### 2.2 PP Claim

This Security Target claims **strict conformance** to:

- **Protection Profile for Certification Authorities**
  - Version 2.1 FINAL
  - NIAP Publication Date: November 2023

### 2.3 Package Claim

None beyond those included in the PP-CA v2.1.

### 2.4 Conformance Rationale

The TOE satisfies all mandatory requirements of PP-CA v2.1:

| Requirement | Conformance |
|-------------|-------------|
| All mandatory SFRs | Implemented |
| All mandatory SARs | Implemented |
| Selection-based SFRs | As applicable |
| Optional SFRs | None claimed |

---

## 3. Security Problem Definition

### 3.1 Threats

The following threats are addressed by the TOE (from PP-CA v2.1):

#### T.MASQUERADE

**Threat Agent:** Unauthorized entity
**Action:** Attempts to impersonate an authorized user or CA administrator
**Asset:** CA operations, certificate issuance authority
**Adverse Effect:** Unauthorized certificate issuance, revocation, or CA configuration

**Countermeasures:**

- mTLS client certificate authentication (FIA_X509_EXT.1)
- Strong authentication before any CA operation (FIA_UAU.2)
- Role-based access control (FMT_SMR.2)

#### T.MODIFY_DATA

**Threat Agent:** Unauthorized entity or insider
**Action:** Attempts to modify TSF data, certificates, or audit records
**Asset:** Certificates, CRLs, audit logs, configuration
**Adverse Effect:** Invalid certificates accepted, security events hidden

**Countermeasures:**

- Cryptographic integrity protection for audit logs (FAU_STG.1.2)
- Access control for configuration changes (FMT_MOF.1)
- Digital signatures on certificates and CRLs (FCS_COP.1)

#### T.DISCLOSURE

**Threat Agent:** Unauthorized entity
**Action:** Attempts to access private keys or sensitive data
**Asset:** CA private keys, user private keys (if escrowed), audit data
**Adverse Effect:** Key compromise, certificate forgery, privacy violation

**Countermeasures:**

- Private key protection in HSM (FPT_SKP_EXT.1)
- Encrypted storage for sensitive data (FCS_COP.1)
- Access control for audit log access (FAU_SAR.1)

#### T.UNDETECTED_ACTIONS

**Threat Agent:** Malicious administrator or attacker
**Action:** Attempts to perform security-relevant actions without audit trail
**Asset:** Audit data completeness
**Adverse Effect:** Security violations undetectable, forensics impossible

**Countermeasures:**

- Comprehensive audit event generation (FAU_GEN.1)
- Audit record integrity protection (FAU_STG.1)
- User identity association with audit events (FAU_GEN.2)

#### T.TSF_FAILURE

**Threat Agent:** Software defect, hardware failure, attack
**Action:** Causes the TOE to enter a failed state
**Asset:** TOE security functions
**Adverse Effect:** Security functions disabled, insecure state persists

**Countermeasures:**

- Self-tests at startup and on-demand (FPT_TST_EXT.1)
- Failure with preservation of secure state (FPT_FLS.1)
- Cryptographic algorithm verification (FCS_COP.1)

#### T.EXPIRED_CERTIFICATE

**Threat Agent:** Relying party
**Action:** Accepts expired or revoked certificate
**Asset:** Certificate validity, trust relationships
**Adverse Effect:** Authentication bypass, unauthorized access

**Countermeasures:**

- Certificate path validation (FIA_X509_EXT.1)
- Real-time revocation status (OCSP)
- CRL distribution (FDP_CER_EXT.2)

### 3.2 Organizational Security Policies

#### P.AUTHORIZED_USERS

Only authorized administrators and operators shall access CA functions. Access shall be based on defined security roles.

**Implementation:** FMT_SMR.2, FMT_MOF.1, FIA_UAU.2

#### P.ACCOUNTABILITY

All security-relevant actions shall be attributed to a responsible user and recorded in tamper-evident audit logs.

**Implementation:** FAU_GEN.1, FAU_GEN.2, FAU_STG.1

#### P.CRYPTOGRAPHY

The TOE shall use FIPS-validated cryptographic algorithms for all security functions.

**Implementation:** FCS_CKM.1, FCS_COP.1, FCS_RBG_EXT.1

#### P.CERTIFICATE_VALIDITY

Certificates shall only be issued after proper validation of the request. Revocation information shall be available in real-time.

**Implementation:** FDP_CER_EXT.1, FIA_X509_EXT.1, OCSP service

### 3.3 Assumptions

#### A.PHYSICAL

The TOE operates in a physically protected environment. Physical access to TOE servers and HSM is restricted to authorized personnel.

#### A.TRUSTED_ADMIN

TOE administrators are competent, appropriately trained, and follow all guidance documentation. Administrators are not malicious but may make errors.

#### A.NETWORK

The network provides adequate protection against denial of service and unauthorized network access. Firewalls and network segmentation are properly configured.

#### A.HSM

The Hardware Security Module (HSM) used for CA key protection is FIPS 140-2 Level 2 or higher validated and properly configured.

#### A.TIME_SOURCE

A reliable time source (e.g., authenticated NTP) is available and the TOE is configured to use it.

#### A.DATABASE

The PostgreSQL database is properly secured with access control, encryption at rest, and regular backups.

---

## 4. Security Objectives

### 4.1 Security Objectives for the TOE

#### O.AUDIT

The TOE shall generate audit records for security-relevant events and protect audit records from unauthorized modification or deletion.

**Addressed by:** FAU_GEN.1, FAU_GEN.2, FAU_SAR.1, FAU_STG.1, FAU_STG.3, FAU_STG.4

#### O.ACCESS_CONTROL

The TOE shall restrict access to security functions based on authenticated user identity and assigned roles.

**Addressed by:** FMT_SMR.2, FMT_MOF.1, FIA_UAU.2, FMT_MTD.1

#### O.CRYPTOGRAPHY

The TOE shall use FIPS-validated cryptographic algorithms for key generation, signatures, hashing, and random number generation.

**Addressed by:** FCS_CKM.1, FCS_CKM.4, FCS_COP.1, FCS_RBG_EXT.1

#### O.CERTIFICATE_MANAGEMENT

The TOE shall properly generate, validate, and revoke X.509 certificates in accordance with RFC 5280.

**Addressed by:** FDP_CER_EXT.1, FDP_CER_EXT.2, FIA_X509_EXT.1

#### O.SECURE_COMMUNICATION

The TOE shall protect communications using TLS 1.3 with mutual authentication where required.

**Addressed by:** FTP_ITC.1, FTP_TRP.1

#### O.SELF_TEST

The TOE shall verify the correct operation of its security functions through self-testing.

**Addressed by:** FPT_TST_EXT.1, FCS_COP.1 (KAT)

#### O.FAILURE_HANDLING

The TOE shall preserve a secure state upon failure and prevent further operation until the failure is resolved.

**Addressed by:** FPT_FLS.1

### 4.2 Security Objectives for the Operational Environment

#### OE.PHYSICAL

The operational environment shall provide physical protection for the TOE and HSM.

#### OE.PERSONNEL

TOE administrators shall be appropriately vetted, trained, and monitored.

#### OE.NETWORK

The operational environment shall provide network security including firewalls, intrusion detection, and network segmentation.

#### OE.HSM

The operational environment shall provide a FIPS 140-2 Level 2+ validated HSM for CA key protection.

#### OE.TIME

The operational environment shall provide a reliable and authenticated time source.

#### OE.BACKUP

The operational environment shall provide secure backup and recovery capabilities.

---

## 5. Extended Components Definition

This Security Target defines the following extended components per PP-CA v2.1:

### FCS_RBG_EXT.1 - Random Bit Generation (Extended)

**Family Behavior:** Defines requirements for cryptographically secure random bit generation.

**Component Definition:**

- FCS_RBG_EXT.1.1: The TSF shall generate random bits using NIST SP 800-90A compliant DRBG.
- FCS_RBG_EXT.1.2: The TSF shall reseed the DRBG before reaching implementation-defined limits.

### FPT_TST_EXT.1 - TSF Self-Testing (Extended)

**Family Behavior:** Defines requirements for TOE self-testing at startup and on-demand.

**Component Definition:**

- FPT_TST_EXT.1.1: The TSF shall run self-tests at startup and on administrator demand.
- FPT_TST_EXT.1.2: The TSF shall verify cryptographic algorithms using known-answer tests.

### FIA_X509_EXT.1 - X.509 Certificate Validation (Extended)

**Family Behavior:** Defines requirements for X.509 certificate path validation per RFC 5280.

**Component Definition:**

- FIA_X509_EXT.1.1: The TSF shall validate certificate paths to a trust anchor.
- FIA_X509_EXT.1.2: The TSF shall verify certificate fields, extensions, and signatures.

---

## 6. Security Requirements

### 6.1 Security Functional Requirements

The following SFRs are implemented by OstrichPKI:

#### 6.1.1 Security Audit (FAU)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FAU_GEN.1 | Audit Data Generation | Implemented |
| FAU_GEN.2 | User Identity Association | Implemented |
| FAU_SAR.1 | Audit Review | Implemented |
| FAU_STG.1 | Protected Audit Trail Storage | Implemented |
| FAU_STG.3 | Action in Case of Possible Audit Data Loss | Implemented |
| FAU_STG.4 | Prevention of Audit Data Loss | Implemented |

**Implementation Evidence:**

- Audit event generation: [crates/ostrich-audit/src/lib.rs](crates/ostrich-audit/src/lib.rs)
- Audit sink implementations: [crates/ostrich-audit/src/sink.rs](crates/ostrich-audit/src/sink.rs)
- Database audit repository: [crates/ostrich-db/src/repository/audit.rs](crates/ostrich-db/src/repository/audit.rs)
- Audit models: [crates/ostrich-db/src/models/audit.rs](crates/ostrich-db/src/models/audit.rs)

#### 6.1.2 Cryptographic Support (FCS)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FCS_CKM.1 | Cryptographic Key Generation | Implemented (HSM) |
| FCS_CKM.4 | Cryptographic Key Destruction | Implemented (HSM) |
| FCS_COP.1(1) | Cryptographic Operation (Signing) | Implemented |
| FCS_COP.1(2) | Cryptographic Operation (Hashing) | Implemented |
| FCS_COP.1(3) | Cryptographic Operation (Encryption) | Implemented |
| FCS_RBG_EXT.1 | Random Bit Generation | Implemented |

**Cryptographic Algorithms Supported:**

| Algorithm | Standard | Key Size | Usage |
|-----------|----------|----------|-------|
| RSA | FIPS 186-5 | 2048, 3072, 4096 | Signatures |
| ECDSA | FIPS 186-5 | P-256, P-384, P-521 | Signatures |
| EdDSA | RFC 8032 | Ed25519, Ed448 | Signatures |
| ML-DSA | FIPS 204 | ML-DSA-44/65/87 | Post-quantum signatures |
| SHA-2 | FIPS 180-4 | 256, 384, 512 | Hashing |
| AES | FIPS 197 | 256 | Encryption |
| HMAC | FIPS 198-1 | SHA-256/384/512 | MACs |

**Implementation Evidence:**

- Crypto provider trait: [crates/ostrich-crypto/src/provider.rs](crates/ostrich-crypto/src/provider.rs)
- PKCS#11 provider: [crates/ostrich-pkcs11/src/provider.rs](crates/ostrich-pkcs11/src/provider.rs)
- Algorithm definitions: [crates/ostrich-crypto/src/algorithm.rs](crates/ostrich-crypto/src/algorithm.rs)

#### 6.1.3 User Data Protection (FDP)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FDP_CER_EXT.1 | Certificate Generation | Implemented |
| FDP_CER_EXT.2 | CRL Generation | Implemented |

**Implementation Evidence:**

- Certificate builder: [crates/ostrich-x509/src/builder.rs](crates/ostrich-x509/src/builder.rs)
- CRL builder: [crates/ostrich-x509/src/crl.rs](crates/ostrich-x509/src/crl.rs)
- Certificate profiles: [crates/ostrich-x509/src/profile.rs](crates/ostrich-x509/src/profile.rs)

#### 6.1.4 Identification and Authentication (FIA)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FIA_X509_EXT.1 | X.509 Certificate Validation | Implemented |
| FIA_UAU.2 | User Authentication Before Any Action | Implemented |
| FIA_AFL.1 | Authentication Failure Handling | Implemented |

**Implementation Evidence:**

- Certificate validation: [crates/ostrich-x509/src/validation.rs](crates/ostrich-x509/src/validation.rs)
- mTLS authentication: [crates/ostrich-common/src/tls.rs](crates/ostrich-common/src/tls.rs)

#### 6.1.5 Security Management (FMT)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FMT_SMR.2 | Restrictions on Security Roles | Implemented |
| FMT_MOF.1 | Management of Security Functions | Implemented |
| FMT_MSA.1 | Management of Security Attributes | Implemented |
| FMT_MSA.2 | Secure Security Attributes | Implemented |
| FMT_MTD.1 | Management of TSF Data | Implemented |
| FMT_SMF.1 | Specification of Management Functions | Implemented |

**Implementation Evidence:**

- RBAC definitions: [crates/ostrich-rbac/src/lib.rs](crates/ostrich-rbac/src/lib.rs)
- Authorization middleware: [crates/ostrich-common/src/auth.rs](crates/ostrich-common/src/auth.rs)

#### 6.1.6 Protection of the TSF (FPT)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FPT_TST_EXT.1 | TSF Self-Testing | Implemented |
| FPT_FLS.1 | Failure with Preservation of Secure State | Implemented |
| FPT_STM.1 | Reliable Time Stamps | Implemented |
| FPT_SKP_EXT.1 | Protection of TSF Private Keys | Implemented (HSM) |

**Implementation Evidence:**

- Self-tests: [crates/ostrich-crypto/src/self_test.rs](crates/ostrich-crypto/src/self_test.rs)
- Time source: [crates/ostrich-common/src/time.rs](crates/ostrich-common/src/time.rs)

#### 6.1.7 TOE Access (FTA)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FTA_SSL.1 | TSF-Initiated Session Locking | Implemented |
| FTA_TSE.1 | TOE Session Establishment | Implemented |

#### 6.1.8 Trusted Path/Channels (FTP)

| SFR ID | Name | Implementation Status |
|--------|------|----------------------|
| FTP_ITC.1 | Inter-TSF Trusted Channel | Implemented |
| FTP_TRP.1 | Trusted Path | Implemented |

**Implementation Evidence:**

- TLS configuration: All services configured for TLS 1.3
- mTLS enforcement: [crates/ostrich-est/src/tls.rs](crates/ostrich-est/src/tls.rs)

### 6.2 Security Assurance Requirements

This ST claims EAL2 augmented with ALC_FLR.2 (Flaw Remediation):

| SAR ID | Name | Level |
|--------|------|-------|
| ADV_ARC.1 | Security Architecture Description | EAL2 |
| ADV_FSP.2 | Security-Enforcing Functional Specification | EAL2 |
| ADV_TDS.1 | Basic Design | EAL2 |
| AGD_OPE.1 | Operational User Guidance | EAL2 |
| AGD_PRE.1 | Preparative Procedures | EAL2 |
| ALC_CMC.2 | Use of a CM System | EAL2 |
| ALC_CMS.2 | Parts of the TOE CM Coverage | EAL2 |
| ALC_DEL.1 | Delivery Procedures | EAL2 |
| ALC_FLR.2 | Flaw Reporting Procedures | Augmentation |
| ATE_COV.1 | Evidence of Coverage | EAL2 |
| ATE_FUN.1 | Functional Testing | EAL2 |
| ATE_IND.2 | Independent Testing - Sample | EAL2 |
| AVA_VAN.2 | Vulnerability Analysis | EAL2 |

---

## 7. TOE Summary Specification

### 7.1 Security Audit

**FAU_GEN.1 - Audit Data Generation:**

The TOE generates audit records for all security-relevant events including:

- Service startup and shutdown
- Authentication attempts (success and failure)
- Certificate issuance, renewal, and revocation
- CRL generation
- Configuration changes
- Access control decisions
- Cryptographic operations

Each audit record contains:

- Timestamp (from reliable time source)
- Event type
- Actor identity (user, service, or client certificate DN)
- Event outcome (success/failure)
- Relevant data (certificate serial number, etc.)

**FAU_STG.1 - Protected Audit Trail Storage:**

Audit records are protected using:

- Hash chain integrity (each record linked to previous)
- Database append-only constraints
- Role-based access control (only Auditor role can read)
- No delete operation available

### 7.2 Cryptographic Support

**FCS_CKM.1 - Key Generation:**

CA signing keys are generated in the HSM using:

- PKCS#11 interface
- NIST-approved algorithms (RSA, ECDSA, EdDSA, ML-DSA)
- Key sizes meeting minimum requirements (RSA-2048, P-256, etc.)

**FCS_COP.1 - Cryptographic Operations:**

All cryptographic operations are performed by:

- HSM for signing operations (CA key never leaves HSM)
- Software cryptographic library for verification
- FIPS-validated algorithms only

### 7.3 User Data Protection

**FDP_CER_EXT.1 - Certificate Generation:**

Certificates are generated following RFC 5280:

- X.509 v3 format
- DER encoding
- Required extensions (keyUsage, basicConstraints, etc.)
- Signature using CA key via HSM

**FDP_CER_EXT.2 - CRL Generation:**

CRLs are generated following RFC 5280 Section 5:

- X.509 v2 CRL format
- thisUpdate and nextUpdate timestamps
- List of revoked certificates with reason codes
- Signature using CA key via HSM

### 7.4 Identification and Authentication

**FIA_X509_EXT.1 - Certificate Validation:**

Certificate path validation implements RFC 5280 Section 6:

- Build path to trust anchor
- Verify signatures
- Check validity periods
- Verify revocation status (OCSP, CRL)
- Check name constraints
- Check policy constraints

**FIA_UAU.2 - User Authentication:**

Users are authenticated using mTLS:

- Client certificate required
- Certificate validated per FIA_X509_EXT.1
- Role extracted from certificate attributes
- All actions require valid session

### 7.5 Security Management

**FMT_SMR.2 - Security Roles:**

The TOE implements five security roles:

1. **Administrator** - System configuration, user management
2. **Operations Staff** - Certificate issuance/revocation
3. **Auditor** - Audit log review (read-only)
4. **RA Staff** - Certificate request approval
5. **AOR** - Policy decisions

Role separation is enforced:

- Administrator cannot issue certificates
- Auditor cannot perform CA operations
- All role assignments require dual authorization

### 7.6 Protection of the TSF

**FPT_TST_EXT.1 - Self-Testing:**

The TOE performs self-tests:

- At startup: Cryptographic KAT, integrity check
- Periodically: DRBG health test, HSM connectivity
- On-demand: Full test suite via admin API

Test failure results in:

- Audit event generated
- TOE enters failed state
- All operations denied until resolved

**FPT_FLS.1 - Failure Handling:**

On critical failure:

- Current state preserved
- Audit record written (if possible)
- Sensitive data zeroized
- Service enters maintenance mode
- Administrator notification sent

### 7.7 Trusted Path/Channels

**FTP_ITC.1 - Inter-TSF Trusted Channel:**

All inter-service communication uses:

- TLS 1.3 minimum version
- mTLS with client certificate authentication
- Approved cipher suites only (AES-256-GCM, ChaCha20-Poly1305)

**FTP_TRP.1 - Trusted Path:**

External client communication uses:

- HTTPS with TLS 1.3
- Server certificate validation
- Client certificate for administrative access

---

## 8. Rationale

### 8.1 Security Objectives Rationale

Each security objective is traced to threats and policies:

| Objective | Addresses Threats | Addresses Policies |
|-----------|------------------|-------------------|
| O.AUDIT | T.UNDETECTED_ACTIONS | P.ACCOUNTABILITY |
| O.ACCESS_CONTROL | T.MASQUERADE, T.MODIFY_DATA | P.AUTHORIZED_USERS |
| O.CRYPTOGRAPHY | T.DISCLOSURE | P.CRYPTOGRAPHY |
| O.CERTIFICATE_MANAGEMENT | T.EXPIRED_CERTIFICATE | P.CERTIFICATE_VALIDITY |
| O.SECURE_COMMUNICATION | T.DISCLOSURE, T.MODIFY_DATA | P.CRYPTOGRAPHY |
| O.SELF_TEST | T.TSF_FAILURE | P.CRYPTOGRAPHY |
| O.FAILURE_HANDLING | T.TSF_FAILURE | P.ACCOUNTABILITY |

### 8.2 Security Requirements Rationale

Each SFR traces to a security objective:

| SFR | Objective |
|-----|-----------|
| FAU_* | O.AUDIT |
| FCS_* | O.CRYPTOGRAPHY |
| FDP_CER_EXT.* | O.CERTIFICATE_MANAGEMENT |
| FIA_* | O.ACCESS_CONTROL, O.CERTIFICATE_MANAGEMENT |
| FMT_* | O.ACCESS_CONTROL |
| FPT_TST_EXT.1 | O.SELF_TEST |
| FPT_FLS.1 | O.FAILURE_HANDLING |
| FPT_STM.1 | O.AUDIT |
| FTP_* | O.SECURE_COMMUNICATION |

### 8.3 Dependency Rationale

All SFR dependencies are satisfied per PP-CA v2.1 analysis.

---

## 9. References

### Standards

- Common Criteria for IT Security Evaluation v3.1 R5
- NIAP Protection Profile for Certification Authorities v2.1
- RFC 5280 - Internet X.509 PKI Certificate and CRL Profile
- RFC 6960 - OCSP
- RFC 8555 - ACME
- RFC 7030 - EST
- FIPS 140-3 - Security Requirements for Cryptographic Modules
- FIPS 186-5 - Digital Signature Standard
- FIPS 203 - ML-KEM
- FIPS 204 - ML-DSA
- FIPS 205 - SLH-DSA
- NIST SP 800-90A - DRBG
- NIST SP 800-53 Rev 5 - Security Controls

### Project Documentation

- [ROADMAP.md](../../ROADMAP.md) - Implementation roadmap
- [NIAP_COMPLIANCE.md](NIAP_COMPLIANCE.md) - Detailed SFR implementation
- [NIAP_GAP_ANALYSIS.md](NIAP_GAP_ANALYSIS.md) - Gap analysis
- [NIST_800-53_MAPPING.md](NIST_800-53_MAPPING.md) - NIST control mapping
- [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md) - RFC compliance status

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial Security Target |

---

**Prepared for NIAP Common Criteria Evaluation**
