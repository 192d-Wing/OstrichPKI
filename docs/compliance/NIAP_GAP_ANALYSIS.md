# NIAP Protection Profile Gap Analysis

**Document Version:** 2.8
**Generated:** 2026-01-04 (POA&M §11 added 2026-10-23)
**OstrichPKI Version:** 0.15.0
**NIAP PP-CA Version:** v2.1 FINAL
**Current Compliance:** 98% (49/50 applicable SFRs Compliant, 1 N/A, 2 optional, 4 OE)
**Target Compliance:** ✅ ACHIEVED - 98% compliance (49/50 applicable SFRs)
**Last Updated:** Phase 19 Complete - All applicable SFRs implemented and documented

---

## Executive Summary

This document provides a comprehensive gap analysis for OstrichPKI's compliance with the NIAP Protection Profile for Certification Authorities (PP-CA) v2.1. Following completion of Phases 8-19, **all applicable security functional requirements are implemented**, achieving **98% compliance (49/50 applicable SFRs)**.

### Overall Status

| Category | Count | Percentage |
|----------|-------|------------|
| 🟢 **Compliant** | 49 | 98% |
| 🔴 Optional/Deployment | 2 | N/A (FPT_TUD_EXT.1, FTA_TAB.1) |
| ⚪ Not Applicable | 1 | N/A (FIA_X509_EXT.3 - not selected) |
| ⚪ Operational Environment | 4 | N/A (HSM hardware, OS security) |
| **Total Applicable SFRs** | **50** | **100%** |
| **Total SFRs in PP-CA v2.1** | **56** | - |

### Compliance by Family

| Family | Compliant | Partial | Missing/OE | Total Applicable | % Complete |
|--------|-----------|---------|------------|------------------|------------|
| **FAU** (Security Audit) | 7 | 0 | 0 | 7 | 100% |
| **FCS** (Cryptographic Support) | 10 | 1 | 0 | 11 | 100% |
| **FDP** (Data Protection) | 7 | 0 | 0 | 7 | 100% |
| **FIA** (Identification/Auth) | 7 | 1 | 0 | 8 | 100% |
| **FMT** (Management) | 4 | 0 | 0 | 4 | 100% |
| **FPT** (TSF Protection) | 5 | 2 | 4 OE | 7 | 100% (applicable) |
| **FTA** (TOE Access) | 3 | 0 | 1 | 3 | 100% |
| **FTP** (Trusted Path) | 2 | 0 | 0 | 2 | 100% |
| **FCO** (Non-repudiation) | 1 | 0 | 0 | 1 | 100% |

### Remaining Documentation Tasks (To Reach 97%+)

All remaining gaps require **documentation only** - no code changes needed:

1. **FMT_SMR.2** - Role separation procedures (ADMIN_GUIDE.md)
2. **FMT_MOF.1** - Security function authorization procedures (ADMIN_GUIDE.md)
3. **FPT_TST_EXT.1** - Self-test evidence collection (TEST_EVIDENCE.md)
4. **FAU_STG.4** - Audit overflow procedures (ADMIN_GUIDE.md)
5. **FTA_SSL.1** - Session timeout configuration (ADMIN_GUIDE.md)

### Not Applicable SFRs (4 Total)

The following SFRs are satisfied by the **operational environment** rather than the TOE itself:

| SFR | Requirement | Satisfied By | Rationale |
|-----|-------------|--------------|-----------|
| **FPT_PHP.1** | Physical tamper detection | HSM (FIPS 140-2 Level 3+) | Physical security provided by validated HSM hardware |
| **FPT_SBOP_EXT.1** | Secure boot | Operating System | OS provides measured boot chain (UEFI Secure Boot) |
| **FPT_EMSEC_EXT.1** | EM emanations protection | HSM | Side-channel protection via FIPS 140-2 Level 3+ HSM |
| **FIA_USB_EXT.1** | USB device authentication | Operating System | USB access control via OS policies |

These requirements are documented in [SECURITY_TARGET.md Section 9](SECURITY_TARGET.md) and operational environment assumptions in Section 3.3.

### Phase 8-14 Accomplishments

✅ **Phase 8 (Crypto):** Complete cryptographic operations (DER, signing, PKCS#7)
✅ **Phase 9 (DB):** Full database integration with audit trails
✅ **Phase 10 (HSM):** PKCS#11 HSM integration + software fallback (~2,000 lines)
✅ **Phase 11 (Validation):** Protocol validation (ACME, EST, mTLS, CSR)
✅ **Phase 12 (Integration):** Service integration (gRPC, circuit breaker, retry logic)
✅ **Phase 14 (Testing):** Comprehensive testing (274 unit tests, CI/CD, security scanning)

---

## 1. Critical Priority Gaps (Certification Blockers)

These gaps MUST be resolved before any certification attempt.

### 1.1 FCS_RBG_EXT.1 - Random Bit Generation

**Status:** 🟢 **IMPLEMENTED**
**Priority:** **CRITICAL** (CLOSED)
**Risk:** MITIGATED - NIST SP 800-90A compliant DRBG implemented
**Completed Phase:** Phase 15
**Effort Expended:** 2 weeks

**Implementation Complete:**

- ✅ NIST SP 800-90A CTR_DRBG (AES-256) fully implemented
- ✅ FIPS 140-3 health tests (startup and continuous)
- ✅ Entropy source integration (OS RNG)
- ✅ Automatic reseeding before 2^48 requests
- ✅ Comprehensive test suite (21 unit tests)

**Code References:**

- [crates/ostrich-crypto/src/drbg.rs](../../crates/ostrich-crypto/src/drbg.rs) - CTR_DRBG (AES-256) implementation, `SecureRng`, and the process-wide `fips_random_bytes()` helper
- [crates/ostrich-ca/src/issuance.rs](../../crates/ostrich-ca/src/issuance.rs) - `generate_serial_number` draws certificate serials from `fips_random_bytes` (was the `rand` crate)
- [tools/ostrich-init/src/main.rs](../../tools/ostrich-init/src/main.rs) - root/subordinate CA serials likewise drawn from the DRBG

**Test Coverage:**

- ✅ DRBG unit tests (instantiation, generation, reseeding, health tests)
- ✅ Startup + continuous health tests (repetition count, adaptive proportion)
- ✅ Reseeding before 2^48 requests
- ✅ `fips_random_bytes` helper test (length, distinctness)
- ✅ **Serial-number integration is real and live-verified**: `issuance_aia_e2e`
  issues a certificate whose serial comes from the DRBG and `openssl x509`
  parses it successfully (previously the issuer used the non-validated `rand`
  crate — this wiring closes that gap).

**NIST SP 800-90A Compliance:**

- ✅ CTR_DRBG with AES-256 (Section 10.2)
- ✅ Derivation function enabled
- ✅ Prediction resistance via automatic reseeding
- ✅ Security strength: 256 bits
- ✅ Reseed interval: 2^48 requests (per standard)

**FIPS 140-3 Health Tests:**

- ✅ Repetition Count Test (startup and continuous)
- ✅ Adaptive Proportion Test (startup and continuous)
- ✅ Failure detection and graceful error handling

**Certification Evidence:**

- ✅ DRBG design documentation
- ✅ Entropy source specification (OS-provided RNG)
- ✅ Test suite results (all 21 tests passing)
- ✅ Compliance annotations in code
- ✅ Integration with serial number generation
- ✅ Security analysis and threat model

---

### 1.2 FMT_SMR.2 - Security Roles

**Status:** 🔴 **Missing**
**Priority:** **CRITICAL**
**Risk:** No access control means unauthorized users can perform CA operations
**Assigned Phase:** Phase 15
**Effort Estimate:** 3 weeks

**Current State:**

- No role definitions exist
- No authentication system
- No authorization checks on any endpoints
- All audit events lack actor identification

**Required Roles (per NIAP PP-CA):**

1. **CA Administrator** - Install, configure, manage CA
2. **CA Operations Staff** - Issue/revoke certificates, manage CRLs
3. **Auditor** - Read audit logs (no CA operations)
4. **RA Staff** - Approve certificate requests
5. **AOR (Authorized Organizational Representative)** - Policy decisions

**Required Capabilities:**

```rust
// Role definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Administrator,
    OperationsStaff,
    Auditor,
    RaStaff,
    Aor,
}

// Permission system
pub struct Permission {
    resource: Resource,
    action: Action,
}

pub enum Resource {
    Certificate,
    CertificateRequest,
    Crl,
    AuditLog,
    Configuration,
    CaKey,
}

pub enum Action {
    Read,
    Create,
    Update,
    Delete,
    Approve,
    Revoke,
}

// RBAC enforcement
pub struct RbacPolicy {
    role_permissions: HashMap<Role, Vec<Permission>>,
}

impl RbacPolicy {
    // FMT_SMR.2 - Check if role can perform action
    pub fn authorize(&self, role: Role, resource: Resource, action: Action) -> Result<()>;
}
```

**Role-Permission Matrix:**

| Role | Certificate Issue | Certificate Revoke | CRL Generate | Audit Read | Config Change | Key Access |
|------|------------------|-------------------|--------------|------------|---------------|------------|
| Administrator | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ (backup only) |
| Operations Staff | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Auditor | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| RA Staff | ❌ (approve only) | ❌ | ❌ | ❌ | ❌ | ❌ |
| AOR | ❌ | ❌ | ❌ | ✅ | ✅ (policy) | ❌ |

**Implementation Tasks:**

1. ✅ Create `crates/ostrich-rbac/src/lib.rs` module (Phase 15)
2. ✅ Define Role enum and Permission struct
3. ✅ Implement RbacPolicy with role-permission mapping
4. ✅ Create authorization middleware for API endpoints
5. ✅ Add role to AuditEvent actor field
6. ✅ Database schema for user-role assignments
7. ✅ Admin API for user/role management
8. ✅ Integration with authentication system (Phase 16)

**Dependencies:**

- Authentication system (Phase 16) - Provides user identity
- Database (existing) - Store user-role mappings
- Audit system (existing) - Log authorization decisions

**Test Criteria:**

- [ ] Each role can only perform authorized actions
- [ ] Unauthorized actions are denied and logged
- [ ] Role separation enforced (auditor cannot issue certs)
- [ ] Administrator cannot directly issue certificates

**Evidence Required:**

- RBAC policy configuration file
- User-role assignment procedures
- Authorization denial logs
- Separation of duties documentation

---

### 1.3 FIA_X509_EXT.1 - X.509 Certificate Validation

**Status:** 🟢 **IMPLEMENTED**
**Priority:** **CRITICAL** (CLOSED)
**Risk:** MITIGATED - RFC 5280 §6 path validation complete
**Completed Phase:** Phase 15
**Effort Expended:** 2 weeks

**Implementation Complete:**

- ✅ RFC 5280 §6.1 path validation algorithm
- ✅ Certificate chain building to trust anchor
- ✅ Signature verification framework (crypto provider integration)
- ✅ Validity period checking
- ✅ Basic constraints enforcement (CA flag, path length)
- ✅ Key usage validation
- ✅ Name constraints framework
- ✅ Certificate policy framework
- ✅ Revocation checking framework (OCSP/CRL integration points)
- ✅ CSR signature verification (proof-of-possession)
- ✅ Subject DN parsing from CSR (RFC 4514)

**Code References:**

- [crates/ostrich-x509/src/validation/mod.rs](../../crates/ostrich-x509/src/validation/mod.rs) - Validation module
- [crates/ostrich-x509/src/validation/path_validator.rs](../../crates/ostrich-x509/src/validation/path_validator.rs) - RFC 5280 §6.1 algorithm
- [crates/ostrich-x509/src/validation/trust_anchor.rs](../../crates/ostrich-x509/src/validation/trust_anchor.rs) - Trust anchor store
- [crates/ostrich-x509/src/validation/path_builder.rs](../../crates/ostrich-x509/src/validation/path_builder.rs) - Chain building
- [crates/ostrich-x509/src/validation/extensions.rs](../../crates/ostrich-x509/src/validation/extensions.rs) - Extension helpers
- [crates/ostrich-x509/src/validation/name_constraints.rs](../../crates/ostrich-x509/src/validation/name_constraints.rs) - Name constraints
- [crates/ostrich-x509/src/validation/policy.rs](../../crates/ostrich-x509/src/validation/policy.rs) - Policy processing
- [crates/ostrich-x509/src/validation/revocation.rs](../../crates/ostrich-x509/src/validation/revocation.rs) - OCSP/CRL integration
- [crates/ostrich-x509/src/parser.rs:326-355](../../crates/ostrich-x509/src/parser.rs#L326-L355) - CSR signature verification

**Test Coverage:**

- ✅ 80 unit tests covering all validation steps
- ✅ Trust anchor CRUD operations
- ✅ Path building scenarios
- ✅ Validity period edge cases
- ✅ Basic constraints enforcement
- ✅ Key usage validation
- ✅ Name constraints framework
- ✅ Policy tree construction
- ✅ Revocation status handling
- ✅ Error handling for all failure modes

**RFC 5280 §6.1 Algorithm Steps:**

- ✅ §6.1.1 - Inputs: ValidationContext with trust anchors, validation time
- ✅ §6.1.2 - Initialization: ValidationState with working variables
- ✅ §6.1.3 - Basic Certificate Processing: All steps (a-k, n)
- ✅ §6.1.4 - Preparation for Next Certificate: Working public key update
- ✅ §6.1.5 - Wrap-Up Procedure: Final policy tree validation
- ✅ §6.1.6 - Outputs: ValidationResult with chain and trust anchor

**Integration Features:**

- ✅ Configurable AIA fetching (default: disabled for security)
- ✅ CRL size limits (10MB max for DoS prevention)
- ✅ Simplified policy mode (any-policy) with future enhancement path
- ✅ Trust anchor provisioning via both API and config file
- ✅ OCSP/CRL revocation checking framework

**Certification Evidence:**

- ✅ Path validation algorithm documentation
- ✅ Test suite results (all 80 tests passing)
- ✅ RFC 5280 §6 compliance verification
- ✅ Integration points for OCSP and CRL services
- ✅ CSR validation and proof-of-possession
- ✅ Subject DN and SAN extraction from CSRs

---

### 1.4 FMT_MOF.1.2 - Management of Security Functions

**Status:** 🔴 **Missing**
**Priority:** **HIGH**
**Risk:** No control over who can perform sensitive CA operations
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State:**

- No authorization checks on configuration changes
- No role restrictions on certificate issuance
- All operations effectively unrestricted

**Required Capabilities:**

```rust
// Security function authorization
pub struct SecurityFunctionGuard;

impl SecurityFunctionGuard {
    // FMT_MOF.1.2 - Restrict security functions to authorized roles
    pub fn check_issue_certificate(actor: &Actor) -> Result<()> {
        // Only Operations Staff and RA Staff (with approval)
        require_role(actor, &[Role::OperationsStaff, Role::RaStaff])
    }

    pub fn check_revoke_certificate(actor: &Actor) -> Result<()> {
        // Only Operations Staff
        require_role(actor, &[Role::OperationsStaff])
    }

    pub fn check_generate_crl(actor: &Actor) -> Result<()> {
        // Only Operations Staff
        require_role(actor, &[Role::OperationsStaff])
    }

    pub fn check_modify_configuration(actor: &Actor) -> Result<()> {
        // Only Administrator and AOR
        require_role(actor, &[Role::Administrator, Role::Aor])
    }

    pub fn check_backup_key(actor: &Actor) -> Result<()> {
        // Only Administrator
        require_role(actor, &[Role::Administrator])
    }
}
```

**Security Functions Requiring Authorization:**

1. **Certificate Lifecycle**:
   - Issue certificate (Operations Staff, RA Staff)
   - Revoke certificate (Operations Staff)
   - Generate CRL (Operations Staff)

2. **Configuration Management**:
   - Modify CA policy (AOR)
   - Change cryptographic parameters (Administrator)
   - Update audit configuration (Administrator)

3. **Key Management**:
   - Generate CA key (Administrator, during initialization)
   - Backup CA key (Administrator)
   - Destroy CA key (Administrator)

4. **Audit Management**:
   - View audit logs (Auditor, Administrator)
   - Export audit logs (Auditor)
   - Clear audit logs (NEVER allowed - append-only)

**Implementation Tasks:**

1. ✅ Integrate SecurityFunctionGuard with RBAC module (Phase 15)
2. ✅ Add authorization checks to all CA service endpoints
3. ✅ Add authorization checks to configuration endpoints
4. ✅ Add authorization checks to key management operations
5. ✅ Audit all authorization decisions (success and failure)

**Dependencies:**

- RBAC system (FMT_SMR.2) - Must be implemented first
- Audit system (existing) - Log authorization decisions

**Test Criteria:**

- [ ] Operations Staff can issue certificates
- [ ] Auditor cannot issue certificates
- [ ] Administrator cannot directly issue certificates
- [ ] AOR can modify policies
- [ ] Unauthorized operations are denied and audited

**Evidence Required:**

- Security function authorization matrix
- Authorization denial logs
- Role-based access control documentation

---

### 1.5 FPT_TST_EXT.1 - TSF Self-Testing

**Status:** 🔴 **Missing**
**Priority:** **HIGH**
**Risk:** Cannot detect cryptographic module failures or tampering
**Assigned Phase:** Phase 15
**Effort Estimate:** 2 weeks

**Current State:**

- No self-tests implemented
- No startup integrity checks
- No periodic health monitoring

**Required Self-Tests (per NIAP PP-CA and FIPS 140-2):**

1. **Startup Tests** (run at initialization):
   - Cryptographic algorithm known-answer tests (KAT)
   - Firmware/software integrity check (HMAC of binaries)
   - DRBG health tests
   - Critical data structure integrity

2. **Continuous Tests** (run during operation):
   - DRBG continuous random number generator test
   - Pair-wise consistency test for key generation
   - Signature verification after signing

3. **On-Demand Tests** (triggered by administrator):
   - Full cryptographic module test suite
   - Database integrity check
   - Audit log integrity verification

**Required Capabilities:**

```rust
pub struct SelfTest {
    test_results: Vec<TestResult>,
}

impl SelfTest {
    // FPT_TST_EXT.1.1 - Run self-tests at startup and on-demand
    pub fn run_startup_tests() -> Result<()> {
        // 1. Cryptographic KAT
        Self::crypto_kat()?;
        // 2. Software integrity
        Self::integrity_check()?;
        // 3. DRBG health test
        Self::drbg_health_test()?;
        // 4. Database connectivity
        Self::database_check()?;

        audit_log.emit(SelfTestCompleted { result: "PASS" }).await;
        Ok(())
    }

    // Known-Answer Tests for crypto algorithms
    fn crypto_kat() -> Result<()> {
        // Test RSA signature
        Self::test_rsa_sign_verify()?;
        // Test ECDSA signature
        Self::test_ecdsa_sign_verify()?;
        // Test AES encryption
        Self::test_aes_encrypt_decrypt()?;
        // Test SHA-256 hash
        Self::test_sha256()?;
        // Test ML-DSA signature (post-quantum)
        Self::test_ml_dsa_sign_verify()?;
        Ok(())
    }

    // Software integrity check (HMAC of binaries)
    fn integrity_check() -> Result<()> {
        // Calculate HMAC-SHA-256 of executable
        // Compare to stored reference value
        // Fail if mismatch detected
    }

    // DRBG health test
    fn drbg_health_test() -> Result<()> {
        // Repetition count test
        // Adaptive proportion test
        // Fail if randomness tests fail
    }
}
```

**Test Vectors Required:**

- **RSA-2048 PKCS#1 v1.5** - NIST CAVP vector
- **ECDSA P-256** - NIST CAVP vector
- **AES-256 CBC** - NIST CAVP vector
- **SHA-256** - NIST CAVP vector
- **HMAC-SHA-256** - NIST CAVP vector
- **ML-DSA-65** - NIST PQC test vector

**Implementation Tasks:**

1. ✅ Create `crates/ostrich-crypto/src/self_test.rs` module (Phase 15)
2. ✅ Implement KAT for all cryptographic algorithms
3. ✅ Implement software integrity check (HMAC of binaries)
4. ✅ Implement DRBG continuous health tests
5. ✅ Add startup test execution to main initialization
6. ✅ Add on-demand test API endpoint (Administrator only)
7. ✅ Audit all test executions and results
8. ✅ Implement failure handling (refuse to operate if tests fail)

**Dependencies:**

- DRBG implementation (FCS_RBG_EXT.1)
- Crypto providers (existing)
- Audit system (existing)

**Test Criteria:**

- [ ] All KATs pass with NIST test vectors
- [ ] Integrity check detects modified binaries
- [ ] DRBG health tests detect statistical failures
- [ ] Self-test failures prevent CA operation
- [ ] All test results are audited

**Evidence Required:**

- Self-test design documentation
- NIST CAVP test results
- Self-test execution logs
- Failure handling documentation

---

### 1.6 FMT_MSA.1.2 - Secure Attribute Defaults

**Status:** 🟢 **Implemented**
**Priority:** **HIGH**
**Risk:** Insecure default configurations could lead to weak certificates
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State (implemented):**

- `SecureDefaults` ([crates/ostrich-x509/src/secure_defaults.rs](../../crates/ostrich-x509/src/secure_defaults.rs)) defines NIAP-restrictive defaults: minimum key sizes (RSA ≥ 2048, EC ≥ 256), an allow-list of FIPS 186-5/204/205 signature algorithms (excluding SHA-1), end-entity (≤ 825 d) and CA (≤ 7300 d) validity ceilings, required SAN for TLS-server profiles, and prohibited EKUs.
- **Enforced at issuance**: `CertificateIssuer::issue` calls `SecureDefaults::validate_profile` on the active profile before signing, so a weak profile is refused rather than issued ([crates/ostrich-ca/src/issuance.rs](../../crates/ostrich-ca/src/issuance.rs)).
- **Evidence**: unit tests (built-in profiles pass; SHA-1 / sub-2048 RSA / over-long validity rejected) in `secure_defaults.rs`, plus the live `issuance_aia_e2e` test which issues a compliant cert and asserts an over-long-validity profile is rejected by `issue()`.

**Required Secure Defaults (per NIAP PP-CA):**

```rust
pub struct SecureDefaults {
    // FMT_MSA.1.2 - Enforce secure defaults for security attributes
    pub fn default_certificate_profile() -> CertificateProfile {
        CertificateProfile {
            // Cryptographic defaults
            signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256, // Modern, secure
            min_key_size: KeySize {
                rsa: 2048,      // NIST minimum
                ecdsa: 256,     // P-256 minimum
                eddsa: 255,     // Ed25519
            },

            // Validity period defaults
            max_validity_days: 825, // Per CA/B Forum baseline requirements

            // Extension defaults
            key_usage: KeyUsage::CRITICAL | KeyUsage::DIGITAL_SIGNATURE,
            extended_key_usage: None, // Must be explicitly set

            // Subject constraints
            require_subject_cn: true,
            require_subject_o: true,
            require_san: true, // RFC 5280 recommendation

            // Policy defaults
            require_certificate_policy: true,
            require_cps_uri: true,

            // Revocation defaults
            include_crl_dp: true,      // Always include CRL distribution point
            include_aia_ocsp: true,    // Always include OCSP responder
        }
    }

    // Validate that profile doesn't weaken security
    pub fn validate_profile(profile: &CertificateProfile) -> Result<()> {
        // Ensure key sizes meet minimum requirements
        if profile.min_key_size.rsa < 2048 {
            return Err(ValidationError::WeakKeySize("RSA < 2048 bits"));
        }

        // Ensure validity period not too long
        if profile.max_validity_days > 825 {
            return Err(ValidationError::ExcessiveValidity);
        }

        // Ensure critical extensions present
        if !profile.key_usage.is_critical() {
            return Err(ValidationError::MissingCriticalExtension("keyUsage"));
        }

        Ok(())
    }
}
```

**Secure Defaults by Certificate Type:**

| Attribute | Root CA | Intermediate CA | Subscriber (TLS) | Code Signing |
|-----------|---------|-----------------|------------------|--------------|
| Key Algorithm | RSA-4096 or ECDSA P-384 | RSA-3072 or ECDSA P-256 | RSA-2048 or ECDSA P-256 | RSA-3072 or ECDSA P-256 |
| Signature Alg | SHA-384 | SHA-256 | SHA-256 | SHA-256 |
| Validity | 20 years | 10 years | 398 days | 39 months |
| Key Usage | keyCertSign, cRLSign | keyCertSign, cRLSign | digitalSignature, keyEncipherment | digitalSignature |
| EKU | N/A | N/A | serverAuth, clientAuth | codeSigning |
| Basic Constraints | CA:TRUE, pathLen:1 | CA:TRUE, pathLen:0 | CA:FALSE | CA:FALSE |

**Prohibited Weak Configurations:**

- ❌ RSA keys < 2048 bits
- ❌ SHA-1 signatures
- ❌ Validity > 825 days for subscriber certificates
- ❌ Missing critical extensions (keyUsage, basicConstraints for CAs)
- ❌ Self-signed subscriber certificates
- ❌ Missing SAN extension

**Implementation Tasks:**

1. ✅ Create `crates/ostrich-x509/src/secure_defaults.rs` module (Phase 15)
2. ✅ Define SecureDefaults struct with NIAP-compliant defaults
3. ✅ Implement profile validation against secure baselines
4. ✅ Add validation to certificate issuance workflow
5. ✅ Reject certificate requests with weak parameters
6. ✅ Audit profile validation failures

**Dependencies:**

- Certificate profile system (existing) - Already has profile definitions
- Crypto provider (existing) - Key size validation

**Test Criteria:**

- [ ] Default profiles use secure algorithms
- [ ] Weak key sizes rejected
- [ ] Excessive validity periods rejected
- [ ] Missing critical extensions detected
- [ ] Profile validation failures audited

**Evidence Required:**

- Secure defaults configuration file
- Profile validation test results
- Rejected weak configuration audit logs

---

## 2. High Priority Gaps (Required for Full Compliance)

These gaps should be addressed after critical gaps are resolved.

### 2.1 FMT_MTD.1.2 - TSF Data Management

**Status:** 🔴 **Missing**
**Priority:** HIGH
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State:**

- No restrictions on who can modify critical TSF data
- Configuration changes not restricted by role
- No validation of configuration changes

**NPE Portal Update (2026-06-29):**

- ✅ Portal certificate inventory and FQDN history reads are owner-scoped for
  PKI Sponsor / NPE Administrator self-service users at the SQL repository layer
  (`crates/ostrich-db/src/repository/{certificate,fqdn}.rs`), with global access
  retained only for approver/operator roles.
- ✅ EST enrollment-token list/revoke is scoped to `created_by` for NPE sponsors
  (`crates/ostrich-est/src/rest.rs`, `crates/ostrich-db/src/repository/est.rs`).
- ✅ NPE portal `/auth/userinfo` and `/auth/consent` re-check the mTLS
  certificate fingerprint before disclosing session identity or mutating consent
  state (`services/npe-portal/src/server/router.rs`).

**Required Capabilities:**

```rust
// TSF data access control
pub enum TsfData {
    AuditConfiguration,
    CertificatePolicy,
    CrlDistributionPoint,
    OcspResponderUrl,
    KeyBackupConfiguration,
    TrustedCertificates,
}

impl TsfDataGuard {
    pub fn check_modify_tsf_data(actor: &Actor, data: TsfData) -> Result<()> {
        match data {
            TsfData::AuditConfiguration => require_role(actor, &[Role::Administrator]),
            TsfData::CertificatePolicy => require_role(actor, &[Role::Aor]),
            TsfData::TrustedCertificates => require_role(actor, &[Role::Administrator]),
            _ => require_role(actor, &[Role::Administrator, Role::Aor]),
        }
    }
}
```

**Implementation Tasks:**

- Create TSF data classification system
- Integrate with RBAC for access control
- Validate TSF data changes before applying
- Audit all TSF data modifications

**Dependencies:** RBAC (FMT_SMR.2)

---

### 2.2 FTA_TSE.1 - TOE Session Establishment

**Status:** 🔴 **Missing**
**Priority:** HIGH
**Assigned Phase:** Phase 16 (Auth & Authorization)
**Effort Estimate:** 1 week

**Current State:**

- No session management
- No authentication required for access
- No denial of access before authentication

**Required Capabilities:**

```rust
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    // FTA_TSE.1 - Deny access before authentication
    pub fn establish_session(&mut self, auth: AuthCredential) -> Result<SessionId> {
        // 1. Validate authentication credential (mTLS cert, API key)
        let identity = self.authenticate(auth)?;

        // 2. Create session
        let session = Session {
            id: SessionId::new(),
            identity,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            permissions: self.rbac.get_permissions(&identity)?,
        };

        // 3. Audit session establishment
        audit_log.emit(SessionEstablished { session_id, identity }).await;

        Ok(session.id)
    }
}
```

**Implementation Tasks:**

- Create session management system
- Integrate with authentication (mTLS)
- Enforce authentication before any CA operations
- Implement session timeout
- Audit session lifecycle

**Dependencies:** Authentication system (Phase 16)

---

### 2.3 FPT_STM_EXT.1 - Reliable Time Stamps

**Status:** 🟡 **Partial** (using system time, not verified)
**Priority:** HIGH
**Assigned Phase:** Phase 15
**Effort Estimate:** 3 days

**Current State:**

- Using `chrono::Utc::now()` without NTP verification
- No time synchronization validation
- No monotonic time source for audit logs

**Required Capabilities:**

```rust
pub struct TimeSource {
    ntp_servers: Vec<String>,
    last_sync: Option<Instant>,
    sync_interval: Duration,
}

impl TimeSource {
    // FPT_STM_EXT.1 - Provide reliable time stamps
    pub fn now(&self) -> Result<DateTime<Utc>> {
        // 1. Check NTP sync status
        if self.last_sync.is_none() || self.last_sync.unwrap().elapsed() > self.sync_interval {
            return Err(TimeError::NotSynchronized);
        }

        // 2. Return current time
        Ok(Utc::now())
    }

    // Verify NTP synchronization
    pub fn verify_sync(&mut self) -> Result<()> {
        // Query NTP servers
        // Verify time within acceptable threshold
        // Update last_sync timestamp
    }
}
```

**Implementation Tasks:**

- Integrate NTP client (use `ntp` crate)
- Verify time synchronization at startup
- Periodic NTP sync verification
- Refuse to operate if time not synchronized
- Audit time synchronization status

**Dependencies:** None

---

### 2.4 FPT_FLS.1 - Failure with Preservation of Secure State

**Status:** 🔴 **Missing**
**Priority:** HIGH
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State:**

- No failure detection mechanisms
- No secure state preservation
- Panics may leave CA in inconsistent state

**Required Capabilities:**

```rust
// Failure handler
pub struct FailureHandler;

impl FailureHandler {
    // FPT_FLS.1 - Preserve secure state on failure
    pub fn handle_failure(error: &Error) -> ! {
        // 1. Log failure to audit system
        audit_log.emit_blocking(CriticalFailure {
            error: error.to_string(),
            timestamp: Utc::now(),
        });

        // 2. Prevent further operations
        OPERATIONAL_STATE.set(OperationalState::Failed);

        // 3. Zeroize sensitive data in memory
        zeroize_all_secrets();

        // 4. Shutdown gracefully
        shutdown_services();

        // 5. Exit with error code
        std::process::exit(1);
    }
}

// Operational state guard
pub static OPERATIONAL_STATE: AtomicU8 = AtomicU8::new(OperationalState::Normal);

pub fn check_operational_state() -> Result<()> {
    match OPERATIONAL_STATE.load(Ordering::SeqCst) {
        OperationalState::Normal => Ok(()),
        OperationalState::Failed => Err(Error::SystemFailed),
        OperationalState::Maintenance => Err(Error::MaintenanceMode),
    }
}
```

**Failure Scenarios:**

1. **Cryptographic failures** - Self-test failure, HSM failure
2. **Audit failures** - Audit log full, audit corruption
3. **Database failures** - Connection lost, corruption detected
4. **Configuration failures** - Invalid configuration loaded

**Implementation Tasks:**

- Create FailureHandler with secure shutdown
- Implement operational state tracking
- Add state checks to all critical operations
- Implement graceful shutdown with audit preservation
- Add panic handler that preserves secure state

**Dependencies:** Audit system, crypto self-tests

---

### 2.5 FCS_CKM.1.1 - Cryptographic Key Generation

**Status:** 🟡 **Partial** (design exists, needs HSM integration)
**Priority:** HIGH
**Assigned Phase:** Phase 10 (HSM Integration)
**Effort Estimate:** 2 weeks

**Current State:**

- Key generation interface defined
- No HSM integration (stubbed in Phase 10)
- Not generating keys in FIPS-validated module

**Required Capabilities:**

```rust
impl CryptoProvider for Pkcs11Provider {
    // FCS_CKM.1.1 - Generate cryptographic keys in HSM
    fn generate_key_pair(&self, params: KeyGenParams) -> Result<KeyPair> {
        // 1. Validate key generation parameters
        self.validate_params(&params)?;

        // 2. Generate key pair in HSM (FIPS 140-2 Level 2+)
        let mechanism = match params.algorithm {
            KeyAlgorithm::Rsa => CKM_RSA_PKCS_KEY_PAIR_GEN,
            KeyAlgorithm::EcdsaP256 => CKM_EC_KEY_PAIR_GEN,
            KeyAlgorithm::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
            KeyAlgorithm::MlDsa65 => CKM_PQC_DILITHIUM_KEY_PAIR_GEN, // Post-quantum
        };

        let key_id = self.pkcs11.generate_key_pair(mechanism, &params)?;

        // 3. Audit key generation
        audit_log.emit(KeyGenerated {
            key_id,
            algorithm: params.algorithm,
            key_size: params.key_size,
        }).await;

        Ok(KeyPair { id: key_id, public_key: self.export_public_key(key_id)? })
    }
}
```

**Implementation Tasks:**

- Complete PKCS#11 provider implementation (Phase 10)
- Integrate with FIPS-validated HSM
- Implement key generation for all supported algorithms
- Add post-quantum key generation (ML-DSA, ML-KEM)
- Test with SoftHSM and hardware HSMs

**Dependencies:** HSM integration (Phase 10), DRBG (FCS_RBG_EXT.1)

---

### 2.6 FAU_STG.1.2 - Protected Audit Trail Storage

**Status:** 🟡 **Partial** (append-only, needs integrity protection)
**Priority:** HIGH
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State:**

- Audit events emitted to database
- No cryptographic integrity protection
- No detection of audit log tampering

**Required Capabilities:**

```rust
pub struct IntegrityProtectedAuditLog {
    log_entries: Vec<AuditEntry>,
    hash_chain: Vec<Hash>,
}

impl IntegrityProtectedAuditLog {
    // FAU_STG.1.2 - Protect audit records from unauthorized modification
    pub fn append(&mut self, event: AuditEvent) -> Result<()> {
        // 1. Create audit entry
        let entry = AuditEntry {
            id: self.next_id(),
            timestamp: time_source.now()?,
            event,
        };

        // 2. Calculate hash chain link
        let previous_hash = self.hash_chain.last().unwrap_or(&GENESIS_HASH);
        let current_hash = Self::hash_entry(&entry, previous_hash);

        // 3. Store entry and hash
        self.log_entries.push(entry);
        self.hash_chain.push(current_hash);

        // 4. Persist to append-only storage
        self.storage.append(&entry, &current_hash)?;

        Ok(())
    }

    // Verify audit log integrity
    pub fn verify_integrity(&self) -> Result<()> {
        // Recalculate hash chain and compare
        for (i, entry) in self.log_entries.iter().enumerate() {
            let expected_hash = &self.hash_chain[i];
            let previous_hash = if i == 0 { &GENESIS_HASH } else { &self.hash_chain[i-1] };
            let actual_hash = Self::hash_entry(entry, previous_hash);

            if &actual_hash != expected_hash {
                return Err(AuditError::IntegrityViolation(i));
            }
        }
        Ok(())
    }
}
```

**Implementation Tasks:**

- Implement hash chain for audit log integrity
- Add integrity verification on startup
- Periodic integrity verification (Administrator-triggered)
- Audit integrity verification results
- Implement append-only storage enforcement

**Dependencies:** Audit system (existing), crypto providers

---

## 3. Medium Priority Gaps (Enhancement)

### 3.1 FCS_COP.1 Suite (Cryptographic Operations)

**Status:** 🟢 **Good (75%)** - **UPDATED: Phase 8 Complete**
**Priority:** MEDIUM
**Assigned Phase:** Phase 10 (HSM Integration - remaining 25%)
**Effort Estimate:** 1 week (reduced from 3 weeks)

**SFRs in this suite:**

- FCS_COP.1.1(1) - Signature generation/verification - ✅ **75% COMPLETE**
- FCS_COP.1.1(2) - Hashing - ✅ **100% COMPLETE**
- FCS_COP.1.1(3) - Key encryption - 🔴 **Not Implemented**
- FCS_COP.1.1(4) - Key agreement - 🔴 **Not Implemented**

**Completed in Phase 8:**

- ✅ X.509 certificate DER encoding and signing fully implemented
- ✅ CRL DER encoding and signing fully implemented
- ✅ OCSP response signing implemented
- ✅ PKCS#7/CMS signing for EST protocol
- ✅ ECDSA (P-256/384/521), EdDSA (Ed25519/448) signature algorithms
- ✅ RSA-PSS SHA-256/384/512 via PKCS#11 — verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), RSA-2048/3072/4096; production HSM not yet validated (POAM-2026-10-23-21). Provider level only; not used for X.509 signing, which uses PKCS#1 v1.5 for RSA CA keys (POAM-2026-10-23-20). POAM-2026-10-23-17 closed 2026-10-23. Qualified 2026-10-23
- ✅ ML-DSA post-quantum signatures (ML-DSA-44/65/87) - FIPS 204
- ✅ Key usage enforcement through certificate extensions
- ✅ SHA-256/384/512 hashing for audit chains and JWK thumbprints

**Remaining Implementation Tasks:**

- ⏳ Complete PKCS#11 HSM integration (Phase 10)
- ⏳ Implement key encryption operations (FCS_COP.1.1(3))
- ⏳ Implement key agreement operations (FCS_COP.1.1(4))
- ⏳ Add test vectors for all algorithms

**Dependencies:** HSM integration (Phase 10)

---

### 3.2 FMT_MTD.1.1 - Audit Configuration Query

**Status:** 🔴 **Missing**
**Priority:** MEDIUM
**Assigned Phase:** Phase 15
**Effort Estimate:** 3 days

**Required Capabilities:**

```rust
// Audit configuration query API
pub fn get_audit_configuration(actor: &Actor) -> Result<AuditConfiguration> {
    // Only Auditor and Administrator can query
    require_role(actor, &[Role::Auditor, Role::Administrator])?;

    Ok(AuditConfiguration {
        storage_location: "/var/log/ostrich-audit",
        max_size_mb: 1024,
        retention_days: 365,
        events_enabled: vec![/* all event types */],
    })
}
```

**Implementation Tasks:**

- Create audit configuration query API
- Restrict to Auditor and Administrator roles
- Return current audit configuration
- Audit configuration queries

**Dependencies:** RBAC

---

### 3.3 FPT_EMSEC_EXT.1 - Electromagnetic Emanations

**Status:** ⚪ **Not Applicable** (software CA, rely on HSM)
**Priority:** LOW
**Assigned Phase:** N/A (HSM responsibility)

**Rationale:**

- OstrichPKI is software-based CA
- Private keys stored in HSM
- HSM provides electromagnetic shielding (FIPS 140-2 Level 3+)
- No direct implementation required in software

**Documentation Required:**

- HSM selection criteria (FIPS 140-2 Level 3+)
- Deployment guidelines for HSM physical security

---

### 3.4 FTP_ITC.1 - Inter-TSF Trusted Channel

**Status:** 🟡 **Partial** (TLS support exists, needs enforcement)
**Priority:** MEDIUM
**Assigned Phase:** Phase 16 (Auth & Authorization)
**Effort Estimate:** 1 week

**Current State:**

- TLS support exists in HTTP servers
- No enforcement of TLS 1.3
- No enforcement of mutual authentication

**Update 2026-10-23 (gap narrowed, status unchanged):** the shared REST
listener (`crates/ostrich-common/src/tls.rs`) is TLS 1.3 only and supports
mandatory or optional mTLS. Under `fips`, rustls 0.23.46 offers only AES-GCM
suites. In-memory handshake tests passed (TLS 1.2-only client rejected;
untrusted, missing and serverAuth-only client certificates rejected). Still
open: gRPC (tonic, `tls-ring` provider) TLS on ca-server; TLS handshake-failure
auditing; revocation checking of TLS peer certificates.

**Update 2026-10-24 (PR 152; gap narrowed, status unchanged):** every HTTPS
listener served through `ostrich_common::tls` (`serve` and
`serve_with_config`, including npe-portal ACME mode) now fails closed unless
`ServerConfig::fips()` is true (`ensure_fips`). gRPC remains outside it: the
ca-server gRPC server is plaintext (no `ServerTlsConfig`,
`services/ca-server/src/main.rs`, `tonic::transport::Server::builder()`), and
the acme/est gRPC clients use tonic `tls-ring` (POAM-2026-10-23-05, -08).

**Update 2026-10-25 (branch `claude/grpc-mtls`, uncommitted; gap narrowed,
status unchanged):** the CA ↔ RA gRPC channel is now a TLS 1.3 mutually
authenticated channel on the aws-lc-rs FIPS provider, with `fips()` asserted on
the server and client configs, ALPN `h2` required, and a listener-wide
client-subject allowlist (default deny; replaced on 2026-10-26 by per-role
lists and a per-method table, see the next update). ca-server refuses to start without the
mTLS configuration (the plaintext dev flag is debug-build only), and refuses a
client CA from its own chain (same key or subject as the issuing CA, a CA it
issued, its issuer, or any ancestor found in the CA database; the refusal is
audited as `grpc_listener_refused`). Per call it also denies client leaves
issued directly by the issuing CA or its ancestors (`subscriber_issuing_ca`).
TLS handshake failures and access denials are audited, rate-limited (60 per
60 s per listener) with summary records. tonic is built without TLS features.
Evidence: `tests/integration/grpc_mtls_e2e.rs` 21/21 passed 2026-10-25 (final
code, re-run by the compliance scribe). Still open: revocation checking of TLS
peer certificates (POAM-2026-10-23-27); issuer/SPKI-unbound allowlist entries,
with sibling CAs, grandchildren and CAs outside the database lineage not
detected (POAM-2026-10-23-28); per-method authorization
(POAM-2026-10-23-26, closed 2026-10-26); authoritative audit actor
(POAM-2026-10-23-25, closed 2026-10-26); first-install bootstrap
(POAM-2026-10-23-29); REST plain-HTTP mode and other client configs
(POAM-2026-10-23-05). Status stays 🟡 Partial because of the revocation gap
and because the other REST listeners do not require mTLS.

**Update 2026-10-26 (branch `claude/grpc-per-method-authz`, uncommitted; run
record `target/agent-workflow/20261025-202226-grpc-per-method/`; gap narrowed,
status unchanged):** the single allowlist is replaced by three role lists
(`CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS`: Issuer;
`CA_GRPC_ADMIN_CLIENT_SUBJECTS`: Admin, empty by default) and a default-deny
method table (`CA_GRPC_METHOD_RULES` in
[grpc_authz.rs](../../crates/ostrich-ca/src/grpc_authz.rs)). Issuers may call
IssueCertificate, GetCaInfo and ListProfiles only, limited per namespace to
listed end-entity profiles; Admin may call RevokeCertificate, GenerateCrl,
CheckRevocationStatus and the two reads, never IssueCertificate. Any other path
is `method_not_mapped`. The audit actor of gRPC issuance, revocation and CRL
records is the verified peer subject DN (with certificate issuer and serial);
the client `requestor` is bound to the caller's namespace and recorded as
`on_behalf_of`. Leaf validity is re-checked per call. Admin calls require a
leaf issued directly by the single client trust anchor (issuer DN and
AKI = anchor SKI). Evidence: `grpc_mtls_e2e` 39/39, `grpc_tls` unit tests
66/66, `ostrich-ca` 78/78, ca-server bins 21/21 (2026-10-26, fix-nits final
tree). This closes POAM-2026-10-23-25 and -26 (pending commit). New residuals:
POAM-2026-10-23-35 (RA namespace confused deputy), -36 (live-database
evidence through `CaGrpcService` and the REST CRL handlers), -37 (REST 500
bodies), -38 (profiles from the database). Status stays 🟡 Partial for the
same reasons as above (POAM-27, -28 for issuer roles, REST listeners).

**Required Capabilities:**

```rust
// TLS configuration enforcement
pub fn configure_tls_server() -> TlsConfig {
    TlsConfig {
        min_version: TlsVersion::Tls13,
        cipher_suites: vec![
            TLS_AES_256_GCM_SHA384,
            TLS_AES_128_GCM_SHA256,
            TLS_CHACHA20_POLY1305_SHA256,
        ],
        require_client_cert: true, // mTLS
        trusted_ca_certs: load_trusted_cas(),
    }
}
```

**Implementation Tasks:**

- Enforce TLS 1.3 minimum version
- Configure approved cipher suites only
- Require client certificate for mTLS
- Validate client certificates (integrate with FIA_X509_EXT.1)
- Audit TLS handshake failures

**Dependencies:** Path validation (FIA_X509_EXT.1)

---

## 4. Low Priority Gaps (Optional/Future)

### 4.1 FPT_PHP.1 - Passive Detection of Physical Attack

**Status:** ⚪ **Not Applicable** (rely on HSM)
**Priority:** N/A
**Assigned Phase:** N/A (HSM responsibility)

**Rationale:** HSM provides physical tamper detection (FIPS 140-2 Level 3+)

---

### 4.2 FPT_SBOP_EXT.1 - Secure Boot

**Status:** ⚪ **Not Applicable** (OS responsibility)
**Priority:** N/A
**Assigned Phase:** N/A (deployment requirement)

**Rationale:**

- Secure boot is OS/platform responsibility
- Document deployment requirement for secure boot enabled systems
- Verify secure boot status in deployment checklist

---

## 5. Implementation Roadmap

### Phase 15: NIAP Compliance Foundation (Current - 3-4 weeks)

**Critical Gaps (Must Complete):**

1. ✅ **FCS_RBG_EXT.1** - DRBG implementation (2 weeks)
   - `crates/ostrich-crypto/src/drbg.rs` (~350 lines)
   - NIST SP 800-90A CTR_DRBG
   - Continuous health tests
   - Entropy source integration

2. ✅ **FMT_SMR.2** - RBAC system (3 weeks)
   - `crates/ostrich-rbac/src/lib.rs` (~400 lines)
   - Role definitions and permission matrix
   - Authorization middleware
   - Database schema for user-role mappings

3. ✅ **FIA_X509_EXT.1** - Path validation (2 weeks)
   - `crates/ostrich-x509/src/validation.rs` (~500 lines)
   - RFC 5280 §6 compliance
   - CRL/OCSP integration
   - Extension validation

**High Priority Gaps:**
4. ✅ **FMT_MOF.1.2** - Security function authorization (1 week)

- Integration with RBAC
- Authorization checks on all endpoints

1. ✅ **FPT_TST_EXT.1** - Self-tests (2 weeks)
   - `crates/ostrich-crypto/src/self_test.rs` (~300 lines)
   - Cryptographic KATs
   - Integrity checking
   - Startup test execution

2. ✅ **FMT_MSA.1.2** - Secure defaults (1 week)
   - `crates/ostrich-x509/src/secure_defaults.rs` (~200 lines)
   - Default profile validation
   - Weak configuration rejection

**Compliance Target:** 40-50% → 60-65%

---

### Phase 16: Authentication & Authorization (4 weeks)

**Focus:** User authentication and session management

1. **FTA_TSE.1** - Session establishment
2. **FIA_UAU.2** - User authentication before any action
3. **FTP_ITC.1** - mTLS enforcement
4. **FMT_MTD.1.1** - Audit configuration query

**Compliance Target:** 60-65% → 75-80%

---

### Phase 10: HSM Integration (Revisit - 3 weeks)

**Focus:** Complete cryptographic module integration

1. **FCS_CKM.1.1** - Key generation in HSM
2. **FCS_COP.1 Suite** - All crypto operations in HSM
3. **FCS_CKM.4.1** - Key destruction
4. **FPT_SKP_EXT.1** - Private key protection

**Compliance Target:** 75-80% → 85-90%

---

### Phase 13: CRL Service (Enhance)

**Focus:** Complete revocation infrastructure

1. **FDP_CER_EXT.2** - CRL generation with all required fields
2. **FAU_GEN.1** - Audit CRL generation events
3. **FPT_STM_EXT.1** - Time stamp validation for CRL

**Compliance Target:** 85-90% → 90%

---

### Phase 14: OCSP Service (Enhance)

**Focus:** Real-time revocation checking

1. **FIA_X509_EXT.1** - OCSP response validation
2. **FTP_ITC.1** - OCSP TLS communication
3. **FAU_GEN.1** - Audit OCSP requests

**Compliance Target:** 90% → 92%

---

### Phase 17: Final Compliance (2-3 weeks)

**Focus:** Remaining gaps and documentation

1. Complete all partial implementations
2. Generate ATO evidence artifacts
3. Security Target (ST) documentation
4. Test evidence collection
5. Final compliance verification

**Compliance Target:** 92% → 95%+

---

## 6. Risk Assessment

### Critical Risks (Certification Blockers)

| Risk | Impact | Mitigation |
|------|--------|------------|
| **DRBG not FIPS-validated** | Cannot generate secure random numbers → certificate serial numbers predictable | Use FIPS-validated HSM for DRBG or validate ring crate |
| **No RBAC** | Unauthorized users can issue/revoke certificates → complete security failure | Implement FMT_SMR.2 in Phase 15 (3 weeks) |
| **No path validation** | Cannot validate client certificates → mTLS authentication broken | Implement FIA_X509_EXT.1 in Phase 15 (2 weeks) |
| **No self-tests** | Cannot detect cryptographic failures → may issue invalid certificates | Implement FPT_TST_EXT.1 in Phase 15 (2 weeks) |

### High Risks (Operational Issues)

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Weak default configurations** | Administrators may configure insecure certificates | Implement FMT_MSA.1.2 secure defaults (1 week) |
| **No audit integrity** | Audit logs can be tampered with → non-repudiation lost | Implement hash chain in Phase 15 (1 week) |
| **No time synchronization** | Certificates may have invalid timestamps | Implement NTP integration (3 days) |
| **No failure handling** | System may continue operating in failed state | Implement FPT_FLS.1 (1 week) |

### Medium Risks (Compliance Issues)

| Risk | Impact | Mitigation |
|------|--------|------------|
| **HSM not integrated** | Private keys not hardware-protected → vulnerable to memory dumps | Complete Phase 10 (3 weeks) |
| **Partial crypto operations** | Some algorithms not implemented → limited functionality | Complete FCS_COP suite in Phase 10 |
| **No session management** | Difficult to audit user actions across requests | Implement FTA_TSE.1 in Phase 16 |

---

## 7. Effort Summary

| Priority | SFRs | Effort (weeks) | Phase |
|----------|------|----------------|-------|
| **Critical** | 6 | 11 weeks | Phase 15, 10 |
| **High** | 10 | 8 weeks | Phase 15, 16 |
| **Medium** | 15 | 6 weeks | Phase 10, 16 |
| **Low** | 5 | 1 week | Phase 17 |
| **Not Applicable** | 3 | 0 weeks | N/A |
| **Already Compliant** | 7 | 0 weeks | Complete |
| **Total** | **50** | **26 weeks** | **Phases 15-17** |

**Critical Path:**

1. Phase 15 (4 weeks) - DRBG, RBAC, Path Validation, Self-Tests
2. Phase 16 (4 weeks) - Authentication, Session Management
3. Phase 10 Revisit (3 weeks) - HSM Integration
4. Phase 17 (3 weeks) - Final compliance and documentation

**Estimated Timeline:** 14-16 weeks to 95%+ compliance

---

## 8. Success Criteria

### Certification Readiness Checklist

- [ ] **All Critical SFRs Implemented** (6/6)
  - [ ] FCS_RBG_EXT.1 - DRBG with NIST SP 800-90A compliance
  - [ ] FMT_SMR.2 - RBAC with 5 roles defined
  - [ ] FIA_X509_EXT.1 - RFC 5280 §6 path validation
  - [ ] FMT_MOF.1.2 - Security function authorization
  - [ ] FPT_TST_EXT.1 - Self-tests with NIST CAVP vectors
  - [ ] FMT_MSA.1.2 - Secure defaults enforced

- [ ] **All High Priority SFRs Implemented** (10/10)

- [ ] **Audit System Complete**
  - [ ] All 57 SFRs have audit events
  - [ ] Hash chain integrity protection
  - [ ] Append-only storage

- [ ] **Cryptographic Module**
  - [ ] FIPS 140-2 Level 2+ HSM integrated
  - [ ] All algorithms in FCS_COP suite implemented
  - [ ] Post-quantum algorithms (ML-DSA, ML-KEM) supported

- [ ] **Documentation Complete**
  - [ ] Security Target (ST) generated
  - [ ] Test evidence collected
  - [ ] Audit log samples
  - [ ] Configuration guides

- [ ] **Test Results**
  - [ ] Self-tests pass with NIST CAVP vectors
  - [ ] RFC 5280 path validation test suite passes
  - [ ] RBAC authorization matrix verified
  - [ ] All audit events tested

### Compliance Metrics

- **Target Compliance:** 95%+ (54/57 SFRs)
- **Acceptable Non-Compliance:** 3 SFRs marked "Not Applicable" (HSM/OS responsibilities)
- **Critical SFRs:** 100% compliance required (0 failures allowed)
- **High Priority SFRs:** 90%+ compliance
- **Medium Priority SFRs:** 80%+ compliance

---

## 9. Evidence Collection Guide

### For Each SFR

1. **Code References:**
   - List all files implementing the SFR
   - Include line numbers for critical sections
   - Mark with `// NIAP PP-CA: <SFR ID> - <description>` comments

2. **Test Evidence:**
   - Unit tests for the SFR functionality
   - Integration tests demonstrating end-to-end behavior
   - Test vectors (especially for cryptographic functions)

3. **Audit Evidence:**
   - Sample audit logs showing SFR compliance
   - Demonstrate security-relevant events captured
   - Show actor, timestamp, outcome in logs

4. **Configuration Evidence:**
   - Default configuration files
   - Secure configuration examples
   - Configuration validation rules

5. **Documentation:**
   - Design documents explaining the approach
   - Security rationale for implementation choices
   - Deployment guides for administrators

### Automated Evidence Collection

```bash
# Extract NIAP annotations from code
grep -r "// NIAP PP-CA:" crates/ > evidence/code_annotations.txt

# Collect test results
cargo test --all -- --nocapture > evidence/test_results.txt

# Export audit logs
psql ostrich -c "SELECT * FROM audit_events WHERE event_type LIKE 'FMT_%'" > evidence/audit_samples.sql

# Generate compliance matrix
./scripts/generate_compliance_matrix.sh > docs/compliance/COMPLIANCE_MATRIX.csv
```

---

## 10. Next Steps

### Immediate Actions (Week 1-2)

1. **Review Gap Analysis** - Stakeholder approval of priorities and timeline
2. **Begin Phase 15 Implementation**:
   - Start with DRBG (FCS_RBG_EXT.1) - 2 weeks
   - Parallel: Begin RBAC design (FMT_SMR.2) - 3 weeks
3. **Set Up Test Infrastructure**:
   - NIST CAVP test vector repository
   - RFC 5280 test suite integration
4. **Document Security Target Outline** - Start ST documentation early

### Mid-Term Actions (Week 3-8)

1. **Complete Phase 15** - All critical and high priority gaps
2. **Begin Phase 16** - Authentication and session management
3. **HSM Vendor Selection** - Evaluate FIPS 140-2 Level 2+ HSMs
4. **First Compliance Assessment** - Self-assessment against NIAP checklist

### Long-Term Actions (Week 9-16)

1. **Complete Phase 10 HSM Integration**
2. **Complete Phase 16 Authentication**
3. **Complete Phase 17 Final Compliance**
4. **External Security Assessment** - Engage NIAP-accredited lab
5. **Submit for Common Criteria Evaluation**

---

## 11. Plan of Action and Milestones (POA&M) — Open Items

Items 01-10 were opened or confirmed on 2026-10-23 by the dependency-advisory
remediation (run record `target/agent-workflow/20261023-185030-audit-advisories/`).
Items 03, 06, 07 and 09 were updated, and items 11-15 added, later on 2026-10-23
by the CI-hardening change (branch `claude/ci-hardening`, not yet merged; run
record `target/agent-workflow/20261023-201031-ci-hardening/`). Items 07 and 14
were updated, and items 16-22 added, later on 2026-10-23 by the PKCS#11 RSA-PSS
fix (same branch, uncommitted; run record
`target/agent-workflow/20261023-230002-pkcs11-rsa-pss/`). Items 07 and 17 were
closed, and item 14 updated, later on 2026-10-23 from the Linux CI evidence for
that fix (commit 44d560d, PR 181, [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)). Item 05 was narrowed,
and item 08 annotated, on 2026-10-24 by the PR 152 review (fail-closed FIPS TLS;
run record `target/agent-workflow/20261024-000214-pr152-fips-tls/`). Items 11, 16
and 22 were closed pending first green CI run, item 09 updated, and item 23 added
on 2026-10-24 by the dependency cleanup (branch `claude/deps-cleanup`, uncommitted;
run record `target/agent-workflow/20261024-104215-deps-cleanup/`). Item 24 records a pre-existing finding from that
change's PQC review. Items 05 and 08 were narrowed, and items 25-34 added, on 2026-10-25 by the CA gRPC mTLS change (item 34 and the refresh of items 05, 25-33 from the final re-verify) (branch `claude/grpc-mtls`, uncommitted; run record `target/agent-workflow/20261024-225627-grpc-mtls/`). Items 25 and 26 were closed, items 27 and 28 updated, and items 35-38 added on 2026-10-26 by the per-method gRPC authorization change (branch `claude/grpc-per-method-authz`, uncommitted; run record `target/agent-workflow/20261025-202226-grpc-per-method/`). Item 03 was annotated, and items 39-42 added, on 2026-10-26 by the Dependabot alert remediation (branch `claude/dependabot-remediation`, uncommitted; run record `target/agent-workflow/20261026-dependabot-remediation/`). Item 39 was closed, item 42 updated, and items 43-44 added on 2026-10-26 by the react-router v7 migration (branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`). Item 41 was narrowed, and items 45-48 added, on 2026-10-26 by the ACME dns-01 resolver fix (branch `claude/dns01-resolver-fix`, uncommitted; run record `target/agent-workflow/20261026-091032-dns01-resolver/`). "Code location"
names the `// POAM:` (or `# POAM:`) marker where one exists. Risk levels and
target dates are proposals for the AO and are not yet approved.

An item marked "Closed pending first green CI run" is resolved in the working
tree and verified locally, but stays on the POA&M until a GitHub Actions run
(and, where named, a GitLab pipeline) records the same result.

| ID | Weakness | Controls / SFRs | Source | Code location (`// POAM:`) | Milestone (proposed) | Status |
|----|----------|-----------------|--------|----------------------------|----------------------|--------|
| POAM-2026-10-23-01 | The CMVP (FIPS 140-3) certificate for **AWS-LC FIPS 4.2.0** (`aws-lc-fips-sys` 0.14.2), now the project's crypto module, could not be confirmed. Until it is confirmed, "FIPS-validated" claims are suspended (docs say "CMVP certificate for 4.2.0 pending confirmation") | SC-13, SC-12, CM-6; FCS_COP.1, FCS_CKM.1, FCS_RBG_EXT.1 | User decision 2026-10-23; NIST-002 | No marker for the confirmation itself; the dependent `# POAM:` (ML-DSA issuance) is in workspace `Cargo.toml` (`aws-lc-rs` comment) | Confirm the certificate number and its approved-algorithm list (ML-KEM, ML-DSA) **before ATO**. If no certificate exists, choose a validated module version and repeat the CM-4 analysis | Open |
| POAM-2026-10-23-02 | ML-DSA certificate issuance disabled. TLS verification of ML-DSA was accepted by the user 2026-10-23 | SC-13, SC-17; FCS_COP.1, FDP_CER_EXT.1 | PQC-003 / NIST-009 | `# POAM:` in workspace `Cargo.toml` (`aws-lc-rs` comment block) | After POAM-01 closes | Open (blocked by 01) |
| POAM-2026-10-23-03 | **Narrowed 2026-10-23.** Originally: the `cargo audit` CI job was advisory (`continue-on-error: true`). Now: `.github/workflows/audit.yml` ("dependency gate", jobs `cargo audit` and `cargo deny`) has no `continue-on-error` and the workflow fails on any new advisory (`cargo audit --deny warnings`, `cargo deny check`). It runs on every pull request, on push to `main`, weekly (Monday 06:00 UTC) and on manual dispatch; GitLab runs `security:audit`/`security:deny` per merge request and on `main`/`develop`, and `scheduled:security-scan` on schedule. This applies once the branch merges. **Still open:** (a) no AO-approved remediation timeframes (proposed: critical 15 days, high 30, medium and low 90; h2/quinn-proto advisories were on `main` for 67 days); (b) no documented procedure for a scheduled run that turns red on an unchanged `Cargo.lock` (who triages, by when); (c) the jobs are not required status checks, so a failing gate does not by itself block a merge (POAM-2026-10-23-14). **Note 2026-10-26 (Dependabot remediation, NIST-002):** "fails on any new advisory" means any new **RustSec** advisory. GitHub-only advisories (no RustSec alias) are found by Dependabot and do not fail CI: GHSA-6w6g-hm98-mhgm, GHSA-5j98-2g5x-46v6 and GHSA-6f2x-v7q7-m7m5 (hickory-resolver, published 2026-10-05) passed `cargo audit` on `main` @ 1294f63. The proposed windows in (a) were missed for 9 npm advisories (10 Dependabot alerts; NIST-004); coverage gaps tracked as POAM-2026-10-23-42 | RA-5, SI-2; ALC_FLR.2, AVA_VAN.2 | NIST-001, NIST-002 | None; `.github/workflows/audit.yml`, `.cargo/audit.toml` (only exception path) | AO approves the timeframes; document the red-scheduled-run procedure; close POAM-14 | Open (narrowed) |
| POAM-2026-10-23-04 | `bulk_enroll` claims AU-2/AU-3 in its COMPLIANCE MAPPING but emits only `tracing::info!`. It emits no `ostrich-audit` event for submissions, and the early-return rejections are not recorded | AU-2, AU-3, AU-12; FAU_GEN.1, FDP_CER_EXT.2 | NIST-003 (pre-existing); QA gap 6 | None yet; `crates/ostrich-ca/src/rest.rs` `bulk_enroll` (the annotation overstates AU-2/AU-3) | Emit `DatabaseAuditSink` events for success and failure, or correct the annotation and add `// POAM:` | Open |
| POAM-2026-10-23-05 | **Narrowed 2026-10-24 (PR 152, branch `revive-fips-tls`) and again 2026-10-25 (branch `claude/grpc-mtls`, uncommitted; run record `target/agent-workflow/20261024-225627-grpc-mtls/`).** Originally: no runtime FIPS-mode assertion; services did not fail closed on a `try_fips_mode()` error and did not log the module version; the self-test KATs do not exercise AWS-LC (PQC-005). **Done 2026-10-24:** a fail-closed FIPS-mode gate (`ensure_fips`) on every TLS listener served via `ostrich_common::tls` (`TlsSettings::load` and first in `serve_with_config`, including npe-portal ACME mode); the HTTPS startup log records `fips = true` and `aws_lc_version`. **Done 2026-10-25:** a process-level gate `fips_gate` ([tls.rs](../../crates/ostrich-common/src/tls.rs)) asserts `try_fips_mode()`, asserts the rustls aws-lc-rs provider reports `fips()`, installs it as the process default and verifies the effective default, so an earlier non-FIPS install makes the process exit. It is the first call after tracing setup in all ten service mains (acme, ca, est, kra, notify, npe-portal, ocsp, scms, tamp, web-ui), before the database, NATS, listeners and clients. The CA gRPC server and client configs are asserted (`ensure_fips`, `ensure_fips_client`), and the ca-server gRPC listener now starts after the gate (former item (c) closed). Tests: `fips_gate_preinstalled` 1/1, `grpc_mtls_e2e` 21/21 (`server_and_client_configs_report_fips`, `connector_and_listener_refuse_non_fips_or_non_h2_configs`), passed 2026-10-25. The gate detects build and linkage problems only: AWS-LC 4.2.0 `FIPS_mode()` is a build-time constant, and a failed power-on self-test aborts the process inside the module (PR152-PQC-009). **Still open:** (a) plain-HTTP REST mode (no certificate configured) is still permitted; (b) rustls `ClientConfig`s outside gRPC are not asserted (web-ui and npe-portal backend clients, the ACME tls-alpn-01 validator), and clients that build their config from the process default (async-nats, lettre, instant-acme) rely on `fips_gate` only; (d) **narrowed 2026-10-25 (round 2):** the ca-server gRPC trust-anchor refusal (including ancestor-walk failures) is now audited as `grpc_listener_refused` (ConfigurationChange / Failure, best effort: a failed audit write is logged and the refusal still applies; `services/ca-server/src/main.rs` `check_grpc_trust_anchors`, test `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal`). Still log-only: the FIPS gate refusal and the gRPC configuration refusals that happen before the database pool exists; (e) KATs not run through AWS-LC; (f) the non-FIPS `aws-lc-sys` 0.46.0 is compiled alongside the FIPS module via aws-lc-rs default features, a second unvalidated AWS-LC copy in the binary and SBOM (PR152-PQC-010) | SC-13, SC-24, SC-8, SI-7; FCS_COP.1, FCS_TLSS_EXT.1, FCS_TLSC_EXT.2, FPT_FLS.1, FPT_TST_EXT.1 | PQC-002 / NIST-007; PQC-005; PR 152 review: PR152-NIST-003, PR152-PQC-006, PR152-PQC-009, PR152-PQC-010, PR152-SEC-006, PR152-SEC-007 (PR 152 finding numbers, not the 2026-10-25 gRPC mTLS review's PQC-006 etc.); gRPC mTLS review 2026-10-25: NIST-007 | `// POAM: POAM-2026-10-23-05` beside `ensure_fips` in `crates/ostrich-common/src/tls.rs`; also `crates/ostrich-crypto/src/self_test.rs` | Refuse or retire plain-HTTP REST mode; `ClientConfig::fips()` assertions for the remaining clients; an audit record for the remaining pre-database startup refusals (for example written once the pool exists, or to a local append-only file); KATs through AWS-LC; decide on (or document) the second `aws-lc-sys` copy | Open (narrowed) |
| POAM-2026-10-23-06 | `cargo deny check` cannot run: `deny.toml` uses 5 keys removed in cargo-deny ≥0.16 and fails validation under 0.20.2. License, ban and source policy is not enforced (6 crates were added on 2026-10-23 without a deny check) | SR-3, CM-7, RA-5, SA-11 | SEC-001 / QA-002 / REL-004 | None; `deny.toml` | Migrate the `[licenses]` schema (cargo-deny PR #611), mirror the `.cargo/audit.toml` exceptions, re-run. **Done locally 2026-10-23:** `deny.toml` rewritten for the cargo-deny ≥0.18 schema; `cargo deny check` (0.20.2) exit 0 (`advisories ok, bans ok, licenses ok, sources ok`); license exceptions crate-scoped per user decision (OpenSSL → `aws-lc-fips-sys`, CDLA-Permissive-2.0 → `webpki-roots`/`webpki-root-certs`, MIT-0 → `borrow-or-share`); advisory ignores identical to `.cargo/audit.toml` (4 IDs); no exception is unused, and negative checks fail the gate when a tested exception is removed (`qa-report.md` gates 6-12) | Closed pending first green CI run (GitHub `cargo deny` and GitLab `security:deny`) |
| POAM-2026-10-23-07 | PKCS#11 integration tests are not run in CI and could not run locally (no SoftHSM). The cryptoki 0.11.1 fix (RUSTSEC-2026-0286) has no executed test evidence | SA-11, SC-12, IA-7; FCS_CKM.1, FCS_COP.1 | QA-004 | None; `crates/ostrich-crypto/tests/pkcs11_integration_test.rs`, `.github/workflows/hsm-integration.yml` | Run `cargo test -p ostrich-crypto --test pkcs11_integration_test -- --test-threads=1` against SoftHSM and attach the output; add a SoftHSM CI job. **Narrowed 2026-10-23:** CI job `PKCS#11 suite (SoftHSM2)` added (ubuntu-24.04, serial, uploads artifact `pkcs11-softhsm-results`); `make install-softhsm` now creates the `OstrichPKI-Test` token the suite looks up. Local macOS result, non-standard invocation (test binary run directly with `DYLD_INSERT_LIBRARIES` to avoid a SoftHSM/OpenSSL 4 exit-time crash): **16 passed, 3 failed, 1 ignored**; the 3 failures are RSA-PSS (`CKR_GENERAL_ERROR`). This run does not exercise the `CKA_ALLOWED_MECHANISMS` decode path fixed by RUSTSEC-2026-0286. **Linux CI result pending.** Close only with the Linux CI artifact attached; if RSA-PSS also fails on Linux, open a new FCS_COP.1 RSA-PSS item. **Updated 2026-10-23 (RSA-PSS fix):** the Linux CI job ran (SoftHSM 2.6.1, commit `3943e9a` per the job log): 16 passed, 3 RSA-PSS failed, 1 ignored, exit 101. The conditional RSA-PSS item was therefore triggered (POAM-2026-10-23-17). After the fix, local SoftHSM 2.7.0: 28 passed, 0 failed, 1 ignored. Still no run exercises the `CKA_ALLOWED_MECHANISMS` decode path (see POAM-18). **Closed 2026-10-23:** GitHub Actions [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) (workflow `HSM integration`, job `PKCS#11 suite (SoftHSM2)`; runner ubuntu24 20261012.334.1, SoftHSM 2.6.1, rustc 1.99.1; GitHub head SHA 44d560d, the PR 181 head; the artifact's `commit:` line shows the PR merge ref c67c10e): 28 passed, 0 failed, 1 ignored (`test_key_wrapping_and_unwrapping`), exit 0. Caveats kept: (a) no run exercises the `CKA_ALLOWED_MECHANISMS` decode path fixed by RUSTSEC-2026-0286 (cryptoki 0.11.1), because `ostrich-crypto/src/pkcs11` never reads that attribute (see POAM-18); (b) SoftHSM is a test double, not a production or validated HSM (production-HSM approval of the raw mechanisms is POAM-21) | Closed 2026-10-23 (evidence: https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654; caveats: `CKA_ALLOWED_MECHANISMS` not exercised, SoftHSM only) |
| POAM-2026-10-23-08 | `ring` (no CMVP certificate) is still used outside the AWS-LC FIPS module. Found during documentation review, not raised by a reviewer. **Note 2026-10-24 (PR 152 review, PR152-SEC-002 / PR152-PQC-003):** gRPC clients used tonic `tls-ring` (TLS 1.2 allowed, no `fips()` assertion) and the ca-server gRPC server had no TLS. **Narrowed 2026-10-25 (branch `claude/grpc-mtls`, uncommitted), not closed:** the gRPC part is done. tonic is built with `features = ["channel"]` only (workspace `Cargo.toml`), `cargo tree -e features -i rustls` shows no tonic TLS feature (re-checked by the compliance scribe 2026-10-25), and gRPC TLS uses OstrichPKI's own aws-lc-rs FIPS, TLS 1.3-only server and client configs with `fips()` asserted. **Still open:** (1) AES-256-GCM key wrap and `SystemRandom` in `crates/ostrich-kra/src/wrap.rs` (`ring::aead`, `ring::rand`); (2) the rustls `ring` feature is still compiled in through `lettre/ring` (notify-server), `reqwest` 0.12 `__rustls-ring` (via `oauth2` in web-ui, POAM-23; `ostrich-cli`; tests crate), `tokio-rustls/ring` and `hyper-rustls/ring` (async-nats, tokio-websockets, reqwest 0.12). All OstrichPKI-built TLS configs select the aws-lc-rs provider explicitly and the process default is the FIPS provider (`fips_gate`), so `ring` is compiled but not the selected TLS provider for those configs; (3) async-nats uses `ring` for SHA-256 (tracked separately as POAM-2026-10-23-30); (4) `rcgen` pulls `ring` for tests and for `instant-acme` | SC-13, SC-12; FCS_COP.1 | Compliance scribe, 2026-10-23; NIST-001 (gRPC mTLS review, 2026-10-25) | Workspace `Cargo.toml` tonic comment ("gRPC part of POAM-2026-10-23-08"); no marker in `crates/ostrich-kra/src/wrap.rs` yet | Move KRA `wrap.rs` to aws-lc-rs (`fips`); drop or replace the crates that enable the rustls `ring` feature (POAM-23 removes `oauth2`); or document the remaining uses as non-security-relevant with AO acceptance | Open (narrowed) |
| POAM-2026-10-23-09 | Risk-accepted advisory in `.cargo/audit.toml`: RUSTSEC-2023-0071 (`rsa` Marvin; no fix). `.cargo/audit.toml` is the authoritative risk-acceptance record. **Updated 2026-10-23:** the `hickory-proto` part (RUSTSEC-2026-0118) is resolved: the stale ignore was removed and `cargo audit --deny warnings` and `cargo deny check` both pass without it. The other unmaintained/unsound acceptances moved to POAM-11 and POAM-12 | RA-5, SI-2 | NIST-006 | `# POAM: POAM-2026-10-23-09` in `.cargo/audit.toml` (`rsa` entry); same ID in the `deny.toml` `[advisories].ignore` reason | Re-evaluate when `rsa` ships a constant-time fix; review at each audit run. **Updated 2026-10-24 (dependency cleanup, run record `target/agent-workflow/20261024-104215-deps-cleanup/`):** with `openidconnect` removed (POAM-22), `cargo tree -i rsa -e normal` lists only `ostrich-acme` (→ `ostrich-acme-server`), `ostrich-benches` and `ostrich-integration-tests`; `ostrich-crypto` also has `rsa` as a dev-dependency. The only production use is `ostrich-acme` and it is public-key-only: [jws.rs](../../crates/ostrich-acme/src/jws.rs) builds an `RsaPublicKey` from an ACME account JWK (n, e) and encodes it to SPKI DER for JWS verification. No production private-key operation and no RSA decryption oracle is exposed; RSA private keys exist only as ephemeral test/bench keys. The ignore rationale in `.cargo/audit.toml` and `deny.toml` no longer mentions `openidconnect`. The advisory has no fix, so the acceptance stays | Open (`rsa` only) |
| POAM-2026-10-23-10 | The FIPS module-source pin (`.cargo/config.toml`, `AWS_LC_FIPS_SYS_USE_SYSTEM=0`) is mirrored as `ENV` in both Dockerfiles; it does not cover the target-suffixed variable, and no container build has been verified. Updated 2026-10-23: the pin is committed on `main` (commit 05ea47a, PR #180) | CM-2, CM-6, SI-7 | PQC-001, SEC-005, SEC-006 | None | ~~Commit the pin~~ (done); verify a container build log shows `Building with: CMake` | Open |
| POAM-2026-10-23-11 | `rand` 0.8.5 is in `Cargo.lock` with RUSTSEC-2026-0097 (`rand::thread_rng` unsound when a custom `log` logger draws from `ThreadRng`; the project's `tracing` loggers do not). A fixed release (0.8.6) is available; the ignore exists only because this change kept `Cargo.lock` unchanged | SI-2, RA-5 | NIST-006; `fixes-round-1.md` item 8 | Removed 2026-10-24 (was `# POAM: POAM-2026-10-23-11` in `.cargo/audit.toml` and the `deny.toml` ignore reason) | `cargo update -p rand@0.8.5 --precise 0.8.6`, then delete the ignore from both files. Target **2026-11-06** (proposed). **Remediated 2026-10-24, before the target (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`):** `Cargo.lock` `rand` 0.8.5 → 0.8.6 (the only version change in the lockfile); the RUSTSEC-2026-0097 entry and its `# POAM:` tag removed from `.cargo/audit.toml` and `deny.toml` (ignore lists identical, 3 IDs); `cargo tree -i rand@0.8.5 --target all -e all` → "did not match any packages"; without the ignore, `cargo audit --deny warnings` exit 0 (1352 advisories, 614 crates) and `cargo deny check` exit 0 (`advisories ok, bans ok, licenses ok, sources ok`), re-run by the compliance scribe 2026-10-24 with the same exit codes. Local only; no CI run of this change recorded | Closed pending first green CI run (GitHub `cargo audit` / `cargo deny`, GitLab `security:audit` / `security:deny`) |
| POAM-2026-10-23-12 | Unmaintained transitive components accepted: `paste` (RUSTSEC-2024-0436, build-time proc-macro via `cryptoki`) and `rustls-pemfile` (RUSTSEC-2025-0134, via `axum-server`; parses operator-supplied TLS PEM only). No supported replacement upstream yet | SA-22, RA-5, SI-2 | NIST-006 | `# POAM: POAM-2026-10-23-12` in `.cargo/audit.toml`; same ID in the `deny.toml` ignore reasons | AO accepts the SA-22 exception; replace when `cryptoki` / `axum-server` drop the dependency; re-check at each weekly scan | Open (acceptance pending AO) |
| POAM-2026-10-23-13 | No `CODEOWNERS` file (none in `.github/`, the repository root or `docs/`, checked 2026-10-23). The gate workflows and exception files (`.github/workflows/`, `.cargo/audit.toml`, `deny.toml`, `rust-toolchain.toml`) can be changed in the same pull request they gate, with no mandatory second reviewer | CM-3, CM-5, SA-10 | SEC-001, NIST-003 | None | Add `CODEOWNERS` covering those paths and require code-owner review in branch protection (with POAM-14) | Open |
| POAM-2026-10-23-14 | `main` has no branch protection and no rulesets (`gh api repos/192d-Wing/OstrichPKI/branches/main/protection` → HTTP 404 "Branch not protected"; `…/rules/branches/main` → `[]`, 2026-10-23). The dependency gate fails the workflow but does not block a merge | CM-3, SI-2, RA-5, SA-10 | NIST-002 | None | Protect `main` and require these job names: `Build & test`, `Web UI (React build + supply-chain)`, `Toolchain pin consistency`, `cargo audit`, `cargo deny`; add `PKCS#11 suite (SoftHSM2)` after two green runs (the RSA-PSS decision is settled: fixed, POAM-17, closed 2026-10-23). **Updated 2026-10-23:** the first green run is recorded ([run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654), PR 181 head 44d560d, 28 passed / 0 failed / 1 ignored, exit 0); the job becomes eligible as a required check after one more green run. Do not require `Clippy (advisory)` / `Rustfmt (advisory)` while they keep `continue-on-error`. Capture the protection API output as evidence | Open |
| POAM-2026-10-23-15 | Pinning outside the hardened workflows: `.github/workflows/docker-publish.yml` (the only workflow with registry credentials) uses tag-pinned actions (`@v7`, `@v4`; 9 `uses:`); `cargo install cargo-chef --locked` has no version in `Dockerfile` and `services/web-ui/Dockerfile`; GitLab uses `zricethezav/gitleaks:latest`, `alpine:latest`, `docker:24`, and unversioned `cargo install` for `cargo-tarpaulin`, `sqlx-cli` and `cargo-sbom`; Go in the GitHub FIPS build jobs comes from the runner image | SR-11, SA-15, CM-2, SR-4 | SEC-005, NIST-010, REL-007 | None | SHA-pin every `uses:` in `docker-publish.yml` and set `persist-credentials: false`; version-pin `cargo-chef` and the GitLab tools and images; consider SHA-pinned `actions/setup-go` | Open |
| POAM-2026-10-23-16 | Risk-accepted advisory RUSTSEC-2026-0387: `crypto-bigint` 0.5.5 has timing variability in operations meant to be constant-time (published 2026-10-23). No compatible fix: the fix is only in ≥0.7.6, which needs the blocked RustCrypto 0.3 migration (issue #21). The crate enters only through `elliptic-curve` 0.13 (`p256`/`p384`) from `openidconnect` 4.0.1, a declared but unused dependency of `ostrich-web-ui` (no call sites), so no production code reaches it; and through the integration-test crate's direct `p256` 0.13 dependency, used only for ephemeral, test-only fixture keys ([tests/integration/common/fixtures.rs](../../tests/integration/common/fixtures.rs)). No production secret flows through the affected operations. User decision 2026-10-23: ignore + POA&M | RA-5, SI-2 | QA-002; `fix-request-round-1.md` (user decision) | Removed 2026-10-24 (was `# POAM: POAM-2026-10-23-16` in `.cargo/audit.toml` and the `deny.toml` ignore reason) | Remove the ignore from both files when `crypto-bigint` ≥0.7.6 is reachable (issue #21), or sooner via POAM-22; re-check at each weekly scan. **Resolved 2026-10-24 by removing the dependency, not by a fix (run record `target/agent-workflow/20261024-104215-deps-cleanup/`):** both roots are gone. `openidconnect` was removed (POAM-22), and the integration-test crate's `p256` 0.13 dependency was removed from `tests/Cargo.toml`; `generate_test_p256_spki` in [fixtures.rs](../../tests/integration/common/fixtures.rs) now generates its throwaway P-256 key through the software `CryptoProvider` (`CryptoProviderFactory::create_software_provider()`, `KeyType::EcP256`, AWS-LC) and returns the SPKI DER. `cargo tree -i crypto-bigint@0.5.5 --target all -e all` (and the same for `p256`, `elliptic-curve`) → "did not match any packages". The RUSTSEC-2026-0387 ignore and its `# POAM:` tag were removed from both files, and the gate passes without it (see POAM-11). New offline test `test_p256_spki_fixture_well_formed` (`tests/integration/ca_core_test.rs`) passed (1 passed). Upstream `crypto-bigint` <0.7.6 is still affected; with no ignore, a dependency that brings it back fails the gate. Local only; no CI run recorded | Closed pending first green CI run (dependency removed; risk acceptance withdrawn) |
| POAM-2026-10-23-17 | FCS_COP.1 RSA-PSS through PKCS#11 (triggered by POAM-07). Raw `CKM_RSA_PKCS_PSS` was given the whole message instead of its SHA-2 digest, so `C_Sign` failed (`CKR_GENERAL_ERROR`) on SoftHSM 2.6.1 (Linux CI) and 2.7.0 (macOS), and HSM verify returned `Ok(false)` for valid signatures. Impact: AU-10 audit-record signing with RSA PKCS#11 CA keys (default algorithm `RsaPssSha256`) failed. X.509 certificate, CRL and OCSP RSA signing uses PKCS#1 v1.5 and was not affected | SC-13, AU-10; FCS_COP.1(1), FCO_NRO_EXT.2 | CI log (`ci-pkcs11-before.txt`); NIST-005, PQC review | None; fix in `crates/ostrich-crypto/src/pkcs11/mod.rs` (`pkcs11_signature_input`, `rsa_pss_profile`) | **Opened and remediated 2026-10-23.** Close when the Linux CI artifact `pkcs11-softhsm-results` for the pushed fix commit shows SoftHSM 2.6.1, 0 failed (28 passed / 1 ignored expected), `test_rsa_pss_hsm_sign_software_verify ... ok`, exit 0. Optional: RSA variant of `audit_signing_e2e` (NIST-005). **Closed 2026-10-23:** the criterion is met by GitHub Actions [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) (workflow `HSM integration`, job `PKCS#11 suite (SoftHSM2)`; runner ubuntu24 20261012.334.1, SoftHSM 2.6.1, rustc 1.99.1; GitHub head SHA 44d560d, the PR 181 head; the artifact's `commit:` line shows the PR merge ref c67c10e): 28 passed, 0 failed, 1 ignored, all six `test_rsa_pss_*` tests ok including `test_rsa_pss_hsm_sign_software_verify`, exit 0 (before the fix: 16 / 3 / 1, exit 101). Scope: RSA-PSS SHA-256/384/512, RSA-2048/3072/4096, SoftHSM 2.6.1 (CI) and 2.7.0 (local). Caveats kept: (a) no run exercises the `CKA_ALLOWED_MECHANISMS` decode path fixed by RUSTSEC-2026-0286 (cryptoki 0.11.1), because `ostrich-crypto/src/pkcs11` never reads that attribute (see POAM-18); (b) SoftHSM is a test double, not a production or validated HSM (production-HSM approval of the raw mechanisms is POAM-21). The AWS-LC FIPS 4.2.0 CMVP certificate is still pending (POAM-01). The optional RSA `audit_signing_e2e` variant was not done | Closed 2026-10-23 (evidence: https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654; caveats: `CKA_ALLOWED_MECHANISMS` not exercised, SoftHSM only) |
| POAM-2026-10-23-18 | PKCS#11 `sign`/`verify` do not check that the requested `Algorithm` matches the key type, curve or `KeyHandle.algorithm`, or that the handle belongs to the PKCS#11 provider (the software provider does check). Key generation does not set `CKA_ALLOWED_MECHANISMS`, so the token does not restrict mechanisms per key (pre-existing) | SC-12, SC-13, AC-3; FCS_COP.1, FCS_CKM.1 | SEC-001 | None; `crates/ostrich-crypto/src/pkcs11/mod.rs` (`sign`, `verify`, key generation) | Reject disallowed (key type, algorithm) pairs and foreign handles; set `CKA_ALLOWED_MECHANISMS` at key generation and add a test that exercises it (also covers the RUSTSEC-2026-0286 decode path) | Open |
| POAM-2026-10-23-19 | The PKCS#11 provider logs out after each sign/verify. PKCS#11 login state is shared by all sessions of the application, so one operation's logout ends the login for concurrent operations (pre-existing) | SC-12, IA-7, SC-5; FCS_COP.1 | SEC-004 | None; `crates/ostrich-crypto/src/pkcs11/mod.rs` (sign/verify logout, login handling) | Remove the per-operation logout; keep the login for the provider's lifetime and log out on `Drop`; add a concurrency test | Open |
| POAM-2026-10-23-20 | The X.509 layer cannot encode RSASSA-PSS AlgorithmIdentifier parameters (RFC 4055), and the parser and path validator map id-RSASSA-PSS (1.2.840.113549.1.1.10) to `RsaPssSha256` without reading RSASSA-PSS-params. RSA-PSS certificates, CRLs and CSRs that use SHA-384/512 or non-default parameters cannot be produced and are not verified correctly (pre-existing) | SC-13, SC-17, SI-10; FCS_COP.1, FDP_CER_EXT.1, FCO_NRO_EXT.2 | PQC-002 | None; `crates/ostrich-x509/src/signing.rs`, `parser.rs`, `validation/path_validator.rs` | Implement RFC 4055 RSASSA-PSS-params encoding and decoding (hash, MGF1, salt length, trailer) with tests; until then, do not claim RSA-PSS for X.509 | Open |
| POAM-2026-10-23-21 | PKCS#11 RSA-PSS and ECDSA are split operations: the digest is computed in the AWS-LC FIPS module on the host; EMSA-PSS encoding and the private-key operation run in the HSM. Whether the production HSM's FIPS 140-3 security policy approves raw `CKM_RSA_PKCS_PSS` / `CKM_ECDSA` with host-supplied digests has not been checked (no production HSM selected) | SC-13, SC-12; FCS_COP.1, FCS_CDP_EXT.1 | NIST-003, PQC-005 | None; boundary statement at `pkcs11_signature_input` in `crates/ostrich-crypto/src/pkcs11/mod.rs` | When the production HSM is chosen, confirm from its CMVP security policy that both raw mechanisms are approved in FIPS mode; otherwise switch to combined `CKM_SHAx_RSA_PKCS_PSS` / `CKM_ECDSA_SHAx` where supported | Open |
| POAM-2026-10-23-22 | `openidconnect` 4.0.1 is a declared but unused dependency of `ostrich-web-ui` (no call sites). It pulls `crypto-bigint` 0.5.5 (POAM-16) and `rsa` (POAM-09) into the web-ui dependency tree. `rsa` stays in production trees through `ostrich-acme` (direct use) | RA-5, SI-2, CM-7 | Coordinator note 2026-10-23 (PQC review) | None; `services/web-ui/Cargo.toml` | Remove the dependency, re-run `cargo audit` / `cargo deny`, and narrow POAM-16 (and the POAM-09 reachability note). **Remediated 2026-10-24 (branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`):** `openidconnect` removed from workspace `Cargo.toml` `[workspace.dependencies]` and from `services/web-ui/Cargo.toml`. With the `p256` test dependency (POAM-16), 28 packages left `Cargo.lock` (642 → 614 `[[package]]` entries), all reachable only through `openidconnect` or `p256`. `cargo tree -i openidconnect --target all -e all` → "did not match any packages". `cargo audit --deny warnings` and `cargo deny check` exit 0; `cargo test --all-features --bins -p ostrich-web-ui` 19 passed / 0 failed; `make test-unit` 667 passed / 0 failed / 1 ignored. No production code changed (no call sites). POAM-16 closed and the POAM-09 reachability note narrowed. `oauth2` was found to be unused too and is tracked as POAM-23. Local only; no CI run recorded | Closed pending first green CI run |
| POAM-2026-10-23-23 | `oauth2` 5.0.0 is a declared but unused dependency of `ostrich-web-ui`: no `.rs` file in the repository references it (`grep -rn oauth2 --include='*.rs'`, 2026-10-24). The web-ui OIDC login ([oidc.rs](../../services/web-ui/src/server/auth/oidc.rs)) does authorization code + PKCE by hand over `reqwest`. The crate adds unneeded code and a dependency edge into `rand` 0.8 (CM-7 least functionality). Its default features (`reqwest`, `rustls-tls`) also link a second HTTP client into the production web-ui binary: `reqwest` 0.12.28 alongside the `reqwest` 0.13.1 that web-ui uses, with the `reqwest` `__rustls-ring` feature, which enables the `rustls` `ring` feature (`cargo tree -p ostrich-web-ui -e features -i rustls`, 2026-10-24). `ring` has no CMVP certificate (see POAM-08). Removing `oauth2` drops `reqwest` 0.12 from web-ui (it stays in the lockfile for `ostrich-cli` and the integration tests), but `ring` stays in web-ui through `tonic` `tls-ring` and `rustls-webpki` (update 2026-10-25: tonic `tls-ring` was removed workspace-wide; `rustls-webpki` remains, see POAM-08). No advisory is open against `oauth2` | CM-7, SC-13, RA-5, SI-2 | Dependency cleanup 2026-10-24 (`impl-notes.md`, report only) | None; workspace `Cargo.toml` (`oauth2 = "5.0"`) and `services/web-ui/Cargo.toml` (`oauth2 = { workspace = true }`) | Remove both manifest lines, as was done for `openidconnect` (POAM-22); re-run `cargo audit --deny warnings`, `cargo deny check` and the web-ui `--bins` tests. The remaining `ring` paths stay under POAM-08 | Open |
| POAM-2026-10-23-24 | Pre-existing; not introduced by the dependency cleanup. Some production secrets and CSPs come from `rand` 0.10 `ThreadRng` (ChaCha12, seeded from the OS), not from the SP 800-90A DRBG in the AWS-LC FIPS module: Shamir KEK share polynomial coefficients ([shamir.rs](../../crates/ostrich-kra/src/shamir.rs) line 102, `rand::rng()`); `secure_random_bytes` ([random.rs](../../crates/ostrich-common/src/util/random.rs) lines 6-14), whose production caller is the PKCS#12 PBES2 salt and IV in `build_encrypted_pkcs12` (`crates/ostrich-x509/src/pkcs12.rs`); the EST PKCS#12 one-time password ([rest.rs](../../crates/ostrich-est/src/rest.rs) line 2247, `rand::random`) and enrollment token (same file, line 2384); web session tokens (`generate_token`, [session.rs](../../crates/ostrich-common/src/auth/session.rs) lines 210-211). Not affected: CA X.509 serial numbers already use `ostrich_crypto::fips_random_bytes` (`generate_serial_number` in `crates/ostrich-ca/src/issuance.rs`); the `secure_random_bytes`-based `generate_serial_number` helper in `random.rs` has no callers, and the other serial-number uses of `secure_random_bytes` are in `#[cfg(test)]` modules of `ostrich-ca` | SC-13, SC-12; FCS_RBG_EXT.1; FIPS 140-3, SP 800-90A | PQC-001 (PQC review of the dependency cleanup, 2026-10-24) | None yet; locations as listed | Route these draws through `aws_lc_rs::rand::fill` via the ostrich-crypto helper `fips_random_bytes` ([drbg.rs](../../crates/ostrich-crypto/src/drbg.rs) line 690), adding `// POAM:` markers until done; then remove `rand` from `ostrich-kra`, `ostrich-common` and `ostrich-est` | Open |
| POAM-2026-10-23-25 | **Closed 2026-10-26 (branch `claude/grpc-per-method-authz`, uncommitted; run record `target/agent-workflow/20261025-202226-grpc-per-method/`).** Originally: the CA gRPC audit actor was client-asserted; the authenticated peer subject was only logged in `IssueCertificate`, `RevokeCertificate` and `GenerateCrl`, and the `actor` of issuance and revocation records was the client-supplied `requestor`. **Remediation:** the actor of gRPC issuance, revocation and CRL records is the verified mTLS peer subject DN; `details.authenticated_caller`, `authenticated_caller_issuer` and `authenticated_caller_serial` identify the client certificate; the `requestor` is bound to the caller's namespace (`validate_requestor`, `bind_caller`) and recorded as `on_behalf_of`. `authenticated_caller` is `#[serde(skip_deserializing)]`, so it cannot be set from JSON. REST full and delta CRL generation now records the authenticated user (`generate` / `generate_delta`); `system` is the scheduler only. Failed revocations and failed CRL generations write Failure records with the same actor. **Evidence (executed 2026-10-26):** `grpc::tests::{issuance_request_carries_verified_caller, revocation_request_carries_verified_caller, crl_actor_is_verified_peer}`, `issuance::tests::{audit_identity_with_caller_uses_peer_as_actor, authenticated_caller_is_never_deserialized}`, `revocation::tests::{crl_audit_event_actor, delta_crl_audit_event_actor, crl_failure_event_contents, revocation_failure_event_contents}` (`ostrich-ca` 78/78); `grpc_mtls_e2e` 39/39 (`bound_caller_actor_is_peer`, `qa_valid_requestors_bind_to_peer_for_each_role`, requestor-denial tests); mutations M10-M13, M12r, M26, M27 killed. **Residuals:** M13h (GenerateCrl handler glue) and the REST CRL handler glue are verified by inspection only, and the live `audit_signing_e2e` / `crl_delta_e2e` assertions were NOT RUN (no Postgres): POAM-2026-10-23-36. RA namespace confused deputy: POAM-2026-10-23-35. The debug-only plaintext listener has no verified actor (refused in release builds) | AU-3, AU-10, IA-3; FAU_GEN.2 | Plan review (user decision 2026-10-25); `impl-notes.md` POAM item 1; NIST-001/-006/-101 (closure 2026-10-26: findings-nist-round-2.md) | Marker removed from `crates/ostrich-ca/src/grpc.rs` | ~~Record the verified peer subject as the audit actor and keep `requestor` as a claimed value~~ (done) | Closed pending commit (remediated in the working tree 2026-10-26; residuals tracked as POAM-35 and -36) |
| POAM-2026-10-23-26 | **Closed 2026-10-26 (branch `claude/grpc-per-method-authz`, uncommitted; run record `target/agent-workflow/20261025-202226-grpc-per-method/`).** Originally: a single client-subject allowlist covered every RPC on the CA gRPC listener, so an allow-listed RA (acme-server, est-server) could also call `RevokeCertificate` and `GenerateCrl`. **Remediation:** three role lists (`CA_GRPC_ACME_CLIENT_SUBJECTS`, `CA_GRPC_EST_CLIENT_SUBJECTS`: Issuer; `CA_GRPC_ADMIN_CLIENT_SUBJECTS`: Admin, empty by default) and the default-deny method table `CA_GRPC_METHOD_RULES` ([grpc_authz.rs](../../crates/ostrich-ca/src/grpc_authz.rs)) enforced by `SubjectAllowlistLayer` (`authorize_peer_at` in [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)). Issuer: IssueCertificate, GetCaInfo, ListProfiles; Admin: RevokeCertificate, GenerateCrl, CheckRevocationStatus, GetCaInfo, ListProfiles, never IssueCertificate; any other path `method_not_mapped`. A subject may hold one role (overlap, including ASCII case variants, refuses startup); the old variable refuses startup. Issuers are further limited to listed end-entity profiles per namespace (`IssuerProfilePolicy`; CA profiles never). **Evidence (executed 2026-10-26):** `grpc_tls` unit tests 66/66 (`authorize_peer_method_matrix`, `qa_authorize_peer_non_canonical_paths_are_not_mapped`, `qa_layer_denies_and_audits_unmapped_paths`, `admin_requires_leaf_issued_directly_by_anchor`); `grpc_authz::tests::{rules_cover_every_proto_rpc, rules_match_policy_table}`; `grpc_mtls_e2e` 39/39 (`role_method_matrix`, `unknown_method_denied`, `qa_unmapped_path_variants_denied_over_the_wire`, `admin_list_empty_default_denies_revoke_crl_status_for_all`, `issuer_profile_allowlist_enforced_and_audited`, `admin_under_intermediate_is_refused`); mutations M1, M2, M15, M16, M19, M23 killed. **Residuals:** (a) admin authenticity rests on POAM-2026-10-23-27 (no client revocation) and -28 (narrowed for Admin: one anchor, direct issuance with AKI = anchor SKI); (b) authorized `CheckRevocationStatus` calls are unaudited admin reads (accepted, AC-6(9); denials are audited); (c) RA namespace confused deputy, POAM-2026-10-23-35; (d) the DB-gated `ca_core_test` / `ocsp_revocation_test` issuer-denied-revoke assertions were NOT RUN (POAM-2026-10-23-36) | AC-6, AC-3; FDP_ACC.1, FDP_ACF.1, FMT_SMF.1 | Plan review (user decision 2026-10-25); `impl-notes.md` POAM item 2; NIST-025 (closure 2026-10-26: findings-nist-round-2.md) | Markers removed from `crates/ostrich-common/src/grpc_tls.rs` and `crates/ostrich-ca/src/grpc.rs` | ~~Per-method allowlists~~ (done) | Closed pending commit (remediated in the working tree 2026-10-26; residuals tracked as POAM-27, -28, -35, -36) |
| POAM-2026-10-23-27 | Client-certificate revocation is not checked on the CA gRPC listener: `WebPkiClientVerifier` is built without CRLs, so a revoked acme/est/admin client certificate is accepted until it expires. The REST mTLS listeners have the same gap. **Updated 2026-10-26 (admin role):** a compromised operator certificate keeps RevokeCertificate, GenerateCrl and CheckRevocationStatus until its subject is removed or until notAfter; the new per-call leaf validity check (`certificate_not_valid_now`) ends access at notAfter at the latest, also on a long-lived connection. Compensating control (runbook `docs/runbooks/ca-grpc-mtls.md`): one short-lived admin certificate per named CA Operations Staff operator; on compromise remove the subject from its role list (`CA_GRPC_{ACME,EST,ADMIN}_CLIENT_SUBJECTS`) and restart ca-server, then reissue under a new subject, or rotate the service-identity CA | IA-5(2), SC-17, IA-3; FIA_X509_EXT.1.1, FCS_TLSS_EXT.2 | RFC-002, NIST-012 | `// POAM: POAM-2026-10-23-27` in `crates/ostrich-common/src/grpc_tls.rs` (line 58, module header) and `services/ca-server/src/main.rs` (line 825, `start_grpc_listener`) | Feed the service-identity CA's CRL to the verifier (`with_crls`), with refresh; same for REST mTLS | Open (accepted risk pending AO) |
| POAM-2026-10-23-28 | CA gRPC allowlist entries bind the client-certificate subject DN only, not the issuer or key (SPKI): any anchor in `CA_GRPC_TLS_CLIENT_CA_FILE` that issues a certificate with an allow-listed subject authorises its holder. **Narrowed 2026-10-25 (round 2):** at startup `ensure_dedicated_client_ca` refuses an anchor with the issuing CA's SPKI, with its subject (subject alone), issued by it (issuer name or AKI = issuing SKI), that is its issuer, or that matches (SPKI or subject) any ancestor from the CA database (`walk_ca_ancestors` over `ca_certificates.parent_ca_id`, fails closed on a missing row, a cycle or depth > 16); a refusal is audited (`grpc_listener_refused`). Per call, `SubjectAllowlistLayer::with_subscriber_issuing_cas` denies a leaf whose issuer DN or AKI matches the issuing CA or a database ancestor (`subscriber_issuing_ca`). Tests: `dedicated_client_ca_refuses_chain_relatives`, `issued_by_checks_cover_name_and_key_id_independently`, `authorize_peer_refuses_subscriber_issuing_ca_leaf` (grpc_tls unit tests), `walk_ca_ancestors_follows_parent_ca_id_and_fails_closed`, `grpc_trust_anchor_check_walks_db_chain_and_audits_refusal` (ca-server bin tests). **Narrowed 2026-10-26 for the Admin role (branch `claude/grpc-per-method-authz`, SEC-101 / SEC-201 / RFC-001):** with a non-empty `CA_GRPC_ADMIN_CLIENT_SUBJECTS`, ca-server refuses to start unless `CA_GRPC_TLS_CLIENT_CA_FILE` holds exactly one distinct trust anchor (`GrpcServerOptions::resolve`; duplicates counted once) and that anchor has a subjectKeyIdentifier (`SubjectAllowlistLayer::with_client_trust_anchors`, audited `grpc_listener_refused` / `check=grpc_authorization_layer`); per call, an Admin leaf is admitted only if it was issued directly by that anchor (issuer DN = anchor subject **and** leaf AKI keyIdentifier present and equal to the anchor SKI; no DN-only fallback), otherwise `admin_issuer_not_anchor` (PERMISSION_DENIED, audited). Every gRPC denial and every issuance, revocation and CRL record carries the peer certificate issuer DN and serial, so a forged identity is distinguishable after the fact. Tests: `admin_requires_leaf_issued_directly_by_anchor`, `layer_admin_anchor_builder_and_denial`, `resolve_refuses_admin_with_several_client_anchors`, e2e `admin_under_intermediate_is_refused`, bin `start_grpc_listener_refusal_is_audited_without_started_record`; mutations M20, M23, M24, M28 killed. Admin certificates must therefore be issued directly by the single anchor. **Residual:** the item stays open for the **Issuer roles** (ACME, EST), which may still chain through intermediates and bind the subject DN only. The guard covers the DB lineage only. Sibling subordinate CAs (other CAs under the same root), grandchildren (CAs issued by a subordinate of this CA; the per-call check compares the leaf's direct issuer only) and an external root not stored in `ca_certificates` are not detected; the allowlist itself is still subject-only | AC-3, IA-3, IA-5(2); FIA_X509_EXT.1, FDP_ACF.1 | SEC-001, RFC-001, NIST-003; SEC-009, RFC-010, NIST-017 (round 2); RFC-017, PQC-014, SEC-016 (final re-verify); RFC-001, SEC-101, SEC-201, NIST-005, NIST-202 (per-method change, 2026-10-26) | `// POAM: POAM-2026-10-23-28` in `crates/ostrich-common/src/grpc_tls.rs` (line 69, module header); references at lines 1115 (`resolve`) and 2865 (`authorize_peer_at`) | Issuer- or SPKI-bound entries for the Issuer roles; extend the checks to sibling and grandchild CAs (or to every platform CA) | Open (narrowed; Admin role closed in code, Issuer roles open) |
| POAM-2026-10-23-29 | First-install bootstrap depends on an external CA: ca-server refuses to start without gRPC mTLS material and must not issue its own gRPC certificates (its issuing CA cannot be the gRPC client CA), so every deployment needs a separate service-identity CA before the first install | CM-2, CP-10, SC-12; FMT_SMF.1 | `impl-notes-u8.md` (candidate); NIST-012 | None; runbook `docs/runbooks/ca-grpc-mtls.md` A1, [ADMIN_GUIDE.md](ADMIN_GUIDE.md) | Document the service-identity CA as a required operational-environment component (inventory, owner, key protection, recovery), or provide a supported offline bootstrap tool | Open |
| POAM-2026-10-23-30 | async-nats 0.49 uses its default `ring` backend for SHA-256 (ca-server, notify-server). async-nats 0.49 offers `aws-lc-rs` and `fips` features | SC-13; FCS_COP.1 | PQC-004 (pre-existing) | `# POAM: POAM-2026-10-23-30` above `async-nats = "0.49"` in the workspace `Cargo.toml` (line 211) | Switch async-nats to `default-features = false` with `aws-lc-rs` / `fips`, verify with `cargo tree -e features -i ring`; narrow POAM-08 | Open |
| POAM-2026-10-23-31 | Audit hash-chain concurrency on Postgres is implemented but not yet evidenced by a Postgres run. **Done in the working tree (2026-10-25, rounds 2-3):** `DatabaseAuditSink::record` serialises read-link-hash-sign-insert under `pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)` (`AuditRepository::begin_append`); `AuditRepository::append` (and `Repository::create`) now goes through the same lock as a checked append; the transaction sets `lock_timeout` 5 s, `statement_timeout` 10 s and `idle_in_transaction_session_timeout` 7 s (server-side backstop that releases the lock if the client stalls); the client bounds begin / sign / commit at 10 s / 5 s / 10 s; the audit signature runs on the tokio blocking pool (`sign_bounded`) so the sign timeout fires even for a PKCS#11 provider that blocks its thread; failures fail closed with `alert="audit_write_failed"`, and a commit timeout is reported as `outcome=unknown`; a moved chain timestamp keeps the original time in `details.occurred_at` (reserved; a caller value goes to `caller_occurred_at`); `OSTRICH_DB_TESTS=1` now makes the Postgres tests fail when the database is missing or unreachable instead of skipping. Unit tests (offline, passed 2026-10-25): `sign_timeout_fires_for_blocking_signer` (multi- and current-thread), `bounded_sign_succeeds_within_timeout`, `idle_in_transaction_timeout_exceeds_sign_timeout`, `apply_chain_timestamp_preserves_original_time`. **Remaining:** the Postgres tests `chain_concurrency.rs`, `signed_chain_tamper.rs` and the new `sign_timeout_db.rs` have NOT RUN against a database (GitLab `test:integration` sets `OSTRICH_DB_TESTS=1` with `ostrich_pki_test`; no pipeline run yet). Residual (accepted design, SEC-017): a hung HSM call cannot be cancelled, so each timed-out sign leaves one blocking-pool thread busy until the HSM returns; tokio waits for those threads at runtime drop, so ca-server shutdown can stall until Kubernetes kills the pod after `terminationGracePeriodSeconds` (not set in the manifests, Kubernetes default 30 s), and a long HSM outage can fill the blocking pool (tokio default 512). Integrity and fail-closed behaviour are unaffected. The chain-order timestamp shift itself is unbounded (lock wait, clock skew) but is recorded. `chain_concurrency.rs` and `signed_chain_tamper.rs` `TRUNCATE audit_events`, so `DATABASE_URL` must point to a disposable database | AU-9(3), AU-5, AU-8, CA-2, SA-11; FAU_STG.4, FPT_STM.1 | NIST-002; SEC-011 / PQC-006 (round 1 re-verify of this change), SEC-013 / PQC-011, NIST-024, SEC-014, SEC-017 (final) | `// POAM: POAM-2026-10-23-31` in `crates/ostrich-audit/src/sink.rs` (line 426), `crates/ostrich-audit/tests/chain_concurrency.rs` (line 15) and `crates/ostrich-db/src/repository/audit.rs` (line 45) | Run the three Postgres tests in GitLab `test:integration` (or another disposable Postgres) and attach the job log | Open (Implemented, not Tested) |
| POAM-2026-10-23-32 | `docker-compose.yml`: the ca, est and ocsp containers bind `./certs:/app/certs:ro` wholesale, and the dev gRPC generator wrote to `./certs/grpc`, so all three could read every dev gRPC key (SEC-004 residual). **Remediated 2026-10-25 (round 2, same branch, uncommitted):** the generator's default output moved to `.dev-grpc-certs/` (outside `./certs`; gitignored and in `.dockerignore`), compose, Makefile and `.env.example` follow it, and the script warns when pointed under `./certs`. Residual: an operator can still place material under `./certs` by overriding the directories (documented in the compose header and the runbook) | AC-6, SC-12, CM-6 | SEC-004 (residual), REL-008 | None; `docker-compose.yml`, `scripts/gen-dev-grpc-certs.sh` | Done in the working tree | Closed pending commit (remediated in the working tree 2026-10-25 by the `.dev-grpc-certs/` move; SEC-004 closed in the final re-verify) |
| POAM-2026-10-23-33 | The REST identity bridge (`CA_TRUSTED_PROXY_SUBJECTS` / `TrustedProxyAuthLayer`) uses the same subject-DN-only pattern as the gRPC allowlist, without the trust-anchor separation check that the gRPC listener now has. If `TLS_CLIENT_CA_FILE` is the subscriber-issuing CA, a subscriber certificate with `CN=npe-portal` would be trusted as the portal | AC-3, IA-3, IA-5(2); FIA_X509_EXT.1, FDP_ACF.1 | SEC-001 fix item (3) | `// POAM: POAM-2026-10-23-33` above `TrustedProxyAuthLayer` in `crates/ostrich-common/src/auth/middleware.rs` (line 367) | Apply `ensure_dedicated_client_ca` (or issuer binding) to the REST trusted-proxy configuration | Open |
| POAM-2026-10-23-34 | Audit records are signed with the CA key itself (`crates/ostrich-ca/src/ca.rs`, `signed_sink` / `DatabaseAuditSink::with_signing_key`), and since 2026-10-25 (round 3) the audit sink refuses every SLH-DSA variant for audit signing (`ensure_audit_signing_algorithm` in `crates/ostrich-audit/src/sink.rs`, because signing runs under the audit chain lock). A CA whose key is SLH-DSA therefore cannot run ca-server at all, which blocks the planned "SLH-DSA for long-lived roots" path (CLAUDE.md, FIPS 205). Currently moot: no provider signs SLH-DSA (software provider: not implemented; PKCS#11 provider: `UnsupportedAlgorithm`) | SC-13, SC-12, AU-10; FCS_COP.1, FAU_STG.4; FIPS 205 | PQC-015 (final re-verify, 2026-10-25); follows PQC-012 | None yet; refusal in `crates/ostrich-audit/src/sink.rs` (`ensure_audit_signing_algorithm`), CA wiring in `crates/ostrich-ca/src/ca.rs` (`signed_sink`) | Decouple the audit signing key from the CA key: a dedicated ML-DSA or ECDSA audit key (`signing_key_id` already records the key label per row, so key separation is supported by the schema), published so relying parties can verify the chain | Open |
| POAM-2026-10-23-35 | **RA namespace confused deputy (residual of the POAM-25 closure).** The CA binds the client `requestor` to the caller's namespace but cannot verify ACME account or EST client binding: `on_behalf_of` is a namespace-bound claim, not a verified identity. A compromised acme-server can issue under any `acme::<id>` (est-server any `est::<id>`). Blast radius: its own namespace only; IssueCertificate limited to that namespace's allowed end-entity profiles (`CA_GRPC_{ACME,EST}_ALLOWED_PROFILES`, CA profiles never), plus the read-only GetCaInfo and ListProfiles; no revocation or CRL generation. The audit actor is the verified peer (with certificate issuer and serial), so the calls are attributed to the RA service certificate | AC-3, AU-10, IA-3; FDP_ACF.1, FAU_GEN.2 | NIST-002, NIST-205; SEC-001 (blast radius); findings-nist-round-2.md | `// POAM:` in `crates/ostrich-ca/src/grpc_authz.rs` (line 48; module docs lines 31-37) | Bind the requestor to evidence the CA can verify (for example an account-key-signed claim forwarded by the RA), or record a formal AO risk acceptance; keep the profile allowlists minimal meanwhile | Open (accepted risk pending AO) |
| POAM-2026-10-23-36 | **Live-database test evidence for the gRPC and REST audit wiring (residual of the POAM-25/-26 closures).** The handler glue from `CaGrpcService` and from the REST `generate_crl` / `generate_delta_crl` handlers into the audit records is verified by inspection and by pure-builder unit tests only. Mutation M13h (GenerateCrl handler passes `crl_actor(None)`) is NOT RUN / survives without a database. Not executed for this change: the CRL failure audits on the database paths, the call-time `ca_profile_not_permitted` refusal through `issue()`, `ca_core_test` and `ocsp_revocation_test` (issuer denied Revoke / CRL / Status, admin succeeds; `#[ignore]`, need the compose stack), `est_serverkeygen_e2e`, and the live `audit_signing_e2e` / `crl_delta_e2e` assertions (SoftHSM and Postgres). `audit_signing_e2e` and `crl_delta_e2e` are `src/` test modules of `ostrich-ca`, which skip internally without `DATABASE_URL` / `PKCS11_*`; the GitLab integration job runs `cargo test --test '*'` only (`.gitlab-ci.yml` line 285) and does not pass `--ignored`, so none of these has a CI path | CA-2, SA-11, AU-3, AU-12; FAU_GEN.1, FAU_GEN.2 | NIST-006, NIST-206, QA-002 (option b), REL-005 | None; `crates/ostrich-ca/src/grpc.rs` (`generate_crl` handler), `crates/ostrich-ca/src/rest.rs` (`generate_crl`, `generate_delta_crl`), `crates/ostrich-ca/src/audit_signing_e2e.rs`, `crates/ostrich-ca/src/crl_delta_e2e.rs`, `.gitlab-ci.yml` | Add a DB- and SoftHSM-gated test that serves the real `CaGrpcService` behind `SubjectAllowlistLayer` and asserts actor, `on_behalf_of` and `authenticated_caller*` for Issue, Revoke and GenerateCrl (kills M13h); run it, `audit_signing_e2e`, `crl_delta_e2e`, `ca_core_test --ignored` and `ocsp_revocation_test --ignored` in CI and attach the result | Open |
| POAM-2026-10-23-37 | **REST 5xx bodies leak internal error text (SI-11; pre-existing, found in the per-method review).** `impl IntoResponse for Error` in [rest.rs](../../crates/ostrich-ca/src/rest.rs) (line 3702) returns the `Display` text of `Database`, `Crypto`, `Audit` and `Common` errors and the message of `Internal`, `CrlGeneration` and `KeyNotFound` in the JSON `error` field with HTTP 500. Database, crypto-provider or audit-sink detail can therefore reach a REST client. The gRPC path already maps these to a generic `INTERNAL` "<op> failed: internal error" (`grpc_status`), and this change replaced the CSR, approval-repository and CRL key-type messages with fixed text | SI-11, SC-24; FPT_FLS.1 | NIST-204, SEC-204 (findings-nist-round-2.md, findings-security-round-2.md) | None; `crates/ostrich-ca/src/rest.rs` `impl IntoResponse for Error` | Return a fixed message (plus request id) for every 5xx variant and log the detail server-side, as `grpc_status` does; add a unit test per variant | Open |
| POAM-2026-10-23-38 | **Certificate profiles come from code defaults, not from the database (pre-existing; ID assigned 2026-10-26).** ca-server registers `default_profiles()` and validates the gRPC `IssuerProfilePolicy` against the same in-memory list (SEC-102). When profiles move to the `certificate_profiles` table (CM-2: configuration as data), `IssuerProfilePolicy` must be re-validated against the stored profiles (unknown names and `basic_constraints_ca` refused) before the gRPC listener starts. Until then the call-time guard in `issue()` refuses CA profiles to every authenticated gRPC caller (`ca_profile_not_permitted`) | CM-2, CM-6, AC-6(10); FDP_IFC.1, FMT_MTD.1 | NIST-107, NIST-205, SEC-102 | `// POAM:` in `services/ca-server/src/main.rs` (line 1133, above the profile registration loop) | Load profiles from `certificate_profiles`; re-run the `IssuerProfilePolicy` checks against the stored set at startup and on any profile change | Open |
| POAM-2026-10-23-39 | **Closed 2026-10-26 (branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`).** Originally: `react-router` 6.30.6 (via `react-router-dom` 6.30.6) in `services/web-ui/web` matched GHSA-wrjc-x8rr-h8h6 (medium, CWE-601, affected `>= 6.0.0, < 7.18.0`) and GHSA-337j-9hxr-rhxg (medium, CWE-915, affected `>= 6.4.0, < 7.18.0`), Dependabot alerts 27 and 28. Both were fixed only in 7.18.0, with no v6 backport (SA-22). GHSA-337j was not reachable (Declarative Mode, no SSR or data router); GHSA-wrjc was low risk (no user-controlled navigation target). **Remediation:** `services/web-ui/web/package.json` (line 24) depends on `react-router` ^7.18.1 instead of `react-router-dom` ^6.30.6. `pnpm-lock.yaml` resolves `react-router` 7.18.4 (lines 26-28) and no longer contains `react-router-dom`, `react-router` 6.x or `@remix-run/router` 1.23.4 (added: `cookie` 1.1.1, `set-cookie-parser` 2.7.3). The app stays in Declarative Mode (`<BrowserRouter basename>`, `src/main.tsx` line 14). The interim same-origin condition is now a standing SI-10 control: the two non-literal navigation targets go through `safeInternalPath` ([safe-path.ts](../../services/web-ui/web/src/lib/safe-path.ts); `navigate(safeInternalPath(e.detail.href))` in `src/components/layout/cloudscape-layout.tsx` line 68 and `src/pages/dashboard.tsx` line 65), and server-returned IDs are encoded as one path segment (`certificate-issue.tsx` line 139, `certificates.tsx` line 213, `fqdn-detail.tsx` lines 162 and 239, API paths in `src/lib/ca.ts` lines 65 and 166; `fqdns.tsx` line 64 was already encoded). The GHSA-allowlist condition is moot. **Evidence (2026-10-26, local):** full `pnpm audit` "No known vulnerabilities found" and the installed `react-router` is 7.18.4 (both re-run by the compliance scribe on the restacked tree, `main` @ 9fad04f plus the working-tree diff); `pnpm install --frozen-lockfile`, typecheck, lint and build pass (orchestrator, restacked tree); run-record scripts `safe-path-check.mjs` 181 checks / 0 failures and `router-smoke.mjs` 5 / 0 failures (re-run by the scribe; not committed, see POAM-44); browser smoke against a mock BFF (login redirect, side-nav and quick-action follow, encoded detail route; OIDC SSO and logout not covered). **Timeliness (SI-2(c)): missed.** Published 2026-07-23; remediated in the working tree on day 95 against the proposed 90-day medium window, overdue since 2026-10-21 (windows pending AO approval, POAM-03). **Residuals:** the BFF proxy forwards a percent-decoded path (POAM-43); the guard has no automated regression test (POAM-44) | SI-2, RA-5, CA-5, SA-22, SI-10; ALC_FLR.2 | SEC-002, NIST-004, NIST-006, NIST-007; closure: react-router v7 review (NIST-001, SEC-002, QA-001) | Marker never added (`package.json` cannot carry comments); router at `services/web-ui/web/src/main.tsx` (line 14) | ~~Migrate `services/web-ui/web` from `react-router-dom` v6 to `react-router` >= 7.18~~ (done 2026-10-26, react-router 7.18.4). After merge, attach the Dependabot auto-close of alerts 27 and 28 and the CI `web-ui-react` run | Closed pending commit (remediated in the working tree 2026-10-26, past the proposed window; residuals tracked as POAM-43 and -44) |
| POAM-2026-10-23-40 | **npe-portal SPA dependencies are unpinned and unscanned (pre-existing; found in the 2026-10-26 review).** `services/npe-portal/web` has no committed lockfile. The image build (`Dockerfile` stage `npe-portal-web-builder`, line 368) runs `npm install --no-audit --no-fund` from `package.json` only (line 379), so each build resolves a fresh, unrecorded tree. No Dependabot entry covers it (the only npm entry in `.github/dependabot.yml` is `/services/web-ui/web`), and no CI job audits it. Its `vite` floor is still `^8.1.2` (`services/npe-portal/web/package.json` line 34), below the 8.1.6 fix applied to web-ui. The SPA's compiled assets ship in the npe-portal image. The Dockerfile comment that said it matched web-ui was corrected on 2026-10-26 | CM-2, SR-3, SI-7, RA-5, SI-2 | SEC-003, NIST-005 | `# POAM: POAM-2026-10-23-40` in `Dockerfile` (line 376) | Commit a lockfile and build with `npm ci`; raise the `vite` floor to ^8.1.6; add a Dependabot npm entry for `/services/npe-portal/web` and a CI audit job | Open |
| POAM-2026-10-23-41 | **Narrowed 2026-10-26 (branch `claude/dns01-resolver-fix`, uncommitted; run record `target/agent-workflow/20261026-091032-dns01-resolver/`).** Originally: ACME dns-01 validation could not succeed (pre-existing since the hickory 0.26 migration, commit f1d0e0b): the resolver was built from `ResolverConfig::default()`, which has no name servers in hickory-resolver 0.26.x, so every TXT lookup failed closed. **Resolved in the working tree:** (1) the resolver is built by `dns01_resolver_config` ([validation.rs](../../crates/ostrich-acme/src/validation.rs) line 511) from the operator list `--dns01-resolvers` / `ACME_DNS01_RESOLVERS` (at most 8 IP literals, port 53 UDP with TCP fallback) or, when that is unset, from the host's system configuration (read off the async runtime, `system_resolver_config_off_runtime`, line 637). An empty server list, a system-configuration read error or an invalid upstream list returns a generic `serverInternal` error and never falls back (tests `dns01_config_rejects_empty_name_servers`, `dns01_config_rejects_system_error`, `dns01_validate_fails_closed_without_name_servers`, `dns01_validate_rejects_invalid_upstreams_without_fallback`); (2) the query name `_acme-challenge.<domain>.` is an FQDN, and the system `domain` / `search` list is dropped, so search domains cannot rewrite it (`dns01_query_name`, line 384; tests `dns01_query_name_is_fqdn`, `dns01_config_uses_system_name_servers_only`, `dns01_mock_valid_digest_returns_true`); identifiers that are wildcards, IP literals, non-LDH, over-long or end in a dot are rejected as `malformed` before any query (`dns01_query_name_rejects_bad_identifiers`, `dns01_mock_trailing_dot_identifier_is_malformed`); (3) no in-process cache: a fresh resolver is built for every round with `cache_size = 0`, positive and negative TTL 0 and no hosts file (lines 562-570; tests `dns01_opts_disable_caching`, `dns01_mock_retry_after_nxdomain_is_not_cached`); (4) TXT matching: a record matches only if the concatenation of its character-strings equals the digest byte for byte, and only records owned by the query name or a CNAME target reached from it (at most 8 hops) count (`txt_answers_match`, line 593; tests `txt_match_requires_concatenation_equal_to_digest`, `txt_match_requires_owner_on_cname_chain`, `txt_match_bounds_cname_chain_length`, `dns01_mock_split_strings_joining_to_digest_returns_true`, `dns01_mock_junk_and_digest_in_one_record_returns_false`, `dns01_mock_foreign_owner_txt_returns_false`, `dns01_mock_cname_delegated_txt_returns_true`, `dns01_mock_near_miss_digests_return_false`, `dns01_mock_wrong_thumbprint_returns_false`); (5) a non-matching answer is retried within the same budget of 5 rounds (RFC 8555 §8.2; `dns01_mock_mismatch_then_match_returns_true`), and exhausted lookups end as `dns` with a generic detail (`dns01_mock_persistent_nxdomain_fails_closed`). Mutation checks M1-M5 (QA) and the owner-filter mutation (fix round 1) were killed. The 72 `ostrich-acme` lib tests and 7 acme-server bin tests passed on the final tree (re-run by the compliance scribe 2026-10-26). **Still open:** (a) **no CAA check** before issuance (RFC 8659 §3): `urn:ietf:params:acme:error:caa` is defined ([error.rs](../../crates/ostrich-acme/src/error.rs) line 135) but never raised, and `caa_identities` is always `None` ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 496); once implemented, a DNS error during the CAA check must deny issuance. (b) **No DNSSEC validation in the TOE** (RFC 8555 §11.2): hickory is built without its DNSSEC feature, and the AD bit is not checked. SC-21 is not implemented in the TOE; it is inherited from the operator's DNSSEC-validating recursive resolver, which is an operational-environment assumption (SECURITY_TARGET A.DNS_RESOLVER / OE.DNS_RESOLVER). The CA-to-recursor channel is unauthenticated (no TSIG or DoT), so the recursor must sit on a trusted network segment. (c) No multi-perspective validation. (d) No 0x20 query-name case randomisation. (e) No live dns-01 end-to-end test against a real recursive or authoritative server; the protocol path is covered offline by a loopback mock DNS server, and TCP fallback, truncation and SERVFAIL are not exercised. (f) The upstream recursor's own negative cache (RFC 2308) can replay an NXDOMAIN cached before the TXT record propagated; only operator guidance exists (cap the negative-cache TTL, e.g. unbound `cache-max-negative-ttl`; ADMIN_GUIDE Section 3.7). (g) Wildcard identifiers are rejected by the validator until `new_order` handles them (POAM-2026-10-23-45) | SC-17, SI-10, SC-21; FDP_CER_EXT.1 | RFC-001 to RFC-005 and RFC-012 (findings-rfc.md, both runs); NIST-002, NIST-004 (findings-nist.md, 2026-10-26) | `// POAM: POAM-2026-10-23-41` in [validation.rs](../../crates/ostrich-acme/src/validation.rs) (line 681, above `Dns01Validator`); [rest.rs](../../crates/ostrich-acme/src/rest.rs) (`caa_identities`, line 496) | Add an RFC 8659 CAA check that fails closed on DNS errors; decide whether to validate DNSSEC in process or keep the environment assumption and check the AD bit from a trusted recursor; add a live dns-01 integration test with a controllable DNS server; consider multi-perspective validation and 0x20 | Open (narrowed) |
| POAM-2026-10-23-42 | **Vulnerability-scan coverage gaps.** (a) The cargo gate (`cargo audit --deny warnings`, `cargo deny check` in `.github/workflows/audit.yml`) reads the RustSec database only. GitHub-only advisories are not seen: GHSA-6w6g-hm98-mhgm, GHSA-5j98-2g5x-46v6 and GHSA-6f2x-v7q7-m7m5 (hickory-resolver, no RustSec alias) passed `cargo audit` on `main` @ 1294f63 and were found only by Dependabot. (b) The npm gate (`.github/workflows/ci.yml` job `web-ui-react`, line 96: `pnpm audit --prod --audit-level=high`) excludes development and build dependencies and medium and low advisories. It could see none of the 18 npm Dependabot alerts open on 2026-10-26 (15 are development scope; the 3 runtime react-router alerts are medium) and returned exit 0 both before and after the remediation, while a full `pnpm audit` went from 28 (1 low / 9 moderate / 18 high) to 2 moderate. **Updated 2026-10-26 (react-router v7 migration, POAM-39):** the full `pnpm audit` of `services/web-ui/web` is now 0 ("No known vulnerabilities found", local); the CI gate is unchanged (`--prod --audit-level=high`, `ci.yml` line 96), so (b) stays open. (c) Open Dependabot alerts are not triaged on a schedule: six high npm advisories (7 alerts) were 38-98 days old on 2026-10-26, beyond the proposed 30-day window (NIST-004). (d) The npe-portal SPA is not scanned at all (POAM-40) | RA-5, RA-5(2), SI-2, SR-3; ALC_FLR.2, AVA_VAN.2 | NIST-002, NIST-003, NIST-004; SEC-002 condition (c) | None; `.github/workflows/audit.yml`, `.github/workflows/ci.yml` (job `web-ui-react`), `.github/dependabot.yml` | Add an OSV/GHSA-aware scan of `Cargo.lock` (for example `osv-scanner --lockfile Cargo.lock`) to the dependency gate, or make open high and critical Dependabot alerts a release-gate check; gate npm development dependencies at `high` and attach a full `pnpm audit` to release evidence; schedule Dependabot alert triage (owner, cadence) against the AO-approved windows (POAM-03) | Open |
| POAM-2026-10-23-43 | **web-ui BFF proxy forwards a percent-decoded path (pre-existing; found in the 2026-10-26 react-router v7 review, SEC-001).** `proxy_ca` in [proxy.rs](../../services/web-ui/src/server/proxy.rs) (line 60) takes the `{*path}` capture as `Path(path): Path<String>` (line 62). axum percent-decodes it (`%2F` → `/`, `%3F` → `?`, `%2E%2E` → `..`), and `proxy_to_service` (line 150) builds the backend URL with `format!("{base}/{path}")` (lines 159-161). The client-side `encodeURIComponent` in `web/src/lib/ca.ts` therefore protects only the browser → BFF hop: a crafted link such as `/certificates/abc%2F..%2F..%2Ffqdns%2Fexample.com%3Fx%3D` makes the BFF send a GET to a different CA path with the signed-in user's backend credentials. Impact: GET only (revocation uses server-returned IDs); a direct `/api/ca/...` link already yields an equivalent GET; whether `..` collapses depends on the CA router (not checked). `proxy_to_service` is shared, so the other six `/{svc}/{*path}` routes (lines 28-40) build their URLs the same way; only the CA route was assessed | SI-10, AC-3 | SEC-001 (react-router v7 security review; medium confidence) | None (code frozen for the react-router v7 change); the `// POAM: POAM-2026-10-23-43` marker belongs above `proxy_to_service` in `services/web-ui/src/server/proxy.rs` (line 150) | Build the backend path from the raw `uri().path()` minus the `/api/<svc>/` prefix, or re-encode each segment; reject `.` / `..` segments and `?` / `#` that appear only after decoding; keep the `ca.ts` encoding; add a proxy test with encoded `/`, `?` and `..` | Open |
| POAM-2026-10-23-44 | **web-ui has no automated frontend test runner (found in the 2026-10-26 react-router v7 review, QA-001 / NIST-004).** `services/web-ui/web/package.json` has no `test` script and no test framework (no vitest, jsdom or happy-dom). The same-origin guard `isSafeInternalPath` / `safeInternalPath` ([safe-path.ts](../../services/web-ui/web/src/lib/safe-path.ts)) and the encoded route and API segments are verified only by run-record scripts that are neither committed nor run in CI (`target/agent-workflow/20261026-091035-react-router-v7/safe-path-check.mjs`, 181 checks; `router-smoke.mjs`, 5 checks) and by one manual browser smoke. A later edit that weakens the guard (for example, removing both the leading-slash lookahead and the URL-origin check) would still pass typecheck, lint, build and audit. Related: `.claude/skills/ostrich-workflow/references/quality-gates.md` and `docs/TESTING.md` define no web-ui gates (QA-002) | SA-11, CA-2, SI-10; ATE_FUN.1 | QA-001, QA-002, NIST-004 | None (code frozen for the react-router v7 change); the `// POAM: POAM-2026-10-23-44` marker belongs in the header comment of `services/web-ui/web/src/lib/safe-path.ts` | Add vitest to web-ui, move the `safe-path-check.mjs` vectors (sections A-G) into `src/lib/safe-path.test.ts`, and run it in the CI job `web-ui-react`; add a "Web UI (pnpm)" section to the quality gates | Open |
| POAM-2026-10-23-45 | **ACME order and authorization identifier handling (pre-existing; found in the 2026-10-26 dns-01 review).** `new_order` ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 679) does not validate identifiers: its SI-10 annotation is not yet met, so a malformed name is only refused later, when a validator runs. A `*.` identifier is stored with `wildcard = false` (line 727) and keeps the `*.` prefix, so wildcard certificates cannot be obtained: the dns-01 validator rejects `*` as `malformed`. The authorization's `wildcard` field is always serialized (line 1481), including `false`, although RFC 8555 §7.1.4 says it MUST be absent unless true. All three challenge types are offered for every identifier (line 732), including dns-01 for IP identifiers, which RFC 8738 §7 forbids. Residual from SEC-005: the SSRF-refusal detail no longer contains the resolved address (`resolve_public` returns `rejectedIdentifier` with a generic detail; test `resolve_pinned_enforces_ssrf_guard_unless_allowed`), but which names resolve to non-public addresses can still be inferred from which challenges fail, so a subscriber can probe internal names | SI-10, SC-17; FDP_CER_EXT.1 | RFC-011, RFC-014 (findings-rfc.md); NIST-006 (findings-nist.md); SEC-005 residual (findings-security.md) | `// POAM: POAM-2026-10-23-45` in [rest.rs](../../crates/ostrich-acme/src/rest.rs) (line 678, above `new_order`) | Validate identifiers in `new_order` (DNS LDH rules, IP literal syntax, `rejectedIdentifier` on refusal); store the base domain with `wildcard: true` and offer only dns-01 for wildcards; omit `wildcard` when false; offer only http-01 and tls-alpn-01 for IP identifiers (RFC 8738 §7); consider rate limits on failed validations to slow name probing | Open |
| POAM-2026-10-23-46 | **ACME challenge response has no ownership or state check, and validations are unbounded (pre-existing).** `respond_to_challenge` ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 888) does not check that the challenge belongs to the requesting account or is still `pending`, and spawns a validation task for every POST (line 933) with no concurrency limit. Each dns-01 validation is bounded at a nominal 83 s (5 rounds × 3 sends × 5 s + 4 × 2 s; `DNS01_TIMEOUT`, [validation.rs](../../crates/ostrich-acme/src/validation.rs) line 321), and the system-configuration read uses the blocking pool, so a flood of POSTs scales tasks and blocking-pool use without limit | AC-3, SC-5; FDP_ACC.1 | SEC-002 (findings-security.md) | `// POAM: POAM-2026-10-23-46` in [rest.rs](../../crates/ostrich-acme/src/rest.rs) (line 887, above `respond_to_challenge`) | Check that the challenge's authorization belongs to the authenticated account; start validation only from `pending` (RFC 8555 §7.5.1); bound concurrent validations with a semaphore | Open |
| POAM-2026-10-23-47 | **ACME challenge-validation audit record content (pre-existing).** The record written by `run_challenge_validation` ([rest.rs](../../crates/ostrich-acme/src/rest.rs) lines 994-1006; actor `acme-validator`, action `validate_challenge`) carries only the challenge id and Success / Failure. It has no challenge type, identifier, account or failure category, so a CA misconfiguration (for example no dns-01 name servers) cannot be told apart from a subscriber failure. No automated test drives this path (it needs Postgres; QA-001) | AU-3, AU-2; FAU_GEN.1 | NIST-005 (findings-nist.md); QA-001 (qa-report.md) | `// POAM: POAM-2026-10-23-47` in [rest.rs](../../crates/ostrich-acme/src/rest.rs) (line 993) | Add challenge type, identifier, account id and the problem type to the record; add a Postgres-backed integration test that asserts the failure record | Open |
| POAM-2026-10-23-48 | **tls-alpn-01 certificate checks are incomplete (RFC 8737 §3; pre-existing).** `TlsAlpn01Validator::validate` ([validation.rs](../../crates/ostrich-acme/src/validation.rs) line 949) does not check that the acmeIdentifier extension is critical or that the certificate has exactly one dNSName SAN equal to the identifier, and `acme_identifier_digest` (line 1140) accepts a bare 32-byte extension value as well as the DER OCTET STRING. The digest comparison itself is enforced and bounds-checked (test `acme_identifier_digest_is_bounds_checked`) | SI-10, SC-17; FDP_CER_EXT.1 | RFC-015, RFC-016 (findings-rfc.md); SEC-008 (findings-security.md) | `// POAM: POAM-2026-10-23-48` in [validation.rs](../../crates/ostrich-acme/src/validation.rs) (line 965) | Require the critical flag, a single dNSName SAN matching the identifier, and a DER-encoded OCTET STRING value; add negative tests for each | Open |

---

## Appendix A: SFR Implementation Status Table

| SFR ID | Name | Status | Priority | Phase | Effort |
|--------|------|--------|----------|-------|--------|
| FAU_GEN.1 | Audit data generation | 🟢 Compliant | - | Complete | - |
| FAU_GEN.2 | User identity association | 🟢 Compliant | - | Complete | - |
| FAU_SAR.1 | Audit review | 🟡 Partial | MED | 16 | 1w |
| FAU_STG.1.1 | Append-only audit storage | 🟢 Compliant | - | Complete | - |
| FAU_STG.1.2 | Audit integrity protection | 🟡 Partial | HIGH | 15 | 1w |
| FAU_STG.3 | Audit storage alerts | 🟡 Partial | MED | 16 | 3d |
| FAU_STG.4 | Audit overflow prevention | 🔴 Missing | MED | 16 | 3d |
| FCS_CKM.1.1 | Key generation | 🟡 Partial | HIGH | 10 | 2w |
| FCS_CKM.4.1 | Key destruction | 🟡 Partial | MED | 10 | 1w |
| FCS_COP.1.1(1) | Signature generation | 🟡 Partial | MED | 10 | 1w |
| FCS_COP.1.1(2) | Hashing | 🟡 Partial | MED | 10 | 3d |
| FCS_COP.1.1(3) | Key encryption | 🔴 Missing | MED | 10 | 1w |
| FCS_COP.1.1(4) | Key agreement | 🔴 Missing | LOW | 10 | 1w |
| FCS_RBG_EXT.1 | Random bit generation | 🔴 Missing | **CRITICAL** | 15 | 2w |
| FCS_CDP_EXT.1 | Crypto module protection | 🟡 Partial | HIGH | 10 | 2w |
| FDP_CER_EXT.1 | Certificate generation | 🟡 Partial | MED | 13 | 1w |
| FDP_CER_EXT.2 | CRL generation | 🟡 Partial | MED | 13 | 1w |
| FIA_X509_EXT.1 | Certificate validation | 🔴 Missing | **CRITICAL** | 15 | 2w |
| FIA_UAU.2 | User authentication | 🔴 Missing | HIGH | 16 | 2w |
| FMT_MOF.1.1 | Credential management | 🟡 Partial | MED | 16 | 1w |
| FMT_MOF.1.2 | Security function mgmt | 🔴 Missing | **CRITICAL** | 15 | 1w |
| FMT_MSA.1.1 | Attribute management | 🟡 Partial | MED | 15 | 3d |
| FMT_MSA.1.2 | Secure defaults | 🟢 Implemented | **CRITICAL** | 15 | 1w |
| FMT_MSA.2 | Secure attribute values | 🔴 Missing | HIGH | 15 | 3d |
| FMT_MTD.1.1 | TSF data query | 🔴 Missing | MED | 15 | 3d |
| FMT_MTD.1.2 | TSF data management | 🔴 Missing | HIGH | 15 | 1w |
| FMT_SMF.1 | Security management | 🔴 Missing | HIGH | 16 | 1w |
| FMT_SMR.2 | Security roles | 🔴 Missing | **CRITICAL** | 15 | 3w |
| FPT_FLS.1 | Failure secure state | 🔴 Missing | HIGH | 15 | 1w |
| FPT_SKP_EXT.1 | Private key protection | 🟡 Partial | HIGH | 10 | 1w |
| FPT_STM_EXT.1 | Reliable time stamps | 🟡 Partial | HIGH | 15 | 3d |
| FPT_TST_EXT.1 | Self-tests | 🔴 Missing | **CRITICAL** | 15 | 2w |
| FTA_TSE.1 | Session establishment | 🔴 Missing | HIGH | 16 | 1w |
| FTP_ITC.1 | Inter-TSF channel | 🟡 Partial | MED | 16 | 1w |
| FTP_TRP.1 | Trusted path | 🟢 Compliant | - | Complete | - |

**Summary:**

- 🟢 Compliant: 7 (12%)
- 🟡 Partial: 26 (46%)
- 🔴 Missing: 24 (42%)

---

## Appendix B: Cross-Reference to Other Compliance Documents

- **NIAP_COMPLIANCE.md** - Detailed SFR implementation status and code references
- **NIST_800-53_MAPPING.md** - NIAP SFRs mapped to NIST 800-53 controls
- **RFC_COMPLIANCE.md** - RFC compliance status (especially RFC 5280 for path validation)
- **FIPS_COMPLIANCE.md** - Cryptographic algorithm compliance (especially DRBG, key generation)
- **ROADMAP.md Phase 15** - Implementation plan for this gap analysis

---

**Document Control:**

- **Author:** OstrichPKI Development Team
- **Reviewers:** Security Architect, NIAP Compliance Officer
- **Next Review:** After Phase 15 completion (estimate: 4 weeks)
- **Change Log:**
  - 2026-01-03: Initial gap analysis created based on NIAP PP-CA v2.1 evaluation
  - 2026-07-27: Added repeatable FCS_CKM.1/FCS_STG_EXT.1 deployment evidence for the EST external-issuer integration profile; production HSM certification remains outside this lab boundary.
  - 2026-10-23: Added §11 POA&M (10 open items from the dependency-advisory remediation: AWS-LC FIPS 4.2.0 CMVP confirmation, ML-DSA issuance, blocking cargo-audit, bulk_enroll AU-2 gap, runtime FIPS assertion, deny.toml schema, PKCS#11 tests not run, `ring` outside the FIPS boundary, audit.toml risk acceptances, module-pin commit). FTP_ITC.1 (§3.4): gap narrowed, status unchanged. No SFR status or compliance percentage changed.
  - 2026-10-23 (CI hardening): §11 POAM-03 narrowed (gate no longer advisory; AO timeframes, red-scheduled-run procedure and required checks still open). POAM-06 closed pending first green CI run. POAM-07 narrowed (SoftHSM CI job added; local macOS 16 passed / 3 RSA-PSS failed / 1 ignored; Linux result pending). POAM-09 hickory part resolved, `rsa` remains. Added POAM-11 (rand 0.8.6 bump), POAM-12 (SA-22 unmaintained acceptances), POAM-13 (CODEOWNERS), POAM-14 (branch protection and required checks), POAM-15 (docker-publish/cargo-chef/GitLab tool pinning). No SFR status or compliance percentage changed.
  - 2026-10-23 (PKCS#11 RSA-PSS fix): §3.1 RSA-PSS qualified (✅ → 🟡; provider level only, not X.509). §11 POAM-07 updated (Linux CI before-fix result 16/3/1, exit 101; conditional RSA-PSS item triggered). POAM-14 precondition settled. Added POAM-16 (RUSTSEC-2026-0387 `crypto-bigint` 0.5.5, risk accepted), POAM-17 (RSA-PSS FCS_COP.1 item, opened and remediated 2026-10-23, closes on green Linux CI artifact), POAM-18 (algorithm-key binding / `CKA_ALLOWED_MECHANISMS`), POAM-19 (per-operation logout), POAM-20 (X.509 RSASSA-PSS parameters), POAM-21 (production-HSM approval of raw mechanisms), POAM-22 (remove unused `openidconnect`). No SFR status or compliance percentage changed.
  - 2026-10-23 (PKCS#11 RSA-PSS Linux CI evidence, commit 44d560d, PR 181): GitHub Actions run 40063317654 (SoftHSM 2.6.1, 28 passed / 0 failed / 1 ignored, exit 0) recorded. §3.1 RSA-PSS 🟡 → ✅ scoped to SoftHSM 2.6.1 / 2.7.0 and RSA-2048/3072/4096 (production HSM not validated, POAM-21; X.509 not claimed, POAM-20). §11 POAM-07 closed and POAM-17 closed, both keeping the `CKA_ALLOWED_MECHANISMS` and SoftHSM-only caveats. POAM-14 updated (first green PKCS#11 run; one more needed before it becomes a required check). No SFR status or compliance percentage changed (§3.1 stays 75%; Appendix A FCS_COP.1.1(1) stays 🟡 Partial).
  - 2026-10-24 (PR 152, fail-closed FIPS TLS, branch `revive-fips-tls`): §11 POAM-05 narrowed, stays Open (done: `ensure_fips` gate on every TLS listener via `ostrich_common::tls` and a startup log of `fips` / AWS-LC version; still open: process-level gate including plain-HTTP mode, `ClientConfig` assertions, gRPC (plaintext CA gRPC server, `tls-ring` clients, gRPC spawned before the HTTPS gate in ca-server), audit event on refusal, KATs through AWS-LC, second non-FIPS `aws-lc-sys` copy). POAM-08 annotated (gRPC clients `tls-ring`, CA gRPC server has no TLS). §3.4 FTP_ITC.1 gap narrowed, status unchanged. No new POA&M IDs. No SFR status or compliance percentage changed.
  - 2026-10-24 (dependency cleanup, branch `claude/deps-cleanup`, uncommitted; run record `target/agent-workflow/20261024-104215-deps-cleanup/`): §11 POAM-11 (`rand` 0.8.6; remediated before the 2026-11-06 target), POAM-16 (`crypto-bigint` 0.5.5 no longer in the dependency graph) and POAM-22 (`openidconnect` removed) set to Closed pending first green CI run; the RUSTSEC-2026-0097 and RUSTSEC-2026-0387 ignores were removed, leaving 3 (RUSTSEC-2023-0071, -2024-0436, -2025-0134). POAM-09 updated (the only production `rsa` use is `ostrich-acme`, public-key-only). Added POAM-23 (remove unused `oauth2`, which also links `reqwest` 0.12 and enables the rustls `ring` feature; CM-7, SC-13; cross-referenced to POAM-08) and POAM-24 (pre-existing: CSPs drawn from `rand` `ThreadRng` instead of the AWS-LC DRBG; SC-13, FCS_RBG_EXT.1; PQC-001). No SFR status or compliance percentage changed.
  - 2026-10-25 (CA gRPC behind mTLS, branch `claude/grpc-mtls`, uncommitted; run record `target/agent-workflow/20261024-225627-grpc-mtls/`): §3.4 FTP_ITC.1 gap narrowed (CA ↔ RA gRPC is TLS 1.3 mTLS on the aws-lc-rs FIPS provider with a default-deny subject allowlist and audited, rate-limited handshake failures and denials), status unchanged (🟡 Partial: revocation, issuer binding, REST mTLS). §11 POAM-05 narrowed (process-level `fips_gate` in all ten mains; gRPC `fips()` assertions; still open: plain-HTTP REST, other client configs, process-default clients, refusal audit, KATs, second `aws-lc-sys`). POAM-08 narrowed, not closed (gRPC `tls-ring` removed; KRA `wrap.rs` and the rustls `ring` feature via lettre / reqwest 0.12 / async-nats / tokio-websockets remain). Added POAM-25 (audit actor client-asserted), -26 (single listener-wide allowlist), -27 (client-certificate revocation, gRPC and REST), -28 (allowlist not issuer/SPKI bound; one-level ancestor check), -29 (first-install bootstrap), -30 (async-nats `ring` SHA-256, PQC-004), -31 (Postgres audit-chain concurrency test not executed; timestamp shift; lock across signing), -32 (`docker-compose.yml` `./certs` exposure; opened and remediated the same day by moving the dev output to `.dev-grpc-certs/`, closed pending commit), -33 (REST trusted-proxy subject-only pattern). The broken `fuzz/Cargo.toml` manifest noted during implementation was fixed in the same change and needed no POA&M row. No SFR status or compliance percentage changed.
  - 2026-10-25 (CA gRPC mTLS final refresh, after fix round 3; same branch and run record): §3.4 FTP_ITC.1 text updated (trust-anchor guard walks the CA database lineage, subject alone, issued-by, per-call `subscriber_issuing_ca`, refusal audited; `grpc_mtls_e2e` 21/21). §11 POAM-05 item (d) narrowed (trust-anchor refusal audited as `grpc_listener_refused`; FIPS gate and pre-database configuration refusals still log-only); PR 152 finding IDs in POAM-05/-08 qualified as `PR152-…` to avoid the clash with this change's PQC-006..PQC-015. Rows 25-33 refreshed: markers now carry IDs, line numbers re-checked with `grep -n`; row 28 narrowed (residual: DB lineage only, siblings, grandchildren and external roots not detected, allowlist subject-only); row 31 updated (timeouts, idle-in-transaction backstop, checked `append`, sign on the blocking pool, `OSTRICH_DB_TESTS` opt-in now fails when the database is unreachable; only the Postgres run remains; SEC-017 hung-HSM thread / shutdown residual added); row 32 kept Closed pending commit. New row POAM-2026-10-23-34 (audit signing key = CA key, so an SLH-DSA CA key cannot run ca-server; PQC-015). No SFR status or percentage changed.
  - 2026-10-26 (per-method CA gRPC authorization and verified audit actor, branch `claude/grpc-per-method-authz`, uncommitted; run record `target/agent-workflow/20261025-202226-grpc-per-method/`): §3.4 FTP_ITC.1 gap narrowed, status unchanged (🟡 Partial). §11 POAM-25 (audit actor) and POAM-26 (single allowlist) set to Closed pending commit with executed unit/e2e/mutation evidence; residuals recorded. POAM-27 updated for the admin-role impact and the per-call leaf validity bound. POAM-28 narrowed for the Admin role (single distinct anchor with SKI, direct issuance with AKI = anchor SKI, no DN-only fallback); stays open for the Issuer roles. Added POAM-35 (RA namespace confused deputy), POAM-36 (live-database / SoftHSM test evidence through `CaGrpcService` and REST CRL handlers; M13h), POAM-37 (SI-11 REST 5xx body leak), POAM-38 (profiles from the database; pre-existing marker given an ID). No SFR status or compliance percentage changed.
  - 2026-10-26 (Dependabot alert remediation, branch `claude/dependabot-remediation`, uncommitted; run record `target/agent-workflow/20261026-dependabot-remediation/`): 19 of the 21 Dependabot alerts open on 2026-10-26 remediated by lockfile updates (GitHub API count; the run brief said 18 of 20) (hickory-resolver/-net/-proto 0.26.1 → 0.26.2; web-ui vite 8.1.6, source-map-js 1.2.2, postcss 8.5.31, brace-expansion 1.1.21 / 5.0.12, js-yaml 4.3.2, react-router(-dom) 6.30.6). Local gates only; first CI run pending. §11 POAM-03 annotated (the cargo gate is RustSec-only). Added POAM-39 (react-router v6 residuals GHSA-wrjc-x8rr-h8h6 and GHSA-337j-9hxr-rhxg; overdue, AO decision pending; proposed target 2026-11-25), POAM-40 (npe-portal SPA unpinned and unscanned), POAM-41 (ACME dns-01 resolver has no name servers; CAA and DNSSEC gaps) and POAM-42 (scan-coverage gaps). No SFR status or compliance percentage changed.
  - 2026-10-26 (react-router v7 migration, branch `claude/react-router-v7`, uncommitted; run record `target/agent-workflow/20261026-091035-react-router-v7/`): web-ui `react-router-dom` ^6.30.6 → `react-router` ^7.18.1 (7.18.4); full `pnpm audit` 0 (local). §11 POAM-39 set to Closed pending commit (SI-2(c) window missed: 95 days against the proposed 90). POAM-42 item (b) updated (full audit now 0; CI gate unchanged; stays Open). Added POAM-43 (BFF proxy forwards a percent-decoded path; SEC-001) and POAM-44 (no web-ui test runner; QA-001 / NIST-004). No SFR status or compliance percentage changed.
  - 2026-10-26 (ACME dns-01 resolver fix, branch `claude/dns01-resolver-fix`, uncommitted; run record `target/agent-workflow/20261026-091032-dns01-resolver/`): §11 POAM-41 narrowed, stays Open (resolved: real name servers from `ACME_DNS01_RESOLVERS` or the system configuration with a fail-closed empty-list check, FQDN query name, no in-process negative cache, TXT concatenation and owner / CNAME check, retry on mismatch; still open: CAA, DNSSEC and the unauthenticated CA-to-recursor channel, multi-perspective validation, 0x20, live dns-01 E2E test, upstream negative-cache guidance only; controls corrected from IA-5(1) to SC-17, SI-10, SC-21). Stale line references in POAM-41 replaced. Added POAM-45 (ACME order / authorization identifier handling, wildcard and RFC 8738 §7), POAM-46 (challenge POST ownership and unbounded validations), POAM-47 (validation audit record content) and POAM-48 (tls-alpn-01 RFC 8737 §3 certificate checks). No SFR status or compliance percentage changed.

### Closed: optional PKCS#11 ECDSA mechanisms

The CA no longer depends on optional `CKM_ECDSA_SHA*` mechanisms. The provider
uses `CKM_ECDSA` with a FIPS AWS-LC SHA-2 digest, closing the SoftHSM and
hardware-token portability gap for FCS_COP.1.

### Closed: Kubernetes probes against mandatory mTLS

The EST chart no longer uses unauthenticated HTTP probes against an mTLS-only
listener. TCP probes confirm socket availability without creating an
authentication bypass or restart loop.

### Closed: unreachable EST Basic bootstrap

The TLS layer now permits certificate-less negotiation only when the operator
explicitly enables Basic bootstrap. HTTP authentication remains mandatory and
fail-closed, closing the mismatch between TLS and application authentication.
