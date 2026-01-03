# NIAP Protection Profile Gap Analysis

**Document Version:** 1.0
**Generated:** 2026-01-03
**NIAP PP-CA Version:** v2.1 FINAL
**Current Compliance:** 29% (7/57 SFRs Compliant)
**Target Compliance:** 95%+ (54/57 SFRs)

---

## Executive Summary

This document provides a comprehensive gap analysis for OstrichPKI's compliance with the NIAP Protection Profile for Certification Authorities (PP-CA) v2.1. The analysis identifies 50 SFRs requiring attention (24 missing, 26 partial) and provides a prioritized remediation roadmap.

### Overall Status

| Category | Count | Percentage |
|----------|-------|------------|
| 🟢 Compliant | 7 | 12% |
| 🟡 Partial | 26 | 46% |
| 🔴 Missing | 24 | 42% |
| **Total SFRs** | **57** | **100%** |

### Compliance by Family

| Family | Compliant | Partial | Missing | Total | % Complete |
|--------|-----------|---------|---------|-------|------------|
| **FAU** (Security Audit) | 3 | 3 | 1 | 7 | 43% |
| **FCS** (Cryptographic Support) | 1 | 7 | 1 | 9 | 11% |
| **FDP** (Data Protection) | 0 | 1 | 0 | 1 | 0% |
| **FIA** (Identification/Auth) | 0 | 1 | 1 | 2 | 0% |
| **FMT** (Management) | 2 | 7 | 10 | 19 | 11% |
| **FPT** (Protection) | 0 | 3 | 6 | 9 | 0% |
| **FTA** (TOE Access) | 0 | 1 | 2 | 3 | 0% |
| **FTP** (Trusted Path) | 1 | 3 | 3 | 7 | 14% |

### Critical Gaps (Blockers for Certification)

1. **FCS_RBG_EXT.1** - DRBG implementation (CRITICAL)
2. **FMT_SMR.2** - Role-Based Access Control (CRITICAL)
3. **FIA_X509_EXT.1** - Certificate path validation (CRITICAL)
4. **FMT_MOF.1.2** - Security function management (HIGH)
5. **FPT_TST_EXT.1** - Self-tests (HIGH)
6. **FMT_MSA.1.2** - Secure attribute defaults (HIGH)

---

## 1. Critical Priority Gaps (Certification Blockers)

These gaps MUST be resolved before any certification attempt.

### 1.1 FCS_RBG_EXT.1 - Random Bit Generation

**Status:** 🔴 **Missing**
**Priority:** **CRITICAL**
**Risk:** Without NIST SP 800-90A compliant DRBG, the CA cannot generate secure keys or serial numbers
**Assigned Phase:** Phase 15
**Effort Estimate:** 2 weeks

**Current State:**

- No DRBG implementation exists
- Using `ring::rand::SystemRandom` (not validated as NIST SP 800-90A compliant)
- No entropy source documentation
- No DRBG self-tests

**Required Capabilities:**

```rust
// Required DRBG implementation
pub struct Drbg {
    // NIST SP 800-90A CTR_DRBG or HMAC_DRBG
    algorithm: DrbgAlgorithm, // AES-256 CTR mode or HMAC-SHA-256
    entropy_source: EntropySource,
    reseed_counter: u64,
    reseed_interval: u64, // Must reseed before 2^48 requests
}

impl Drbg {
    // FCS_RBG_EXT.1.1 - Generate random bits
    pub fn generate(&mut self, len: usize) -> Result<Vec<u8>>;

    // FCS_RBG_EXT.1.2 - Reseed from entropy source
    pub fn reseed(&mut self) -> Result<()>;

    // FPT_TST_EXT.1 - Continuous RNG test
    fn continuous_test(&self, output: &[u8]) -> Result<()>;
}
```

**Implementation Tasks:**

1. ✅ Create `crates/ostrich-crypto/src/drbg.rs` module (Phase 15)
2. ✅ Implement NIST SP 800-90A CTR_DRBG or HMAC_DRBG
3. ✅ Add entropy source abstraction (HSM, /dev/random)
4. ✅ Implement continuous health tests (repetition count, adaptive proportion)
5. ✅ Document entropy source and seeding procedures
6. ✅ Add unit tests for DRBG functionality
7. ✅ Integration testing with serial number generation

**Dependencies:**

- HSM integration (Phase 10) - HSM may provide validated DRBG
- Crypto provider abstraction already exists

**Test Criteria:**

- [ ] DRBG passes NIST CAVP testing vectors
- [ ] Continuous health tests detect failures
- [ ] Reseeding occurs before counter limit
- [ ] Serial numbers are unique and random

**Evidence Required:**

- NIST CAVP test results
- Entropy source documentation
- DRBG design and implementation documentation
- Self-test logs

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

**Status:** 🔴 **Missing**
**Priority:** **CRITICAL**
**Risk:** Cannot validate client certificates for mTLS authentication
**Assigned Phase:** Phase 15
**Effort Estimate:** 2 weeks

**Current State:**

- CSR validation stub exists ([crates/ostrich-x509/src/parser.rs:96-99](crates/ostrich-x509/src/parser.rs#L96-L99))
- No certificate path validation implementation
- No revocation checking (CRL/OCSP)
- No policy/constraint validation

**Required Capabilities (RFC 5280 §6):**

```rust
pub struct PathValidator {
    trust_anchors: Vec<TrustAnchor>,
    max_path_length: u8,
    permitted_name_subtrees: Option<Vec<GeneralSubtree>>,
    excluded_name_subtrees: Option<Vec<GeneralSubtree>>,
}

impl PathValidator {
    // FIA_X509_EXT.1.1 - Validate certificate path
    pub fn validate_path(&self, cert_chain: &[Certificate]) -> Result<ValidatedPath> {
        // 1. Build certification path to trust anchor
        // 2. Verify signatures
        // 3. Check validity periods
        // 4. Check revocation status (CRL/OCSP)
        // 5. Verify policy constraints
        // 6. Verify name constraints
        // 7. Verify basic constraints (CA flag, path length)
    }

    // FIA_X509_EXT.1.2 - Validate certificate fields
    pub fn validate_certificate(&self, cert: &Certificate) -> Result<()> {
        // 1. Signature algorithm in supported list
        // 2. Key usage consistent with purpose
        // 3. Extended key usage present and valid
        // 4. Subject/issuer DN non-empty
        // 5. SAN extension for subscriber certs
    }
}
```

**RFC 5280 §6 Requirements:**

1. **Basic Path Validation** (§6.1):
   - Trust anchor lookup
   - Signature verification
   - Validity period checking
   - Name chaining (issuer → subject)
   - Policy processing
   - Name constraints

2. **Revocation Checking**:
   - CRL validation (§5)
   - OCSP response validation (RFC 6960)
   - Fallback strategy when revocation info unavailable

3. **Extension Processing**:
   - Basic Constraints (critical)
   - Key Usage (critical)
   - Name Constraints (critical)
   - Policy Constraints
   - Inhibit anyPolicy

**Implementation Tasks:**

1. ✅ Create `crates/ostrich-x509/src/validation.rs` module (Phase 15)
2. ✅ Implement basic path building algorithm
3. ✅ Implement signature verification (use existing crypto providers)
4. ✅ Implement validity period checking
5. ✅ Implement name chaining validation
6. ✅ Integrate CRL checking (use existing CRL service)
7. ✅ Integrate OCSP checking (use existing OCSP service)
8. ✅ Implement extension validation (basic constraints, key usage, etc.)
9. ✅ Add comprehensive test suite with RFC 5280 test vectors

**Dependencies:**

- CRL service (Phase 8) - Provides revocation data
- OCSP service (Phase 9) - Provides real-time revocation status
- Crypto providers (existing) - Signature verification

**Test Criteria:**

- [ ] Valid paths accepted, invalid paths rejected
- [ ] Expired certificates rejected
- [ ] Revoked certificates rejected
- [ ] Invalid signatures rejected
- [ ] Path length constraints enforced
- [ ] Name constraints enforced

**Evidence Required:**

- Path validation algorithm documentation
- Test results with RFC 5280 test vectors
- Revocation checking logs
- Validation failure audit events

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

**Status:** 🔴 **Missing**
**Priority:** **HIGH**
**Risk:** Insecure default configurations could lead to weak certificates
**Assigned Phase:** Phase 15
**Effort Estimate:** 1 week

**Current State:**

- Certificate profiles exist but may lack secure defaults
- No validation of profile security attributes
- No enforcement of minimum key sizes

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

**Status:** 🟡 **Partial** (most operations designed but not implemented)
**Priority:** MEDIUM
**Assigned Phase:** Phase 10 (HSM Integration)
**Effort Estimate:** 3 weeks

**SFRs in this suite:**

- FCS_COP.1.1(1) - Signature generation/verification
- FCS_COP.1.1(2) - Hashing
- FCS_COP.1.1(3) - Key encryption
- FCS_COP.1.1(4) - Key agreement

**Implementation Tasks:**

- Complete all crypto operations in PKCS#11 provider
- Add test vectors for all algorithms
- Implement post-quantum algorithms (ML-DSA, ML-KEM, SLH-DSA)
- Integrate with FIPS-validated HSM

**Dependencies:** HSM integration, DRBG

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
| FMT_MSA.1.2 | Secure defaults | 🔴 Missing | **CRITICAL** | 15 | 1w |
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
