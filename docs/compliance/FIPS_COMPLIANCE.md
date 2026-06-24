# FIPS Cryptographic Standards Compliance Matrix

**Document Version:** 1.2
**Date:** 2026-01-04
**OstrichPKI Version:** 0.15.0
**Compliance Status:** Enhanced (70-75%)

## Executive Summary

This document tracks OstrichPKI's compliance with Federal Information Processing Standards (FIPS) for cryptographic algorithms and modules. FIPS compliance is required for NIAP PP-CA v2.1 certification and federal system deployment.

**Key Standards:**

- **Classical Cryptography**: FIPS 186-5, 197, 180-4, 202
- **Post-Quantum Cryptography**: FIPS 203, 204, 205
- **Cryptographic Modules**: FIPS 140-2/140-3

**Crypto-Agility Requirement**: OstrichPKI must support both classical and post-quantum algorithms to facilitate migration as quantum computing advances.

---

## Classical Cryptography Standards

### FIPS 186-5: Digital Signature Standard (DSS)

**Status:** 🟢 **FIPS-backed** — RSA, ECDSA (P-256/P-384), and Ed25519
signing/verification/key-generation run inside the AWS-LC FIPS 140-3 module via
`aws-lc-rs` (workspace `fips` feature). The previous non-FIPS backends — `ring`
(ECDSA/Ed25519) and the pure-Rust `rsa` crate — have been removed from
`ostrich-crypto`. Verified by live OpenSSL interop
([tests/integration/fips_signature_openssl_interop.rs](../../tests/integration/fips_signature_openssl_interop.rs)).

**Publication Date:** February 2023 (supersedes FIPS 186-4)

**Approved Algorithms:**

#### RSA Digital Signatures

**Modulus Sizes:**

- ✅ RSA-2048 (minimum for new keys)
- ✅ RSA-3072 (recommended)
- ✅ RSA-4096 (high security)

**Signature Schemes:**

- ✅ RSASSA-PSS (preferred)
- ✅ RSASSA-PKCS1-v1_5 (legacy compatibility)

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm enum defines RSA variants
- [crates/ostrich-crypto/src/provider.rs:66-74](../../crates/ostrich-crypto/src/provider.rs#L66-L74) - Sign method signature

**Evidence:**

- ✅ RSA PKCS#1 v1.5 and PSS (SHA-256/384/512) signing/verification via the AWS-LC FIPS module — [crates/ostrich-crypto/src/software/mod.rs](../../crates/ostrich-crypto/src/software/mod.rs) (`sign_rsa`/`verify_rsa`, `generate` keygen)
- ✅ RSA-2048 (PKCS#1/SHA-256) and RSA-3072 (PKCS#1/SHA-384) signatures verified externally by OpenSSL 3.6
- ✅ ECDSA P-256/P-384 and Ed25519 sign/verify/keygen via the FIPS module (ECDSA verified externally by OpenSSL)
- ✅ FIPS-validated DRBG supplies all key-generation and signing entropy (passed RNG args are ignored by aws-lc-rs in favour of the module's DRBG)

**Hash Functions (for RSA signatures):**

- ✅ SHA-256
- ✅ SHA-384
- ✅ SHA-512

**Compliance Notes:**

- FIPS 186-5 deprecates RSA-1024 (not supported)
- Minimum modulus size: 2048 bits
- Salt length for PSS: Same as hash output length

**Code References:**

- [algorithm.rs:20-35](../../crates/ostrich-crypto/src/algorithm.rs#L20-L35) - RSA algorithm variants
- [pkcs11/mod.rs:45-53](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L45-L53) - Key generation (stubbed)
- [pkcs11/mod.rs:66-74](../../crates/ostrich-crypto/src/pkcs11/mod.rs#L66-L74) - Signing (stubbed)

**Remediation:** Phase 10 - Complete PKCS#11 and software provider implementations

---

#### ECDSA (Elliptic Curve Digital Signature Algorithm)

**Approved Curves:**

- ✅ P-256 (secp256r1, prime256v1) - minimum
- ✅ P-384 (secp384r1) - recommended
- ✅ P-521 (secp521r1) - high security

**Hash Functions:**

- ✅ SHA-256 (for P-256)
- ✅ SHA-384 (for P-384)
- ✅ SHA-512 (for P-521)

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - ECDSA variants defined

**Evidence:**

- ✅ Algorithm types: `EcdsaP256Sha256`, `EcdsaP384Sha384`, `EcdsaP521Sha512`
- 🔴 Implementation incomplete

**Compliance Notes:**

- FIPS 186-5 does not approve Curve25519/448 for ECDSA (use EdDSA instead)
- Random k value MUST be generated per FIPS 186-5 Appendix B.5.2
- Deterministic k generation allowed (RFC 6979)

**Remediation:** Phase 10 - Implement ECDSA with proper random k generation (DRBG)

---

#### EdDSA (Edwards-Curve Digital Signature Algorithm)

**Approved Curves:**

- ✅ Ed25519 (FIPS 186-5 approved)
- ✅ Ed448 (FIPS 186-5 approved)

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - EdDSA variants

**Evidence:**

- ✅ Algorithm types: `Ed25519`, `Ed448`
- 🔴 Implementation incomplete

**Compliance Notes:**

- EdDSA is deterministic (no random k)
- Ed25519: 128-bit security level
- Ed448: 224-bit security level
- Preferred over ECDSA for new deployments (simpler, no random k risk)

**OID Compliance:**

- ✅ Ed25519: 1.3.101.112 (RFC 8410)
- ✅ Ed448: 1.3.101.113 (RFC 8410)

**Code References:**

- [oid.rs:50-60](../../crates/ostrich-common/src/oid.rs#L50-L60) - EdDSA OIDs

**Remediation:** Phase 10 - Implement EdDSA signing

---

#### DSA (Digital Signature Algorithm)

**Status:** ⚪ **Not Supported** (intentional)

**Reason:** DSA deprecated in FIPS 186-5, use RSA or ECDSA instead

**Compliance:** Conformant (not required)

---

### FIPS 197: Advanced Encryption Standard (AES)

**Status:** 🟡 **Partial** (Used indirectly)

**Publication Date:** November 2001

**Key Sizes:**

- ✅ AES-128
- ✅ AES-192
- ✅ AES-256

**Modes of Operation:**

- ✅ GCM (Galois/Counter Mode) - for AEAD
- ✅ KW (Key Wrap) - for key transport

**Usage in OstrichPKI:**

1. **TLS Transport Encryption** (via rustls)
   - AES-128-GCM
   - AES-256-GCM
   - ChaCha20-Poly1305 (not AES, but AEAD)

2. **KRA Key Escrow Wrapping** ✅ **Implemented**
   - [crates/ostrich-kra/src/wrap.rs](../../crates/ostrich-kra/src/wrap.rs) - AES-256-GCM (NIST SP 800-38D) via ring
   - Per-escrow random 256-bit KEK (OS CSPRNG via ring `SystemRandom`)
   - 96-bit random nonce per wrap; wire format `nonce || ciphertext || tag`
   - Escrow certificate ID bound as AEAD associated data (context binding)
   - KEK Shamir-split for M-of-N recovery, zeroized after use, never persisted
   - Test coverage: roundtrip, wrong-KEK rejection, tamper detection, AAD
     mismatch rejection, nonce uniqueness, KEK length validation
   - [crates/ostrich-crypto/src/provider.rs:83-91](../../crates/ostrich-crypto/src/provider.rs#L83-L91) - HSM `wrap_key()` interface (AES-KW per SP 800-38F) remains for PKCS#11-resident keys

3. **TLS 1.3 Service Endpoints** ✅ **Implemented (FIPS provider)**
   - [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - rustls with the explicit `aws_lc_rs` provider, TLS 1.3 only
   - The serving TLS stack runs inside AWS-LC's FIPS 140-3 module (rustls `fips`
     feature), so the handshake AEAD, key-exchange, and the client/server
     CertificateVerify signature checks all execute in the validated module —
     not `ring` (which is not FIPS-validated). Restricted to FIPS-approved suites
     (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`; ChaCha20 excluded).
   - `SettingsTls::load` asserts `ServerConfig::fips()` and **fails closed** if it
     is not FIPS-compliant, so a build/feature regression cannot silently serve a
     non-FIPS transport (SC-13). Shared by every service binary (ca, acme, est,
     ocsp, kra, scms, web-ui server).

**Implementation:**

- ✅ KRA escrow key wrapping: AES-256-GCM (the prior placeholder XOR stub is removed)
- ✅ TLS uses AES-GCM inside the AWS-LC FIPS module (via rustls/aws-lc-rs `fips`); `ServerConfig::fips()` asserted at startup
- ✅ Regression guard: `tls::tests::aws_lc_rs_provider_is_in_fips_mode` fails if the `fips` feature is dropped

**Compliance Notes:**

- CBC mode deprecated for most uses (use GCM or CCM for AEAD)
- ECB mode prohibited (not secure)
- GCM IV: 96 bits random per wrap; each escrow uses a fresh single-use KEK,
  so IV reuse with the same key cannot occur structurally

**Remediation:** Complete for KRA escrow. AES-KW (SP 800-38F) for HSM-resident key transport remains available via the PKCS#11 provider.

---

### FIPS 180-4: Secure Hash Standard (SHS)

**Status:** 🟢 **Compliant**

**Publication Date:** August 2015

**Approved Hash Functions:**

#### SHA-2 Family

- ✅ SHA-224 (224-bit output)
- ✅ SHA-256 (256-bit output) - **primary use**
- ✅ SHA-384 (384-bit output)
- ✅ SHA-512 (512-bit output)
- ✅ SHA-512/224 (224-bit output, SHA-512 truncated)
- ✅ SHA-512/256 (256-bit output, SHA-512 truncated)

**Implementation:**

- Uses `ring::digest` crate (FIPS 140-2 validated)
- [crates/ostrich-audit/src/event.rs:145-150](../../crates/ostrich-audit/src/event.rs#L145-L150) - SHA-256 for audit chain
- [crates/ostrich-acme/src/jws.rs](../../crates/ostrich-acme/src/jws.rs) - SHA-256 for JWK thumbprints

**Evidence:**

- ✅ SHA-256 used for:
  - Audit event hash chain
  - JWK thumbprints (ACME)
  - Certificate identifier computation (EST)
  - OCSP CertID hashes
- ✅ SHA-384, SHA-512 available for RSA/ECDSA signatures

**Compliance Notes:**

- SHA-1 deprecated (not used in OstrichPKI except for legacy OCSP compatibility)
- Minimum hash length: 224 bits for new applications
- Use SHA-256 as default unless higher security required

**NIAP Mapping:**

- FCS_COP.1(2) - Cryptographic Operation (Hashing)

**Remediation:** None required (compliant)

---

### FIPS 202: SHA-3 Standard

**Status:** 🟡 **Partial** (Available but not used)

**Publication Date:** August 2015

**Approved Functions:**

#### SHA-3 Hash Functions

- ⚪ SHA3-224
- ⚪ SHA3-256
- ⚪ SHA3-384
- ⚪ SHA3-512

#### Extendable-Output Functions (XOF)

- ⚪ SHAKE128
- ⚪ SHAKE256

**Implementation:**

- `ring` crate does not include SHA-3
- `sha3` crate available (RustCrypto)

**Usage Consideration:**

- SHA-3 not widely used in PKI (SHA-2 sufficient)
- May be needed for post-quantum signature schemes
- Consider for future-proofing

**Compliance:** Not required, SHA-2 sufficient for current needs

**Remediation:** Phase 13 (optional) - Add SHA-3 support for PQC algorithms

---

## Post-Quantum Cryptography Standards

### FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)

**Status:** ✅ **Implemented** (software provider; FIPS-validatable backend)

**Publication Date:** August 2024 (finalized)

**Former Name:** CRYSTALS-Kyber

**Approved Parameter Sets:**

#### ML-KEM-512

- **Security Level:** NIST Level 1 (equivalent to AES-128)
- **Public Key:** 800 bytes
- **Ciphertext:** 768 bytes
- **Shared Secret:** 32 bytes

#### ML-KEM-768

- **Security Level:** NIST Level 3 (equivalent to AES-192)
- **Public Key:** 1184 bytes
- **Ciphertext:** 1088 bytes
- **Shared Secret:** 32 bytes
- **Recommended for most applications**

#### ML-KEM-1024

- **Security Level:** NIST Level 5 (equivalent to AES-256)
- **Public Key:** 1568 bytes
- **Ciphertext:** 1568 bytes
- **Shared Secret:** 32 bytes

**Usage in PKI:**

1. **KRA Transport Keys** - Encrypt private keys for escrow
2. **Hybrid TLS** - Key exchange alongside classical ECDH
3. **Encrypted Certificate Delivery** - EST server-side keygen

**Implementation:**

- [crates/ostrich-crypto/src/kem.rs](../../crates/ostrich-crypto/src/kem.rs) - `MlKemKeyPair` (KeyGen/Decaps), `encapsulate()` (Encaps), and raw `ek`/`dk` import/export for KRA escrow
- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - `KeyType::MlKem512/768/1024`

**Backend:** AWS `aws-lc-rs` STABLE `kem` module (`ML_KEM_512/768/1024`). Unlike
our ML-DSA path (which requires the non-FIPS `unstable` feature), ML-KEM is NOT
gated by `unstable` and the same algorithm IDs are present inside AWS-LC's FIPS
module (`aws-lc-fips-sys`). ML-KEM is therefore the one PQC primitive that can
run inside the FIPS 140-3 boundary today by enabling the `fips` feature; see the
ML-DSA caveat below.

**Evidence:**

- ✅ Algorithm types defined: `MlKem512`, `MlKem768`, `MlKem1024`
- ✅ FIPS 203 KeyGen / Encaps / Decaps implemented in `kem.rs`
- ✅ Exact ek/dk/ciphertext sizes asserted against FIPS 203 Table 3 — `crates/ostrich-crypto/src/kem.rs` unit tests
- ✅ Private-key (`dk`) escrow export/import round-trip — `private_key_escrow_round_trip`
- ✅ **Live cross-implementation interop with OpenSSL 3.6** (both directions) — [tests/integration/mlkem_openssl_interop.rs](../../tests/integration/mlkem_openssl_interop.rs)

**Rust Crates:**

- `aws-lc-rs` (≥1.16, `kem` module) - implementation in use (AWS-LC backend, FIPS-track)

**Compliance Notes:**

- FIPS 203 is now final (August 2024)
- Use ML-KEM-768 for general applications
- Hybrid mode recommended: ML-KEM + ECDH (classical key exchange retained until
  the AWS-LC FIPS module is certified for ML-KEM on the deployed platform)

**NIAP Mapping:**

- FCS_CKM.1 - cryptographic key generation (`MlKemKeyPair::generate`)
- FCS_CKM.2 - cryptographic key establishment (`encapsulate` / `decapsulate`)

**Remaining work:**

- Wire ML-KEM into KRA transport-key escrow and EST encrypted key delivery
- Finalize X.509 SubjectPublicKey/OID encoding per draft-ietf-lamps-kyber-certificates
- Enable the `fips` feature for production once AWS-LC's FIPS module is certified
  for ML-KEM on the target platform (note: `fips` is currently mutually exclusive
  with the `unstable` feature our ML-DSA path needs)

**Priority:** Medium (for future quantum resistance)

---

### FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)

**Status:** ⛔ **Removed from the build** (incompatible with the FIPS posture)

ML-DSA was previously implemented (ML-DSA-44/65/87) via `aws-lc-rs`'s `unstable`
feature. To make all classical algorithms FIPS-backed, the workspace now enables
`aws-lc-rs`'s **`fips`** feature, which is **mutually exclusive with `unstable`**
(`#[cfg(all(feature = "unstable", not(feature = "fips")))]` in aws-lc-rs through
1.17). AWS-LC's FIPS 140-3 module does not yet include ML-DSA, so there is no
FIPS-validated ML-DSA path. Rather than ship a non-FIPS signature algorithm
alongside FIPS-validated ones, ML-DSA key generation and signing have been
removed from the software provider, and `ml_dsa_*` is no longer an allowed
key type or signature algorithm (`crates/ostrich-x509/src/secure_defaults.rs`).

The `KeyType::MlDsa*` / `Algorithm::MlDsa*` enum variants and their CSOR OID
mappings (`crates/ostrich-x509/src/signing.rs`) are retained as reserved
metadata; attempting to generate or sign with them returns `UnsupportedAlgorithm`.

POAM: restore ML-DSA (FIPS 204) once AWS-LC's FIPS module is certified for it and
`aws-lc-rs` exposes it under the `fips` feature.

**Publication Date:** August 2024 (finalized)

**Former Name:** CRYSTALS-Dilithium

**Approved Parameter Sets:**

#### ML-DSA-44

- **Security Level:** NIST Level 2 (similar to SHA-256 collision resistance)
- **Public Key:** 1312 bytes
- **Signature:** ~2420 bytes
- **Best for:** Certificates with size constraints

#### ML-DSA-65

- **Security Level:** NIST Level 3 (similar to SHA-384)
- **Public Key:** 1952 bytes
- **Signature:** ~3293 bytes
- **Recommended for most PKI applications**

#### ML-DSA-87

- **Security Level:** NIST Level 5 (similar to SHA-512)
- **Public Key:** 2592 bytes
- **Signature:** ~4595 bytes
- **Best for:** Long-lived root CA certificates

**Usage in PKI:**

1. **Certificate Signing** - Issue certificates with PQC signatures
2. **CRL Signing** - Sign certificate revocation lists
3. **OCSP Response Signing** - Sign OCSP responses
4. **Hybrid Certificates** - Dual signatures (classical + PQC)

**Implementation:**

- [crates/ostrich-crypto/src/software/mod.rs](../../crates/ostrich-crypto/src/software/mod.rs) - ML-DSA keygen/sign/verify/SPKI export via aws-lc-rs (`generate_ml_dsa_key_pair`, `sign_ml_dsa`, `verify_ml_dsa`)
- [crates/ostrich-x509/src/signing.rs](../../crates/ostrich-x509/src/signing.rs) - id-ml-dsa-* OIDs (NIST CSOR 2.16.840.1.101.3.4.3.17/.18/.19, parameters absent) wired into the X.509 AlgorithmIdentifier path
- [crates/ostrich-crypto/src/hsm_validation.rs](../../crates/ostrich-crypto/src/hsm_validation.rs) - FCS_STG_EXT.1 exception permitting software-backed ML-DSA CA keys (no HSM supports ML-DSA yet; POAM)

**Evidence:**

- ✅ Algorithm types: `MlDsa44`, `MlDsa65`, `MlDsa87`
- ✅ Signing/verification implemented and OpenSSL-verified (see above)
- ⏳ Hybrid (classical+PQC) composite signatures: types defined, not implemented

**Implementation library:** `aws-lc-rs` (`unstable` feature). RustCrypto
`ml-dsa` was deliberately NOT used (AWS-LC's FIPS-track validation is the
rationale).

**Compliance Notes:**

- FIPS 204 is now final (August 2024)
- Use ML-DSA-65 for intermediate/issuing CAs
- Use ML-DSA-87 for root CAs (10+ year validity)
- Hybrid mode: ECDSA P-384 + ML-DSA-65 for transition

**NIAP Mapping:**

- FCS_COP.1(1) - Digital Signature (future)
- FDP_CER_EXT.1 - Certificate Profiles (PQC extension)

**Remediation:**

- Phase 13 - Implement ML-DSA using `ml-dsa` crate
- Phase 13 - Update OID to final NIST value (2.16.840.1.101.3.4.3.17)
- Phase 13 - Add to CryptoProvider signing interface
- Phase 13 - Support hybrid certificates (classical + PQC)

**Priority:** Medium-High (prepare for PQC transition)

---

### FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)

**Status:** ⛔ **No backend** (not implementable on the current crypto stack)

AWS-LC has **no SLH-DSA implementation at all** — neither in the FIPS 140-3
module (`aws-lc-fips-sys` 0.13.14 contains zero `slh_dsa`/`sphincs` symbols; its
only PQC algorithm is ML-KEM) nor in the non-FIPS build (`aws-lc-sys` 0.41.0),
and `aws-lc-rs` exposes no SLH-DSA API. Since the project standardized on
aws-lc-rs for cryptography, SLH-DSA cannot be produced. It has accordingly been
removed from the CA's allowed signature algorithms and key types
(`crates/ostrich-x509/src/secure_defaults.rs`). The `KeyType`/`Algorithm` enum
variants remain as reserved metadata only.

POAM: revisit if/when AWS-LC adds (and FIPS-validates) SLH-DSA, or introduce a
separate validated provider for hash-based signatures.

**Publication Date:** August 2024 (finalized)

**Former Name:** SPHINCS+

**Approved Parameter Sets:**

#### SLH-DSA-SHA2-128s

- **Security Level:** 128-bit (Category 1)
- **Hash Function:** SHA-256
- **Optimization:** Small signatures (~7856 bytes)
- **Signing Time:** Slower

#### SLH-DSA-SHA2-128f

- **Security Level:** 128-bit (Category 1)
- **Hash Function:** SHA-256
- **Optimization:** Fast signing
- **Signature:** ~17088 bytes

#### SLH-DSA-SHA2-256s

- **Security Level:** 256-bit (Category 5)
- **Hash Function:** SHA-512
- **Optimization:** Small signatures (~29792 bytes)
- **Best for:** Root CA (conservative choice)

**Characteristics:**

- **Stateless:** No secret state that changes per signature (unlike XMSS)
- **Conservative:** Based on hash functions (well-understood security)
- **Large Signatures:** 8KB - 30KB (much larger than ML-DSA)
- **Slow:** Signing is slower than ML-DSA

**Usage in PKI:**

1. **Root CA Certificates** - Conservative long-term security (20+ years)
2. **Backup Signing Algorithm** - If ML-DSA is broken
3. **High-Assurance Applications** - Where hash-based security preferred

**Implementation:**

- [crates/ostrich-common/src/oid.rs:86](../../crates/ostrich-common/src/oid.rs#L86) - OID placeholder
- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - SLH-DSA variants defined

**Evidence:**

- ✅ Algorithm types: `SlhDsaSha2_128s`, `SlhDsaSha2_128f`, `SlhDsaSha2_256s`
- 🔴 No implementation

**Rust Crates:**

- `slh-dsa` - Pure Rust implementation (RustCrypto)
- `pqcrypto-sphincsplus` - Bindings to PQClean

**Compliance Notes:**

- FIPS 205 is now final (August 2024)
- Use SLH-DSA-SHA2-256s for root CA (maximum security)
- Large signature size limits practical use (avoid for end-entity certs)
- Consider for offline root CA only

**Trade-offs vs. ML-DSA:**

- ✅ More conservative (hash-based security)
- ✅ Stateless (no secret state management)
- ❌ Much larger signatures (30KB vs. 3KB)
- ❌ Slower signing

**Remediation:**

- Phase 13 - Implement SLH-DSA for root CA option
- Phase 13 - Update OID to final NIST value
- Priority: Low (optional, ML-DSA sufficient for most uses)

---

## Cryptographic Module Validation

### FIPS 140-2 / FIPS 140-3: Security Requirements for Cryptographic Modules

**Status:** 🟡 **Partial** (Depends on HSM and libraries)

**Standard:** FIPS 140-2 (transitioning to FIPS 140-3)

**Security Levels:**

- **Level 1:** Software cryptography (basic requirements)
- **Level 2:** Physical tamper-evidence required
- **Level 3:** Tamper-resistant, zeroization on intrusion
- **Level 4:** Complete envelope protection

**OstrichPKI Approach:**

#### Software Cryptography (FIPS 140-2 Level 1)

**Library:** `ring` v0.17+

- **Status:** FIPS 140-2 validated (certificate #3678)
- **Algorithms:** RSA, ECDSA, AES-GCM, SHA-2
- **Usage:** Software crypto provider fallback

**Evidence:**

- ✅ `ring` used for hashing (audit chain, JWK thumbprints)
- 🔴 Software crypto provider not implemented yet

**Compliance:**

- Level 1 sufficient for software-only deployments
- Requires documentation of FIPS mode configuration

---

#### Hardware Security Module (FIPS 140-2 Level 2/3)

**Interface:** PKCS#11

- **Status:** Designed, not implemented
- **Target HSMs:** Thales Luna, Entrust nShield, AWS CloudHSM, SoftHSM (testing)

**Implementation:**

- [crates/ostrich-crypto/src/pkcs11/mod.rs](../../crates/ostrich-crypto/src/pkcs11/mod.rs) - PKCS#11 provider (stubbed)

**HSM Requirements:**

- FIPS 140-2 Level 2 minimum for production CA
- FIPS 140-2 Level 3 recommended for root CA
- Certificate: Must have valid CMVP certificate

**Common HSM Choices:**

| HSM Product | FIPS Level | Certificate | Notes |
|-------------|------------|-------------|-------|
| Thales Luna HSM 7 | Level 3 | #3839 | Enterprise-grade |
| Entrust nShield Connect | Level 3 | #3858 | Common for CAs |
| AWS CloudHSM | Level 3 | #3254 | Cloud-based |
| SoftHSMv2 | Level 1 | N/A | Testing only |

**Compliance Notes:**

- CA signing keys MUST be in FIPS 140-2 Level 2+ HSM
- Software crypto acceptable for OCSP signing, challenge nonces
- Document HSM configuration in Security Target

**NIAP Mapping:**

- FCS_STG_EXT.1 - Cryptographic Key Storage
- FPT_KST_EXT.1/2 - Key Protection

**Remediation:**

- Phase 10 - Complete PKCS#11 implementation
- Document HSM requirements in deployment guide
- Obtain FIPS 140-2 certificate for chosen HSM

---

## Random Number Generation

### NIST SP 800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators

**Status:** 🟢 **Implemented** (Phase 15 Complete)

**Standard:** NIST SP 800-90A Rev 1

**Approved DRBGs:**

#### Hash_DRBG

- **Hash Function:** SHA-256, SHA-384, SHA-512
- **Use:** General purpose
- **Implementation:** Available in RustCrypto

#### HMAC_DRBG

- **HMAC:** HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
- **Use:** General purpose, deterministic k for ECDSA
- **Implementation:** Available in RustCrypto

#### CTR_DRBG

- **Block Cipher:** AES-128, AES-192, AES-256
- **Use:** High performance
- **Implementation:** Available in RustCrypto

**OstrichPKI Implementation:**

✅ **Implemented:** [crates/ostrich-crypto/src/drbg/](../../crates/ostrich-crypto/src/drbg/)

1. **CTR_DRBG (AES-256)** - [ctr_drbg.rs](../../crates/ostrich-crypto/src/drbg/ctr_drbg.rs)
   - ✅ Full NIST SP 800-90A Rev 1 Section 10.2 compliance
   - ✅ AES-256 block cipher with derivation function
   - ✅ Security strength: 256 bits
   - ✅ Reseed interval: 2^48 requests (per standard)
   - ✅ Prediction resistance via automatic reseeding
   - ✅ Thread-safe design with proper state management

2. **FIPS 140-3 Health Tests** - [health_tests.rs](../../crates/ostrich-crypto/src/drbg/health_tests.rs)
   - ✅ Repetition Count Test (startup and continuous)
   - ✅ Adaptive Proportion Test (startup and continuous)
   - ✅ Failure detection with graceful error handling
   - ✅ Per-request continuous testing

3. **Entropy Source Integration**
   - ✅ OS-provided RNG integration (getrandom crate)
   - ✅ Configurable entropy strength (256-bit minimum)
   - ✅ Automatic reseeding on counter exhaustion
   - ✅ Personalization string support
   - ✅ Additional input support for prediction resistance

**OstrichPKI Usage (Ready for Integration):**

1. **Certificate Serial Numbers** (CRITICAL)
   - ✅ DRBG implementation ready
   - ✅ Requirement: ≥20 bits random (RFC 5280, FDP_CER_EXT.1.3)
   - 🔧 Integration pending: Phase 16

2. **ACME Nonces**
   - ✅ DRBG implementation ready
   - 🔧 Migration from UUID v4 to DRBG: Phase 16

3. **Challenge Tokens**
   - ✅ DRBG provides unpredictable tokens
   - ✅ ACME HTTP-01, DNS-01, TLS-ALPN-01 ready

4. **ECDSA k values**
   - ✅ DRBG ready for random k generation
   - ✅ HSM handles k internally (PKCS#11)

**Test Coverage:**

- ✅ 21 comprehensive unit tests
- ✅ CTR_DRBG instantiation with/without personalization
- ✅ Generation with multiple requests
- ✅ Reseeding functionality
- ✅ Health test failures (repetition count, adaptive proportion)
- ✅ Reseed counter overflow protection
- ✅ Concurrent access (thread safety)
- ✅ Factory creation patterns
- ✅ Error handling for all failure modes

**NIAP PP-CA Compliance:**

- ✅ FCS_RBG_EXT.1 - Random Bit Generation: **CLOSED**
- ✅ FDP_CER_EXT.1.3 - Serial number randomness: **READY**

**Implementation Reference:**

```rust
// NIST SP 800-90A CTR_DRBG (AES-256)
use ostrich_crypto::drbg::create_drbg;

let mut drbg = create_drbg()?;  // Automatic health tests on instantiation
let random_bytes = drbg.generate(32)?;  // Generate 32 bytes of random data
```

**NIAP Mapping:**

- FCS_RBG_EXT.1 - Random Bit Generation
- FDP_CER_EXT.1.3 - Serial Number Randomness

**Remediation:** Phase 15 - CRITICAL - Implement DRBG module

**Priority:** CRITICAL (blocking NIAP compliance)

---

## Algorithm Implementation Summary

| FIPS Standard | Algorithm | Status | Implementation | Library | Priority |
|---------------|-----------|--------|----------------|---------|----------|
| **FIPS 186-5** | RSA-2048/3072/4096 | 🟢 FIPS-backed | Sign/verify/keygen (OpenSSL interop) | aws-lc-rs `fips` | HIGH |
| **FIPS 186-5** | ECDSA P-256/384 | 🟢 FIPS-backed | Sign/verify/keygen (OpenSSL interop) | aws-lc-rs `fips` | HIGH |
| **FIPS 186-5** | EdDSA Ed25519 | 🟢 FIPS-backed | Sign/verify/keygen | aws-lc-rs `fips` | HIGH |
| **FIPS 197** | AES-128/256-GCM | 🟢 In Use | TLS library | rustls | DONE |
| **FIPS 197** | AES-KW | 🟡 Designed | Not impl | aes-kw | MEDIUM |
| **FIPS 180-4** | SHA-256/384/512 | 🟢 FIPS-backed | Active | aws-lc-rs `fips` | DONE |
| **FIPS 202** | SHA-3 | ⚪ Optional | Not impl | sha3 | LOW |
| **FIPS 203** | ML-KEM-512/768/1024 | 🟢 FIPS-backed | KeyGen/Encaps/Decaps (OpenSSL interop) | aws-lc-rs `kem` | MEDIUM |
| **FIPS 204** | ML-DSA-44/65/87 | ⛔ Removed | Unavailable under `fips` (needs `unstable`) | — | DEFERRED |
| **FIPS 205** | SLH-DSA-SHA2 | ⛔ No backend | No AWS-LC impl (FIPS or otherwise) | — | DEFERRED |
| **SP 800-90A** | DRBG | 🟢 FIPS-backed | `fips_random_bytes` + keygen entropy | aws-lc-rs `fips` | DONE |

---

## Crypto-Agility Architecture

### Design Principles

1. **Algorithm Abstraction**
   - [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Single Algorithm enum
   - [crates/ostrich-crypto/src/provider.rs](../../crates/ostrich-crypto/src/provider.rs) - Provider trait abstracts implementations

2. **Provider Pattern**
   - `CryptoProvider` trait supports multiple backends
   - PKCS#11 provider for HSM
   - Software provider for testing/fallback
   - Future: Cloud KMS provider (AWS KMS, Azure Key Vault)

3. **OID Management**
   - [crates/ostrich-common/src/oid.rs](../../crates/ostrich-common/src/oid.rs) - Centralized OID definitions
   - Easy to update PQC OIDs when NIST finalizes

4. **Certificate Profile Flexibility**
   - [crates/ostrich-x509/src/profile.rs](../../crates/ostrich-x509/src/profile.rs) - Profiles specify allowed algorithms
   - Can create "PQC-only" or "Hybrid" profiles

### Migration Strategy

**Phase 1: Classical Only** (Current)

- RSA, ECDSA, EdDSA
- SHA-256/384/512
- AES-GCM

**Phase 2: Hybrid Deployment** (2025-2027)

- Dual signatures on certificates (ECDSA P-384 + ML-DSA-65)
- Clients validate either signature
- Gradual client migration to PQC support

**Phase 3: PQC Primary** (2028+)

- ML-DSA for all new certificates
- ML-KEM for key transport
- Classical algorithms for legacy compatibility only

**Phase 4: PQC Only** (2030+)

- Deprecate classical algorithms
- All certificates use ML-DSA
- Archive classical root CAs

---

## FIPS Compliance Testing

### Algorithm Validation

**CAVP (Cryptographic Algorithm Validation Program):**

- Test vectors for each FIPS algorithm
- Must validate implementations against CAVP test vectors

**Test Approach:**

1. Use NIST CAVP test vectors
2. Test each algorithm (RSA, ECDSA, EdDSA, AES, SHA-2)
3. Verify signatures, hashes, encryption with known-answer tests
4. Document test results for NIAP evaluation

**Example Test (SHA-256):**

```rust
#[test]
fn test_sha256_cavp() {
    // CAVP test vector
    let msg = b"abc";
    let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

    let digest = ring::digest::digest(&ring::digest::SHA256, msg);
    assert_eq!(digest.as_ref(), expected.as_slice());
}
```

### Module Validation

**CMVP (Cryptographic Module Validation Program):**

- FIPS 140-2/140-3 validation of cryptographic modules
- Required for production deployment

**OstrichPKI Validation Strategy:**

1. **Software:** Use pre-validated `ring` library (certificate #3678)
2. **HSM:** Use pre-validated HSM (e.g., Thales Luna certificate #3839)
3. **Documentation:** Reference validation certificates in Security Target

**No custom crypto implementation** → Rely on validated modules

---

## Compliance Roadmap

### Phase 15 (Current) - Critical Foundations

**Priority: CRITICAL**

- ✅ Implement DRBG (NIST SP 800-90A)
  - Use `ring::rand::SystemRandom`
  - Generate cryptographically secure serial numbers (≥20 bits random)
  - Add to CryptoProvider trait

### Phase 10 - Classical Crypto Implementation

**Priority: HIGH**

- ✅ Complete PKCS#11 provider (FIPS 186-5 algorithms)
  - RSA-2048/3072/4096 key generation and signing
  - ECDSA P-256/384/521 key generation and signing
  - EdDSA Ed25519/448 key generation and signing
- ✅ Implement software crypto provider fallback
  - Use `ring` library (FIPS 140-2 validated)
- ✅ Implement AES-KW for key wrapping (FIPS 197)

### Phase 13 - Post-Quantum Crypto

**Priority: MEDIUM**

- ✅ Implement ML-DSA (FIPS 204)
  - Use `ml-dsa` crate
  - Add ML-DSA-65 for intermediate CAs
  - Add ML-DSA-87 for root CAs
- ✅ Implement ML-KEM (FIPS 203)
  - Use `ml-kem` crate
  - Add ML-KEM-768 for KRA key transport
- ✅ Implement hybrid certificates
  - Dual signatures (ECDSA + ML-DSA)
  - Support in certificate profiles
- ⚪ Optional: Implement SLH-DSA (FIPS 205) for root CA

### Phase 14 - Validation & Testing

**Priority: HIGH**

- ✅ CAVP test vector validation
- ✅ Algorithm interoperability testing
- ✅ FIPS mode configuration testing
- ✅ HSM validation certificate documentation

---

## Deployment Configuration

### FIPS Mode Requirements

**Operating System:**

```bash
# Enable FIPS mode (RHEL/CentOS)
sudo fips-mode-setup --enable
sudo reboot

# Verify FIPS mode
cat /proc/sys/crypto/fips_enabled  # Should output: 1
```

**Application Configuration:**

```toml
[crypto]
provider = "pkcs11"  # or "software" for testing
fips_mode = true
drbg_algorithm = "ctr_drbg_aes256"  # or "hash_drbg_sha256", "hmac_drbg_sha256"

[pkcs11]
library_path = "/usr/lib/softhsm/libsofthsm2.so"  # or HSM library path
slot = 0
fips_validate_certificate = true  # Verify HSM FIPS certificate

[algorithms]
# Allowed signature algorithms (restrict to FIPS-approved)
allowed_signature_algorithms = [
    "rsa_2048_pss_sha256",
    "rsa_3072_pss_sha384",
    "rsa_4096_pss_sha512",
    "ecdsa_p256_sha256",
    "ecdsa_p384_sha384",
    "ecdsa_p521_sha512",
    "ed25519",
    "ed448"
]

# Future: PQC algorithms
pqc_enabled = false  # Enable when ready
allowed_pqc_algorithms = [
    "ml_dsa_65",
    "ml_dsa_87"
]
```

**Security Target Documentation:**

- List FIPS validation certificates for all modules
- Document algorithm usage for each operation
- Specify FIPS mode configuration requirements

---

## Document Change History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-03 | OstrichPKI Team | Initial FIPS compliance assessment based on v0.10.0 codebase |

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 15)

**Post-Quantum Transition Review:** Annually (monitor NIST PQC standardization)
