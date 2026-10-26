# FIPS Cryptographic Standards Compliance Matrix

**Document Version:** 2.5
**Date:** 2026-10-26
**OstrichPKI Version:** 0.15.0
**Compliance Status:** Enhanced (70-75%)

## Executive Summary

This document tracks OstrichPKI's compliance with Federal Information Processing Standards (FIPS) for cryptographic algorithms and modules. FIPS compliance is required for NIAP PP-CA v2.1 certification and federal system deployment.

**Key Standards:**

- **Classical Cryptography**: FIPS 186-5, 197, 180-4, 202
- **Post-Quantum Cryptography**: FIPS 203, 204, 205
- **Cryptographic Modules**: FIPS 140-2/140-3

**Crypto-Agility Requirement**: OstrichPKI must support both classical and post-quantum algorithms to facilitate migration as quantum computing advances.

**Cryptographic module of record (2026-10-23):** **AWS-LC FIPS 4.2.0**, built
from source by `aws-lc-fips-sys` **0.14.2** and used through `aws-lc-rs`
1.18.2 (`fips` feature) and `rustls` 0.23.46 (aws-lc-rs provider). This
replaces AWS-LC FIPS 3.3.0 (`aws-lc-fips-sys` 0.13.14). The user approved the
change on 2026-10-23. **CMVP certificate for 4.2.0 pending confirmation
(POA&M).** In this document, "FIPS-backed" means the algorithm runs inside this
module's FIPS boundary. It does not mean the module version has a confirmed
CMVP certificate. See [Cryptographic Module Validation](#fips-140-2--fips-140-3-security-requirements-for-cryptographic-modules).

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

- ✅ RSASSA-PSS SHA-256/384/512, provider level. Software provider: AWS-LC FIPS 4.2.0 module (CMVP certificate for 4.2.0 pending confirmation, POAM-2026-10-23-01). Via PKCS#11: verified on SoftHSM 2.6.1 (Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), RSA-2048/3072/4096; production HSM not yet validated (POAM-2026-10-23-21)
- 🟡 RSASSA-PSS for X.509: not used for X.509 signing, and the X.509 layer does not encode RSASSA-PSS parameters (POAM-2026-10-23-20)
- ✅ RSASSA-PKCS1-v1_5: used for all X.509 certificate, CRL and OCSP signing with RSA CA keys

**Implementation:**

- [crates/ostrich-crypto/src/algorithm.rs](../../crates/ostrich-crypto/src/algorithm.rs) - Algorithm enum defines RSA variants
- [crates/ostrich-crypto/src/provider.rs:66-74](../../crates/ostrich-crypto/src/provider.rs#L66-L74) - Sign method signature

**Evidence:**

- ✅ RSA PKCS#1 v1.5 and PSS (SHA-256/384/512) signing/verification via the AWS-LC FIPS module — [crates/ostrich-crypto/src/software/mod.rs](../../crates/ostrich-crypto/src/software/mod.rs) (`sign_rsa`/`verify_rsa`, `generate` keygen)
- ✅ RSA-2048 (PKCS#1/SHA-256) and RSA-3072 (PKCS#1/SHA-384) signatures verified externally by OpenSSL 3.6
- ✅ ECDSA P-256/P-384 and Ed25519 sign/verify/keygen via the FIPS module (ECDSA verified externally by OpenSSL)
- ✅ RSA-PSS SHA-256/384/512 through PKCS#11 (RSA-2048/3072/4096, SoftHSM only): HSM signatures verified by an independent AWS-LC verifier, and software signatures verified by the HSM (`pkcs11_integration_test.rs`; 2026-10-23: Linux CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) on SoftHSM 2.6.1 and local SoftHSM 2.7.0, both 28 passed / 0 failed / 1 ignored; POAM-2026-10-23-17 closed 2026-10-23). SoftHSM only; production HSM not yet validated (POAM-2026-10-23-21). See "PKCS#11 split cryptographic boundary" below
- ✅ The AWS-LC FIPS 4.2.0 module's DRBG supplies all key-generation and signing entropy (passed RNG args are ignored by aws-lc-rs in favour of the module's DRBG; CMVP certificate for 4.2.0 pending confirmation)

**Hash Functions (for RSA signatures):**

- ✅ SHA-256
- ✅ SHA-384
- ✅ SHA-512

**Compliance Notes:**

- FIPS 186-5 deprecates RSA-1024 (not supported)
- Minimum modulus size: 2048 bits
- Salt length for PSS: Same as hash output length (FIPS 186-5 §5.4; MGF1 hash = message hash). The PKCS#11 provider fixes sLen = hLen, so HSM verify rejects PSS signatures made with another salt length

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

1. **TLS Transport Encryption** (via rustls, aws-lc-rs provider, `fips` feature)
   - AES-128-GCM (`TLS_AES_128_GCM_SHA256`)
   - AES-256-GCM (`TLS_AES_256_GCM_SHA384`)
   - ChaCha20-Poly1305 is **not** offered: rustls excludes it under `fips`
     (corrected 2026-10-24; earlier revisions listed it)

2. **KRA Key Escrow Wrapping** ✅ **Implemented**
   - [crates/ostrich-kra/src/wrap.rs](../../crates/ostrich-kra/src/wrap.rs) - AES-256-GCM (NIST SP 800-38D) via ring
   - Per-escrow random 256-bit KEK (OS CSPRNG via ring `SystemRandom`)
   - 96-bit random nonce per wrap; wire format `nonce || ciphertext || tag`
   - Escrow certificate ID bound as AEAD associated data (context binding)
   - KEK Shamir-split for M-of-N recovery, zeroized after use, never persisted
   - Test coverage: roundtrip, wrong-KEK rejection, tamper detection, AAD
     mismatch rejection, nonce uniqueness, KEK length validation
   - [crates/ostrich-crypto/src/provider.rs:83-91](../../crates/ostrich-crypto/src/provider.rs#L83-L91) - HSM `wrap_key()` interface (AES-KW per SP 800-38F) remains for PKCS#11-resident keys

3. **TLS 1.3 Service Endpoints** ✅ **Implemented (FIPS mode, fail-closed; scoped to HTTPS listeners)**
   - [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - rustls with the explicit `aws_lc_rs` provider, TLS 1.3 only
   - The serving TLS stack uses the AWS-LC FIPS 4.2.0 module (FIPS mode /
     approved algorithms; CMVP certificate pending confirmation,
     POAM-2026-10-23-01) through
     the rustls `fips` feature. The handshake AEAD, key exchange and the
     CertificateVerify signature checks run in that module, not in `ring`
     (which has no FIPS mode and no CMVP certificate).
   - **Fail-closed gate:** `ensure_fips(&ServerConfig)` returns
     `Error::Config` unless `ServerConfig::fips()` is true, and logs the refusal
     with `tracing::error!`. It is called from `TlsSettings::load` (defence in
     depth) and as the first statement of `serve_with_config`, before anything
     is bound. Every HTTPS listener served through `ostrich_common::tls`
     (`serve` and `serve_with_config`) is therefore refused on a non-FIPS TLS
     stack. That covers the nine service binaries that call
     `TlsSettings::from_options` + `serve` (acme, ca, est, kra, npe-portal, ocsp,
     scms, tamp, web-ui) and npe-portal ACME mode, which builds its own config
     (`build_mtls_server_config`) and calls `ensure_fips` itself before spawning
     the renewal task
     ([services/npe-portal/src/main.rs](../../services/npe-portal/src/main.rs)),
     then `serve_with_config`. The HTTPS startup logs carry `fips = true` and
     `aws_lc_version` (from `aws_lc_rs::awslc_version()`). No live log value has
     been captured yet.
   - **Process-level gate (2026-10-25, branch `claude/grpc-mtls`,
     uncommitted):** `fips_gate()` asserts `aws_lc_rs::try_fips_mode()`,
     asserts the rustls aws-lc-rs provider reports `fips()`, installs it as the
     process default and checks that the effective default is FIPS (a
     non-FIPS provider installed earlier makes the process exit). It is the
     first call after tracing setup in all ten service mains (acme, ca, est,
     kra, notify, npe-portal, ocsp, scms, tamp, web-ui), before the database,
     NATS, listeners or clients. Test: `fips_gate_preinstalled` 1/1 passed
     2026-10-25. npe-portal and notify-server no longer call
     `install_default` themselves.
   - **CA gRPC (2026-10-25):** tonic is built with `features = ["channel"]`
     only. The gRPC server config (`grpc_server_config`) and client config
     (`grpc_client_config`) in
     [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs) are built on
     `grpc_crypto_provider()` (aws-lc-rs FIPS provider, TLS 1.3 only) and
     asserted with `ensure_fips` / `ensure_fips_client`. Tests:
     `server_and_client_configs_report_fips`,
     `connector_and_listener_refuse_non_fips_or_non_h2_configs`,
     `p384_chain_end_to_end_with_fips_hybrid_group` (asserts `conn.fips()` and
     the negotiated group) in `grpc_mtls_e2e`, 21/21 passed 2026-10-25 (re-run by
     the compliance scribe on the final code).
   - **Not covered** (POAM-2026-10-23-05): plain-HTTP REST mode (no
     certificate configured); rustls `ClientConfig`s outside gRPC (web-ui and
     npe-portal backend clients, the ACME tls-alpn-01 validator); clients that
     build their config from the process default (async-nats, lettre,
     instant-acme) rely on `fips_gate` only; no `ostrich-audit` event on
     refusal; self-test KATs do not run through AWS-LC.
   - **What `fips()` asserts** (rustls 0.23.46): `provider.fips() &&
     require_ems`. The provider part requires every cipher suite, every
     key-exchange group, the signature-verification algorithms, the secure RNG
     and the key provider to report FIPS. For aws-lc-rs each of these reduces
     to AWS-LC `FIPS_mode()` plus rustls's allowlist. In AWS-LC FIPS 4.2.0
     `FIPS_mode()` is a build-time constant (1 when built with `BORINGSSL_FIPS`
     and without ASAN), so the gate detects build and linkage problems: rustls
     `fips` feature missing, a non-FIPS or ASAN AWS-LC linked, a non-approved
     suite or group, or extended master secret disabled. It does **not** detect
     a failed power-on self-test: on self-test failure the module calls
     `AWS_LC_FIPS_failure()` and aborts the process (the module enforces its own
     FIPS 140-3 error state). It does **not** check protocol versions: TLS 1.3-only comes from
     `with_protocol_versions(&[&TLS13])` (test
     `server_rejects_tls12_only_client`). It does not inspect the
     client-certificate verifier, which `load` builds from the same provider.
   - **Key-exchange groups offered:** X25519MLKEM768, P-256, P-384.
     ChaCha20-Poly1305 and plain X25519 are excluded under `fips`. The hybrid
     X25519MLKEM768 counts as approved because the ML-KEM share comes first and
     rustls treats the FIPS-pending ML-KEM as approved. That status depends on
     the AWS-LC 4.2.0 CMVP certificate covering ML-KEM (POAM-2026-10-23-01).
   - **CA gRPC provider (2026-10-25, `grpc_crypto_provider` in
     [grpc_tls.rs](../../crates/ostrich-common/src/grpc_tls.rs)):** groups in
     order `SECP256R1MLKEM768` (ECDH P-256 + ML-KEM-768; both components are
     FIPS-approved algorithms, SP 800-56A / FIPS 203), `X25519MLKEM768`,
     P-256, P-384; no plain X25519. Signature verification is narrowed to
     ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA-PSS (2048-8192 bit,
     SHA-256/384/512) and ML-DSA-44/65/87; RSA PKCS#1 v1.5, P-521, mismatched
     curve/hash pairs and Ed25519 are refused on this channel. `fips()` stays
     true. Tests: `p384_chain_end_to_end_with_fips_hybrid_group` (negotiated
     group and `conn.fips()` asserted) and `x25519_only_client_rejected`
     (`grpc_mtls_e2e`, passed 2026-10-25). Not claimed: an assessed FIPS 140-3
     status for either hybrid combination; the module's CMVP certificate is
     still pending (POAM-2026-10-23-01).
   - **Tests (2026-10-24, `fixes-round-1.md`):**
     `ensure_fips_rejects_non_fips_server_configs` (plain X25519 added →
     `Err(Config)`; `require_ems = false` → `Err(Config)`),
     `ensure_fips_accepts_loaded_config`,
     `serve_with_config_refuses_non_fips_config` (returns `Err(Config)` without
     binding), `load_builds_fips_config_with_alpn`,
     `fips_server_config_kx_groups_exclude_x25519_keep_mlkem_hybrid` (asserts no
     X25519, X25519MLKEM768 present, every group `fips()`), and npe-portal
     `build_mtls_server_config_reports_fips_mode`
     ([services/npe-portal/src/server/acme.rs](../../services/npe-portal/src/server/acme.rs)).
     Mutation check: with `ensure_fips` forced to `Ok`, the first and third
     tests fail.

**Implementation:**

- ✅ KRA escrow key wrapping: AES-256-GCM (the prior placeholder XOR stub is removed)
- ✅ TLS uses AES-GCM in the AWS-LC FIPS 4.2.0 module (FIPS mode; CMVP certificate pending confirmation, POAM-2026-10-23-01) via rustls/aws-lc-rs `fips`; `ServerConfig::fips()` enforced by `ensure_fips` before any HTTPS listener binds

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

- Audit chain and ACME JWK thumbprints use RustCrypto `sha2`, which is outside
  the AWS-LC module and has no CMVP certificate (corrected 2026-10-24: earlier
  text said "`ring::digest` (FIPS 140-2 validated)"; no `ring::digest` call
  exists). SHA-2 inside `ostrich-crypto` and TLS runs in the AWS-LC FIPS 4.2.0
  module (CMVP certificate pending confirmation, POAM-2026-10-23-01)
- [crates/ostrich-audit/src/event.rs](../../crates/ostrich-audit/src/event.rs) - SHA-256 for audit chain (`compute_hash`)
- [crates/ostrich-acme/src/jws.rs](../../crates/ostrich-acme/src/jws.rs) - SHA-256 for JWK thumbprints
- [crates/ostrich-acme/src/validation.rs](../../crates/ostrich-acme/src/validation.rs) - SHA-256 of the ACME key authorization for the dns-01 TXT value and the tls-alpn-01 acmeIdentifier (RFC 8555 §8.4, RFC 8737 §3), also with RustCrypto `sha2`, not the AWS-LC module (pre-existing; recorded 2026-10-26). This digest is a challenge-binding value, not a FIPS 140-3 module service, and is not cited as validated-module evidence

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

**Backend:** AWS `aws-lc-rs` STABLE `kem` module (`ML_KEM_512/768/1024`), built
with the workspace `fips` feature, so ML-KEM runs inside the AWS-LC FIPS 4.2.0
module (`aws-lc-fips-sys` 0.14.2). The PQC reviewer found `kem.rs` byte-identical
between aws-lc-rs 1.17 and 1.18.2 (2026-10-23). CMVP certificate for 4.2.0
pending confirmation (POA&M).

**Evidence:**

- ✅ Algorithm types defined: `MlKem512`, `MlKem768`, `MlKem1024`
- ✅ FIPS 203 KeyGen / Encaps / Decaps implemented in `kem.rs`
- ✅ Exact ek/dk/ciphertext sizes asserted against FIPS 203 Table 3 — `crates/ostrich-crypto/src/kem.rs` unit tests
- ✅ Private-key (`dk`) escrow export/import round-trip — `private_key_escrow_round_trip`
- ✅ **Live cross-implementation interop with OpenSSL 3.6** (both directions) — [tests/integration/mlkem_openssl_interop.rs](../../tests/integration/mlkem_openssl_interop.rs). Re-run 2026-10-23 against OpenSSL 4.0.3 under AWS-LC FIPS 4.2.0: 2 passed

**Rust Crates:**

- `aws-lc-rs` (≥1.18 workspace requirement, 1.18.2 locked; `kem` module) - implementation in use (AWS-LC backend, FIPS-track)

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
- Confirm the CMVP certificate for AWS-LC FIPS 4.2.0 (with ML-KEM in its
  approved-algorithm list) for the target platform (POA&M). The `fips` feature
  is already enabled workspace-wide.

**Priority:** Medium (for future quantum resistance)

---

### FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)

**Status:** 🟡 **TLS verification only** (key generation, signing and X.509 issuance disabled)

**History.** ML-DSA-44/65/87 was once implemented through `aws-lc-rs`'s
`unstable` feature. That feature cannot be combined with `fips` in aws-lc-rs up
to 1.17, and the AWS-LC FIPS 3.x module had no ML-DSA. ML-DSA key generation and
signing were therefore removed from the software provider, and `ml_dsa_*` is not
an allowed key type or signature algorithm
(`crates/ostrich-x509/src/secure_defaults.rs`).

**Since 2026-10-23 (AWS-LC FIPS 4.2.0):**

- ML-DSA is part of the AWS-LC FIPS 4.2.0 module (`aws-lc-fips-sys` 0.14.2).
  From aws-lc-rs 1.18 it is exposed under the `fips` feature
  (`aws_lc_rs::signature::ML_DSA_*`); the old `unstable::signature` path is
  deprecated. aws-lc-rs ML-DSA is pure mode with an empty context, and
  private-key export is `to_pkcs8v1` (seed form).
- **TLS verifies ML-DSA.** rustls 0.23.46 with the aws-lc-rs provider
  advertises ML-DSA-44/65/87 in `signature_algorithms` and verifies ML-DSA
  CertificateVerify signatures. rustls-webpki 0.103.16 verifies ML-DSA
  certificate signatures during path building. Both report `fips() == true`.
  This applies to every rustls endpoint: the `ostrich-common` TLS listener, the
  web-ui and npe-portal backend clients, and the ACME TLS-ALPN-01 validator. As
  a result, an mTLS peer whose chain uses ML-DSA and leads to a configured
  trust anchor is now accepted; on AWS-LC 3.x it was rejected.
- **User decision 2026-10-23: accepted.** ML-DSA was not ready in AWS-LC 3.x
  and is in 4.2.0, so TLS accepts it. CA issuance policy is unchanged.
- **Not changed:** ML-DSA key generation, signing, and certificate, CRL, or
  OCSP issuance stay disabled (`secure_defaults.rs` tests assert
  `ml_dsa_65` is not allowed). The `KeyType::MlDsa*` / `Algorithm::MlDsa*`
  variants and their CSOR OID mappings (`crates/ostrich-x509/src/signing.rs`)
  are reserved metadata; generating or signing with them returns
  `UnsupportedAlgorithm`.
- **No OstrichPKI test covers ML-DSA in TLS.** The behaviour was established
  by the RFC and PQC reviewers from the rustls/webpki source.

POAM: enable ML-DSA (FIPS 204) certificate issuance once CMVP confirms the
AWS-LC FIPS 4.2.0 module certificate with ML-DSA in its approved-algorithm list.
The blocker is validation status, not the API (`Cargo.toml` `aws-lc-rs`
comment).

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

- [crates/ostrich-x509/src/signing.rs](../../crates/ostrich-x509/src/signing.rs) - id-ml-dsa-* OIDs (NIST CSOR 2.16.840.1.101.3.4.3.17/.18/.19, parameters absent) retained as reserved AlgorithmIdentifier metadata
- [crates/ostrich-crypto/src/hsm_validation.rs](../../crates/ostrich-crypto/src/hsm_validation.rs) - FCS_STG_EXT.1 exception text for software-backed ML-DSA CA keys (dormant while issuance is disabled; POAM)
- [crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs) - TLS listener on the aws-lc-rs provider, which since rustls 0.23.46 includes ML-DSA in its verification algorithms (upstream behaviour, no OstrichPKI code)

**Evidence:**

- ✅ Algorithm types: `MlDsa44`, `MlDsa65`, `MlDsa87` (reserved)
- ⛔ Key generation and signing: not present in `crates/ostrich-crypto/src/software/mod.rs` (an earlier revision of this section listed `generate_ml_dsa_key_pair` / `sign_ml_dsa` / `verify_ml_dsa`; those functions are no longer in the code)
- 🟡 TLS verification: provided by rustls/rustls-webpki under `fips`; no project test
- ⏳ Hybrid (classical+PQC) composite signatures: types defined, not implemented

**Implementation library:** `aws-lc-rs` (`fips` feature, AWS-LC FIPS 4.2.0).
RustCrypto `ml-dsa` was deliberately NOT used, so that ML-DSA comes from the
AWS-LC FIPS module.

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
module (the `aws-lc-fips-sys` 0.14.2 source, AWS-LC FIPS 4.2.0, contains no
`slh_dsa`/`slhdsa`/`sphincs` identifiers; its PQC algorithms are ML-KEM and
ML-DSA) nor in the non-FIPS build (`aws-lc-sys` 0.46.0, AWS-LC 5.11.0; same
source search, 2026-10-23), and `aws-lc-rs` 1.18.2 exposes no SLH-DSA API. Since the project standardized on
aws-lc-rs for cryptography, SLH-DSA cannot be produced. It has accordingly been
removed from the CA's allowed signature algorithms and key types
(`crates/ostrich-x509/src/secure_defaults.rs`). The `KeyType`/`Algorithm` enum
variants remain as reserved metadata only.

POAM: revisit if/when AWS-LC adds (and FIPS-validates) SLH-DSA, or introduce a
separate validated provider for hash-based signatures.

**SLH-DSA CA keys are not supported by ca-server (2026-10-25, branch
`claude/grpc-mtls`, uncommitted).** ca-server signs audit records with the CA
key itself (`crates/ostrich-ca/src/ca.rs`, `signed_sink`), and the audit sink
refuses every SLH-DSA variant for audit signing (`ensure_audit_signing_algorithm`
in `crates/ostrich-audit/src/sink.rs`; signing runs under the audit chain lock
and SLH-DSA signing latency is unsuitable there). A CA whose key is SLH-DSA
therefore fails to start. This blocks the planned "SLH-DSA for long-lived root
CAs" path until the audit signing key is decoupled from the CA key (dedicated
ML-DSA or ECDSA audit key; POAM-2026-10-23-34). Currently moot: no provider
signs SLH-DSA (the software provider does not implement it and the PKCS#11
provider returns `UnsupportedAlgorithm`).

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

#### Software Cryptography (target: FIPS 140-3 Level 1)

**Module:** **AWS-LC FIPS 4.2.0**, built from source by `aws-lc-fips-sys` 0.14.2
(symbol prefix `aws_lc_fips_0_14_2`), used through `aws-lc-rs` 1.18.2 with the
workspace `fips` feature.

- **Status:** 🟡 **CMVP certificate for 4.2.0 pending confirmation (POA&M).**
  The 2026-10-23 review could not confirm a CMVP certificate for AWS-LC FIPS
  4.2.0. Until it is confirmed, no document may describe this module as
  "FIPS-validated".
- **Previous module:** AWS-LC FIPS 3.3.0 (`aws-lc-fips-sys` 0.13.14), until
  2026-10-23
- **Change approval:** user decision 2026-10-23 (CM-3 / CM-4 note in
  [NIST_800-53_MAPPING.md](NIST_800-53_MAPPING.md#cm-3-configuration-change-control)).
  The update was required by the rustls 0.23.46 / rustls-webpki 0.103.16
  advisory fixes. `aws-lc-fips-sys` is pinned at 0.14.2 rather than 0.14.3
  because 0.14.3 builds with bindgen 0.73, which fails once syn 3 is in the
  graph. Both releases ship AWS-LC 4.2.0.
- **Module-source pin (CM-6):** [.cargo/config.toml](../../.cargo/config.toml)
  sets `AWS_LC_FIPS_SYS_USE_SYSTEM = "0"` (`force = true`). Without it,
  `aws-lc-fips-sys` 0.14 would auto-detect and link a system AWS-LC
  (pkg-config / `OPENSSL_DIR`) instead of the bundled 4.2.0 source. The
  2026-10-23 build log shows `Building with: CMake` (bundled source). The pin
  does not override the target-suffixed `AWS_LC_FIPS_SYS_USE_SYSTEM_<target>`
  variable. The container builder stages set the same variable (not
  build-verified). The file is committed on `main` (commit 05ea47a).
- **Build-environment baseline (CM-2; CI hardening 2026-10-23, not yet
  merged):** the module is compiled with the Rust toolchain pinned by
  [rust-toolchain.toml](../../rust-toolchain.toml) (1.99.1). Builder images
  are `rust:1.99.1-bookworm` everywhere: both Dockerfiles (previously
  `rust:1.96-bookworm`) and GitLab `.rust-base` (previously
  `rust:1.92.0-trixie`, which was below the 1.94 MSRV and lacked the FIPS
  build dependencies). GitLab now installs clang, libclang-dev, cmake,
  golang-go and perl, as the Dockerfiles already did. GitHub jobs that build
  the module install `golang-go perl` and log `go version`, but the runner's
  preinstalled Go may come first on `PATH`, so the Go version is recorded, not
  pinned (POAM-2026-10-23-15). **The FIPS module itself is unchanged:**
  `Cargo.lock` is untouched and `aws-lc-fips-sys` stays at 0.14.2 (AWS-LC FIPS
  4.2.0). No container or GitLab build on the new images has been run yet.
- **Algorithms in the boundary (as used):** RSA, ECDSA P-256/P-384, Ed25519,
  SHA-2, SP 800-90A DRBG, ML-KEM-512/768/1024, ML-DSA-44/65/87 (TLS
  verification only), AES-GCM (TLS 1.3 record protection via rustls)
- **Unchanged by the 4.2.0 update (PQC review 2026-10-23):** rustls `fips()`
  logic; aws-lc-rs `kem.rs` (byte-identical 1.17 → 1.18.2); RSA/ECDSA/Ed25519
  signing semantics; DRBG

**Evidence:**

- ✅ `aws_lc_module_reports_fips_mode` ([crates/ostrich-crypto/src/self_test.rs](../../crates/ostrich-crypto/src/self_test.rs)): `aws_lc_rs::try_fips_mode() == Ok(())` and a SHA-256 "abc" KAT through the module (passed 2026-10-23)
- ✅ `load_builds_fips_config_with_alpn` ([crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs)): `ServerConfig::fips()` and the provider's `fips()` are `true` (passed 2026-10-23)
- ✅ `fips_signature_openssl_interop` (1 passed) and `mlkem_openssl_interop` (2 passed) against OpenSSL 4.0.3, 2026-10-23
- ✅ `ensure_fips_rejects_non_fips_server_configs`, `ensure_fips_accepts_loaded_config`, `serve_with_config_refuses_non_fips_config` ([crates/ostrich-common/src/tls.rs](../../crates/ostrich-common/src/tls.rs)): the HTTPS fail-closed gate refuses non-FIPS configs and accepts the `load()` config (26 `tls::` tests passed 2026-10-24)
- 🟡 **Runtime FIPS-mode assertion (2026-10-24, extended 2026-10-25).** Every HTTPS listener served via `ostrich_common::tls` refuses to start unless `ServerConfig::fips()` is true (`ensure_fips`), and its startup log records `fips = true` and `aws_lc_version`. Since 2026-10-25 (uncommitted) a process-level `fips_gate` runs first in all ten service mains, and the CA gRPC server and client configs are asserted; the ca-server gRPC listener starts only after the gate. Tests: `fips_gate_preinstalled` 1/1, `grpc_mtls_e2e` 21/21 (2026-10-25, final code). Still open (POAM-2026-10-23-05): plain-HTTP REST mode; client configs outside gRPC; no audit event on a FIPS gate refusal; KATs not through AWS-LC. The gate supports, but does not by itself meet, FPT_TST_EXT.1
- 🔴 The existing FIPS self-test KATs in `self_test.rs` use RustCrypto `sha2`, and the integrity test checks only the hash length, so they do not exercise the AWS-LC module (PQC-005, pre-existing). The only test that exercises the module is the `aws_lc_module_reports_fips_mode` unit test above.

**Outside the AWS-LC boundary (no CMVP certificate):**

- `ring` 0.17 (POAM-2026-10-23-08, narrowed 2026-10-25, not closed):
  AES-256-GCM key wrapping and `SystemRandom` in `crates/ostrich-kra/src/wrap.rs`;
  SHA-256 inside async-nats 0.49 (default `ring` backend; ca-server,
  notify-server; POAM-2026-10-23-30); and the rustls `ring` feature, still
  compiled in through `lettre/ring` (notify-server), `reqwest` 0.12
  `__rustls-ring` (via `oauth2` in web-ui, POAM-23; `ostrich-cli`; tests
  crate), and `tokio-rustls/ring` / `hyper-rustls/ring` (async-nats,
  tokio-websockets, reqwest 0.12); `rcgen` (tests, `instant-acme`). Every
  OstrichPKI-built TLS config selects the aws-lc-rs provider explicitly and the
  process default is the FIPS provider (`fips_gate`), so the rustls `ring`
  provider is compiled but not selected by those configs. **gRPC TLS no longer
  uses `ring`** (2026-10-25): tonic's `tls-ring` feature was removed;
  `cargo tree -e features -i rustls` shows no tonic TLS feature (checked by the
  compliance scribe 2026-10-25). An earlier revision of this section said `ring` was "FIPS 140-2 validated
  (certificate #3678)". That was wrong: `ring` has no CMVP certificate.
- RustCrypto `sha2`: audit hash chain (`crates/ostrich-audit/src/event.rs`) and
  the self-test KATs above
- Non-FIPS `aws-lc-sys` 0.46.0 (2026-10-24, PR152-PQC-010 from the PR 152 review): `aws-lc-rs` default
  features pull it in. `cargo tree -i aws-lc-sys` lists rustls, rustls-webpki,
  rcgen, instant-acme, ostrich-common and ostrich-crypto as dependents of
  aws-lc-rs, and it is in `Cargo.lock`, so it is compiled alongside
  `aws-lc-fips-sys` 0.14.2. With `fips` enabled it is not the backend and its
  symbols are prefixed, but it is still a second, unvalidated AWS-LC copy in
  the binary and the SBOM. Tracked under POAM-2026-10-23-05; no status change

**Compliance:**

- Level 1 sufficient for software-only deployments
- Requires documentation of FIPS mode configuration

---

#### Hardware Security Module (FIPS 140-2 Level 2/3)

**Interface:** PKCS#11

- **Status:** Implemented in the PKCS#11 provider; tested against SoftHSM only. No production HSM selected or tested
- **Target HSMs:** Thales Luna, Entrust nShield, AWS CloudHSM, SoftHSM (testing)
- **Test environment (2026-10-23):** the PKCS#11 integration suite runs in CI
  against the Ubuntu 24.04 `softhsm2` package
  ([.github/workflows/hsm-integration.yml](../../.github/workflows/hsm-integration.yml);
  first Linux run, SoftHSM 2.6.1, before the RSA-PSS fix: 16 passed, 3 RSA-PSS
  failed, 1 ignored, exit 101). After the RSA-PSS fix: Linux CI
  [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654) (SoftHSM 2.6.1, rustc 1.99.1, PR head 44d560d) and local SoftHSM
  2.7.0 both 28 passed / 0 failed / 1 ignored. SoftHSM is test-only and is not
  represented as a FIPS-validated module

**Implementation:**

- [crates/ostrich-crypto/src/pkcs11/mod.rs](../../crates/ostrich-crypto/src/pkcs11/mod.rs) - PKCS#11 provider (key generation, sign/verify, key wrap through cryptoki)

**Cryptographic boundary (split operation, PKCS#11 RSA-PSS and ECDSA):**

- The message digest (SHA-256/384/512, FIPS 180-4) is computed on the host by
  the AWS-LC FIPS module (CMVP certificate for 4.2.0 pending,
  POAM-2026-10-23-01)
- The digest goes to the raw mechanisms `CKM_RSA_PKCS_PSS` (PKCS#11 v3.0
  §2.1.14) or `CKM_ECDSA` (§2.3.6). EMSA-PSS encoding (RSA-PSS) and the
  private-key operation run inside the HSM; the private key never leaves it
- RSA PKCS#1 v1.5 uses the combined `CKM_SHAx_RSA_PKCS` mechanisms and is
  hashed inside the token
- The production HSM's FIPS 140-3 security policy must approve raw
  `CKM_RSA_PKCS_PSS` / `CKM_ECDSA` with host-supplied digests. Not yet checked
  (no production HSM selected; POAM-2026-10-23-21)

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
   - ✅ ACME HTTP-01 and TLS-ALPN-01 tokens in use
   - 🟡 DNS-01: tokens in use; dns-01 validation is functional since 2026-10-26 (branch `claude/dns01-resolver-fix`, uncommitted; POAM-2026-10-23-41 narrowed to CAA and DNSSEC). Kept 🟡 because challenge tokens for all three types are UUID v4 values ([rest.rs](../../crates/ostrich-acme/src/rest.rs) line 767; reference refreshed 2026-10-26), not DRBG output (same migration as ACME nonces)

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
- 🟡 **Gap (pre-existing, recorded 2026-10-24, PQC-001, POAM-2026-10-23-24):**
  not every CSP comes from the AWS-LC DRBG. These are drawn from `rand` 0.10
  `ThreadRng` (ChaCha12, OS-seeded), which is not an SP 800-90A DRBG in the
  module: Shamir KEK share coefficients (`crates/ostrich-kra/src/shamir.rs`),
  `secure_random_bytes` in `crates/ostrich-common/src/util/random.rs` (PKCS#12
  PBES2 salt and IV), the EST PKCS#12 one-time password and enrollment token
  (`crates/ostrich-est/src/rest.rs`), and web session tokens
  (`crates/ostrich-common/src/auth/session.rs`). CA serial numbers use
  `fips_random_bytes` (`aws_lc_rs::rand::fill`, `crates/ostrich-crypto/src/drbg.rs`).
  Status above not changed

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
| **FIPS 204** | ML-DSA-44/65/87 | 🟡 TLS verify only | TLS peer/chain verification via rustls/webpki (accepted 2026-10-23); keygen, signing and issuance disabled | aws-lc-rs `fips` (AWS-LC FIPS 4.2.0) | DEFERRED (issuance) |
| **FIPS 205** | SLH-DSA-SHA2 | ⛔ No backend | No AWS-LC impl (FIPS or otherwise) | — | DEFERRED |
| **SP 800-90A** | DRBG | 🟢 FIPS-backed | `fips_random_bytes` + keygen entropy; gap: some CSPs still from `rand` `ThreadRng` (POAM-2026-10-23-24) | aws-lc-rs `fips` | DONE |

"FIPS-backed" = runs inside the AWS-LC FIPS 4.2.0 module (`aws-lc-fips-sys`
0.14.2); CMVP certificate for 4.2.0 pending confirmation (POA&M).

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

1. **Software:** AWS-LC FIPS module via `aws-lc-rs` `fips` (currently AWS-LC FIPS 4.2.0, `aws-lc-fips-sys` 0.14.2; CMVP certificate for 4.2.0 pending confirmation, POA&M). `ring` is not a validated module and must not be cited as one.
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
  - Now aws-lc-rs `fips` (AWS-LC FIPS module); originally planned on `ring`, which has no CMVP certificate
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
| 1.3 | 2026-06-29 | OstrichPKI Team | NPE portal vulnerability fixes reviewed for FIPS impact: access-control/session-binding changes only; no cryptographic algorithm, key-generation, signature, KEM, DRBG, or module-boundary changes. |
| 1.4 | 2026-07-27 | OstrichPKI Team | Integration profile generates a P-384 CA key through the PKCS#11 abstraction using SoftHSM. SoftHSM is test emulation and is not represented as a FIPS-validated production module. |
| 1.5 | 2026-10-23 | OstrichPKI Team | Module change AWS-LC FIPS 3.3.0 → 4.2.0 (`aws-lc-fips-sys` 0.13.14 → 0.14.2; aws-lc-rs 1.18.2; rustls 0.23.46), approved by the user 2026-10-23. CMVP certificate for 4.2.0 pending confirmation (POA&M). `.cargo/config.toml` module-source pin (CM-6). ML-DSA: TLS verification accepted (user decision 2026-10-23), issuance still disabled. Removed stale ML-DSA `unstable` and software-provider claims. Corrected the false "`ring` FIPS 140-2 validated (#3678)" statements. SLH-DSA source check updated to 0.14.2 / aws-lc-sys 0.46.0. No algorithm was added to CA issuance. |
| 1.6 | 2026-10-23 | OstrichPKI Team | CI hardening. Build-environment baseline: `rust-toolchain.toml` 1.99.1; `rust:1.99.1-bookworm` in both Dockerfiles and GitLab (GitLab moved from `rust:1.92.0-trixie` and gained the FIPS build dependencies). Module-pin file recorded as committed. PKCS#11 SoftHSM test environment noted (RSA-PSS fails locally; Linux CI pending). **FIPS module unchanged** (AWS-LC FIPS 4.2.0, `aws-lc-fips-sys` 0.14.2); no algorithm, self-test or boundary change. |
| 1.7 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS fix. RSASSA-PSS qualified (✅ → 🟡): provider level only, PKCS#11 "Fixed; local SoftHSM 2.7.0 28/0/1; Linux CI pending", not used for X.509 (RSA X.509 signing is PKCS#1 v1.5). Documented the PKCS#11 split boundary (host digest in AWS-LC; EMSA-PSS and private-key operation in the HSM) and the production-HSM policy check (POAM-21). HSM interface status corrected from "Designed, not implemented" / "stubbed" to implemented and SoftHSM-tested only. PSS salt-length note. **FIPS module unchanged** (AWS-LC FIPS 4.2.0); no algorithm added. |
| 1.8 | 2026-10-23 | OstrichPKI Team | PKCS#11 RSA-PSS Linux CI evidence (commit 44d560d, PR 181): GitHub Actions run 40063317654, SoftHSM 2.6.1, 28 passed / 0 failed / 1 ignored, exit 0. RSASSA-PSS split into two lines: provider level / via PKCS#11 🟡 → ✅ **scoped to SoftHSM** 2.6.1 / 2.7.0 and RSA-2048/3072/4096 (production HSM not validated, POAM-21); X.509 RSASSA-PSS stays 🟡 (POAM-20). PKCS#11 PSS interop evidence 🟡 → ✅ (SoftHSM only). HSM test environment and RSA-PSS digest-boundary status updated. AWS-LC 4.2.0 CMVP caveat kept. **FIPS module unchanged**; no algorithm, self-test or boundary change. |
| 1.9 | 2026-10-24 | OstrichPKI Team | PR 152 (fail-closed FIPS TLS), branch `revive-fips-tls`. FIPS 197 TLS endpoints: "validated module" / "FIPS-validated" wording replaced by "AWS-LC FIPS 4.2.0 module (FIPS mode / approved algorithms; CMVP certificate pending confirmation, POAM-2026-10-23-01)"; scope corrected to every HTTPS listener served via `ostrich_common::tls` (`serve` and `serve_with_config`, including npe-portal ACME mode) through `ensure_fips`; added what `fips()` asserts (build and linkage only; a failed power-on self-test aborts inside the module and is not detected by the gate, PQC-009), offered groups and the hybrid ML-KEM approval basis; tests replaced (the removed `aws_lc_rs_provider_is_in_fips_mode` no longer cited). Self-contradictions fixed: ChaCha20-Poly1305 removed from the TLS suite list; runtime FIPS-mode evidence 🔴 → 🟡 **scoped to HTTPS listeners** (POAM-05 stays open); `ring::digest` "FIPS 140-2 validated" corrected to RustCrypto `sha2` (no CMVP certificate). aws-lc-rs requirement ≥1.16 → ≥1.18. Module boundary: the non-FIPS `aws-lc-sys` 0.46.0 recorded as a second, unvalidated AWS-LC copy in the build and SBOM (PQC-010, POAM-05; no status change). Header version 1.5 → 1.9 (1.6-1.8 had not updated it). **FIPS module unchanged** (AWS-LC FIPS 4.2.0); no algorithm added. |
| 2.0 | 2026-10-24 | OstrichPKI Team | Dependency cleanup (branch `claude/deps-cleanup`). SP 800-90A: added a pre-existing gap (PQC-001, POAM-2026-10-23-24): Shamir KEK coefficients, `secure_random_bytes` (PKCS#12 salt/IV), EST one-time password and enrollment token, and session tokens use `rand` `ThreadRng`, not the AWS-LC DRBG. No status changed. The non-FIPS `aws-lc-sys` note was re-checked with `cargo tree -i aws-lc-sys -e normal` (aws-lc-rs dependents still rustls, rustls-webpki, rcgen, instant-acme, ostrich-common, ostrich-crypto); no edit needed. Removing `openidconnect`, `p256` and `crypto-bigint` 0.5.5 changes no algorithm, module or boundary statement |
| 2.1 | 2026-10-25 | OstrichPKI Team | CA gRPC behind mTLS (branch `claude/grpc-mtls`, uncommitted). FIPS 197 TLS endpoints: process-level `fips_gate` (all ten mains) and CA gRPC server/client `fips()` assertions added; "Not covered" list narrowed (tonic `tls-ring` and the gRPC ordering gap removed; plain-HTTP REST, non-gRPC client configs, process-default clients, refusal audit and KATs remain, POAM-05). New CA gRPC provider note: SECP256R1MLKEM768 first, narrowed signature algorithms, CMVP pending. Runtime FIPS-mode evidence stays 🟡 with the extended scope. `ring` inventory rewritten: gRPC no longer uses `ring`; KRA `wrap.rs`, async-nats SHA-256 (POAM-30) and the rustls `ring` feature via lettre / reqwest 0.12 / async-nats / tokio-websockets remain (POAM-08 narrowed, not closed). Header version 1.9 → 2.1 (2.0 had not updated it). **FIPS module unchanged** (AWS-LC FIPS 4.2.0); no algorithm added; no status raised. |
| 2.2 | 2026-10-25 | OstrichPKI Team | CA gRPC mTLS final refresh after fix round 3. FIPS 205: SLH-DSA CA keys not supported by ca-server (CA key signs audit records; audit sink refuses SLH-DSA; POAM-2026-10-23-34; currently moot, no provider signs SLH-DSA). FIPS 197 TLS endpoints: `grpc_mtls_e2e` 21/21. PR 152 finding cited as PR152-PQC-010. No algorithm, module or status change |
| 2.3 | 2026-10-26 | OstrichPKI Team | Dependabot alert remediation: no algorithm, parameter set, module or self-test changed (hickory DNS and web-ui build-chain lockfile updates only). Challenge-token item corrected: DNS-01 validation is non-functional (POAM-2026-10-23-41); no FIPS claim changed |
| 2.4 | 2026-10-26 | OstrichPKI Team | ACME dns-01 resolver fix (branch `claude/dns01-resolver-fix`, uncommitted): no algorithm, parameter set, module or self-test changed; the dns-01 digest code is unchanged. FIPS 180-4: recorded that the dns-01 and tls-alpn-01 key-authorization SHA-256 uses RustCrypto `sha2` (pre-existing, outside the AWS-LC module; not validated-module evidence). Challenge-token item: DNS-01 validation functional (POAM-41 narrowed); stays 🟡 because tokens are UUID v4, not DRBG output. No FIPS claim raised |
| 2.5 | 2026-10-26 | OstrichPKI Team | ACME wildcard identifiers (branch `claude/acme-wildcard-identifiers`, uncommitted): no algorithm, parameter set, module or self-test changed (identifier validation, challenge offering, finalize binding and audit records only). Challenge-token line reference refreshed (rest.rs line 767); tokens are still UUID v4 |

---

**Next Review Date:** 2026-02-01 (or upon completion of Phase 15)

**Post-Quantum Transition Review:** Annually (monitor NIST PQC standardization)

### PKCS#11 ECDSA digest boundary

For ECDSA, SHA-256, SHA-384, or SHA-512 is computed by the FIPS-enabled AWS-LC
module (FIPS 180-4), and the resulting digest is signed by the configured
PKCS#11 token using `CKM_ECDSA` (FIPS 186-5). SoftHSM remains test-only and is
not represented as a FIPS-validated production module.

### PKCS#11 RSA-PSS digest boundary

RSA-PSS uses the same split as ECDSA: SHA-256, SHA-384 or SHA-512 is computed
by the AWS-LC module, and the token performs EMSA-PSS encoding and the RSA
private-key operation with `CKM_RSA_PKCS_PSS` (hashAlg = MGF1 hash = signature
hash, sLen = hash length). Status: ✅ Fixed; verified on SoftHSM 2.6.1 (Linux
CI [run 40063317654](https://github.com/192d-Wing/OstrichPKI/actions/runs/40063317654)) and 2.7.0 (local), 28 passed / 0 failed / 1 ignored,
RSA-2048/3072/4096. Production HSM not yet validated (POAM-2026-10-23-21);
CMVP certificate for AWS-LC 4.2.0 pending confirmation (POAM-2026-10-23-01).

### EST mTLS probe boundary

Kubernetes TCP probes do not negotiate cryptography or bypass client
authentication. Application traffic remains protected by the EST service's
TLS 1.3 configuration and configured trust anchors.

### EST Basic bootstrap transport

Basic bootstrap remains protected by the same TLS 1.3 server-authenticated
channel. Optional client-certificate negotiation changes authentication
selection, not the approved transport cryptography.
