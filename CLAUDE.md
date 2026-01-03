# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OstrichPKI is a Public Key Infrastructure (PKI) system written in Rust. The project is currently in its initial setup phase.

## Development Commands

### Rust Standard Commands
- `cargo build` - Build the project
- `cargo build --release` - Build optimized release version
- `cargo test` - Run all tests
- `cargo test <test_name>` - Run a specific test
- `cargo check` - Quick compile check without producing binaries
- `cargo clippy` - Run linter for common mistakes and improvements
- `cargo fmt` - Format code according to Rust style guidelines
- `cargo run` - Build and run the main binary
- `cargo doc --open` - Generate and open documentation

## Architecture Notes

### PKI System Considerations

When implementing this PKI system, key architectural components will likely include:

- **Certificate Authority (CA) Core**: Certificate issuance, revocation, and lifecycle management
- **Cryptographic Operations**: Key generation, signing, verification using Rust crypto libraries
- **Certificate Storage**: Secure storage and retrieval of certificates and keys
- **Validation Engine**: Certificate chain validation, revocation checking (CRL/OCSP)
- **API/Interface Layer**: How external systems interact with the PKI

### Rust-Specific Patterns for PKI

- **Security**: Use `zeroize` for sensitive data in memory, avoid exposing private keys
- **Error Handling**: PKI operations should have comprehensive error types for different failure modes
- **Async/Sync**: Consider whether CA operations need async runtime (tokio/async-std) or can be synchronous
- **Serialization**: Certificate formats (X.509/PEM/DER) require careful serialization handling

## Dependencies to Consider

Common Rust PKI/crypto crates:
- `rustls` - TLS library
- `x509-parser` or `x509-cert` - X.509 certificate parsing
- `ring` or `rust-crypto` - Cryptographic primitives
- `pem` - PEM encoding/decoding
- `der` - DER encoding/decoding

---

## NIST 800-53 Rev 5 Compliance & ATO Readiness

This system is designed for Authority to Operate (ATO) readiness. All code must incorporate NIST 800-53 Rev 5 controls. When implementing features, consider and document the following control families:

### Access Control (AC)
- **AC-2**: Account management - All services must have account lifecycle management
- **AC-3**: Access enforcement - Implement RBAC for all API endpoints
- **AC-6**: Least privilege - Services run with minimum required permissions
- **AC-17**: Remote access - mTLS required for all inter-service communication

### Audit and Accountability (AU)
- **AU-2**: Auditable events - Log all security-relevant events (auth, cert issuance, revocation, key operations)
- **AU-3**: Audit content - Include who, what, when, where, outcome in all audit records
- **AU-9**: Protection of audit information - Audit logs are append-only with hash chain integrity
- **AU-10**: Non-repudiation - Sign audit log entries, maintain tamper-evident chain
- **AU-12**: Audit generation - Every service must emit structured audit events to `ostrich-audit`

### Identification and Authentication (IA)
- **IA-2**: User identification - Unique identifiers for all actors (users, services, ACME accounts)
- **IA-5**: Authenticator management - Secure PIN/password handling in SCMS, credential rotation
- **IA-7**: Cryptographic module authentication - PKCS#11/HSM authentication required for CA keys

### System and Communications Protection (SC)
- **SC-8**: Transmission confidentiality - TLS 1.3 for external, mTLS for internal communication
- **SC-12**: Cryptographic key management - HSM-protected CA keys, key lifecycle management in KRA
- **SC-13**: Cryptographic protection - Use FIPS-validated algorithms (via ring or HSM)
- **SC-17**: PKI certificates - This is the core mission; implement RFC 5280 compliance
- **SC-23**: Session authenticity - Nonce-based replay protection in ACME, session binding

### System and Information Integrity (SI)
- **SI-7**: Software/firmware integrity - Signed releases, SBOM generation
- **SI-10**: Information input validation - Validate all CSRs, API inputs, certificate requests
- **SI-12**: Information handling - Zeroize sensitive data in memory after use

### Configuration Management (CM)
- **CM-2**: Baseline configuration - Document all configuration parameters
- **CM-3**: Configuration change control - Version control, audit config changes
- **CM-6**: Configuration settings - Secure defaults, no hardcoded secrets

### Contingency Planning (CP)
- **CP-9**: System backup - Database backup procedures, HSM key backup via KRA
- **CP-10**: System recovery - Document recovery procedures for each service

### Key Implementation Requirements

When writing code, ensure:

1. **Audit everything**: Every state change must emit an audit event
   ```rust
   audit_log.emit(AuditEvent::CertificateIssued { ... }).await;
   ```

2. **Validate all inputs**: Never trust external data
   ```rust
   let csr = Csr::parse(&input).map_err(|e| ValidationError::InvalidCsr(e))?;
   csr.verify_signature()?;
   ```

3. **Protect secrets in memory**: Use zeroize for all sensitive data
   ```rust
   use zeroize::Zeroizing;
   let pin = Zeroizing::new(get_pin());
   ```

4. **Enforce authentication**: All endpoints require authentication except OCSP/CRL
   ```rust
   async fn handler(auth: MtlsAuth, ...) -> Result<...> { }
   ```

5. **Log with context**: Include request ID, actor, resource in all logs
   ```rust
   tracing::info!(request_id = %req_id, actor = %user, "certificate issued");
   ```

6. **Fail secure**: On error, deny access and log the failure
   ```rust
   .unwrap_or_else(|e| { audit_log.emit(AccessDenied { ... }); Err(Forbidden) })
   ```

### ATO Documentation Artifacts

The codebase should support generation of:
- **System Security Plan (SSP)** evidence via code comments and audit logs
- **Security Assessment Report (SAR)** evidence via test results
- **Plan of Action and Milestones (POA&M)** tracking via issues/TODO comments marked `// POAM:`
- **Continuous Monitoring** via structured logging and metrics

### Control Implementation Tracking

Mark control implementations in code with:
```rust
// NIST 800-53: AU-3 - Audit record contains required fields
// NIST 800-53: SC-13 - Using FIPS-validated algorithm via HSM
```

This enables automated SSP evidence collection.

---

## FIPS Cryptographic Standards Compliance

This system must support both classical and post-quantum cryptographic algorithms per NIST requirements.

### Classical Cryptography (Current)

- **FIPS 186-5**: Digital Signature Standard (DSS) - RSA, ECDSA, EdDSA
- **FIPS 197**: Advanced Encryption Standard (AES)
- **FIPS 180-4**: Secure Hash Standard (SHA-2 family)
- **FIPS 202**: SHA-3 Standard

### Post-Quantum Cryptography (PQC) - Required

The system must be crypto-agile and support these NIST post-quantum standards:

- **FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
  - Formerly CRYSTALS-Kyber
  - For key encapsulation/key exchange
  - Security levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - Use for: KRA transport keys, TLS key exchange (hybrid mode)

- **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
  - Formerly CRYSTALS-Dilithium
  - For digital signatures
  - Security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Use for: Certificate signing, CRL signing, OCSP response signing

- **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
  - Formerly SPHINCS+
  - Stateless hash-based signatures (conservative choice)
  - Use for: Long-lived root CA certificates, high-assurance signing

### Crypto-Agility Requirements

1. **Algorithm abstraction**: All crypto operations go through `CryptoProvider` trait
2. **Hybrid certificates**: Support composite signatures (classical + PQC)
3. **OID support**: Register and handle PQC algorithm OIDs
4. **Key storage**: HSM/KRA must support PQC key types
5. **Migration path**: Support certificate re-issuance with PQC algorithms

### Implementation Notes

```rust
// FIPS 203: ML-KEM for key encapsulation
pub enum KemAlgorithm {
    MlKem512,   // NIST Level 1
    MlKem768,   // NIST Level 3
    MlKem1024,  // NIST Level 5
}

// FIPS 204: ML-DSA for signatures
pub enum SignatureAlgorithm {
    // Classical
    RsaPkcs1Sha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    // Post-Quantum
    MlDsa44,    // NIST Level 2
    MlDsa65,    // NIST Level 3
    MlDsa87,    // NIST Level 5
    // FIPS 205: SLH-DSA
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_256s,
    // Hybrid (classical + PQC)
    EcdsaP256_MlDsa44,
    EcdsaP384_MlDsa65,
}
```

### PQC Rust Crates

- `pqcrypto` - Bindings to PQClean implementations
- `ml-kem` - Pure Rust ML-KEM (RustCrypto)
- `ml-dsa` - Pure Rust ML-DSA (RustCrypto)
- `slh-dsa` - Pure Rust SLH-DSA (RustCrypto)
- `hybrid-array` - For composite key handling

---

## RFC Compliance Requirements

All protocol implementations must strictly follow these RFCs:

### Core PKI Standards

- **RFC 5280**: X.509 PKI Certificate and CRL Profile
- **RFC 6818**: Updates to RFC 5280
- **RFC 5758**: Additional Algorithms for X.509 (SHA-2)
- **RFC 8410**: Algorithm Identifiers for Ed25519, Ed448, X25519, X448

### Certificate Status

- **RFC 6960**: OCSP (Online Certificate Status Protocol)
- **RFC 5019**: Lightweight OCSP Profile
- **RFC 6277**: OCSP Algorithm Agility
- **RFC 5280 §5**: CRL Profile

### Enrollment Protocols

- **RFC 8555**: ACME (Automatic Certificate Management Environment)
- **RFC 8737**: ACME TLS-ALPN-01 Challenge
- **RFC 7030**: EST (Enrollment over Secure Transport)
- **RFC 8295**: EST Extensions (CSR attributes)

### Cryptographic Message Syntax

- **RFC 5652**: CMS (Cryptographic Message Syntax)
- **RFC 6268**: Additional Algorithms for CMS
- **RFC 8933**: CMS Algorithm Identifier Protection

### Key Management

- **RFC 5958**: Asymmetric Key Packages (PKCS#8)
- **RFC 7292**: PKCS#12
- **RFC 5915**: EC Private Key Structure

### Transport Security

- **RFC 8446**: TLS 1.3
- **RFC 9325**: TLS Client Authentication

### Post-Quantum (Draft/Emerging)

- **draft-ietf-lamps-dilithium-certificates**: ML-DSA in X.509
- **draft-ietf-lamps-kyber-certificates**: ML-KEM in X.509
- **draft-ietf-pquip-hybrid-signature-spectrums**: Hybrid signatures

### Compliance Tracking

Mark RFC compliance in code:
```rust
// RFC 5280 §4.1.2.2 - Serial number must be positive integer ≤ 20 octets
// RFC 6960 §4.2.1 - OCSP response must include producedAt
// RFC 8555 §7.1.3 - Order object state machine
```
