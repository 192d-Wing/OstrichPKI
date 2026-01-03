# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-02

### Added

#### Foundation Layer (Phase 1)

**ostrich-common**
- Error handling with security-relevant event flagging and public message sanitization
- Configuration loading from TOML with environment variable support
- OID definitions for X.509 including Post-Quantum Cryptography algorithms (ML-DSA, ML-KEM, SLH-DSA)
- Core PKI types: DistinguishedName, Validity, SerialNumber with RFC 5280 compliance
- Utility modules: Base64/PEM/DER encoding, secure random generation, time helpers

**ostrich-crypto**
- CryptoProvider trait - unified interface for HSM and software cryptographic operations
- Support for classical algorithms: RSA, ECDSA, EdDSA
- Support for Post-Quantum algorithms: ML-DSA, SLH-DSA, ML-KEM (FIPS 203/204/205)
- Hybrid algorithm support (e.g., ECDSA + ML-DSA)
- KeyHandle abstraction for opaque key references with provider tracking
- PKCS#11 provider stub for HSM integration
- Software provider stub using ring
- Factory pattern with auto-detection and fallback capabilities

**ostrich-db**
- PostgreSQL connection pooling with TLS enforcement and health checks
- Repository pattern with generic CRUD operations
- CertificateRepository for certificate storage, revocation, and validity checks
- AuditRepository with append-only log and hash chain integrity
- Database models for certificates and audit events
- Complete schema migration with 30+ tables supporting all microservices:
  - CA tables (keys, certificates, profiles, CRLs)
  - KRA tables (transport keys, storage keys, escrowed keys, recovery workflow)
  - OCSP tables (signing keys, response cache)
  - SCMS tables (token models, inventory, lifecycle)
  - ACME tables (accounts, orders, authorizations, challenges, nonces)
  - EST tables (enrollments, authorized clients)
  - Audit tables (events with hash chain)

**ostrich-audit**
- Audit event types covering all security-relevant operations
- Hash chain integrity using SHA-256 for non-repudiation (NIST 800-53: AU-9(3))
- AuditSink trait for pluggable backends
- DatabaseAuditSink with automatic chain linking
- Query support by actor, event type, and time range
- Memory-based sink for testing
- Comprehensive test coverage (6 passing tests)

#### NIST 800-53 Rev 5 Compliance
- AU-2: Auditable events identification
- AU-3: Content of audit records
- AU-9: Protection of audit information
- AU-9(3): Cryptographic protection via hash chain
- AU-10: Non-repudiation
- SC-12: Cryptographic key establishment and management
- SC-13: Cryptographic protection
- SC-28: Protection of information at rest
- IA-2: Database authentication
- IA-7: Cryptographic module authentication
- SI-11: Error handling and message sanitization

#### RFC Compliance
- RFC 5280: X.509 certificate and CRL format support
- RFC 6960: OCSP response preparation
- RFC 8555: ACME protocol database schema
- RFC 7030: EST enrollment schema

### Changed
- Upgraded to Rust 2024 edition
- Set minimum Rust version to 1.92
- Updated to latest dependencies:
  - tokio 1.42
  - axum 0.8
  - tonic 0.12
  - sqlx 0.8
  - thiserror 2.0
  - base64 0.22

### Technical Details
- Workspace with 13 crates + 2 tools configured
- All foundation crates compile without errors
- Full test suite passing
- Crypto-agile design supporting algorithm transitions
- Zero-knowledge key management (keys never leave cryptographic provider)
- Append-only audit log with cryptographic integrity

## [0.1.0] - 2026-01-02

### Added
- Initial repository setup
- Project architecture documentation
- Workspace structure with all crate stubs

[Unreleased]: https://github.com/yourusername/ostrich-pki/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yourusername/ostrich-pki/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/ostrich-pki/releases/tag/v0.1.0
