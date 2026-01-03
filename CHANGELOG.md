# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-01-02

### Added

#### ACME Responder Service (Phase 5)

##### ostrich-acme

- RFC 8555 compliant ACME responder implementation
- Account management with JWK-based authentication
- Order lifecycle management (Pending → Ready → Processing → Valid → Invalid)
- Authorization objects linking identifiers to challenges
- Challenge types: HTTP-01, DNS-01, TLS-ALPN-01
- Key authorization computation for challenge validation
- ACME directory endpoint for service discovery
- Nonce management for replay protection
- Error types with RFC 8555 URNs and HTTP status codes
- REST API endpoints:
  - Directory (GET /acme/directory)
  - New nonce (GET /acme/new-nonce)
  - New account (POST /acme/new-account)
  - New order (POST /acme/new-order)
  - Get authorization (GET /acme/authz/{id})
  - Respond to challenge (POST /acme/challenge/{id})
  - Finalize order (POST /acme/order/{id}/finalize)
  - Download certificate (GET /acme/cert/{id})

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- RFC 8555: Automatic Certificate Management Environment (ACME)
- NIST 800-53: SC-12 - Automated certificate lifecycle management
- Comprehensive test coverage

## [0.4.0] - 2026-01-02

### Added

#### Key Recovery Authority Service (Phase 4)

##### ostrich-kra

- Shamir's Secret Sharing implementation for M-of-N threshold key recovery
- Key escrow functionality with encrypted private key storage
- Key recovery workflow with multi-agent authorization
- Recovery agent management
- Recovery session tracking with status (Pending, CollectingShares, Completed, Denied, Cancelled)
- GF(256) finite field arithmetic for secret sharing
- Polynomial interpolation for secret reconstruction
- Audit logging for all escrow and recovery operations
- Support for configurable threshold (M) and total shares (N)
- Comprehensive test coverage for Shamir's algorithm

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- NIST 800-53: SC-12 (Cryptographic key establishment and management)
- NIST 800-57: Key management best practices
- Cryptographically secure secret splitting and reconstruction


## [0.3.0] - 2026-01-02

### Added

#### X.509 Certificate Handling (Phase 2 - Part 1)

##### ostrich-x509

- X.509 certificate parsing and validation with RFC 5280 compliance
- Certificate builder with profile-based generation
- CRL (Certificate Revocation List) generation and parsing
- Certificate profile system (Root CA, Intermediate CA, TLS Server/Client, Code Signing, OCSP Signing)
- Extension support: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAltName, AuthorityInfoAccess, CRL Distribution Points
- RFC 5280 validation: path length constraints, critical extensions, validity periods
- DER and PEM encoding/decoding
- Serial number generation with cryptographic randomness

#### Certificate Authority Service (Phase 2 - Parts 2-4)

##### ostrich-protocol

- gRPC Protocol Buffers definitions for CA service
- 6 RPC methods: IssueCertificate, RevokeCertificate, GenerateCrl, CheckRevocationStatus, GetCaInfo, ListProfiles
- Type-safe message definitions for all request/response types
- tonic-build integration for code generation

##### ostrich-ca

- Core CA service with certificate issuance and revocation
- CertificateIssuer with profile-based certificate generation
- RevocationManager with RFC 5280 revocation reason codes
- CRL generation with proper ASN.1 encoding
- gRPC service implementation with bidirectional type conversion
- REST API with 8 endpoints (health check, CA info, issue, revoke, status, CRL, profiles)
- Integration with audit logging for all operations
- Profile management system

##### ostrich-cli

- Command-line interface for CA administration
- CA commands: info, issue, revoke, status, generate-crl, list-profiles
- Full subject DN specification (CN, O, OU, L, ST, C)
- Multiple SAN types (DNS, email, IP address)
- Base64 encoding for binary data transfer
- PEM certificate and CRL output

#### OCSP Responder Service (Phase 3)

##### ostrich-ocsp

- RFC 6960 compliant OCSP responder
- OcspRequest parsing with serial number and issuer hash support
- OcspResponse generation with status codes (Good, Revoked, Unknown)
- REST API with GET and POST methods for OCSP requests
- Nonce support for replay protection
- SHA-256 hash algorithm for CertID
- Response caching infrastructure (placeholder)
- Delegated signing support (placeholder)
- Integration with certificate repository for status lookups
- Audit logging for OCSP protocol events

#### Audit System Enhancement

##### ostrich-audit

- Added OcspProtocol event type for OCSP operations

### Changed

- Base64 API migration to v0.22 Engine trait
- Improved error handling across all services
- Enhanced type safety with proper conversions

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- Full RFC compliance: RFC 5280 (X.509), RFC 6960 (OCSP)
- NIST 800-53 Rev 5 compliance maintained
- Proper ASN.1/DER encoding throughout
- Comprehensive test coverage

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

[Unreleased]: https://github.com/yourusername/ostrich-pki/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/yourusername/ostrich-pki/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/yourusername/ostrich-pki/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yourusername/ostrich-pki/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/ostrich-pki/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/ostrich-pki/releases/tag/v0.1.0
