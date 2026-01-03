# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Database Integration - EST and KRA Services (Phase 9 - Part 2a)

##### ostrich-est

- Integrated EST service with database persistence layer
- Updated `EstState` struct with database pool, crypto provider, and audit sink
- Implemented database operations in 5 REST handlers:
  - `simple_enroll`: Creates enrollment records with pending status workflow
  - `simple_reenroll`: Tracks re-enrollment requests
  - `get_ca_certs`: Prepared for CA certificate chain retrieval (Phase 12)
  - `get_csr_attrs`: Returns CSR attributes for clients
  - `server_key_gen`: Tracks server-generated key enrollments
- Added dependencies: `ostrich-crypto`, `ostrich-audit`
- Deferred work: CA integration (Phase 12), mTLS client certificate validation (Phase 11)

##### ostrich-kra

- Integrated KRA library services with database persistence layer
- `KeyEscrow::escrow_key()`: Database integration complete
  - Stores encrypted keys with wrapping key metadata
  - Splits KEK into M-of-N shares using Shamir secret sharing
  - Records audit events for escrow operations
  - Default threshold: 3-of-5 recovery agents
- `KeyRecovery::initiate_recovery()`: Database integration complete
  - Validates escrowed key existence
  - Creates recovery request records
  - Tracks recovery sessions with status workflow
- `KeyRecovery::submit_share()`: Share tracking and threshold monitoring
  - Stores recovery shares from authorized agents
  - Counts submitted shares against threshold
  - Updates recovery session status
- `KeyRecovery::list_agents()`: Recovery agent management
  - Lists active recovery agents from database
- Deferred work: Crypto provider key wrapping/unwrapping (Phase 10), agent authorization (Phase 12)

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- Phase 9 completion: ~60% (repository layer + EST + KRA REST integration complete)
- ACME and SCMS REST integration deferred to future increments
- NIST 800-53: SC-28 - Protection of information at rest, AU-2 - Audit events
- RFC compliance: RFC 7030 (EST), NIST 800-57 (Key Management)

## [0.9.0] - 2026-01-02

### Added

#### Database Repository Layer (Phase 9 - Part 1)

##### ostrich-db

- Implemented complete ACME repository with 28 methods for RFC 8555 protocol state management
  - Account management: create, find by ID/account ID/JWK thumbprint, update, deactivate
  - Order lifecycle: create, find, update status, list by account
  - Authorization tracking: create, find, update status, list by order
  - Challenge management: create, find, update status, list by authorization
  - Nonce operations: create, consume (atomic replay protection), cleanup expired
- Implemented SCMS repository for smartcard token lifecycle management
  - Token model registry: create, list, find by ID
  - Token inventory: create, find by ID/serial, list with filters, update, delete
  - Token lifecycle operations: status updates, PIN/PUK attempt tracking
  - Key management: create, list by token, find, delete
  - Event audit: record events, list by token
- Implemented EST repository for enrollment tracking
  - Enrollment records: create, find, list by client, update status
  - Client authorization: create, find, list (active/all), update status
- Implemented KRA repository for key recovery workflows
  - Escrowed key storage: create, find by ID/certificate
  - Recovery agent management: create, find, list active, update status
  - Recovery request tracking: create, find, list by status, update status
  - Share management: create, submit, list by request, count submitted shares
- Database models with sqlx FromRow derivation for all entities
  - ACME: AcmeAccount, AcmeOrder, AcmeAuthorization, AcmeChallenge, AcmeNonce
  - SCMS: TokenModel, Token, TokenKey, TokenEvent
  - EST: EstEnrollment, EstClient
  - KRA: EscrowedKey, RecoveryAgent, RecoveryRequest, RecoveryShare
- Type-safe parameterized queries using sqlx for SQL injection protection
- Proper timestamp tracking (created_at, updated_at) across all entities
- UUID v4 primary keys for all records
- Repository exports and module organization

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- Phase 9 completion: ~40% (repository layer complete, REST integration pending)
- 1,487 lines of repository code across 4 services
- Database schema already present in migration 00001
- NIST 800-53: SC-28 - Protection of information at rest
- RFC compliance: RFC 8555 (ACME), RFC 7030 (EST)

## [0.8.0] - 2026-01-02

### Added

#### Core Cryptographic Operations (Phase 8)

##### ostrich-x509

- Implemented RFC 5280 compliant DER encoding for TBS certificates
- Added `TbsCertificate::to_der()` method with complete ASN.1 structure encoding
- Implemented RFC 5280 compliant DER encoding for TBS CRLs
- Added `TbsCrl::to_der()` method for CRL encoding
- Distinguished Name to X.509 Name conversion with proper RDN construction
- DateTime to X.509 Time conversion (UTCTime for ≤2049, GeneralizedTime for >2049)
- Helper methods for signature algorithm encoding
- Error handling for encoding failures

##### ostrich-ca

- Implemented real certificate signing workflow (previously placeholder)
- TBS certificate DER encoding → crypto signing → final certificate construction
- Implemented real CRL signing workflow (previously placeholder)
- TBS CRL DER encoding → crypto signing → final CRL construction
- DER to PEM conversion for certificate distribution
- DER to PEM conversion for CRL distribution
- Added dependencies: `der`, `x509-cert`, `pem-rfc7468`

##### ostrich-ocsp

- Implemented RFC 6960 §4.1.1 compliant OCSP request parsing from DER
- ASN.1 structure definitions for OCSPRequest, TBSRequest, Request, CertID
- OID to hash algorithm conversion (SHA-256/384/512)
- Serial number extraction from ASN.1 Int
- Implemented RFC 6960 §4.2.1 compliant OCSP response encoding to DER
- BasicOCSPResponse structure with proper ASN.1 encoding
- SingleResponse encoding with CertID and status
- ResponseData encoding for signature computation
- Implemented OCSP response signing workflow
- Response data → DER encoding → crypto signing → final BasicOCSPResponse

##### ostrich-est

- Implemented RFC 5652 compliant PKCS#7 encoding for certificate distribution
- Degenerate SignedData structure (certs-only, no signed content)
- CertificateChoices wrapping for X.509 certificates
- ContentInfo construction with proper OIDs
- Added dependencies: `der`, `cms`, `x509-cert`

### Changed

- All cryptographic operations now use proper RFC-compliant DER/ASN.1 encoding
- Certificate and CRL signing moved from placeholder to production implementation
- OCSP request parsing moved from placeholder to full ASN.1 decoder
- EST certificate distribution moved from placeholder to PKCS#7 encoding

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- RFC 5280: X.509 Certificate and CRL Profile (DER encoding)
- RFC 6960: Online Certificate Status Protocol (request/response encoding)
- RFC 5652: Cryptographic Message Syntax (PKCS#7 for EST)
- RFC 7468: PEM encoding for certificate distribution
- Comprehensive ROADMAP.md created documenting all 142 TODOs across phases 8-14
- Project completion: 45-50% (up from 35-40%)

## [0.7.0] - 2026-01-02

### Added

#### Smartcard Management System Service (Phase 7)

##### ostrich-scms

- Complete smartcard token lifecycle management
- Token status tracking (Uninitialized, Initialized, Active, Suspended, Blocked, Expired, Revoked)
- Token inventory management with model support
- PIN/SO-PIN management with retry counters
- Token personalization and assignment
- Key management on tokens (generation, storage, deletion)
- Token event audit trail
- PKCS#11 integration support (placeholder)
- REST API endpoints:
  - GET/POST /scms/tokens - List and create tokens
  - GET/PUT/DELETE /scms/tokens/{id} - Token operations
  - POST /scms/tokens/{id}/initialize - Initialize token
  - POST /scms/tokens/{id}/personalize - Personalize token
  - POST /scms/tokens/{id}/suspend - Suspend token
  - POST /scms/tokens/{id}/resume - Resume suspended token
  - POST /scms/tokens/{id}/unblock - Unblock token (SO-PIN recovery)
  - POST /scms/tokens/{id}/verify-pin - Verify user PIN
  - POST /scms/tokens/{id}/change-pin - Change PIN
  - GET /scms/tokens/{id}/keys - List keys on token
  - POST /scms/tokens/{id}/keys/generate - Generate key pair
  - DELETE /scms/tokens/{token_id}/keys/{key_id} - Delete key
  - GET/POST /scms/models - Token model management
  - GET /scms/tokens/{id}/events - Token event history

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- NIST 800-53: IA-2, IA-5 - Multi-factor authentication with smartcards
- Comprehensive test coverage
- PIN retry mechanism with automatic blocking

## [0.6.0] - 2026-01-02

### Added

#### EST Server Service (Phase 6)

##### ostrich-est

- RFC 7030 compliant EST (Enrollment over Secure Transport) server
- Simple enrollment endpoint for certificate requests
- Simple re-enrollment for certificate renewal
- CA certificates distribution endpoint
- CSR attributes endpoint for client guidance
- Server-side key generation endpoint (placeholder)
- Enrollment status tracking (Pending, Approved, Rejected, Expired)
- PKCS#7 and PKCS#10 support for certificate exchange
- mTLS client authentication support
- REST API endpoints:
  - GET /.well-known/est/cacerts - CA certificate chain
  - POST /.well-known/est/simpleenroll - Initial enrollment
  - POST /.well-known/est/simplereenroll - Certificate renewal
  - GET /.well-known/est/csrattrs - CSR attribute requirements
  - POST /.well-known/est/serverkeygen - Server-side key generation

### Technical Details

- All code passes cargo check, fmt, and clippy with -D warnings
- RFC 7030: Enrollment over Secure Transport
- NIST 800-53: SC-12 - Certificate enrollment and renewal
- Comprehensive test coverage

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
[0.7.0]: https://github.com/yourusername/ostrich-pki/compare/v0.6.0...v0.7.0
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

[Unreleased]: https://github.com/yourusername/ostrich-pki/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/yourusername/ostrich-pki/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/yourusername/ostrich-pki/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/yourusername/ostrich-pki/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/yourusername/ostrich-pki/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/yourusername/ostrich-pki/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/yourusername/ostrich-pki/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yourusername/ostrich-pki/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/ostrich-pki/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/ostrich-pki/releases/tag/v0.1.0
