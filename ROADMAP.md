# OstrichPKI Development Roadmap

## Executive Summary

OstrichPKI v0.7.0 represents a comprehensive Public Key Infrastructure system implementing multiple RFC standards and NIST 800-53 security controls. The project has successfully completed **8 major implementation phases** covering all core microservices and cryptographic operations:

- **Phase 1**: Foundation (common, crypto, db, audit)
- **Phase 2**: CA (certificate authority, X.509, gRPC, CLI)
- **Phase 3**: OCSP (RFC 6960 responder)
- **Phase 4**: KRA (key recovery with Shamir secret sharing)
- **Phase 5**: ACME (RFC 8555 automated certificate management)
- **Phase 6**: EST (RFC 7030 enrollment over secure transport)
- **Phase 7**: SCMS (smartcard token lifecycle management)
- **Phase 8**: ✅ **COMPLETE** - Core Cryptographic Operations (DER encoding, signing, PKCS#7)

**Current Status**:
- **Total codebase**: ~11,400 lines of Rust code across 15 crates
- **Services**: 7 microservices fully scaffolded with REST/gRPC APIs
- **Protocol compliance**: RFC 5280, 6960, 7030, 8555
- **Security compliance**: NIST 800-53 (AU-2, AU-3, AU-9, SC-12, SC-13, IA-2, IA-5)

However, comprehensive code analysis revealed **142 TODO items** (now **127 remaining after Phase 8**) indicating significant remaining work before production readiness. These TODOs cluster around critical areas:

1. ✅ **Cryptographic Operations** ~~(15 TODOs)~~ - **COMPLETE**: DER/ASN.1 encoding, certificate/CRL signing, PKCS#7 encoding
2. **Database Persistence** (53 TODOs): ACME, EST, SCMS services lack database integration
3. **PKCS#11 HSM Integration** (35 TODOs): All HSM operations are placeholder implementations
4. **Protocol Validation** (18 TODOs): JWS signatures, mTLS, CSR parsing, challenge validation
5. **Service Integration** (21 TODOs): Cross-service communication (CA ↔ ACME/EST/KRA/SCMS)

**Overall Completion**: Approximately **45-50%** complete (up from 35-40% after Phase 8)
- **Architecture & APIs**: 85-90% complete (all endpoints defined)
- **Core Implementation**: 50-55% complete (✅ crypto complete, gaps in DB, HSM remain)
- **Production Readiness**: 30-35% complete (missing integration, testing, hardening)

**Estimated Effort to Production**: 12-16 weeks across 6 remaining phases

---

## TODO Summary by Category

### ✅ Cryptographic Operations ~~(15 TODOs)~~ - **PHASE 8 COMPLETE**

**X.509 & PKI Core**:

- ✅ ~~[crates/ostrich-x509/src/builder/certificate.rs:275](crates/ostrich-x509/src/builder/certificate.rs#L275)~~ - DER encoding for X.509 certificates **DONE**
- ✅ ~~[crates/ostrich-x509/src/builder/crl.rs:160](crates/ostrich-x509/src/builder/crl.rs#L160)~~ - DER encoding for CRLs **DONE**
- [crates/ostrich-x509/src/parser.rs:34](crates/ostrich-x509/src/parser.rs#L34) - PEM parsing for certificates (not needed - using pem-rfc7468 crate)

**CA Operations**:

- ✅ ~~[crates/ostrich-ca/src/issuance.rs:172-180](crates/ostrich-ca/src/issuance.rs#L172-L180)~~ - Certificate signing **DONE**
- ✅ ~~[crates/ostrich-ca/src/revocation.rs:197-204](crates/ostrich-ca/src/revocation.rs#L197-L204)~~ - CRL signing **DONE**

**OCSP**:

- ✅ ~~[crates/ostrich-ocsp/src/request.rs:43](crates/ostrich-ocsp/src/request.rs#L43)~~ - ASN.1 OCSP request parsing **DONE**
- ✅ ~~[crates/ostrich-ocsp/src/response.rs:117](crates/ostrich-ocsp/src/response.rs#L117)~~ - ASN.1 OCSP response encoding **DONE**
- ✅ ~~[crates/ostrich-ocsp/src/responder.rs:170](crates/ostrich-ocsp/src/responder.rs#L170)~~ - OCSP response signing **DONE**

**EST**:

- ✅ ~~[crates/ostrich-est/src/rest.rs:61](crates/ostrich-est/src/rest.rs#L61)~~ - PKCS#7 encoding for CA certificates **DONE**
- ✅ ~~[crates/ostrich-est/src/rest.rs:101](crates/ostrich-est/src/rest.rs#L101)~~ - PKCS#7 encoding for enrollment response **DONE**
- ✅ ~~[crates/ostrich-est/src/rest.rs:134](crates/ostrich-est/src/rest.rs#L134)~~ - PKCS#7 encoding for re-enrollment response **DONE**

### Database Persistence (53 TODOs)

**ACME Service** (28 TODOs in [crates/ostrich-acme/src/rest.rs](crates/ostrich-acme/src/rest.rs)):
- Account management: create, lookup, update (lines 145-187)
- Order lifecycle: create, lookup, finalize (lines 237-362)
- Authorization tracking: create, update, complete (lines 305-424)
- Challenge management: create, validate, update (lines 464-522)
- Nonce generation and validation for replay protection (line 127)

**SCMS Service** (45 TODOs in [crates/ostrich-scms/src/rest.rs](crates/ostrich-scms/src/rest.rs)):
- Token inventory: create, update, lookup, revoke (lines 134-225)
- Token lifecycle: initialize, personalize, suspend, resume, unblock (lines 188-245)
- Key management: list, generate, delete (lines 285-327)
- Event audit log: record and query token events (lines 349-357)
- Model registry: list and create token models (lines 330-346)

**EST Service** (17 TODOs in [crates/ostrich-est/src/rest.rs](crates/ostrich-est/src/rest.rs)):
- Enrollment records: create and track (lines 81-99)
- Client certificate validation and lookup (lines 81, 118)
- CA certificate chain retrieval (line 60)

**KRA Service** (8 TODOs):
- [crates/ostrich-kra/src/escrow.rs:156](crates/ostrich-kra/src/escrow.rs#L156) - Store escrowed keys
- [crates/ostrich-kra/src/recovery.rs:237](crates/ostrich-kra/src/recovery.rs#L237) - Load escrowed keys for recovery
- Share distribution and tracking (escrow.rs, recovery.rs)

**CA Service** (2 TODOs):
- [crates/ostrich-ca/src/rest.rs:141-142](crates/ostrich-ca/src/rest.rs#L141-L142) - Load profiles from database

### PKCS#11 HSM Integration (35 TODOs)

**Core PKCS#11 Provider** (20 TODOs in [crates/ostrich-crypto/src/pkcs11/mod.rs](crates/ostrich-crypto/src/pkcs11/mod.rs)):
- Lines 27-36: Initialize library, open session, login
- Lines 45-53: Key generation on HSM (RSA, ECDSA, EdDSA)
- Lines 66-74: Signing operations via HSM
- Lines 83-91: Key wrapping/unwrapping
- Lines 100-108: Key listing and destruction
- Line 125: Session cleanup on drop

**Software Crypto Fallback** (10 TODOs in [crates/ostrich-crypto/src/software/mod.rs](crates/ostrich-crypto/src/software/mod.rs)):
- Lines 37-45: Key generation using ring library
- Lines 58-66: Signing operations
- Lines 75-83: Key wrapping/unwrapping
- Lines 92-100: Key management
- Line 116: Cleanup

**SCMS Token Operations** (15 TODOs in [crates/ostrich-scms/src/rest.rs](crates/ostrich-scms/src/rest.rs)):
- Lines 193-195: Initialize token via PKCS#11
- Lines 207-208: Set PIN and generate keys on token
- Lines 240-241: Reset PIN retry counter
- Lines 255-256: Verify PIN via PKCS#11
- Lines 274: Change PIN via PKCS#11
- Lines 290: Query PKCS#11 for keys
- Lines 304: Generate key via PKCS#11
- Lines 323: Delete key via PKCS#11

### Protocol Validation & Security (18 TODOs)

**ACME JWS Validation** (10 TODOs in [crates/ostrich-acme/src/rest.rs](crates/ostrich-acme/src/rest.rs)):
- Line 145: Validate JWS signature on account creation
- Line 146: Extract JWK from protected header
- Line 187: Validate JWS signature on account update
- Line 237: Validate JWS signature on order creation
- Line 305: Validate JWS signature on authorization
- Line 358: Validate JWS signature on order finalization
- Line 362: Parse and validate CSR
- Line 424: Validate JWS signature on challenge completion
- Line 464: Validate JWS signature on challenge request

**ACME Challenge Validation** (3 TODOs):
- Line 471: HTTP-01 challenge validation
- Line 477: DNS-01 challenge validation
- Line 483: TLS-ALPN-01 challenge validation

**ACME Nonce Management** (1 TODO):
- Line 127: Cryptographically secure nonce generation

**EST mTLS Validation** (4 TODOs in [crates/ostrich-est/src/rest.rs](crates/ostrich-est/src/rest.rs)):
- Line 81: Validate client certificate (mTLS) for enrollment
- Line 89: Parse PKCS#10 CSR
- Line 90: Validate CSR signature
- Line 118: Validate client certificate (mTLS) for re-enrollment

### Service Integration (21 TODOs)

**ACME → CA** (1 TODO):
- [crates/ostrich-acme/src/rest.rs:362](crates/ostrich-acme/src/rest.rs#L362) - Issue certificate via CA service

**EST → CA** (2 TODOs):
- [crates/ostrich-est/src/rest.rs:84](crates/ostrich-est/src/rest.rs#L84) - Submit CSR to CA for issuance
- [crates/ostrich-est/src/rest.rs:122](crates/ostrich-est/src/rest.rs#L122) - Issue renewed certificate via CA

**SCMS → CA** (2 TODOs):
- [crates/ostrich-scms/src/rest.rs:209](crates/ostrich-scms/src/rest.rs#L209) - Issue certificates on token personalization
- [crates/ostrich-scms/src/rest.rs:180](crates/ostrich-scms/src/rest.rs#L180) - Revoke all certificates on token revocation

**CA → KRA** (implicit in issuance flow):
- Key escrow integration during certificate issuance

### Advanced Features (8 TODOs)

**OCSP Optimizations** (3 TODOs):
- [crates/ostrich-ocsp/src/responder.rs:47-49](crates/ostrich-ocsp/src/responder.rs#L47-L49) - Implement response caching
- Delegated signing support

**EST Advanced** (1 TODO):
- [crates/ostrich-est/src/rest.rs:168-173](crates/ostrich-est/src/rest.rs#L168-L173) - Server-side key generation (optional RFC 7030 feature)

**Post-Quantum Cryptography** (3 TODOs in [crates/ostrich-common/src/oid.rs](crates/ostrich-common/src/oid.rs)):
- Line 74: Update ML-DSA OID when NIST finalizes
- Line 80: Update ML-KEM OID when NIST finalizes
- Line 86: Update SLH-DSA OID when NIST finalizes

**Audit Enhancements** (1 TODO):
- [crates/ostrich-db/src/repository/audit.rs:132](crates/ostrich-db/src/repository/audit.rs#L132) - Implement hash chain verification

---

## Remaining Implementation Phases (8-14)

### Phase 8: Core Cryptographic Operations

**Priority**: HIGH
**Completion**: ~20%
**Estimated Effort**: 2-3 weeks
**Dependencies**: None (critical blocker for all other phases)
**Blocks**: All other phases

#### Scope

Implement all cryptographic operations required for certificate lifecycle management, including DER/ASN.1 encoding, signing, and PKCS#7 packaging.

#### Key Tasks

1. **X.509 Certificate DER Encoding** ([x509/builder/certificate.rs:275](crates/ostrich-x509/src/builder/certificate.rs#L275))
   - Implement ASN.1 encoding using `der` crate
   - Support all certificate extensions (SAN, key usage, policies, etc.)
   - Generate proper TBSCertificate structure
   - Handle version, serial number, validity period encoding

2. **X.509 CRL DER Encoding** ([x509/builder/crl.rs:160](crates/ostrich-x509/src/builder/crl.rs#L160))
   - Implement ASN.1 encoding for CRL structure
   - Support revoked certificate entries with reasons and dates
   - Handle CRL extensions (CRL number, delta CRL indicator)
   - Generate TBSCertList structure

3. **Certificate Signing** ([ca/issuance.rs:172-180](crates/ostrich-ca/src/issuance.rs#L172-L180))
   - RSA-PSS signing (2048, 3072, 4096 bit)
   - ECDSA signing (P-256, P-384, P-521)
   - EdDSA signing (Ed25519, Ed448)
   - ML-DSA signing (ML-DSA-44, ML-DSA-65, ML-DSA-87)
   - Integrate with crypto provider abstraction
   - Support both software and HSM signing

4. **CRL Signing** ([ca/revocation.rs:197-204](crates/ostrich-ca/src/revocation.rs#L197-L204))
   - Same algorithm support as certificate signing
   - Proper signature algorithm identifier encoding

5. **OCSP ASN.1 Operations**
   - Request parsing ([ocsp/request.rs:43](crates/ostrich-ocsp/src/request.rs#L43))
   - Response encoding ([ocsp/response.rs:117](crates/ostrich-ocsp/src/response.rs#L117))
   - Response signing ([ocsp/responder.rs:170](crates/ostrich-ocsp/src/responder.rs#L170))

6. **PKCS#7 Encoding for EST**
   - CA certificates package ([est/rest.rs:61](crates/ostrich-est/src/rest.rs#L61))
   - Enrollment response ([est/rest.rs:101](crates/ostrich-est/src/rest.rs#L101))
   - Re-enrollment response ([est/rest.rs:134](crates/ostrich-est/src/rest.rs#L134))

7. **PEM Parsing** ([x509/parser.rs:34](crates/ostrich-x509/src/parser.rs#L34))
   - Parse PEM-encoded certificates and CSRs
   - Convert to DER for processing

#### Technical Approach

- Use `der` crate for ASN.1 encoding/decoding
- Use `x509-cert` crate structures where applicable
- Use `pem-rfc7468` for PEM parsing
- Integrate with `ostrich-crypto` provider abstraction for signing
- Write comprehensive unit tests for each encoding/signing operation

#### Success Criteria

- All certificates properly DER-encoded and parseable by OpenSSL
- All CRLs properly encoded and verifiable
- Signatures verify with correct public keys
- OCSP requests/responses parse correctly
- PKCS#7 structures readable by EST clients
- Zero panics on malformed input

#### Files to Modify

- `crates/ostrich-x509/src/builder/certificate.rs`
- `crates/ostrich-x509/src/builder/crl.rs`
- `crates/ostrich-x509/src/parser.rs`
- `crates/ostrich-ca/src/issuance.rs`
- `crates/ostrich-ca/src/revocation.rs`
- `crates/ostrich-ocsp/src/request.rs`
- `crates/ostrich-ocsp/src/response.rs`
- `crates/ostrich-ocsp/src/responder.rs`
- `crates/ostrich-est/src/rest.rs`

---

### Phase 9: Database Integration & Persistence

**Priority**: HIGH
**Completion**: ✅ 100% COMPLETE (v0.10.0)
**Actual Effort**: 2 weeks
**Dependencies**: Phase 8 (need signing before storing certificates)
**Blocks**: Phase 12 (service integration)

#### Final Status (v0.10.0)

**Phase 9 Part 1 - Repository Layer** (v0.9.0):

- ✅ ACME repository layer with full CRUD operations (553 lines, 28 methods)
- ✅ SCMS repository layer for token lifecycle management (383 lines)
- ✅ EST repository layer for enrollment tracking (205 lines)
- ✅ KRA repository layer for key recovery workflows (346 lines)
- ✅ All database models with proper FromRow derivation
- ✅ Type-safe parameterized queries using sqlx
- ✅ Repository exports and module organization

**Phase 9 Part 2 - REST Handler Integration** (v0.10.0):

- ✅ **EST Service** (commit 7c1d080): 5 endpoints
  - EstState struct with database pool, crypto provider, audit sink
  - Enrollment tracking with pending status workflow
  - Deferred: CA integration (Phase 12), mTLS validation (Phase 11)

- ✅ **KRA Service** (commit d2c571c): Library integration
  - KeyEscrow and KeyRecovery services integrated with KraRepository
  - Escrowed key storage with M-of-N threshold tracking (3-of-5 default)
  - Recovery request and share submission tracking
  - Recovery agent management
  - Deferred: Crypto provider key wrapping (Phase 10), agent authorization (Phase 12)

- ✅ **ACME Service** (commit 107906a): 9 endpoints
  - Complete RFC 8555 state machine with database persistence
  - Account management (create, lookup by JWK, update)
  - Order lifecycle (pending → ready → processing → valid)
  - Authorization and challenge tracking (3 challenge types per authz)
  - Nonce generation and storage for replay protection
  - Deferred: JWS validation (Phase 11), CA integration (Phase 12)

- ✅ **SCMS Service** (commit f123c5e): 18 endpoints
  - Token lifecycle (initialize, personalize, suspend, resume, revoke, unblock)
  - PIN operations (verify with retry tracking, change)
  - Key management (generate, list, delete)
  - Model registry (create, list)
  - Event audit queries
  - State machine enforcement with proper error handling
  - Deferred: PKCS#11 operations (Phase 10), CA integration (Phase 12)

**Summary**: All 32 REST endpoints across 4 services fully integrated with database persistence

#### Achievements

**Architecture**:

- Established repository pattern for database abstraction across all services
- Type-safe database operations using sqlx with compile-time query validation
- Consistent error handling and mapping to HTTP status codes
- State machine enforcement for lifecycle operations (ACME orders, SCMS tokens)

**Scale & Quality**:

- 1,487 lines of repository code across 4 services
- 32 REST endpoints with full database integration
- All code passes clippy -D warnings, cargo fmt, cargo check
- Comprehensive TODOs documenting deferred work for future phases

**Deferred Work** (documented in code):

- Phase 8: Certificate signing, CSR validation, key wrapping
- Phase 10: PKCS#11 operations for real smartcard/HSM integration
- Phase 11: JWS/JWT validation, mTLS client auth, ACME challenge validation
- Phase 12: Service integration (CA ↔ ACME/EST/SCMS, CA ↔ KRA)

---

#### Historical Task Details (Completed)

##### ACME Service

1. **Account Management**
   - Create account records ([acme/rest.rs:145-155](crates/ostrich-acme/src/rest.rs#L145-L155))
   - Lookup accounts by JWK fingerprint ([acme/rest.rs:187](crates/ostrich-acme/src/rest.rs#L187))
   - Update account contact info and status
   - Store JWK for signature validation

2. **Order Lifecycle**
   - Create order records ([acme/rest.rs:237-248](crates/ostrich-acme/src/rest.rs#L237-L248))
   - Track order status (pending → ready → processing → valid/invalid)
   - Store order identifiers and DNS names
   - Link orders to accounts

3. **Authorization Tracking**
   - Create authorization records ([acme/rest.rs:305-315](crates/ostrich-acme/src/rest.rs#L305-L315))
   - Update authorization status as challenges complete
   - Store identifier and challenge set
   - Link authorizations to orders

4. **Challenge Management**
   - Create challenge records ([acme/rest.rs:464-483](crates/ostrich-acme/src/rest.rs#L464-L483))
   - Update challenge status (pending → processing → valid/invalid)
   - Store challenge tokens and validation data
   - Link challenges to authorizations

5. **Nonce Management**
   - Generate cryptographically secure nonces ([acme/rest.rs:127](crates/ostrich-acme/src/rest.rs#L127))
   - Store nonces with expiration
   - Mark nonces as used for replay protection
   - Clean up expired nonces

##### SCMS Service (45 TODOs)

1. **Token Inventory**
   - Create token records ([scms/rest.rs:147-150](crates/ostrich-scms/src/rest.rs#L147-L150))
   - Validate serial number uniqueness
   - Update token metadata (label, assigned user)
   - Query tokens with filters (status, assigned user, pagination)

2. **Token Lifecycle**
   - Initialize: Update status to initialized ([scms/rest.rs:192-195](crates/ostrich-scms/src/rest.rs#L192-L195))
   - Personalize: Set assigned user, update status ([scms/rest.rs:206-211](crates/ostrich-scms/src/rest.rs#L206-L211))
   - Suspend/Resume: Update status ([scms/rest.rs:222-234](crates/ostrich-scms/src/rest.rs#L222-L234))
   - Revoke: Mark as revoked, cascade to keys ([scms/rest.rs:179-182](crates/ostrich-scms/src/rest.rs#L179-L182))
   - Unblock: Reset PIN retry counter ([scms/rest.rs:240-243](crates/ostrich-scms/src/rest.rs#L240-L243))

3. **Key Management**
   - Store key metadata on generation ([scms/rest.rs:303-306](crates/ostrich-scms/src/rest.rs#L303-L306))
   - List keys on token ([scms/rest.rs:289-290](crates/ostrich-scms/src/rest.rs#L289-L290))
   - Delete key metadata ([scms/rest.rs:322-324](crates/ostrich-scms/src/rest.rs#L322-L324))
   - Link keys to tokens

4. **Event Audit Log**
   - Record all token operations ([scms/rest.rs](crates/ostrich-scms/src/rest.rs) - throughout)
   - Query events by token ID ([scms/rest.rs:353](crates/ostrich-scms/src/rest.rs#L353))
   - Store timestamps, actors, event types

5. **Token Models**
   - Create model records ([scms/rest.rs:343](crates/ostrich-scms/src/rest.rs#L343))
   - List available models ([scms/rest.rs:332](crates/ostrich-scms/src/rest.rs#L332))
   - Store model capabilities (algorithms, key sizes)

##### EST Service (17 TODOs)

1. **Enrollment Records**
   - Create enrollment on simple enroll ([est/rest.rs:98](crates/ostrich-est/src/rest.rs#L98))
   - Store CSR, issued certificate, timestamps
   - Track enrollment status

2. **Client Certificate Tracking**
   - Validate client certificates for mTLS ([est/rest.rs:81, 118](crates/ostrich-est/src/rest.rs#L81))
   - Store client DN and serial for authorization
   - Track re-enrollment history

3. **CA Certificate Chain**
   - Fetch CA certificates from database ([est/rest.rs:60](crates/ostrich-est/src/rest.rs#L60))

##### KRA Service (8 TODOs)

1. **Escrowed Key Storage**
   - Store encrypted key material ([kra/escrow.rs:156](crates/ostrich-kra/src/escrow.rs#L156))
   - Store shares for each recovery agent
   - Track escrow status and metadata

2. **Recovery Operations**
   - Load escrowed keys by certificate serial ([kra/recovery.rs:237](crates/ostrich-kra/src/recovery.rs#L237))
   - Track share submissions
   - Update recovery status

##### CA Service (2 TODOs)

1. **Profile Management**
   - Load certificate profiles from database ([ca/rest.rs:141-142](crates/ostrich-ca/src/rest.rs#L141-L142))

#### Database Schema Extensions

**ACME Tables**:
```sql
CREATE TABLE acme_accounts (
    id UUID PRIMARY KEY,
    jwk_fingerprint TEXT UNIQUE NOT NULL,
    jwk JSONB NOT NULL,
    contact JSONB,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE acme_orders (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES acme_accounts(id),
    status TEXT NOT NULL,
    identifiers JSONB NOT NULL,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    certificate_serial TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires TIMESTAMPTZ NOT NULL
);

CREATE TABLE acme_authorizations (
    id UUID PRIMARY KEY,
    order_id UUID REFERENCES acme_orders(id),
    identifier JSONB NOT NULL,
    status TEXT NOT NULL,
    expires TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE acme_challenges (
    id UUID PRIMARY KEY,
    authz_id UUID REFERENCES acme_authorizations(id),
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    token TEXT NOT NULL,
    validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE acme_nonces (
    nonce TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL
);
```

**SCMS Tables**:
```sql
CREATE TABLE scms_models (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    capabilities JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE scms_tokens (
    id UUID PRIMARY KEY,
    serial_number TEXT UNIQUE NOT NULL,
    model_id UUID REFERENCES scms_models(id),
    label TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_to TEXT,
    pin_retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE scms_keys (
    id UUID PRIMARY KEY,
    token_id UUID REFERENCES scms_tokens(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_size INTEGER NOT NULL,
    usage JSONB NOT NULL,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE scms_events (
    id UUID PRIMARY KEY,
    token_id UUID REFERENCES scms_tokens(id),
    event_type TEXT NOT NULL,
    actor TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
);
```

**EST Tables**:
```sql
CREATE TABLE est_enrollments (
    id UUID PRIMARY KEY,
    client_dn TEXT NOT NULL,
    csr BYTEA NOT NULL,
    certificate_serial TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
```

**KRA Tables**:
```sql
CREATE TABLE kra_escrowed_keys (
    id UUID PRIMARY KEY,
    certificate_serial TEXT UNIQUE NOT NULL,
    encrypted_key BYTEA NOT NULL,
    algorithm TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE kra_shares (
    id UUID PRIMARY KEY,
    escrowed_key_id UUID REFERENCES kra_escrowed_keys(id),
    agent_id UUID NOT NULL,
    encrypted_share BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE kra_recoveries (
    id UUID PRIMARY KEY,
    escrowed_key_id UUID REFERENCES kra_escrowed_keys(id),
    requestor TEXT NOT NULL,
    status TEXT NOT NULL,
    shares_submitted INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
```

#### Technical Approach

- Use `sqlx` for database operations
- Write migrations for new tables
- Implement repository pattern for each service
- Use transactions for multi-step operations
- Add database indexes for common queries
- Implement pagination for list endpoints
- Handle constraint violations gracefully

#### Success Criteria

- All services persist state to database
- Services survive restarts without data loss
- Concurrent requests handled safely with transactions
- Database migrations apply cleanly
- Query performance acceptable (<100ms for common operations)
- Foreign key constraints prevent orphaned records

#### Files to Modify

- `migrations/` - New migration files
- `crates/ostrich-acme/src/rest.rs`
- `crates/ostrich-scms/src/rest.rs`
- `crates/ostrich-est/src/rest.rs`
- `crates/ostrich-kra/src/escrow.rs`
- `crates/ostrich-kra/src/recovery.rs`
- `crates/ostrich-ca/src/rest.rs`
- `crates/ostrich-db/src/repository/` - New repository modules

---

### Phase 10: PKCS#11 HSM Integration

**Priority**: MEDIUM
**Completion**: 0%
**Estimated Effort**: 3-4 weeks
**Dependencies**: Physical HSM or SoftHSM for testing
**Blocks**: None (can run with software crypto)

#### Scope

Implement production-grade PKCS#11 HSM integration for key generation, signing, and key management operations. Provide software crypto fallback for development/testing.

#### Key Tasks

##### Core PKCS#11 Provider (20 TODOs in [crypto/pkcs11/mod.rs](crates/ostrich-crypto/src/pkcs11/mod.rs))

1. **Initialization & Session Management** (lines 27-36)
   - Initialize PKCS#11 library (C_Initialize)
   - Open session with HSM slot (C_OpenSession)
   - Login with SO/User PIN (C_Login)
   - Session pooling for concurrent operations
   - Cleanup on drop (C_Logout, C_CloseSession, C_Finalize)

2. **Key Generation** (lines 45-53)
   - RSA key pair generation (2048, 3072, 4096 bit)
   - ECDSA key pair generation (P-256, P-384, P-521)
   - EdDSA key pair generation (Ed25519, Ed448)
   - ML-DSA key pair generation (when HSM supports)
   - Set key attributes (label, usage flags, extractable)
   - Return key handles for signing

3. **Signing Operations** (lines 66-74)
   - RSA-PSS signing with configurable salt length
   - ECDSA signing with SHA-256/384/512
   - EdDSA signing
   - ML-DSA signing
   - Use C_Sign or C_SignInit/C_SignUpdate/C_SignFinal
   - Handle digest computation (on HSM vs. software)

4. **Key Wrapping** (lines 83-91)
   - Wrap private keys for escrow/backup (C_WrapKey)
   - Unwrap keys for recovery (C_UnwrapKey)
   - Support AES-KW and RSA-OAEP wrapping mechanisms
   - Set wrapped key attributes correctly

5. **Key Management** (lines 100-108)
   - List keys on HSM (C_FindObjects)
   - Get key attributes (public key material, label, usage)
   - Destroy keys (C_DestroyObject)
   - Filter by key type, label, usage

##### Software Crypto Fallback (10 TODOs in [crypto/software/mod.rs](crates/ostrich-crypto/src/software/mod.rs))

Implement same interface as PKCS#11 provider using `ring` library:
- RSA key generation and signing (ring_compat crate)
- ECDSA key generation and signing (ring::signature)
- EdDSA key generation and signing (ed25519-dalek, ed448-goldilocks)
- Key wrapping using AES-KW (aes-kw crate)
- In-memory key storage (protected by OS memory permissions)

##### SCMS Token Operations (15 TODOs in [scms/rest.rs](crates/ostrich-scms/src/rest.rs))

1. **Token Initialization** ([scms/rest.rs:193](crates/ostrich-scms/src/rest.rs#L193))
   - Initialize token via C_InitToken
   - Set SO-PIN and User-PIN
   - Configure token label

2. **PIN Management**
   - Set initial PIN on personalization ([scms/rest.rs:207](crates/ostrich-scms/src/rest.rs#L207))
   - Verify PIN ([scms/rest.rs:255](crates/ostrich-scms/src/rest.rs#L255))
   - Change PIN ([scms/rest.rs:274](crates/ostrich-scms/src/rest.rs#L274))
   - Reset PIN retry counter ([scms/rest.rs:241](crates/ostrich-scms/src/rest.rs#L241))

3. **Key Operations on Smartcards**
   - Generate key pair on token ([scms/rest.rs:304](crates/ostrich-scms/src/rest.rs#L304))
   - List keys on token ([scms/rest.rs:290](crates/ostrich-scms/src/rest.rs#L290))
   - Delete key from token ([scms/rest.rs:323](crates/ostrich-scms/src/rest.rs#L323))
   - Extract public key for certificate issuance

#### Technical Approach

- Use `cryptoki` crate for PKCS#11 bindings
- Abstract crypto provider interface:
  ```rust
  pub trait CryptoProvider {
      fn generate_key_pair(&self, params: KeyGenParams) -> Result<KeyHandle>;
      fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>>;
      fn wrap_key(&self, key: &KeyHandle, wrapping_key: &KeyHandle) -> Result<Vec<u8>>;
      fn unwrap_key(&self, wrapped: &[u8], wrapping_key: &KeyHandle) -> Result<KeyHandle>;
      fn list_keys(&self, filter: KeyFilter) -> Result<Vec<KeyMetadata>>;
      fn destroy_key(&self, key: &KeyHandle) -> Result<()>;
  }
  ```
- Implement for both `Pkcs11Provider` and `SoftwareProvider`
- Configuration: HSM library path, slot ID, PIN (from env/config)
- Error handling: Map PKCS#11 errors to domain errors
- Testing: Use SoftHSM for CI/CD pipeline

#### HSM Configuration

**Required Environment Variables**:
```bash
OSTRICH_HSM_ENABLED=true
OSTRICH_HSM_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so
OSTRICH_HSM_SLOT=0
OSTRICH_HSM_SO_PIN=<secret>
OSTRICH_HSM_USER_PIN=<secret>
```

**SoftHSM Setup for Testing**:
```bash
softhsm2-util --init-token --slot 0 --label "OstrichPKI" --so-pin 1234 --pin 5678
```

#### Success Criteria

- Can generate RSA, ECDSA, EdDSA keys on HSM
- Signing operations produce valid signatures
- Key wrapping/unwrapping preserves key material
- Software provider passes same test suite as PKCS#11 provider
- SCMS can initialize smartcards and manage PINs
- Zero memory leaks or crashes
- Performance: <50ms for signing operation, <500ms for key generation

#### Files to Modify

- `crates/ostrich-crypto/src/pkcs11/mod.rs`
- `crates/ostrich-crypto/src/software/mod.rs`
- `crates/ostrich-crypto/src/provider.rs` (new - trait definition)
- `crates/ostrich-scms/src/rest.rs`
- `crates/ostrich-ca/src/issuance.rs` (use crypto provider)
- `crates/ostrich-ca/src/revocation.rs` (use crypto provider)

---

### Phase 11: Protocol Validation & Security

**Priority**: HIGH
**Completion**: ~75%
**Estimated Effort**: 2 weeks
**Dependencies**: None (can run in parallel with Phase 8-9)
**Blocks**: Production deployment

#### Scope

Implement comprehensive protocol validation for ACME and EST, including JWS signature validation, mTLS client certificate validation, CSR parsing, and challenge validation.

**Completed**:

- ✅ ACME JWS signature validation (all POST endpoints)
- ✅ ACME nonce replay protection
- ✅ ACME URL binding validation
- ✅ ACME CSR parsing and signature verification
- ✅ EST CSR parsing and signature verification
- ✅ EST mTLS module implementation (certificate parsing, validation structure)
- ✅ ACME challenge validation module (HTTP-01, DNS-01, TLS-ALPN-01 infrastructure)

**Remaining**:

- ACME challenge integration into handlers (connect validators to challenge endpoints)
- EST mTLS TLS server integration (requires rustls/tokio-rustls setup)
- DNS-01 full implementation (requires DNS resolver library)
- TLS-ALPN-01 full implementation (requires TLS client library)
- SAN extraction from CSR extensionRequest

#### Key Tasks

##### ACME JWS Validation (10 TODOs)

**Status**: ✅ **JWS validation fully integrated into all ACME POST endpoints**

1. **JWS Signature Validation** ✅ **COMPLETE**
   - ✅ Parse JWS compact/flattened serialization (jws.rs:parse_jws)
   - ✅ Extract protected header (jws.rs:decode_protected_header)
   - ✅ Validate signature using JWK (jws.rs:verify_jws_with_jwk)
   - ✅ Support for RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA
   - ✅ JWK to SPKI DER conversion for RSA, EC (P-256/384/521), Ed25519
   - ✅ Integrated into all POST endpoints: new-account, update-account, new-order, respond-to-challenge, finalize-order
   - ✅ Nonce freshness verification (consume_nonce integration)
   - ✅ URL binding validation in protected header

2. **JWK Handling** ✅ **IMPLEMENTED**
   - ✅ Extract JWK from protected header (ProtectedHeader.jwk field)
   - ✅ Compute JWK thumbprint for account lookup (jws.rs:compute_jwk_thumbprint - RFC 7638)
   - ✅ Support RSA, ECDSA (P-256/384/521), Ed25519 JWKs
   - ✅ Validate JWK structure (required fields, valid values)

3. **CSR Parsing & Validation** ✅ **COMPLETE**
   - ✅ Parse PKCS#10 CSR from finalize request using x509-parser
   - ✅ Validate CSR signature (proof of possession)
   - ✅ Extract subject DN and public key
   - ✅ Extract attributes from CSR
   - ⏳ TODO: Extract SANs from extensionRequest attribute
   - ⏳ TODO: Verify SANs match order identifiers
   - ⏳ TODO: Check key usage consistency

4. **Nonce Management** ✅ **COMPLETE**
   - ✅ Cryptographically secure random nonce generation (UUID v4)
   - ✅ Database storage with expiration (5 minutes)
   - ✅ Replay protection: consume_nonce() deletes used nonces
   - ✅ Fresh nonce returned in Replay-Nonce header on every response

##### ACME Challenge Validation (3 TODOs)

**Status**: ✅ **Infrastructure Complete** (crates/ostrich-acme/src/validation.rs)

1. **HTTP-01 Challenge** ✅ **IMPLEMENTED**
   - ✅ Http01Validator structure with reqwest HTTP client
   - ✅ Fetch `http://<domain>/.well-known/acme-challenge/<token>`
   - ✅ Verify response = `<token>.<account_key_thumbprint>`
   - ✅ Follow HTTP redirects (max 10)
   - ✅ Timeout: 10 seconds
   - ✅ SSRF prevention (block private IP domains)
   - ⏳ TODO: DNS resolution to detect private IPs
   - ⏳ TODO: Integration into challenge response handler

2. **DNS-01 Challenge** ⏳ **PARTIAL** (infrastructure ready)
   - ✅ Dns01Validator structure
   - ✅ Compute expected TXT value: Base64URL(SHA256(`<token>.<thumbprint>`))
   - ✅ Construct TXT record name: `_acme-challenge.<domain>`
   - ⏳ TODO: DNS resolver implementation (requires trust-dns-resolver)
   - ⏳ TODO: Query TXT records
   - ⏳ TODO: Timeout: 30 seconds
   - ⏳ TODO: Integration into challenge response handler

3. **TLS-ALPN-01 Challenge** ⏳ **PARTIAL** (infrastructure ready)
   - ✅ TlsAlpn01Validator structure
   - ✅ Compute expected acmeIdentifier hash: SHA256(`<token>.<thumbprint>`)
   - ⏳ TODO: TLS client implementation (requires tokio-rustls)
   - ⏳ TODO: Establish TLS connection with ALPN extension "acme-tls/1"
   - ⏳ TODO: Extract certificate from handshake
   - ⏳ TODO: Verify certificate has acmeIdentifier extension with SHA256 hash
   - ⏳ TODO: Validate domain matches certificate SAN
   - ⏳ TODO: Timeout: 10 seconds
   - ⏳ TODO: Integration into challenge response handler

##### EST mTLS Validation (4 TODOs)

1. **mTLS Module Implementation** ✅ **COMPLETE** (crates/ostrich-est/src/mtls.rs)
   - ✅ MtlsClientCert structure for parsed certificates
   - ✅ Certificate parsing from DER with x509-parser
   - ✅ Certificate expiration validation
   - ✅ Client identifier computation (SHA-256 of certificate DER)
   - ✅ validate_client() function for authorized client database lookup
   - ✅ Extract subject DN, serial number, issuer DN
   - ✅ Integration points documented in EST handlers

2. **Client Certificate Extraction** ⏳ **PENDING** (requires TLS server setup)
   - ⏳ TODO: Configure Axum server with TLS using rustls/tokio-rustls
   - ⏳ TODO: Enable client certificate requirement in TLS config
   - ⏳ TODO: Extract peer certificate from TLS connection info
   - ⏳ TODO: Integrate extract_client_cert_placeholder() into handlers
   - ⏳ TODO: Verify certificate chain up to trusted CA
   - ⏳ TODO: Check certificate is not revoked (CRL or OCSP)

3. **CSR Parsing** ✅ **COMPLETE**
   - ✅ Parse PKCS#10 from base64-encoded body
   - ✅ Validate CSR signature (proof of possession)
   - ✅ Extract subject DN and public key
   - ⏳ TODO: For re-enrollment, verify subject matches client certificate (when mTLS available)

#### Technical Approach

**ACME JWS**:
- Use `jsonwebtoken` crate or `josekit` for JWS parsing
- Use `ring` for signature verification
- Store account JWK in database for lookup

**Challenge Validation**:
- Use `reqwest` for HTTP-01 (async HTTP client)
- Use `trust-dns-resolver` for DNS-01
- Use `tokio-rustls` for TLS-ALPN-01
- Run validations asynchronously with timeout
- Implement retry logic (3 attempts with exponential backoff)

**EST mTLS**:
- Configure Axum to require client certificates
- Extract certificate from `axum::extract::ConnectInfo`
- Use `x509-cert` for parsing and validation
- Query OCSP responder or CRL for revocation check

**Nonce Generation**:
```rust
use getrandom::getrandom;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).expect("RNG failure");
    URL_SAFE_NO_PAD.encode(&bytes)
}
```

#### Security Considerations

- Prevent timing attacks in signature validation
- Rate limit challenge validation attempts
- Prevent SSRF in HTTP-01 validation (block private IPs)
- Validate DNS responses are authentic (DNSSEC if possible)
- Use constant-time comparison for nonces
- Implement account rate limiting (e.g., 10 orders/hour)

#### Success Criteria

- All ACME requests with invalid JWS rejected with 401
- Nonce reuse detected and rejected
- HTTP-01, DNS-01, TLS-ALPN-01 challenges validate correctly
- Invalid CSRs rejected (bad signature, mismatched SANs)
- EST enforces mTLS and rejects unauthenticated requests
- Zero false positives/negatives in validation
- Performance: <200ms for JWS validation, <5s for challenge validation

#### Files to Modify

- `crates/ostrich-acme/src/rest.rs`
- `crates/ostrich-acme/src/jws.rs` (new - JWS validation module)
- `crates/ostrich-acme/src/challenge.rs` (new - challenge validation)
- `crates/ostrich-est/src/rest.rs`
- `crates/ostrich-est/src/mtls.rs` (new - mTLS validation)
- `crates/ostrich-x509/src/parser.rs` (CSR parsing)

---

### Phase 12: Service Integration

**Priority**: MEDIUM
**Completion**: 0%
**Estimated Effort**: 1-2 weeks
**Dependencies**: Phase 8 (crypto), Phase 9 (database)
**Blocks**: End-to-end workflows

#### Scope

Connect all microservices to enable end-to-end workflows: ACME/EST enrollments result in CA-issued certificates, KRA escrows keys, SCMS manages smartcard certificates.

#### Key Tasks

##### ACME → CA Integration

1. **Certificate Issuance** ([acme/rest.rs:362](crates/ostrich-acme/src/rest.rs#L362))
   - After order finalized with valid CSR
   - Call CA service via gRPC: `IssueCertificate` RPC
   - Pass CSR, profile ID, validity period
   - Receive issued certificate (DER-encoded)
   - Encode in PKCS#7 for ACME response
   - Update order status to "valid"
   - Store certificate serial in order record

**gRPC Call**:
```rust
let cert = ca_client.issue_certificate(IssueCertificateRequest {
    csr: csr_der,
    profile_id: "acme-server-cert".to_string(),
    validity_days: 90,
}).await?;
```

##### EST → CA Integration

1. **Simple Enrollment** ([est/rest.rs:84](crates/ostrich-est/src/rest.rs#L84))
   - Parse CSR from request body
   - Validate client certificate (mTLS)
   - Call CA service to issue certificate
   - Return PKCS#7 with issued certificate
   - Create enrollment record

2. **Re-enrollment** ([est/rest.rs:122](crates/ostrich-est/src/rest.rs#L122))
   - Validate client certificate matches CSR subject
   - Issue renewed certificate via CA
   - Same validity period and profile as original

##### CA → KRA Integration

1. **Key Escrow on Issuance** (implicit in CA flow)
   - After issuing certificate with key escrow policy
   - Call KRA service: `EscrowKey` RPC
   - Pass certificate serial, public key, encrypted private key
   - KRA splits into shares and stores
   - CA records escrow ID in certificate metadata

**When to Escrow**:
- Certificate profile has `key_escrow: true`
- User consents to escrow (stored in CSR attributes)
- Key recovery agents configured

##### SCMS → CA Integration

1. **Certificate Issuance on Personalization** ([scms/rest.rs:209](crates/ostrich-scms/src/rest.rs#L209))
   - Generate keys on smartcard
   - Extract public key via PKCS#11
   - Create CSR with smartcard holder's DN
   - Call CA to issue certificate
   - Write certificate to smartcard (via PKCS#11)
   - Update token status to "personalized"

2. **Certificate Revocation on Token Revocation** ([scms/rest.rs:180](crates/ostrich-scms/src/rest.rs#L180))
   - List all certificates on token (from scms_keys table)
   - For each certificate:
     - Call CA service: `RevokeCertificate` RPC
     - Reason: "cessation_of_operation" or "key_compromise"
   - Update token status to "revoked"

#### Service Discovery & Communication

**Approach**: gRPC with TLS
- Each service exposes gRPC endpoint on separate port
- Use mTLS between services (mutual authentication)
- Service discovery via configuration (not dynamic for now)

**Configuration** (example):
```toml
[services.ca]
grpc_endpoint = "https://ca.ostrich.local:8443"
tls_cert = "/etc/ostrich/certs/acme-client.pem"
tls_key = "/etc/ostrich/keys/acme-client.key"
ca_cert = "/etc/ostrich/ca.pem"
```

**gRPC Client Setup**:
```rust
use tonic::transport::{ClientTlsConfig, Channel, Certificate, Identity};

let tls = ClientTlsConfig::new()
    .ca_certificate(Certificate::from_pem(ca_cert))
    .identity(Identity::from_pem(client_cert, client_key));

let channel = Channel::from_static("https://ca.ostrich.local:8443")
    .tls_config(tls)?
    .connect()
    .await?;

let ca_client = CaServiceClient::new(channel);
```

#### Error Handling

- Retry transient errors (3 attempts with exponential backoff)
- Circuit breaker pattern for downstream service failures
- Graceful degradation: ACME returns 503 if CA unavailable
- Log all inter-service calls for audit trail

#### Success Criteria

- ACME finalize-order results in CA-issued certificate
- EST enrollment returns valid CA-signed certificate
- SCMS personalization writes certificate to smartcard
- KRA automatically escrows keys for designated profiles
- SCMS revocation triggers CA revocation
- All inter-service calls use mTLS
- Error handling prevents partial state (transactions)

#### Files to Modify

- `crates/ostrich-acme/src/rest.rs`
- `crates/ostrich-est/src/rest.rs`
- `crates/ostrich-scms/src/rest.rs`
- `crates/ostrich-ca/src/issuance.rs`
- `crates/ostrich-ca/src/revocation.rs`
- `crates/ostrich-kra/src/escrow.rs`
- Configuration files for service endpoints

---

### Phase 13: Advanced Features

**Priority**: LOW
**Completion**: 0%
**Estimated Effort**: 2-3 weeks
**Dependencies**: Phases 8-12
**Blocks**: None (optional enhancements)

#### Scope

Implement optional advanced features to improve performance, compliance, and functionality.

#### Key Tasks

##### OCSP Response Caching (3 TODOs)

**Goal**: Reduce CA load and improve response time

1. **Response Caching** ([ocsp/responder.rs:47-49](crates/ostrich-ocsp/src/responder.rs#L47-L49))
   - Cache OCSP responses in memory (LRU cache)
   - Key: certificate serial number
   - Value: signed OCSP response + expiration
   - TTL: `nextUpdate` from response (typically 1-24 hours)
   - Invalidate on certificate revocation

2. **Pre-generation**
   - Background task to pre-generate responses for recently issued certs
   - Reduces latency for first request

3. **Delegated Signing**
   - OCSP responder uses dedicated signing key
   - Issued by CA with id-kp-OCSPSigning EKU
   - Reduces exposure of CA signing key

**Implementation**:
```rust
use lru::LruCache;
use std::sync::Arc;
use tokio::sync::RwLock;

struct OcspCache {
    cache: Arc<RwLock<LruCache<String, CachedResponse>>>,
}

struct CachedResponse {
    response: Vec<u8>,
    expires_at: SystemTime,
}
```

##### EST Server-Side Key Generation (1 TODO)

**Goal**: Support RFC 7030 §4.3 optional feature

1. **Implementation** ([est/rest.rs:168-173](crates/ostrich-est/src/rest.rs#L168-L173))
   - Parse CSR (contains subject info, no private key)
   - Generate key pair on server (via crypto provider)
   - Issue certificate with generated public key
   - Encrypt private key for client using client certificate's public key
   - Return PKCS#7 with certificate + encrypted private key (PKCS#8)

**Security Considerations**:
- Private key never stored unencrypted
- Use ephemeral encryption key
- Audit log all key generation events
- Require strong client authentication

**Use Case**: Clients without crypto capabilities (embedded devices)

##### Post-Quantum Cryptography OID Updates (3 TODOs)

**Goal**: Stay current with NIST PQC standards

1. **ML-DSA OID** ([common/oid.rs:74](crates/ostrich-common/src/oid.rs#L74))
   - Update when NIST publishes final OID for ML-DSA
   - Currently using draft OID: `2.16.840.1.101.3.4.3.17` (placeholder)

2. **ML-KEM OID** ([common/oid.rs:80](crates/ostrich-common/src/oid.rs#L80))
   - Update for ML-KEM (formerly CRYSTALS-Kyber)
   - Used for key encapsulation in hybrid schemes

3. **SLH-DSA OID** ([common/oid.rs:86](crates/ostrich-common/src/oid.rs#L86))
   - Update for SLH-DSA (formerly SPHINCS+)
   - Stateless hash-based signature scheme

**Action**: Monitor NIST Computer Security Resource Center for updates

##### Audit Hash Chain Verification (1 TODO)

**Goal**: Ensure audit log integrity

1. **Hash Chain Verification** ([db/repository/audit.rs:132](crates/ostrich-db/src/repository/audit.rs#L132))
   - Each audit event includes hash of previous event
   - Verification reconstructs chain and checks consistency
   - Detects tampering or missing events

**Implementation**:
```rust
pub fn verify_hash_chain(events: &[AuditEvent]) -> Result<bool> {
    let mut prev_hash = [0u8; 32]; // Genesis hash
    for event in events {
        let computed = compute_event_hash(&prev_hash, event);
        if computed != event.previous_hash {
            return Ok(false); // Chain broken
        }
        prev_hash = event.hash;
    }
    Ok(true)
}
```

##### Software Crypto Provider (implicit)

**Goal**: Full software fallback when HSM unavailable

- Already planned in Phase 10
- Ensure feature parity with PKCS#11 provider
- Use `ring` for RSA/ECDSA, `ed25519-dalek` for EdDSA
- In-memory key storage with OS memory protection

#### Success Criteria

- OCSP responses served from cache (>90% hit rate)
- EST server-side key generation works for test clients
- PQC OIDs updated when NIST publishes
- Audit hash chain verification detects tampering
- Software crypto provider passes all tests

#### Files to Modify

- `crates/ostrich-ocsp/src/responder.rs`
- `crates/ostrich-ocsp/src/cache.rs` (new)
- `crates/ostrich-est/src/rest.rs`
- `crates/ostrich-common/src/oid.rs`
- `crates/ostrich-db/src/repository/audit.rs`

---

### Phase 14: Testing & Hardening

**Priority**: HIGH
**Completion**: ~10% (unit tests only)
**Estimated Effort**: 2-3 weeks
**Dependencies**: Phases 8-12
**Blocks**: Production deployment

#### Scope

Comprehensive testing, security hardening, and production readiness preparation.

#### Key Tasks

##### Integration Testing

1. **End-to-End Workflows**
   - **ACME Order Flow**: new-account → new-order → authz → challenges → finalize → download certificate
   - **EST Enrollment**: mTLS connection → simple enroll → receive certificate
   - **SCMS Lifecycle**: create token → initialize → personalize → issue cert → suspend → resume → revoke
   - **KRA Recovery**: escrow key → request recovery → submit shares → recover key

2. **Service Integration Tests**
   - ACME → CA certificate issuance
   - EST → CA certificate issuance
   - CA → KRA key escrow
   - SCMS → CA certificate issuance and revocation
   - OCSP responder validates certificates issued by CA

3. **Cross-Service mTLS**
   - All gRPC calls use mutual TLS
   - Certificate validation enforced
   - Unauthorized services rejected

4. **Database Transactions**
   - Verify atomicity of multi-step operations
   - Test rollback on errors
   - Concurrent request handling

##### Security Testing

1. **Input Validation**
   - Fuzz testing for ASN.1 parsers (certificates, CSRs, OCSP)
   - Invalid JWS signatures rejected
   - SQL injection prevention (parameterized queries)
   - XSS prevention (proper JSON encoding)

2. **Cryptographic Validation**
   - All signatures verify correctly
   - Nonce replay protection works
   - Challenge validation prevents bypass

3. **Authorization Testing**
   - ACME account isolation (can't access other accounts' orders)
   - EST client certificate enforcement
   - SCMS role-based access control

4. **Rate Limiting**
   - Per-IP rate limits on ACME endpoints
   - Account-level rate limits (orders/hour)
   - Challenge validation rate limits

5. **TLS Configuration**
   - Enforce TLS 1.3 (disable TLS 1.2 and below)
   - Strong cipher suites only
   - HSTS headers on HTTP endpoints

##### Performance Testing

1. **Load Testing**
   - ACME: 100 concurrent orders/second
   - OCSP: 1000 requests/second (with caching)
   - CA issuance: 50 certificates/second
   - Identify bottlenecks and optimize

2. **Database Performance**
   - Index optimization for common queries
   - Connection pooling tuning
   - Query execution plans review

3. **Latency Benchmarks**
   - ACME order finalize: <500ms (excluding CA signing)
   - OCSP response: <50ms (cached), <200ms (uncached)
   - CA certificate issuance: <1s

##### Error Handling Review

1. **Graceful Degradation**
   - Services continue when dependencies unavailable
   - Appropriate HTTP status codes
   - Informative error messages (no stack traces to clients)

2. **Logging & Monitoring**
   - Structured logging (JSON format)
   - Log levels appropriate (ERROR for failures, INFO for success)
   - Audit events for all security-relevant operations
   - Metrics: request count, latency, error rate

3. **Panic Recovery**
   - No panics in production code paths
   - Graceful handling of unexpected errors
   - Process restarts on panic (systemd/Kubernetes)

##### Documentation Updates

1. **API Documentation**
   - OpenAPI specs for REST endpoints
   - gRPC protobuf documentation
   - Example requests/responses

2. **Deployment Guide**
   - Docker Compose setup
   - Kubernetes manifests
   - HSM configuration
   - Database setup and migrations

3. **Security Documentation**
   - Threat model
   - Security controls matrix (NIST 800-53)
   - Incident response procedures

4. **Operational Runbooks**
   - Service startup/shutdown
   - Backup and recovery
   - Certificate renewal procedures
   - Troubleshooting common issues

##### Security Audit Preparation

1. **Code Review**
   - Third-party security audit of cryptographic code
   - Review of database access patterns
   - Input validation completeness

2. **Dependency Audit**
   - `cargo audit` for known vulnerabilities
   - Review transitive dependencies
   - Pin dependency versions

3. **Compliance Checklist**
   - NIST 800-53 controls implemented
   - RFC compliance matrix
   - Common Criteria (CC) considerations

#### Test Coverage Goals

- **Unit Tests**: >80% line coverage
- **Integration Tests**: All end-to-end workflows covered
- **Security Tests**: All OWASP Top 10 mitigated
- **Performance Tests**: All latency benchmarks met

#### CI/CD Pipeline

1. **Continuous Integration**
   - Run tests on every commit
   - Cargo clippy (linter) with zero warnings
   - Cargo fmt (formatter) enforced
   - Cargo audit for dependencies

2. **Continuous Deployment**
   - Automated deployment to staging
   - Smoke tests on staging
   - Manual approval for production

#### Success Criteria

- All integration tests pass
- Security audit finds no critical/high vulnerabilities
- Performance benchmarks met
- Zero panics in stress testing
- Documentation complete and accurate
- CI/CD pipeline operational
- Ready for production deployment

#### Files to Modify

- `crates/*/tests/` - Integration test modules
- `tests/` - End-to-end test suite
- `docs/` - Documentation
- `.github/workflows/` or CI config
- `docker-compose.yml`, Kubernetes manifests

---

## Priority Matrix

| Phase | Priority | Completion | Effort | Dependencies | Blocks |
|-------|----------|------------|--------|--------------|--------|
| **8: Cryptographic Operations** | **HIGH** | **20%** | **2-3 weeks** | None | All others |
| **9: Database Integration** | **HIGH** | **25%** | **2-3 weeks** | Phase 8 | Phase 12 |
| **10: PKCS#11 HSM Integration** | **MEDIUM** | **0%** | **3-4 weeks** | HSM hardware/SoftHSM | None |
| **11: Protocol Validation** | **HIGH** | **5%** | **2 weeks** | None | Production |
| **12: Service Integration** | **MEDIUM** | **0%** | **1-2 weeks** | Phases 8, 9 | End-to-end workflows |
| **13: Advanced Features** | **LOW** | **0%** | **2-3 weeks** | Phases 8-12 | None |
| **14: Testing & Hardening** | **HIGH** | **10%** | **2-3 weeks** | Phases 8-12 | Production |

---

## Timeline Estimates

### Critical Path (Production Deployment)

**Sequential Phases**:
1. Phase 8: Cryptographic Operations (2-3 weeks)
2. Phase 9: Database Integration (2-3 weeks)
3. Phase 12: Service Integration (1-2 weeks)
4. Phase 14: Testing & Hardening (2-3 weeks)

**Total Critical Path**: **7-11 weeks**

### Parallel Work

- **Phase 10** (PKCS#11) can run in parallel with Phases 8-9 (3-4 weeks)
- **Phase 11** (Protocol Validation) can run in parallel with Phases 8-9 (2 weeks)
- **Phase 13** (Advanced Features) runs after Phases 8-12 (2-3 weeks)

### Realistic Timeline

**Aggressive Schedule**: 11-14 weeks (all hands on deck)
**Realistic Schedule**: 14-18 weeks (accounting for unknowns)
**Conservative Schedule**: 18-24 weeks (includes buffer for security audit)

### Recommended Approach

**Sprint 1-3** (Weeks 1-6): Phases 8 + 11 (parallel)
- Focus: Get crypto working, validate protocols
- Deliverable: Certificates sign correctly, ACME/EST validate inputs

**Sprint 4-6** (Weeks 7-12): Phases 9 + 10 (parallel)
- Focus: Persist state, integrate HSM
- Deliverable: Services survive restarts, HSM signing works

**Sprint 7-8** (Weeks 13-16): Phase 12
- Focus: Wire services together
- Deliverable: End-to-end ACME order produces CA-issued cert

**Sprint 9-11** (Weeks 17-22): Phase 14
- Focus: Test everything, prepare for production
- Deliverable: Security audit passed, documentation complete

**Sprint 12** (Weeks 23-24): Phase 13 (if time permits)
- Focus: Polish, performance optimization
- Deliverable: OCSP caching, EST server-side keygen

---

## Success Criteria

### Phase 8: Core Cryptographic Operations
- ✅ All certificates properly DER-encoded
- ✅ Certificates parseable by OpenSSL: `openssl x509 -in cert.pem -text -noout`
- ✅ All signatures verify: `openssl verify -CAfile ca.pem cert.pem`
- ✅ CRLs properly encoded and verifiable
- ✅ OCSP requests/responses parse correctly
- ✅ PKCS#7 structures readable by EST clients
- ✅ Zero panics on malformed input
- ✅ All signing algorithms implemented (RSA, ECDSA, EdDSA, ML-DSA)

### Phase 9: Database Integration & Persistence
- ✅ All services persist state to PostgreSQL
- ✅ Services survive restarts without data loss
- ✅ ACME order state tracked through full lifecycle
- ✅ SCMS token inventory queryable with filters
- ✅ Database migrations apply cleanly on fresh database
- ✅ Foreign key constraints prevent orphaned records
- ✅ Concurrent requests handled safely with transactions
- ✅ Query performance <100ms for common operations

### Phase 10: PKCS#11 HSM Integration
- ✅ Can generate RSA, ECDSA, EdDSA keys on HSM
- ✅ Signing operations produce valid signatures verifiable by OpenSSL
- ✅ Key wrapping/unwrapping preserves key material
- ✅ Software provider passes same test suite as PKCS#11 provider
- ✅ SCMS can initialize smartcards via PKCS#11
- ✅ PIN verification and change operations work
- ✅ Zero memory leaks (valgrind clean)
- ✅ Performance: <50ms signing, <500ms key generation

### Phase 11: Protocol Validation & Security
- ✅ ACME rejects all requests with invalid JWS signatures (401 Unauthorized)
- ✅ Nonce reuse detected and rejected
- ✅ HTTP-01, DNS-01, TLS-ALPN-01 challenges validate correctly against live domains
- ✅ Invalid CSRs rejected (bad signature, mismatched SANs)
- ✅ EST enforces mTLS and rejects unauthenticated requests
- ✅ Zero false positives in validation (legitimate requests accepted)
- ✅ Zero false negatives (invalid requests rejected)
- ✅ Performance: <200ms JWS validation, <5s challenge validation

### Phase 12: Service Integration
- ✅ ACME finalize-order results in CA-issued certificate
- ✅ Certificate appears in CA database
- ✅ EST enrollment returns valid CA-signed certificate
- ✅ SCMS personalization writes certificate to smartcard
- ✅ KRA automatically escrows keys for designated profiles
- ✅ SCMS revocation triggers CA revocation (certificate in CRL)
- ✅ All inter-service gRPC calls use mTLS
- ✅ Error handling prevents partial state (transactions committed or rolled back)

### Phase 13: Advanced Features
- ✅ OCSP responses served from cache (>90% hit rate for popular certs)
- ✅ Cache invalidates on revocation
- ✅ EST server-side key generation works for test clients
- ✅ Private key encrypted for client, never stored unencrypted
- ✅ PQC OIDs updated to match NIST final standards
- ✅ Audit hash chain verification detects tampering
- ✅ Software crypto provider passes all tests

### Phase 14: Testing & Hardening
- ✅ Full ACME workflow test passes: account → order → challenge → finalize → certificate
- ✅ EST enrollment test passes: mTLS → CSR → certificate
- ✅ SCMS lifecycle test passes: create → initialize → personalize → revoke
- ✅ KRA recovery test passes: escrow → request → recover
- ✅ Security audit finds no critical/high vulnerabilities
- ✅ Load testing: 100 ACME orders/sec, 1000 OCSP requests/sec
- ✅ Zero panics in 24-hour stress test
- ✅ Code coverage >80%
- ✅ Documentation complete (API docs, deployment guide, runbooks)
- ✅ CI/CD pipeline operational (tests run on every commit)

---

## Risk Assessment

### High Risks

1. **Cryptographic Implementation Complexity**
   - **Risk**: DER encoding bugs could produce invalid certificates
   - **Mitigation**: Extensive testing with OpenSSL, third-party parsers
   - **Contingency**: Use established libraries (x509-cert crate) instead of custom encoding

2. **HSM Integration Challenges**
   - **Risk**: PKCS#11 driver bugs, hardware availability, performance issues
   - **Mitigation**: Test with SoftHSM first, abstract crypto provider interface
   - **Contingency**: Proceed with software crypto, defer HSM to post-launch

3. **Database Performance at Scale**
   - **Risk**: Query slowness with large certificate databases (>1M certs)
   - **Mitigation**: Index optimization, query profiling, caching
   - **Contingency**: Implement sharding or read replicas

### Medium Risks

1. **Service Integration Complexity**
   - **Risk**: mTLS configuration, network issues, error handling across services
   - **Mitigation**: Comprehensive integration tests, circuit breakers
   - **Contingency**: Monolithic deployment option (all services in one process)

2. **ACME Challenge Validation**
   - **Risk**: DNS/HTTP issues, timeouts, false negatives
   - **Mitigation**: Retry logic, multiple validation perspectives, extensive logging
   - **Contingency**: Support only HTTP-01 initially, defer DNS-01/TLS-ALPN-01

3. **Security Audit Findings**
   - **Risk**: Audit discovers critical vulnerabilities requiring rework
   - **Mitigation**: Internal security review before external audit, follow best practices
   - **Contingency**: Budget 2-4 weeks for remediation

### Low Risks

1. **Post-Quantum Cryptography Changes**
   - **Risk**: NIST changes OIDs or algorithms
   - **Mitigation**: Monitor NIST announcements, abstract OID definitions
   - **Contingency**: Quick update when standards finalize

2. **Documentation Completeness**
   - **Risk**: Missing or outdated documentation
   - **Mitigation**: Write docs alongside code, review in Phase 14
   - **Contingency**: Allocate extra sprint for documentation if needed

---

## Conclusion

OstrichPKI has successfully completed foundational work (Phases 1-7), establishing a solid architecture and comprehensive API surface. The remaining work (Phases 8-14) focuses on **implementation depth** rather than **breadth**, with emphasis on:

1. **Cryptographic correctness** (Phase 8)
2. **State persistence** (Phase 9)
3. **Production-grade security** (Phases 10, 11)
4. **Service orchestration** (Phase 12)
5. **Operational readiness** (Phase 14)

**Estimated timeline to production**: **14-20 weeks**

**Critical path**: Phases 8 → 9 → 12 → 14 (7-11 weeks minimum)

**Recommended next steps**:
1. Begin Phase 8 (Cryptographic Operations) immediately - highest priority blocker
2. Start Phase 11 (Protocol Validation) in parallel - can run independently
3. Secure HSM hardware or set up SoftHSM for Phase 10 testing
4. Schedule external security audit for Week 20-22
5. Allocate resources for comprehensive testing in Phase 14

With focused effort on the critical path and parallel execution of independent phases, OstrichPKI can achieve production readiness in approximately **4-5 months**.
