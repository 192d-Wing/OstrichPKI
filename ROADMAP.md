# OstrichPKI Development Roadmap

> **Last Updated**: January 2026 | **Current Version**: v0.10.0 | **Status**: Active Development

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Quick Status Dashboard](#quick-status-dashboard)
- [Completed Milestones](#completed-milestones)
- [Remaining Phases](#remaining-phases)
  - [Phase 8: Core Cryptographic Operations](#phase-8-core-cryptographic-operations)
  - [Phase 10: PKCS#11 HSM Integration](#phase-10-pkcs11-hsm-integration)
  - [Phase 11: Protocol Validation & Security](#phase-11-protocol-validation--security)
  - [Phase 12: Service Integration](#phase-12-service-integration)
  - [Phase 13: Advanced Features](#phase-13-advanced-features)
  - [Phase 14: Testing & Hardening](#phase-14-testing--hardening)
  - [Phase 15: NIAP Compliance](#phase-15-niap-compliance)
- [Priority Matrix](#priority-matrix)
- [Timeline & Schedule](#timeline--schedule)
- [Risk Assessment](#risk-assessment)
- [Success Metrics](#success-metrics)

---

## Executive Summary

**OstrichPKI** is a comprehensive Public Key Infrastructure system written in Rust, designed for **ATO (Authority to Operate) readiness** with full **NIST 800-53 Rev 5** and **NIAP PP-CA v2.1** compliance.

### Current State (v0.10.0)

| Metric | Status |
|--------|--------|
| **Codebase** | ~11,400 lines of Rust across 15 crates |
| **Services** | 7 microservices (CA, OCSP, KRA, ACME, EST, SCMS, Audit) |
| **Standards** | RFC 5280, 6960, 7030, 8555 compliance |
| **Security** | NIST 800-53 controls (AU-2, AU-3, AU-9, SC-12, SC-13, IA-2, IA-5) |
| **Overall Progress** | **~55%** complete |

### Critical Gaps

| Category | Remaining Work | Priority |
|----------|----------------|----------|
| **Cryptographic Operations** | DER encoding, signing operations | 🔴 HIGH |
| **HSM Integration** | PKCS#11 hardware security module | 🟡 MEDIUM |
| **Protocol Validation** | ACME challenges, mTLS, CSR validation | 🔴 HIGH |
| **Service Integration** | Cross-service communication (gRPC) | 🟡 MEDIUM |
| **Testing & Hardening** | Integration tests, security audits | 🔴 HIGH |
| **NIAP Compliance** | Protection Profile documentation | 🔴 HIGH |

### Estimated Completion

- **Aggressive**: 11 weeks (all parallel work)
- **Realistic**: 14-16 weeks (mixed parallel/sequential)
- **Conservative**: 20-24 weeks (with buffer for unknowns)

**Recommended**: 12 sprints (2-week iterations) = **24 weeks** for production-ready system

---

## Quick Status Dashboard

### Phase Completion Overview

```
✅ COMPLETE  🟡 IN PROGRESS  ⏳ PLANNED  ⏸️ DEFERRED
```

| Phase | Name | Status | Completion | Priority | Effort |
|-------|------|--------|------------|----------|--------|
| 1-7 | Foundation | ✅ COMPLETE | 100% | - | - |
| **8** | **Crypto Operations** | **🟡 IN PROGRESS** | **85%** | 🔴 HIGH | 1 week |
| **9** | **Database Integration** | **✅ COMPLETE** | **100%** | - | ✅ 2 weeks |
| **10** | **PKCS#11 HSM** | ⏳ PLANNED | 0% | 🟡 MEDIUM | 3-4 weeks |
| **11** | **Protocol Validation** | 🟡 IN PROGRESS | 75% | 🔴 HIGH | 1 week |
| **12** | **Service Integration** | ⏳ PLANNED | 0% | 🟡 MEDIUM | 1-2 weeks |
| **13** | **Advanced Features** | ⏸️ DEFERRED | 0% | ⚪ LOW | 2-3 weeks |
| **14** | **Testing & Hardening** | ⏳ PLANNED | 10% | 🔴 HIGH | 2-3 weeks |
| **15** | **NIAP Compliance** | ⏳ PLANNED | 45% | 🔴 HIGH | 3-4 weeks |

### Critical Path

```
Phase 8 (Crypto) → Phase 9 (DB) ✅ → Phase 11 (Validation) → Phase 12 (Integration) → Phase 14 (Testing)
                                ↓
                          Phase 10 (HSM) → Phase 12 → Phase 14
                                         ↓
                                   Phase 15 (NIAP) → Production
```

---

## Completed Milestones

### Phases 1-7: Foundation & Core Services ✅

**Scope**: Architecture, common libraries, and all microservice scaffolding

**Achievements**:

- ✅ **Phase 1**: Common libraries (crypto abstractions, OID registry, error handling)
- ✅ **Phase 2**: CA service (X.509 certificate issuance, gRPC API, CLI)
- ✅ **Phase 3**: OCSP responder (RFC 6960 compliance)
- ✅ **Phase 4**: KRA service (Shamir secret sharing for key recovery)
- ✅ **Phase 5**: ACME service (RFC 8555 automated certificate management)
- ✅ **Phase 6**: EST service (RFC 7030 enrollment over secure transport)
- ✅ **Phase 7**: SCMS service (smartcard/token lifecycle management)

### Phase 9: Database Integration & Persistence ✅ (v0.10.0)

**Completion**: December 2025 | **Effort**: 2 weeks

**Achievements**:

- ✅ Repository pattern for all services (1,487 lines of type-safe SQL)
- ✅ **ACME**: 28 database methods (account, order, authorization, challenge, nonce management)
- ✅ **SCMS**: 45 methods (token lifecycle, PIN operations, key management, event audit)
- ✅ **EST**: 17 methods (enrollment tracking, client certificate validation)
- ✅ **KRA**: 8 methods (escrowed key storage, recovery workflows)
- ✅ All 32 REST endpoints integrated with database persistence
- ✅ State machine enforcement (ACME order lifecycle, SCMS token states)

**Database Schema**: Complete migrations for PostgreSQL with proper indexes, foreign keys, and JSONB support

**Deferred to Future Phases**:

- Phase 8: Certificate signing, CSR validation, PKCS#7 encoding
- Phase 10: PKCS#11 operations for real HSM integration
- Phase 11: JWS validation, mTLS client authentication, ACME challenge validation
- Phase 12: Service-to-service integration (CA ↔ ACME/EST/SCMS/KRA)

---

## Remaining Phases

### Phase 8: Core Cryptographic Operations

**Status**: 🟡 IN PROGRESS (85% complete) | **Priority**: 🔴 HIGH | **Effort**: 1 week
**Dependencies**: None | **Blocks**: All other phases

#### Overview

Implement all cryptographic operations required for certificate lifecycle management: DER/ASN.1 encoding, signing, and PKCS#7 packaging.

#### Progress Summary

| Component | Status | Remaining Work |
|-----------|--------|----------------|
| X.509 DER encoding | ✅ COMPLETE | - |
| CRL DER encoding | ✅ COMPLETE | - |
| Certificate signing | ✅ COMPLETE | - |
| CRL signing | ✅ COMPLETE | - |
| OCSP ASN.1 operations | ✅ COMPLETE | - |
| PKCS#7 encoding (EST) | ✅ COMPLETE | - |
| PEM parsing | ⏸️ NOT NEEDED | Using `pem-rfc7468` crate |
| **Integration testing** | ⏳ TODO | Verify with OpenSSL compatibility |

#### Completed Work (v0.7.0-v0.9.0)

✅ **DER Encoding Implementation**:

- X.509 TBSCertificate structure with all extensions (SAN, key usage, policies)
- CRL TBSCertList with revocation entries, reasons, and CRL extensions
- Uses `der` crate for ASN.1 encoding/decoding

✅ **Signing Operations**:

- RSA-PSS (2048, 3072, 4096 bit)
- ECDSA (P-256, P-384, P-521)
- EdDSA (Ed25519, Ed448)
- ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87) - Post-Quantum
- Integrated with `CryptoProvider` trait for HSM/software fallback

✅ **OCSP Implementation**:

- ASN.1 request parsing and response encoding
- Response signing with nonce support
- RFC 6960 compliance

✅ **PKCS#7 Packaging**:

- CA certificate chain encoding for EST `/cacerts`
- Enrollment response wrapping for EST `/simpleenroll`
- Re-enrollment response for EST `/simplereenroll`

#### Remaining Tasks

1. ✅ ~~Complete integration testing with OpenSSL~~ → **Move to Phase 14**
2. ⏳ Verify interoperability with external clients (certbot, EST clients)
3. ⏳ Performance benchmarking for signing operations

#### Success Criteria

- [x] All certificates DER-encoded and parseable by `openssl x509 -text`
- [x] CRLs properly encoded and verifiable by `openssl crl -text`
- [x] Signatures verify with correct public keys
- [x] OCSP requests/responses parse correctly
- [x] PKCS#7 structures readable by EST clients
- [ ] Zero panics on malformed input (fuzzing in Phase 14)

#### Technical Implementation

**Key Libraries**:

- `der` - ASN.1 DER encoding/decoding
- `x509-cert` - X.509 structures
- `pem-rfc7468` - PEM parsing
- `cms` - PKCS#7/CMS message syntax

**Files Modified**:

- `crates/ostrich-x509/src/builder/certificate.rs` - Certificate DER encoding
- `crates/ostrich-x509/src/builder/crl.rs` - CRL DER encoding
- `crates/ostrich-ca/src/issuance.rs` - Certificate signing
- `crates/ostrich-ca/src/revocation.rs` - CRL signing
- `crates/ostrich-ocsp/src/request.rs` - OCSP request parsing
- `crates/ostrich-ocsp/src/response.rs` - OCSP response encoding
- `crates/ostrich-ocsp/src/responder.rs` - OCSP signing
- `crates/ostrich-est/src/rest.rs` - PKCS#7 encoding

---

### Phase 10: PKCS#11 HSM Integration

**Status**: ⏳ PLANNED (0% complete) | **Priority**: 🟡 MEDIUM | **Effort**: 3-4 weeks
**Dependencies**: Phase 8 | **Blocks**: Production deployment

#### Overview

Implement production-ready Hardware Security Module (HSM) integration via PKCS#11 interface with software fallback for development/testing.

#### Scope

**35 TODO items** across 3 areas:

1. **Core PKCS#11 Provider** (20 TODOs in `ostrich-crypto/src/pkcs11/mod.rs`)
2. **Software Crypto Fallback** (10 TODOs in `ostrich-crypto/src/software/mod.rs`)
3. **SCMS Token Operations** (5 TODOs in `ostrich-scms/src/rest.rs`)

#### Key Work Items

##### 1. Core PKCS#11 Provider Implementation

**File**: `crates/ostrich-crypto/src/pkcs11/mod.rs`

- [ ] Initialize PKCS#11 library (`C_Initialize`, `C_GetSlotList`)
- [ ] Session management (`C_OpenSession`, `C_Login`, `C_Logout`)
- [ ] Key generation on HSM (`C_GenerateKeyPair` for RSA, ECDSA, EdDSA, ML-DSA)
- [ ] Signing operations (`C_SignInit`, `C_Sign` with mechanism mapping)
- [ ] Key wrapping/unwrapping (`C_WrapKey`, `C_UnwrapKey` for key escrow)
- [ ] Key listing (`C_FindObjects`) and destruction (`C_DestroyObject`)
- [ ] Session cleanup and error handling

##### 2. Software Crypto Fallback

**File**: `crates/ostrich-crypto/src/software/mod.rs`

- [ ] Key generation using `ring` and `ml-dsa` crates
- [ ] In-memory signing operations (RSA-PSS, ECDSA, EdDSA, ML-DSA)
- [ ] AES-GCM key wrapping for escrow
- [ ] Zeroize sensitive key material on drop
- [ ] Feature flag: `--features software-crypto`

##### 3. SCMS Token Operations

**File**: `crates/ostrich-scms/src/rest.rs`

- [ ] Initialize smartcard token via PKCS#11
- [ ] Set PIN and generate initial keys on token
- [ ] PIN verification with retry counter
- [ ] PIN change operations
- [ ] Generate/list/delete keys on token
- [ ] Query token capabilities

#### Technical Approach

**CryptoProvider Trait** (abstraction for HSM/software):

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn generate_keypair(&self, algorithm: SignatureAlgorithm) -> Result<KeyPair>;
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
    async fn wrap_key(&self, key_id: &str, wrapping_key_id: &str) -> Result<Vec<u8>>;
    async fn unwrap_key(&self, wrapped_key: &[u8], unwrapping_key_id: &str) -> Result<String>;
    async fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    async fn delete_key(&self, key_id: &str) -> Result<()>;
}
```

**HSM Configuration** (environment variables):

```bash
PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so  # SoftHSM for testing
PKCS11_SLOT_ID=0
PKCS11_PIN=1234
CRYPTO_PROVIDER=hsm  # or "software" for fallback
```

**Testing with SoftHSM**:

```bash
# Initialize SoftHSM token
softhsm2-util --init-token --slot 0 --label "ostrich-ca" --pin 1234 --so-pin 5678

# Run CA with HSM
CRYPTO_PROVIDER=hsm PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so cargo run --bin ostrich-ca
```

#### Success Criteria

- [ ] CA keys generated and stored in HSM
- [ ] Certificate signing via HSM (<50ms per operation)
- [ ] Software fallback works without HSM
- [ ] Key escrow integrates with KRA service
- [ ] SCMS token operations functional
- [ ] Zero key material exposure in logs/memory dumps
- [ ] Graceful handling of HSM unavailability

#### Performance Targets

| Operation | Target | Acceptable |
|-----------|--------|------------|
| Key generation (RSA 2048) | <500ms | <1s |
| Key generation (ECDSA P-256) | <200ms | <500ms |
| Sign operation (any algorithm) | <50ms | <100ms |
| Session initialization | <100ms | <200ms |

#### Dependencies & Libraries

- `cryptoki` - Rust PKCS#11 bindings
- `ring` - Software crypto fallback
- `ml-dsa` - Post-quantum signatures (RustCrypto)
- `zeroize` - Secure memory wiping

---

### Phase 11: Protocol Validation & Security

**Status**: 🟡 IN PROGRESS (75% complete) | **Priority**: 🔴 HIGH | **Effort**: 1 week
**Dependencies**: Phase 8 | **Blocks**: Production security

#### Overview

Implement security-critical protocol validation: JWS signatures (ACME), challenge validation (HTTP-01, DNS-01, TLS-ALPN-01), mTLS client authentication (EST), and CSR validation.

#### Progress Summary

| Component | Status | Completion |
|-----------|--------|------------|
| JWS validation (ACME) | ✅ COMPLETE | 100% |
| Nonce management | ✅ COMPLETE | 100% |
| CSR parsing & validation | ✅ COMPLETE | 100% |
| HTTP-01 challenge | ✅ COMPLETE | 100% |
| DNS-01 challenge | ⏳ TODO | 0% |
| TLS-ALPN-01 challenge | ⏳ TODO | 0% |
| mTLS client auth (EST) | ⏳ TODO | 0% |

#### Completed Work (v0.11.0)

✅ **ACME JWS Validation**:

- JWS signature verification using `josekit` crate
- JWK extraction from protected header
- Account public key validation
- Integration with all ACME endpoints (account, order, authorization, challenge)
- **Files**: `crates/ostrich-acme/src/jws.rs`, `crates/ostrich-acme/src/rest.rs`

✅ **Nonce Management**:

- Cryptographically secure nonce generation (32 bytes, base64url)
- Database-backed nonce tracking with expiration (15 minutes)
- Replay protection (one-time use)
- Automatic cleanup of expired nonces
- **Files**: `crates/ostrich-acme/src/rest.rs:127-140`

✅ **CSR Parsing & Validation**:

- PKCS#10 CSR parsing using `x509-cert` crate
- Signature verification on CSR
- Public key extraction
- Subject DN and SAN validation
- **Files**: `crates/ostrich-est/src/rest.rs:89-90`, `crates/ostrich-acme/src/rest.rs:362`

✅ **HTTP-01 Challenge Validation**:

- HTTP GET to `http://<domain>/.well-known/acme-challenge/<token>`
- Key authorization verification (`<token>.<account_key_thumbprint>`)
- Timeout handling (10 seconds)
- **Files**: `crates/ostrich-acme/src/challenges.rs`

#### Remaining Work

##### 1. DNS-01 Challenge Validation

**File**: `crates/ostrich-acme/src/challenges.rs`

- [ ] DNS TXT record lookup for `_acme-challenge.<domain>`
- [ ] Verify record contains key authorization hash (SHA-256, base64url)
- [ ] Support multiple authoritative nameservers
- [ ] Retry logic for DNS propagation delays (5 retries, 2s interval)

**Implementation**:

```rust
use trust_dns_resolver::TokioAsyncResolver;

async fn validate_dns_01(domain: &str, token: &str, key_auth: &str) -> Result<bool> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let expected = base64url(sha256(key_auth));
    let name = format!("_acme-challenge.{}", domain);

    let txt_records = resolver.txt_lookup(&name).await?;
    for record in txt_records.iter() {
        if record.to_string() == expected {
            return Ok(true);
        }
    }
    Ok(false)
}
```

##### 2. TLS-ALPN-01 Challenge Validation

**File**: `crates/ostrich-acme/src/challenges.rs`

- [ ] TLS connection to `<domain>:443` with ALPN protocol `acme-tls/1`
- [ ] Extract certificate presented during handshake
- [ ] Verify certificate contains:
  - Subject: `<domain>`
  - Extension: `id-pe-acmeIdentifier` with key authorization hash
- [ ] Self-signed certificate validation (for challenge only)

**Implementation**:

```rust
use tokio_rustls::TlsConnector;

async fn validate_tls_alpn_01(domain: &str, key_auth: &str) -> Result<bool> {
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_alpn_protocols(vec![b"acme-tls/1".to_vec()])
        .with_custom_certificate_verifier(/* allow self-signed */);

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((domain, 443)).await?;
    let tls_stream = connector.connect(domain, stream).await?;

    // Extract peer certificate and verify id-pe-acmeIdentifier extension
    // ...
}
```

##### 3. mTLS Client Authentication (EST)

**File**: `crates/ostrich-est/src/rest.rs`

- [ ] Configure TLS server to request client certificates
- [ ] Extract client certificate from TLS connection
- [ ] Validate certificate chain against trusted CA
- [ ] Check certificate is not revoked (OCSP/CRL)
- [ ] Authorize enrollment based on client DN/SAN
- [ ] Integration with axum server TLS configuration

**Implementation**:

```rust
use axum_server::tls_rustls::RustlsConfig;

let tls_config = RustlsConfig::from_pem_file(
    "certs/server.pem",
    "certs/server-key.pem",
)
.await?
.with_client_auth_required(/* CA cert pool */);

// Extract client cert in handler
async fn enroll(
    Extension(client_cert): Extension<Certificate>,
    body: Bytes,
) -> Result<Response> {
    // Validate client_cert...
}
```

#### Integration Points

| Validation | Service | Endpoint | Phase 12 Dependency |
|------------|---------|----------|---------------------|
| JWS | ACME | All endpoints | None |
| HTTP-01 | ACME | POST `/acme/challenge/{id}` | None |
| DNS-01 | ACME | POST `/acme/challenge/{id}` | External DNS resolver |
| TLS-ALPN-01 | ACME | POST `/acme/challenge/{id}` | External TLS server |
| mTLS | EST | `/simpleenroll`, `/simplereenroll` | CA certificate validation |

#### Success Criteria

- [ ] All ACME JWS signatures validated ✅
- [ ] HTTP-01 challenges functional ✅
- [ ] DNS-01 challenges functional
- [ ] TLS-ALPN-01 challenges functional
- [ ] EST mTLS client authentication working
- [ ] CSR signature validation enforced ✅
- [ ] Zero security bypasses or weak validation
- [ ] Comprehensive error handling for network failures

#### Security Considerations

**CRITICAL**: All validation must fail securely:

- Invalid signature → Reject request, log security event
- Challenge validation timeout → Mark challenge as "invalid"
- mTLS failure → HTTP 403 Forbidden, do not fallback to HTTP auth
- CSR signature invalid → Reject enrollment, audit log

#### Dependencies & Libraries

- `josekit` - JWS/JWT validation ✅
- `reqwest` - HTTP client for HTTP-01 ✅
- `trust-dns-resolver` - DNS lookups for DNS-01
- `tokio-rustls` - TLS client for TLS-ALPN-01
- `axum-server` - TLS server configuration for mTLS

---

### Phase 12: Service Integration

**Status**: ⏳ PLANNED (0% complete) | **Priority**: 🟡 MEDIUM | **Effort**: 1-2 weeks
**Dependencies**: Phases 8, 11 | **Blocks**: End-to-end workflows

#### Overview

Connect microservices to enable complete certificate lifecycle workflows: ACME→CA certificate issuance, EST→CA enrollment, CA→KRA key escrow, and SCMS→CA token certificate management.

#### Scope

**21 TODO items** across 4 integration patterns:

1. **ACME → CA**: Certificate issuance after challenge validation
2. **EST → CA**: Enrollment and re-enrollment
3. **CA → KRA**: Key escrow during certificate issuance
4. **SCMS → CA**: Token certificate issuance and revocation

#### Key Work Items

##### 1. ACME → CA Integration

**File**: `crates/ostrich-acme/src/rest.rs:362`

- [ ] Call CA gRPC `IssueCertificate` RPC after order finalization
- [ ] Pass validated CSR from ACME order to CA
- [ ] Apply certificate profile based on ACME order type
- [ ] Store issued certificate serial in ACME order
- [ ] Handle CA errors (invalid CSR, policy violations)

**Workflow**:

```
Client → ACME: Finalize order (POST /acme/order/{id}/finalize)
  ↓
ACME: Validate all challenges complete
  ↓
ACME → CA: gRPC IssueCertificate(csr, profile="acme-domain-validation")
  ↓
CA: Issue certificate
  ↓
CA → ACME: Return signed certificate
  ↓
ACME: Store certificate, update order status="valid"
  ↓
ACME → Client: Return order with certificate URL
```

##### 2. EST → CA Integration

**Files**: `crates/ostrich-est/src/rest.rs:84, 122`

**Simple Enroll** (`/simpleenroll`):

- [ ] Extract CSR from PKCS#10 request body
- [ ] Call CA gRPC `IssueCertificate` with profile="est-enrollment"
- [ ] Wrap issued certificate in PKCS#7 response
- [ ] Return `application/pkcs7-mime` response

**Simple Re-enroll** (`/simplereenroll`):

- [ ] Validate client certificate from mTLS (Phase 11)
- [ ] Extract CSR from request
- [ ] Call CA gRPC `IssueCertificate` with profile="est-reenrollment"
- [ ] Optionally revoke old certificate
- [ ] Return new certificate in PKCS#7

##### 3. CA → KRA Integration

**File**: `crates/ostrich-ca/src/issuance.rs` (implicit)

- [ ] Check certificate profile: escrow_private_key=true
- [ ] After key generation (if CA generates key), call KRA gRPC `EscrowKey`
- [ ] Encrypt private key with KRA public key
- [ ] Store escrow receipt in certificate record
- [ ] Handle KRA unavailability gracefully (queue for retry)

**Note**: Most certificates use CSR (client-generated keys), so escrow only applies to:

- EST server-side key generation (optional, Phase 13)
- SCMS token certificates (if CA generates keys)

##### 4. SCMS → CA Integration

**Files**: `crates/ostrich-scms/src/rest.rs:180, 209`

**Token Personalization** (generate certificates on token):

- [ ] After token personalization, call CA gRPC `IssueCertificate`
- [ ] Generate CSR from token public key (via PKCS#11)
- [ ] Apply profile="scms-token-authentication"
- [ ] Store issued certificate serial in token record

**Token Revocation** (revoke all certificates):

- [ ] On token revocation, list all certificate serials for token
- [ ] Call CA gRPC `RevokeCertificate` for each serial
- [ ] Reason: `keyCompromise` (token lost/stolen)
- [ ] Audit log all revocations

#### gRPC Service Communication

**Protocol**: gRPC with mutual TLS (mTLS) for inter-service authentication

**CA Service gRPC API** (to be implemented):

```protobuf
service CertificateAuthority {
  rpc IssueCertificate(IssueCertificateRequest) returns (IssueCertificateResponse);
  rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);
  rpc GetCertificate(GetCertificateRequest) returns (GetCertificateResponse);
}

message IssueCertificateRequest {
  bytes csr = 1;  // PKCS#10 DER
  string profile = 2;  // "acme-dv", "est-enrollment", "scms-token"
  map<string, string> metadata = 3;
}

message IssueCertificateResponse {
  bytes certificate = 1;  // X.509 DER
  string serial = 2;
}
```

**gRPC Client Setup Example** (ACME → CA):

```rust
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

let ca_cert = tokio::fs::read("certs/ca.pem").await?;
let client_cert = tokio::fs::read("certs/acme-client.pem").await?;
let client_key = tokio::fs::read("certs/acme-client-key.pem").await?;

let tls_config = ClientTlsConfig::new()
    .ca_certificate(Certificate::from_pem(&ca_cert))
    .identity(Identity::from_pem(&client_cert, &client_key));

let channel = Channel::from_static("https://ca.ostrichpki.internal:50051")
    .tls_config(tls_config)?
    .connect()
    .await?;

let mut client = CertificateAuthorityClient::new(channel);

let response = client.issue_certificate(IssueCertificateRequest {
    csr: csr_der,
    profile: "acme-domain-validation".to_string(),
    metadata: HashMap::new(),
}).await?;
```

#### Configuration

**Environment Variables** (per service):

```bash
# ACME service
CA_GRPC_ENDPOINT=https://ca.ostrichpki.internal:50051
CA_CLIENT_CERT=/etc/ostrich/certs/acme-client.pem
CA_CLIENT_KEY=/etc/ostrich/certs/acme-client-key.pem
CA_CA_CERT=/etc/ostrich/certs/ca.pem

# EST service
CA_GRPC_ENDPOINT=https://ca.ostrichpki.internal:50051
# ... (similar TLS config)

# SCMS service
CA_GRPC_ENDPOINT=https://ca.ostrichpki.internal:50051
# ...
```

#### Error Handling

**Retry Strategy**:

- Transient errors (network, unavailable): Retry with exponential backoff (3 attempts, 1s/2s/4s)
- Validation errors (invalid CSR, policy violation): Do NOT retry, return error to client
- Timeout: 30 seconds per RPC call

**Circuit Breaker**:

- Open circuit after 5 consecutive CA failures
- Half-open after 60 seconds (allow 1 test request)
- Close circuit after 3 successful requests

**Graceful Degradation**:

- ACME: Queue finalized orders for later processing if CA unavailable
- EST: Return HTTP 503 Service Unavailable
- SCMS: Allow token operations but defer certificate issuance

#### Success Criteria

- [ ] ACME can issue certificates end-to-end (account → order → challenge → certificate)
- [ ] EST enrollment produces valid certificates
- [ ] SCMS token personalization issues certificates
- [ ] CA→KRA escrow functional (when enabled)
- [ ] All gRPC calls use mTLS authentication
- [ ] Circuit breaker prevents cascading failures
- [ ] Comprehensive audit logging for all cross-service calls

#### Testing Strategy

**Integration Tests**:

1. ACME E2E: Create account → new order → HTTP-01 challenge → finalize → download cert
2. EST E2E: mTLS authentication → simple enroll → verify certificate
3. SCMS E2E: Create token → personalize → verify certificate issued
4. Failure scenarios: CA unavailable, invalid CSR, network timeout

---

### Phase 13: Advanced Features

**Status**: ⏸️ DEFERRED (0% complete) | **Priority**: ⚪ LOW | **Effort**: 2-3 weeks
**Dependencies**: Phases 12, 14 | **Blocks**: None

#### Overview

Optional enhancements that improve performance, functionality, and compliance but are not required for initial production deployment. **Can be deferred post-launch**.

#### Scope

**8 TODO items** across 4 areas (all optional):

1. **OCSP Response Caching** (3 TODOs)
2. **EST Server-Side Key Generation** (1 TODO)
3. **Post-Quantum OID Updates** (3 TODOs)
4. **Audit Hash Chain Verification** (1 TODO)

#### Work Items

##### 1. OCSP Response Caching

**Files**: `crates/ostrich-ocsp/src/responder.rs:47-49`

**Benefit**: Reduce database load, improve response latency for high-traffic OCSP queries

- [ ] Implement in-memory LRU cache (10,000 entries)
- [ ] Cache key: `(serial_number, hash_algorithm)`
- [ ] Cache TTL: `nextUpdate - now` (from OCSP response)
- [ ] Invalidate cache on certificate revocation
- [ ] Optional: Redis-backed cache for multi-instance deployments

**Implementation**:

```rust
use lru::LruCache;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct OcspCache {
    cache: Arc<RwLock<LruCache<String, (OcspResponse, Instant)>>>,
}

impl OcspCache {
    async fn get(&self, serial: &str) -> Option<OcspResponse> {
        let cache = self.cache.read().await;
        cache.get(serial).and_then(|(resp, expiry)| {
            if Instant::now() < *expiry {
                Some(resp.clone())
            } else {
                None
            }
        })
    }
}
```

**Performance Target**: <5ms response time (99th percentile) for cached responses

##### 2. EST Server-Side Key Generation

**File**: `crates/ostrich-est/src/rest.rs:168-173`

**Benefit**: Support legacy devices that cannot generate their own keys

- [ ] Implement `/serverkeygen` endpoint (RFC 7030 §4.4)
- [ ] Generate key pair on server (RSA 2048 or ECDSA P-256)
- [ ] Issue certificate with generated public key
- [ ] Encrypt private key with client transport key
- [ ] Return PKCS#12 bundle (certificate + encrypted private key)
- [ ] **CRITICAL**: Zeroize private key from memory after encryption
- [ ] Optionally escrow private key via KRA

**Security Note**: Discouraged in high-security environments (key material generated on server). Only enable if explicitly required.

##### 3. Post-Quantum OID Updates

**File**: `crates/ostrich-common/src/oid.rs:74, 80, 86`

**Benefit**: Ensure compliance when NIST finalizes PQC OIDs

- [ ] Update ML-DSA OID when NIST publishes final FIPS 204 assignments
- [ ] Update ML-KEM OID when NIST publishes final FIPS 203 assignments
- [ ] Update SLH-DSA OID when NIST publishes final FIPS 205 assignments
- [ ] Add unit tests to verify OID correctness against NIST specifications

**Current Status**: Using draft OIDs from `draft-ietf-lamps-dilithium-certificates` and `draft-ietf-lamps-kyber-certificates`

**Action**: Monitor NIST publications and update when finalized (expected Q2 2026)

##### 4. Audit Hash Chain Verification

**File**: `crates/ostrich-db/src/repository/audit.rs:132`

**Benefit**: Tamper-evident audit logs (NIST 800-53 AU-9 enhancement)

- [ ] Compute hash chain: `H(event_n) = SHA-256(event_n || H(event_{n-1}))`
- [ ] Store hash in `audit_events.hash_chain` column
- [ ] Verify chain integrity on log retrieval
- [ ] Detect tampering or missing events
- [ ] Optional: Periodically sign chain head with CA key

**Implementation**:

```rust
pub async fn verify_hash_chain(&self) -> Result<bool> {
    let events = self.query_all_events().await?;
    let mut prev_hash = vec![0u8; 32];  // Genesis hash

    for event in events {
        let computed = sha256(&[&event.serialize(), &prev_hash].concat());
        if computed != event.hash_chain {
            return Ok(false);  // Tampering detected
        }
        prev_hash = computed;
    }
    Ok(true)
}
```

#### Prioritization Rationale

These features are **LOW priority** because:

- OCSP caching: Performance optimization, not functional requirement
- EST server-side keygen: Niche use case, security concerns
- PQC OID updates: Dependent on external NIST timeline
- Audit hash chain: Enhancement beyond baseline AU-9 compliance

**Recommendation**: Defer to post-v1.0 release unless specific customer requirement emerges.

---

### Phase 14: Testing & Hardening

**Status**: ⏳ PLANNED (10% complete) | **Priority**: 🔴 HIGH | **Effort**: 2-3 weeks
**Dependencies**: Phases 8, 11, 12 | **Blocks**: Production deployment

#### Overview

Comprehensive testing, security hardening, and operational readiness before production deployment.

#### Current Status

- ✅ Unit tests for core libraries (~60% coverage)
- ⏳ Integration tests (incomplete)
- ⏳ Security testing (not started)
- ⏳ Performance testing (not started)
- ⏳ Documentation (partial)

#### Scope

**5 major testing categories**:

1. **Integration Testing** (end-to-end workflows)
2. **Security Testing** (penetration testing, fuzzing, SAST)
3. **Performance Testing** (load testing, benchmarking)
4. **Operational Readiness** (deployment, monitoring, disaster recovery)
5. **Documentation** (API docs, runbooks, compliance artifacts)

#### Key Work Items

##### 1. Integration Testing

**Goal**: >80% coverage of critical workflows

**ACME End-to-End Tests**:

- [ ] Account lifecycle: create → update → deactivate
- [ ] Certificate issuance: order → challenge (HTTP-01, DNS-01, TLS-ALPN-01) → finalize → download
- [ ] Error scenarios: invalid JWS, expired nonce, failed challenge validation
- [ ] Multi-domain certificates (SAN)
- [ ] Order expiration and cleanup

**EST End-to-End Tests**:

- [ ] Simple enroll: mTLS auth → submit CSR → receive certificate
- [ ] Simple re-enroll: authenticate with old cert → issue new cert
- [ ] CA certificates retrieval (`/cacerts`)
- [ ] CSR attributes query (`/csrattrs`)
- [ ] Error scenarios: invalid mTLS cert, malformed CSR

**SCMS End-to-End Tests**:

- [ ] Token lifecycle: create → initialize → personalize → suspend → resume → revoke
- [ ] PIN operations: verify → change → unblock
- [ ] Key management: generate → list → delete
- [ ] Certificate issuance integration with CA
- [ ] Event audit log queries

**KRA End-to-End Tests**:

- [ ] Key escrow: submit → split shares → distribute
- [ ] Key recovery: request → submit M-of-N shares → reconstruct key
- [ ] Agent authorization and audit

**CA Core Tests**:

- [ ] Certificate issuance with all supported algorithms (RSA, ECDSA, EdDSA, ML-DSA)
- [ ] CRL generation and updates
- [ ] Certificate revocation (all revocation reasons)
- [ ] Profile enforcement (key usage, extended key usage, validity periods)

**Test Framework**: `cargo test --test integration_*` with Docker Compose for multi-service orchestration

##### 2. Security Testing

**Static Application Security Testing (SAST)**:

- [ ] Run `cargo clippy -D warnings` (already enforced)
- [ ] Run `cargo audit` for dependency vulnerabilities
- [ ] Run `cargo-deny` for license compliance and security advisories
- [ ] SonarQube or Semgrep for code quality and security patterns

**Fuzzing**:

- [ ] Fuzz DER/ASN.1 parsers (certificate, CSR, OCSP, CRL)
- [ ] Fuzz JWS signature validation
- [ ] Fuzz HTTP request handlers (ACME, EST, SCMS)
- [ ] Use `cargo fuzz` with `libFuzzer`
- [ ] Target: 1 million iterations per fuzzer, zero crashes

**Penetration Testing**:

- [ ] ACME protocol: replay attacks, JWS bypass attempts, challenge manipulation
- [ ] EST protocol: mTLS bypass, CSR injection
- [ ] SQL injection (parameterized queries should prevent, verify)
- [ ] Timing attacks on PIN verification (SCMS)
- [ ] HSM key extraction attempts (via PKCS#11)

**Secrets Scanning**:

- [ ] Run `gitleaks` to detect hardcoded secrets in code/history
- [ ] Verify no private keys, passwords, tokens in repository

**Dependency Security**:

- [ ] Review all dependencies with `cargo tree`
- [ ] Ensure critical dependencies are actively maintained
- [ ] Pin dependency versions in `Cargo.lock`

##### 3. Performance Testing

**Load Testing Scenarios**:

| Scenario | Target TPS | Concurrent Users | Duration |
|----------|-----------|------------------|----------|
| OCSP queries | 1,000 TPS | 500 | 5 minutes |
| ACME account creation | 50 TPS | 100 | 2 minutes |
| Certificate issuance (CA) | 100 TPS | 200 | 5 minutes |
| EST enrollment | 50 TPS | 100 | 2 minutes |

**Benchmarking** (using `criterion` crate):

- [ ] Certificate DER encoding: <1ms per certificate
- [ ] Certificate signing (software): <10ms (RSA), <5ms (ECDSA)
- [ ] Certificate signing (HSM): <50ms
- [ ] OCSP response generation: <5ms (without caching)
- [ ] Database queries: <10ms (p99)

**Tools**:

- `wrk` or `k6` for HTTP load testing
- `ghz` for gRPC load testing
- `criterion` for microbenchmarks

##### 4. Operational Readiness

**Deployment**:

- [ ] Dockerfiles for all services
- [ ] Docker Compose for local development
- [ ] Kubernetes manifests (Deployment, Service, ConfigMap, Secret)
- [ ] Helm chart for production deployment
- [ ] Health check endpoints (`/health`, `/ready`)

**Monitoring**:

- [ ] Prometheus metrics export (`/metrics` endpoint)
- [ ] Grafana dashboards (service health, latency, throughput, error rates)
- [ ] Alerting rules (high error rate, service down, certificate expiration)
- [ ] Distributed tracing (OpenTelemetry + Jaeger)

**Logging**:

- [ ] Structured logging (JSON format) via `tracing` crate
- [ ] Log aggregation (ELK stack or Loki)
- [ ] Log levels configurable via environment variable
- [ ] Sensitive data redaction (passwords, private keys, PINs)

**Backup & Disaster Recovery**:

- [ ] PostgreSQL backup strategy (pg_dump, WAL archiving)
- [ ] HSM backup procedures (key export via KRA)
- [ ] Database restore testing (RTO < 4 hours, RPO < 15 minutes)
- [ ] Service failover testing (simulate node failure)

**Security Hardening**:

- [ ] Run services as non-root user
- [ ] Minimize container image size (distroless or Alpine)
- [ ] Network policies (Kubernetes NetworkPolicy)
- [ ] Secrets management (Vault, Kubernetes Secrets with encryption at rest)
- [ ] TLS 1.3 enforcement for all external communication

##### 5. Documentation

**API Documentation**:

- [ ] OpenAPI 3.0 specs for all REST APIs (ACME, EST, SCMS)
- [ ] gRPC service documentation (Protobuf comments)
- [ ] Postman collections for manual testing

**Operational Runbooks**:

- [ ] Installation guide (Docker, Kubernetes)
- [ ] Configuration reference (environment variables, config files)
- [ ] Certificate issuance guide (ACME, EST, CA CLI)
- [ ] Troubleshooting guide (common errors, log analysis)
- [ ] Certificate revocation procedure
- [ ] HSM key backup and recovery

**Compliance Documentation**:

- [ ] NIST 800-53 control implementation statements → `docs/compliance/NIST_800-53_MAPPING.md`
- [ ] NIAP PP-CA v2.1 SFR evidence → `docs/compliance/NIAP_COMPLIANCE.md`
- [ ] RFC compliance matrix → `docs/compliance/RFC_COMPLIANCE.md`
- [ ] Security assessment artifacts → `docs/compliance/ATO_EVIDENCE.md`

**Developer Documentation**:

- [ ] Architecture decision records (ADRs)
- [ ] Code contribution guidelines (CONTRIBUTING.md)
- [ ] Development environment setup
- [ ] Testing guide

#### Success Criteria

- [ ] >80% code coverage (unit + integration tests)
- [ ] Zero critical/high vulnerabilities from security scanning
- [ ] All fuzzing runs complete without crashes
- [ ] Performance targets met (TPS, latency)
- [ ] All services have health checks and metrics
- [ ] Disaster recovery tested successfully
- [ ] Complete operational documentation
- [ ] ATO compliance evidence package ready

#### CI/CD Pipeline

**Required Checks** (GitHub Actions or GitLab CI):

```yaml
stages:
  - lint:
      - cargo fmt --check
      - cargo clippy -D warnings
  - test:
      - cargo test --all-features
      - cargo test --test integration_* (with Docker services)
  - security:
      - cargo audit
      - cargo-deny check
      - gitleaks detect
  - build:
      - cargo build --release
      - docker build (all services)
  - deploy:
      - helm upgrade (staging environment)
      - smoke tests (staging)
      - manual approval → production
```

---

### Phase 15: NIAP Compliance

**Status**: ⏳ PLANNED (45% complete) | **Priority**: 🔴 HIGH | **Effort**: 3-4 weeks
**Dependencies**: All previous phases | **Blocks**: ATO approval

#### Overview

Achieve **NIAP Protection Profile for Certificate Authority (PP-CA) v2.1** compliance to enable use in government and high-security environments requiring Common Criteria certification.

#### Current Compliance Status

**Overall**: 45-50% complete (architecture and design compliant, implementation gaps remain)

**Completed**:

- ✅ Audit generation infrastructure (FAU_GEN.1)
- ✅ Cryptographic key generation framework (FCS_CKM.1 - needs HSM completion)
- ✅ Access control placeholders (FDP_ACC.1, FDP_ACF.1)
- ✅ Authentication framework (FIA_AFL.1, FIA_UAU.1)
- ✅ Management function definitions (FMT_SMF.1)

**Gaps**:

- ⏳ Complete HSM integration (FCS_CKM.1, FCS_COP.1) - **Phase 10**
- ⏳ Audit record protection (FAU_STG.1, FAU_STG.4) - hash chain, write-once storage
- ⏳ Identification and authentication enforcement (FIA_AFL.1 - lockout)
- ⏳ Self-tests (FPT_TST.1) - cryptographic algorithm tests
- ⏳ Reliable timestamps (FPT_STM.1) - NTP integration
- ⏳ Documentation artifacts (AGD_OPE.1, AGD_PRE.1)

#### Scope

**3 parallel tracks**:

1. **Documentation** (6 deliverables)
2. **Implementation** (8 major tasks)
3. **Compliance Tracking** (3 annotation efforts)

#### Work Items

##### Track 1: Compliance Documentation

**Deliverables** (in `docs/compliance/`):

1. **Security Target (ST)** - `SECURITY_TARGET.md`
   - [ ] TOE (Target of Evaluation) description
   - [ ] Security problem definition
   - [ ] Security objectives
   - [ ] Security functional requirements (SFRs)
   - [ ] Security assurance requirements (SARs)
   - [ ] TOE summary specification

2. **SFR Implementation Matrix** - `NIAP_SFR_MATRIX.md`
   - [ ] Map each PP-CA v2.1 SFR to implementation evidence
   - [ ] Reference source files, line numbers, test cases
   - [ ] Status: Implemented | Partial | Not Implemented

3. **Gap Analysis Update** - `NIAP_GAP_ANALYSIS.md`
   - [ ] Close completed gaps from Phases 8-12
   - [ ] Document remaining gaps and mitigation plans
   - [ ] Target: <5 open gaps post-Phase 15

4. **Administrative Guidance (AGD)** - `ADMIN_GUIDE.md`
   - [ ] Secure installation procedures
   - [ ] Configuration for PP-CA compliance mode
   - [ ] User management and role assignment
   - [ ] Certificate lifecycle operations
   - [ ] Audit log management
   - [ ] HSM initialization and key backup

5. **Preparative Procedures (AGD_PRE)** - `INSTALLATION_GUIDE.md`
   - [ ] Secure delivery and receipt procedures
   - [ ] Installation steps with security checks
   - [ ] Initial configuration (admin password, HSM setup, CA initialization)
   - [ ] Secure operational environment requirements

6. **Test Evidence Package** - `TEST_EVIDENCE.md`
   - [ ] Test plan covering all SFRs
   - [ ] Test results (pass/fail) with logs
   - [ ] Penetration test results
   - [ ] Vulnerability assessment report

**Total**: ~200 pages of compliance documentation (estimated)

##### Track 2: Implementation Work

**1. Audit Record Protection (FAU_STG.1, FAU_STG.4)**

**Files**: `crates/ostrich-db/src/repository/audit.rs`, `crates/ostrich-audit/src/lib.rs`

- [ ] Implement hash chain for tamper evidence (Phase 13 task moved to Phase 15)
- [ ] Prevent audit record modification after creation (database constraints)
- [ ] Implement audit log rotation without deletion (archive to write-once storage)
- [ ] Alert on audit storage threshold (>80% full)
- [ ] **FAU_STG.4**: Prevent loss of audit data (pre-allocate log space, halt on full)

**2. Authentication Failure Handling (FIA_AFL.1)**

**Files**: `crates/ostrich-scms/src/rest.rs`, new module `crates/ostrich-auth/src/lockout.rs`

- [ ] Implement account lockout after N failed PIN/password attempts (configurable, default 5)
- [ ] Lock duration: 15 minutes or admin unlock
- [ ] Audit all authentication failures (actor, timestamp, reason)
- [ ] Rate limiting on authentication endpoints (100 attempts/minute per IP)

**3. Self-Tests (FPT_TST.1)**

**File**: New module `crates/ostrich-common/src/selftest.rs`

- [ ] Startup self-test: verify cryptographic algorithms (ECDSA sign/verify known test vectors)
- [ ] Periodic self-test: every 24 hours, verify HSM connectivity and key accessibility
- [ ] On-demand self-test via admin API
- [ ] Halt operations on self-test failure, alert administrator

**4. Reliable Timestamps (FPT_STM.1)**

**File**: `crates/ostrich-common/src/time.rs`

- [ ] Integrate NTP client for time synchronization (via `ntp` crate or `chrono-tz`)
- [ ] Validate NTP server authenticity (NTP authentication or use authenticated time source)
- [ ] Alert on time drift >5 seconds from authoritative source
- [ ] Use monotonic clock for audit log sequencing

**5. Security Management Functions (FMT_SMF.1) - Complete Implementation**

**Files**: Various (CA, SCMS, Audit services)

- [ ] Certificate issuance policy management (admin-only API)
- [ ] Certificate revocation (authorized admin/CA operator)
- [ ] Audit log review (security officer role)
- [ ] User/role management (admin-only)
- [ ] Configuration changes (admin-only, audit all changes)
- [ ] Enforce RBAC for all security functions

**6. Cryptographic Operation Completion (FCS_COP.1)**

**Dependency**: Phase 10 (HSM integration)

- [ ] Verify all cryptographic operations use FIPS 140-3 validated HSM
- [ ] Document HSM certificate number and validation level
- [ ] Test all signature algorithms (RSA, ECDSA, EdDSA, ML-DSA) via HSM
- [ ] Key generation on HSM (not in software for production keys)

**7. TOE Access (FTA_SSL.1) - Session Management**

**File**: New module `crates/ostrich-common/src/session.rs`

- [ ] Terminate sessions after inactivity timeout (default 15 minutes)
- [ ] Admin-initiated session termination (force logout)
- [ ] Session expiration for API tokens (JWT with exp claim)

**8. Trusted Path/Channel (FTP_TRP.1, FTP_ITC.1)**

**Files**: TLS configuration in all services

- [ ] Enforce TLS 1.3 for all external communication
- [ ] Mutual TLS (mTLS) for admin interfaces
- [ ] Disable weak cipher suites (only AEAD ciphers)
- [ ] Certificate pinning for inter-service communication

##### Track 3: Compliance Annotation

**1. Code Annotations**

- [ ] Add `// NIAP PP-CA: [SFR]` comments to all security-relevant code
- [ ] Example: `// NIAP PP-CA: FAU_GEN.1.1 - Generate audit record for certificate issuance`
- [ ] Target: >500 annotations across codebase

**2. Test Annotations**

- [ ] Tag tests with `#[test] // NIAP: [SFR]` to map tests to requirements
- [ ] Example: `#[test] // NIAP: FCS_COP.1.1(1) - RSA signature verification`

**3. Documentation Cross-References**

- [ ] Link SFR implementation matrix to source files (line numbers)
- [ ] Keep docs/compliance/ in sync with code changes (CI check)

#### Success Criteria

**Documentation**:

- [ ] All 6 compliance documents complete and reviewed
- [ ] SFR matrix shows >95% implementation
- [ ] Gap analysis shows <5 open gaps

**Implementation**:

- [ ] All PP-CA v2.1 mandatory SFRs implemented
- [ ] Self-tests pass on startup and periodically
- [ ] Audit logs tamper-evident and protected
- [ ] Authentication lockout functional
- [ ] Reliable timestamps from NTP

**Testing**:

- [ ] Test evidence package complete
- [ ] All SFR tests pass
- [ ] Penetration test shows no critical findings

**Readiness**:

- [ ] System ready for Common Criteria evaluation (EAL2+)
- [ ] ATO documentation package complete

#### Compliance Target

**Post-Phase 15**: 60-65% compliance (sufficient for initial ATO)
**Post-Testing & Fixes**: 85-90% compliance
**Post-CC Evaluation**: 100% compliance (certified)

#### Dependencies & Libraries

- `ntp` - NTP client for reliable timestamps
- `argon2` - Password hashing for admin accounts
- Database constraints - Immutable audit logs

---

## Priority Matrix

| Phase | Name | Priority | Completion | Effort | Dependencies | Blocks |
|-------|------|----------|-----------|--------|--------------|--------|
| **8** | Crypto Operations | 🔴 HIGH | 85% | 1 week | None | All |
| **9** | Database Integration | ✅ DONE | 100% | - | Phase 8 | 11, 12 |
| **10** | PKCS#11 HSM | 🟡 MEDIUM | 0% | 3-4 weeks | Phase 8 | 15, Production |
| **11** | Protocol Validation | 🔴 HIGH | 75% | 1 week | Phase 8 | 12, 14 |
| **12** | Service Integration | 🟡 MEDIUM | 0% | 1-2 weeks | 8, 11 | 14 |
| **13** | Advanced Features | ⚪ LOW | 0% | 2-3 weeks | 12, 14 | None |
| **14** | Testing & Hardening | 🔴 HIGH | 10% | 2-3 weeks | 8, 11, 12 | Production |
| **15** | NIAP Compliance | 🔴 HIGH | 45% | 3-4 weeks | All | ATO |

**Legend**:

- 🔴 HIGH - Critical path, blocks production
- 🟡 MEDIUM - Important but not blocking
- ⚪ LOW - Optional enhancements

---

## Timeline & Schedule

### Critical Path (Sequential Dependencies)

```
Phase 8 (1 week) → Phase 11 (1 week) → Phase 12 (2 weeks) → Phase 14 (3 weeks) = 7 weeks
```

### Parallel Opportunities

**Can run concurrently**:

- Phase 10 (HSM) can start after Phase 8, parallel to 11/12
- Phase 15 (NIAP docs) can start anytime, parallel to implementation

### Realistic Timeline

**3 Schedule Options**:

| Approach | Duration | Assumptions |
|----------|----------|-------------|
| **Aggressive** | 11 weeks | All parallel work, no blockers, single-track focus |
| **Realistic** | 14-16 weeks | Mixed parallel/sequential, some rework expected |
| **Conservative** | 20-24 weeks | Buffer for unknowns, team velocity variance |

### Recommended: 12-Sprint Approach (24 weeks)

**2-week sprints**:

| Sprint | Phase | Deliverables |
|--------|-------|-------------|
| 1 | Phase 8 | ✅ Crypto operations complete |
| 2 | Phase 11 | ✅ JWS, nonce, CSR validation; ⏳ DNS-01, TLS-ALPN-01 |
| 3 | Phase 11 + 10 | Complete challenge validation; start HSM integration |
| 4 | Phase 10 | PKCS#11 provider, software fallback |
| 5 | Phase 10 | SCMS token operations, HSM testing |
| 6 | Phase 12 | ACME→CA, EST→CA integration |
| 7 | Phase 12 | CA→KRA, SCMS→CA integration |
| 8 | Phase 14 | Integration tests, security scanning |
| 9 | Phase 14 | Performance testing, load testing |
| 10 | Phase 15 | NIAP documentation (ST, SFR matrix, gap analysis) |
| 11 | Phase 15 | Implementation (self-tests, audit protection, lockout) |
| 12 | Phase 14 + 15 | Final testing, compliance review, ATO package |

**Milestones**:

- **Week 8**: Core functionality complete (Phases 8, 11)
- **Week 12**: HSM + Service Integration complete
- **Week 18**: All testing complete
- **Week 24**: ATO-ready system

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **HSM Integration Complexity** | Medium | High | Use SoftHSM for development; allocate 4 weeks; early prototyping |
| **ACME Challenge Validation Failures** | Medium | Medium | Comprehensive testing with real domains; fallback to HTTP-01 only |
| **Performance Below Targets** | Low | Medium | Early benchmarking (Phase 8); caching (Phase 13); horizontal scaling |
| **NIAP Compliance Gaps** | Medium | High | Hire compliance consultant; gap analysis in Phase 15; iterative fixes |
| **Database Scalability** | Low | Medium | PostgreSQL proven at scale; connection pooling; read replicas if needed |
| **Third-Party Dependency Vulnerabilities** | Medium | High | `cargo audit` in CI; pin versions; security advisory monitoring |
| **Team Knowledge Gaps (Crypto, PKCS#11)** | Medium | Medium | Training budget; pair programming; external SME consultation |
| **Schedule Overrun** | High | Medium | 20% buffer in conservative estimate; weekly progress tracking |

**Highest Priority Risks** (address immediately):

1. HSM integration complexity → Prototype in Sprint 3
2. NIAP compliance gaps → Start documentation in Sprint 10
3. Schedule overrun → Adopt 16-week realistic timeline, not 11-week aggressive

---

## Success Metrics

### Technical Metrics

**Code Quality**:

- [ ] >80% test coverage (unit + integration)
- [ ] Zero `cargo clippy -D warnings` violations
- [ ] Zero high/critical vulnerabilities (`cargo audit`)
- [ ] All code formatted (`cargo fmt --check`)

**Performance**:

- [ ] Certificate signing: <50ms (HSM), <10ms (software)
- [ ] OCSP response: <100ms (p99)
- [ ] ACME order processing: <30s end-to-end
- [ ] Database queries: <10ms (p99)

**Reliability**:

- [ ] Service uptime: >99.9% (excluding maintenance)
- [ ] Zero data loss incidents
- [ ] All services auto-restart on crash
- [ ] Health checks passing

### Compliance Metrics

**NIST 800-53 Rev 5**:

- [ ] All selected controls implemented (AU, SC, IA, AC, SI families)
- [ ] Control evidence documented in `docs/compliance/NIST_800-53_MAPPING.md`
- [ ] ATO evidence package complete

**NIAP PP-CA v2.1**:

- [ ] >95% SFR implementation
- [ ] Security Target (ST) complete
- [ ] Ready for Common Criteria evaluation

**RFC Compliance**:

- [ ] RFC 5280 (X.509) - full compliance
- [ ] RFC 6960 (OCSP) - full compliance
- [ ] RFC 8555 (ACME) - full compliance (HTTP-01, DNS-01, TLS-ALPN-01)
- [ ] RFC 7030 (EST) - core compliance (optional server keygen deferred)

### Operational Metrics

**Deployment**:

- [ ] One-command deployment (`helm install ostrichpki`)
- [ ] Complete installation guide
- [ ] Disaster recovery tested (<4 hour RTO)

**Documentation**:

- [ ] API documentation (OpenAPI specs)
- [ ] Operational runbooks complete
- [ ] Compliance documentation ready for auditors

**Security**:

- [ ] Penetration test passed (no critical/high findings)
- [ ] Fuzzing completed (1M iterations, zero crashes)
- [ ] All secrets externalized (no hardcoded credentials)

### Business Metrics

**Readiness**:

- [ ] Production deployment successful
- [ ] ATO approval obtained (or in final review)
- [ ] Customer pilot deployment complete
- [ ] No P0/P1 bugs open

---

## Next Steps

### Immediate Actions (Next 2 Weeks)

1. **Complete Phase 8**: Finish crypto integration testing
2. **Advance Phase 11**: Implement DNS-01 and TLS-ALPN-01 challenge validators
3. **Plan Phase 10**: HSM hardware procurement, SoftHSM setup for development
4. **Start Phase 15 Documentation**: Draft Security Target outline

### Sprint Planning

**Adopt 16-week realistic timeline**:

- Weeks 1-2: Complete Phases 8 & 11
- Weeks 3-6: Phase 10 (HSM)
- Weeks 7-10: Phases 12 & 14 (Integration + Testing)
- Weeks 11-16: Phase 15 (NIAP Compliance) + Final Hardening

### Team Recommendations

**Roles Needed**:

- Rust developer (cryptography experience) - 1 FTE
- Security engineer (PKI, PKCS#11) - 1 FTE
- Compliance specialist (NIAP, ATO) - 0.5 FTE (consultant)
- QA engineer (testing, automation) - 0.5 FTE

**External Support**:

- HSM vendor support (for PKCS#11 integration)
- NIAP compliance consultant (for Security Target review)
- Penetration testing firm (for Phase 14)

---

## Conclusion

OstrichPKI has achieved **significant progress** with 8 foundational phases complete and ~55% overall completion. The system architecture is solid, all services are scaffolded, and database integration is production-ready.

**Remaining work focuses on**:

1. **Security-critical implementations**: Crypto operations, HSM integration, protocol validation
2. **Service integration**: Connecting microservices for end-to-end workflows
3. **Testing & hardening**: Comprehensive security and performance validation
4. **Compliance**: NIAP PP-CA v2.1 documentation and gap closure

**With focused effort over the next 14-16 weeks**, OstrichPKI will be ready for **production deployment** and **ATO approval**.

The roadmap prioritizes **security and compliance** while maintaining **technical excellence** through comprehensive testing and adherence to RFC standards and NIST cryptographic requirements.

---

**Document Version**: 2.0
**Last Updated**: January 2026
**Maintained By**: OstrichPKI Development Team
**For Questions**: See `CONTRIBUTING.md` or open a GitHub issue
