# OstrichPKI Implementation Plan

## Overview

A comprehensive PKI system in Rust with six microservices:

- **Certificate Authority (CA)** - Certificate issuance, signing, CRL generation
- **Key Recovery Authority (KRA)** - Key escrow with M-of-N recovery
- **OCSP Responder** - RFC 6960 real-time certificate status
- **Smartcard Management System (SCMS)** - Token lifecycle, PKCS#11
- **ACME Responder** - RFC 8555 automated certificate management
- **EST Server** - RFC 7030 enrollment over secure transport

## Technology Stack

| Component | Choice |
|-----------|--------|
| Database | PostgreSQL |
| Web Framework | Axum |
| HSM | PKCS#11 from day one (with software fallback) |
| Architecture | Microservices (separate binaries) |
| Inter-service | gRPC with mTLS |
| Crypto | ring + RustCrypto ecosystem |

---

## Project Structure

```text
ostrich-pki/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── ostrich-common/           # Shared types, config, errors
│   ├── ostrich-crypto/           # PKCS#11 abstraction + software fallback
│   ├── ostrich-x509/             # X.509 parsing, building, profiles
│   ├── ostrich-db/               # SQLx repositories and models
│   ├── ostrich-audit/            # Audit logging with integrity chain
│   ├── ostrich-protocol/         # gRPC definitions (tonic)
│   ├── ostrich-api/              # Shared Axum middleware, auth, extractors
│   ├── ostrich-ca/               # Certificate Authority service
│   ├── ostrich-kra/              # Key Recovery Authority service
│   ├── ostrich-ocsp/             # OCSP Responder service
│   ├── ostrich-scms/             # Smartcard Management service
│   ├── ostrich-acme/             # ACME Responder service
│   └── ostrich-est/              # EST Server service
├── tools/
│   ├── ostrich-cli/              # Admin CLI tool
│   └── ostrich-init/             # Initial setup wizard
├── proto/                        # gRPC .proto files
├── migrations/                   # SQLx migrations
├── config/                       # Configuration templates
└── docker/                       # Dockerfiles and compose
```

---

## Key Abstractions

### CryptoProvider Trait (ostrich-crypto)

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn generate_key_pair(&self, key_type: KeyType, label: &str, extractable: bool) -> Result<KeyHandle>;
    async fn sign(&self, key: &KeyHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>>;
    async fn verify(&self, key: &KeyHandle, algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<bool>;
    async fn export_public_key(&self, key: &KeyHandle) -> Result<Vec<u8>>;
    async fn wrap_key(&self, key_to_wrap: &KeyHandle, wrapping_key: &KeyHandle) -> Result<Vec<u8>>;
    async fn unwrap_key(&self, wrapped: &[u8], unwrapping_key: &KeyHandle, key_type: KeyType) -> Result<KeyHandle>;
}
```

### Repository Pattern (ostrich-db)

- `CertificateRepository` - Store, find, revoke certificates
- `AuditRepository` - Append-only audit log with hash chain
- `TokenRepository` - Smartcard inventory
- `AcmeRepository` - Accounts, orders, challenges

---

## Database Schema (Key Tables)

### CA Tables

- `ca_keys` - CA key metadata (actual keys in HSM)
- `ca_certificates` - CA certificates
- `certificates` - Issued end-entity certificates
- `certificate_profiles` - Issuance profiles/templates
- `crl_entries` - Generated CRLs

### KRA Tables

- `transport_keys`, `storage_keys` - Key wrapping keys
- `escrowed_keys` - Wrapped private keys
- `recovery_agents` - M-of-N agents
- `recovery_requests`, `recovery_shares` - Recovery workflow

### OCSP Tables

- `ocsp_signing_keys` - Delegated responder keys
- `ocsp_response_cache` - Pre-signed responses

### SCMS Tables

- `token_models` - Supported token types
- `tokens` - Token inventory
- `token_keys` - Keys on tokens
- `token_events` - Lifecycle audit

### ACME Tables

- `acme_accounts` - JWK-based accounts
- `acme_orders` - Certificate orders
- `acme_authorizations` - Domain authorizations
- `acme_challenges` - HTTP-01/DNS-01/TLS-ALPN-01
- `acme_nonces` - Replay protection

### EST Tables

- `est_enrollments` - Enrollment records
- `est_clients` - Authorized clients

---

## Service Communication

```text
External (HTTPS)          Internal (gRPC/mTLS)         Database
─────────────────         ────────────────────         ────────
OCSP :80/8080  ◄────────► CA (status stream)  ◄──────► PostgreSQL
ACME :443      ◄────────► CA (issuance)       ◄──────► PostgreSQL
EST  :8443     ◄────────► CA (issuance)       ◄──────► PostgreSQL
CA   :8443     ◄────────► KRA (escrow)        ◄──────► PostgreSQL
SCMS :8443     ◄────────► CA + KRA            ◄──────► PostgreSQL
KRA  :8443     (admin only)                   ◄──────► PostgreSQL
```

---

## Implementation Phases

### Phase 1: Foundation

- [ ] Set up Cargo workspace with all crate stubs
- [ ] Implement `ostrich-common` (errors, config, types)
- [ ] Implement `ostrich-crypto` (CryptoProvider trait, PKCS#11 + ring backends)
- [ ] Implement `ostrich-db` (pool, migrations, base repositories)
- [ ] Implement `ostrich-audit` (event types, database sink)

### Phase 2: Certificate Authority

- [ ] Implement `ostrich-x509` (parsing, building, profiles, CRL)
- [ ] Implement `ostrich-ca` service (issuance, revocation, CRL generation)
- [ ] CA REST API and gRPC service
- [ ] `ostrich-cli` CA commands

### Phase 3: OCSP Responder

- [ ] Implement `ostrich-protocol` OCSP types
- [ ] Implement `ostrich-ocsp` service (RFC 6960)
- [ ] Response caching, delegated signing

### Phase 4: Key Recovery Authority

- [ ] Implement `ostrich-kra` service
- [ ] Shamir secret sharing for M-of-N
- [ ] Recovery workflow with agent authentication

### Phase 5: ACME Responder

- [ ] Implement `ostrich-acme` service (RFC 8555)
- [ ] Account, order, authorization state machines
- [ ] HTTP-01, DNS-01, TLS-ALPN-01 challenges

### Phase 6: EST Server

- [ ] Implement `ostrich-est` service (RFC 7030)
- [ ] /cacerts, /simpleenroll, /simplereenroll, /csrattrs

### Phase 7: Smartcard Management

- [ ] Implement `ostrich-scms` service
- [ ] Token inventory, lifecycle, PIN management
- [ ] PKCS#11 token operations

### Phase 8: Integration & Hardening

- [ ] End-to-end integration tests
- [ ] mTLS between all services
- [ ] Security audit preparation
- [ ] Documentation

---

## Key Dependencies

```toml
# Core
tokio = "1.35"
axum = "0.7"
tonic = "0.11"
sqlx = { version = "0.7", features = ["postgres"] }

# Crypto
ring = "0.17"
cryptoki = "0.6"           # PKCS#11
x509-cert = "0.2"
x509-parser = "0.16"
der = "0.7"
pkcs8 = "0.10"
pkcs10 = "0.2"

# Utilities
serde = "1.0"
chrono = "0.4"
uuid = "1.6"
zeroize = "1.7"
tracing = "0.1"
clap = "4.4"
```

---

## Critical Files to Create First

1. **Cargo.toml** - Workspace definition with all crates
2. **crates/ostrich-crypto/src/provider.rs** - CryptoProvider trait
3. **crates/ostrich-crypto/src/pkcs11/mod.rs** - HSM implementation
4. **crates/ostrich-x509/src/builder/certificate.rs** - Cert builder
5. **crates/ostrich-db/src/repository/certificate.rs** - Cert repository
6. **migrations/00001_create_base_tables.sql** - Core schema
7. **proto/ca_service.proto** - CA gRPC contract
8. **crates/ostrich-ca/src/main.rs** - CA service entry point
