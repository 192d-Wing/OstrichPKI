-- Initial database schema for OstrichPKI
--
-- NIST 800-53: SC-28 - Protection of information at rest
-- RFC 5280: X.509 certificate and CRL storage

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Certificate Authority (CA) keys table
-- Stores metadata about CA keys (actual keys are in HSM)
--
-- NIST 800-53: SC-12 - Cryptographic key establishment and management
CREATE TABLE ca_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    label VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) NOT NULL, -- RSA2048, EcP256, MlDsa65, etc.
    algorithm VARCHAR(50) NOT NULL, -- RsaPkcs1Sha256, EcdsaP256Sha256, etc.
    provider_type VARCHAR(50) NOT NULL, -- Pkcs11, Software
    provider_slot_id BIGINT, -- For PKCS#11 HSM
    key_id BYTEA NOT NULL, -- Provider-specific key identifier
    extractable BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ca_keys_label ON ca_keys(label);
CREATE INDEX idx_ca_keys_provider ON ca_keys(provider_type, provider_slot_id);

-- CA certificates table
-- Stores the CA certificates themselves
--
-- RFC 5280 §4.1 - Basic certificate fields
CREATE TABLE ca_certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ca_key_id UUID NOT NULL REFERENCES ca_keys(id) ON DELETE RESTRICT,
    serial_number BYTEA NOT NULL UNIQUE,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    der_encoded BYTEA NOT NULL,
    pem_encoded TEXT NOT NULL,
    is_root BOOLEAN NOT NULL DEFAULT false,
    parent_ca_id UUID REFERENCES ca_certificates(id),
    path_len_constraint INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ca_certs_serial ON ca_certificates(serial_number);
CREATE INDEX idx_ca_certs_subject ON ca_certificates(subject_dn);
CREATE INDEX idx_ca_certs_key ON ca_certificates(ca_key_id);

-- End-entity certificates table
-- Stores issued certificates
--
-- RFC 5280 §4.1 - Basic certificate fields
CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ca_id UUID NOT NULL REFERENCES ca_certificates(id) ON DELETE RESTRICT,
    serial_number BYTEA NOT NULL,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    der_encoded BYTEA NOT NULL,
    pem_encoded TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revocation_time TIMESTAMPTZ,
    revocation_reason INTEGER, -- RFC 5280 §5.3.1 CRL reason codes
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_serial_per_ca UNIQUE (ca_id, serial_number)
);

CREATE INDEX idx_certs_serial ON certificates(serial_number);
CREATE INDEX idx_certs_subject ON certificates(subject_dn);
CREATE INDEX idx_certs_ca ON certificates(ca_id);
CREATE INDEX idx_certs_revoked ON certificates(revoked);
CREATE INDEX idx_certs_validity ON certificates(not_before, not_after);

-- Certificate Revocation Lists (CRL) table
-- Stores generated CRLs
--
-- RFC 5280 §5 - CRL format
CREATE TABLE crls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ca_id UUID NOT NULL REFERENCES ca_certificates(id) ON DELETE RESTRICT,
    crl_number BIGINT NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    der_encoded BYTEA NOT NULL,
    pem_encoded TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_crl_number_per_ca UNIQUE (ca_id, crl_number)
);

CREATE INDEX idx_crls_ca ON crls(ca_id);
CREATE INDEX idx_crls_validity ON crls(this_update, next_update);

-- Audit events table
-- Append-only audit log with hash chain for integrity
--
-- NIST 800-53: AU-2 - Auditable events
-- NIST 800-53: AU-3 - Content of audit records
-- NIST 800-53: AU-9 - Protection of audit information
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL, -- authentication, authorization, certificate_issuance, etc.
    actor VARCHAR(255) NOT NULL, -- User/system that triggered event
    target VARCHAR(255) NOT NULL, -- Resource affected
    action VARCHAR(100) NOT NULL, -- create, read, update, delete, sign, etc.
    outcome VARCHAR(50) NOT NULL, -- success, failure, error
    details JSONB, -- Additional event-specific data
    ip_address VARCHAR(45), -- IPv4 or IPv6
    user_agent TEXT,
    session_id VARCHAR(255),
    previous_hash BYTEA, -- Hash of previous event for chain integrity
    event_hash BYTEA NOT NULL, -- Hash of this event
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit events are append-only, no updates or deletes allowed
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_actor ON audit_events(actor);
CREATE INDEX idx_audit_type ON audit_events(event_type);
CREATE INDEX idx_audit_outcome ON audit_events(outcome);

-- Certificate profiles table
-- Templates for certificate issuance
--
-- NIST 800-53: CM-2 - Baseline configuration
CREATE TABLE certificate_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    validity_days INTEGER NOT NULL,
    key_usage TEXT[], -- digitalSignature, keyEncipherment, etc.
    extended_key_usage TEXT[], -- serverAuth, clientAuth, etc.
    basic_constraints_ca BOOLEAN NOT NULL DEFAULT false,
    basic_constraints_path_len INTEGER,
    subject_alt_name_required BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cert_profiles_name ON certificate_profiles(name);

-- OCSP signing keys table
-- Delegated OCSP responder keys
--
-- RFC 6960 §2.6 - OCSP response signing
CREATE TABLE ocsp_signing_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ca_id UUID NOT NULL REFERENCES ca_certificates(id) ON DELETE RESTRICT,
    label VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    provider_slot_id BIGINT,
    key_id BYTEA NOT NULL,
    certificate_der BYTEA NOT NULL, -- Delegated OCSP signer cert
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ocsp_keys_ca ON ocsp_signing_keys(ca_id);
CREATE INDEX idx_ocsp_keys_validity ON ocsp_signing_keys(not_before, not_after);

-- OCSP response cache table
-- Pre-signed OCSP responses for performance
--
-- RFC 6960 §2.2 - OCSP response
CREATE TABLE ocsp_response_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    response_der BYTEA NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_cert_ocsp_cache UNIQUE (certificate_id)
);

CREATE INDEX idx_ocsp_cache_cert ON ocsp_response_cache(certificate_id);
CREATE INDEX idx_ocsp_cache_validity ON ocsp_response_cache(this_update, next_update);

-- KRA transport keys table
-- Keys used to wrap keys for transport to KRA
--
-- NIST 800-53: SC-12 - Cryptographic key transport
CREATE TABLE kra_transport_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    label VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) NOT NULL, -- MlKem1024 for PQC
    algorithm VARCHAR(50) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    provider_slot_id BIGINT,
    key_id BYTEA NOT NULL,
    public_key_der BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- KRA storage keys table
-- Keys used to wrap keys for long-term storage
--
-- NIST 800-53: SC-12 - Cryptographic key storage
CREATE TABLE kra_storage_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    label VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    provider_slot_id BIGINT,
    key_id BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Escrowed keys table
-- Private keys wrapped and stored by KRA
--
-- NIST 800-53: SC-12 - Cryptographic key escrow
CREATE TABLE escrowed_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE RESTRICT,
    wrapped_key BYTEA NOT NULL, -- Encrypted private key
    wrapping_key_id UUID NOT NULL REFERENCES kra_storage_keys(id),
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    escrow_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_escrowed_keys_cert ON escrowed_keys(certificate_id);
CREATE INDEX idx_escrowed_keys_wrapping ON escrowed_keys(wrapping_key_id);

-- Recovery agents table
-- Authorized agents for M-of-N key recovery
--
-- NIST 800-53: AC-3 - Access enforcement for key recovery
CREATE TABLE recovery_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    public_key_der BYTEA NOT NULL, -- For encrypting recovery shares
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Recovery requests table
-- Tracks key recovery requests
--
-- NIST 800-53: AU-2 - Audit key recovery events
CREATE TABLE recovery_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    escrowed_key_id UUID NOT NULL REFERENCES escrowed_keys(id) ON DELETE RESTRICT,
    requestor VARCHAR(255) NOT NULL,
    justification TEXT NOT NULL,
    status VARCHAR(50) NOT NULL, -- pending, approved, rejected, completed
    required_shares INTEGER NOT NULL, -- M in M-of-N
    total_agents INTEGER NOT NULL, -- N in M-of-N
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recovery_requests_status ON recovery_requests(status);
CREATE INDEX idx_recovery_requests_escrowed ON recovery_requests(escrowed_key_id);

-- Recovery shares table
-- Encrypted shares for M-of-N recovery
--
-- NIST 800-53: SC-12 - Shamir secret sharing
CREATE TABLE recovery_shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    recovery_request_id UUID NOT NULL REFERENCES recovery_requests(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES recovery_agents(id) ON DELETE RESTRICT,
    encrypted_share BYTEA NOT NULL, -- Share encrypted with agent's public key
    submitted_at TIMESTAMPTZ,
    CONSTRAINT unique_agent_per_request UNIQUE (recovery_request_id, agent_id)
);

CREATE INDEX idx_recovery_shares_request ON recovery_shares(recovery_request_id);

-- ACME accounts table
-- RFC 8555 §7.1.2 - Account objects
CREATE TABLE acme_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id VARCHAR(255) NOT NULL UNIQUE, -- URL-safe account identifier
    jwk_thumbprint VARCHAR(255) NOT NULL UNIQUE, -- RFC 7638 thumbprint
    public_key_jwk JSONB NOT NULL, -- JWK format public key
    contact TEXT[], -- Email addresses
    status VARCHAR(50) NOT NULL, -- valid, deactivated, revoked
    terms_of_service_agreed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_acme_accounts_status ON acme_accounts(status);

-- ACME orders table
-- RFC 8555 §7.1.3 - Order objects
CREATE TABLE acme_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id VARCHAR(255) NOT NULL UNIQUE,
    account_id UUID NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL, -- pending, ready, processing, valid, invalid
    identifiers JSONB NOT NULL, -- DNS names, IP addresses
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    expires TIMESTAMPTZ NOT NULL,
    certificate_id UUID REFERENCES certificates(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_acme_orders_account ON acme_orders(account_id);
CREATE INDEX idx_acme_orders_status ON acme_orders(status);
CREATE INDEX idx_acme_orders_expires ON acme_orders(expires);

-- ACME authorizations table
-- RFC 8555 §7.1.4 - Authorization objects
CREATE TABLE acme_authorizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    authorization_id VARCHAR(255) NOT NULL UNIQUE,
    order_id UUID NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    identifier_type VARCHAR(50) NOT NULL, -- dns, ip
    identifier_value TEXT NOT NULL,
    status VARCHAR(50) NOT NULL, -- pending, valid, invalid, revoked, expired
    expires TIMESTAMPTZ NOT NULL,
    wildcard BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_acme_authz_order ON acme_authorizations(order_id);
CREATE INDEX idx_acme_authz_status ON acme_authorizations(status);

-- ACME challenges table
-- RFC 8555 §8 - Challenge types
CREATE TABLE acme_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge_id VARCHAR(255) NOT NULL UNIQUE,
    authorization_id UUID NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
    challenge_type VARCHAR(50) NOT NULL, -- http-01, dns-01, tls-alpn-01
    token VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL, -- pending, processing, valid, invalid
    validated_at TIMESTAMPTZ,
    error_detail JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_acme_challenges_authz ON acme_challenges(authorization_id);
CREATE INDEX idx_acme_challenges_status ON acme_challenges(status);
CREATE INDEX idx_acme_challenges_token ON acme_challenges(token);

-- ACME nonces table
-- RFC 8555 §6.5 - Replay protection
CREATE TABLE acme_nonces (
    nonce VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_acme_nonces_expires ON acme_nonces(expires_at);

-- Smartcard token models table
-- Supported token types (YubiKey, JavaCard, etc.)
CREATE TABLE token_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    manufacturer VARCHAR(255) NOT NULL,
    model VARCHAR(255) NOT NULL,
    atr VARCHAR(255), -- Answer-to-reset for identification
    supported_key_types TEXT[], -- RSA2048, EcP256, etc.
    max_pin_length INTEGER NOT NULL,
    min_pin_length INTEGER NOT NULL,
    supports_puk BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_token_model UNIQUE (manufacturer, model)
);

-- Tokens table
-- Physical token inventory
--
-- NIST 800-53: IA-2(1) - Multi-factor authentication
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    serial_number VARCHAR(255) NOT NULL UNIQUE,
    token_model_id UUID NOT NULL REFERENCES token_models(id) ON DELETE RESTRICT,
    status VARCHAR(50) NOT NULL, -- inventory, assigned, active, blocked, retired
    assigned_to VARCHAR(255), -- User identifier
    pin_attempts_remaining INTEGER NOT NULL DEFAULT 3,
    puk_attempts_remaining INTEGER NOT NULL DEFAULT 10,
    assigned_at TIMESTAMPTZ,
    blocked_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_serial ON tokens(serial_number);
CREATE INDEX idx_tokens_status ON tokens(status);
CREATE INDEX idx_tokens_assigned ON tokens(assigned_to);

-- Token keys table
-- Keys stored on tokens
CREATE TABLE token_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    label VARCHAR(255) NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    certificate_id UUID REFERENCES certificates(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_key_per_token UNIQUE (token_id, label)
);

CREATE INDEX idx_token_keys_token ON token_keys(token_id);
CREATE INDEX idx_token_keys_cert ON token_keys(certificate_id);

-- Token events table
-- Lifecycle audit for tokens
--
-- NIST 800-53: AU-2 - Token lifecycle events
CREATE TABLE token_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- assigned, pin_reset, blocked, unblocked, retired
    actor VARCHAR(255) NOT NULL,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_events_token ON token_events(token_id);
CREATE INDEX idx_token_events_timestamp ON token_events(timestamp DESC);

-- EST enrollments table
-- RFC 7030 - EST enrollment records
CREATE TABLE est_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_identifier VARCHAR(255) NOT NULL,
    enrollment_type VARCHAR(50) NOT NULL, -- simple_enroll, simple_reenroll
    csr_der BYTEA NOT NULL,
    certificate_id UUID REFERENCES certificates(id),
    status VARCHAR(50) NOT NULL, -- pending, approved, rejected, issued
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_est_enrollments_client ON est_enrollments(client_identifier);
CREATE INDEX idx_est_enrollments_status ON est_enrollments(status);

-- EST authorized clients table
-- Clients authorized for EST enrollment
--
-- NIST 800-53: AC-3 - Access enforcement
CREATE TABLE est_clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_identifier VARCHAR(255) NOT NULL UNIQUE,
    client_certificate_der BYTEA NOT NULL,
    authorized_profiles UUID[] NOT NULL, -- References certificate_profiles.id
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_est_clients_active ON est_clients(active);
