-- Trust Anchor Management Protocol (RFC 5934) authoritative store.
--
-- OstrichPKI plays the TAMP *manager / authority* role: it maintains the
-- authoritative model of which trust anchors and community memberships each
-- target cryptographic module should hold, issues signed TAMP messages to
-- effect changes, and records the targets' signed confirmations. Durable
-- per-signer sequence numbers provide replay protection that survives restarts
-- (RFC 5934 §4.1).
--
-- COMPLIANCE MAPPING:
--  * NIST 800-53: SC-12 (trust anchor / key management), SC-23 (replay
--    protection via monotonic sequence numbers), AU-2/AU-3 (auditable
--    trust-anchor lifecycle), CM-3 (configuration change control), SI-10
--    (validated DER stored verbatim for provenance)
--  * NIAP PP-CA: FMT_SMF.1 (trust anchor management functions),
--    FPT_STM.1 (reliable timestamps), FAU_GEN.1 (audit generation)
--  * RFC 5934 §1.3.2 (trust anchor store), §4.1 (sequence numbers)

-- A managed target: a module, community set, URI, or "all modules" broadcast.
-- The DER of the RFC 5934 TargetIdentifier is the canonical key.
CREATE TABLE IF NOT EXISTS tamp_targets (
    id          UUID PRIMARY KEY,
    -- Human-readable label for operator displays (e.g. a URI or "all-modules").
    label       VARCHAR(255) NOT NULL,
    -- DER encoding of the TargetIdentifier CHOICE; canonical identity.
    target_der  BYTEA NOT NULL UNIQUE,
    -- RFC 5934 §4.2 usesApex: whether the target's store is under an apex TA.
    uses_apex   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Trust anchors held by a target's store. RFC 5934 keys the set on the trust
-- anchor public key (SubjectPublicKeyInfo), so (target, pub_key_spki) is unique;
-- re-adding an existing public key with differing fields must be rejected by the
-- application with improperTAAddition.
CREATE TABLE IF NOT EXISTS tamp_trust_anchors (
    id            UUID PRIMARY KEY,
    target_id     UUID NOT NULL REFERENCES tamp_targets(id) ON DELETE CASCADE,
    -- DER SubjectPublicKeyInfo — the TA's identity within the store.
    pub_key_spki  BYTEA NOT NULL,
    -- Trust anchor key identifier (SKI), used to locate the TA by SignerInfo sid.
    key_id        BYTEA,
    -- Optional human-readable title (RFC 5914 TrustAnchorTitle).
    ta_title      VARCHAR(64),
    -- Exactly one apex trust anchor per target (RFC 5934 §1.2.1).
    is_apex       BOOLEAN NOT NULL DEFAULT FALSE,
    -- DER of the RFC 5914 TrustAnchorChoice as installed (provenance / re-emit).
    ta_der        BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, pub_key_spki)
);

CREATE INDEX IF NOT EXISTS idx_tamp_trust_anchors_target
    ON tamp_trust_anchors (target_id);

-- At most one apex trust anchor per target (RFC 5934 §1.2.1).
CREATE UNIQUE INDEX IF NOT EXISTS idx_tamp_trust_anchors_one_apex
    ON tamp_trust_anchors (target_id)
    WHERE is_apex;

-- Per-target, per-signer monotonic sequence-number baselines (RFC 5934 §4.1).
-- A request is accepted only if its seqNum is strictly greater than the stored
-- value, which is then advanced; this is the durable anti-replay state.
CREATE TABLE IF NOT EXISTS tamp_sequence_numbers (
    id              UUID PRIMARY KEY,
    target_id       UUID NOT NULL REFERENCES tamp_targets(id) ON DELETE CASCADE,
    -- SKI of the authorized signer this baseline applies to.
    signer_key_id   BYTEA NOT NULL,
    -- Last accepted sequence number. RFC 5934 caps SeqNumber at i64::MAX, so
    -- BIGINT holds the full permitted range.
    last_seq_number BIGINT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, signer_key_id)
);

-- Community OID membership per target (RFC 5934 §4.7).
CREATE TABLE IF NOT EXISTS tamp_communities (
    id            UUID PRIMARY KEY,
    target_id     UUID NOT NULL REFERENCES tamp_targets(id) ON DELETE CASCADE,
    community_oid VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, community_oid)
);

-- Provenance log of issued messages and received confirmations / errors.
-- Complements the tamper-evident ostrich-audit chain with the full message DER.
CREATE TABLE IF NOT EXISTS tamp_message_log (
    id            UUID PRIMARY KEY,
    target_id     UUID REFERENCES tamp_targets(id) ON DELETE SET NULL,
    -- 'outbound' (manager -> target) or 'inbound' (target -> manager).
    direction     VARCHAR(16) NOT NULL,
    -- TAMP content-type OID (dotted string) and friendly message name.
    content_type  VARCHAR(64) NOT NULL,
    message_name  VARCHAR(64) NOT NULL,
    -- Sequence number carried by the message (if any).
    seq_number    BIGINT,
    -- SKI of the signer (outbound: our apex/management key; inbound: target).
    signer_key_id BYTEA,
    -- Resulting status code label for confirmations / errors.
    status_code   VARCHAR(48),
    -- The full CMS ContentInfo DER, for audit / replay analysis.
    message_der   BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tamp_message_log_target_created
    ON tamp_message_log (target_id, created_at DESC);
