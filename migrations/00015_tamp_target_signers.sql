-- TAMP target response-signing keys (RFC 5934 §2.2.1).
--
-- A TAMP target signs the confirmations / status responses it returns to the
-- manager. To verify those responses the manager must hold the target's
-- response-signing public key(s), located by the SignerInfo subjectKeyIdentifier
-- (RFC 5934 §2.2.1). This is distinct from the trust anchors *installed on* the
-- target (tamp_trust_anchors): it is the key the target signs *with*.
--
-- Registering signers here lets `ingest` resolve the verifying key from trusted
-- state instead of trusting a key supplied alongside the message, closing the
-- gap where a caller could dictate which key a response is verified against.
--
-- COMPLIANCE MAPPING:
--  * NIST 800-53: SC-12 (key management), IA-7 (cryptographic module auth),
--    SI-10 (input validation — verify against trusted key, not request data)
--  * NIAP PP-CA: FMT_SMF.1 (management of trust relationships)
--  * RFC 5934 §2.2.1 (locate signing trust anchor by key id)
CREATE TABLE IF NOT EXISTS tamp_target_signers (
    id            UUID PRIMARY KEY,
    target_id     UUID NOT NULL REFERENCES tamp_targets(id) ON DELETE CASCADE,
    -- subjectKeyIdentifier (SKI) of the target's response-signing key.
    signer_key_id BYTEA NOT NULL,
    -- DER SubjectPublicKeyInfo used to verify responses from this signer.
    spki          BYTEA NOT NULL,
    -- Optional operator description (e.g. "module-A response key, rotated 2026").
    description   VARCHAR(255),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, signer_key_id)
);

CREATE INDEX IF NOT EXISTS idx_tamp_target_signers_lookup
    ON tamp_target_signers (target_id, signer_key_id);
