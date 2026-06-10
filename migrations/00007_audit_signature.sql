-- Migration 00007: signed audit records (AU-10 non-repudiation / tamper-evidence)
--
-- The audit hash chain (previous_hash -> event_hash) detects accidental
-- corruption and reordering, but it is NOT tamper-evident against an attacker
-- with database write access: SHA-256 is public, so such an attacker can modify
-- a record and recompute that record's event_hash AND every subsequent
-- event_hash, producing an internally consistent (but forged) chain.
--
-- Signing each record's event_hash with a key the attacker does not hold closes
-- that gap: a modified record's signature no longer verifies, and the attacker
-- cannot re-sign it. This is the AU-10 (non-repudiation) control.
--
-- Both columns are nullable: signing is optional (DatabaseAuditSink::new stays
-- unsigned for backward compatibility; ::with_signing_key enables it). A NULL
-- signature simply means that record predates / was written without signing.
--
-- COMPLIANCE MAPPING:
--   NIST 800-53: AU-9(3) (Cryptographic protection of audit information)
--   NIST 800-53: AU-10 (Non-repudiation) - signed audit records
--   NIAP PP-CA: FAU_STG.4 (Prevention of audit data loss / undetected modification)
--   NIST 800-53: CM-3 (Configuration Change Control)

ALTER TABLE audit_events
    -- Signature over this record's event_hash (algorithm per the signing key).
    ADD COLUMN IF NOT EXISTS signature BYTEA,
    -- Identifier/label of the key that produced the signature, so verifiers
    -- know which public key to check against (and for key rotation).
    ADD COLUMN IF NOT EXISTS signing_key_id VARCHAR(255);
