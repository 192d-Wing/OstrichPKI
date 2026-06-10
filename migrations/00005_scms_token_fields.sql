-- Migration 00005: Phase 1c SCMS schema extensions
--
-- Adds the fields the SCMS service models (`crates/ostrich-scms/src/token.rs`)
-- carry but the database had been defaulting in code. Source of truth moves
-- from the service layer into the database, so list/get endpoints return real
-- values and update operations no longer silently drop fields.
--
-- All columns are added as nullable so the migration is forward-only and safe
-- to run against an existing database. Where the SCMS Token / TokenModel
-- DTOs require a non-Option<T> field, the service layer provides a sensible
-- default at construction time.
--
-- COMPLIANCE MAPPING:
--   NIST 800-53: CM-3 (Configuration Change Control) - migration is checked in
--   NIST 800-53: AU-2 (Auditable Events) - schema extends what audit can record
--   NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)
--                - separate so_pin_attempts_remaining counter
--   NIAP PP-CA: FMT_SMF.1 (Security Management Functions)
--                - lifecycle timestamps (initialized_at, expires_at)

------------------------------------------------------------
-- tokens: lifecycle timestamps + display label + SO-PIN counter
------------------------------------------------------------

ALTER TABLE tokens
    -- Operator-facing display label. Distinct from serial_number, which is
    -- the manufacturer-assigned identifier; label is mutable and may be
    -- changed by SCMS administrators (e.g., "Smith - 2026 contractor").
    ADD COLUMN IF NOT EXISTS label VARCHAR(255),

    -- Security Officer PIN retry counter. Tracked separately from the User
    -- PIN counter (pin_attempts_remaining) per NIAP PP-CA FMT_SMR.1: SO-PIN
    -- and User PIN are distinct authentication mechanisms with independent
    -- lockout state. Default 3 matches the User PIN default.
    ADD COLUMN IF NOT EXISTS so_pin_attempts_remaining INTEGER NOT NULL DEFAULT 3,

    -- Timestamp the token was first initialized (status: uninitialized -> initialized).
    -- Distinct from created_at, which is when the inventory record was added.
    ADD COLUMN IF NOT EXISTS initialized_at TIMESTAMPTZ,

    -- Token expiration (battery limit, certificate expiry, contract end, etc.).
    -- Optional - some token models do not have a usable lifespan limit.
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_tokens_label ON tokens(label);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);

------------------------------------------------------------
-- token_models: hardware capacities + interface declaration
------------------------------------------------------------

ALTER TABLE token_models
    -- Vendor-reported firmware version (e.g. "5.4.3" for YubiKey 5).
    -- Auditors compare this against advisories to track patch level.
    ADD COLUMN IF NOT EXISTS firmware_version VARCHAR(64),

    -- Maximum number of asymmetric keys the model can hold. NULL = unknown.
    ADD COLUMN IF NOT EXISTS key_capacity INTEGER,

    -- Maximum number of certificates the model can hold. NULL = unknown.
    ADD COLUMN IF NOT EXISTS cert_capacity INTEGER,

    -- Whether this model exposes a PKCS#11 interface. Tokens that do not
    -- (e.g. some legacy USB tokens) cannot host CA signing keys, so SCMS
    -- enforces this at provisioning time.
    ADD COLUMN IF NOT EXISTS pkcs11_support BOOLEAN NOT NULL DEFAULT TRUE;

------------------------------------------------------------
-- token_keys: key size + usage flags
------------------------------------------------------------

ALTER TABLE token_keys
    -- Key size in bits. For RSA this is the modulus size; for ECDSA this is
    -- the curve size; for EdDSA this is fixed by the algorithm. Stored
    -- separately from the algorithm string so queries can filter by strength.
    ADD COLUMN IF NOT EXISTS key_size INTEGER,

    -- Permitted key usage flags as an array of strings. Allowed values
    -- mirror the X.509 KeyUsage extension bits per RFC 5280 §4.2.1.3:
    --   "digital_signature", "non_repudiation", "key_encipherment",
    --   "data_encipherment", "key_agreement", "key_cert_sign",
    --   "crl_sign", "encipher_only", "decipher_only".
    -- NIAP PP-CA FCS_COP.1 - support cryptographic key usage enforcement.
    ADD COLUMN IF NOT EXISTS usage TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE INDEX IF NOT EXISTS idx_token_keys_size ON token_keys(key_size);
