-- EST single-use enrollment tokens (RFC 7030 bootstrap credentials).
--
-- An operator with Permission::GenerateEstToken mints a time-limited, single-use
-- bearer token bound to a specific device identity (the CN the device must
-- enroll as). The EST server accepts the token for exactly one initial
-- enrollment, then marks it consumed.
--
-- Security:
--  * Only the SHA-256 of the token is stored (token_hash); the plaintext is
--    returned to the operator once and never persisted (treat like an API key).
--  * Single-use is enforced by `used_at` (set on successful enrollment).
--  * `identity` pins the certificate identity, enforced at enroll time by the
--    EST H1 binding (CSR CN/SAN must equal `identity`).
--
-- COMPLIANCE MAPPING:
--  * NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege),
--    IA-5 (authenticator management), AU-2 (auditable token lifecycle)
--  * NIAP PP-CA: FMT_SMF.1 / FMT_MTD.1 (management of enrollment credentials),
--    FDP_CER_EXT.1 (certificate enrollment)
CREATE TABLE IF NOT EXISTS est_enrollment_tokens (
    id          UUID PRIMARY KEY,
    -- SHA-256 of the bearer token. Unique so a (vanishingly unlikely) collision
    -- or a re-mint with the same bytes cannot create ambiguous rows.
    token_hash  BYTEA NOT NULL UNIQUE,
    -- Certificate identity (CN) the bearer is allowed to enroll as.
    identity    VARCHAR(255) NOT NULL,
    -- Optional certificate profile override for this enrollment.
    profile     VARCHAR(64),
    -- Operator (username) who minted the token, for audit attribution (AU-3).
    created_by  VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Single-use marker: NULL = unused; set to the consumption time on success.
    used_at     TIMESTAMPTZ,
    -- The certificate issued when the token was consumed (provenance).
    used_by_cert UUID REFERENCES certificates(id) ON DELETE SET NULL,
    metadata    JSONB
);

-- Fast lookup of the live (unused) token by hash during enrollment validation.
CREATE INDEX IF NOT EXISTS idx_est_enrollment_tokens_live
    ON est_enrollment_tokens (token_hash)
    WHERE used_at IS NULL;

-- Operator listing of outstanding tokens by recency.
CREATE INDEX IF NOT EXISTS idx_est_enrollment_tokens_created_at
    ON est_enrollment_tokens (created_at DESC);
