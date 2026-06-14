-- EST per-account allowed identities
--
-- Backs the "account allow-list" EST enrollment identity policy: an account may
-- only enroll for certificates whose asserted identities (subject CommonName and
-- SubjectAltName values) appear in its allow-list. This supports delegated
-- enrollment (e.g. an RA account provisioned to request several device names),
-- which the default "username must appear in the certificate" policy does not.
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-3 (access enforcement), AC-6 (least privilege)
-- - NIAP PP-CA: FDP_ACC.1 / FDP_ACF.1 - access control on issuance identity

CREATE TABLE est_account_identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_username VARCHAR(255) NOT NULL,
    -- A CommonName or SubjectAltName value (prefix-stripped, e.g. "device-42.example.com")
    -- this account is permitted to request.
    allowed_identity VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_username, allowed_identity)
);

CREATE INDEX idx_est_account_identities_user ON est_account_identities(account_username);
