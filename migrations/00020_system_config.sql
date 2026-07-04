-- System configuration key/value store (NPE portal, CAA "System Configuration").
--
-- A small set of operator-tunable settings the CAA can view (ViewConfig) and
-- modify (ModifyConfig). Every change is attributed and audited (CM-3).
--
-- COMPLIANCE MAPPING:
--   * NIST 800-53: CM-2 (baseline configuration — seeded defaults), CM-3
--     (change control — attributed + audited), CM-6 (configuration settings),
--     AC-6 (modified only by ModifyConfig holders), SC-28 (at rest)
--   * NIAP PP-CA: FMT_SMF.1 (security management function), FMT_MTD.1

CREATE TABLE IF NOT EXISTS system_config (
    -- Stable setting key (e.g. `default_certificate_validity_days`).
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    description TEXT,
    -- Attribution for the change-control record (CM-3 / AU-3).
    updated_by  TEXT        NOT NULL DEFAULT 'system',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT system_config_key_len CHECK (length(key) BETWEEN 1 AND 128),
    CONSTRAINT system_config_value_len CHECK (length(value) <= 4096)
);

-- CM-2: baseline defaults so the management UI shows meaningful settings. These
-- are replay-safe (ON CONFLICT DO NOTHING preserves any operator edits).
INSERT INTO system_config (key, value, description) VALUES
    ('default_certificate_validity_days', '397',
     'Default certificate validity in days for new issuance.'),
    ('require_approval_for_issuance', 'true',
     'Whether certificate issuance requires Registration Authority approval.'),
    ('max_bulk_csrs', '100',
     'Maximum number of CSRs accepted in a single bulk enrollment upload.')
ON CONFLICT (key) DO NOTHING;
