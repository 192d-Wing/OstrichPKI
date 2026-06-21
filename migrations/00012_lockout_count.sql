-- DB-authoritative account lockout: track consecutive lockouts so the
-- permanent-lockout policy (LockoutConfig.lockouts_before_permanent) can be
-- enforced from the database instead of the in-memory AuthLockout.
--
-- The temporary-lockout fields (failed_attempts, locked_until) already exist
-- (migration 00003). This adds the escalation counter; when it reaches the
-- configured threshold and permanent lockout is enabled, the account is moved
-- to status='locked' (administrator unlock required).
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - single, persistent
--   source of truth for lockout state
-- - NIAP PP-CA: FIA_AFL.1 (Authentication Failure Handling)

ALTER TABLE users ADD COLUMN IF NOT EXISTS lockout_count INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN users.lockout_count IS 'Consecutive temporary lockouts since last successful login; drives permanent-lockout escalation (NIAP PP-CA: FIA_AFL.1)';
