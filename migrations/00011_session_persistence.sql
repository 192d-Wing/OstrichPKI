-- Persist authenticated sessions across restarts (closes the in-memory-session POA&M).
--
-- The `sessions` table was introduced in 00003 but never used; SessionManager
-- kept sessions in process memory, so a restart logged every user out and a
-- second service instance shared no session state. The DbSessionStore
-- (crates/ostrich-db/src/repository/session.rs) makes Postgres the source of
-- truth for sessions. This migration reconciles the 00003 schema with the
-- SessionManager model:
--   1. status must also represent user- and admin-initiated termination, so a
--      terminated token stays dead after a restart (not just absent from a map).
--   2. an optional metadata column for forward-compatible session attributes.
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-12 (Session Termination) - termination persists across restart
-- - NIST 800-53: SC-23 (Session Authenticity) - durable, single source of truth
-- - NIAP PP-CA: FTA_SSL.3 (TSF-initiated termination), FTA_SSL.4 (user-initiated
--   termination) - both survive a restart now that status is persisted

-- Replace the status CHECK (00003 allowed only active/locked/expired) so the
-- terminated states SessionManager produces are storable.
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS chk_sessions_status;
ALTER TABLE sessions
    ADD CONSTRAINT chk_sessions_status CHECK (
        status IN ('active', 'locked', 'expired', 'terminated', 'admin_terminated')
    );

-- Optional, forward-compatible per-session attributes (Session::metadata).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS metadata JSONB;

COMMENT ON COLUMN sessions.status IS 'Session status: active, locked, expired, terminated, admin_terminated (NIAP PP-CA: FTA_SSL.1/.3/.4)';
COMMENT ON COLUMN sessions.metadata IS 'Optional session attributes (JSON), reserved for forward compatibility';
