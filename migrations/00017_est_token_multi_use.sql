-- Multi-use EST enrollment tokens.
--
-- The original token model (migration 00013) is strictly single-use: a token is
-- consumed by setting `used_at` on first enrollment. The NPE portal's Password
-- Management screen offers a "Multiple Devices" mode (a token that several
-- devices may enroll with, e.g. a fleet bootstrap), so a token now carries a
-- use budget.
--
-- Backward compatibility: existing rows are single-use. The new columns default
-- to 1, so every previously-issued token keeps exactly one remaining use, and
-- the consume path (decrement-then-mark-exhausted) behaves identically to the
-- old single-use UPDATE for them.
--
-- Semantics:
--   * `max_uses`       — the budget the token was minted with (audit/provenance).
--   * `uses_remaining` — decremented on each successful enrollment; the token is
--                        "live" while > 0. `used_at` is stamped when it reaches 0
--                        (or on revoke), preserving the existing "used"/"revoked"
--                        status derivation.
--
-- COMPLIANCE MAPPING:
--   * NIST 800-53: IA-5 (authenticator management — bounded, time-limited),
--     AC-6 (least privilege — identity still pinned), AU-2 (auditable lifecycle)
--   * NIAP PP-CA: FMT_SMF.1 / FMT_MTD.1 (management of enrollment credentials)
ALTER TABLE est_enrollment_tokens
    ADD COLUMN IF NOT EXISTS max_uses       INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS uses_remaining INTEGER NOT NULL DEFAULT 1;

-- Guard rails: a token must have a positive budget and never go negative.
ALTER TABLE est_enrollment_tokens
    ADD CONSTRAINT est_token_max_uses_positive CHECK (max_uses >= 1),
    ADD CONSTRAINT est_token_uses_remaining_nonneg CHECK (uses_remaining >= 0);

-- Replace the live-token lookup index: "live" now means uses remain (not just
-- "used_at IS NULL"). The old partial index keyed on `used_at IS NULL`; a
-- multi-use token has `used_at IS NULL` until exhausted, so that predicate would
-- still work, but indexing on the actual liveness condition keeps lookups exact.
DROP INDEX IF EXISTS idx_est_enrollment_tokens_live;
CREATE INDEX IF NOT EXISTS idx_est_enrollment_tokens_live
    ON est_enrollment_tokens (token_hash)
    WHERE uses_remaining > 0;
