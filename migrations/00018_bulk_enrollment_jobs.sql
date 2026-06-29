-- Bulk certificate enrollment jobs (NPE portal, Administrator "Submit Bulk").
--
-- An Administrator uploads a ZIP of CSRs under a single certificate profile; the
-- server records one job row plus one item row per CSR, so the per-CSR outcome
-- (validated/queued/failed) is durable and the result is downloadable later by
-- the submitter.
--
-- COMPLIANCE MAPPING:
--   * NIST 800-53: AU-2 (auditable bulk operation — submitter + per-CSR outcome
--     recorded), AC-3/AC-6 (submitter identity owns the job; own-scope reads),
--     SI-10 (each CSR validated before a request is created), SC-28 (at rest)
--   * NIAP PP-CA: FDP_CER_EXT.2 (CSR -> request linkage per item),
--     FDP_CER_EXT.3 (request workflow state), FAU_GEN.1 (auditable generation)

CREATE TABLE IF NOT EXISTS bulk_enrollment_jobs (
    id              UUID PRIMARY KEY,
    -- Human-facing "Bulk Identifier" handed back to the submitter.
    bulk_identifier TEXT        NOT NULL UNIQUE,
    -- Authenticated submitter (own-scope: only the submitter or an approver may
    -- read the job). Stored by id + username for audit (AU-3).
    submitter_id    UUID        NOT NULL,
    submitter_username TEXT     NOT NULL,
    -- The single issuance profile applied to every CSR in the batch.
    profile_name    TEXT        NOT NULL,
    -- Lifecycle: pending -> processing -> completed (terminal). A job is never
    -- silently dropped; a crash leaves it non-terminal for recovery/inspection.
    status          TEXT        NOT NULL DEFAULT 'pending',
    total_count     INTEGER     NOT NULL DEFAULT 0,
    succeeded_count INTEGER     NOT NULL DEFAULT 0,
    failed_count    INTEGER     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    CONSTRAINT bulk_job_counts_nonneg
        CHECK (total_count >= 0 AND succeeded_count >= 0 AND failed_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_bulk_enrollment_jobs_submitter
    ON bulk_enrollment_jobs (submitter_id, created_at DESC);

CREATE TABLE IF NOT EXISTS bulk_enrollment_items (
    id              UUID PRIMARY KEY,
    job_id          UUID        NOT NULL
        REFERENCES bulk_enrollment_jobs (id) ON DELETE CASCADE,
    -- 0-based position of the CSR within the uploaded ZIP, for stable ordering
    -- and to correlate a result row with its source file.
    item_index      INTEGER     NOT NULL,
    -- Source file name from the ZIP entry (informational, for the result sheet).
    source_name     TEXT        NOT NULL,
    -- Subject CN parsed from the CSR (NULL when the CSR failed to parse).
    subject_cn      TEXT,
    -- Per-CSR outcome: validated, queued, issued, or failed.
    status          TEXT        NOT NULL,
    -- The approval request created for a queued CSR (FDP_CER_EXT.2 linkage).
    request_id      UUID,
    -- The certificate issued for an auto-issued CSR (when applicable).
    certificate_id  UUID,
    -- Failure detail for a failed CSR (validation/issuance error); NULL on success.
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT bulk_item_index_nonneg CHECK (item_index >= 0),
    CONSTRAINT bulk_item_unique_index UNIQUE (job_id, item_index)
);

CREATE INDEX IF NOT EXISTS idx_bulk_enrollment_items_job
    ON bulk_enrollment_items (job_id, item_index);
