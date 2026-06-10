-- Migration 00008: certificate -> request linkage (FDP_CER_EXT.2)
--
-- Adds a request_id to each issued certificate so every certificate is traceable
-- back to the request that produced it. The same request_id is recorded on the
-- issuance audit event, giving end-to-end traceability:
--   request_id  <->  certificate row  <->  issuance audit event.
--
-- The column is nullable: certificates issued before this migration have no
-- request_id, and a caller (ACME order, EST enrollment, direct API) MAY supply
-- its own request identifier; when absent the CA generates one at issuance.
--
-- COMPLIANCE MAPPING:
--   NIAP PP-CA: FDP_CER_EXT.2 (Certificate Request Linkage)
--   NIST 800-53: AU-3 (Audit content), AU-10 (Non-repudiation - request binding)
--   NIST 800-53: CM-3 (Configuration Change Control)

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS request_id UUID;

COMMENT ON COLUMN certificates.request_id IS
    'Identifier of the request that produced this certificate (ACME order, EST '
    'enrollment, or CA-generated); recorded on the issuance audit event for '
    'end-to-end traceability (FDP_CER_EXT.2).';

-- Index for tracing certificates by request.
CREATE INDEX IF NOT EXISTS idx_certs_request_id ON certificates(request_id);
