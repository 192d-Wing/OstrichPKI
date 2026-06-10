-- Migration 00009: delta CRL support (RFC 5280 §5.2.4)
--
-- A delta CRL lists only the revocations added since a base (full) CRL, so
-- relying parties can fetch small, frequent updates between full CRLs. Delta
-- and full CRLs share the same monotonic crl_number sequence (RFC 5280 §5.2.3).
--
-- `is_delta`        marks a row as a delta CRL.
-- `base_crl_number` is the crl_number of the full CRL the delta is relative to
--                   (the BaseCRLNumber carried in the Delta CRL Indicator, §5.2.4).
--
-- COMPLIANCE MAPPING:
--   RFC 5280 §5.2.4 (Delta CRL Indicator), §5.2.6 (Freshest CRL)
--   NIST 800-53: SC-17 (PKI certificate status), CM-3 (change control)

ALTER TABLE crls
    ADD COLUMN IF NOT EXISTS is_delta BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS base_crl_number BIGINT;

-- Serve the latest full / latest delta CRL efficiently.
CREATE INDEX IF NOT EXISTS idx_crls_ca_delta_number
    ON crls (ca_id, is_delta, crl_number DESC);
