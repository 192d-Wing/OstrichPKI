-- Migration 00016: FQDN indexing + renewal-notification contact
--
-- Backs the "FQDN record" feature: a per-DNS-name history view that lists every
-- certificate ever issued for a given fully-qualified domain name.
--
-- Two additions:
--   1. `certificate_sans` — a queryable index of the DNS names each certificate
--      covers. SANs are otherwise locked inside the DER blob (no column/index),
--      so "find all certs for qemu-node-001.oopl.dev.mil" was impossible. This
--      table is populated at issuance (all paths flow through the certificate
--      repository's create()) and backfilled for pre-existing certs at startup.
--      Names are stored lowercased (DNS is case-insensitive) and cover both the
--      Subject Alternative Name dnsNames and the Subject CN when it is a hostname.
--   2. `fqdn_notification` — an operator-set renewal-notification contact email
--      per FQDN. Storage + display only; no mail is sent (no mailer exists yet).
--
-- COMPLIANCE MAPPING:
--   NIST 800-53: CM-3 (Configuration Change Control) - versioned schema change
--   NIST 800-53: AU-3 (Audit content) - updated_by/updated_at attribution
--   NIST 800-53: SC-17 / RFC 5280 §4.2.1.6 - SubjectAltName is the authoritative
--                identity binding being indexed here
--   NIAP PP-CA: FMT_MTD.1 (Management of TSF data) - renewal-contact management

-- 1. Queryable SAN / CN index ------------------------------------------------
CREATE TABLE IF NOT EXISTS certificate_sans (
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    -- Lowercased DNS name (SAN dnsName) or Subject CN hostname.
    name           TEXT NOT NULL,
    -- 'dnsName' | 'commonName' (provenance of the name; informational).
    name_type      VARCHAR(20) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One row per (cert, name): a name appearing as both CN and SAN collapses.
    PRIMARY KEY (certificate_id, name)
);

COMMENT ON TABLE certificate_sans IS
    'Queryable index of the DNS names (SAN dnsNames + hostname CNs) each '
    'certificate covers, populated at issuance and backfilled at startup. '
    'Enables per-FQDN certificate history (RFC 5280 §4.2.1.6).';

-- Lookups are by name ("all certs for this FQDN") and for the distinct-FQDN list.
CREATE INDEX IF NOT EXISTS idx_cert_sans_name ON certificate_sans(name);

-- 2. Per-FQDN renewal-notification contact -----------------------------------
CREATE TABLE IF NOT EXISTS fqdn_notification (
    -- Lowercased FQDN this contact applies to.
    fqdn       TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    -- Actor who last set the contact (AU-3 attribution).
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE fqdn_notification IS
    'Operator-set renewal-notification contact email per FQDN. Storage and '
    'display only; no mail is sent yet (FMT_MTD.1).';
