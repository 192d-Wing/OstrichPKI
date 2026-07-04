-- Certificate namespace / wildcard policy (NPE portal, CAA "Wildcard Management").
--
-- A namespace rule allows or denies issuance for subject/SAN names matching a
-- DNS pattern (e.g. `*.example.mil` or `app.example.mil`). The CAA curates this
-- list. (Enforcing the rules in the issuance validation path is the follow-up
-- integration; this milestone delivers the curated policy store + management.)
--
-- COMPLIANCE MAPPING:
--   * NIST 800-53: CM-3 (configuration change control — audited, attributed),
--     AC-3/AC-6 (managed only by holders of ManageNamespaces), SI-10 (validated
--     pattern input), SC-28 (at rest)
--   * NIAP PP-CA: FMT_SMF.1 (security management function), FDP_ACF.1
--     (name-based issuance constraint)

CREATE TABLE IF NOT EXISTS namespaces (
    id          UUID PRIMARY KEY,
    -- DNS name pattern. A leading `*.` denotes a wildcard over one or more
    -- labels of the suffix; otherwise an exact name. Stored lowercased.
    pattern     TEXT        NOT NULL UNIQUE,
    -- true = names matching `pattern` are permitted; false = explicitly denied.
    allow       BOOLEAN     NOT NULL DEFAULT true,
    description TEXT,
    -- Attribution for the change-control record (CM-3 / AU-3).
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- DNS names are at most 253 octets (RFC 1035); enforce at the DB too so the
    -- bound holds even if a future caller skips the application-layer validator.
    CONSTRAINT namespace_pattern_len CHECK (length(pattern) BETWEEN 1 AND 253)
);

CREATE INDEX IF NOT EXISTS idx_namespaces_pattern ON namespaces (pattern);
