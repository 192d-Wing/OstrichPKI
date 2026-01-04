-- Add metadata fields to certificates table for service integration
--
-- NIST 800-53: AU-3 - Audit record content
-- NIST 800-53: AC-3 - Access enforcement tracking

-- Add columns to track which service issued the certificate
ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS issuer_service VARCHAR(50), -- 'CA', 'ACME', 'EST', 'SCMS'
ADD COLUMN IF NOT EXISTS requestor VARCHAR(255), -- Who requested the certificate
ADD COLUMN IF NOT EXISTS profile_name VARCHAR(255), -- Which profile was used
ADD COLUMN IF NOT EXISTS metadata JSONB; -- Service-specific metadata

-- Create index for querying by issuer service
CREATE INDEX IF NOT EXISTS idx_certs_issuer_service ON certificates(issuer_service);
CREATE INDEX IF NOT EXISTS idx_certs_requestor ON certificates(requestor);
CREATE INDEX IF NOT EXISTS idx_certs_profile ON certificates(profile_name);

-- Add foreign key to link profile name to certificate_profiles table
-- Note: We use profile_name as a string instead of FK to allow flexibility
-- for certificates issued before profile was created or with custom parameters

COMMENT ON COLUMN certificates.issuer_service IS 'Service that issued this certificate: CA (direct), ACME, EST, or SCMS';
COMMENT ON COLUMN certificates.requestor IS 'Identity of requestor (ACME account ID, EST client ID, SCMS user ID, etc.)';
COMMENT ON COLUMN certificates.profile_name IS 'Certificate profile used for issuance';
COMMENT ON COLUMN certificates.metadata IS 'Service-specific metadata (JSON): ACME order ID, EST enrollment ID, SCMS token serial, etc.';

-- Add column to ACME orders to track CSR
ALTER TABLE acme_orders
ADD COLUMN IF NOT EXISTS csr_der BYTEA; -- Final CSR submitted for certificate issuance

COMMENT ON COLUMN acme_orders.csr_der IS 'DER-encoded CSR submitted in finalize request (RFC 8555 §7.4)';

-- Add column to track certificate profile for EST enrollments
ALTER TABLE est_enrollments
ADD COLUMN IF NOT EXISTS profile_name VARCHAR(255);

COMMENT ON COLUMN est_enrollments.profile_name IS 'Certificate profile used for this enrollment';

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_acme_orders_certificate ON acme_orders(certificate_id);
CREATE INDEX IF NOT EXISTS idx_est_enrollments_certificate ON est_enrollments(certificate_id);
