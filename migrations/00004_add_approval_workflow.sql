-- Migration: Add Approval Workflow Tables
-- Date: 2026-01-04
-- Phase: 18 - Certificate Request Approval System
--
-- COMPLIANCE MAPPING:
-- - NIAP PP-CA: FDP_CER_EXT.2 - Certificate request linkage to issued certificates
-- - NIAP PP-CA: FDP_CER_EXT.3 - Certificate request approval workflow
-- - NIAP PP-CA: FDP_SEPP.1 - Segregation of duties (requestor ≠ approver)
-- - NIST 800-53: AC-5 - Separation of Duties
-- - NIST 800-53: AU-2 - Auditable Events (approval decisions)

-- ============================================================================
-- Approval Requests Table
-- ============================================================================
-- Tracks certificate-related requests requiring approval
CREATE TABLE IF NOT EXISTS approval_requests (
    id UUID PRIMARY KEY,

    -- Request identification
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('issuance', 'revocation', 'renewal')),

    -- Linkage to certificate operations (FDP_CER_EXT.2)
    csr_id UUID REFERENCES certificate_requests(id) ON DELETE SET NULL,
    certificate_id UUID REFERENCES certificates(id) ON DELETE SET NULL,

    -- Requestor information (FDP_SEPP.1 - segregation of duties)
    requestor_id UUID NOT NULL REFERENCES users(id),
    requestor_username VARCHAR(255) NOT NULL,
    requestor_roles TEXT[] NOT NULL DEFAULT '{}',

    -- Request status
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'completed')),

    -- Request details (JSON for flexibility)
    request_details JSONB NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Metadata
    metadata JSONB,

    CONSTRAINT valid_timestamps CHECK (expires_at > created_at),
    CONSTRAINT approved_requires_approval CHECK (
        (status = 'approved' AND approved_at IS NOT NULL) OR
        (status != 'approved')
    )
);

-- Indexes for performance
CREATE INDEX idx_approval_requests_status ON approval_requests(status);
CREATE INDEX idx_approval_requests_requestor ON approval_requests(requestor_id);
CREATE INDEX idx_approval_requests_type ON approval_requests(request_type);
CREATE INDEX idx_approval_requests_created ON approval_requests(created_at DESC);
CREATE INDEX idx_approval_requests_expires ON approval_requests(expires_at) WHERE status = 'pending';

-- Index for CSR linkage (FDP_CER_EXT.2)
CREATE INDEX idx_approval_requests_csr ON approval_requests(csr_id) WHERE csr_id IS NOT NULL;
CREATE INDEX idx_approval_requests_cert ON approval_requests(certificate_id) WHERE certificate_id IS NOT NULL;

-- ============================================================================
-- Approval Decisions Table
-- ============================================================================
-- Tracks individual approval/rejection decisions by authorized personnel
CREATE TABLE IF NOT EXISTS approval_decisions (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,

    -- Approver information (FDP_SEPP.1 - must be different from requestor)
    approver_id UUID NOT NULL REFERENCES users(id),
    approver_username VARCHAR(255) NOT NULL,
    approver_roles TEXT[] NOT NULL DEFAULT '{}',

    -- Decision
    decision VARCHAR(50) NOT NULL CHECK (decision IN ('approved', 'rejected', 'needs_info', 'deferred')),
    reason TEXT,
    justification TEXT,

    -- Timestamps
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Metadata
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX idx_approval_decisions_request ON approval_decisions(request_id);
CREATE INDEX idx_approval_decisions_approver ON approval_decisions(approver_id);
CREATE INDEX idx_approval_decisions_decision ON approval_decisions(decision);
CREATE INDEX idx_approval_decisions_decided ON approval_decisions(decided_at DESC);

-- Prevent duplicate decisions from same approver on same request
CREATE UNIQUE INDEX idx_approval_decisions_unique ON approval_decisions(request_id, approver_id);

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE approval_requests IS 'Certificate request approval workflow - FDP_CER_EXT.3';
COMMENT ON COLUMN approval_requests.request_type IS 'Type of certificate operation requiring approval';
COMMENT ON COLUMN approval_requests.csr_id IS 'Linkage to CSR for traceability - FDP_CER_EXT.2';
COMMENT ON COLUMN approval_requests.certificate_id IS 'Linkage to issued certificate - FDP_CER_EXT.2';
COMMENT ON COLUMN approval_requests.requestor_id IS 'User who submitted the request - FDP_SEPP.1';
COMMENT ON COLUMN approval_requests.status IS 'Current state of approval workflow';
COMMENT ON COLUMN approval_requests.expires_at IS 'Request expiration time (configurable, default 7 days)';

COMMENT ON TABLE approval_decisions IS 'Individual approval decisions - supports multi-person approval';
COMMENT ON COLUMN approval_decisions.approver_id IS 'User who made approval decision - must differ from requestor per FDP_SEPP.1';
COMMENT ON COLUMN approval_decisions.decision IS 'Approval decision: approved, rejected, needs_info, deferred';
COMMENT ON COLUMN approval_decisions.justification IS 'Detailed justification for approval decision - required for audit';
