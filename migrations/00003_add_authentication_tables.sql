-- Add authentication and authorization tables
--
-- NIAP PP-CA v2.1:
-- - FIA_UID.1: User Identification - unique user identifiers
-- - FIA_UAU.1: User Authentication - credential storage
-- - FMT_SMR.2: Security Management Roles - role assignment
-- - FIA_AFL.1: Authentication Failure Handling - lockout tracking
--
-- NIST 800-53 Rev 5:
-- - IA-2: Identification and Authentication - user accounts
-- - IA-4: Identifier Management - unique user IDs
-- - IA-5: Authenticator Management - password/certificate storage
-- - AC-2: Account Management - account lifecycle
-- - AC-7: Unsuccessful Login Attempts - failed attempt tracking
-- - FMT_MTD.1: TSF Data Access Control - role-based permissions

-- ============================================================================
-- Users Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    -- Unique user identifier (UUID v4)
    -- NIAP PP-CA: FIA_UID.1.1 - Each user has unique identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Username (human-readable identifier, unique)
    -- NIAP PP-CA: FIA_UID.1 - User identification
    username VARCHAR(255) UNIQUE NOT NULL,

    -- Display name (optional, for UI)
    display_name VARCHAR(255),

    -- Email address (optional)
    email VARCHAR(255),

    -- Password hash (Argon2id)
    -- NIAP PP-CA: FIA_UAU.1 - Password authentication
    -- NIST 800-53: IA-5 - Authenticator management
    -- NULL if user only authenticates via certificate
    password_hash VARCHAR(255),

    -- Certificate subject DN (for certificate-based auth)
    -- NIAP PP-CA: FIA_UAU.1 - Certificate authentication
    -- NULL if user only authenticates via password
    certificate_subject VARCHAR(500),

    -- Assigned roles (array)
    -- NIAP PP-CA: FMT_SMR.2 - Role assignment
    -- Values: 'administrator', 'auditor', 'operations_staff', 'ra_staff', 'aor'
    roles TEXT[] NOT NULL DEFAULT '{}',

    -- Account status
    -- NIAP PP-CA: FIA_AFL.1 - Account lockout
    -- NIST 800-53: AC-2 - Account status tracking
    -- Values: 'active', 'locked', 'suspended', 'disabled', 'pending_activation'
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    -- Account creation timestamp
    -- NIST 800-53: AC-2 - Account lifecycle tracking
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Last modification timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Last successful login
    -- NIST 800-53: AC-2 - Login activity tracking
    last_login_at TIMESTAMPTZ,

    -- Account locked until (NULL if not locked or locked indefinitely)
    -- NIAP PP-CA: FIA_AFL.1.2 - Lockout duration
    locked_until TIMESTAMPTZ,

    -- Failed login attempt count (since last success)
    -- NIAP PP-CA: FIA_AFL.1.1 - Failed attempt tracking
    failed_attempts INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT chk_users_auth_method CHECK (
        -- User must have at least one authentication method
        password_hash IS NOT NULL OR certificate_subject IS NOT NULL
    ),

    CONSTRAINT chk_users_status CHECK (
        status IN ('active', 'locked', 'suspended', 'disabled', 'pending_activation')
    ),

    CONSTRAINT chk_users_failed_attempts CHECK (
        failed_attempts >= 0
    )
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_certificate_subject ON users(certificate_subject) WHERE certificate_subject IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);

-- Index for role-based queries (GIN index for array contains)
CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);

-- Comments
COMMENT ON TABLE users IS 'User accounts for authentication and authorization (NIAP PP-CA: FIA_UID.1, FIA_UAU.1, FMT_SMR.2)';
COMMENT ON COLUMN users.id IS 'Unique user identifier (UUID v4) - NIAP PP-CA: FIA_UID.1.1';
COMMENT ON COLUMN users.username IS 'Unique username for identification';
COMMENT ON COLUMN users.password_hash IS 'Argon2id password hash (NULL for certificate-only auth) - NIAP PP-CA: FIA_UAU.1';
COMMENT ON COLUMN users.certificate_subject IS 'X.509 certificate subject DN (RFC 4514) for mTLS auth';
COMMENT ON COLUMN users.roles IS 'Assigned security roles (NIAP PP-CA defined) - FMT_SMR.2';
COMMENT ON COLUMN users.status IS 'Account status: active, locked, suspended, disabled, pending_activation';
COMMENT ON COLUMN users.locked_until IS 'Account locked until timestamp (NIAP PP-CA: FIA_AFL.1.2)';
COMMENT ON COLUMN users.failed_attempts IS 'Failed login attempts since last success (NIAP PP-CA: FIA_AFL.1.1)';

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    -- Unique session identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Session token (for authentication, random string)
    -- Indexed for fast lookup
    token VARCHAR(255) UNIQUE NOT NULL,

    -- User identifier
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Session status
    -- Values: 'active', 'locked', 'expired'
    -- NIAP PP-CA: FTA_SSL.1 - Session status tracking
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    -- User's IP address (optional)
    ip_address VARCHAR(45), -- IPv6 max length

    -- User agent string (optional)
    user_agent TEXT,

    -- Session creation timestamp
    -- NIAP PP-CA: FTA_SSL.1 - Session establishment time
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Last activity timestamp
    -- NIAP PP-CA: FTA_SSL.1 - Session inactivity tracking
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Session expiration timestamp (absolute)
    -- NIAP PP-CA: FTA_SSL.3 - TSF-initiated session termination
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT chk_sessions_status CHECK (
        status IN ('active', 'locked', 'expired')
    ),

    CONSTRAINT chk_sessions_expires_after_created CHECK (
        expires_at > created_at
    )
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Comments
COMMENT ON TABLE sessions IS 'Active user sessions (NIAP PP-CA: FTA_SSL.1, FTA_SSL.3)';
COMMENT ON COLUMN sessions.token IS 'Session token for authentication (random string)';
COMMENT ON COLUMN sessions.status IS 'Session status: active, locked, expired';
COMMENT ON COLUMN sessions.expires_at IS 'Absolute session expiration time (NIAP PP-CA: FTA_SSL.3)';
COMMENT ON COLUMN sessions.last_activity IS 'Last activity timestamp for inactivity timeout (NIAP PP-CA: FTA_SSL.1)';

-- ============================================================================
-- Approval Requests Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS approval_requests (
    -- Unique request identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Request type
    -- Values: 'issuance', 'revocation', 'renewal'
    -- NIAP PP-CA: FDP_CER_EXT.3 - Approval workflow
    request_type VARCHAR(50) NOT NULL,

    -- CSR ID (for issuance/renewal requests)
    -- TODO: Add FK to certificate_requests table when implemented
    csr_id UUID,

    -- Certificate ID (for revocation requests)
    certificate_id UUID REFERENCES certificates(id) ON DELETE CASCADE,

    -- Requestor user ID
    -- NIAP PP-CA: FDP_SEPP.1 - Separation of requestor and approver
    requestor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Request status
    -- Values: 'pending', 'approved', 'rejected', 'expired', 'completed'
    status VARCHAR(50) NOT NULL DEFAULT 'pending',

    -- Request creation timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Request expiration timestamp
    -- Requests auto-expire if not approved within time limit
    expires_at TIMESTAMPTZ NOT NULL,

    -- Completion timestamp (when certificate issued/revoked)
    completed_at TIMESTAMPTZ,

    -- Request details (JSON)
    -- Contains request-specific data (e.g., revocation reason, renewal parameters)
    details JSONB,

    CONSTRAINT chk_approval_requests_type CHECK (
        request_type IN ('issuance', 'revocation', 'renewal')
    ),

    CONSTRAINT chk_approval_requests_status CHECK (
        status IN ('pending', 'approved', 'rejected', 'expired', 'completed')
    ),

    CONSTRAINT chk_approval_requests_expires_after_created CHECK (
        expires_at > created_at
    )
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_requestor ON approval_requests(requestor_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_csr ON approval_requests(csr_id) WHERE csr_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_requests_certificate ON approval_requests(certificate_id) WHERE certificate_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_requests_expires_at ON approval_requests(expires_at);

-- Comments
COMMENT ON TABLE approval_requests IS 'Certificate request approval workflow (NIAP PP-CA: FDP_CER_EXT.3)';
COMMENT ON COLUMN approval_requests.request_type IS 'Type of request: issuance, revocation, renewal';
COMMENT ON COLUMN approval_requests.requestor_id IS 'User who submitted the request (NIAP PP-CA: FDP_SEPP.1)';
COMMENT ON COLUMN approval_requests.status IS 'Request status: pending, approved, rejected, expired, completed';
COMMENT ON COLUMN approval_requests.expires_at IS 'Request expiration time (auto-reject if not approved)';

-- ============================================================================
-- Approval Decisions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS approval_decisions (
    -- Unique decision identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Approval request ID
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,

    -- Approver user ID
    -- NIAP PP-CA: FDP_SEPP.1 - Approver must be different from requestor
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Decision
    -- Values: 'approved', 'rejected', 'needs_info'
    decision VARCHAR(50) NOT NULL,

    -- Decision reason/comment (optional)
    reason TEXT,

    -- Decision timestamp
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_approval_decisions_decision CHECK (
        decision IN ('approved', 'rejected', 'needs_info')
    )
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_approval_decisions_request ON approval_decisions(request_id);
CREATE INDEX IF NOT EXISTS idx_approval_decisions_approver ON approval_decisions(approver_id);
CREATE INDEX IF NOT EXISTS idx_approval_decisions_decided_at ON approval_decisions(decided_at);

-- Comments
COMMENT ON TABLE approval_decisions IS 'Approval decisions for certificate requests (NIAP PP-CA: FDP_CER_EXT.3)';
COMMENT ON COLUMN approval_decisions.approver_id IS 'User who made the decision (must differ from requestor - NIAP PP-CA: FDP_SEPP.1)';
COMMENT ON COLUMN approval_decisions.decision IS 'Decision: approved, rejected, needs_info';

-- ============================================================================
-- Trigger Functions
-- ============================================================================

-- Update updated_at timestamp on user modification
CREATE OR REPLACE FUNCTION update_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_users_updated_at();

-- ============================================================================
-- Seed Data (Development/Testing)
-- ============================================================================

-- Default admin user (password: 'admin', Argon2id hash)
-- WARNING: Change password in production!
-- This is the Argon2id hash for 'admin' with default parameters
INSERT INTO users (username, display_name, password_hash, roles, status)
VALUES (
    'admin',
    'Default Administrator',
    '$argon2id$v=19$m=19456,t=2,p=1$aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u$vW3xY4zA5bC6dD7eE8fF9gG0hH1iI2j',
    ARRAY['administrator'],
    'active'
)
ON CONFLICT (username) DO NOTHING;

-- Default auditor user (certificate-only auth)
-- Must configure certificate_subject DN after first login
INSERT INTO users (username, display_name, certificate_subject, roles, status)
VALUES (
    'auditor',
    'Default Auditor',
    'CN=auditor,OU=Auditors,O=OstrichPKI,C=US',
    ARRAY['auditor'],
    'active'
)
ON CONFLICT (username) DO NOTHING;
