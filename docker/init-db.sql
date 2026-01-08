-- OstrichPKI Database Initialization Script
--
-- This script creates the required schemas and extensions for:
-- - OstrichPKI application tables
-- - Keycloak identity provider
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: CM-2 (Baseline Configuration)
-- - NIST 800-53: AU-9 (Protection of Audit Information)

-- Create schemas
CREATE SCHEMA IF NOT EXISTS keycloak;
CREATE SCHEMA IF NOT EXISTS audit;

-- Grant permissions
GRANT ALL ON SCHEMA keycloak TO ostrich;
GRANT ALL ON SCHEMA audit TO ostrich;

-- Create UUID extension if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Audit log table for Web UI operations
-- NIST 800-53: AU-3 (Content of Audit Records)
CREATE TABLE IF NOT EXISTS audit.web_ui_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(255),
    username VARCHAR(255),
    client_ip VARCHAR(45),
    user_agent TEXT,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    event_type VARCHAR(50),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient audit log queries
CREATE INDEX IF NOT EXISTS idx_web_ui_events_timestamp ON audit.web_ui_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_web_ui_events_user_id ON audit.web_ui_events(user_id);
CREATE INDEX IF NOT EXISTS idx_web_ui_events_request_id ON audit.web_ui_events(request_id);

-- Comment on audit table
COMMENT ON TABLE audit.web_ui_events IS 'Web UI audit log - NIST 800-53 AU-2, AU-3, NIAP FAU_GEN.1';
