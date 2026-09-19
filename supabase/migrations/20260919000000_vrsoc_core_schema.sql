-- =============================================================================
-- VRSOC Enterprise Security Operations Center — Core Database Schema
-- Target: Supabase PostgreSQL (PostgreSQL 15+)
-- Version: 1.0.0
-- =============================================================================

-- Enable UUID and Cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. IDENTITIES, ORGANIZATIONS & RBAC
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    vr_soc_key CHAR(14) UNIQUE NOT NULL, -- Exactly 14-character hexadecimal security key
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    retention_days INT NOT NULL DEFAULT 90,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY, -- References auth.users(id)
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'SOC Analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'SOC Analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 2. ENDPOINT AGENTS & HEALTH
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os VARCHAR(100) NOT NULL,
    os_version VARCHAR(100),
    architecture VARCHAR(50) NOT NULL DEFAULT 'x64',
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(50),
    agent_version VARCHAR(50) NOT NULL DEFAULT '1.4.0',
    enrollment_key CHAR(14) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'online', -- online, offline, updating, error, revoked
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cpu_usage NUMERIC(5,2) DEFAULT 0,
    ram_usage NUMERIC(5,2) DEFAULT 0,
    disk_usage NUMERIC(5,2) DEFAULT 0,
    tags TEXT[] DEFAULT '{}',
    policy JSONB DEFAULT '{}'::jsonb,
    health VARCHAR(50) DEFAULT 'healthy',
    environment VARCHAR(50) NOT NULL DEFAULT 'production', -- production, training, test
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cpu_percent NUMERIC(5,2),
    ram_percent NUMERIC(5,2),
    disk_percent NUMERIC(5,2),
    active_processes_count INT,
    network_connections_count INT,
    heartbeat_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. TELEMETRY & EVENTS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS endpoint_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- process, file, network, auth, dns, registry, service, usb
    event_time TIMESTAMPTZ NOT NULL,
    ingestion_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(100) NOT NULL DEFAULT 'vrsoc-agent',
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    severity VARCHAR(50) NOT NULL DEFAULT 'info',
    data JSONB NOT NULL,
    schema_version VARCHAR(20) NOT NULL DEFAULT '1.0'
);

-- -----------------------------------------------------------------------------
-- 4. DETECTION RULES & ALERTS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(100) PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE, -- NULL for global system rules
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    risk_score INT NOT NULL DEFAULT 50,
    category VARCHAR(100) NOT NULL,
    mitre_tactic VARCHAR(100) NOT NULL,
    mitre_technique_id VARCHAR(50) NOT NULL,
    mitre_technique_name VARCHAR(255) NOT NULL,
    conditions JSONB NOT NULL,
    remediation_steps TEXT[] DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(100) PRIMARY KEY, -- ALT-YYYYMMDD-XXXX
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium', -- critical, high, medium, low, informational
    risk_score INT NOT NULL DEFAULT 50,
    status VARCHAR(50) NOT NULL DEFAULT 'open', -- open, investigating, contained, resolved, false_positive
    hostname VARCHAR(255),
    username VARCHAR(255),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(255),
    mitre_id VARCHAR(50),
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    trigger_event_ids UUID[] DEFAULT '{}',
    ai_summary JSONB,
    assigned_to UUID REFERENCES profiles(id) ON DELETE SET NULL,
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id VARCHAR(100) NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    comment TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 5. INCIDENTS & CASE MANAGEMENT
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(100) PRIMARY KEY, -- INC-YYYYMMDD-XXXX
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    status VARCHAR(50) NOT NULL DEFAULT 'open', -- open, investigating, contained, resolved, false_positive
    priority VARCHAR(50) NOT NULL DEFAULT 'P2',
    lead_investigator UUID REFERENCES profiles(id) ON DELETE SET NULL,
    summary_report JSONB,
    lessons_learned TEXT,
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id VARCHAR(100) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id VARCHAR(100) NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(100) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_title VARCHAR(255) NOT NULL,
    event_description TEXT,
    event_type VARCHAR(50) NOT NULL DEFAULT 'observation',
    evidence_state VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED' -- CONFIRMED, INFERRED, UNKNOWN
);

CREATE TABLE IF NOT EXISTS incident_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(100) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    assigned_to UUID REFERENCES profiles(id) ON DELETE SET NULL,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    due_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. PHISHGUARD ML SCANS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS phishing_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    classification VARCHAR(50) NOT NULL, -- Safe, Suspicious, Phishing
    risk_score INT NOT NULL,
    features JSONB NOT NULL,
    reasons TEXT[] DEFAULT '{}',
    promoted_to_alert_id VARCHAR(100) REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 7. THREAT INTELLIGENCE & INDICATORS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- ip, domain, hash_sha256, url, email
    value VARCHAR(512) NOT NULL,
    threat_actor VARCHAR(100),
    confidence INT NOT NULL DEFAULT 70,
    tags TEXT[] DEFAULT '{}',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 8. AUDIT LOGS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NOT NULL,
    target_id VARCHAR(255),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 9. REPORTS & AI ANALYSES
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    generated_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL, -- incident, executive, compliance, agent_health, phishing
    target_id VARCHAR(100),
    content JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type VARCHAR(50) NOT NULL, -- alert, incident, agent, telemetry
    target_id VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL DEFAULT 'gemini-3.8-flash',
    confirmed_evidence JSONB DEFAULT '[]'::jsonb,
    inferred_insights JSONB DEFAULT '[]'::jsonb,
    unknowns JSONB DEFAULT '[]'::jsonb,
    explanation TEXT NOT NULL,
    containment_steps TEXT[] DEFAULT '{}',
    recovery_steps TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 10. INDEXES FOR PERFORMANCE
-- -----------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_agents_org_id ON agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_events_org_agent ON endpoint_events(organization_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_events_time ON endpoint_events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON endpoint_events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_org_status ON alerts(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_phishing_scans_org ON phishing_scans(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time ON audit_logs(organization_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- 11. ROW LEVEL SECURITY (RLS)
-- -----------------------------------------------------------------------------

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE phishing_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_analyses ENABLE ROW LEVEL SECURITY;

-- Helper function to fetch user's active organizations
CREATE OR REPLACE FUNCTION get_user_organizations()
RETURNS SETOF UUID AS $$
    SELECT organization_id FROM organization_members WHERE user_id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER;

-- Organization Isolation Policies
CREATE POLICY "Users can only view their own organizations"
    ON organizations FOR SELECT
    USING (id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only access agents in their organization"
    ON agents FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only access telemetry in their organization"
    ON endpoint_events FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only access alerts in their organization"
    ON alerts FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only access incidents in their organization"
    ON incidents FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only access phishing scans in their organization"
    ON phishing_scans FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can only view audit logs in their organization"
    ON audit_logs FOR SELECT
    USING (organization_id IN (SELECT get_user_organizations()));
