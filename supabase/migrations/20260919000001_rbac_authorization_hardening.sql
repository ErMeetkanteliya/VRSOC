-- =============================================================================
-- VR_SOC Phase 03: RBAC & Tenant Authorization Hardening Migration
-- =============================================================================

-- Ensure RLS is active on all workspace entity tables
ALTER TABLE IF EXISTS indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS agent_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS alert_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS incident_tasks ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 1. Threat Intelligence Indicators RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access indicators in their organization" ON indicators;
CREATE POLICY "Users can access indicators in their organization"
    ON indicators FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

-- -----------------------------------------------------------------------------
-- 2. Reports RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access reports in their organization" ON reports;
CREATE POLICY "Users can access reports in their organization"
    ON reports FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

-- -----------------------------------------------------------------------------
-- 3. AI Analyses RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access AI analyses in their organization" ON ai_analyses;
CREATE POLICY "Users can access AI analyses in their organization"
    ON ai_analyses FOR ALL
    USING (organization_id IN (SELECT get_user_organizations()));

-- -----------------------------------------------------------------------------
-- 4. Detection Rules RLS (Global rules visible to all, Custom scoped to org)
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can view global and org detection rules" ON detection_rules;
CREATE POLICY "Users can view global and org detection rules"
    ON detection_rules FOR SELECT
    USING (organization_id IS NULL OR organization_id IN (SELECT get_user_organizations()));

DROP POLICY IF EXISTS "Users can manage org custom detection rules" ON detection_rules;
CREATE POLICY "Users can manage org custom detection rules"
    ON detection_rules FOR ALL
    USING (organization_id IS NOT NULL AND organization_id IN (SELECT get_user_organizations()));

-- -----------------------------------------------------------------------------
-- 5. Profiles RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can view self and org members profiles" ON profiles;
CREATE POLICY "Users can view self and org members profiles"
    ON profiles FOR SELECT
    USING (
        id = auth.uid() OR
        id IN (
            SELECT user_id FROM organization_members
            WHERE organization_id IN (SELECT get_user_organizations())
        )
    );

DROP POLICY IF EXISTS "Users can update own profile" ON profiles;
CREATE POLICY "Users can update own profile"
    ON profiles FOR UPDATE
    USING (id = auth.uid());

-- -----------------------------------------------------------------------------
-- 6. Organization Members RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can view organization members" ON organization_members;
CREATE POLICY "Users can view organization members"
    ON organization_members FOR SELECT
    USING (
        user_id = auth.uid() OR
        organization_id IN (SELECT get_user_organizations())
    );

-- -----------------------------------------------------------------------------
-- 7. Alert Comments RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access comments for org alerts" ON alert_comments;
CREATE POLICY "Users can access comments for org alerts"
    ON alert_comments FOR ALL
    USING (
        alert_id IN (SELECT id FROM alerts WHERE organization_id IN (SELECT get_user_organizations()))
    );

-- -----------------------------------------------------------------------------
-- 8. Incident Sub-entities RLS (Tasks, Timeline, Linked Alerts)
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access tasks for org incidents" ON incident_tasks;
CREATE POLICY "Users can access tasks for org incidents"
    ON incident_tasks FOR ALL
    USING (
        incident_id IN (SELECT id FROM incidents WHERE organization_id IN (SELECT get_user_organizations()))
    );

DROP POLICY IF EXISTS "Users can access timeline for org incidents" ON incident_timeline;
CREATE POLICY "Users can access timeline for org incidents"
    ON incident_timeline FOR ALL
    USING (
        incident_id IN (SELECT id FROM incidents WHERE organization_id IN (SELECT get_user_organizations()))
    );

DROP POLICY IF EXISTS "Users can access alert links for org incidents" ON incident_alerts;
CREATE POLICY "Users can access alert links for org incidents"
    ON incident_alerts FOR ALL
    USING (
        incident_id IN (SELECT id FROM incidents WHERE organization_id IN (SELECT get_user_organizations()))
    );

-- -----------------------------------------------------------------------------
-- 9. Agent Heartbeats RLS
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Users can access heartbeats for org agents" ON agent_heartbeats;
CREATE POLICY "Users can access heartbeats for org agents"
    ON agent_heartbeats FOR ALL
    USING (
        agent_id IN (SELECT id FROM agents WHERE organization_id IN (SELECT get_user_organizations()))
    );

-- -----------------------------------------------------------------------------
-- 10. Performance Indexes for Scoped Lookups
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_indicators_org_id ON indicators(organization_id);
CREATE INDEX IF NOT EXISTS idx_reports_org_id ON reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_org_id ON ai_analyses(organization_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_org_id ON detection_rules(organization_id);
CREATE INDEX IF NOT EXISTS idx_alert_comments_alert_id ON alert_comments(alert_id);
CREATE INDEX IF NOT EXISTS idx_incident_tasks_inc_id ON incident_tasks(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_inc_id ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc_id ON incident_alerts(incident_id);
