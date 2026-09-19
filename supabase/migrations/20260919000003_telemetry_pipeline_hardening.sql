-- =============================================================================
-- VRSOC Migration: Telemetry Pipeline, Detection Indexing & Incident Correlation
-- Target: Supabase PostgreSQL (PostgreSQL 15+)
-- Version: 1.0.3
-- =============================================================================

-- Performance indexes for telemetry querying and detection window evaluations
CREATE INDEX IF NOT EXISTS idx_events_org_type_time 
  ON endpoint_events(organization_id, event_type, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_events_org_time 
  ON endpoint_events(organization_id, event_time DESC);

-- Alert deduplication and correlation indexes
CREATE INDEX IF NOT EXISTS idx_alerts_org_rule_host 
  ON alerts(organization_id, rule_id, hostname);

CREATE INDEX IF NOT EXISTS idx_alerts_org_agent 
  ON alerts(organization_id, agent_id);

-- Incident alert relationship indexes
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert 
  ON incident_alerts(alert_id);

CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident 
  ON incident_alerts(incident_id);

-- Incident timeline ordering index
CREATE INDEX IF NOT EXISTS idx_incident_timeline_inc_time 
  ON incident_timeline(incident_id, event_timestamp ASC);
