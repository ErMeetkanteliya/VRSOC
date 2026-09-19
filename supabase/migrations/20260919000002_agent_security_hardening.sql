-- =============================================================================
-- VR_SOC — PHASE 05: ENDPOINT AGENT SECURITY & LIFECYCLE HARDENING
-- =============================================================================

-- 1. Add agent_token_hash column to agents table for secure credential storage
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_token_hash VARCHAR(128);

-- 2. Create index on agent_token_hash for high-speed O(1) authentication
CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(agent_token_hash);

-- 3. Create composite index on organization and status for fast fleet queries
CREATE INDEX IF NOT EXISTS idx_agents_org_status ON agents(organization_id, status);

-- 4. Create index on last_seen for online/offline determination
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

-- 5. Migrate existing agents: hash any existing policy.agentToken into agent_token_hash
UPDATE agents
SET agent_token_hash = encode(sha256((policy->>'agentToken')::bytea), 'hex')
WHERE agent_token_hash IS NULL AND policy->>'agentToken' IS NOT NULL;

-- 6. Clean up plaintext agentToken from policy JSONB
UPDATE agents
SET policy = policy - 'agentToken'
WHERE policy ? 'agentToken';

-- 7. Ensure agent_heartbeats table has index on agent_id and heartbeat_time
CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_time ON agent_heartbeats(agent_id, heartbeat_time DESC);
