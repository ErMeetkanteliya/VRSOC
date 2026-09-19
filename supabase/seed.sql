-- =============================================================================
-- VRSOC Enterprise Security Operations Center — Local Seed Data
-- Target: Supabase PostgreSQL (Local Development / Testing)
-- Demo Login: admin@vrsoc.cyber / VRSOC-Security2025!
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. AUTH IDENTITIES (auth.users & auth.identities)
-- -----------------------------------------------------------------------------

DO $$
DECLARE
    demo_user_id UUID := '8ed6df10-83f4-4de1-a646-9a81a69427f8';
BEGIN
    -- Insert or update demo user in Supabase auth schema
    IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = demo_user_id OR email = 'admin@vrsoc.cyber') THEN
        INSERT INTO auth.users (
            id,
            instance_id,
            aud,
            role,
            email,
            encrypted_password,
            email_confirmed_at,
            raw_app_meta_data,
            raw_user_meta_data,
            created_at,
            updated_at,
            confirmation_token,
            recovery_token,
            email_change_token_new,
            email_change
        ) VALUES (
            demo_user_id,
            '00000000-0000-0000-0000-000000000000',
            'authenticated',
            'authenticated',
            'admin@vrsoc.cyber',
            crypt('VRSOC-Security2025!', gen_salt('bf')),
            NOW(),
            '{"provider": "email", "providers": ["email"]}'::jsonb,
            '{"full_name": "Senior SOC Analyst", "role": "Organization Admin"}'::jsonb,
            NOW(),
            NOW(),
            '',
            '',
            '',
            ''
        );

        INSERT INTO auth.identities (
            id,
            user_id,
            identity_data,
            provider,
            provider_id,
            last_sign_in_at,
            created_at,
            updated_at
        ) VALUES (
            demo_user_id,
            demo_user_id,
            json_build_object('sub', demo_user_id::text, 'email', 'admin@vrsoc.cyber')::jsonb,
            'email',
            'admin@vrsoc.cyber',
            NOW(),
            NOW(),
            NOW()
        );
    ELSE
        UPDATE auth.users
        SET encrypted_password = crypt('VRSOC-Security2025!', gen_salt('bf')),
            email_confirmed_at = COALESCE(email_confirmed_at, NOW()),
            raw_user_meta_data = '{"full_name": "Senior SOC Analyst", "role": "Organization Admin"}'::jsonb,
            updated_at = NOW()
        WHERE email = 'admin@vrsoc.cyber';
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 2. ORGANIZATIONS
-- -----------------------------------------------------------------------------

INSERT INTO organizations (id, name, slug, vr_soc_key, status, retention_days, created_at, updated_at)
VALUES
    ('ea69b866-8ba0-4df9-a5c8-360748a240ca', 'VRsecurity', 'vrsecurity-mu85c8pr', '90952D6805A3DF', 'active', 90, NOW(), NOW()),
    ('97e9fcae-b4b8-4f30-a669-9fae507a5942', 'Stone Defense Systems', 'stone-defense-systems-mu8abxqe', '0CA1A97CD67B5F', 'active', 90, NOW(), NOW()),
    ('22032c3b-dc93-4158-9fb1-4a6c69cdd401', 'Vance Cyber Defense', 'vance-cyber-defense-mu8abpbu', '8568F62F5077EE', 'active', 90, NOW(), NOW())
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    slug = EXCLUDED.slug,
    vr_soc_key = EXCLUDED.vr_soc_key,
    updated_at = NOW();

-- -----------------------------------------------------------------------------
-- 3. PROFILES
-- -----------------------------------------------------------------------------

INSERT INTO profiles (id, email, full_name, phone_number, email_verified, phone_verified, mfa_enabled, role, created_at, updated_at)
VALUES
    ('8ed6df10-83f4-4de1-a646-9a81a69427f8', 'admin@vrsoc.cyber', 'Senior SOC Analyst', '+15550198273', TRUE, TRUE, FALSE, 'Organization Admin', NOW(), NOW())
ON CONFLICT (id) DO UPDATE
SET email = EXCLUDED.email,
    full_name = EXCLUDED.full_name,
    email_verified = TRUE,
    role = EXCLUDED.role,
    updated_at = NOW();

-- -----------------------------------------------------------------------------
-- 4. ORGANIZATION MEMBERSHIPS
-- -----------------------------------------------------------------------------

INSERT INTO organization_members (organization_id, user_id, role, created_at)
VALUES
    ('ea69b866-8ba0-4df9-a5c8-360748a240ca', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'Organization Admin', NOW()),
    ('97e9fcae-b4b8-4f30-a669-9fae507a5942', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'Organization Admin', NOW()),
    ('22032c3b-dc93-4158-9fb1-4a6c69cdd401', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'Organization Admin', NOW())
ON CONFLICT (organization_id, user_id) DO UPDATE
SET role = EXCLUDED.role;

-- -----------------------------------------------------------------------------
-- 5. ENDPOINT AGENTS
-- -----------------------------------------------------------------------------

INSERT INTO agents (
    id, organization_id, name, hostname, os, os_version, architecture, ip_address,
    agent_version, enrollment_key, status, last_seen, cpu_usage, ram_usage, disk_usage,
    tags, policy, health, environment, created_at, updated_at
) VALUES
    (
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'Workstation SOC-Primary',
        'vrsoc-workstation-01',
        'Linux',
        'Ubuntu 22.04 LTS',
        'x86_64',
        '192.168.10.45',
        '1.4.0',
        '90952D6805A3DF',
        'online',
        NOW(),
        24.0,
        42.0,
        35.0,
        ARRAY['workstation', 'linux'],
        '{"scanIntervalSec": 15, "isolationMode": false}'::jsonb,
        'healthy',
        'production',
        NOW(),
        NOW()
    ),
    (
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'DC-Enterprise-Primary',
        'vrsoc-dc-01',
        'Windows Server',
        '2022 Datacenter',
        'x64',
        '192.168.10.10',
        '1.4.0',
        '90952D6805A3DF',
        'online',
        NOW(),
        18.0,
        64.0,
        52.0,
        ARRAY['domain-controller', 'windows', 'critical-infra'],
        '{"scanIntervalSec": 10, "isolationMode": false}'::jsonb,
        'healthy',
        'production',
        NOW(),
        NOW()
    ),
    (
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989dc',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'SecOps-MacBook-Pro',
        'vrsoc-mac-09',
        'macOS',
        'Sonoma 14.4',
        'arm64',
        '192.168.10.78',
        '1.4.0',
        '90952D6805A3DF',
        'online',
        NOW(),
        12.0,
        38.0,
        28.0,
        ARRAY['executive', 'macos', 'laptop'],
        '{"scanIntervalSec": 30, "isolationMode": false}'::jsonb,
        'healthy',
        'production',
        NOW(),
        NOW()
    )
ON CONFLICT (id) DO UPDATE
SET status = EXCLUDED.status,
    last_seen = NOW(),
    updated_at = NOW();

-- -----------------------------------------------------------------------------
-- 6. DETECTION RULES
-- -----------------------------------------------------------------------------

INSERT INTO detection_rules (
    id, organization_id, name, description, severity, risk_score, category,
    mitre_tactic, mitre_technique_id, mitre_technique_name, conditions,
    remediation_steps, enabled, created_at
) VALUES
    (
        'RULE-AUTH-001',
        NULL,
        'Multiple Authentication Failures (Brute Force Indicator)',
        'Triggers when 5 or more failed logon attempts occur against a single host or account within a 5-minute window.',
        'high',
        78,
        'Credential Access',
        'Credential Access',
        'T1110.001',
        'Brute Force: Password Guessing',
        '{"eventType": "auth", "status": "failure", "threshold": 5, "windowMinutes": 5}'::jsonb,
        ARRAY['Identify source IP address.', 'Temporarily lock account.', 'Review edge network logs.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-AUTH-002',
        NULL,
        'Account Lockout Security Event',
        'Triggers when an endpoint or directory service logs an explicit user account lockout event.',
        'medium',
        55,
        'Credential Access',
        'Credential Access',
        'T1110.004',
        'Brute Force: Account Lockout',
        '{"eventType": "auth", "subType": "lockout"}'::jsonb,
        ARRAY['Contact user to verify whether lockout was caused by user error or external attack.', 'Inspect endpoint audit logs.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-PROC-001',
        NULL,
        'Suspicious / Obfuscated PowerShell Execution',
        'Detects PowerShell or bash processes invoked with encoded commands, hidden windows, or execution bypass flags.',
        'critical',
        92,
        'Execution',
        'Execution',
        'T1059.001',
        'Command and Scripting Interpreter: PowerShell',
        '{"eventType": "process", "patterns": ["-enc", "-encodedcommand", "-w hidden", "-nop", "bypass", "downloadstring", "iex("]}'::jsonb,
        ARRAY['Isolate host immediately.', 'Decode base64 command.', 'Inspect parent process tree.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-PERS-001',
        NULL,
        'Persistence Indicator: Scheduled Task or Cron Creation',
        'Detects execution of schtasks, crontab, or systemd timer modification to establish persistent autostart.',
        'high',
        80,
        'Persistence',
        'Persistence',
        'T1053.005',
        'Scheduled Task/Job: Scheduled Task',
        '{"eventType": "process", "commandKeywords": ["schtasks /create", "crontab -e", "systemctl enable --now"]}'::jsonb,
        ARRAY['Inspect created task path.', 'Verify binary signature.', 'Remove unauthorized task.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-NET-001',
        NULL,
        'Network Reconnaissance / Port Scanning Indicator',
        'Detects rapid outbound network connection attempts across multiple destination ports within short timeframe.',
        'medium',
        65,
        'Discovery',
        'Discovery',
        'T1046',
        'Network Service Discovery',
        '{"eventType": "network", "connectionRate": "high", "portSpan": 15}'::jsonb,
        ARRAY['Identify if scanning utility is present.', 'Review firewall logs.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-DEV-001',
        NULL,
        'Unauthorized Removable Storage / USB Mass Storage Mount',
        'Detects mounting of external USB mass storage devices on monitored defensive endpoints.',
        'low',
        40,
        'Initial Access',
        'Initial Access',
        'T1091',
        'Replication Through Removable Media',
        '{"eventType": "usb", "action": "mount"}'::jsonb,
        ARRAY['Confirm authorization under DLP policy.', 'Check file creation logs.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-PHISH-001',
        NULL,
        'High-Risk Phishing URL Ingestion (PhishGuard ML)',
        'Detects URLs classified as Phishing with high model risk score (>= 70) via PhishGuard ML feature analysis.',
        'high',
        88,
        'Initial Access',
        'Initial Access',
        'T1566.002',
        'Phishing: Spearphishing Link',
        '{"eventType": "phishing", "classification": "Phishing", "minScore": 70}'::jsonb,
        ARRAY['Block phishing domain at DNS resolver.', 'Check mail gateway logs.', 'Force password reset.'],
        TRUE,
        NOW()
    ),
    (
        'RULE-HEART-001',
        NULL,
        'Endpoint Agent Heartbeat Loss',
        'Triggers when a previously active enrolled endpoint agent stops reporting heartbeats for longer than threshold.',
        'medium',
        50,
        'Defense Evasion',
        'Defense Evasion',
        'T1562.001',
        'Impair Defenses: Disable or Modify Tools',
        '{"type": "agent_heartbeat_loss", "timeoutSeconds": 180}'::jsonb,
        ARRAY['Verify host state.', 'Inspect host services.'],
        TRUE,
        NOW()
    )
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    description = EXCLUDED.description,
    severity = EXCLUDED.severity,
    risk_score = EXCLUDED.risk_score,
    conditions = EXCLUDED.conditions,
    enabled = EXCLUDED.enabled;

-- -----------------------------------------------------------------------------
-- 7. ENDPOINT EVENTS
-- -----------------------------------------------------------------------------

INSERT INTO endpoint_events (
    id, organization_id, agent_id, event_type, severity, source, event_time, ingestion_time, data, schema_version
) VALUES
    (
        '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
        'process',
        'high',
        'simulation',
        NOW() - INTERVAL '10 minutes',
        NOW() - INTERVAL '10 minutes',
        '{"action": "EXECUTE", "processName": "powershell.exe", "commandLine": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==", "parentPid": 4920, "parentProcess": "cmd.exe", "user": "Bob Stone", "hostname": "vrsoc-workstation-01"}'::jsonb,
        '1.0'
    ),
    (
        '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4eb',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
        'auth',
        'high',
        'vrsoc-agent',
        NOW() - INTERVAL '8 minutes',
        NOW() - INTERVAL '8 minutes',
        '{"action": "logon_failed", "status": "failure", "user": "Administrator", "sourceIp": "198.51.100.42", "hostname": "vrsoc-dc-01", "failureReason": "BadPassword"}'::jsonb,
        '1.0'
    ),
    (
        '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ec',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
        'network',
        'medium',
        'vrsoc-agent',
        NOW() - INTERVAL '5 minutes',
        NOW() - INTERVAL '5 minutes',
        '{"action": "CONNECT", "sourceIp": "192.168.10.45", "destinationIp": "198.51.100.42", "destinationPort": 443, "protocol": "TCP", "bytesSent": 4096}'::jsonb,
        '1.0'
    )
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 8. ALERTS
-- -----------------------------------------------------------------------------

INSERT INTO alerts (
    id, organization_id, agent_id, rule_id, title, description, severity,
    risk_score, status, hostname, username, source_ip, mitre_tactic, mitre_technique,
    mitre_id, evidence, trigger_event_ids, assigned_to, environment, created_at, updated_at
) VALUES
    (
        'ALT-20260919-0001',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
        'RULE-PROC-001',
        'Suspicious PowerShell Execution on vrsoc-workstation-01',
        'Process ''powershell.exe'' was executed with obfuscated or policy bypass command line arguments.',
        'critical',
        92,
        'open',
        'vrsoc-workstation-01',
        'Bob Stone',
        '192.168.10.45',
        'Execution',
        'Command and Scripting Interpreter: PowerShell',
        'T1059.001',
        '[{"type": "Process Telemetry", "description": "Encoded command execution", "state": "CONFIRMED"}]'::jsonb,
        ARRAY['0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea'::uuid],
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'production',
        NOW() - INTERVAL '10 minutes',
        NOW() - INTERVAL '10 minutes'
    ),
    (
        'ALT-20260919-0002',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
        'RULE-AUTH-001',
        'Multiple Authentication Failures on vrsoc-dc-01',
        'Repeated failed administrator logon attempts observed from external IP 198.51.100.42.',
        'high',
        78,
        'investigating',
        'vrsoc-dc-01',
        'Administrator',
        '198.51.100.42',
        'Credential Access',
        'Brute Force: Password Guessing',
        'T1110.001',
        '[{"type": "Auth Telemetry", "description": "5 consecutive failed logons", "state": "CONFIRMED"}]'::jsonb,
        ARRAY['0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4eb'::uuid],
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'production',
        NOW() - INTERVAL '8 minutes',
        NOW() - INTERVAL '8 minutes'
    )
ON CONFLICT (id) DO UPDATE
SET status = EXCLUDED.status,
    updated_at = NOW();

-- -----------------------------------------------------------------------------
-- 9. ALERT COMMENTS
-- -----------------------------------------------------------------------------

INSERT INTO alert_comments (id, alert_id, user_id, comment, created_at)
VALUES
    ('c1000000-0000-0000-0000-000000000001', 'ALT-20260919-0001', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'Investigating encoded base64 payload. Host isolation recommended.', NOW() - INTERVAL '9 minutes')
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 10. INCIDENTS
-- -----------------------------------------------------------------------------

INSERT INTO incidents (
    id, organization_id, title, description, severity, status, priority,
    lead_investigator, environment, created_at, updated_at
) VALUES
    (
        'INC-20260919-0001',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'APT29 Emulated Credential Harvesting & Obfuscated Incursion',
        'Correlated multi-vector security incident involving spearphishing landing page, obfuscated PowerShell execution, and external brute-force targeting domain controller.',
        'critical',
        'investigating',
        'P1',
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'production',
        NOW() - INTERVAL '7 minutes',
        NOW() - INTERVAL '7 minutes'
    )
ON CONFLICT (id) DO UPDATE
SET status = EXCLUDED.status,
    updated_at = NOW();

-- -----------------------------------------------------------------------------
-- 11. INCIDENT RELATIONSHIPS (Alerts, Timeline, Tasks)
-- -----------------------------------------------------------------------------

INSERT INTO incident_alerts (incident_id, alert_id, linked_at)
VALUES
    ('INC-20260919-0001', 'ALT-20260919-0001', NOW() - INTERVAL '7 minutes'),
    ('INC-20260919-0001', 'ALT-20260919-0002', NOW() - INTERVAL '7 minutes')
ON CONFLICT (incident_id, alert_id) DO NOTHING;

INSERT INTO incident_tasks (id, incident_id, title, assigned_to, completed, created_at)
VALUES
    ('a1000000-0000-0000-0000-000000000001', 'INC-20260919-0001', 'Isolate workstation vrsoc-workstation-01 from corporate network segment', '8ed6df10-83f4-4de1-a646-9a81a69427f8', TRUE, NOW() - INTERVAL '6 minutes'),
    ('a1000000-0000-0000-0000-000000000002', 'INC-20260919-0001', 'Extract and analyze base64 payload strings for C2 staging infrastructure', '8ed6df10-83f4-4de1-a646-9a81a69427f8', TRUE, NOW() - INTERVAL '6 minutes'),
    ('a1000000-0000-0000-0000-000000000003', 'INC-20260919-0001', 'Rotate compromised domain administrator and service account credentials', '8ed6df10-83f4-4de1-a646-9a81a69427f8', FALSE, NOW() - INTERVAL '5 minutes'),
    ('a1000000-0000-0000-0000-000000000004', 'INC-20260919-0001', 'Publish threat indicators (IP 198.51.100.42) to perimeter firewall blocklists', '8ed6df10-83f4-4de1-a646-9a81a69427f8', FALSE, NOW() - INTERVAL '5 minutes')
ON CONFLICT (id) DO NOTHING;

INSERT INTO incident_timeline (id, incident_id, event_title, event_description, event_type, evidence_state, event_timestamp)
VALUES
    ('b1000000-0000-0000-0000-000000000001', 'INC-20260919-0001', 'Spearphishing Email Delivered', 'User received deceptive Microsoft 365 credential verification link.', 'observation', 'CONFIRMED', NOW() - INTERVAL '15 minutes'),
    ('b1000000-0000-0000-0000-000000000002', 'INC-20260919-0001', 'Obfuscated PowerShell Execution Detected', 'VRSOC EDR triggered critical alert ALT-20260919-0001 on workstation.', 'detection', 'CONFIRMED', NOW() - INTERVAL '10 minutes'),
    ('b1000000-0000-0000-0000-000000000003', 'INC-20260919-0001', 'Endpoint Network Isolation Initiated', 'Workstation vrsoc-workstation-01 isolated via VRSOC agent policy.', 'containment', 'CONFIRMED', NOW() - INTERVAL '6 minutes')
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 12. PHISHING SCANS
-- -----------------------------------------------------------------------------

INSERT INTO phishing_scans (
    id, organization_id, user_id, url, normalized_url, classification,
    risk_score, features, reasons, created_at
) VALUES
    (
        'e8e44649-ab68-4ea7-abfc-8a4a49f316c0',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'https://secure-login-microsoft.suspicious-domain-123.com/update',
        'https://secure-login-microsoft.suspicious-domain-123.com/update',
        'Suspicious',
        51,
        '{"urlLength": 63, "hasIpAddress": false, "sensitiveKeywordsFound": ["login", "update", "microsoft", "secure"]}'::jsonb,
        ARRAY['Hostname contains hyphens typical of credential harvesting typosquatting.', 'Contains high-risk credential keywords: [login, update, microsoft, secure].'],
        NOW() - INTERVAL '20 minutes'
    ),
    (
        'e8e44649-ab68-4ea7-abfc-8a4a49f316c1',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'https://auth-portal-reset.internal-verify-cdn.net/login',
        'https://auth-portal-reset.internal-verify-cdn.net/login',
        'Phishing',
        94,
        '{"urlLength": 54, "hasIpAddress": false, "sensitiveKeywordsFound": ["auth", "portal", "reset", "verify", "login"]}'::jsonb,
        ARRAY['Confirmed deceptive credential phishing lure imitating enterprise SSO portal.', 'Domain newly registered within last 48 hours.'],
        NOW() - INTERVAL '12 minutes'
    )
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 13. THREAT INTELLIGENCE INDICATORS
-- -----------------------------------------------------------------------------

INSERT INTO indicators (
    id, organization_id, type, value, threat_actor, confidence, tags, description, created_at
) VALUES
    (
        'd1000000-0000-0000-0000-000000000001',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'ip',
        '198.51.100.42',
        'APT29',
        90,
        ARRAY['c2', 'cobalt-strike', 'brute-force'],
        'Known Cobalt Strike command and control IP address involved in active campaigns.',
        NOW() - INTERVAL '1 day'
    ),
    (
        'd1000000-0000-0000-0000-000000000002',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'domain',
        'suspicious-domain-123.com',
        'Storm-0558',
        85,
        ARRAY['phishing', 'typosquatting', 'credential-harvesting'],
        'Credential harvesting typosquatting domain impersonating Microsoft 365 login.',
        NOW() - INTERVAL '2 days'
    ),
    (
        'd1000000-0000-0000-0000-000000000003',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        'hash_sha256',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'Unknown',
        95,
        ARRAY['dropper', 'malware', 'powershell'],
        'Obfuscated PowerShell dropper payload hash observed in memory.',
        NOW() - INTERVAL '3 days'
    )
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 14. AUDIT LOGS
-- -----------------------------------------------------------------------------

INSERT INTO audit_logs (id, organization_id, user_id, action, target_type, target_id, details, ip_address, created_at)
VALUES
    ('c31c2dec-b14c-4b7e-a2f7-823ecd7e805d', 'ea69b866-8ba0-4df9-a5c8-360748a240ca', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'USER_SIGNUP', 'user', '8ed6df10-83f4-4de1-a646-9a81a69427f8', '{"organizationName": "VRsecurity", "role": "Organization Admin"}'::jsonb, '127.0.0.1', NOW() - INTERVAL '1 hour'),
    ('8f360320-2bff-4425-84c6-d669176b6b28', 'ea69b866-8ba0-4df9-a5c8-360748a240ca', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'USER_LOGIN', 'user', '8ed6df10-83f4-4de1-a646-9a81a69427f8', '{"role": "Organization Admin"}'::jsonb, '127.0.0.1', NOW() - INTERVAL '30 minutes'),
    ('a50f4051-9393-492b-b7cd-576c9901fcd7', 'ea69b866-8ba0-4df9-a5c8-360748a240ca', '8ed6df10-83f4-4de1-a646-9a81a69427f8', 'SIMULATE_THREAT_SCENARIO', 'telemetry_event', '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea', '{"scenario": "powershell_obfuscated", "agent": "vrsoc-workstation-01", "triggeredAlertId": "ALT-20260919-0001"}'::jsonb, '127.0.0.1', NOW() - INTERVAL '10 minutes')
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 15. REPORTS
-- -----------------------------------------------------------------------------

INSERT INTO reports (id, organization_id, generated_by, title, report_type, target_id, content, created_at)
VALUES
    (
        'e1000000-0000-0000-0000-000000000001',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'Weekly Executive SOC Threat Assessment - September 2026',
        'executive',
        NULL,
        '{"executiveSummary": "Defensive posture remains robust across enterprise perimeter with 3 active endpoints monitored.", "criticalIncidents": 1, "resolvedAlerts": 14, "threatsNeutralized": 3}'::jsonb,
        NOW() - INTERVAL '1 day'
    ),
    (
        'e1000000-0000-0000-0000-000000000002',
        'ea69b866-8ba0-4df9-a5c8-360748a240ca',
        '8ed6df10-83f4-4de1-a646-9a81a69427f8',
        'Incident Post-Mortem: INC-20260919-0001 APT29 Incursion',
        'incident',
        'INC-20260919-0001',
        '{"rootCause": "Credential phishing landing page bypassed legacy email filtering.", "containmentTimeMinutes": 12, "lessonsLearned": "Enforce FIDO2 WebAuthn authentication across all administrative workstation access."}'::jsonb,
        NOW() - INTERVAL '2 hours'
    )
ON CONFLICT (id) DO NOTHING;
