import 'dotenv/config';
import { supabaseAdmin } from '../server/supabase';

export const DEMO_USER = {
  id: '8ed6df10-83f4-4de1-a646-9a81a69427f8',
  email: 'admin@vrsoc.cyber',
  password: 'VRSOC-Security2025!',
  fullName: 'Senior SOC Analyst',
  role: 'Organization Admin'
};

export const DEMO_ORGS = [
  {
    id: 'ea69b866-8ba0-4df9-a5c8-360748a240ca',
    name: 'VRsecurity',
    slug: 'vrsecurity-mu85c8pr',
    vr_soc_key: '90952D6805A3DF',
    status: 'active',
    retention_days: 90
  },
  {
    id: '97e9fcae-b4b8-4f30-a669-9fae507a5942',
    name: 'Stone Defense Systems',
    slug: 'stone-defense-systems-mu8abxqe',
    vr_soc_key: '0CA1A97CD67B5F',
    status: 'active',
    retention_days: 90
  },
  {
    id: '22032c3b-dc93-4158-9fb1-4a6c69cdd401',
    name: 'Vance Cyber Defense',
    slug: 'vance-cyber-defense-mu8abpbu',
    vr_soc_key: '8568F62F5077EE',
    status: 'active',
    retention_days: 90
  }
];

export async function seedLocalData() {
  if (!supabaseAdmin) {
    throw new Error('[VRSOC Seed] Supabase Admin client is not configured. Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
  }

  const admin = supabaseAdmin;
  console.log('[VRSOC Seed] Starting local Supabase database seed...');

  // 1. Create or ensure Demo Auth User
  console.log('[VRSOC Seed] Ensuring demo auth user (admin@vrsoc.cyber)...');
  const { data: userList } = await admin.auth.admin.listUsers();
  let authUser = userList?.users?.find(u => u.email === DEMO_USER.email);

  if (!authUser) {
    const { data: newUser, error: createError } = await admin.auth.admin.createUser({
      id: DEMO_USER.id,
      email: DEMO_USER.email,
      password: DEMO_USER.password,
      email_confirm: true,
      user_metadata: {
        full_name: DEMO_USER.fullName,
        role: DEMO_USER.role
      }
    });

    if (createError) {
      console.warn('[VRSOC Seed] Warning creating auth user with fixed ID:', createError.message);
      const { data: fallbackUser, error: fallbackError } = await admin.auth.admin.createUser({
        email: DEMO_USER.email,
        password: DEMO_USER.password,
        email_confirm: true,
        user_metadata: {
          full_name: DEMO_USER.fullName,
          role: DEMO_USER.role
        }
      });
      if (fallbackError) throw fallbackError;
      authUser = fallbackUser.user;
    } else {
      authUser = newUser.user;
    }
  } else {
    await admin.auth.admin.updateUserById(authUser.id, {
      password: DEMO_USER.password,
      email_confirm: true,
      user_metadata: {
        full_name: DEMO_USER.fullName,
        role: DEMO_USER.role
      }
    });
  }

  const userId = authUser.id;
  console.log(`[VRSOC Seed] Auth user ready with ID: ${userId}`);

  // 2. Seed Organizations
  console.log('[VRSOC Seed] Seeding organizations...');
  for (const org of DEMO_ORGS) {
    const { error } = await admin.from('organizations').upsert({
      id: org.id,
      name: org.name,
      slug: org.slug,
      vr_soc_key: org.vr_soc_key,
      status: org.status,
      retention_days: org.retention_days
    }, { onConflict: 'id' });
    if (error) throw new Error(`Org error: ${error.message}`);
  }

  // 3. Seed Profile
  console.log('[VRSOC Seed] Seeding profiles...');
  const { error: profileError } = await admin.from('profiles').upsert({
    id: userId,
    email: DEMO_USER.email,
    full_name: DEMO_USER.fullName,
    phone_number: '+15550198273',
    email_verified: true,
    phone_verified: true,
    mfa_enabled: false,
    role: DEMO_USER.role
  }, { onConflict: 'id' });
  if (profileError) throw new Error(`Profile error: ${profileError.message}`);

  // 4. Seed Organization Memberships
  console.log('[VRSOC Seed] Seeding organization memberships...');
  for (const org of DEMO_ORGS) {
    await admin.from('organization_members').upsert({
      organization_id: org.id,
      user_id: userId,
      role: 'Organization Admin'
    }, { onConflict: 'organization_id,user_id' });
  }

  // 5. Seed Agents
  console.log('[VRSOC Seed] Seeding agents...');
  const agents: Record<string, any>[] = [
    {
      id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
      organization_id: DEMO_ORGS[0].id,
      name: 'Workstation SOC-Primary',
      hostname: 'vrsoc-workstation-01',
      os: 'Linux',
      os_version: 'Ubuntu 22.04 LTS',
      architecture: 'x86_64',
      ip_address: '192.168.10.45',
      agent_version: '1.4.0',
      enrollment_key: DEMO_ORGS[0].vr_soc_key,
      status: 'online',
      cpu_usage: 24,
      ram_usage: 42,
      disk_usage: 35,
      tags: ['workstation', 'linux'],
      health: 'healthy',
      environment: 'production',
      policy: { scanIntervalSec: 15, isolationMode: false }
    },
    {
      id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
      organization_id: DEMO_ORGS[0].id,
      name: 'DC-Enterprise-Primary',
      hostname: 'vrsoc-dc-01',
      os: 'Windows Server',
      os_version: '2022 Datacenter',
      architecture: 'x64',
      ip_address: '192.168.10.10',
      agent_version: '1.4.0',
      enrollment_key: DEMO_ORGS[0].vr_soc_key,
      status: 'online',
      cpu_usage: 18,
      ram_usage: 64,
      disk_usage: 52,
      tags: ['domain-controller', 'windows', 'critical-infra'],
      health: 'healthy',
      environment: 'production',
      policy: { scanIntervalSec: 10, isolationMode: false }
    },
    {
      id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989dc',
      organization_id: DEMO_ORGS[0].id,
      name: 'SecOps-MacBook-Pro',
      hostname: 'vrsoc-mac-09',
      os: 'macOS',
      os_version: 'Sonoma 14.4',
      architecture: 'arm64',
      ip_address: '192.168.10.78',
      agent_version: '1.4.0',
      enrollment_key: DEMO_ORGS[0].vr_soc_key,
      status: 'online',
      cpu_usage: 12,
      ram_usage: 38,
      disk_usage: 28,
      tags: ['executive', 'macos', 'laptop'],
      health: 'healthy',
      environment: 'production',
      policy: { scanIntervalSec: 30, isolationMode: false }
    }
  ];

  for (const ag of agents) {
    const { error } = await admin.from('agents').upsert(ag, { onConflict: 'id' });
    if (error) throw new Error(`Agent error: ${error.message}`);
  }

  // 6. Seed Detection Rules
  console.log('[VRSOC Seed] Seeding detection rules...');
  const detectionRules: Record<string, any>[] = [
    {
      id: 'RULE-AUTH-001',
      organization_id: null,
      name: 'Multiple Authentication Failures (Brute Force Indicator)',
      description: 'Triggers when 5 or more failed logon attempts occur against a single host or account within a 5-minute window.',
      severity: 'high',
      risk_score: 78,
      category: 'Credential Access',
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1110.001',
      mitre_technique_name: 'Brute Force: Password Guessing',
      conditions: { eventType: 'auth', status: 'failure', threshold: 5, windowMinutes: 5 },
      remediation_steps: [
        'Identify the source IP address or workstation originating the authentication failures.',
        'Temporarily lock or reset the affected account credentials if unauthorized.',
        'Review network edge logs to determine if external proxy/VPN was used.'
      ],
      enabled: true
    },
    {
      id: 'RULE-AUTH-002',
      organization_id: null,
      name: 'Account Lockout Security Event',
      description: 'Triggers when an endpoint or directory service logs an explicit user account lockout event.',
      severity: 'medium',
      risk_score: 55,
      category: 'Credential Access',
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1110.004',
      mitre_technique_name: 'Brute Force: Account Lockout',
      conditions: { eventType: 'auth', subType: 'lockout' },
      remediation_steps: [
        'Contact user to verify whether lockout was caused by user error or external attack.',
        'Inspect endpoint audit logs for malicious background services caching stale credentials.'
      ],
      enabled: true
    },
    {
      id: 'RULE-PROC-001',
      organization_id: null,
      name: 'Suspicious / Obfuscated PowerShell Execution',
      description: 'Detects PowerShell or bash processes invoked with encoded commands, hidden windows, or execution bypass flags.',
      severity: 'critical',
      risk_score: 92,
      category: 'Execution',
      mitre_tactic: 'Execution',
      mitre_technique_id: 'T1059.001',
      mitre_technique_name: 'Command and Scripting Interpreter: PowerShell',
      conditions: {
        eventType: 'process',
        patterns: ['-enc', '-encodedcommand', '-w hidden', '-nop', 'bypass', 'downloadstring', 'iex(']
      },
      remediation_steps: [
        'Isolate the host immediately from the network segment to prevent lateral movement.',
        'Dump and decode the base64 or obfuscated command line parameter.',
        'Inspect parent process tree to identify the dropper or vector.'
      ],
      enabled: true
    },
    {
      id: 'RULE-PERS-001',
      organization_id: null,
      name: 'Persistence Indicator: Scheduled Task or Cron Creation',
      description: 'Detects execution of schtasks, crontab, or systemd timer modification to establish persistent autostart.',
      severity: 'high',
      risk_score: 80,
      category: 'Persistence',
      mitre_tactic: 'Persistence',
      mitre_technique_id: 'T1053.005',
      mitre_technique_name: 'Scheduled Task/Job: Scheduled Task',
      conditions: {
        eventType: 'process',
        commandKeywords: ['schtasks /create', 'crontab -e', 'systemctl enable --now']
      },
      remediation_steps: [
        'Inspect the created task path and executable payload.',
        'Verify digital signature and authorization of the scheduled binary.',
        'Remove the unauthorized task and terminate any active spawned PIDs.'
      ],
      enabled: true
    },
    {
      id: 'RULE-NET-001',
      organization_id: null,
      name: 'Network Reconnaissance / Port Scanning Indicator',
      description: 'Detects rapid outbound network connection attempts across multiple destination ports within short timeframe.',
      severity: 'medium',
      risk_score: 65,
      category: 'Discovery',
      mitre_tactic: 'Discovery',
      mitre_technique_id: 'T1046',
      mitre_technique_name: 'Network Service Discovery',
      conditions: { eventType: 'network', connectionRate: 'high', portSpan: 15 },
      remediation_steps: [
        'Identify if scanning utility (nmap, masscan, netcat) is present on the host.',
        'Review firewall logs for internal subnet enumeration.'
      ],
      enabled: true
    },
    {
      id: 'RULE-DEV-001',
      organization_id: null,
      name: 'Unauthorized Removable Storage / USB Mass Storage Mount',
      description: 'Detects mounting of external USB mass storage devices on monitored defensive endpoints.',
      severity: 'low',
      risk_score: 40,
      category: 'Initial Access',
      mitre_tactic: 'Initial Access',
      mitre_technique_id: 'T1091',
      mitre_technique_name: 'Replication Through Removable Media',
      conditions: { eventType: 'usb', action: 'mount' },
      remediation_steps: [
        'Confirm whether endpoint is authorized for removable storage under organization DLP policy.',
        'Check file creation logs on the mounted drive for data exfiltration indicators.'
      ],
      enabled: true
    },
    {
      id: 'RULE-PHISH-001',
      organization_id: null,
      name: 'High-Risk Phishing URL Ingestion (PhishGuard ML)',
      description: 'Detects URLs classified as Phishing with high model risk score (>= 70) via PhishGuard ML feature analysis.',
      severity: 'high',
      risk_score: 88,
      category: 'Initial Access',
      mitre_tactic: 'Initial Access',
      mitre_technique_id: 'T1566.002',
      mitre_technique_name: 'Phishing: Spearphishing Link',
      conditions: { eventType: 'phishing', classification: 'Phishing', minScore: 70 },
      remediation_steps: [
        'Block the phishing domain at the enterprise DNS resolver / proxy level.',
        'Check mail gateway and proxy logs for any other users who visited the URL.',
        'Force password reset for any users who submitted credentials to the landing page.'
      ],
      enabled: true
    },
    {
      id: 'RULE-HEART-001',
      organization_id: null,
      name: 'Endpoint Agent Heartbeat Loss',
      description: 'Triggers when a previously active enrolled endpoint agent stops reporting heartbeats for longer than threshold.',
      severity: 'medium',
      risk_score: 50,
      category: 'Defense Evasion',
      mitre_tactic: 'Defense Evasion',
      mitre_technique_id: 'T1562.001',
      mitre_technique_name: 'Impair Defenses: Disable or Modify Tools',
      conditions: { type: 'agent_heartbeat_loss', timeoutSeconds: 180 },
      remediation_steps: [
        'Verify if host was shutdown or put to sleep by the authorized user.',
        'Inspect host services to confirm VRSOC agent service was not terminated by malware.'
      ],
      enabled: true
    }
  ];

  for (const rule of detectionRules) {
    const { error } = await admin.from('detection_rules').upsert(rule, { onConflict: 'id' });
    if (error) throw new Error(`Rule error: ${error.message}`);
  }

  // 7. Seed Endpoint Events
  console.log('[VRSOC Seed] Seeding endpoint events...');
  const events: Record<string, any>[] = [
    {
      id: '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea',
      organization_id: DEMO_ORGS[0].id,
      agent_id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
      event_type: 'process',
      severity: 'high',
      source: 'simulation',
      event_time: '2026-09-19T11:09:22.912Z',
      data: {
        action: 'EXECUTE',
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==',
        parentPid: 4920,
        parentProcess: 'cmd.exe',
        user: 'Bob Stone',
        hostname: 'vrsoc-workstation-01'
      }
    },
    {
      id: '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4eb',
      organization_id: DEMO_ORGS[0].id,
      agent_id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
      event_type: 'auth',
      severity: 'high',
      source: 'vrsoc-agent',
      event_time: '2026-09-19T11:15:00.000Z',
      data: {
        action: 'logon_failed',
        status: 'failure',
        user: 'Administrator',
        sourceIp: '198.51.100.42',
        hostname: 'vrsoc-dc-01',
        failureReason: 'BadPassword'
      }
    },
    {
      id: '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ec',
      organization_id: DEMO_ORGS[0].id,
      agent_id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
      event_type: 'network',
      severity: 'medium',
      source: 'vrsoc-agent',
      event_time: '2026-09-19T11:20:00.000Z',
      data: {
        action: 'CONNECT',
        sourceIp: '192.168.10.45',
        destinationIp: '198.51.100.42',
        destinationPort: 443,
        protocol: 'TCP',
        bytesSent: 4096
      }
    }
  ];

  for (const ev of events) {
    const { error } = await admin.from('endpoint_events').upsert(ev, { onConflict: 'id' });
    if (error) throw new Error(`Event error: ${error.message}`);
  }

  // 8. Seed Alerts
  console.log('[VRSOC Seed] Seeding alerts...');
  const alerts: Record<string, any>[] = [
    {
      id: 'ALT-20260919-0001',
      organization_id: DEMO_ORGS[0].id,
      agent_id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989da',
      rule_id: 'RULE-PROC-001',
      title: 'Suspicious PowerShell Execution on vrsoc-workstation-01',
      description: "Process 'powershell.exe' was executed with obfuscated or policy bypass command line arguments.",
      severity: 'critical',
      risk_score: 92,
      status: 'open',
      hostname: 'vrsoc-workstation-01',
      username: 'Bob Stone',
      source_ip: '192.168.10.45',
      mitre_tactic: 'Execution',
      mitre_technique: 'Command and Scripting Interpreter: PowerShell',
      mitre_id: 'T1059.001',
      evidence: [
        {
          type: 'Process Telemetry',
          description: 'Command line: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==',
          timestamp: '2026-09-19T11:09:22.912Z',
          data: {
            action: 'EXECUTE',
            processName: 'powershell.exe',
            commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==',
            parentPid: 4920,
            parentProcess: 'cmd.exe',
            user: 'Bob Stone',
            hostname: 'vrsoc-workstation-01'
          },
          state: 'CONFIRMED'
        }
      ],
      trigger_event_ids: ['0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea'],
      assigned_to: userId,
      environment: 'production'
    },
    {
      id: 'ALT-20260919-0002',
      organization_id: DEMO_ORGS[0].id,
      agent_id: '5e2ec8c3-e4b5-4d2d-ab8f-5b4bc89989db',
      rule_id: 'RULE-AUTH-001',
      title: 'Multiple Authentication Failures on vrsoc-dc-01',
      description: 'Repeated failed administrator logon attempts observed from external IP 198.51.100.42.',
      severity: 'high',
      risk_score: 78,
      status: 'investigating',
      hostname: 'vrsoc-dc-01',
      username: 'Administrator',
      source_ip: '198.51.100.42',
      mitre_tactic: 'Credential Access',
      mitre_technique: 'Brute Force: Password Guessing',
      mitre_id: 'T1110.001',
      evidence: [
        {
          type: 'Auth Telemetry',
          description: '5 consecutive authentication failures in 3 minutes',
          timestamp: '2026-09-19T11:15:00.000Z',
          data: {
            user: 'Administrator',
            sourceIp: '198.51.100.42',
            failures: 5
          },
          state: 'CONFIRMED'
        }
      ],
      trigger_event_ids: ['0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4eb'],
      assigned_to: userId,
      environment: 'production'
    }
  ];

  for (const alt of alerts) {
    const { error } = await admin.from('alerts').upsert(alt, { onConflict: 'id' });
    if (error) throw new Error(`Alert error: ${error.message}`);
  }

  // 9. Seed Alert Comments
  console.log('[VRSOC Seed] Seeding alert comments...');
  await admin.from('alert_comments').upsert({
    id: 'c1000000-0000-0000-0000-000000000001',
    alert_id: 'ALT-20260919-0001',
    user_id: userId,
    comment: 'Investigating encoded base64 payload. Parent process was cmd.exe spawned from Outlook temporary attachments.'
  }, { onConflict: 'id' });

  // 10. Seed Incidents
  console.log('[VRSOC Seed] Seeding incidents...');
  const incidents: Record<string, any>[] = [
    {
      id: 'INC-20260919-0001',
      organization_id: DEMO_ORGS[0].id,
      title: 'APT29 Emulated Credential Harvesting & Obfuscated Incursion',
      description: 'Correlated multi-vector security incident involving spearphishing landing page, obfuscated PowerShell execution, and external brute-force targeting domain controller.',
      severity: 'critical',
      status: 'investigating',
      priority: 'P1',
      lead_investigator: userId,
      environment: 'production'
    }
  ];

  for (const inc of incidents) {
    const { error } = await admin.from('incidents').upsert(inc, { onConflict: 'id' });
    if (error) throw new Error(`Incident error: ${error.message}`);
  }

  // 11. Seed Incident Relationships
  console.log('[VRSOC Seed] Seeding incident links, tasks, and timeline...');
  await admin.from('incident_alerts').upsert([
    { incident_id: 'INC-20260919-0001', alert_id: 'ALT-20260919-0001' },
    { incident_id: 'INC-20260919-0001', alert_id: 'ALT-20260919-0002' }
  ], { onConflict: 'incident_id,alert_id' });

  await admin.from('incident_tasks').upsert([
    {
      id: 'a1000000-0000-0000-0000-000000000001',
      incident_id: 'INC-20260919-0001',
      title: 'Isolate workstation vrsoc-workstation-01 from corporate network segment',
      assigned_to: userId,
      completed: true
    },
    {
      id: 'a1000000-0000-0000-0000-000000000002',
      incident_id: 'INC-20260919-0001',
      title: 'Extract and analyze base64 payload strings for C2 staging infrastructure',
      assigned_to: userId,
      completed: true
    },
    {
      id: 'a1000000-0000-0000-0000-000000000003',
      incident_id: 'INC-20260919-0001',
      title: 'Rotate compromised domain administrator and service account credentials',
      assigned_to: userId,
      completed: false
    },
    {
      id: 'a1000000-0000-0000-0000-000000000004',
      incident_id: 'INC-20260919-0001',
      title: 'Publish threat indicators (IP 198.51.100.42) to perimeter firewall blocklists',
      assigned_to: userId,
      completed: false
    }
  ], { onConflict: 'id' });

  await admin.from('incident_timeline').upsert([
    {
      id: 'b1000000-0000-0000-0000-000000000001',
      incident_id: 'INC-20260919-0001',
      event_title: 'Spearphishing Email Delivered',
      event_description: 'User received deceptive Microsoft 365 credential verification link.',
      event_type: 'observation',
      evidence_state: 'CONFIRMED'
    },
    {
      id: 'b1000000-0000-0000-0000-000000000002',
      incident_id: 'INC-20260919-0001',
      event_title: 'Obfuscated PowerShell Execution Detected',
      event_description: 'VRSOC EDR triggered critical alert ALT-20260919-0001 on workstation.',
      event_type: 'detection',
      evidence_state: 'CONFIRMED'
    },
    {
      id: 'b1000000-0000-0000-0000-000000000003',
      incident_id: 'INC-20260919-0001',
      event_title: 'Endpoint Network Isolation Initiated',
      event_description: 'Workstation vrsoc-workstation-01 isolated via VRSOC agent policy.',
      event_type: 'containment',
      evidence_state: 'CONFIRMED'
    }
  ], { onConflict: 'id' });

  // 12. Seed Phishing Scans
  console.log('[VRSOC Seed] Seeding PhishGuard scans...');
  await admin.from('phishing_scans').upsert([
    {
      id: 'e8e44649-ab68-4ea7-abfc-8a4a49f316c0',
      organization_id: DEMO_ORGS[0].id,
      user_id: userId,
      url: 'https://secure-login-microsoft.suspicious-domain-123.com/update',
      normalized_url: 'https://secure-login-microsoft.suspicious-domain-123.com/update',
      classification: 'Suspicious',
      risk_score: 51,
      features: {
        urlLength: 63,
        hasIpAddress: false,
        sensitiveKeywordsFound: ['login', 'update', 'microsoft', 'secure']
      },
      reasons: [
        'Hostname contains hyphens typical of credential harvesting typosquatting.',
        'Contains high-risk credential keywords: [login, update, microsoft, secure].'
      ]
    },
    {
      id: 'e8e44649-ab68-4ea7-abfc-8a4a49f316c1',
      organization_id: DEMO_ORGS[0].id,
      user_id: userId,
      url: 'https://auth-portal-reset.internal-verify-cdn.net/login',
      normalized_url: 'https://auth-portal-reset.internal-verify-cdn.net/login',
      classification: 'Phishing',
      risk_score: 94,
      features: {
        urlLength: 54,
        hasIpAddress: false,
        sensitiveKeywordsFound: ['auth', 'portal', 'reset', 'verify', 'login']
      },
      reasons: [
        'Confirmed deceptive credential phishing lure imitating enterprise SSO portal.',
        'Domain newly registered within last 48 hours.'
      ]
    }
  ], { onConflict: 'id' });

  // 13. Seed Indicators (IOCs)
  console.log('[VRSOC Seed] Seeding Threat Intelligence IOCs...');
  await admin.from('indicators').upsert([
    {
      id: 'd1000000-0000-0000-0000-000000000001',
      organization_id: DEMO_ORGS[0].id,
      type: 'ip',
      value: '198.51.100.42',
      threat_actor: 'APT29',
      confidence: 90,
      tags: ['c2', 'cobalt-strike', 'brute-force'],
      description: 'Known Cobalt Strike command and control IP address involved in active campaigns.'
    },
    {
      id: 'd1000000-0000-0000-0000-000000000002',
      organization_id: DEMO_ORGS[0].id,
      type: 'domain',
      value: 'suspicious-domain-123.com',
      threat_actor: 'Storm-0558',
      confidence: 85,
      tags: ['phishing', 'typosquatting', 'credential-harvesting'],
      description: 'Credential harvesting typosquatting domain impersonating Microsoft 365 login.'
    },
    {
      id: 'd1000000-0000-0000-0000-000000000003',
      organization_id: DEMO_ORGS[0].id,
      type: 'hash_sha256',
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      threat_actor: 'Unknown',
      confidence: 95,
      tags: ['dropper', 'malware', 'powershell'],
      description: 'Obfuscated PowerShell dropper payload hash observed in memory.'
    }
  ], { onConflict: 'id' });

  // 14. Seed Audit Logs
  console.log('[VRSOC Seed] Seeding audit logs...');
  await admin.from('audit_logs').upsert([
    {
      id: 'c31c2dec-b14c-4b7e-a2f7-823ecd7e805d',
      organization_id: DEMO_ORGS[0].id,
      user_id: userId,
      action: 'USER_SIGNUP',
      target_type: 'user',
      target_id: userId,
      details: { organizationName: 'VRsecurity', role: 'Organization Admin' },
      ip_address: '127.0.0.1'
    },
    {
      id: '8f360320-2bff-4425-84c6-d669176b6b28',
      organization_id: DEMO_ORGS[0].id,
      user_id: userId,
      action: 'USER_LOGIN',
      target_type: 'user',
      target_id: userId,
      details: { role: 'Organization Admin' },
      ip_address: '127.0.0.1'
    },
    {
      id: 'a50f4051-9393-492b-b7cd-576c9901fcd7',
      organization_id: DEMO_ORGS[0].id,
      user_id: userId,
      action: 'SIMULATE_THREAT_SCENARIO',
      target_type: 'telemetry_event',
      target_id: '0c8aca5a-37f3-4b2b-9f0f-4f0d19c0b4ea',
      details: { scenario: 'powershell_obfuscated', agent: 'vrsoc-workstation-01', triggeredAlertId: 'ALT-20260919-0001' },
      ip_address: '127.0.0.1'
    }
  ], { onConflict: 'id' });

  // 15. Seed Reports
  console.log('[VRSOC Seed] Seeding reports...');
  await admin.from('reports').upsert([
    {
      id: 'e1000000-0000-0000-0000-000000000001',
      organization_id: DEMO_ORGS[0].id,
      generated_by: userId,
      title: 'Weekly Executive SOC Threat Assessment - September 2026',
      report_type: 'executive',
      content: {
        executiveSummary: 'Defensive posture remains robust across enterprise perimeter with 3 active endpoints monitored.',
        criticalIncidents: 1,
        resolvedAlerts: 14,
        threatsNeutralized: 3
      }
    },
    {
      id: 'e1000000-0000-0000-0000-000000000002',
      organization_id: DEMO_ORGS[0].id,
      generated_by: userId,
      title: 'Incident Post-Mortem: INC-20260919-0001 APT29 Incursion',
      report_type: 'incident',
      target_id: 'INC-20260919-0001',
      content: {
        rootCause: 'Credential phishing landing page bypassed legacy email filtering.',
        containmentTimeMinutes: 12,
        lessonsLearned: 'Enforce FIDO2 WebAuthn authentication across all administrative workstation access.'
      }
    }
  ], { onConflict: 'id' });

  console.log('[VRSOC Seed] Database seed completed successfully!');
}

if (process.argv[1]?.includes('seed-local')) {
  seedLocalData()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[VRSOC Seed] Error seeding database:', err);
      process.exit(1);
    });
}
