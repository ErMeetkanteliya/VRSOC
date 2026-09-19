import crypto from 'crypto';
import { supabaseAdmin, checkSupabaseConfig } from './supabase';

export interface Profile {
  id: string;
  email: string;
  fullName: string;
  phoneNumber?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  mfaEnabled: boolean;
  mfaSecret?: string;
  role: 'Super Admin' | 'Organization Admin' | 'Instructor' | 'SOC Analyst' | 'Incident Responder' | 'Threat Hunter' | 'Auditor' | 'Viewer' | 'Student';
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  vrSocKey: string; // Exactly 14-char hexadecimal key e.g. A7F29C81D40E5B
  status: 'active' | 'suspended';
  retentionDays: number;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationMember {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  createdAt: string;
}

export interface UserSession {
  id: string;
  userId: string;
  organizationId: string;
  sessionToken: string;
  ipAddress?: string;
  userAgent?: string;
  expiresAt: string;
  createdAt: string;
}

export interface Agent {
  id: string;
  organizationId: string;
  name: string;
  hostname: string;
  os: string;
  osVersion: string;
  architecture: string;
  ipAddress: string;
  macAddress?: string;
  agentVersion: string;
  enrollmentKey: string;
  agentToken?: string;
  status: 'online' | 'offline' | 'updating' | 'error' | 'revoked';
  lastSeen: string;
  cpuUsage: number;
  ramUsage: number;
  diskUsage: number;
  tags: string[];
  policy: Record<string, any>;
  health: 'healthy' | 'warning' | 'critical';
  environment: 'production' | 'training' | 'test';
  createdAt: string;
  updatedAt: string;
}

export interface EndpointEvent {
  id: string;
  organizationId: string;
  agentId: string;
  eventType: 'process' | 'file' | 'network' | 'auth' | 'dns' | 'registry' | 'service' | 'usb';
  eventTime: string;
  ingestionTime: string;
  source: string;
  environment: 'production' | 'training' | 'test';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  data: Record<string, any>;
  schemaVersion: string;
}

export interface DetectionRule {
  id: string;
  organizationId?: string | null;
  name: string;
  description: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  category: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  conditions: Record<string, any>;
  remediationSteps: string[];
  enabled: boolean;
  createdAt: string;
}

export interface AlertEvidence {
  type: string;
  description: string;
  timestamp: string;
  data: any;
  state: 'CONFIRMED' | 'INFERRED' | 'UNKNOWN';
}

export interface AlertAiSummary {
  confirmedEvidence: string[];
  inferredInsights: string[];
  unknowns: string[];
  explanation: string;
  investigationSteps: string[];
  containmentSteps: string[];
  recoverySteps: string[];
  generatedAt: string;
}

export interface AlertComment {
  id: string;
  userId: string;
  userName: string;
  comment: string;
  createdAt: string;
}

export interface Alert {
  id: string; // ALT-XXXXXX
  organizationId: string;
  agentId?: string | null;
  ruleId: string;
  title: string;
  description: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
  hostname?: string;
  username?: string;
  sourceIp?: string;
  destinationIp?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  mitreId?: string;
  evidence: AlertEvidence[];
  triggerEventIds: string[];
  aiSummary?: AlertAiSummary;
  assignedTo?: string | null;
  environment: 'production' | 'training' | 'test';
  comments: AlertComment[];
  createdAt: string;
  updatedAt: string;
}

export interface IncidentTimelineItem {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  type: 'alert' | 'action' | 'observation' | 'containment';
  evidenceState: 'CONFIRMED' | 'INFERRED' | 'UNKNOWN';
}

export interface IncidentTask {
  id: string;
  title: string;
  assignedTo?: string | null;
  completed: boolean;
  createdAt: string;
}

export interface IncidentNote {
  id: string;
  userId: string;
  userName: string;
  note: string;
  createdAt: string;
}

export interface Incident {
  id: string; // INC-XXXXXX
  organizationId: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  leadInvestigator?: string | null;
  leadInvestigatorName?: string;
  linkedAlertIds: string[];
  timeline: IncidentTimelineItem[];
  tasks: IncidentTask[];
  notes: IncidentNote[];
  lessonsLearned?: string;
  environment: 'production' | 'training' | 'test';
  createdAt: string;
  updatedAt: string;
}

export interface PhishingScan {
  id: string;
  organizationId: string;
  userId?: string | null;
  url: string;
  normalizedUrl: string;
  classification: 'Safe' | 'Suspicious' | 'Phishing';
  riskScore: number;
  features: {
    urlLength: number;
    hasIpAddress: boolean;
    isShortener: boolean;
    hasAtSymbol: boolean;
    doubleSlashRedirect: boolean;
    hasPrefixSuffix: boolean;
    subdomainsCount: number;
    isHttps: boolean;
    suspiciousTld: boolean;
    hasPort: boolean;
    httpsInDomain: boolean;
    sensitiveKeywordsFound: string[];
    hexEncodingCount: number;
  };
  reasons: string[];
  promotedToAlertId?: string | null;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  organizationId: string;
  userId?: string | null;
  userEmail?: string;
  action: string;
  targetType: string;
  targetId?: string;
  details: Record<string, any>;
  ipAddress?: string;
  createdAt: string;
}

export interface Report {
  id: string;
  organizationId: string;
  generatedBy?: string | null;
  title: string;
  reportType: 'incident' | 'executive' | 'agent_health' | 'phishing';
  targetId?: string;
  content: Record<string, any>;
  createdAt: string;
}

export interface Indicator {
  id: string;
  organizationId: string;
  type: 'ip' | 'domain' | 'hash_sha256' | 'url' | 'email';
  value: string;
  threatActor?: string;
  confidence: number;
  tags: string[];
  description: string;
  createdAt: string;
}

export interface RealMetrics {
  connectedAgentsCount: number;
  onlineAgentsCount: number;
  offlineAgentsCount: number;
  totalAlertsCount: number;
  activeAlertsCount: number;
  criticalAlertsCount: number;
  totalIncidentsCount: number;
  openIncidentsCount: number;
  phishingScansCount: number;
  phishingDetectionsCount: number;
  authFailuresCount: number;
  totalEventsCount: number;
}

export const DEFAULT_DETECTION_RULES: DetectionRule[] = [
  {
    id: 'RULE-AUTH-001',
    organizationId: null,
    name: 'Multiple Authentication Failures (Brute Force Indicator)',
    description: 'Triggers when 5 or more failed logon attempts occur against a single host or account within a 5-minute window.',
    severity: 'high',
    riskScore: 78,
    category: 'Credential Access',
    mitreTactic: 'Credential Access',
    mitreTechniqueId: 'T1110.001',
    mitreTechniqueName: 'Brute Force: Password Guessing',
    conditions: { eventType: 'auth', status: 'failure', threshold: 5, windowMinutes: 5 },
    remediationSteps: [
      'Identify the source IP address or workstation originating the authentication failures.',
      'Temporarily lock or reset the affected account credentials if unauthorized.',
      'Review network edge logs to determine if external proxy/VPN was used.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-AUTH-002',
    organizationId: null,
    name: 'Account Lockout Security Event',
    description: 'Triggers when an endpoint or directory service logs an explicit user account lockout event.',
    severity: 'medium',
    riskScore: 55,
    category: 'Credential Access',
    mitreTactic: 'Credential Access',
    mitreTechniqueId: 'T1110.004',
    mitreTechniqueName: 'Brute Force: Account Lockout',
    conditions: { eventType: 'auth', subType: 'lockout' },
    remediationSteps: [
      'Contact user to verify whether lockout was caused by user error or external attack.',
      'Inspect endpoint audit logs for malicious background services caching stale credentials.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-PROC-001',
    organizationId: null,
    name: 'Suspicious / Obfuscated PowerShell Execution',
    description: 'Detects PowerShell or bash processes invoked with encoded commands, hidden windows, or execution bypass flags.',
    severity: 'critical',
    riskScore: 92,
    category: 'Execution',
    mitreTactic: 'Execution',
    mitreTechniqueId: 'T1059.001',
    mitreTechniqueName: 'Command and Scripting Interpreter: PowerShell',
    conditions: { eventType: 'process', patterns: ['-enc', '-encodedcommand', '-w hidden', '-nop', 'bypass', 'downloadstring', 'iex('] },
    remediationSteps: [
      'Isolate the host immediately from the network segment to prevent lateral movement.',
      'Dump and decode the base64 or obfuscated command line parameter.',
      'Inspect parent process tree to identify the dropper or vector.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-PERS-001',
    organizationId: null,
    name: 'Persistence Indicator: Scheduled Task or Cron Creation',
    description: 'Detects execution of schtasks, crontab, or systemd timer modification to establish persistent autostart.',
    severity: 'high',
    riskScore: 80,
    category: 'Persistence',
    mitreTactic: 'Persistence',
    mitreTechniqueId: 'T1053.005',
    mitreTechniqueName: 'Scheduled Task/Job: Scheduled Task',
    conditions: { eventType: 'process', commandKeywords: ['schtasks /create', 'crontab -e', 'systemctl enable --now'] },
    remediationSteps: [
      'Inspect the created task path and executable payload.',
      'Verify digital signature and authorization of the scheduled binary.',
      'Remove the unauthorized task and terminate any active spawned PIDs.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-NET-001',
    organizationId: null,
    name: 'Network Reconnaissance / Port Scanning Indicator',
    description: 'Detects rapid outbound network connection attempts across multiple destination ports within short timeframe.',
    severity: 'medium',
    riskScore: 65,
    category: 'Discovery',
    mitreTactic: 'Discovery',
    mitreTechniqueId: 'T1046',
    mitreTechniqueName: 'Network Service Discovery',
    conditions: { eventType: 'network', connectionRate: 'high', portSpan: 15 },
    remediationSteps: [
      'Identify if scanning utility (nmap, masscan, netcat) is present on the host.',
      'Review firewall logs for internal subnet enumeration.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-DEV-001',
    organizationId: null,
    name: 'Unauthorized Removable Storage / USB Mass Storage Mount',
    description: 'Detects mounting of external USB mass storage devices on monitored defensive endpoints.',
    severity: 'low',
    riskScore: 40,
    category: 'Initial Access',
    mitreTactic: 'Initial Access',
    mitreTechniqueId: 'T1091',
    mitreTechniqueName: 'Replication Through Removable Media',
    conditions: { eventType: 'usb', action: 'mount' },
    remediationSteps: [
      'Confirm whether endpoint is authorized for removable storage under organization DLP policy.',
      'Check file creation logs on the mounted drive for data exfiltration indicators.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-PHISH-001',
    organizationId: null,
    name: 'High-Risk Phishing URL Ingestion (PhishGuard ML)',
    description: 'Detects URLs classified as Phishing with high model risk score (>= 70) via PhishGuard ML feature analysis.',
    severity: 'high',
    riskScore: 88,
    category: 'Initial Access',
    mitreTactic: 'Initial Access',
    mitreTechniqueId: 'T1566.002',
    mitreTechniqueName: 'Phishing: Spearphishing Link',
    conditions: { eventType: 'phishing', classification: 'Phishing', minScore: 70 },
    remediationSteps: [
      'Block the phishing domain at the enterprise DNS resolver / proxy level.',
      'Check mail gateway and proxy logs for any other users who visited the URL.',
      'Force password reset for any users who submitted credentials to the landing page.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  },
  {
    id: 'RULE-HEART-001',
    organizationId: null,
    name: 'Endpoint Agent Heartbeat Loss',
    description: 'Triggers when a previously active enrolled endpoint agent stops reporting heartbeats for longer than threshold.',
    severity: 'medium',
    riskScore: 50,
    category: 'Defense Evasion',
    mitreTactic: 'Defense Evasion',
    mitreTechniqueId: 'T1562.001',
    mitreTechniqueName: 'Impair Defenses: Disable or Modify Tools',
    conditions: { type: 'agent_heartbeat_loss', timeoutSeconds: 180 },
    remediationSteps: [
      'Verify if host was shutdown or put to sleep by the authorized user.',
      'Inspect host services to confirm VRSOC agent service was not terminated by malware.'
    ],
    enabled: true,
    createdAt: new Date().toISOString()
  }
];

export class Database {
  private get client() {
    if (!supabaseAdmin) {
      throw new Error('Supabase PostgreSQL database is not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
    }
    return supabaseAdmin;
  }

  // Cryptographically secure 14-character hexadecimal VRSOC Key generator
  public generateVrSocKey(): string {
    return crypto.randomBytes(7).toString('hex').toUpperCase();
  }

  // --- Organizations ---
  public async getOrganizationById(id: string): Promise<Organization | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
    const { data, error } = await this.client
      .from('organizations')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (error) throw new Error(`Database error fetching organization: ${error.message}`);
    return data ? this.mapOrg(data) : null;
  }

  public async getOrganizationByKey(key: string): Promise<Organization | null> {
    const cleanKey = key.trim().toUpperCase();
    const { data, error } = await this.client
      .from('organizations')
      .select('*')
      .eq('vr_soc_key', cleanKey)
      .maybeSingle();
    if (error) throw new Error(`Database error fetching organization by key: ${error.message}`);
    return data ? this.mapOrg(data) : null;
  }

  public async createOrganization(name: string): Promise<Organization> {
    const key = this.generateVrSocKey();
    const slugBase = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'org';
    const slug = `${slugBase}-${Date.now().toString(36)}`;
    const { data, error } = await this.client
      .from('organizations')
      .insert({
        name: name.trim(),
        slug,
        vr_soc_key: key,
        status: 'active',
        retention_days: 90
      })
      .select()
      .single();
    if (error) throw new Error(`Database error creating organization: ${error.message}`);
    return this.mapOrg(data);
  }

  public async rotateVrSocKey(orgId: string): Promise<string> {
    const newKey = this.generateVrSocKey();
    const { error } = await this.client
      .from('organizations')
      .update({
        vr_soc_key: newKey,
        updated_at: new Date().toISOString()
      })
      .eq('id', orgId);
    if (error) throw new Error(`Database error rotating VRSOC key: ${error.message}`);
    return newKey;
  }

  // --- Profiles & Memberships ---
  public async getProfileById(id: string): Promise<Profile | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
    const { data, error } = await this.client
      .from('profiles')
      .select('*')
      .eq('id', id)
      .maybeSingle();
    if (error) throw new Error(`Database error fetching profile: ${error.message}`);
    return data ? this.mapProfile(data) : null;
  }

  public async getProfileByEmail(email: string): Promise<Profile | null> {
    const { data, error } = await this.client
      .from('profiles')
      .select('*')
      .ilike('email', email.trim())
      .maybeSingle();
    if (error) throw new Error(`Database error fetching profile by email: ${error.message}`);
    return data ? this.mapProfile(data) : null;
  }

  public async createProfile(
    email: string,
    fullName: string,
    phoneNumber?: string,
    role: Profile['role'] = 'SOC Analyst',
    customId?: string,
    verifiedFlags?: { emailVerified?: boolean; phoneVerified?: boolean; mfaEnabled?: boolean }
  ): Promise<Profile> {
    const id = customId || crypto.randomUUID();
    const { data, error } = await this.client
      .from('profiles')
      .insert({
        id,
        email: email.trim().toLowerCase(),
        full_name: fullName.trim(),
        phone_number: phoneNumber?.trim() || null,
        email_verified: verifiedFlags?.emailVerified ?? false,
        phone_verified: verifiedFlags?.phoneVerified ?? false,
        mfa_enabled: verifiedFlags?.mfaEnabled ?? false,
        role
      })
      .select()
      .single();
    if (error) throw new Error(`Database error creating profile: ${error.message}`);
    return this.mapProfile(data);
  }

  public async updateProfile(id: string, updates: Partial<Profile>): Promise<Profile> {
    const row: Record<string, any> = { updated_at: new Date().toISOString() };
    if (updates.fullName !== undefined) row.full_name = updates.fullName;
    if (updates.phoneNumber !== undefined) row.phone_number = updates.phoneNumber;
    if (updates.emailVerified !== undefined) row.email_verified = updates.emailVerified;
    if (updates.phoneVerified !== undefined) row.phone_verified = updates.phoneVerified;
    if (updates.mfaEnabled !== undefined) row.mfa_enabled = updates.mfaEnabled;
    if (updates.mfaSecret !== undefined) row.mfa_secret = updates.mfaSecret;
    if (updates.role !== undefined) row.role = updates.role;

    const { data, error } = await this.client
      .from('profiles')
      .update(row)
      .eq('id', id)
      .select()
      .single();
    if (error) throw new Error(`Database error updating profile: ${error.message}`);
    return this.mapProfile(data);
  }

  public async getUserOrganizations(userId: string): Promise<Organization[]> {
    const { data: members, error: memError } = await this.client
      .from('organization_members')
      .select('organization_id')
      .eq('user_id', userId);
    if (memError) throw new Error(`Database error querying user organizations: ${memError.message}`);
    if (!members || members.length === 0) return [];

    const orgIds = members.map(m => m.organization_id);
    const { data: orgs, error: orgError } = await this.client
      .from('organizations')
      .select('*')
      .in('id', orgIds);
    if (orgError) throw new Error(`Database error fetching organizations: ${orgError.message}`);
    return (orgs || []).map(o => this.mapOrg(o));
  }

  public async addMember(orgId: string, userId: string, role = 'SOC Analyst'): Promise<OrganizationMember> {
    const { data, error } = await this.client
      .from('organization_members')
      .upsert({
        organization_id: orgId,
        user_id: userId,
        role
      }, { onConflict: 'organization_id,user_id' })
      .select()
      .single();
    if (error) throw new Error(`Database error adding organization member: ${error.message}`);
    return {
      id: data.id,
      organizationId: data.organization_id,
      userId: data.user_id,
      role: data.role,
      createdAt: data.created_at
    };
  }

  public async getMembers(orgId: string): Promise<OrganizationMember[]> {
    const { data, error } = await this.client
      .from('organization_members')
      .select('*')
      .eq('organization_id', orgId);
    if (error) throw new Error(`Database error fetching members: ${error.message}`);
    return (data || []).map(d => ({
      id: d.id,
      organizationId: d.organization_id,
      userId: d.user_id,
      role: d.role,
      createdAt: d.created_at
    }));
  }

  // --- Sessions ---
  public async createSession(userId: string, orgId: string, ip?: string, ua?: string): Promise<UserSession> {
    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data, error } = await this.client
      .from('user_sessions')
      .insert({
        user_id: userId,
        organization_id: orgId,
        session_token: sessionToken,
        ip_address: ip || null,
        user_agent: ua || null,
        expires_at: expiresAt
      })
      .select()
      .single();
    if (error) throw new Error(`Database error creating user session: ${error.message}`);
    return {
      id: data.id,
      userId: data.user_id,
      organizationId: data.organization_id,
      sessionToken: data.session_token,
      ipAddress: data.ip_address,
      userAgent: data.user_agent,
      expiresAt: data.expires_at,
      createdAt: data.created_at
    };
  }

  public async getSession(token: string): Promise<{ profile: Profile; organization: Organization; sessionToken: string } | null> {
    const { data: session, error } = await this.client
      .from('user_sessions')
      .select('*')
      .eq('session_token', token)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    if (error || !session) return null;

    const [profile, organization] = await Promise.all([
      this.getProfileById(session.user_id),
      this.getOrganizationById(session.organization_id)
    ]);
    if (!profile || !organization) return null;
    return { profile, organization, sessionToken: token };
  }

  public async deleteSession(token: string): Promise<void> {
    await this.client
      .from('user_sessions')
      .delete()
      .eq('session_token', token);
  }

  // --- Agents & Credentials ---
  public hashAgentToken(token: string): string {
    return crypto.createHash('sha256').update(token.trim()).digest('hex');
  }

  public generateAgentToken(): { rawToken: string; tokenHash: string } {
    const rawToken = 'vrsoc_agt_' + crypto.randomBytes(24).toString('hex');
    const tokenHash = this.hashAgentToken(rawToken);
    return { rawToken, tokenHash };
  }

  public async getAgentByToken(token: string): Promise<Agent | null> {
    if (!token || typeof token !== 'string') return null;
    const cleanToken = token.trim();
    const tokenHash = this.hashAgentToken(cleanToken);

    // 1. Primary lookup by agent_token_hash column
    const { data: hashedAgent, error: hashError } = await this.client
      .from('agents')
      .select('*')
      .eq('agent_token_hash', tokenHash)
      .maybeSingle();

    if (!hashError && hashedAgent) {
      return this.mapAgent(hashedAgent);
    }

    // 2. Fallback lookup for legacy seed or policy token (auto-migrate to hash)
    const { data: legacyAgents, error: legError } = await this.client
      .from('agents')
      .select('*');

    if (!legError && legacyAgents) {
      const match = legacyAgents.find(a => {
        const pol = a.policy || {};
        return pol.agentToken === cleanToken || a.id === cleanToken;
      });
      if (match) {
        // Auto-migrate to hash
        await this.client
          .from('agents')
          .update({
            agent_token_hash: tokenHash,
            policy: { ...(match.policy || {}), agentToken: undefined }
          })
          .eq('id', match.id);
        return this.mapAgent({ ...match, agent_token_hash: tokenHash });
      }
    }

    return null;
  }

  public async getAgents(orgId: string): Promise<Agent[]> {
    const { data, error } = await this.client
      .from('agents')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false });
    if (error) throw new Error(`Database error fetching agents: ${error.message}`);
    return (data || []).map(a => this.mapAgent(a));
  }

  public async getAgentById(id: string, orgId?: string): Promise<Agent | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
    let query = this.client
      .from('agents')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(`Database error fetching agent by id: ${error.message}`);
    return data ? this.mapAgent(data) : null;
  }

  public async createAgent(agent: Omit<Agent, 'id' | 'createdAt' | 'updatedAt'> & { rawToken?: string }): Promise<{ agent: Agent; agentToken: string }> {
    const { rawToken, tokenHash } = agent.rawToken
      ? { rawToken: agent.rawToken, tokenHash: this.hashAgentToken(agent.rawToken) }
      : this.generateAgentToken();

    const safePolicy = { ...(agent.policy || {}) };
    delete (safePolicy as any).agentToken;

    const row = {
      organization_id: agent.organizationId,
      name: agent.name,
      hostname: agent.hostname,
      os: agent.os,
      os_version: agent.osVersion,
      architecture: agent.architecture || 'x64',
      ip_address: agent.ipAddress,
      mac_address: agent.macAddress || null,
      agent_version: agent.agentVersion || '1.4.0',
      enrollment_key: agent.enrollmentKey,
      agent_token_hash: tokenHash,
      status: agent.status || 'online',
      last_seen: agent.lastSeen || new Date().toISOString(),
      cpu_usage: agent.cpuUsage ?? 0,
      ram_usage: agent.ramUsage ?? 0,
      disk_usage: agent.diskUsage ?? 0,
      tags: agent.tags || [],
      policy: safePolicy,
      health: agent.health || 'healthy',
      environment: agent.environment || 'production'
    };
    const { data, error } = await this.client
      .from('agents')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error creating agent: ${error.message}`);
    return {
      agent: this.mapAgent(data),
      agentToken: rawToken
    };
  }

  public async updateAgent(id: string, updates: Partial<Agent> & { rawToken?: string }, orgId?: string): Promise<{ agent: Agent; agentToken?: string }> {
    const row: Record<string, any> = { updated_at: new Date().toISOString() };
    if (updates.name !== undefined) row.name = updates.name;
    if (updates.ipAddress !== undefined) row.ip_address = updates.ipAddress;
    if (updates.status !== undefined) row.status = updates.status;
    if (updates.lastSeen !== undefined) row.last_seen = updates.lastSeen;
    if (updates.cpuUsage !== undefined) row.cpu_usage = updates.cpuUsage;
    if (updates.ramUsage !== undefined) row.ram_usage = updates.ramUsage;
    if (updates.diskUsage !== undefined) row.disk_usage = updates.diskUsage;
    if (updates.tags !== undefined) row.tags = updates.tags;
    if (updates.policy !== undefined) row.policy = updates.policy;
    if (updates.health !== undefined) row.health = updates.health;
    if (updates.agentVersion !== undefined) row.agent_version = updates.agentVersion;

    let newRawToken: string | undefined;
    if (updates.rawToken) {
      newRawToken = updates.rawToken;
      row.agent_token_hash = this.hashAgentToken(newRawToken);
    }

    let query = this.client
      .from('agents')
      .update(row)
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query
      .select()
      .maybeSingle();
    if (error) throw new Error(`Database error updating agent: ${error.message}`);
    if (!data) throw new Error('Agent not found or cross-tenant access denied');
    return {
      agent: this.mapAgent(data),
      agentToken: newRawToken
    };
  }

  public async revokeAgent(id: string, orgId?: string): Promise<Agent> {
    let query = this.client
      .from('agents')
      .update({
        status: 'revoked',
        updated_at: new Date().toISOString()
      })
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query
      .select()
      .maybeSingle();
    if (error) throw new Error(`Database error revoking agent: ${error.message}`);
    if (!data) throw new Error('Agent not found or cross-tenant access denied');
    return this.mapAgent(data);
  }

  public async addAgentHeartbeat(record: {
    agentId: string;
    organizationId: string;
    cpuPercent?: number;
    ramPercent?: number;
    diskPercent?: number;
    activeProcessesCount?: number;
    networkConnectionsCount?: number;
  }): Promise<void> {
    const row = {
      agent_id: record.agentId,
      organization_id: record.organizationId,
      cpu_percent: record.cpuPercent ?? null,
      ram_percent: record.ramPercent ?? null,
      disk_percent: record.diskPercent ?? null,
      active_processes_count: record.activeProcessesCount ?? null,
      network_connections_count: record.networkConnectionsCount ?? null,
      heartbeat_time: new Date().toISOString()
    };
    const { error } = await this.client
      .from('agent_heartbeats')
      .insert(row);
    if (error) {
      console.warn(`[Agent Heartbeat Insert Warning] ${error.message}`);
    }
  }

  // --- Endpoint Telemetry Events ---
  public normalizeEndpointEvent(raw: {
    eventType?: string;
    eventTime?: string;
    severity?: string;
    data?: Record<string, any>;
    source?: string;
  }, agent: Agent): Omit<EndpointEvent, 'id' | 'ingestionTime'> {
    const validEventTypes = ['process', 'file', 'network', 'auth', 'dns', 'registry', 'service', 'usb'] as const;
    let eventType: 'process' | 'file' | 'network' | 'auth' | 'dns' | 'registry' | 'service' | 'usb' = 'process';
    if (raw.eventType && validEventTypes.includes(raw.eventType as any)) {
      eventType = raw.eventType as any;
    }

    const validSeverities = ['info', 'low', 'medium', 'high', 'critical'] as const;
    let severity: 'info' | 'low' | 'medium' | 'high' | 'critical' = 'info';
    if (raw.severity && validSeverities.includes(raw.severity as any)) {
      severity = raw.severity as any;
    }

    // Timestamp sanitization: prevent future timestamp spoofing, bounded clock skew (max 5m future, 30d past)
    const now = Date.now();
    let sanitizedEventTime = new Date().toISOString();
    if (raw.eventTime) {
      const parsedTime = new Date(raw.eventTime).getTime();
      if (!isNaN(parsedTime) && parsedTime <= now + 300000 && parsedTime >= now - (30 * 86400000)) {
        sanitizedEventTime = new Date(raw.eventTime).toISOString();
      }
    }

    const rawData = raw.data && typeof raw.data === 'object' ? raw.data : {};
    const normalizedData: Record<string, any> = {
      ...rawData,
      hostname: rawData.hostname || agent.hostname || 'Unknown Host',
      username: rawData.username || rawData.user || null,
      processName: rawData.processName || rawData.name || null,
      commandLine: rawData.commandLine || rawData.command || null,
      sourceIp: rawData.sourceIp || rawData.ip || agent.ipAddress || null,
      destinationIp: rawData.destinationIp || rawData.destIp || null,
      destinationPort: rawData.destinationPort || rawData.destPort || null,
      filePath: rawData.filePath || rawData.path || null,
      fileHash: rawData.fileHash || rawData.hash || rawData.sha256 || null
    };

    return {
      organizationId: agent.organizationId,
      agentId: agent.id,
      eventType,
      eventTime: sanitizedEventTime,
      source: raw.source || 'vrsoc-agent',
      environment: agent.environment || 'production',
      severity,
      data: normalizedData,
      schemaVersion: '1.0'
    };
  }

  public async addEndpointEvent(event: Omit<EndpointEvent, 'id' | 'ingestionTime'>): Promise<EndpointEvent> {
    const row = {
      organization_id: event.organizationId,
      agent_id: event.agentId,
      event_type: event.eventType,
      event_time: event.eventTime || new Date().toISOString(),
      source: event.source || 'vrsoc-agent',
      environment: event.environment || 'production',
      severity: event.severity || 'info',
      data: event.data || {},
      schema_version: event.schemaVersion || '1.0'
    };
    const { data, error } = await this.client
      .from('endpoint_events')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error logging endpoint event: ${error.message}`);
    return this.mapEndpointEvent(data);
  }

  public async getEndpointEvents(orgId: string, limit = 100, agentId?: string, eventType?: string): Promise<EndpointEvent[]> {
    let query = this.client
      .from('endpoint_events')
      .select('*')
      .eq('organization_id', orgId);
    if (agentId) query = query.eq('agent_id', agentId);
    if (eventType) query = query.eq('event_type', eventType);

    const { data, error } = await query
      .order('event_time', { ascending: false })
      .limit(limit);
    if (error) throw new Error(`Database error fetching endpoint events: ${error.message}`);
    return (data || []).map(e => this.mapEndpointEvent(e));
  }

  // --- Detection Rules ---
  public async getDetectionRules(orgId?: string | null): Promise<DetectionRule[]> {
    let query = this.client.from('detection_rules').select('*');
    if (orgId) {
      query = query.or(`organization_id.eq.${orgId},organization_id.is.null`);
    } else {
      query = query.is('organization_id', null);
    }
    const { data, error } = await query.order('created_at', { ascending: true });
    if (error) throw new Error(`Database error fetching detection rules: ${error.message}`);
    if (!data || data.length === 0) return DEFAULT_DETECTION_RULES;
    return data.map(r => this.mapRule(r));
  }

  public async getDetectionRuleById(id: string, orgId?: string): Promise<DetectionRule | null> {
    let query = this.client
      .from('detection_rules')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.or(`organization_id.eq.${orgId},organization_id.is.null`);
    }
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(`Database error fetching detection rule: ${error.message}`);
    return data ? this.mapRule(data) : null;
  }

  public async toggleDetectionRule(id: string, enabled: boolean, orgId?: string): Promise<DetectionRule | null> {
    // If orgId is provided, verify it is either global or matches orgId
    if (orgId) {
      const existing = await this.getDetectionRuleById(id, orgId);
      if (!existing) throw new Error('Detection rule not found or cross-tenant access denied');
    }

    const { data, error } = await this.client
      .from('detection_rules')
      .update({ enabled })
      .eq('id', id)
      .select()
      .maybeSingle();
    if (error) throw new Error(`Database error toggling detection rule: ${error.message}`);
    return data ? this.mapRule(data) : null;
  }

  public async addDetectionRule(rule: DetectionRule): Promise<DetectionRule> {
    const row = {
      id: rule.id,
      organization_id: rule.organizationId || null,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      risk_score: rule.riskScore,
      category: rule.category,
      mitre_tactic: rule.mitreTactic,
      mitre_technique_id: rule.mitreTechniqueId,
      mitre_technique_name: rule.mitreTechniqueName,
      conditions: rule.conditions,
      remediation_steps: rule.remediationSteps || [],
      enabled: rule.enabled ?? true
    };
    const { data, error } = await this.client
      .from('detection_rules')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error adding detection rule: ${error.message}`);
    return this.mapRule(data);
  }

  // --- Alerts & Comments ---
  public async getAlerts(orgId: string, environment = 'production'): Promise<Alert[]> {
    const { data: alerts, error: alertError } = await this.client
      .from('alerts')
      .select('*')
      .eq('organization_id', orgId)
      .eq('environment', environment)
      .order('created_at', { ascending: false });
    if (alertError) throw new Error(`Database error fetching alerts: ${alertError.message}`);
    if (!alerts || alerts.length === 0) return [];

    const alertIds = alerts.map(a => a.id);
    const { data: comments, error: commentError } = await this.client
      .from('alert_comments')
      .select('*')
      .in('alert_id', alertIds)
      .order('created_at', { ascending: true });
    if (commentError) throw new Error(`Database error fetching alert comments: ${commentError.message}`);

    return alerts.map(a => this.mapAlert(a, comments?.filter(c => c.alert_id === a.id) || []));
  }

  public async getAlertById(id: string, orgId?: string): Promise<Alert | null> {
    let query = this.client
      .from('alerts')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data: alert, error: alertError } = await query.maybeSingle();
    if (alertError) throw new Error(`Database error fetching alert by id: ${alertError.message}`);
    if (!alert) return null;

    const { data: comments, error: commentError } = await this.client
      .from('alert_comments')
      .select('*')
      .eq('alert_id', id)
      .order('created_at', { ascending: true });
    if (commentError) throw new Error(`Database error fetching comments: ${commentError.message}`);

    return this.mapAlert(alert, comments || []);
  }

  public async createAlert(alert: Omit<Alert, 'id' | 'comments' | 'createdAt' | 'updatedAt'>): Promise<Alert> {
    const alertId = `ALT-${Date.now().toString(36).toUpperCase()}-${Math.floor(100 + Math.random() * 900)}`;
    const row = {
      id: alertId,
      organization_id: alert.organizationId,
      agent_id: alert.agentId || null,
      rule_id: alert.ruleId,
      title: alert.title,
      description: alert.description,
      severity: alert.severity || 'medium',
      risk_score: alert.riskScore || 50,
      status: alert.status || 'open',
      hostname: alert.hostname || null,
      username: alert.username || null,
      source_ip: alert.sourceIp || null,
      destination_ip: alert.destinationIp || null,
      mitre_tactic: alert.mitreTactic || null,
      mitre_technique: alert.mitreTechnique || null,
      mitre_id: alert.mitreId || null,
      evidence: alert.evidence || [],
      trigger_event_ids: alert.triggerEventIds || [],
      ai_summary: alert.aiSummary || null,
      assigned_to: alert.assignedTo || null,
      environment: alert.environment || 'production'
    };
    const { data, error } = await this.client
      .from('alerts')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error creating alert: ${error.message}`);
    return this.mapAlert(data, []);
  }

  public async updateAlert(id: string, updates: Partial<Alert>, orgId?: string): Promise<Alert> {
    const row: Record<string, any> = { updated_at: new Date().toISOString() };
    if (updates.status !== undefined) row.status = updates.status;
    if (updates.aiSummary !== undefined) row.ai_summary = updates.aiSummary;
    if (updates.assignedTo !== undefined) row.assigned_to = updates.assignedTo;

    let query = this.client
      .from('alerts')
      .update(row)
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query
      .select()
      .maybeSingle();
    if (error) throw new Error(`Database error updating alert: ${error.message}`);
    if (!data) throw new Error('Alert not found or cross-tenant access denied');
    
    return this.getAlertById(id, orgId) as Promise<Alert>;
  }

  public async addAlertComment(alertId: string, userId: string, userName: string, comment: string, orgId?: string): Promise<Alert> {
    const alert = await this.getAlertById(alertId, orgId);
    if (!alert) throw new Error('Alert not found or cross-tenant access denied');

    const { error } = await this.client
      .from('alert_comments')
      .insert({
        alert_id: alertId,
        user_id: userId,
        comment: `[${userName}] ${comment}`
      });
    if (error) throw new Error(`Database error adding alert comment: ${error.message}`);
    const updated = await this.getAlertById(alertId, orgId);
    if (!updated) throw new Error('Alert not found after adding comment');
    return updated;
  }

  // --- Incidents, Tasks & Timeline ---
  public async getIncidents(orgId: string, environment = 'production'): Promise<Incident[]> {
    const { data: incidents, error: incError } = await this.client
      .from('incidents')
      .select('*')
      .eq('organization_id', orgId)
      .eq('environment', environment)
      .order('created_at', { ascending: false });
    if (incError) throw new Error(`Database error fetching incidents: ${incError.message}`);
    if (!incidents || incidents.length === 0) return [];

    const incidentIds = incidents.map(i => i.id);
    const [alertsRes, tasksRes, timelineRes] = await Promise.all([
      this.client.from('incident_alerts').select('*').in('incident_id', incidentIds),
      this.client.from('incident_tasks').select('*').in('incident_id', incidentIds),
      this.client.from('incident_timeline').select('*').in('incident_id', incidentIds).order('event_timestamp', { ascending: true })
    ]);

    if (alertsRes.error) throw new Error(`Database error fetching incident alerts: ${alertsRes.error.message}`);
    if (tasksRes.error) throw new Error(`Database error fetching incident tasks: ${tasksRes.error.message}`);
    if (timelineRes.error) throw new Error(`Database error fetching incident timeline: ${timelineRes.error.message}`);

    return incidents.map(inc => this.mapIncident(
      inc,
      alertsRes.data?.filter(a => a.incident_id === inc.id) || [],
      tasksRes.data?.filter(t => t.incident_id === inc.id) || [],
      timelineRes.data?.filter(tl => tl.incident_id === inc.id) || []
    ));
  }

  public async getIncidentById(id: string, orgId?: string): Promise<Incident | null> {
    let query = this.client
      .from('incidents')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data: incident, error: incError } = await query.maybeSingle();
    if (incError) throw new Error(`Database error fetching incident by id: ${incError.message}`);
    if (!incident) return null;

    const [alertsRes, tasksRes, timelineRes] = await Promise.all([
      this.client.from('incident_alerts').select('*').eq('incident_id', id),
      this.client.from('incident_tasks').select('*').eq('incident_id', id),
      this.client.from('incident_timeline').select('*').eq('incident_id', id).order('event_timestamp', { ascending: true })
    ]);

    return this.mapIncident(
      incident,
      alertsRes.data || [],
      tasksRes.data || [],
      timelineRes.data || []
    );
  }

  public async createIncident(incident: Omit<Incident, 'id' | 'tasks' | 'timeline' | 'notes' | 'createdAt' | 'updatedAt'>): Promise<Incident> {
    const incidentId = `INC-${Date.now().toString(36).toUpperCase()}-${Math.floor(100 + Math.random() * 900)}`;
    const row = {
      id: incidentId,
      organization_id: incident.organizationId,
      title: incident.title,
      description: incident.description,
      severity: incident.severity || 'medium',
      status: incident.status || 'open',
      priority: incident.priority || 'P2',
      lead_investigator: incident.leadInvestigator || null,
      summary_report: { leadInvestigatorName: incident.leadInvestigatorName || 'Unassigned', notes: [] },
      lessons_learned: incident.lessonsLearned || '',
      environment: incident.environment || 'production'
    };
    const { error: insertError } = await this.client
      .from('incidents')
      .insert(row);
    if (insertError) throw new Error(`Database error creating incident: ${insertError.message}`);

    if (incident.linkedAlertIds && incident.linkedAlertIds.length > 0) {
      const alertRows = incident.linkedAlertIds.map(alertId => ({
        incident_id: incidentId,
        alert_id: alertId
      }));
      await this.client.from('incident_alerts').insert(alertRows);
    }

    const created = await this.getIncidentById(incidentId, incident.organizationId);
    if (!created) throw new Error('Incident not found after creation');
    return created;
  }

  public async updateIncident(id: string, updates: Partial<Incident>, orgId?: string): Promise<Incident> {
    const existing = await this.getIncidentById(id, orgId);
    if (!existing) throw new Error('Incident not found or cross-tenant access denied');

    const row: Record<string, any> = { updated_at: new Date().toISOString() };
    if (updates.title !== undefined) row.title = updates.title;
    if (updates.description !== undefined) row.description = updates.description;
    if (updates.severity !== undefined) row.severity = updates.severity;
    if (updates.status !== undefined) row.status = updates.status;
    if (updates.priority !== undefined) row.priority = updates.priority;
    if (updates.leadInvestigator !== undefined) row.lead_investigator = updates.leadInvestigator;
    if (updates.lessonsLearned !== undefined) row.lessons_learned = updates.lessonsLearned;

    let query = this.client
      .from('incidents')
      .update(row)
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { error } = await query;
    if (error) throw new Error(`Database error updating incident: ${error.message}`);

    if (updates.linkedAlertIds !== undefined) {
      await this.client.from('incident_alerts').delete().eq('incident_id', id);
      if (updates.linkedAlertIds.length > 0) {
        await this.client.from('incident_alerts').insert(
          updates.linkedAlertIds.map(aid => ({ incident_id: id, alert_id: aid }))
        );
      }
    }

    const updated = await this.getIncidentById(id, orgId);
    if (!updated) throw new Error('Incident not found after update');
    return updated;
  }

  public async linkAlertToIncident(incidentId: string, alertId: string, orgId?: string): Promise<Incident> {
    const inc = await this.getIncidentById(incidentId, orgId);
    if (!inc) throw new Error('Incident not found or cross-tenant access denied');

    const alert = await this.getAlertById(alertId, orgId);
    if (!alert) throw new Error('Alert not found or cross-tenant access denied');

    // Upsert incident_alert link
    await this.client
      .from('incident_alerts')
      .upsert({
        incident_id: incidentId,
        alert_id: alertId
      }, { onConflict: 'incident_id,alert_id' });

    // Add timeline entry
    await this.client
      .from('incident_timeline')
      .insert({
        incident_id: incidentId,
        event_title: `Correlated Alert: ${alert.title}`,
        event_description: `Alert ${alertId} (${alert.severity.toUpperCase()} / Risk ${alert.riskScore}) automatically correlated to this incident investigation.`,
        event_type: 'alert',
        evidence_state: 'CONFIRMED',
        event_timestamp: new Date().toISOString()
      });

    const updated = await this.getIncidentById(incidentId, orgId);
    if (!updated) throw new Error('Incident not found after linking alert');
    return updated;
  }

  public async addIncidentTask(incidentId: string, title: string, assignedTo?: string, orgId?: string): Promise<Incident> {
    const inc = await this.getIncidentById(incidentId, orgId);
    if (!inc) throw new Error('Incident not found or cross-tenant access denied');

    const { error } = await this.client
      .from('incident_tasks')
      .insert({
        incident_id: incidentId,
        title,
        assigned_to: assignedTo || null,
        completed: false
      });
    if (error) throw new Error(`Database error adding incident task: ${error.message}`);
    const updated = await this.getIncidentById(incidentId, orgId);
    if (!updated) throw new Error('Incident not found after task creation');
    return updated;
  }

  public async toggleIncidentTask(incidentId: string, taskId: string, completed: boolean, orgId?: string): Promise<Incident> {
    const inc = await this.getIncidentById(incidentId, orgId);
    if (!inc) throw new Error('Incident not found or cross-tenant access denied');

    const { error } = await this.client
      .from('incident_tasks')
      .update({ completed })
      .eq('id', taskId)
      .eq('incident_id', incidentId);
    if (error) throw new Error(`Database error toggling task: ${error.message}`);
    const updated = await this.getIncidentById(incidentId, orgId);
    if (!updated) throw new Error('Incident not found after task update');
    return updated;
  }

  public async addIncidentTimelineItem(incidentId: string, item: { title: string; description?: string; type?: 'alert' | 'action' | 'observation' | 'containment'; evidenceState?: 'CONFIRMED' | 'INFERRED' | 'UNKNOWN'; timestamp?: string }, orgId?: string): Promise<Incident> {
    const inc = await this.getIncidentById(incidentId, orgId);
    if (!inc) throw new Error('Incident not found or cross-tenant access denied');

    const { error } = await this.client
      .from('incident_timeline')
      .insert({
        incident_id: incidentId,
        event_title: item.title,
        event_description: item.description || '',
        event_type: item.type || 'observation',
        evidence_state: item.evidenceState || 'CONFIRMED',
        event_timestamp: item.timestamp || new Date().toISOString()
      });
    if (error) throw new Error(`Database error recording timeline item: ${error.message}`);
    const updated = await this.getIncidentById(incidentId, orgId);
    if (!updated) throw new Error('Incident not found after timeline addition');
    return updated;
  }

  public async addIncidentNote(incidentId: string, userId: string, userName: string, note: string, orgId?: string): Promise<Incident> {
    const inc = await this.getIncidentById(incidentId, orgId);
    if (!inc) throw new Error('Incident not found or cross-tenant access denied');

    const existingNotes = inc.notes || [];
    const updatedNotes = [...existingNotes, { id: crypto.randomUUID(), userId, userName, note, createdAt: new Date().toISOString() }];
    const currentReport = (inc as any).summaryReport || {};
    const { error } = await this.client
      .from('incidents')
      .update({
        summary_report: { ...currentReport, notes: updatedNotes, leadInvestigatorName: inc.leadInvestigatorName || 'Unassigned' },
        updated_at: new Date().toISOString()
      })
      .eq('id', incidentId);
    if (error) throw new Error(`Database error adding note: ${error.message}`);

    const updated = await this.getIncidentById(incidentId, orgId);
    if (!updated) throw new Error('Incident not found after adding note');
    return updated;
  }

  // --- PhishGuard Scans ---
  public async addPhishingScan(scan: Omit<PhishingScan, 'id' | 'createdAt'>): Promise<PhishingScan> {
    const row = {
      organization_id: scan.organizationId,
      user_id: scan.userId || null,
      url: scan.url,
      normalized_url: scan.normalizedUrl,
      classification: scan.classification,
      risk_score: scan.riskScore,
      features: scan.features,
      reasons: scan.reasons || [],
      promoted_to_alert_id: scan.promotedToAlertId || null
    };
    const { data, error } = await this.client
      .from('phishing_scans')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error storing phishing scan: ${error.message}`);
    return this.mapPhishingScan(data);
  }

  public async getPhishingScans(orgId: string): Promise<PhishingScan[]> {
    const { data, error } = await this.client
      .from('phishing_scans')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false });
    if (error) throw new Error(`Database error fetching phishing scans: ${error.message}`);
    return (data || []).map(s => this.mapPhishingScan(s));
  }

  public async getPhishingScanById(id: string, orgId?: string): Promise<PhishingScan | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
    let query = this.client
      .from('phishing_scans')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(`Database error fetching phishing scan: ${error.message}`);
    return data ? this.mapPhishingScan(data) : null;
  }

  // --- Threat Indicators (IOCs) ---
  public async getIndicators(orgId: string): Promise<Indicator[]> {
    const { data, error } = await this.client
      .from('indicators')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false });
    if (error) throw new Error(`Database error fetching IOC indicators: ${error.message}`);
    return (data || []).map(i => this.mapIndicator(i));
  }

  public async addIndicator(indicator: Omit<Indicator, 'id' | 'createdAt'>): Promise<Indicator> {
    const row = {
      organization_id: indicator.organizationId,
      type: indicator.type,
      value: indicator.value,
      threat_actor: indicator.threatActor || null,
      confidence: indicator.confidence || 70,
      tags: indicator.tags || [],
      description: indicator.description || ''
    };
    const { data, error } = await this.client
      .from('indicators')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error saving indicator: ${error.message}`);
    return this.mapIndicator(data);
  }

  // --- Audit Logs ---
  public async addAuditLog(log: Omit<AuditLog, 'id' | 'createdAt'>): Promise<AuditLog> {
    const row = {
      organization_id: log.organizationId,
      user_id: log.userId || null,
      action: log.action,
      target_type: log.targetType,
      target_id: log.targetId || null,
      details: log.details || {},
      ip_address: log.ipAddress || null
    };
    const { data, error } = await this.client
      .from('audit_logs')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error writing audit log: ${error.message}`);
    return this.mapAuditLog(data);
  }

  public async getAuditLogs(orgId: string, limit = 100): Promise<AuditLog[]> {
    const { data, error } = await this.client
      .from('audit_logs')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .limit(limit);
    if (error) throw new Error(`Database error fetching audit logs: ${error.message}`);
    return (data || []).map(a => this.mapAuditLog(a));
  }

  // --- Reports ---
  public async addReport(report: Omit<Report, 'id' | 'createdAt'>): Promise<Report> {
    const row = {
      organization_id: report.organizationId,
      generated_by: report.generatedBy || null,
      title: report.title,
      report_type: report.reportType,
      target_id: report.targetId || null,
      content: report.content || {}
    };
    const { data, error } = await this.client
      .from('reports')
      .insert(row)
      .select()
      .single();
    if (error) throw new Error(`Database error saving report: ${error.message}`);
    return this.mapReport(data);
  }

  public async getReports(orgId: string): Promise<Report[]> {
    const { data, error } = await this.client
      .from('reports')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false });
    if (error) throw new Error(`Database error fetching reports: ${error.message}`);
    return (data || []).map(r => this.mapReport(r));
  }

  public async getReportById(id: string, orgId?: string): Promise<Report | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) && !id.startsWith('REP-')) return null;
    let query = this.client
      .from('reports')
      .select('*')
      .eq('id', id);
    if (orgId) {
      query = query.eq('organization_id', orgId);
    }
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(`Database error fetching report: ${error.message}`);
    return data ? this.mapReport(data) : null;
  }

  // --- Real Metrics Aggregator ---
  public async getRealMetrics(orgId: string, environment = 'production'): Promise<RealMetrics> {
    const [agents, alerts, incidents, phishingScans, events] = await Promise.all([
      this.getAgents(orgId),
      this.getAlerts(orgId, environment),
      this.getIncidents(orgId, environment),
      this.getPhishingScans(orgId),
      this.getEndpointEvents(orgId, 200)
    ]);

    const envAgents = agents.filter(a => a.environment === environment);
    const onlineAgents = envAgents.filter(a => a.status === 'online');
    const offlineAgents = envAgents.filter(a => a.status === 'offline');

    const activeAlerts = alerts.filter(a => a.status === 'open' || a.status === 'investigating');
    const criticalAlerts = alerts.filter(a => a.severity === 'critical' && (a.status === 'open' || a.status === 'investigating'));

    const openIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating');
    const phishingDetections = phishingScans.filter(s => s.classification === 'Phishing');
    const authFailures = events.filter(e => e.eventType === 'auth' && (e.data?.status === 'failure' || e.data?.action === 'logon_failed'));

    return {
      connectedAgentsCount: envAgents.length,
      onlineAgentsCount: onlineAgents.length,
      offlineAgentsCount: offlineAgents.length,
      totalAlertsCount: alerts.length,
      activeAlertsCount: activeAlerts.length,
      criticalAlertsCount: criticalAlerts.length,
      totalIncidentsCount: incidents.length,
      openIncidentsCount: openIncidents.length,
      phishingScansCount: phishingScans.length,
      phishingDetectionsCount: phishingDetections.length,
      authFailuresCount: authFailures.length,
      totalEventsCount: events.length
    };
  }

  // --- Entity Transformation Mappers ---
  private mapOrg(row: any): Organization {
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      vrSocKey: row.vr_soc_key,
      status: row.status,
      retentionDays: row.retention_days || 90,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapProfile(row: any): Profile {
    return {
      id: row.id,
      email: row.email,
      fullName: row.full_name,
      phoneNumber: row.phone_number || undefined,
      emailVerified: Boolean(row.email_verified),
      phoneVerified: Boolean(row.phone_verified),
      mfaEnabled: Boolean(row.mfa_enabled),
      mfaSecret: row.mfa_secret || undefined,
      role: row.role || 'SOC Analyst',
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapAgent(row: any): Agent {
    const policy = row.policy || {};
    const isRevoked = row.status === 'revoked';
    const lastSeenTime = new Date(row.last_seen || row.created_at).getTime();
    const isOnline = !isRevoked && (Date.now() - lastSeenTime <= 30000);
    const computedStatus = isRevoked ? 'revoked' : (isOnline ? 'online' : 'offline');

    return {
      id: row.id,
      organizationId: row.organization_id,
      name: row.name,
      hostname: row.hostname,
      os: row.os,
      osVersion: row.os_version || '1.0',
      architecture: row.architecture || 'x64',
      ipAddress: row.ip_address,
      macAddress: row.mac_address || undefined,
      agentVersion: row.agent_version || '1.4.0',
      enrollmentKey: row.enrollment_key,
      status: computedStatus,
      lastSeen: row.last_seen,
      cpuUsage: Number(row.cpu_usage) || 0,
      ramUsage: Number(row.ram_usage) || 0,
      diskUsage: Number(row.disk_usage) || 0,
      tags: row.tags || [],
      policy,
      health: row.health || 'healthy',
      environment: row.environment || 'production',
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapEndpointEvent(row: any): EndpointEvent {
    return {
      id: row.id,
      organizationId: row.organization_id,
      agentId: row.agent_id,
      eventType: row.event_type,
      eventTime: row.event_time,
      ingestionTime: row.ingestion_time,
      source: row.source || 'vrsoc-agent',
      environment: row.environment || 'production',
      severity: row.severity || 'info',
      data: row.data || {},
      schemaVersion: row.schema_version || '1.0'
    };
  }

  private mapRule(row: any): DetectionRule {
    return {
      id: row.id,
      organizationId: row.organization_id || null,
      name: row.name,
      description: row.description,
      severity: row.severity,
      riskScore: row.risk_score,
      category: row.category,
      mitreTactic: row.mitre_tactic,
      mitreTechniqueId: row.mitre_technique_id,
      mitreTechniqueName: row.mitre_technique_name,
      conditions: row.conditions || {},
      remediationSteps: row.remediation_steps || [],
      enabled: Boolean(row.enabled),
      createdAt: row.created_at
    };
  }

  private mapAlert(row: any, commentsRows: any[]): Alert {
    const comments: AlertComment[] = (commentsRows || []).map(c => {
      let userName = 'SOC Analyst';
      let cleanComment = c.comment || '';
      if (cleanComment.startsWith('[') && cleanComment.includes(']')) {
        const closeIdx = cleanComment.indexOf(']');
        userName = cleanComment.slice(1, closeIdx);
        cleanComment = cleanComment.slice(closeIdx + 1).trim();
      }
      return {
        id: c.id,
        userId: c.user_id,
        userName,
        comment: cleanComment,
        createdAt: c.created_at
      };
    });

    return {
      id: row.id,
      organizationId: row.organization_id,
      agentId: row.agent_id || null,
      ruleId: row.rule_id,
      title: row.title,
      description: row.description,
      severity: row.severity,
      riskScore: row.risk_score,
      status: row.status,
      hostname: row.hostname || undefined,
      username: row.username || undefined,
      sourceIp: row.source_ip || undefined,
      destinationIp: row.destination_ip || undefined,
      mitreTactic: row.mitre_tactic || undefined,
      mitreTechnique: row.mitre_technique || undefined,
      mitreId: row.mitre_id || undefined,
      evidence: row.evidence || [],
      triggerEventIds: row.trigger_event_ids || [],
      aiSummary: row.ai_summary || undefined,
      assignedTo: row.assigned_to || null,
      environment: row.environment || 'production',
      comments,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapIncident(row: any, alertLinks: any[], tasks: any[], timeline: any[]): Incident {
    const summary = row.summary_report || {};
    const notes: IncidentNote[] = summary.notes || [];

    return {
      id: row.id,
      organizationId: row.organization_id,
      title: row.title,
      description: row.description,
      severity: row.severity,
      status: row.status,
      priority: row.priority,
      leadInvestigator: row.lead_investigator || null,
      leadInvestigatorName: summary.leadInvestigatorName || 'Unassigned',
      linkedAlertIds: (alertLinks || []).map(a => a.alert_id),
      timeline: (timeline || []).map(tl => ({
        id: tl.id,
        timestamp: tl.event_timestamp,
        title: tl.event_title,
        description: tl.event_description || '',
        type: tl.event_type || 'observation',
        evidenceState: tl.evidence_state || 'CONFIRMED'
      })),
      tasks: (tasks || []).map(t => ({
        id: t.id,
        title: t.title,
        assignedTo: t.assigned_to || null,
        completed: Boolean(t.completed),
        createdAt: t.created_at
      })),
      notes,
      lessonsLearned: row.lessons_learned || '',
      environment: row.environment || 'production',
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapPhishingScan(row: any): PhishingScan {
    return {
      id: row.id,
      organizationId: row.organization_id,
      userId: row.user_id || null,
      url: row.url,
      normalizedUrl: row.normalized_url,
      classification: row.classification,
      riskScore: row.risk_score,
      features: row.features || {},
      reasons: row.reasons || [],
      promotedToAlertId: row.promoted_to_alert_id || null,
      createdAt: row.created_at
    };
  }

  private mapAuditLog(row: any): AuditLog {
    return {
      id: row.id,
      organizationId: row.organization_id,
      userId: row.user_id || null,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id || undefined,
      details: row.details || {},
      ipAddress: row.ip_address || undefined,
      createdAt: row.created_at
    };
  }

  private mapReport(row: any): Report {
    return {
      id: row.id,
      organizationId: row.organization_id,
      generatedBy: row.generated_by || null,
      title: row.title,
      reportType: row.report_type,
      targetId: row.target_id || undefined,
      content: row.content || {},
      createdAt: row.created_at
    };
  }

  private mapIndicator(row: any): Indicator {
    return {
      id: row.id,
      organizationId: row.organization_id,
      type: row.type,
      value: row.value,
      threatActor: row.threat_actor || undefined,
      confidence: row.confidence || 70,
      tags: row.tags || [],
      description: row.description || '',
      createdAt: row.created_at
    };
  }
}

export const db = new Database();
