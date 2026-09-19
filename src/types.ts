export interface Profile {
  id: string;
  email: string;
  fullName: string;
  phoneNumber?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  mfaEnabled: boolean;
  role: 'Super Admin' | 'Organization Admin' | 'Instructor' | 'SOC Analyst' | 'Incident Responder' | 'Threat Hunter' | 'Auditor' | 'Viewer' | 'Student';
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  vrSocKey: string; // Exactly 14-char hexadecimal e.g. A7F29C81D40E5B
  status: 'active' | 'suspended';
  retentionDays: number;
  createdAt: string;
  updatedAt: string;
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
  comments: Array<{
    id: string;
    userId: string;
    userName: string;
    comment: string;
    createdAt: string;
  }>;
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
  id: string;
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
