import { Profile, Organization, Agent, Alert, Incident, PhishingScan, DetectionRule, Indicator, AuditLog, Report, RealMetrics, EndpointEvent } from './types';

class ApiClient {
  private getHeaders(): HeadersInit {
    const token = localStorage.getItem('vrsoc_token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    };
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(path, {
      ...options,
      headers: {
        ...this.getHeaders(),
        ...options.headers
      }
    });

    if (!res.ok) {
      let errMsg = `Request failed: ${res.statusText}`;
      try {
        const errJson = await res.json();
        errMsg = errJson.error || errMsg;
      } catch {
        // use default
      }
      throw new Error(errMsg);
    }

    return res.json();
  }

  // Auth
  async signup(data: { fullName: string; email: string; phoneNumber?: string; organizationName: string; password?: string }) {
    const res = await this.request<{ profile: Profile; organization: Organization; sessionToken: string; devHint?: string; emailOtp?: string; phoneOtp?: string }>('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify(data)
    });
    localStorage.setItem('vrsoc_token', res.sessionToken);
    return res;
  }

  async login(data: { email: string; password?: string }) {
    const res = await this.request<{ profile: Profile; organization: Organization; sessionToken: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(data)
    });
    localStorage.setItem('vrsoc_token', res.sessionToken);
    return res;
  }

  async getMe() {
    return this.request<{ profile: Profile; organization: Organization; sessionToken: string }>('/api/auth/me');
  }

  async completeOnboarding(data: { organizationName: string; fullName?: string; phoneNumber?: string }) {
    return this.request<{ success: boolean; profile: Profile; organization: Organization; vrSocKey: string }>('/api/auth/complete-onboarding', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async logout() {
    try {
      await this.request('/api/auth/logout', { method: 'POST' });
    } finally {
      localStorage.removeItem('vrsoc_token');
    }
  }

  async verifyEmailOtp(otp: string) {
    return this.request<{ success: boolean; profile: Profile }>('/api/auth/verify-email-otp', {
      method: 'POST',
      body: JSON.stringify({ otp })
    });
  }

  async resendEmailOtp() {
    return this.request<{ success: boolean; message: string; emailOtp?: string; devHint?: string }>('/api/auth/resend-email-otp', {
      method: 'POST'
    });
  }

  async verifyPhoneOtp(otp: string) {
    return this.request<{ success: boolean; profile: Profile }>('/api/auth/verify-phone-otp', {
      method: 'POST',
      body: JSON.stringify({ otp })
    });
  }

  async resendPhoneOtp() {
    return this.request<{ success: boolean; message: string; phoneOtp?: string; devHint?: string }>('/api/auth/resend-phone-otp', {
      method: 'POST'
    });
  }

  async getMfaSetup() {
    return this.request<{ mfaSecret: string; qrUri: string }>('/api/auth/mfa-setup', { method: 'POST' });
  }

  async verifyMfa(token: string) {
    return this.request<{ success: boolean; profile: Profile }>('/api/auth/mfa-verify', {
      method: 'POST',
      body: JSON.stringify({ token })
    });
  }

  // Organizations
  async rotateKey() {
    return this.request<{ success: boolean; vrSocKey: string; message: string }>('/api/organizations/key/rotate', {
      method: 'POST'
    });
  }

  async getMetrics(environment = 'production') {
    return this.request<{ metrics: RealMetrics }>(`/api/organizations/metrics?environment=${environment}`);
  }

  // Agents
  async getAgents() {
    return this.request<{ agents: Agent[] }>('/api/agents');
  }

  async getAgent(id: string) {
    return this.request<{ agent: Agent; events: EndpointEvent[] }>(`/api/agents/${id}`);
  }

  async revokeAgent(id: string) {
    return this.request<{ success: boolean; agent: Agent }>(`/api/agents/${id}/revoke`, {
      method: 'POST'
    });
  }

  async enrollAgent(payload: { enrollmentKey: string; name: string; hostname: string; os: string; ipAddress: string }) {
    return this.request<{ agent: Agent; agentToken: string }>('/api/agent/enroll', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  async sendAgentHeartbeat(agentId: string, agentToken: string, stats: { cpuUsage: number; ramUsage: number; diskUsage: number }) {
    return this.request<{ status: string }>('/api/agent/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ agentId, agentToken, ...stats })
    });
  }

  async sendAgentTelemetry(agentId: string, agentToken: string, payload: { eventType: string; severity: string; data: any }) {
    return this.request<{ status: string; eventId: string; triggeredAlert: string | null }>('/api/agent/telemetry', {
      method: 'POST',
      body: JSON.stringify({ agentId, agentToken, ...payload })
    });
  }

  // Alerts
  async getAlerts(environment = 'production') {
    return this.request<{ alerts: Alert[] }>(`/api/alerts?environment=${environment}`);
  }

  async getAlert(id: string) {
    return this.request<{ alert: Alert }>(`/api/alerts/${id}`);
  }

  async updateAlertStatus(id: string, status: Alert['status']) {
    return this.request<{ alert: Alert }>(`/api/alerts/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
  }

  async addAlertComment(id: string, comment: string) {
    return this.request<{ alert: Alert }>(`/api/alerts/${id}/comment`, {
      method: 'POST',
      body: JSON.stringify({ comment })
    });
  }

  async analyzeAlertWithAi(id: string) {
    return this.request<{ aiSummary: any; alert: Alert }>(`/api/alerts/${id}/ai-analyze`, {
      method: 'POST'
    });
  }

  // Incidents
  async getIncidents(environment = 'production') {
    return this.request<{ incidents: Incident[] }>(`/api/incidents?environment=${environment}`);
  }

  async getIncident(id: string) {
    return this.request<{ incident: Incident; linkedAlerts: Alert[] }>(`/api/incidents/${id}`);
  }

  async createIncident(data: { title: string; description: string; severity?: string; priority?: string; linkedAlertIds?: string[]; environment?: string }) {
    return this.request<{ incident: Incident }>('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async updateIncident(id: string, updates: Partial<Incident>) {
    return this.request<{ incident: Incident }>(`/api/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates)
    });
  }

  async addIncidentTask(id: string, title: string) {
    return this.request<{ incident: Incident }>(`/api/incidents/${id}/task`, {
      method: 'POST',
      body: JSON.stringify({ title })
    });
  }

  async toggleIncidentTask(id: string, taskId: string, completed: boolean) {
    return this.request<{ incident: Incident }>(`/api/incidents/${id}/task/${taskId}`, {
      method: 'PATCH',
      body: JSON.stringify({ completed })
    });
  }

  async addIncidentTimeline(id: string, data: { title: string; description?: string; type?: string; evidenceState?: string }) {
    return this.request<{ incident: Incident }>(`/api/incidents/${id}/timeline`, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async addIncidentNote(id: string, note: string) {
    return this.request<{ incident: Incident }>(`/api/incidents/${id}/note`, {
      method: 'POST',
      body: JSON.stringify({ note })
    });
  }

  // Detection Rules
  async getRules() {
    return this.request<{ rules: DetectionRule[] }>('/api/detection-rules');
  }

  async toggleRule(id: string, enabled: boolean) {
    return this.request<{ success: boolean; ruleId: string; enabled: boolean }>(`/api/detection-rules/${id}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled })
    });
  }

  async createRule(data: Partial<DetectionRule>) {
    return this.request<{ rule: DetectionRule }>('/api/detection-rules', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  // PhishGuard
  async scanUrl(url: string) {
    return this.request<{ scan: PhishingScan; analysis: any }>('/api/phishguard/scan', {
      method: 'POST',
      body: JSON.stringify({ url })
    });
  }

  async promotePhishingScanToAlert(scanId: string) {
    return this.request<{ success: boolean; alert: Alert }>('/api/phishguard/promote-to-alert', {
      method: 'POST',
      body: JSON.stringify({ scanId })
    });
  }

  async getPhishingScans() {
    return this.request<{ scans: PhishingScan[] }>('/api/phishguard/scans');
  }

  // AI Chat
  async chatAi(message: string, context?: { alertId?: string; incidentId?: string; agentId?: string }) {
    return this.request<{ reply: string }>('/api/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, context })
    });
  }

  // Threat Intel & Audit
  async getIndicators() {
    return this.request<{ indicators: Indicator[] }>('/api/indicators');
  }

  async createIndicator(data: Partial<Indicator>) {
    return this.request<{ indicator: Indicator }>('/api/indicators', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async getAuditLogs() {
    return this.request<{ logs: AuditLog[] }>('/api/audit-logs');
  }

  // Reports
  async generateReport(reportType: string, targetId?: string) {
    return this.request<{ report: Report }>('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ reportType, targetId })
    });
  }

  async getReports() {
    return this.request<{ reports: Report[] }>('/api/reports');
  }

  // Telemetry Threat Simulation for live SOC verification
  async simulateTelemetry(scenario: 'powershell_obfuscated' | 'persistence_task' | 'usb_storage' | 'auth_lockout', agentId?: string) {
    return this.request<{ success: boolean; event: EndpointEvent; agent: Agent; triggeredAlert: Alert | null }>('/api/telemetry/simulate', {
      method: 'POST',
      body: JSON.stringify({ scenario, agentId })
    });
  }
}

export const api = new ApiClient();
