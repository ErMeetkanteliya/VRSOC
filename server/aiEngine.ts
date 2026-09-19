import { GoogleGenAI } from '@google/genai';
import { Alert, Incident, db, EndpointEvent } from './db';

let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
    try {
      aiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    } catch (err) {
      console.warn('Failed to initialize GoogleGenAI client:', err);
    }
  }
  return aiClient;
}

export interface AiAnalysisResult {
  confirmedEvidence: string[];
  inferredInsights: string[];
  unknowns: string[];
  explanation: string;
  investigationSteps: string[];
  containmentSteps: string[];
  recoverySteps: string[];
  generatedAt: string;
}

/**
 * Performs evidence-grounded AI analysis of a real security alert.
 * Adheres strictly to the 3 evidence states: CONFIRMED, INFERRED, UNKNOWN.
 * Never invents fabricated telemetry, fake users, or fake IP addresses.
 */
export async function analyzeAlertWithAi(alert: Alert): Promise<AiAnalysisResult> {
  const client = getAiClient();

  // Grounded context strictly extracted from actual alert record
  const context = {
    alertId: alert.id,
    title: alert.title,
    description: alert.description,
    severity: alert.severity,
    riskScore: alert.riskScore,
    hostname: alert.hostname || 'Unknown Host',
    username: alert.username || 'No user identified in telemetry',
    sourceIp: alert.sourceIp || 'Not provided',
    ruleId: alert.ruleId,
    mitreTactic: alert.mitreTactic || 'Unspecified',
    mitreTechnique: alert.mitreTechnique || 'Unspecified',
    mitreId: alert.mitreId || 'Unspecified',
    evidenceRecords: alert.evidence,
    triggerEventCount: alert.triggerEventIds.length,
    timestamp: alert.createdAt
  };

  if (client) {
    try {
      const prompt = `You are the VRSOC AI Security Assistant, an expert defensive security analyst.
Analyze the following REAL security alert grounded strictly in the provided evidence.

CRITICAL DIRECTIVES:
1. NEVER invent or fabricate any evidence, IP addresses, usernames, filenames, or attack outcomes not present in the data.
2. Separate all findings strictly into:
   - CONFIRMED: Directly verified by the provided telemetry.
   - INFERRED: Logical deduction from the verified evidence.
   - UNKNOWN: Missing data that cannot be determined from the telemetry.
3. Label all potential damage or impact as "Assessment" rather than confirmed breach.
4. Output your response strictly as valid JSON matching this structure:
{
  "confirmedEvidence": ["string", "string"],
  "inferredInsights": ["string", "string"],
  "unknowns": ["string", "string"],
  "explanation": "Plain English explanation of what happened and why it triggered",
  "investigationSteps": ["Step 1...", "Step 2..."],
  "containmentSteps": ["Step 1...", "Step 2..."],
  "recoverySteps": ["Step 1...", "Step 2..."]
}

ALERT DATA:
${JSON.stringify(context, null, 2)}`;

      const response = await client.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      if (response.text) {
        const parsed = JSON.parse(response.text);
        return {
          confirmedEvidence: parsed.confirmedEvidence || [],
          inferredInsights: parsed.inferredInsights || [],
          unknowns: parsed.unknowns || [],
          explanation: parsed.explanation || alert.description,
          investigationSteps: parsed.investigationSteps || [],
          containmentSteps: parsed.containmentSteps || [],
          recoverySteps: parsed.recoverySteps || [],
          generatedAt: new Date().toISOString()
        };
      }
    } catch (err) {
      console.warn('Gemini API call failed, falling back to deterministic grounded analysis:', err);
    }
  }

  // Deterministic grounded analysis strictly based on actual telemetry
  const confirmed: string[] = [];
  if (alert.evidence && alert.evidence.length > 0) {
    alert.evidence.forEach(ev => {
      confirmed.push(`[${ev.type}] ${ev.description} (Timestamp: ${ev.timestamp})`);
    });
  } else {
    confirmed.push(`Detection Rule ${alert.ruleId} condition satisfied on host '${alert.hostname || 'Unknown'}'.`);
  }

  const inferred: string[] = [
    `Calculated risk score of ${alert.riskScore}/100 based on severity '${alert.severity}' and category '${alert.mitreTactic || 'General Detection'}'.`,
    alert.username ? `Activity attributed to account context '${alert.username}'.` : 'Activity ran under system context or unauthenticated network probe.'
  ];

  const unknowns: string[] = [
    alert.sourceIp ? `Threat actor infrastructure behind IP ${alert.sourceIp} is not confirmed.` : 'Originating source network IP address was not captured in this event schema.',
    'Whether secondary persistence or lateral movement occurred requires active endpoint triage.'
  ];

  const investigationSteps = [
    `Inspect endpoint '${alert.hostname || 'host'}' active processes and socket connections.`,
    `Review authentication and process logs around ${alert.createdAt} for anomalous activity.`,
    alert.mitreId ? `Cross-reference MITRE technique ${alert.mitreId} (${alert.mitreTechnique}) against active threat intelligence indicators.` : 'Inspect related detection rules.'
  ];

  const containmentSteps = [
    `If anomalous execution is verified, isolate host '${alert.hostname || 'endpoint'}' from the network segment.`,
    alert.username ? `Temporarily suspend or rotate credentials for user account '${alert.username}'.` : 'Verify service accounts associated with the triggering process.'
  ];

  const recoverySteps = [
    'Terminate any malicious spawned child PIDs.',
    'Verify file system integrity and remove unauthorized autostart persistence.',
    'Conduct post-incident review and update detection rule exclusions if verified false positive.'
  ];

  return {
    confirmedEvidence: confirmed,
    inferredInsights: inferred,
    unknowns,
    explanation: alert.description,
    investigationSteps,
    containmentSteps,
    recoverySteps,
    generatedAt: new Date().toISOString()
  };
}

/**
 * Interactive contextual AI Assistant for SOC analysts.
 * Retrieves comprehensive, authorized workspace context strictly scoped to orgId.
 */
export async function chatWithAiAnalyst(
  orgId: string,
  userMessage: string,
  context?: { alertId?: string; incidentId?: string; agentId?: string }
): Promise<string> {
  const client = getAiClient();

  // Gather real, authorized PostgreSQL records strictly scoped to orgId
  let specificContextData = '';
  let targetedAlert: Alert | null = null;
  let targetedIncident: Incident | null = null;

  if (context?.alertId) {
    targetedAlert = await db.getAlertById(context.alertId, orgId);
    if (targetedAlert) {
      specificContextData += `TARGET ALERT DETAILS:\n${JSON.stringify(targetedAlert, null, 2)}\n\n`;
    }
  }

  if (context?.incidentId) {
    targetedIncident = await db.getIncidentById(context.incidentId, orgId);
    if (targetedIncident) {
      specificContextData += `TARGET INCIDENT DETAILS:\n${JSON.stringify(targetedIncident, null, 2)}\n\n`;
    }
  }

  if (context?.agentId) {
    const agent = await db.getAgentById(context.agentId, orgId);
    if (agent) {
      const recentEvents = await db.getEndpointEvents(orgId, 5, agent.id);
      specificContextData += `TARGET ENDPOINT AGENT:\n${JSON.stringify(agent, null, 2)}\nRECENT AGENT TELEMETRY:\n${JSON.stringify(recentEvents, null, 2)}\n\n`;
    }
  }

  // Fetch broader authorized workspace dataset for thorough grounding
  const [metrics, recentAlerts, recentIncidents, agents, recentEvents, rules, phishingScans, iocs] = await Promise.all([
    db.getRealMetrics(orgId),
    db.getAlerts(orgId, 'production'),
    db.getIncidents(orgId, 'production'),
    db.getAgents(orgId),
    db.getEndpointEvents(orgId, 10),
    db.getDetectionRules(orgId),
    db.getPhishingScans(orgId),
    db.getIndicators(orgId)
  ]);

  const workspaceContext = `CURRENT SOC WORKSPACE STATE (Tenant: ${orgId}):
- Enrolled Agents (${agents.length}): ${agents.map(a => `${a.hostname} [${a.status}]`).join(', ') || 'None'}
- Active Alerts (${recentAlerts.length}): ${recentAlerts.slice(0, 5).map(a => `${a.id}: ${a.title} (${a.severity.toUpperCase()}, Host: ${a.hostname || 'N/A'})`).join('\n  ') || 'None'}
- Open Incidents (${recentIncidents.length}): ${recentIncidents.slice(0, 3).map(i => `${i.id}: ${i.title} [${i.status}]`).join('\n  ') || 'None'}
- Recent Telemetry Events (${recentEvents.length}): ${recentEvents.slice(0, 5).map(e => `${e.eventType} on ${e.data?.hostname || 'host'} at ${e.eventTime}`).join('\n  ') || 'None'}
- Active Detection Rules (${rules.filter(r => r.enabled).length}): ${rules.filter(r => r.enabled).map(r => r.id).join(', ')}
- Phishing Scans: ${phishingScans.length}
- Threat Intel IOCs: ${iocs.length}

${specificContextData}`;

  if (client) {
    try {
      const systemInstruction = `You are VRSOC Copilot, a senior Tier-3 SOC analyst and defensive cybersecurity tutor.
You assist security engineers and analysts in investigating real alerts, telemetry events, and incidents.

RULES:
1. Ground answers strictly in the real provided PostgreSQL telemetry/context.
2. Clearly separate findings into:
   - CONFIRMED: Directly verified by the provided records.
   - INFERRED: Logical deduction from the verified evidence.
   - UNKNOWN: Missing information that cannot be determined from the telemetry.
3. If an alert, IP, host, or user is not in the data, state that it is UNKNOWN rather than fabricating one.
4. Maintain strict tenant boundary: never discuss or reference data outside this organization.`;

      const response = await client.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: `${systemInstruction}\n\n${workspaceContext}\n\nANALYST QUESTION:\n${userMessage}`
      });

      if (response.text) {
        return response.text;
      }
    } catch (err) {
      console.warn('Gemini chat error, falling back to deterministic response:', err);
    }
  }

  // Deterministic Evidence-Grounded Analyst Assistant Fallback
  if (targetedAlert) {
    return `**VRSOC Analyst Assistant (Evidence-Grounded Mode)**

**Alert Investigation: ${targetedAlert.id} - ${targetedAlert.title}**
- **CONFIRMED Evidence**:
  - Status: ${targetedAlert.status.toUpperCase()} (Assigned: ${targetedAlert.assignedTo || 'Unassigned'})
  - Rule: ${targetedAlert.ruleId} (${targetedAlert.mitreTactic || 'Detection'})
  - Target Host: ${targetedAlert.hostname || 'Unknown Host'}
  - Severity / Risk: ${targetedAlert.severity.toUpperCase()} (Risk Score: ${targetedAlert.riskScore}/100)
  - Logged Timestamp: ${targetedAlert.createdAt}
  - Triggering Telemetry Count: ${targetedAlert.triggerEventIds.length} event(s)
- **INFERRED Assessment**:
  - ${targetedAlert.username ? `Activity ran within account context '${targetedAlert.username}'.` : 'Executed under system background context.'}
- **UNKNOWN Factors**:
  - ${targetedAlert.sourceIp ? `Threat actor identity behind source IP ${targetedAlert.sourceIp} is unverified.` : 'Originating network IP address not recorded.'}
  - Full lateral movement scope is unknown until host forensic triage is completed.
- **Recommended Actions**:
  1. Review endpoint telemetry in the Logs tab for host '${targetedAlert.hostname || 'endpoint'}'.
  2. Verify active process tree and parent PID.
  3. Apply containment procedures if confirmed malicious.`;
  }

  if (targetedIncident) {
    return `**VRSOC Analyst Assistant (Evidence-Grounded Mode)**

**Incident Investigation: ${targetedIncident.id} - ${targetedIncident.title}**
- **CONFIRMED Evidence**:
  - Priority / Severity: ${targetedIncident.priority} / ${targetedIncident.severity.toUpperCase()}
  - Current Status: ${targetedIncident.status.toUpperCase()}
  - Linked Alerts: ${targetedIncident.linkedAlertIds.join(', ') || 'No linked alerts'}
  - Timeline Events: ${targetedIncident.timeline.length} recorded entry/entries
  - Tasks: ${targetedIncident.tasks.filter(t => t.completed).length}/${targetedIncident.tasks.length} completed
- **INFERRED Assessment**:
  - Investigation scope is actively tracked across ${targetedIncident.linkedAlertIds.length} detection alerts.
- **UNKNOWN Factors**:
  - Root cause attribution is currently under investigation by SOC analysts.`;
  }

  // General workspace summary grounded in real database records
  const openAlertSummary = recentAlerts.length > 0
    ? recentAlerts.slice(0, 3).map(a => `- **${a.id}**: ${a.title} [${a.severity.toUpperCase()} / Risk ${a.riskScore}] on host '${a.hostname || 'Unknown'}'`).join('\n')
    : 'No active security alerts currently open in this workspace.';

  return `**VRSOC Analyst Assistant (Evidence-Grounded Mode)**

**Current Workspace Status (${orgId}):**
- **Connected Fleet**: ${metrics.connectedAgentsCount} agents enrolled (${metrics.onlineAgentsCount} online).
- **CONFIRMED Active Detections**:
${openAlertSummary}
- **Open Incidents**: ${metrics.openIncidentsCount} active investigation case(s).
- **Recent Telemetry**: ${recentEvents.length} endpoint event(s) processed.
- **UNKNOWN Factors**:
  - Full scope of external reconnaissance requires continuous telemetry monitoring.
- **Guidance**: Select any specific Alert or Incident from the left navigation for detailed deep-dive forensics and MITRE playbooks.`;
}
