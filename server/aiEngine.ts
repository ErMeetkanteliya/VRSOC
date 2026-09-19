import { GoogleGenAI } from '@google/genai';
import { Alert, Incident, db } from './db';

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

  // Deterministic grounded analysis strictly based on telemetry
  const confirmed: string[] = [];
  alert.evidence.forEach(ev => {
    confirmed.push(`[${ev.type}] ${ev.description} at ${ev.timestamp}`);
  });
  if (confirmed.length === 0) {
    confirmed.push(`Rule ${alert.ruleId} condition satisfied for ${alert.hostname}.`);
  }

  const inferred: string[] = [
    `Calculated risk score of ${alert.riskScore}/100 based on severity '${alert.severity}' and category '${alert.mitreTactic}'.`,
    alert.username ? `Activity attributed to authenticated account context '${alert.username}'.` : 'Activity ran under system context or unauthenticated network probe.'
  ];

  const unknowns: string[] = [
    alert.sourceIp ? `External threat actor identity behind IP ${alert.sourceIp} is not confirmed.` : 'Originating network IP address was not captured in this event schema.',
    'Whether lateral movement or secondary persistence was attempted requires endpoint inspection.'
  ];

  const investigationSteps = [
    `Inspect endpoint ${alert.hostname} active processes and established socket connections.`,
    `Review authentication logs around ${alert.createdAt} for unusual logon origins.`,
    `Cross-reference MITRE technique ${alert.mitreId} (${alert.mitreTechnique}) against threat intelligence indicators.`
  ];

  const containmentSteps = [
    `If anomalous behavior continues, isolate host ${alert.hostname} from the network.`,
    alert.username ? `Suspend or force password reset on user account '${alert.username}'.` : 'Verify service accounts associated with the triggering process.'
  ];

  const recoverySteps = [
    'Terminate any malicious spawned child PIDs.',
    'Validate file system integrity and remove unauthorized autostart persistence.',
    'Conduct post-incident retrospective and update detection rule exclusions if false positive.'
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
 */
export async function chatWithAiAnalyst(
  orgId: string,
  userMessage: string,
  context?: { alertId?: string; incidentId?: string; agentId?: string }
): Promise<string> {
  const client = getAiClient();

  // Gather real context from database
  let relevantData = '';
  if (context?.alertId) {
    const alert = await db.getAlertById(context.alertId);
    if (alert && alert.organizationId === orgId) {
      relevantData += `CURRENT ALERT CONTEXT:\n${JSON.stringify(alert, null, 2)}\n\n`;
    }
  }

  if (context?.incidentId) {
    const incident = await db.getIncidentById(context.incidentId);
    if (incident && incident.organizationId === orgId) {
      relevantData += `CURRENT INCIDENT CONTEXT:\n${JSON.stringify(incident, null, 2)}\n\n`;
    }
  }

  if (context?.agentId) {
    const agent = await db.getAgentById(context.agentId);
    if (agent && agent.organizationId === orgId) {
      relevantData += `CURRENT AGENT HOST CONTEXT:\n${JSON.stringify(agent, null, 2)}\n\n`;
    }
  }

  if (!relevantData) {
    const metrics = await db.getRealMetrics(orgId);
    relevantData = `CURRENT SOC STATE:
- Enrolled Agents: ${metrics.connectedAgentsCount} (${metrics.onlineAgentsCount} online)
- Active Alerts: ${metrics.activeAlertsCount} (${metrics.criticalAlertsCount} critical)
- Open Incidents: ${metrics.openIncidentsCount}
- Phishing Scans: ${metrics.phishingScansCount} (${metrics.phishingDetectionsCount} detections)
`;
  }

  if (client) {
    try {
      const systemInstruction = `You are VRSOC Copilot, a senior Tier-3 SOC analyst and defensive cybersecurity tutor.
You assist security engineers, analysts, and students in investigating alerts, decoding evidence, mapping MITRE ATT&CK techniques, and formulating containment playbooks.

RULES:
1. Always ground your answers in the real provided telemetry/context.
2. Clearly distinguish between CONFIRMED facts, INFERRED hypotheses, and UNKNOWN factors.
3. Be professional, direct, concise, and educational.
4. Never invent fake telemetry or claim a breach has occurred without telemetry proof.`;

      const response = await client.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: `${systemInstruction}\n\nCONTEXT:\n${relevantData}\n\nANALYST QUESTION:\n${userMessage}`
      });

      if (response.text) {
        return response.text;
      }
    } catch (err) {
      console.warn('Gemini chat error, falling back to deterministic response:', err);
    }
  }

  // Fallback analyst response
  return `**VRSOC Analyst Assistant (Evidence-Grounded Mode)**

Based on the verified records currently loaded in your SOC workspace:
- **Observed Context**: ${context?.alertId ? `Alert ${context.alertId}` : context?.incidentId ? `Incident ${context.incidentId}` : 'Workspace environment'}
- **Confirmed Evidence**: All detections are validated against active detection rules without synthetic placeholders.
- **Recommended Action**: Review the latest telemetry in the Logs tab, verify whether host processes correlate with the alert timestamp, and follow defensive containment procedures.`;
}
