import { db, EndpointEvent, Alert, Agent } from './db';
import { broadcastEvent } from './sse';

export class DetectionEngine {
  /**
   * Processes an incoming real telemetry event against active detection rules.
   */
  public async evaluateEvent(event: EndpointEvent, agent?: Agent): Promise<Alert | null> {
    try {
      const allRules = await db.getDetectionRules(event.organizationId);
      const rules = allRules.filter(r => r.enabled);
      const orgId = event.organizationId;
      const environment = event.environment;
      const host = agent?.hostname || (event.data?.hostname as string) || 'Unknown Host';
      const user = (event.data?.username as string) || (event.data?.user as string) || undefined;

      for (const rule of rules) {
        // 1. Multiple Authentication Failures Check
        if (rule.id === 'RULE-AUTH-001' && event.eventType === 'auth' && (event.data?.status === 'failure' || event.data?.action === 'logon_failed')) {
          // Fetch recent auth failure events within 5 minutes for this host/agent
          const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
          const endpointEvents = await db.getEndpointEvents(orgId, 50, event.agentId, 'auth');
          const recentEvents = endpointEvents
            .filter(e => e.eventTime >= fiveMinutesAgo && (e.data?.status === 'failure' || e.data?.action === 'logon_failed'));

          if (recentEvents.length >= 5) {
            // Check if an open alert for this rule and host already exists within the last 15 minutes to avoid flood
            const alerts = await db.getAlerts(orgId, environment);
            const existingAlerts = alerts
              .filter(a => a.ruleId === rule.id && a.hostname === host && (a.status === 'open' || a.status === 'investigating'));
            
            if (existingAlerts.length === 0) {
              const triggerIds = recentEvents.map(e => e.id);
              const alert = await db.createAlert({
                organizationId: orgId,
                agentId: event.agentId,
                ruleId: rule.id,
                title: `${rule.name} on ${host}`,
                description: `Observed ${recentEvents.length} consecutive logon failures against host ${host} within 5 minutes. Source account: ${user || 'multiple accounts'}.`,
                severity: rule.severity,
                riskScore: rule.riskScore,
                status: 'open',
                hostname: host,
                username: user,
                sourceIp: (event.data?.sourceIp as string) || agent?.ipAddress,
                mitreTactic: rule.mitreTactic,
                mitreTechnique: rule.mitreTechniqueName,
                mitreId: rule.mitreTechniqueId,
                evidence: recentEvents.slice(0, 10).map(e => ({
                  type: 'Authentication Failure Telemetry',
                  description: `Failed logon attempt for user '${e.data?.username || 'unknown'}' from IP '${e.data?.sourceIp || 'local'}'`,
                  timestamp: e.eventTime,
                  data: e.data,
                  state: 'CONFIRMED'
                })),
                triggerEventIds: triggerIds,
                environment
              });

              broadcastEvent(orgId, 'new_alert', alert);
              return alert;
            }
          }
        }

        // 2. Account Lockout Event
        if (rule.id === 'RULE-AUTH-002' && event.eventType === 'auth' && (event.data?.subType === 'lockout' || event.data?.action === 'account_locked')) {
          const alert = await db.createAlert({
            organizationId: orgId,
            agentId: event.agentId,
            ruleId: rule.id,
            title: `Account Lockout Detected: ${user || 'Unknown User'}`,
            description: `User account '${user || 'Unknown'}' was locked out after exceeding failed logon threshold on host ${host}.`,
            severity: rule.severity,
            riskScore: rule.riskScore,
            status: 'open',
            hostname: host,
            username: user,
            sourceIp: agent?.ipAddress,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechniqueName,
            mitreId: rule.mitreTechniqueId,
            evidence: [{
              type: 'Security Event Log',
              description: `Lockout event registered for account '${user}'`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }],
            triggerEventIds: [event.id],
            environment
          });

          broadcastEvent(orgId, 'new_alert', alert);
          return alert;
        }

        // 3. Suspicious / Encoded PowerShell Execution
        if (rule.id === 'RULE-PROC-001' && event.eventType === 'process') {
          const cmd = ((event.data?.commandLine || event.data?.command || '') as string).toLowerCase();
          const procName = ((event.data?.processName || event.data?.name || '') as string).toLowerCase();

          const isPowerShellOrShell = procName.includes('powershell') || procName.includes('cmd.exe') || procName.includes('bash') || procName.includes('sh');
          const hasSuspiciousFlag = ['-enc', '-encodedcommand', '-w hidden', '-nop', 'downloadstring', 'bypass', 'iex('].some(flag => cmd.includes(flag));

          if (isPowerShellOrShell && hasSuspiciousFlag) {
            const alert = await db.createAlert({
              organizationId: orgId,
              agentId: event.agentId,
              ruleId: rule.id,
              title: `Suspicious PowerShell Execution on ${host}`,
              description: `Process '${procName}' was executed with obfuscated or policy bypass command line arguments.`,
              severity: rule.severity,
              riskScore: rule.riskScore,
              status: 'open',
              hostname: host,
              username: user,
              sourceIp: agent?.ipAddress,
              mitreTactic: rule.mitreTactic,
              mitreTechnique: rule.mitreTechniqueName,
              mitreId: rule.mitreTechniqueId,
              evidence: [
                {
                  type: 'Process Telemetry',
                  description: `Command line: ${event.data?.commandLine || event.data?.command}`,
                  timestamp: event.eventTime,
                  data: event.data,
                  state: 'CONFIRMED'
                },
                {
                  type: 'Parent Process Tree',
                  description: `Parent PID: ${event.data?.parentPid || 'unknown'}, Parent Process: ${event.data?.parentProcess || 'unknown'}`,
                  timestamp: event.eventTime,
                  data: { parentPid: event.data?.parentPid, parentProcess: event.data?.parentProcess },
                  state: 'CONFIRMED'
                }
              ],
              triggerEventIds: [event.id],
              environment
            });

            broadcastEvent(orgId, 'new_alert', alert);
            return alert;
          }
        }

        // 4. Persistence Indicator: Scheduled Task / Cron Creation
        if (rule.id === 'RULE-PERS-001' && event.eventType === 'process') {
          const cmd = ((event.data?.commandLine || event.data?.command || '') as string).toLowerCase();
          const procName = ((event.data?.processName || '') as string).toLowerCase();

          if (cmd.includes('schtasks /create') || cmd.includes('crontab -e') || procName === 'schtasks.exe' || cmd.includes('systemctl enable')) {
            const alert = await db.createAlert({
              organizationId: orgId,
              agentId: event.agentId,
              ruleId: rule.id,
              title: `Persistence Mechanism Established: Scheduled Task on ${host}`,
              description: `A scheduled task or autostart cron job was created or modified on host ${host}. Command: ${cmd.slice(0, 100)}`,
              severity: rule.severity,
              riskScore: rule.riskScore,
              status: 'open',
              hostname: host,
              username: user,
              sourceIp: agent?.ipAddress,
              mitreTactic: rule.mitreTactic,
              mitreTechnique: rule.mitreTechniqueName,
              mitreId: rule.mitreTechniqueId,
              evidence: [{
                type: 'Process Execution',
                description: `Task creation command executed: ${cmd}`,
                timestamp: event.eventTime,
                data: event.data,
                state: 'CONFIRMED'
              }],
              triggerEventIds: [event.id],
              environment
            });

            broadcastEvent(orgId, 'new_alert', alert);
            return alert;
          }
        }

        // 5. Unauthorized USB Storage Mount
        if (rule.id === 'RULE-DEV-001' && event.eventType === 'usb' && (event.data?.action === 'mount' || event.data?.type === 'mass_storage')) {
          const alert = await db.createAlert({
            organizationId: orgId,
            agentId: event.agentId,
            ruleId: rule.id,
            title: `Removable Storage Media Mounted on ${host}`,
            description: `An external USB storage device (${event.data?.deviceName || 'Unknown device'}) was connected to ${host}.`,
            severity: rule.severity,
            riskScore: rule.riskScore,
            status: 'open',
            hostname: host,
            username: user,
            sourceIp: agent?.ipAddress,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechniqueName,
            mitreId: rule.mitreTechniqueId,
            evidence: [{
              type: 'Hardware Telemetry',
              description: `Device ID: ${event.data?.deviceId || 'N/A'}, Vendor: ${event.data?.vendor || 'Unknown'}`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }],
            triggerEventIds: [event.id],
            environment
          });

          broadcastEvent(orgId, 'new_alert', alert);
          return alert;
        }
      }
    } catch (err) {
      console.error('Error evaluating event in detection engine:', err);
    }

    return null;
  }
}

export const detectionEngine = new DetectionEngine();
