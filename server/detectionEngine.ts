import { db, EndpointEvent, Alert, Agent, DetectionRule } from './db';
import { broadcastEvent } from './sse';

export class DetectionEngine {
  /**
   * Processes an incoming real telemetry event against active detection rules.
   * Derives trusted identity strictly from authenticated event organization scope.
   */
  public async evaluateEvent(event: EndpointEvent, agent?: Agent): Promise<Alert | null> {
    try {
      const allRules = await db.getDetectionRules(event.organizationId);
      const rules = allRules.filter(r => r.enabled);
      const orgId = event.organizationId;
      const environment = event.environment;
      const host = agent?.hostname || (event.data?.hostname as string) || 'Unknown Host';
      const user = (event.data?.username as string) || (event.data?.user as string) || undefined;
      const srcIp = (event.data?.sourceIp as string) || (event.data?.ip as string) || agent?.ipAddress || undefined;

      for (const rule of rules) {
        let isMatch = false;
        let alertTitle = `${rule.name} on ${host}`;
        let alertDesc = rule.description;
        let evidence: any[] = [];
        let triggerIds: string[] = [event.id];

        // ---------------------------------------------------------------------
        // 1. RULE-AUTH-001: Multiple Authentication Failures (Brute Force)
        // ---------------------------------------------------------------------
        if (rule.id === 'RULE-AUTH-001' && event.eventType === 'auth') {
          const isAuthFailure = event.data?.status === 'failure' || event.data?.action === 'logon_failed' || event.data?.result === 'fail';
          if (isAuthFailure) {
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
            const endpointEvents = await db.getEndpointEvents(orgId, 50, event.agentId, 'auth');
            const recentEvents = endpointEvents.filter(e => 
              e.eventTime >= fiveMinutesAgo && 
              (e.data?.status === 'failure' || e.data?.action === 'logon_failed' || e.data?.result === 'fail')
            );

            if (recentEvents.length >= 5) {
              isMatch = true;
              triggerIds = recentEvents.map(e => e.id);
              alertDesc = `Observed ${recentEvents.length} consecutive logon failures against host ${host} within 5 minutes. Source account: ${user || 'multiple accounts'}.`;
              evidence = recentEvents.slice(0, 10).map(e => ({
                type: 'Authentication Failure Telemetry',
                description: `Failed logon attempt for user '${e.data?.username || 'unknown'}' from IP '${e.data?.sourceIp || srcIp || 'local'}'`,
                timestamp: e.eventTime,
                data: e.data,
                state: 'CONFIRMED'
              }));
            }
          }
        }

        // ---------------------------------------------------------------------
        // 2. RULE-AUTH-002: Account Lockout Security Event
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-AUTH-002' && event.eventType === 'auth') {
          const isLockout = event.data?.subType === 'lockout' || event.data?.action === 'account_locked' || event.data?.eventCode === '4740';
          if (isLockout) {
            isMatch = true;
            alertTitle = `Account Lockout Detected: ${user || 'Unknown User'}`;
            alertDesc = `User account '${user || 'Unknown'}' was locked out after exceeding failed logon threshold on host ${host}.`;
            evidence = [{
              type: 'Security Event Log',
              description: `Lockout event registered for account '${user || 'Unknown'}'`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }];
          }
        }

        // ---------------------------------------------------------------------
        // 3. RULE-PROC-001: Suspicious / Encoded PowerShell Execution
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-PROC-001' && event.eventType === 'process') {
          const cmd = ((event.data?.commandLine || event.data?.command || '') as string).toLowerCase();
          const procName = ((event.data?.processName || event.data?.name || '') as string).toLowerCase();

          const isShell = procName.includes('powershell') || procName.includes('pwsh') || procName.includes('cmd.exe') || procName.includes('bash') || procName.includes('sh');
          const hasSuspiciousFlag = ['-enc', '-encodedcommand', '-w hidden', '-nop', 'downloadstring', 'bypass', 'iex('].some(flag => cmd.includes(flag));

          if (isShell && hasSuspiciousFlag) {
            isMatch = true;
            alertTitle = `Suspicious PowerShell Execution on ${host}`;
            alertDesc = `Process '${procName || 'powershell'}' was executed with obfuscated or policy bypass command line arguments.`;
            evidence = [
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
            ];
          }
        }

        // ---------------------------------------------------------------------
        // 4. RULE-PERS-001: Persistence Indicator (Scheduled Task / Cron)
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-PERS-001' && event.eventType === 'process') {
          const cmd = ((event.data?.commandLine || event.data?.command || '') as string).toLowerCase();
          const procName = ((event.data?.processName || '') as string).toLowerCase();

          if (cmd.includes('schtasks /create') || cmd.includes('crontab -e') || procName === 'schtasks.exe' || cmd.includes('systemctl enable')) {
            isMatch = true;
            alertTitle = `Persistence Mechanism Established: Scheduled Task on ${host}`;
            alertDesc = `A scheduled task or autostart cron job was created or modified on host ${host}. Command: ${cmd.slice(0, 100)}`;
            evidence = [{
              type: 'Process Execution',
              description: `Task creation command executed: ${cmd}`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }];
          }
        }

        // ---------------------------------------------------------------------
        // 5. RULE-NET-001: Network Reconnaissance / Port Scanning
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-NET-001' && event.eventType === 'network') {
          const isPortScan = event.data?.action === 'port_scan' || event.data?.scanDetected || event.data?.connectionRate === 'high' || (event.data?.portSpan && Number(event.data.portSpan) >= 15);
          if (isPortScan) {
            isMatch = true;
            alertTitle = `Network Reconnaissance / Port Scanning Detected on ${host}`;
            alertDesc = `Rapid outbound network connection attempts across multiple destination ports detected from ${host}.`;
            evidence = [{
              type: 'Network Telemetry',
              description: `Port scan probe originating from ${srcIp || host} targeting destination subnet`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }];
          }
        }

        // ---------------------------------------------------------------------
        // 6. RULE-DEV-001: Unauthorized Removable Storage / USB Mount
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-DEV-001' && event.eventType === 'usb') {
          const isUsbMount = event.data?.action === 'mount' || event.data?.type === 'mass_storage' || event.data?.action === 'connect';
          if (isUsbMount) {
            isMatch = true;
            alertTitle = `Removable Storage Media Mounted on ${host}`;
            alertDesc = `An external USB storage device (${event.data?.deviceName || 'Unknown device'}) was connected to ${host}.`;
            evidence = [{
              type: 'Hardware Telemetry',
              description: `Device ID: ${event.data?.deviceId || 'N/A'}, Vendor: ${event.data?.vendor || 'Unknown'}`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }];
          }
        }

        // ---------------------------------------------------------------------
        // 7. RULE-PHISH-001: Phishing URL Ingestion (PhishGuard ML)
        // ---------------------------------------------------------------------
        else if (rule.id === 'RULE-PHISH-001' && (event.eventType as string) === 'phishing') {
          const isPhish = event.data?.classification === 'Phishing' || (typeof event.data?.riskScore === 'number' && event.data.riskScore >= 70);
          if (isPhish) {
            isMatch = true;
            alertTitle = `High-Risk Phishing URL Ingested from ${host}`;
            alertDesc = `PhishGuard ML flagged URL '${event.data?.url || 'unknown'}' as high risk phishing.`;
            evidence = [{
              type: 'PhishGuard Telemetry',
              description: `Phishing scan URL: ${event.data?.url}, Risk Score: ${event.data?.riskScore}`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }];
          }
        }

        // ---------------------------------------------------------------------
        // 8. Dynamic Condition Fallback (for Custom Rules)
        // ---------------------------------------------------------------------
        else if (rule.conditions && typeof rule.conditions === 'object') {
          const cond = rule.conditions as Record<string, any>;
          if (cond.eventType && cond.eventType === event.eventType) {
            // Check if required field patterns match
            let matched = true;
            for (const [key, val] of Object.entries(cond)) {
              if (key === 'eventType') continue;
              if (event.data?.[key] !== val) {
                matched = false;
                break;
              }
            }
            if (matched) {
              isMatch = true;
              evidence = [{
                type: 'Rule Condition Telemetry',
                description: `Custom rule condition matched for ${rule.name}`,
                timestamp: event.eventTime,
                data: event.data,
                state: 'CONFIRMED'
              }];
            }
          }
        }

        // ---------------------------------------------------------------------
        // IF MATCHED: DEDUPLICATION & PERSISTENCE
        // ---------------------------------------------------------------------
        if (isMatch) {
          // Check for existing open alert on this host/rule within last 15 minutes
          const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
          const existingAlerts = await db.getAlerts(orgId, environment);
          const duplicate = existingAlerts.find(a => 
            a.ruleId === rule.id && 
            a.hostname === host && 
            (a.status === 'open' || a.status === 'investigating') &&
            a.createdAt >= fifteenMinutesAgo
          );

          if (duplicate) {
            // Duplicate detected: do not create redundant alert flood
            return duplicate;
          }

          // Create new Alert record in PostgreSQL
          const alert = await db.createAlert({
            organizationId: orgId,
            agentId: event.agentId,
            ruleId: rule.id,
            title: alertTitle,
            description: alertDesc,
            severity: rule.severity,
            riskScore: rule.riskScore,
            status: 'open',
            hostname: host,
            username: user,
            sourceIp: srcIp,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechniqueName,
            mitreId: rule.mitreTechniqueId,
            evidence: evidence.length > 0 ? evidence : [{
              type: 'Endpoint Event Telemetry',
              description: `Rule ${rule.name} matched triggering event`,
              timestamp: event.eventTime,
              data: event.data,
              state: 'CONFIRMED'
            }],
            triggerEventIds: triggerIds,
            environment
          });

          // Log to audit trail safely
          await db.addAuditLog({
            organizationId: orgId,
            action: 'ALERT_GENERATED',
            targetType: 'alert',
            targetId: alert.id,
            details: {
              ruleId: rule.id,
              severity: alert.severity,
              riskScore: alert.riskScore,
              hostname: alert.hostname
            }
          });

          // Publish SSE event
          broadcastEvent(orgId, 'new_alert', alert);

          // -------------------------------------------------------------------
          // INCIDENT CORRELATION
          // -------------------------------------------------------------------
          try {
            const openIncidents = await db.getIncidents(orgId, environment);
            const matchingIncident = openIncidents.find(inc => 
              (inc.status === 'open' || inc.status === 'investigating') &&
              (inc.title.includes(host) || (inc.linkedAlertIds && inc.linkedAlertIds.length > 0))
            );

            if (matchingIncident) {
              await db.linkAlertToIncident(matchingIncident.id, alert.id, orgId);
              broadcastEvent(orgId, 'incident_updated', { incidentId: matchingIncident.id, linkedAlertId: alert.id });
            } else if (alert.severity === 'critical' || alert.riskScore >= 85) {
              // High severity / Critical alert auto-correlation
              const newInc = await db.createIncident({
                organizationId: orgId,
                title: `Incident: High-Severity Security Threat on ${host}`,
                description: `Automated incident correlation triggered by ${alert.severity.toUpperCase()} alert: '${alert.title}'.`,
                severity: alert.severity === 'critical' ? 'critical' : 'high',
                status: 'open',
                priority: alert.severity === 'critical' ? 'P1' : 'P2',
                leadInvestigator: null,
                linkedAlertIds: [alert.id],
                environment
              });
              broadcastEvent(orgId, 'new_incident', newInc);
            }
          } catch (corrErr) {
            console.warn('[Incident Correlation Warning]', corrErr);
          }

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
