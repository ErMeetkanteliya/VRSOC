import React, { useState } from 'react';
import { X, Terminal, Download, Copy, Check, ShieldCheck, Cpu, HardDrive, Play, AlertTriangle } from 'lucide-react';
import { Organization, Agent } from '../types';
import { api } from '../api';

interface AddAgentModalProps {
  organization: Organization;
  onClose: () => void;
  onAgentEnrolled: (agent: Agent) => void;
  activeLocalAgent: { agentId: string; agentToken: string; hostname: string } | null;
  setActiveLocalAgent: (agent: { agentId: string; agentToken: string; hostname: string } | null) => void;
}

export const AddAgentModal: React.FC<AddAgentModalProps> = ({
  organization,
  onClose,
  onAgentEnrolled,
  activeLocalAgent,
  setActiveLocalAgent
}) => {
  const [activeTab, setActiveTab] = useState<'script' | 'cli' | 'local_collector'>('local_collector');
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [localAgentName, setLocalAgentName] = useState('Analyst-Workstation-01');
  const [enrollingLocal, setEnrollingLocal] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [testSent, setTestSent] = useState<string | null>(null);

  const serverUrl = window.location.origin;
  const enrollCmd = `node vrsoc-agent.js --enroll ${organization.vrSocKey} --server ${serverUrl} --name "Endpoint-PC"`;

  const handleCopyCmd = () => {
    navigator.clipboard.writeText(enrollCmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleDownloadScript = () => {
    window.location.href = '/api/agent/script';
  };

  // Authorize & Start Local Host Collector
  const handleEnrollLocalHost = async () => {
    setEnrollingLocal(true);
    setLocalError(null);
    try {
      const res = await api.enrollAgent({
        enrollmentKey: organization.vrSocKey,
        name: localAgentName,
        hostname: `${window.location.hostname || 'local-host'}`,
        os: `${navigator.platform || 'Desktop Client'} (Browser Collector)`,
        ipAddress: '127.0.0.1'
      });

      setActiveLocalAgent({
        agentId: res.agent.id,
        agentToken: res.agentToken,
        hostname: res.agent.hostname
      });

      onAgentEnrolled(res.agent);

      // Send initial startup telemetry event
      await api.sendAgentTelemetry(res.agent.id, res.agentToken, {
        eventType: 'process',
        severity: 'info',
        data: {
          action: 'collector_startup',
          agentVersion: '1.4.0',
          cores: navigator.hardwareConcurrency || 4,
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString()
        }
      });
    } catch (err: any) {
      setLocalError(err.message || 'Failed to authorize local endpoint');
    } finally {
      setEnrollingLocal(false);
    }
  };

  // Send real defensive test telemetry through the local agent
  const handleTriggerTelemetryTest = async (testType: 'powershell' | 'brute_force' | 'scheduled_task' | 'usb_mount') => {
    if (!activeLocalAgent) return;
    setTestSent(null);
    try {
      if (testType === 'powershell') {
        const res = await api.sendAgentTelemetry(activeLocalAgent.agentId, activeLocalAgent.agentToken, {
          eventType: 'process',
          severity: 'critical',
          data: {
            processName: 'powershell.exe',
            commandLine: 'powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
            parentPid: 1044,
            parentProcess: 'cmd.exe',
            user: 'corp_analyst',
            hostname: activeLocalAgent.hostname
          }
        });
        setTestSent(`Triggered process telemetry event. Generated Alert: ${res.triggeredAlert || 'Evaluated in engine'}`);
      } else if (testType === 'brute_force') {
        // Send 5 consecutive auth failures to trigger RULE-AUTH-001
        for (let i = 1; i <= 5; i++) {
          await api.sendAgentTelemetry(activeLocalAgent.agentId, activeLocalAgent.agentToken, {
            eventType: 'auth',
            severity: 'medium',
            data: {
              action: 'logon_failed',
              status: 'failure',
              username: 'admin_sys',
              sourceIp: '192.168.1.144',
              hostname: activeLocalAgent.hostname,
              attemptNumber: i
            }
          });
        }
        setTestSent('Sent 5 consecutive authentication failure events. Alert RULE-AUTH-001 triggered!');
      } else if (testType === 'scheduled_task') {
        const res = await api.sendAgentTelemetry(activeLocalAgent.agentId, activeLocalAgent.agentToken, {
          eventType: 'process',
          severity: 'high',
          data: {
            processName: 'schtasks.exe',
            commandLine: 'schtasks /create /tn "DefensiveUpdate" /tr "C:\\Windows\\Temp\\update.bat" /sc onlogon',
            user: 'SYSTEM',
            hostname: activeLocalAgent.hostname
          }
        });
        setTestSent(`Sent scheduled task creation event. Generated Alert: ${res.triggeredAlert || 'Evaluated in engine'}`);
      } else if (testType === 'usb_mount') {
        const res = await api.sendAgentTelemetry(activeLocalAgent.agentId, activeLocalAgent.agentToken, {
          eventType: 'usb',
          severity: 'low',
          data: {
            action: 'mount',
            type: 'mass_storage',
            deviceName: 'SanDisk Ultra USB 3.0',
            deviceId: 'USB\\VID_0781&PID_5581',
            hostname: activeLocalAgent.hostname
          }
        });
        setTestSent(`Sent USB mass storage insertion event. Generated Alert: ${res.triggeredAlert || 'Evaluated in engine'}`);
      }
    } catch (err: any) {
      setLocalError(err.message || 'Failed to dispatch telemetry test');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-zinc-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden text-zinc-100">
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold font-mono">ENROLL AUTHORIZED ENDPOINT AGENT</h2>
              <p className="text-xs text-zinc-400">Defense Telemetry Ingestion & Real-Time Monitoring</p>
            </div>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Enrollment Key Banner */}
        <div className="px-6 py-3 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-zinc-400">Organization Key:</span>
            <span className="font-mono font-bold text-amber-400 tracking-widest">{organization.vrSocKey}</span>
          </div>
          <span className="text-[11px] font-mono text-zinc-500">14-CHAR HEXADECIMAL</span>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-zinc-800 px-6 pt-2">
          <button
            onClick={() => setActiveTab('local_collector')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'local_collector'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Authorize Local Host Collector
          </button>
          <button
            onClick={() => setActiveTab('script')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'script'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Download Agent Daemon
          </button>
          <button
            onClick={() => setActiveTab('cli')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === 'cli'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Terminal / CLI Command
          </button>
        </div>

        {/* Tab Contents */}
        <div className="p-6 space-y-4 text-xs">
          {localError && (
            <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{localError}</span>
            </div>
          )}

          {testSent && (
            <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-2">
              <Check className="w-4 h-4 shrink-0" />
              <span>{testSent}</span>
            </div>
          )}

          {/* TAB 1: LOCAL HOST COLLECTOR */}
          {activeTab === 'local_collector' && (
            <div className="space-y-4">
              <p className="text-zinc-400 leading-relaxed">
                Connect your active host directly to VRSOC without external dependencies. This authorizes telemetry collection from your current environment, registers heartbeats, and enables real security detection testing.
              </p>

              {!activeLocalAgent ? (
                <div className="p-4 rounded bg-zinc-950 border border-zinc-800 space-y-3">
                  <div>
                    <label className="block text-zinc-400 mb-1 font-medium">Endpoint Identifier Name</label>
                    <input
                      type="text"
                      value={localAgentName}
                      onChange={(e) => setLocalAgentName(e.target.value)}
                      className="w-full px-3 py-2 rounded bg-zinc-900 border border-zinc-700 text-zinc-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-[11px] font-mono text-zinc-400 pt-1">
                    <div className="p-2 rounded bg-zinc-900 border border-zinc-800">
                      <span className="text-zinc-500 block">Platform:</span>
                      <span className="text-zinc-200">{navigator.platform || 'Unknown'}</span>
                    </div>
                    <div className="p-2 rounded bg-zinc-900 border border-zinc-800">
                      <span className="text-zinc-500 block">CPU Hardware Cores:</span>
                      <span className="text-zinc-200">{navigator.hardwareConcurrency || 4} Logical Cores</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleEnrollLocalHost}
                    disabled={enrollingLocal}
                    className="w-full py-2.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>{enrollingLocal ? 'Authorizing & Enrolling...' : 'Authorize Local Host Agent'}</span>
                  </button>
                </div>
              ) : (
                <div className="p-4 rounded bg-emerald-950/20 border border-emerald-500/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="font-semibold text-emerald-300 font-mono text-xs">LOCAL ENDPOINT AGENT ACTIVE</span>
                    </div>
                    <span className="font-mono text-[10px] text-zinc-400">ID: {activeLocalAgent.agentId.slice(0, 8)}...</span>
                  </div>

                  <p className="text-[11px] text-zinc-300">
                    Host <strong>{activeLocalAgent.hostname}</strong> is enrolled and transmitting heartbeats every 10 seconds.
                  </p>

                  <div className="pt-2 border-t border-emerald-500/20">
                    <span className="text-zinc-400 block font-medium mb-2">Test Real Detection Rules (Sends Authentic Telemetry):</span>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => handleTriggerTelemetryTest('powershell')}
                        className="p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-left transition-colors"
                      >
                        <div className="font-semibold text-rose-400 font-mono text-[11px]">Test Obfuscated PowerShell</div>
                        <div className="text-[10px] text-zinc-500">Triggers RULE-PROC-001 (Critical)</div>
                      </button>

                      <button
                        onClick={() => handleTriggerTelemetryTest('brute_force')}
                        className="p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-left transition-colors"
                      >
                        <div className="font-semibold text-amber-400 font-mono text-[11px]">Test 5x Failed Logins</div>
                        <div className="text-[10px] text-zinc-500">Triggers RULE-AUTH-001 (High)</div>
                      </button>

                      <button
                        onClick={() => handleTriggerTelemetryTest('scheduled_task')}
                        className="p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-left transition-colors"
                      >
                        <div className="font-semibold text-cyan-400 font-mono text-[11px]">Test Persistence Autostart</div>
                        <div className="text-[10px] text-zinc-500">Triggers RULE-PERS-001 (High)</div>
                      </button>

                      <button
                        onClick={() => handleTriggerTelemetryTest('usb_mount')}
                        className="p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-left transition-colors"
                      >
                        <div className="font-semibold text-zinc-300 font-mono text-[11px]">Test USB Device Mount</div>
                        <div className="text-[10px] text-zinc-500">Triggers RULE-DEV-001 (Low)</div>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: DOWNLOAD AGENT SCRIPT */}
          {activeTab === 'script' && (
            <div className="space-y-4">
              <p className="text-zinc-400 leading-relaxed">
                Download the standalone, cross-platform VRSOC Endpoint Agent daemon (<strong>vrsoc-agent.js</strong>). Compatible with Windows, macOS, and Linux systems with Node.js installed.
              </p>

              <div className="p-4 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                <div>
                  <div className="font-mono font-semibold text-zinc-200">vrsoc-agent.js</div>
                  <div className="text-[11px] text-zinc-500">Standalone Node.js Telemetry Daemon (v1.4.0)</div>
                </div>
                <button
                  onClick={handleDownloadScript}
                  className="px-4 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium flex items-center gap-1.5 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Script</span>
                </button>
              </div>

              <div className="p-3 bg-zinc-950 rounded border border-zinc-800 space-y-1.5 font-mono text-[11px] text-zinc-400">
                <p className="text-zinc-300 font-semibold">Execution Instructions:</p>
                <p>1. Open PowerShell or Terminal on the target machine.</p>
                <p>2. Execute: <code className="text-emerald-400">node vrsoc-agent.js --enroll {organization.vrSocKey} --server {serverUrl}</code></p>
                <p>3. Telemetry and heartbeat will appear live on your VRSOC dashboard.</p>
              </div>
            </div>
          )}

          {/* TAB 3: CLI / CURL */}
          {activeTab === 'cli' && (
            <div className="space-y-3">
              <p className="text-zinc-400">Run this command on your workstation terminal to enroll:</p>

              <div className="p-3 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-emerald-400 break-all relative">
                <code>{enrollCmd}</code>
                <button
                  onClick={handleCopyCmd}
                  className="absolute right-2 top-2 px-2 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700 flex items-center gap-1 text-[10px]"
                >
                  {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="p-3 bg-zinc-950/60 rounded border border-zinc-800 text-[11px] text-zinc-400 space-y-1">
                <span className="text-zinc-300 font-medium block">Prerequisites:</span>
                <p>• Node.js 18+ installed on endpoint host.</p>
                <p>• Outbound network connectivity to VRSOC server on port 3000 / 443.</p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-zinc-950 border-t border-zinc-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
