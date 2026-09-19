import React, { useState } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Cpu, 
  AlertTriangle, 
  Activity, 
  Terminal, 
  ExternalLink, 
  Globe, 
  ArrowRight, 
  CheckCircle2, 
  Clock, 
  Key, 
  Copy, 
  Check, 
  RefreshCw, 
  Zap, 
  Search, 
  Bot, 
  Sparkles, 
  Radio, 
  Filter
} from 'lucide-react';
import { RealMetrics, Alert, Agent, EndpointEvent, Organization, Profile } from '../types';
import { api } from '../api';

interface DashboardViewProps {
  metrics: RealMetrics | null;
  alerts: Alert[];
  agents: Agent[];
  recentEvents: EndpointEvent[];
  organization?: Organization | null;
  profile?: Profile | null;
  onOpenAddAgent: () => void;
  onNavigateTab: (tab: string) => void;
  onSelectAlert: (alert: Alert) => void;
  onUpdateAlert?: (alert: Alert) => void;
  onRefresh?: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  alerts,
  agents,
  recentEvents,
  organization,
  profile,
  onOpenAddAgent,
  onNavigateTab,
  onSelectAlert,
  onUpdateAlert,
  onRefresh
}) => {
  const [copiedKey, setCopiedKey] = useState(false);
  const [simulating, setSimulating] = useState<string | null>(null);
  const [simulationNotice, setSimulationNotice] = useState<string | null>(null);
  const [alertFilter, setAlertFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  // Quick PhishGuard Widget state
  const [quickUrl, setQuickUrl] = useState('');
  const [quickScanning, setQuickScanning] = useState(false);
  const [quickResult, setQuickResult] = useState<any | null>(null);

  const handleCopyKey = () => {
    if (organization?.vrSocKey) {
      navigator.clipboard.writeText(organization.vrSocKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const handleManualRefresh = async () => {
    setRefreshing(true);
    if (onRefresh) {
      await onRefresh();
    }
    setTimeout(() => setRefreshing(false), 600);
  };

  const handleSimulateScenario = async (scenario: 'powershell_obfuscated' | 'persistence_task' | 'usb_storage' | 'auth_lockout', label: string) => {
    setSimulating(scenario);
    setSimulationNotice(null);
    try {
      const res = await api.simulateTelemetry(scenario);
      setSimulationNotice(`Simulated ${label}: Alert ${res.triggeredAlert?.id || 'Triggered'} generated against ${res.agent.hostname}`);
      if (onRefresh) onRefresh();
      setTimeout(() => setSimulationNotice(null), 5000);
    } catch (err: any) {
      setSimulationNotice(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(null);
    }
  };

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl || !quickUrl.trim()) return;
    setQuickScanning(true);
    setQuickResult(null);
    try {
      const res = await api.scanUrl(quickUrl.trim());
      setQuickResult(res);
      if (onRefresh) onRefresh();
    } catch (err: any) {
      setQuickResult({ error: err.message || 'Scan failed' });
    } finally {
      setQuickScanning(false);
    }
  };

  const handleQuickAcknowledge = async (e: React.MouseEvent, alert: Alert) => {
    e.stopPropagation();
    try {
      const nextStatus = alert.status === 'open' ? 'investigating' : 'resolved';
      const res = await api.updateAlertStatus(alert.id, nextStatus);
      if (onUpdateAlert) onUpdateAlert(res.alert);
      if (onRefresh) onRefresh();
    } catch (err: any) {
      console.error('Failed to update alert:', err);
    }
  };

  // Filter alerts
  const filteredAlerts = alerts.filter(a => {
    if (alertFilter !== 'all' && a.severity !== alertFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return a.title.toLowerCase().includes(q) || 
             (a.hostname ? a.hostname.toLowerCase().includes(q) : false) || 
             (a.mitreId ? a.mitreId.toLowerCase().includes(q) : false) ||
             a.id.toLowerCase().includes(q);
    }
    return true;
  });

  // Calculate Defensive Posture Health Score
  const criticalCount = alerts.filter(a => a.severity === 'critical' && a.status !== 'resolved').length;
  const highCount = alerts.filter(a => a.severity === 'high' && a.status !== 'resolved').length;
  const rawScore = 100 - (criticalCount * 18) - (highCount * 7);
  const postureScore = Math.max(25, Math.min(100, rawScore));
  const postureColor = postureScore >= 80 ? 'text-emerald-400' : postureScore >= 60 ? 'text-amber-400' : 'text-rose-400';
  const postureBg = postureScore >= 80 ? 'bg-emerald-500' : postureScore >= 60 ? 'bg-amber-500' : 'bg-rose-500';

  const hasAgents = (metrics?.connectedAgentsCount || 0) > 0 || agents.length > 0;
  const hasAlerts = (metrics?.totalAlertsCount || 0) > 0 || alerts.length > 0;

  return (
    <div className="space-y-6">
      {/* Top Organization & Executive SOC Status Banner */}
      <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-lg bg-gradient-to-br from-emerald-600 to-teal-800 flex items-center justify-center border border-emerald-500/40 shadow-sm shrink-0">
            <Shield className="w-5 h-5 text-emerald-100" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-base font-bold font-mono tracking-tight text-zinc-100">
                {organization?.name || 'VRSOC Cyber Defense Command'}
              </h1>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-500/40 font-semibold">
                ACTIVE SOC
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-zinc-800 text-zinc-400 border border-zinc-700">
                MITRE ATT&CK Grounded
              </span>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5 flex items-center gap-2 flex-wrap">
              <span>Analyst: <strong className="text-zinc-200">{profile?.fullName || profile?.email || 'Authorized SOC Operator'}</strong></span>
              <span>•</span>
              <span className="font-mono text-[11px] text-zinc-400">{profile?.role || 'Lead SOC Analyst'}</span>
            </p>
          </div>
        </div>

        {/* 14-character Key & Posture Score */}
        <div className="flex items-center gap-4 flex-wrap">
          {organization?.vrSocKey && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-zinc-950 border border-zinc-800 text-xs">
              <div className="flex items-center gap-1.5 text-zinc-400 font-mono text-[11px]">
                <Key className="w-3.5 h-3.5 text-emerald-400" />
                <span>VRSOC KEY:</span>
              </div>
              <code className="font-mono font-bold text-emerald-400 tracking-wider">
                {organization.vrSocKey}
              </code>
              <button
                onClick={handleCopyKey}
                className="p-1 hover:text-emerald-300 text-zinc-400 transition-colors"
                title="Copy 14-character VRSOC provisioning key"
              >
                {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}

          {/* Defense Posture Meter */}
          <div className="px-3.5 py-1.5 rounded bg-zinc-950 border border-zinc-800 flex items-center gap-3">
            <div>
              <div className="text-[10px] font-mono text-zinc-500 uppercase">Defense Posture</div>
              <div className={`text-base font-mono font-bold ${postureColor}`}>
                {postureScore}/100
              </div>
            </div>
            <div className="w-12 h-2 rounded-full bg-zinc-800 overflow-hidden">
              <div className={`h-full ${postureBg}`} style={{ width: `${postureScore}%` }} />
            </div>
          </div>

          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="p-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Quick Action Interactive Threat Simulation Ribbon */}
      <div className="p-3.5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <span className="text-xs font-bold font-mono text-zinc-200 uppercase tracking-wide">
              Live Pipeline Verification & Threat Ingestion Scenarios
            </span>
          </div>
          <span className="text-[11px] text-zinc-400 font-mono">
            Test real-time detection rules & live SSE telemetry stream
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => handleSimulateScenario('powershell_obfuscated', 'PowerShell Obfuscation')}
            disabled={Boolean(simulating)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 hover:bg-zinc-800 border border-zinc-700/80 text-zinc-200 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {simulating === 'powershell_obfuscated' ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" /> : <Zap className="w-3.5 h-3.5 text-rose-400" />}
            <span>Obfuscated PowerShell (T1059.001)</span>
          </button>

          <button
            onClick={() => handleSimulateScenario('persistence_task', 'Persistence Scheduled Task')}
            disabled={Boolean(simulating)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 hover:bg-zinc-800 border border-zinc-700/80 text-zinc-200 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {simulating === 'persistence_task' ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" /> : <Zap className="w-3.5 h-3.5 text-orange-400" />}
            <span>Persistence Task (T1053.005)</span>
          </button>

          <button
            onClick={() => handleSimulateScenario('usb_storage', 'Removable Storage Mount')}
            disabled={Boolean(simulating)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 hover:bg-zinc-800 border border-zinc-700/80 text-zinc-200 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {simulating === 'usb_storage' ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" /> : <Zap className="w-3.5 h-3.5 text-amber-400" />}
            <span>USB Storage Mount (T1091)</span>
          </button>

          <button
            onClick={() => handleSimulateScenario('auth_lockout', 'Account Lockout')}
            disabled={Boolean(simulating)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 hover:bg-zinc-800 border border-zinc-700/80 text-zinc-200 text-xs font-mono flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {simulating === 'auth_lockout' ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" /> : <Zap className="w-3.5 h-3.5 text-cyan-400" />}
            <span>Auth Lockout (T1110)</span>
          </button>
        </div>

        {simulationNotice && (
          <div className="p-2.5 rounded bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{simulationNotice}</span>
          </div>
        )}
      </div>

      {/* Metrics Row (Derived strictly from real records) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Connected Endpoints */}
        <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2 hover:border-zinc-700 transition-colors">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span className="font-medium">ENROLLED ENDPOINTS</span>
            <Cpu className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-zinc-100">
              {metrics ? metrics.connectedAgentsCount : agents.length}
            </span>
            <span className="text-xs font-mono text-emerald-400">
              {agents.filter(a => a.status === 'online').length} online
            </span>
          </div>
          <div className="text-[11px] text-zinc-500 flex items-center justify-between pt-1 border-t border-zinc-800/60 font-mono">
            <span>Offline: {agents.filter(a => a.status !== 'online').length}</span>
            <button onClick={() => onNavigateTab('agents')} className="text-emerald-400 hover:text-emerald-300 font-medium">
              Manage Agents →
            </button>
          </div>
        </div>

        {/* Metric 2: Active Alerts */}
        <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2 hover:border-zinc-700 transition-colors">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span className="font-medium">ACTIVE ALERTS</span>
            <ShieldAlert className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-zinc-100">
              {alerts.filter(a => a.status !== 'resolved').length}
            </span>
            {criticalCount > 0 ? (
              <span className="text-xs font-mono text-rose-400 font-bold animate-pulse">
                {criticalCount} critical
              </span>
            ) : (
              <span className="text-xs font-mono text-emerald-400">0 critical</span>
            )}
          </div>
          <div className="text-[11px] text-zinc-500 flex items-center justify-between pt-1 border-t border-zinc-800/60 font-mono">
            <span>Total Queue: {alerts.length}</span>
            <button onClick={() => onNavigateTab('alerts')} className="text-emerald-400 hover:text-emerald-300 font-medium">
              Alert Queue →
            </button>
          </div>
        </div>

        {/* Metric 3: Open Incidents */}
        <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2 hover:border-zinc-700 transition-colors">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span className="font-medium">OPEN INCIDENTS</span>
            <AlertTriangle className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-zinc-100">
              {metrics ? metrics.openIncidentsCount : 0}
            </span>
            <span className="text-xs font-mono text-zinc-400">
              {metrics ? `${metrics.totalIncidentsCount} total` : '0 cases'}
            </span>
          </div>
          <div className="text-[11px] text-zinc-500 flex items-center justify-between pt-1 border-t border-zinc-800/60 font-mono">
            <span>Active cases</span>
            <button onClick={() => onNavigateTab('incidents')} className="text-emerald-400 hover:text-emerald-300 font-medium">
              Case Room →
            </button>
          </div>
        </div>

        {/* Metric 4: PhishGuard ML Scans */}
        <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2 hover:border-zinc-700 transition-colors">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span className="font-medium">PHISHGUARD ML SCANS</span>
            <Globe className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-zinc-100">
              {metrics ? metrics.phishingScansCount : 0}
            </span>
            <span className={`text-xs font-mono ${metrics && metrics.phishingDetectionsCount > 0 ? 'text-rose-400 font-bold' : 'text-zinc-400'}`}>
              {metrics ? `${metrics.phishingDetectionsCount} flagged` : '0 threats'}
            </span>
          </div>
          <div className="text-[11px] text-zinc-500 flex items-center justify-between pt-1 border-t border-zinc-800/60 font-mono">
            <span>Heuristic & ML</span>
            <button onClick={() => onNavigateTab('phishguard')} className="text-emerald-400 hover:text-emerald-300 font-medium">
              PhishGuard Studio →
            </button>
          </div>
        </div>
      </div>

      {/* Main Two-Column SOC Dashboard Body */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Column (2 cols): Active Detections, In-Line Triage & Search */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-bold font-mono text-zinc-200 uppercase tracking-wider">
                Detection Feed & Triage Queue
              </h2>
            </div>

            {/* Filter buttons */}
            <div className="flex items-center gap-1.5 text-xs font-mono flex-wrap">
              <button
                onClick={() => setAlertFilter('all')}
                className={`px-2 py-0.5 rounded text-[11px] ${alertFilter === 'all' ? 'bg-zinc-100 text-zinc-950 font-bold' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'}`}
              >
                All ({alerts.length})
              </button>
              <button
                onClick={() => setAlertFilter('critical')}
                className={`px-2 py-0.5 rounded text-[11px] ${alertFilter === 'critical' ? 'bg-rose-600 text-white font-bold' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'}`}
              >
                Critical ({alerts.filter(a => a.severity === 'critical').length})
              </button>
              <button
                onClick={() => setAlertFilter('high')}
                className={`px-2 py-0.5 rounded text-[11px] ${alertFilter === 'high' ? 'bg-orange-600 text-white font-bold' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'}`}
              >
                High ({alerts.filter(a => a.severity === 'high').length})
              </button>
              <button
                onClick={() => setAlertFilter('medium')}
                className={`px-2 py-0.5 rounded text-[11px] ${alertFilter === 'medium' ? 'bg-amber-600 text-white font-bold' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'}`}
              >
                Medium ({alerts.filter(a => a.severity === 'medium').length})
              </button>
            </div>
          </div>

          {/* Search bar */}
          <div className="relative">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter alerts by title, hostname, MITRE ID, or technique..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-200 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="p-8 rounded-lg bg-zinc-900 border border-zinc-800 text-center space-y-3">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-xs font-mono text-zinc-300 font-semibold">No alerts matching filter criteria.</div>
              <p className="text-[11px] text-zinc-500 max-w-sm mx-auto">
                Endpoints are reporting nominal telemetry. Use the simulation scenario buttons above to trigger a test incident.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredAlerts.slice(0, 6).map((alert) => {
                const severityBadge =
                  alert.severity === 'critical' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                  alert.severity === 'high' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                  alert.severity === 'medium' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                  'bg-zinc-800 text-zinc-300 border-zinc-700';

                const statusBadge =
                  alert.status === 'open' ? 'text-rose-400 bg-rose-950/40 border-rose-800/50' :
                  alert.status === 'investigating' ? 'text-amber-400 bg-amber-950/40 border-amber-800/50' :
                  'text-emerald-400 bg-emerald-950/40 border-emerald-800/50';

                return (
                  <div
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className="p-3.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 cursor-pointer transition-all space-y-2 group"
                  >
                    <div className="flex items-center justify-between text-xs flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${severityBadge}`}>
                          {alert.severity}
                        </span>
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase border ${statusBadge}`}>
                          {alert.status}
                        </span>
                        <span className="font-mono text-zinc-500 text-[11px]">{alert.id}</span>
                        <span className="font-mono text-zinc-300 text-[11px]">| {alert.hostname}</span>
                      </div>
                      <div className="flex items-center gap-2 text-zinc-500 font-mono text-[11px]">
                        <span>Risk: <strong className="text-zinc-300">{alert.riskScore}/100</strong></span>
                        <span>•</span>
                        <span>{new Date(alert.createdAt).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="text-xs font-semibold text-zinc-100 group-hover:text-emerald-300 transition-colors">
                      {alert.title}
                    </div>
                    <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed">
                      {alert.description}
                    </p>

                    <div className="flex items-center justify-between pt-1 border-t border-zinc-800/70 text-xs">
                      {alert.mitreId ? (
                        <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-400">
                          <span className="px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-emerald-400">
                            MITRE {alert.mitreId}
                          </span>
                          <span className="truncate max-w-[200px]">{alert.mitreTechnique}</span>
                        </div>
                      ) : <div />}

                      <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={(e) => handleQuickAcknowledge(e, alert)}
                          className="px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] font-mono transition-colors"
                        >
                          {alert.status === 'open' ? 'Acknowledge' : alert.status === 'investigating' ? 'Mark Resolved' : 'Reopen'}
                        </button>
                        <button
                          onClick={() => {
                            onSelectAlert(alert);
                            onNavigateTab('ai_assistant');
                          }}
                          className="px-2 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-300 text-[11px] font-mono flex items-center gap-1 transition-colors"
                        >
                          <Bot className="w-3 h-3" />
                          <span>AI Copilot</span>
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Recent Ingested Telemetry Feed */}
          <div className="pt-3 space-y-2.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold font-mono text-zinc-300 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                <span>Live Telemetry Stream Ingestion</span>
              </h3>
              <div className="flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                <Radio className="w-3 h-3 animate-pulse" />
                <span>INGESTION REAL-TIME</span>
              </div>
            </div>

            {recentEvents.length === 0 ? (
              <div className="p-4 rounded bg-zinc-900 border border-zinc-800 text-xs text-zinc-500 text-center font-mono">
                No telemetry events logged yet. Connect an endpoint or trigger a simulation scenario above.
              </div>
            ) : (
              <div className="bg-zinc-900 rounded-lg border border-zinc-800 divide-y divide-zinc-800/80 overflow-hidden">
                {recentEvents.slice(0, 5).map((ev) => (
                  <div key={ev.id} className="p-2.5 text-xs flex items-center justify-between font-mono hover:bg-zinc-800/40 transition-colors">
                    <div className="flex items-center gap-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${
                        ev.severity === 'high' || ev.severity === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        ev.severity === 'medium' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-zinc-800 text-zinc-300'
                      }`}>
                        {ev.eventType}
                      </span>
                      <span className="text-zinc-200 text-[11px] truncate max-w-xs sm:max-w-md">
                        {ev.data?.action || ev.data?.processName || ev.data?.commandLine || ev.eventType}
                      </span>
                      {ev.data?.user && (
                        <span className="text-zinc-500 text-[10px]">({ev.data.user})</span>
                      )}
                    </div>
                    <span className="text-[10px] text-zinc-500 shrink-0">
                      {new Date(ev.eventTime).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column (1 col): Quick PhishGuard ML, Endpoints Matrix & Coverage */}
        <div className="space-y-4">
          {/* Quick PhishGuard ML Analysis Widget */}
          <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold font-mono text-zinc-200 uppercase">Quick URL Scanner</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30 font-semibold">
                PhishGuard ML
              </span>
            </div>

            <form onSubmit={handleQuickScan} className="space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="https://login-verification-secure.com"
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  className="flex-1 px-2.5 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-xs font-mono text-zinc-100 focus:border-emerald-500 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={quickScanning || !quickUrl.trim()}
                  className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium transition-colors disabled:opacity-50 font-mono shrink-0"
                >
                  {quickScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : 'Scan'}
                </button>
              </div>
            </form>

            {quickResult && (
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 space-y-1.5 text-xs font-mono">
                {quickResult.error ? (
                  <div className="text-rose-400">{quickResult.error}</div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-zinc-400">Verdict:</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        quickResult.scan?.verdict === 'phishing' ? 'bg-rose-600 text-white' :
                        quickResult.scan?.verdict === 'suspicious' ? 'bg-amber-600 text-white' :
                        'bg-emerald-700 text-white'
                      }`}>
                        {quickResult.scan?.verdict || 'ANALYZED'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-zinc-400">
                      <span>Threat Score:</span>
                      <span className="font-bold text-zinc-200">{quickResult.scan?.threatScore || 0}/100</span>
                    </div>
                    {quickResult.scan?.indicators && quickResult.scan.indicators.length > 0 && (
                      <div className="text-[10px] text-zinc-500 pt-1 border-t border-zinc-800">
                        {quickResult.scan.indicators[0]?.description}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>

          {/* Monitored Endpoints Matrix */}
          <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-zinc-200 uppercase">Monitored Endpoints</span>
              <span className="text-[11px] font-mono text-emerald-400">{agents.filter(a => a.status === 'online').length} active</span>
            </div>

            {agents.length === 0 ? (
              <div className="text-xs text-zinc-500 font-mono py-2 text-center">
                No active endpoints enrolled yet.
              </div>
            ) : (
              <div className="space-y-2">
                {agents.slice(0, 4).map((agent) => (
                  <div key={agent.id} className="p-2.5 rounded bg-zinc-950 border border-zinc-800 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold text-zinc-200">{agent.hostname}</span>
                      <div className="flex items-center gap-1.5">
                        <span className={`inline-block w-2 h-2 rounded-full ${agent.status === 'online' ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                        <span className="text-[10px] font-mono uppercase text-zinc-400">{agent.status}</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-zinc-400 font-mono">
                      <span>{agent.os}</span>
                      <span>{agent.ipAddress}</span>
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-zinc-500 font-mono pt-1">
                      <span>CPU: {agent.cpuUsage}%</span>
                      <span>RAM: {agent.ramUsage}%</span>
                      <span>Disk: {agent.diskUsage}%</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <button
              onClick={onOpenAddAgent}
              className="w-full py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium text-center transition-colors block font-mono"
            >
              + Enroll Endpoint Agent
            </button>
          </div>

          {/* Active Defense Coverage & MITRE Matrix */}
          <div className="p-4 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2.5 text-xs">
            <span className="text-xs font-bold font-mono text-zinc-200 uppercase block">Defensive Matrix Coverage</span>
            <div className="space-y-1.5 text-[11px]">
              <div className="flex items-center justify-between text-zinc-400">
                <span>Rule Engine Signatures:</span>
                <span className="font-mono font-semibold text-zinc-200">8 Active Rules</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Execution Defense (T1059):</span>
                <span className="font-mono font-semibold text-emerald-400">Active</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Persistence Guard (T1053):</span>
                <span className="font-mono font-semibold text-emerald-400">Active</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Credential Access (T1110):</span>
                <span className="font-mono font-semibold text-emerald-400">Active</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Initial Access (T1566):</span>
                <span className="font-mono font-semibold text-emerald-400">PhishGuard ML</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Data Integrity:</span>
                <span className="font-mono font-semibold text-emerald-400">100% Real Logs</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
