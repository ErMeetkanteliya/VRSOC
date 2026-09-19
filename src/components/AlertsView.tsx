import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Check, Brain, Clock, Terminal, User, FileText, Send, ChevronRight, X, ExternalLink } from 'lucide-react';
import { Alert } from '../types';
import { api } from '../api';

interface AlertsViewProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onSelectAlert: (alert: Alert | null) => void;
  onUpdateAlert: (updatedAlert: Alert) => void;
  onEscalateToIncident: (alert: Alert) => void;
  onOpenAddAgent: () => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
  onUpdateAlert,
  onEscalateToIncident,
  onOpenAddAgent
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [newComment, setNewComment] = useState<string>('');
  const [analyzingAi, setAnalyzingAi] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = alert.title.toLowerCase().includes(q);
      const matchHost = alert.hostname?.toLowerCase().includes(q);
      const matchRule = alert.ruleId.toLowerCase().includes(q);
      const matchId = alert.id.toLowerCase().includes(q);
      if (!matchTitle && !matchHost && !matchRule && !matchId) return false;
    }
    return true;
  });

  const handleStatusChange = async (newStatus: Alert['status']) => {
    if (!selectedAlert) return;
    try {
      const res = await api.updateAlertStatus(selectedAlert.id, newStatus);
      onUpdateAlert(res.alert);
      onSelectAlert(res.alert);
    } catch (err: any) {
      setError(err.message || 'Failed to update alert status');
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert || !newComment.trim()) return;
    try {
      const res = await api.addAlertComment(selectedAlert.id, newComment.trim());
      setNewComment('');
      onUpdateAlert(res.alert);
      onSelectAlert(res.alert);
    } catch (err: any) {
      setError(err.message || 'Failed to add comment');
    }
  };

  const handleRunAiAnalysis = async () => {
    if (!selectedAlert) return;
    setAnalyzingAi(true);
    setError(null);
    try {
      const res = await api.analyzeAlertWithAi(selectedAlert.id);
      onUpdateAlert(res.alert);
      onSelectAlert(res.alert);
    } catch (err: any) {
      setError(err.message || 'AI analysis failed');
    } finally {
      setAnalyzingAi(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>ALERT INVESTIGATION QUEUE</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              {alerts.length} Records
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Traceable evidence from authentic endpoint telemetry & detection rules
          </p>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-zinc-900 p-3 rounded-lg border border-zinc-800 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-200 focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-200 focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>

        {/* Search */}
        <input
          type="text"
          placeholder="Filter by ID, host, rule..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="px-3 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-200 w-64 focus:outline-none text-xs"
        />
      </div>

      {/* Main Grid: List + Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Alerts List */}
        <div className={selectedAlert ? 'lg:col-span-5 space-y-2' : 'lg:col-span-12 space-y-2'}>
          {filteredAlerts.length === 0 ? (
            <div className="p-12 rounded-lg bg-zinc-900 border border-zinc-800 text-center space-y-3">
              <ShieldAlert className="w-8 h-8 text-zinc-600 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-semibold font-mono text-zinc-200">No alerts detected.</p>
                <p className="text-xs text-zinc-500 max-w-sm mx-auto">
                  Connect an authorized endpoint to begin monitoring or send defensive telemetry.
                </p>
              </div>
              <button
                onClick={onOpenAddAgent}
                className="mt-2 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs transition-colors inline-flex items-center gap-1.5"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Connect Endpoint</span>
              </button>
            </div>
          ) : (
            filteredAlerts.map((alert) => {
              const isSelected = selectedAlert?.id === alert.id;
              const severityColor =
                alert.severity === 'critical' ? 'text-rose-400 border-rose-500/30 bg-rose-500/10' :
                alert.severity === 'high' ? 'text-orange-400 border-orange-500/30 bg-orange-500/10' :
                alert.severity === 'medium' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' :
                'text-zinc-400 border-zinc-700 bg-zinc-800';

              return (
                <div
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all space-y-2 ${
                    isSelected
                      ? 'bg-zinc-800/90 border-emerald-500/60 shadow-md'
                      : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${severityColor}`}>
                        {alert.severity}
                      </span>
                      <span className="font-mono text-zinc-400 text-[11px] font-bold">{alert.id}</span>
                      <span className="text-zinc-500 text-[10px] uppercase font-mono">[{alert.status}]</span>
                    </div>
                    <span className="font-mono text-[10px] text-zinc-500">
                      {new Date(alert.createdAt).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-zinc-100">{alert.title}</div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 pt-1">
                    <span>Host: {alert.hostname || 'N/A'}</span>
                    <span>Risk: {alert.riskScore}/100</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Alert Detail Drawer */}
        {selectedAlert && (
          <div className="lg:col-span-7 bg-zinc-900 border border-zinc-800 rounded-lg p-5 space-y-5 text-xs text-zinc-200">
            {/* Drawer Top Header */}
            <div className="flex items-start justify-between pb-3 border-b border-zinc-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono font-bold text-sm text-emerald-400">{selectedAlert.id}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono uppercase">
                    {selectedAlert.severity}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono uppercase">
                    STATUS: {selectedAlert.status}
                  </span>
                </div>
                <h2 className="text-base font-bold text-zinc-100">{selectedAlert.title}</h2>
              </div>
              <button
                onClick={() => onSelectAlert(null)}
                className="text-zinc-500 hover:text-zinc-300 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Actions Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-zinc-950 rounded border border-zinc-800">
              <div className="flex items-center gap-2">
                <span className="text-zinc-400 text-[11px]">Change Status:</span>
                <select
                  value={selectedAlert.status}
                  onChange={(e) => handleStatusChange(e.target.value as any)}
                  className="px-2 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs focus:outline-none"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => onEscalateToIncident(selectedAlert)}
                  className="px-3 py-1 rounded bg-amber-600/20 text-amber-300 border border-amber-500/30 hover:bg-amber-600/30 font-medium transition-colors text-xs"
                >
                  Escalate to Incident
                </button>
                <button
                  onClick={handleRunAiAnalysis}
                  disabled={analyzingAi}
                  className="px-3 py-1 rounded bg-purple-600/20 text-purple-300 border border-purple-500/30 hover:bg-purple-600/30 font-medium transition-colors text-xs flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Brain className="w-3.5 h-3.5" />
                  <span>{analyzingAi ? 'Analyzing Evidence...' : 'Run Grounded AI Analysis'}</span>
                </button>
              </div>
            </div>

            {/* What Happened & Technical Details */}
            <div className="space-y-3">
              <h3 className="font-bold text-xs uppercase tracking-wider text-zinc-400 font-mono">1. What Happened?</h3>
              <p className="text-zinc-300 leading-relaxed bg-zinc-950 p-3 rounded border border-zinc-800">
                {selectedAlert.description}
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
                <div className="p-2 bg-zinc-950 rounded border border-zinc-800">
                  <span className="text-zinc-500 block">Affected Host</span>
                  <span className="text-zinc-200 font-semibold">{selectedAlert.hostname || 'Unknown'}</span>
                </div>
                <div className="p-2 bg-zinc-950 rounded border border-zinc-800">
                  <span className="text-zinc-500 block">Account / User</span>
                  <span className="text-zinc-200 font-semibold">{selectedAlert.username || 'System'}</span>
                </div>
                <div className="p-2 bg-zinc-950 rounded border border-zinc-800">
                  <span className="text-zinc-500 block">Risk Score</span>
                  <span className="text-amber-400 font-bold">{selectedAlert.riskScore}/100</span>
                </div>
                <div className="p-2 bg-zinc-950 rounded border border-zinc-800">
                  <span className="text-zinc-500 block">Detection Rule</span>
                  <span className="text-zinc-200 font-semibold">{selectedAlert.ruleId}</span>
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Mapping */}
            {selectedAlert.mitreId && (
              <div className="space-y-2">
                <h3 className="font-bold text-xs uppercase tracking-wider text-zinc-400 font-mono">2. MITRE ATT&CK Framework Mapping</h3>
                <div className="p-3 bg-zinc-950 rounded border border-zinc-800 flex items-center justify-between">
                  <div>
                    <div className="font-mono text-emerald-400 font-bold text-xs">
                      {selectedAlert.mitreId}: {selectedAlert.mitreTechnique}
                    </div>
                    <div className="text-[11px] text-zinc-400 mt-0.5">Tactic: {selectedAlert.mitreTactic}</div>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400">
                    ATT&CK v14
                  </span>
                </div>
              </div>
            )}

            {/* Evidence Table (Section 15 & 23) */}
            <div className="space-y-2">
              <h3 className="font-bold text-xs uppercase tracking-wider text-zinc-400 font-mono">3. Telemetry Evidence (Traceable Records)</h3>
              <div className="space-y-2">
                {selectedAlert.evidence.map((ev, idx) => (
                  <div key={idx} className="p-3 bg-zinc-950 rounded border border-zinc-800 font-mono text-[11px] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-emerald-400 font-semibold">{ev.type}</span>
                      <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 text-[10px] border border-emerald-500/30">
                        {ev.state}
                      </span>
                    </div>
                    <p className="text-zinc-300">{ev.description}</p>
                    <div className="text-zinc-500 text-[10px]">Timestamp: {ev.timestamp}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Grounded AI Analysis Result (3 States: CONFIRMED, INFERRED, UNKNOWN) */}
            {selectedAlert.aiSummary && (
              <div className="p-4 rounded-lg bg-zinc-950 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-purple-400" />
                    <span className="font-bold font-mono text-purple-300 text-xs uppercase">
                      Grounded AI Security Analysis
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-500">Gemini 3.8 Flash</span>
                </div>

                {/* 3 Evidence States Breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
                  {/* Confirmed */}
                  <div className="p-2.5 rounded bg-zinc-900 border border-emerald-500/30 space-y-1">
                    <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase block">
                      CONFIRMED (Telemetry)
                    </span>
                    <ul className="list-disc list-inside text-[11px] text-zinc-300 space-y-1">
                      {selectedAlert.aiSummary.confirmedEvidence.slice(0, 3).map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Inferred */}
                  <div className="p-2.5 rounded bg-zinc-900 border border-blue-500/30 space-y-1">
                    <span className="text-[10px] font-mono font-bold text-blue-400 uppercase block">
                      INFERRED (Assessment)
                    </span>
                    <ul className="list-disc list-inside text-[11px] text-zinc-300 space-y-1">
                      {selectedAlert.aiSummary.inferredInsights.slice(0, 3).map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Unknowns */}
                  <div className="p-2.5 rounded bg-zinc-900 border border-amber-500/30 space-y-1">
                    <span className="text-[10px] font-mono font-bold text-amber-400 uppercase block">
                      UNKNOWN (Missing Data)
                    </span>
                    <ul className="list-disc list-inside text-[11px] text-zinc-300 space-y-1">
                      {selectedAlert.aiSummary.unknowns.slice(0, 3).map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Recommended Investigation & Containment */}
                <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <span className="font-semibold text-[11px] text-zinc-200">Recommended Investigation Steps:</span>
                    <ol className="list-decimal list-inside text-[11px] text-zinc-400 space-y-1">
                      {selectedAlert.aiSummary.investigationSteps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>

                  <div className="space-y-1">
                    <span className="font-semibold text-[11px] text-zinc-200">Recommended Containment Playbook:</span>
                    <ol className="list-decimal list-inside text-[11px] text-zinc-400 space-y-1">
                      {selectedAlert.aiSummary.containmentSteps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>
                </div>
              </div>
            )}

            {/* Analyst Comments & Investigation Notes */}
            <div className="space-y-2 pt-2 border-t border-zinc-800">
              <h3 className="font-bold text-xs uppercase tracking-wider text-zinc-400 font-mono">4. Analyst Notes & Actions</h3>

              <div className="space-y-2">
                {selectedAlert.comments.length === 0 ? (
                  <p className="text-zinc-500 text-[11px] italic">No comments added yet.</p>
                ) : (
                  selectedAlert.comments.map((c) => (
                    <div key={c.id} className="p-2 rounded bg-zinc-950 border border-zinc-800 text-[11px]">
                      <div className="flex items-center justify-between text-zinc-400 font-mono text-[10px] mb-0.5">
                        <span className="font-semibold text-zinc-200">{c.userName}</span>
                        <span>{new Date(c.createdAt).toLocaleString()}</span>
                      </div>
                      <p className="text-zinc-300">{c.comment}</p>
                    </div>
                  ))
                )}
              </div>

              <form onSubmit={handleAddComment} className="flex gap-2 pt-1">
                <input
                  type="text"
                  placeholder="Add analyst note or observation..."
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  className="flex-1 px-3 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!newComment.trim()}
                  className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Send className="w-3 h-3" />
                  <span>Post</span>
                </button>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
