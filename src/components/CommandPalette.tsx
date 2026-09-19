import React, { useState, useEffect } from 'react';
import { Search, X, ShieldAlert, Cpu, AlertTriangle, Globe, Terminal, FileText, ArrowRight } from 'lucide-react';
import { Alert, Agent, Incident, DetectionRule } from '../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: Alert[];
  agents: Agent[];
  incidents: Incident[];
  rules: DetectionRule[];
  onNavigateTab: (tab: string) => void;
  onSelectAlert: (alert: Alert) => void;
  onOpenAddAgent: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  alerts,
  agents,
  incidents,
  rules,
  onNavigateTab,
  onSelectAlert,
  onOpenAddAgent
}) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else setQuery('');
      } else if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const q = query.toLowerCase().trim();

  // Search Results
  const matchingAlerts = alerts.filter(a =>
    a.title.toLowerCase().includes(q) || a.id.toLowerCase().includes(q) || a.hostname?.toLowerCase().includes(q)
  ).slice(0, 3);

  const matchingAgents = agents.filter(ag =>
    ag.hostname.toLowerCase().includes(q) || ag.ipAddress.includes(q)
  ).slice(0, 3);

  const matchingRules = rules.filter(r =>
    r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.mitreTechniqueId.toLowerCase().includes(q)
  ).slice(0, 3);

  const matchingIncidents = incidents.filter(i =>
    i.title.toLowerCase().includes(q) || i.id.toLowerCase().includes(q)
  ).slice(0, 3);

  return (
    <div className="fixed inset-0 z-50 bg-zinc-950/80 backdrop-blur-sm flex items-start justify-center pt-20 p-4">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-lg max-w-xl w-full shadow-2xl overflow-hidden text-zinc-100 text-xs">
        {/* Input */}
        <div className="p-3 border-b border-zinc-800 flex items-center gap-3">
          <Search className="w-4 h-4 text-zinc-400 shrink-0" />
          <input
            type="text"
            autoFocus
            placeholder="Search alerts, hosts, rules, incidents, or jump to view..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent border-none text-zinc-100 placeholder-zinc-500 focus:outline-none text-xs"
          />
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Container */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-3 font-mono">
          {/* Quick Actions */}
          <div className="space-y-1">
            <span className="text-[10px] text-zinc-500 uppercase px-2 font-bold block">Quick Actions</span>
            <button
              onClick={() => { onOpenAddAgent(); onClose(); }}
              className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between group text-zinc-300 hover:text-white"
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span>Connect Authorized Endpoint Agent</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-400" />
            </button>

            <button
              onClick={() => { onNavigateTab('phishguard'); onClose(); }}
              className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between group text-zinc-300 hover:text-white"
            >
              <div className="flex items-center gap-2">
                <Globe className="w-3.5 h-3.5 text-amber-400" />
                <span>Inspect URL with PhishGuard ML</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-400" />
            </button>

            <button
              onClick={() => { onNavigateTab('ai_assistant'); onClose(); }}
              className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between group text-zinc-300 hover:text-white"
            >
              <div className="flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-purple-400" />
                <span>Ask Grounded SOC Copilot</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-400" />
            </button>
          </div>

          {/* Alerts */}
          {matchingAlerts.length > 0 && (
            <div className="space-y-1 pt-1 border-t border-zinc-800">
              <span className="text-[10px] text-zinc-500 uppercase px-2 font-bold block">Alerts</span>
              {matchingAlerts.map(a => (
                <button
                  key={a.id}
                  onClick={() => { onSelectAlert(a); onNavigateTab('alerts'); onClose(); }}
                  className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between text-zinc-300 hover:text-white"
                >
                  <div className="flex items-center gap-2 truncate">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span className="text-zinc-400 text-[11px]">{a.id}</span>
                    <span className="truncate">{a.title}</span>
                  </div>
                  <span className="text-[10px] text-zinc-500 uppercase">{a.severity}</span>
                </button>
              ))}
            </div>
          )}

          {/* Agents */}
          {matchingAgents.length > 0 && (
            <div className="space-y-1 pt-1 border-t border-zinc-800">
              <span className="text-[10px] text-zinc-500 uppercase px-2 font-bold block">Endpoints</span>
              {matchingAgents.map(ag => (
                <button
                  key={ag.id}
                  onClick={() => { onNavigateTab('agents'); onClose(); }}
                  className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between text-zinc-300 hover:text-white"
                >
                  <div className="flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{ag.hostname}</span>
                    <span className="text-zinc-500 text-[11px]">({ag.ipAddress})</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 uppercase">{ag.status}</span>
                </button>
              ))}
            </div>
          )}

          {/* Rules */}
          {matchingRules.length > 0 && (
            <div className="space-y-1 pt-1 border-t border-zinc-800">
              <span className="text-[10px] text-zinc-500 uppercase px-2 font-bold block">Rules</span>
              {matchingRules.map(r => (
                <button
                  key={r.id}
                  onClick={() => { onNavigateTab('rules'); onClose(); }}
                  className="w-full px-2.5 py-1.5 rounded hover:bg-zinc-800 text-left flex items-center justify-between text-zinc-300 hover:text-white"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-emerald-400">{r.id}</span>
                    <span className="truncate">{r.name}</span>
                  </div>
                  <span className="text-[10px] text-zinc-500">{r.mitreTechniqueId}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-2 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between text-[10px] text-zinc-500 font-mono">
          <span>Navigate with arrows or click</span>
          <span>ESC to close</span>
        </div>
      </div>
    </div>
  );
};
