import React, { useState } from 'react';
import { Cpu, Terminal, Shield, RefreshCw, AlertCircle, CheckCircle, Clock, X, Trash2, Activity } from 'lucide-react';
import { Agent, EndpointEvent } from '../types';
import { api } from '../api';

interface AgentsViewProps {
  agents: Agent[];
  onOpenAddAgent: () => void;
  onRefresh: () => void;
}

export const AgentsView: React.FC<AgentsViewProps> = ({
  agents,
  onOpenAddAgent,
  onRefresh
}) => {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [agentEvents, setAgentEvents] = useState<EndpointEvent[]>([]);
  const [loadingDetails, setLoadingDetails] = useState<boolean>(false);
  const [revoking, setRevoking] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSelectAgent = async (agent: Agent) => {
    setSelectedAgent(agent);
    setLoadingDetails(true);
    setError(null);
    try {
      const res = await api.getAgent(agent.id);
      setAgentEvents(res.events || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load agent events');
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleRevokeAgent = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this endpoint agent? It will immediately stop receiving telemetry.')) {
      return;
    }
    setRevoking(true);
    try {
      await api.revokeAgent(id);
      onRefresh();
      setSelectedAgent(null);
    } catch (err: any) {
      setError(err.message || 'Failed to revoke agent');
    } finally {
      setRevoking(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>ENDPOINT FLEET & AGENTS</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              {agents.length} Enrolled
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Cross-platform telemetry collectors running real-time host monitoring
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="p-2 rounded bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-300 text-xs"
            title="Refresh Fleet Status"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onOpenAddAgent}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-emerald-50 text-xs font-medium transition-colors shadow-xs"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Connect Endpoint</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid: Agent Cards + Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Fleet List */}
        <div className={selectedAgent ? 'lg:col-span-6 space-y-3' : 'lg:col-span-12 space-y-3'}>
          {agents.length === 0 ? (
            <div className="p-12 rounded-lg bg-zinc-900 border border-zinc-800 text-center space-y-3">
              <Cpu className="w-8 h-8 text-zinc-600 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-semibold font-mono text-zinc-200">No endpoints enrolled.</p>
                <p className="text-xs text-zinc-500 max-w-sm mx-auto">
                  Add an endpoint agent to start receiving live security telemetry, heartbeats, and audit logs.
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
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {agents.map((agent) => {
                const isSelected = selectedAgent?.id === agent.id;
                const isOnline = agent.status === 'online';

                return (
                  <div
                    key={agent.id}
                    onClick={() => handleSelectAgent(agent)}
                    className={`p-4 rounded-lg border cursor-pointer transition-all space-y-3 ${
                      isSelected
                        ? 'bg-zinc-800/90 border-emerald-500/60 shadow-md'
                        : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-zinc-600'}`} />
                        <span className="font-mono font-bold text-xs text-zinc-100">{agent.hostname}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                        isOnline ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30' : 'bg-zinc-800 text-zinc-400'
                      }`}>
                        {agent.status}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-zinc-400">
                      <div>
                        <span className="text-zinc-500 block text-[10px]">OS / Architecture:</span>
                        <span className="text-zinc-300 truncate block">{agent.os} ({agent.architecture})</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[10px]">IP Address:</span>
                        <span className="text-zinc-300 font-bold">{agent.ipAddress}</span>
                      </div>
                    </div>

                    {/* Hardware Gauges */}
                    <div className="space-y-1.5 pt-1 border-t border-zinc-800 font-mono text-[10px]">
                      <div className="flex justify-between text-zinc-400">
                        <span>CPU Load: {agent.cpuUsage}%</span>
                        <span>RAM: {agent.ramUsage}%</span>
                        <span>Disk: {agent.diskUsage}%</span>
                      </div>
                      <div className="w-full bg-zinc-950 rounded-full h-1.5 overflow-hidden flex">
                        <div style={{ width: `${agent.cpuUsage}%` }} className="bg-emerald-500 h-full" />
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono pt-1">
                      <span>Agent v{agent.agentVersion}</span>
                      <span>Last seen: {new Date(agent.lastSeen).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Agent Drawer */}
        {selectedAgent && (
          <div className="lg:col-span-6 bg-zinc-900 border border-zinc-800 rounded-lg p-5 space-y-5 text-xs text-zinc-200">
            <div className="flex items-start justify-between pb-3 border-b border-zinc-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono font-bold text-sm text-emerald-400">{selectedAgent.hostname}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase font-bold ${
                    selectedAgent.status === 'online' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30' : 'bg-zinc-800 text-zinc-400'
                  }`}>
                    {selectedAgent.status}
                  </span>
                </div>
                <p className="text-zinc-400 text-xs font-mono">Agent ID: {selectedAgent.id}</p>
              </div>
              <button
                onClick={() => setSelectedAgent(null)}
                className="text-zinc-500 hover:text-zinc-300 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Agent Specs */}
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Operating System</span>
                <span className="text-zinc-200 font-semibold">{selectedAgent.os}</span>
              </div>
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Primary IP</span>
                <span className="text-zinc-200 font-semibold">{selectedAgent.ipAddress}</span>
              </div>
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Architecture</span>
                <span className="text-zinc-200 font-semibold">{selectedAgent.architecture}</span>
              </div>
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Agent Version</span>
                <span className="text-zinc-200 font-semibold">v{selectedAgent.agentVersion}</span>
              </div>
            </div>

            {/* Recent Telemetry Stream */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-xs uppercase tracking-wider text-zinc-400 font-mono flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Ingested Telemetry Stream</span>
                </h3>
                <span className="text-[10px] font-mono text-zinc-500">{agentEvents.length} events logged</span>
              </div>

              {loadingDetails ? (
                <div className="p-6 text-center text-zinc-500 text-xs">Loading telemetry...</div>
              ) : agentEvents.length === 0 ? (
                <div className="p-4 rounded bg-zinc-950 border border-zinc-800 text-center text-zinc-500 text-xs font-mono">
                  No telemetry events received from this agent yet.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                  {agentEvents.map((ev) => (
                    <div key={ev.id} className="p-2 rounded bg-zinc-950 border border-zinc-800/80 font-mono text-[10px] space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 font-bold uppercase">
                          {ev.eventType}
                        </span>
                        <span className="text-zinc-500">{new Date(ev.eventTime).toLocaleTimeString()}</span>
                      </div>
                      <div className="text-zinc-300 truncate">
                        {ev.data?.commandLine || ev.data?.action || JSON.stringify(ev.data)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Revoke Action */}
            <div className="pt-3 border-t border-zinc-800 flex justify-end">
              <button
                onClick={() => handleRevokeAgent(selectedAgent.id)}
                disabled={revoking}
                className="px-3 py-1.5 rounded bg-rose-950/40 text-rose-400 hover:bg-rose-900/60 border border-rose-800/40 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{revoking ? 'Revoking...' : 'Revoke Endpoint Agent'}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
