import React, { useState } from 'react';
import { FileText, Shield, Search, RefreshCw } from 'lucide-react';
import { AuditLog } from '../types';

interface AuditLogsViewProps {
  logs: AuditLog[];
  onRefresh: () => void;
}

export const AuditLogsView: React.FC<AuditLogsViewProps> = ({ logs, onRefresh }) => {
  const [search, setSearch] = useState('');

  const filteredLogs = logs.filter((log) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      log.action.toLowerCase().includes(q) ||
      log.targetType.toLowerCase().includes(q) ||
      log.userEmail?.toLowerCase().includes(q) ||
      log.ipAddress?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>AUDIT LOGS & COMPLIANCE LEDGER</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              IMMUTABLE
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Cryptographically timestamped audit trail of administrative and security events
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Search action, user, IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs w-56 focus:outline-none"
          />
          <button
            onClick={onRefresh}
            className="p-2 rounded bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-300 text-xs"
            title="Refresh Audit Logs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-zinc-900 rounded-lg border border-zinc-800 overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-xs text-zinc-500 font-mono">
            No audit records matching criteria.
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-zinc-950 text-zinc-400 border-b border-zinc-800 text-[11px]">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Action</th>
                <th className="p-3">Target</th>
                <th className="p-3">Analyst / Actor</th>
                <th className="p-3">IP Address</th>
                <th className="p-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800 text-zinc-300">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-zinc-800/40">
                  <td className="p-3 text-zinc-400 text-[11px] whitespace-nowrap">
                    {new Date(log.createdAt).toLocaleString()}
                  </td>
                  <td className="p-3 font-semibold text-emerald-400 whitespace-nowrap">
                    {log.action}
                  </td>
                  <td className="p-3 text-zinc-300 whitespace-nowrap">
                    <span className="px-1.5 py-0.2 rounded bg-zinc-950 border border-zinc-800 text-[10px]">
                      {log.targetType} {log.targetId ? `(${log.targetId.slice(0, 8)})` : ''}
                    </span>
                  </td>
                  <td className="p-3 text-zinc-200 truncate max-w-xs">{log.userEmail || 'System'}</td>
                  <td className="p-3 text-zinc-400 font-mono text-[11px]">{log.ipAddress || '127.0.0.1'}</td>
                  <td className="p-3 text-zinc-400 text-[11px] truncate max-w-sm">
                    {JSON.stringify(log.details)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
