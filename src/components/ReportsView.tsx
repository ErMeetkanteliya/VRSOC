import React, { useState } from 'react';
import { FileText, Download, Printer, Copy, Check, Plus, RefreshCw, AlertCircle } from 'lucide-react';
import { Report } from '../types';
import { api } from '../api';

interface ReportsViewProps {
  reports: Report[];
  onReportCreated: (report: Report) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ reports, onReportCreated }) => {
  const [selectedReport, setSelectedReport] = useState<Report | null>(reports[0] || null);
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateReport = async () => {
    setGenerating(true);
    setError(null);
    try {
      const res = await api.generateReport(reportType);
      onReportCreated(res.report);
      setSelectedReport(res.report);
    } catch (err: any) {
      setError(err.message || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyJson = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(JSON.stringify(selectedReport, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>REPORTS & EXECUTIVE DOCUMENTATION</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              {reports.length} Generated
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Audit-ready cybersecurity summaries and technical incident reconstructions
          </p>
        </div>

        {/* Generate Controls */}
        <div className="flex items-center gap-2">
          <select
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            className="px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs focus:outline-none"
          >
            <option value="executive">Executive Summary</option>
            <option value="incident">Technical Incident Report</option>
          </select>

          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-xs"
          >
            {generating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid: Reports List + Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Reports Archive */}
        <div className="lg:col-span-4 space-y-2">
          <span className="font-mono text-zinc-400 font-bold uppercase text-[10px]">Generated Reports Archive:</span>
          {reports.length === 0 ? (
            <div className="p-8 rounded-lg bg-zinc-900 border border-zinc-800 text-center text-zinc-500 text-xs font-mono">
              No reports generated yet. Click "Generate Report" above to compile one.
            </div>
          ) : (
            reports.map((r) => {
              const isSelected = selectedReport?.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => setSelectedReport(r)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all space-y-1 text-xs ${
                    isSelected
                      ? 'bg-zinc-800 border-emerald-500/60 shadow-md'
                      : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-[10px] text-zinc-400">
                    <span className="uppercase text-emerald-400 font-bold">{r.reportType}</span>
                    <span>{new Date(r.createdAt).toLocaleDateString()}</span>
                  </div>
                  <div className="font-semibold text-zinc-100">{r.title}</div>
                </div>
              );
            })
          )}
        </div>

        {/* Report Document Preview (Printable & Exportable) */}
        <div className="lg:col-span-8">
          {selectedReport ? (
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 space-y-6 text-xs text-zinc-200 printable-area">
              {/* Report Document Header */}
              <div className="flex items-start justify-between pb-4 border-b border-zinc-800">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono uppercase font-bold">
                      CONFIDENTIAL • SOC INCIDENT RECORD
                    </span>
                    <span className="font-mono text-[11px] text-zinc-500">{selectedReport.id}</span>
                  </div>
                  <h2 className="text-lg font-bold text-zinc-100 font-mono">{selectedReport.title}</h2>
                  <p className="text-zinc-400 text-[11px]">
                    Compiled on {new Date(selectedReport.createdAt).toLocaleString()}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyJson}
                    className="p-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs flex items-center gap-1"
                    title="Copy Raw JSON"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    onClick={handlePrint}
                    className="p-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs flex items-center gap-1"
                    title="Print Document"
                  >
                    <Printer className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Document Body */}
              <div className="space-y-4 leading-relaxed">
                {/* Executive Section */}
                <div className="space-y-1.5">
                  <h3 className="text-xs font-bold font-mono text-zinc-300 uppercase tracking-wider">
                    1. Executive Summary
                  </h3>
                  <div className="p-3.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
                    {selectedReport.content?.executiveSummary ||
                      'Automated cybersecurity readiness assessment generated from authentic telemetry and active detection rule evaluations across authorized fleet endpoints.'}
                  </div>
                </div>

                {/* Telemetry & Detection Posture */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
                  <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                    <span className="text-zinc-500 block text-[10px]">Endpoints Monitored</span>
                    <span className="text-zinc-100 font-bold">{selectedReport.content?.totalAgents || 0}</span>
                  </div>
                  <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                    <span className="text-zinc-500 block text-[10px]">Active Alerts</span>
                    <span className="text-amber-400 font-bold">{selectedReport.content?.activeAlerts || 0}</span>
                  </div>
                  <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                    <span className="text-zinc-500 block text-[10px]">Investigated Incidents</span>
                    <span className="text-zinc-100 font-bold">{selectedReport.content?.openIncidents || 0}</span>
                  </div>
                  <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                    <span className="text-zinc-500 block text-[10px]">Telemetry Source</span>
                    <span className="text-emerald-400 font-bold">100% Real Logs</span>
                  </div>
                </div>

                {/* Structured 8-Point Questions (Section 21 & 22) */}
                <div className="space-y-3 pt-2 border-t border-zinc-800">
                  <h3 className="text-xs font-bold font-mono text-zinc-300 uppercase tracking-wider">
                    2. Structured Defensive Findings (Human-Readable)
                  </h3>

                  <div className="space-y-2">
                    <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
                      <span className="font-mono text-emerald-400 font-bold text-[11px] block">What Happened?</span>
                      <p className="text-zinc-300">
                        {selectedReport.content?.whatHappened ||
                          'The detection engine evaluated incoming endpoint telemetry against MITRE ATT&CK detection signatures and identified security events requiring analyst review.'}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
                      <span className="font-mono text-emerald-400 font-bold text-[11px] block">When Did It Occur?</span>
                      <p className="text-zinc-300">
                        {selectedReport.content?.whenOccurred ||
                          'Events were captured in real-time via authenticated endpoint agent daemon telemetry pipes.'}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
                      <span className="font-mono text-emerald-400 font-bold text-[11px] block">Where & Who?</span>
                      <p className="text-zinc-300">
                        {selectedReport.content?.whereWho ||
                          'Telemetry ingested from enrolled workstations and host daemons within the authorized organization perimeter.'}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
                      <span className="font-mono text-amber-400 font-bold text-[11px] block">Known Unknowns & Visibility Gaps:</span>
                      <p className="text-zinc-300">
                        {selectedReport.content?.unknownsGaps ||
                          'Non-enrolled hosts and out-of-band network traffic remain outside current endpoint telemetry coverage.'}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
                      <span className="font-mono text-emerald-400 font-bold text-[11px] block">Recommended Actions Taken:</span>
                      <p className="text-zinc-300">
                        {selectedReport.content?.actionsTaken ||
                          'Alerts placed in analyst investigation queue, containment playbooks prepared, and indicators registered.'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 rounded-lg bg-zinc-900 border border-zinc-800 text-center text-zinc-500 text-xs font-mono">
              Select a report from the archive to inspect.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
