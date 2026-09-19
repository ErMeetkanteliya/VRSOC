import React, { useState } from 'react';
import { Globe, Shield, ShieldAlert, AlertTriangle, Check, ArrowRight, Activity, Search, RefreshCw, ExternalLink } from 'lucide-react';
import { PhishingScan, Alert } from '../types';
import { api } from '../api';

interface PhishGuardViewProps {
  onAlertCreated?: (alert: Alert) => void;
  onNavigateAlerts?: () => void;
}

export const PhishGuardView: React.FC<PhishGuardViewProps> = ({
  onAlertCreated,
  onNavigateAlerts
}) => {
  const [urlInput, setUrlInput] = useState<string>('http://paypal-security-verification.xyz/login.php');
  const [scanning, setScanning] = useState<boolean>(false);
  const [currentScan, setCurrentScan] = useState<PhishingScan | null>(null);
  const [scanHistory, setScanHistory] = useState<PhishingScan[]>([]);
  const [promoting, setPromoting] = useState<boolean>(false);
  const [promotedSuccess, setPromotedSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sampleUrls = [
    { label: 'Phishing Impersonation', url: 'http://paypal-security-verification.xyz/login.php' },
    { label: 'Raw IP + Sensitive Token', url: 'http://192.168.1.100:8080/secure/auth?token=928374' },
    { label: 'Legitimate Domain', url: 'https://www.google.com/search?q=cybersecurity+defense' }
  ];

  const handleScan = async (targetUrl = urlInput) => {
    if (!targetUrl.trim()) return;
    setScanning(true);
    setError(null);
    setPromotedSuccess(null);
    try {
      const res = await api.scanUrl(targetUrl.trim());
      setCurrentScan(res.scan);
      setScanHistory((prev) => [res.scan, ...prev.filter(s => s.id !== res.scan.id)]);
    } catch (err: any) {
      setError(err.message || 'PhishGuard scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handlePromoteToAlert = async () => {
    if (!currentScan) return;
    setPromoting(true);
    setError(null);
    try {
      const res = await api.promotePhishingScanToAlert(currentScan.id);
      setPromotedSuccess(`Successfully promoted to active Alert: ${res.alert.id}`);
      if (onAlertCreated) onAlertCreated(res.alert);
      setCurrentScan({ ...currentScan, promotedToAlertId: res.alert.id });
    } catch (err: any) {
      setError(err.message || 'Failed to promote scan to alert');
    } finally {
      setPromoting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>PHISHGUARD ML URL CLASSIFIER</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              FEATURE EXTRACTION & RANDOM FOREST
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Static lexical analysis, domain heuristics, and machine learning risk classification
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* URL Input Form */}
      <div className="p-5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-3">
        <label className="block text-xs font-mono font-semibold text-zinc-300">
          Target URL to Inspect & Classify:
        </label>
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-zinc-500 absolute left-3 top-3" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleScan(); }}
              placeholder="https://example.com/login"
              className="w-full pl-9 pr-3 py-2.5 rounded bg-zinc-950 border border-zinc-700 font-mono text-xs text-zinc-100 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={scanning || !urlInput.trim()}
            className="px-5 py-2.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shrink-0"
          >
            {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>Analyze with PhishGuard ML</span>
          </button>
        </div>

        {/* Quick Sample URLs */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono text-zinc-400">
          <span className="text-zinc-500">Quick Samples:</span>
          {sampleUrls.map((s, idx) => (
            <button
              key={idx}
              onClick={() => {
                setUrlInput(s.url);
                handleScan(s.url);
              }}
              className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scan Result Card */}
      {currentScan && (
        <div className="p-5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-5">
          {/* Top Banner: Classification + Risk Meter */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className={`px-3 py-1 rounded font-mono text-xs font-bold uppercase tracking-wider border ${
                  currentScan.classification === 'Phishing'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : currentScan.classification === 'Suspicious'
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  CLASSIFICATION: {currentScan.classification}
                </span>
                <span className="font-mono text-xs text-zinc-400">ID: {currentScan.id}</span>
              </div>
              <p className="font-mono text-xs text-zinc-300 break-all">{currentScan.url}</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <span className="text-[10px] text-zinc-500 font-mono block">PHISHGUARD RISK SCORE</span>
                <span className={`text-2xl font-mono font-bold ${
                  currentScan.riskScore >= 65 ? 'text-rose-400' :
                  currentScan.riskScore >= 35 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {currentScan.riskScore}/100
                </span>
              </div>

              {/* Promote to SOC Alert Action */}
              {!currentScan.promotedToAlertId ? (
                <button
                  onClick={handlePromoteToAlert}
                  disabled={promoting}
                  className="px-3 py-2 rounded bg-amber-600/20 text-amber-300 border border-amber-500/40 hover:bg-amber-600/30 text-xs font-medium flex items-center gap-1.5 transition-colors"
                >
                  <ShieldAlert className="w-4 h-4" />
                  <span>{promoting ? 'Promoting...' : 'Promote to SOC Alert'}</span>
                </button>
              ) : (
                <div className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                  <Check className="w-4 h-4" />
                  <span>Promoted ({currentScan.promotedToAlertId})</span>
                </div>
              )}
            </div>
          </div>

          {promotedSuccess && (
            <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4" />
                <span>{promotedSuccess}</span>
              </div>
              {onNavigateAlerts && (
                <button
                  onClick={onNavigateAlerts}
                  className="text-xs text-emerald-200 underline hover:text-white"
                >
                  Go to Alert Queue →
                </button>
              )}
            </div>
          )}

          {/* Mandatory SOC Analyst Notice (Section 19) */}
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-400 flex items-center gap-2 font-mono">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              <strong>Analyst Guidance:</strong> PhishGuard ML classification is probabilistic based on static lexical features. Always correlate with endpoint telemetry and threat intelligence before automated blocking.
            </span>
          </div>

          {/* Detection Reasons */}
          <div className="space-y-2">
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-300">
              ML Feature Scoring Breakdown:
            </h3>
            {currentScan.reasons.length === 0 ? (
              <p className="text-xs text-emerald-400 font-mono">No high-risk indicators detected in lexical evaluation.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {currentScan.reasons.map((reason, i) => (
                  <div key={i} className="p-2.5 rounded bg-zinc-950 border border-zinc-800 text-xs font-mono flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span className="text-zinc-300">{reason}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Detailed Features Grid */}
          <div className="space-y-2 pt-2 border-t border-zinc-800">
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-400">
              Extracted Lexical Features:
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">URL Length</span>
                <span className="text-zinc-200">{currentScan.features.urlLength} characters</span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Subdomain Count</span>
                <span className="text-zinc-200">{currentScan.features.subdomainsCount} subdomains</span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Raw IP Host</span>
                <span className={currentScan.features.hasIpAddress ? 'text-rose-400 font-bold' : 'text-zinc-400'}>
                  {currentScan.features.hasIpAddress ? 'YES (Suspicious)' : 'NO'}
                </span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Known Shortener</span>
                <span className={currentScan.features.isShortener ? 'text-rose-400 font-bold' : 'text-zinc-400'}>
                  {currentScan.features.isShortener ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Prefix / Suffix Hyphens</span>
                <span className={currentScan.features.hasPrefixSuffix ? 'text-amber-400 font-bold' : 'text-zinc-400'}>
                  {currentScan.features.hasPrefixSuffix ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Suspicious TLD</span>
                <span className={currentScan.features.suspiciousTld ? 'text-rose-400 font-bold' : 'text-zinc-400'}>
                  {currentScan.features.suspiciousTld ? 'YES (.xyz, .top, etc)' : 'NO'}
                </span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">HTTPS Token in Domain</span>
                <span className={currentScan.features.httpsInDomain ? 'text-rose-400 font-bold' : 'text-zinc-400'}>
                  {currentScan.features.httpsInDomain ? 'YES (Deceptive)' : 'NO'}
                </span>
              </div>
              <div className="p-2 rounded bg-zinc-950 border border-zinc-800">
                <span className="text-zinc-500 block text-[10px]">Keywords Triggered</span>
                <span className="text-zinc-200 truncate">
                  {currentScan.features.sensitiveKeywordsFound.length > 0
                    ? currentScan.features.sensitiveKeywordsFound.join(', ')
                    : 'None'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* History Table */}
      {scanHistory.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-zinc-800">
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-300">
            Session Scan History
          </h3>
          <div className="bg-zinc-900 rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-zinc-950 text-zinc-400 border-b border-zinc-800">
                <tr>
                  <th className="p-3">Target URL</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 text-zinc-300">
                {scanHistory.map((scan) => (
                  <tr key={scan.id} className="hover:bg-zinc-800/40">
                    <td className="p-3 truncate max-w-xs">{scan.url}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        scan.classification === 'Phishing' ? 'text-rose-400 bg-rose-500/10' :
                        scan.classification === 'Suspicious' ? 'text-amber-400 bg-amber-500/10' :
                        'text-emerald-400 bg-emerald-500/10'
                      }`}>
                        {scan.classification}
                      </span>
                    </td>
                    <td className="p-3">{scan.riskScore}/100</td>
                    <td className="p-3">
                      {scan.promotedToAlertId ? (
                        <span className="text-emerald-400 text-[10px]">Alert Created</span>
                      ) : (
                        <span className="text-zinc-500 text-[10px]">Scanned</span>
                      )}
                    </td>
                    <td className="p-3 text-zinc-500 text-[10px]">
                      {new Date(scan.createdAt).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
