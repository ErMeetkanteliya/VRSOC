import React, { useState } from 'react';
import { ShieldCheck, Plus, Check, X, Sliders, AlertCircle, ExternalLink, Code } from 'lucide-react';
import { DetectionRule } from '../types';
import { api } from '../api';

interface DetectionRulesViewProps {
  rules: DetectionRule[];
  onRuleToggled: (ruleId: string, enabled: boolean) => void;
  onRuleCreated: (rule: DetectionRule) => void;
}

export const DetectionRulesView: React.FC<DetectionRulesViewProps> = ({
  rules,
  onRuleToggled,
  onRuleCreated
}) => {
  const [activeTab, setActiveTab] = useState<'rules' | 'mitre_matrix' | 'create'>('rules');
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);

  // Create form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<'informational' | 'low' | 'medium' | 'high' | 'critical'>('medium');
  const [riskScore, setRiskScore] = useState(60);
  const [category, setCategory] = useState('Process Execution');
  const [mitreTactic, setMitreTactic] = useState('Execution');
  const [mitreTechniqueId, setMitreTechniqueId] = useState('T1059');
  const [mitreTechniqueName, setMitreTechniqueName] = useState('Command and Scripting Interpreter');
  const [conditionJson, setConditionJson] = useState('{\n  "eventType": "process",\n  "conditions": {\n    "processName": "whoami.exe"\n  }\n}');
  const [remediationText, setRemediationText] = useState('Isolate endpoint\nInspect parent process\nCheck for privilege escalation');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleToggle = async (rule: DetectionRule) => {
    try {
      const res = await api.toggleRule(rule.id, !rule.enabled);
      onRuleToggled(rule.id, res.enabled);
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule');
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      let parsedConditions = {};
      try {
        parsedConditions = JSON.parse(conditionJson);
      } catch {
        throw new Error('Invalid JSON in condition definition');
      }

      const remediationSteps = remediationText.split('\n').map(s => s.trim()).filter(Boolean);

      const res = await api.createRule({
        name,
        description,
        severity,
        riskScore: Number(riskScore),
        category,
        mitreTactic,
        mitreTechniqueId,
        mitreTechniqueName,
        conditions: parsedConditions,
        remediationSteps,
        enabled: true
      });

      onRuleCreated(res.rule);
      setName('');
      setDescription('');
      setActiveTab('rules');
    } catch (err: any) {
      setError(err.message || 'Failed to create detection rule');
    } finally {
      setLoading(false);
    }
  };

  // MITRE Tactics Matrix Mapping
  const tactics = [
    { name: 'Initial Access', id: 'TA0001' },
    { name: 'Execution', id: 'TA0002' },
    { name: 'Persistence', id: 'TA0003' },
    { name: 'Privilege Escalation', id: 'TA0004' },
    { name: 'Defense Evasion', id: 'TA0005' },
    { name: 'Credential Access', id: 'TA0006' },
    { name: 'Discovery', id: 'TA0007' },
    { name: 'Command & Control', id: 'TA0011' }
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>DETECTION RULES REPOSITORY</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              {rules.length} Signatures
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Real-time event evaluation engine mapped directly to MITRE ATT&CK Framework
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-zinc-800 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-2.5 px-4 border-b-2 transition-colors ${
            activeTab === 'rules'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Rules Library ({rules.length})
        </button>
        <button
          onClick={() => setActiveTab('mitre_matrix')}
          className={`pb-2.5 px-4 border-b-2 transition-colors ${
            activeTab === 'mitre_matrix'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          MITRE ATT&CK Matrix
        </button>
        <button
          onClick={() => setActiveTab('create')}
          className={`pb-2.5 px-4 border-b-2 transition-colors ${
            activeTab === 'create'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          + Custom Rule Builder
        </button>
      </div>

      {/* TAB 1: RULES LIBRARY */}
      {activeTab === 'rules' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className={selectedRule ? 'lg:col-span-6 space-y-3' : 'lg:col-span-12 space-y-3'}>
            <div className="space-y-2.5">
              {rules.map((rule) => {
                const isSelected = selectedRule?.id === rule.id;
                return (
                  <div
                    key={rule.id}
                    onClick={() => setSelectedRule(rule)}
                    className={`p-4 rounded-lg border cursor-pointer transition-all space-y-2.5 ${
                      isSelected
                        ? 'bg-zinc-800/90 border-emerald-500/60 shadow-md'
                        : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-emerald-400 text-[11px]">{rule.id}</span>
                        <span className="px-2 py-0.2 rounded bg-zinc-950 border border-zinc-700 font-mono text-[10px] uppercase">
                          {rule.severity}
                        </span>
                        <span className="text-zinc-400 font-mono text-[10px]">
                          Risk: {rule.riskScore}/100
                        </span>
                      </div>

                      {/* Enable/Disable Toggle */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleToggle(rule);
                        }}
                        className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase transition-colors ${
                          rule.enabled
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                            : 'bg-zinc-800 text-zinc-500 border border-zinc-700'
                        }`}
                      >
                        {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                      </button>
                    </div>

                    <div className="text-xs font-semibold text-zinc-100">{rule.name}</div>
                    <p className="text-[11px] text-zinc-400 line-clamp-2">{rule.description}</p>

                    <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500 pt-1 border-t border-zinc-800">
                      <span>MITRE: {rule.mitreTechniqueId} ({rule.mitreTechniqueName})</span>
                      <span>Tactic: {rule.mitreTactic}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Rule Inspector */}
          {selectedRule && (
            <div className="lg:col-span-6 bg-zinc-900 border border-zinc-800 rounded-lg p-5 space-y-4 text-xs text-zinc-200">
              <div className="flex items-start justify-between pb-3 border-b border-zinc-800">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono font-bold text-sm text-emerald-400">{selectedRule.id}</span>
                    <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono text-[10px] uppercase">
                      {selectedRule.severity}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-zinc-100">{selectedRule.name}</h2>
                </div>
                <button onClick={() => setSelectedRule(null)} className="text-zinc-500 hover:text-zinc-300">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-1">
                <span className="font-mono text-zinc-400 font-bold uppercase text-[10px]">Description:</span>
                <p className="p-3 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 leading-relaxed">
                  {selectedRule.description}
                </p>
              </div>

              <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1 font-mono text-[11px]">
                <span className="text-zinc-400 font-bold block text-[10px] uppercase">MITRE ATT&CK Mapping:</span>
                <div className="text-emerald-400">{selectedRule.mitreTechniqueId} - {selectedRule.mitreTechniqueName}</div>
                <div className="text-zinc-500 text-[10px]">Tactic: {selectedRule.mitreTactic}</div>
              </div>

              <div className="space-y-1">
                <span className="font-mono text-zinc-400 font-bold uppercase text-[10px]">Evaluation Logic (AST Conditions):</span>
                <pre className="p-3 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto">
                  {JSON.stringify(selectedRule.conditions, null, 2)}
                </pre>
              </div>

              <div className="space-y-1">
                <span className="font-mono text-zinc-400 font-bold uppercase text-[10px]">Recommended Remediation Playbook:</span>
                <ul className="list-disc list-inside p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1 text-zinc-300">
                  {selectedRule.remediationSteps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: MITRE ATT&CK MATRIX */}
      {activeTab === 'mitre_matrix' && (
        <div className="space-y-4">
          <div className="p-3 rounded bg-zinc-900 border border-zinc-800 text-xs text-zinc-300 font-mono">
            MITRE Enterprise ATT&CK matrix visualization showing active detection coverage against adversary tactics.
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {tactics.map((tactic) => {
              const matchedRules = rules.filter(r => r.mitreTactic.toLowerCase() === tactic.name.toLowerCase());
              return (
                <div key={tactic.id} className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 space-y-2">
                  <div className="border-b border-zinc-800 pb-1.5">
                    <span className="text-[10px] font-mono text-zinc-500 block">{tactic.id}</span>
                    <span className="text-xs font-bold text-zinc-200 font-mono">{tactic.name}</span>
                  </div>

                  {matchedRules.length === 0 ? (
                    <div className="text-[10px] text-zinc-600 font-mono py-2 text-center">
                      No signatures
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {matchedRules.map((r) => (
                        <div key={r.id} className="p-2 rounded bg-zinc-950 border border-zinc-800 text-[10px] font-mono space-y-0.5">
                          <span className="text-emerald-400 font-bold block">{r.mitreTechniqueId}</span>
                          <span className="text-zinc-300 block truncate">{r.name}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: CUSTOM RULE BUILDER */}
      {activeTab === 'create' && (
        <div className="p-6 rounded-lg bg-zinc-900 border border-zinc-800 max-w-2xl text-xs space-y-4">
          <h2 className="text-sm font-bold font-mono text-zinc-100">CREATE CUSTOM DETECTION RULE</h2>

          <form onSubmit={handleCreateRule} className="space-y-3.5">
            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Rule Name</label>
              <input
                type="text"
                required
                placeholder="e.g. Suspicious Recon Command (whoami / priv)"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Description</label>
              <textarea
                rows={2}
                required
                placeholder="Explain the security significance and detection trigger..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-zinc-400 mb-1 font-medium">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as any)}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-zinc-400 mb-1 font-medium">Risk Score (0-100)</label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={riskScore}
                  onChange={(e) => setRiskScore(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-zinc-400 mb-1 font-medium">MITRE Tactic</label>
                <input
                  type="text"
                  value={mitreTactic}
                  onChange={(e) => setMitreTactic(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none font-mono"
                />
              </div>
              <div>
                <label className="block text-zinc-400 mb-1 font-medium">Technique ID (e.g. T1059.001)</label>
                <input
                  type="text"
                  value={mitreTechniqueId}
                  onChange={(e) => setMitreTechniqueId(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Condition Matching Logic (JSON)</label>
              <textarea
                rows={4}
                value={conditionJson}
                onChange={(e) => setConditionJson(e.target.value)}
                className="w-full p-3 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none font-mono"
              />
            </div>

            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Remediation Steps (1 per line)</label>
              <textarea
                rows={3}
                value={remediationText}
                onChange={(e) => setRemediationText(e.target.value)}
                className="w-full p-3 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs disabled:opacity-50"
            >
              {loading ? 'Compiling Signature...' : 'Deploy Detection Rule'}
            </button>
          </form>
        </div>
      )}
    </div>
  );
};
