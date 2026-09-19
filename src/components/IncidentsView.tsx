import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, Check, Plus, Clock, User, CheckSquare, FileText, X, AlertCircle } from 'lucide-react';
import { Incident, Alert } from '../types';
import { api } from '../api';

interface IncidentsViewProps {
  incidents: Incident[];
  alerts: Alert[];
  onIncidentUpdated: (incident: Incident) => void;
  onNavigateReports: () => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  alerts,
  onIncidentUpdated,
  onNavigateReports
}) => {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);

  // New incident form
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('high');
  const [priority, setPriority] = useState('P2');
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);

  // Task & timeline additions
  const [newTaskTitle, setNewTaskTitle] = useState('');
  const [newTimelineTitle, setNewTimelineTitle] = useState('');
  const [newTimelineDesc, setNewTimelineDesc] = useState('');
  const [newTimelineState, setNewTimelineState] = useState<'CONFIRMED' | 'INFERRED' | 'UNKNOWN'>('CONFIRMED');
  const [newNote, setNewNote] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.createIncident({
        title,
        description,
        severity,
        priority,
        linkedAlertIds: selectedAlertIds
      });
      onIncidentUpdated(res.incident);
      setSelectedIncident(res.incident);
      setShowCreateModal(false);
      setTitle('');
      setDescription('');
      setSelectedAlertIds([]);
    } catch (err: any) {
      setError(err.message || 'Failed to create incident');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (newStatus: Incident['status']) => {
    if (!selectedIncident) return;
    try {
      const res = await api.updateIncident(selectedIncident.id, { status: newStatus });
      setSelectedIncident(res.incident);
      onIncidentUpdated(res.incident);
    } catch (err: any) {
      setError(err.message || 'Failed to update status');
    }
  };

  const handleAddTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newTaskTitle.trim()) return;
    try {
      const res = await api.addIncidentTask(selectedIncident.id, newTaskTitle.trim());
      setSelectedIncident(res.incident);
      onIncidentUpdated(res.incident);
      setNewTaskTitle('');
    } catch (err: any) {
      setError(err.message || 'Failed to add task');
    }
  };

  const handleToggleTask = async (taskId: string, completed: boolean) => {
    if (!selectedIncident) return;
    try {
      const res = await api.toggleIncidentTask(selectedIncident.id, taskId, completed);
      setSelectedIncident(res.incident);
      onIncidentUpdated(res.incident);
    } catch (err: any) {
      setError(err.message || 'Failed to update task');
    }
  };

  const handleAddTimeline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newTimelineTitle.trim()) return;
    try {
      const res = await api.addIncidentTimeline(selectedIncident.id, {
        title: newTimelineTitle.trim(),
        description: newTimelineDesc.trim(),
        evidenceState: newTimelineState
      });
      setSelectedIncident(res.incident);
      onIncidentUpdated(res.incident);
      setNewTimelineTitle('');
      setNewTimelineDesc('');
    } catch (err: any) {
      setError(err.message || 'Failed to add timeline item');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newNote.trim()) return;
    try {
      const res = await api.addIncidentNote(selectedIncident.id, newNote.trim());
      setSelectedIncident(res.incident);
      onIncidentUpdated(res.incident);
      setNewNote('');
    } catch (err: any) {
      setError(err.message || 'Failed to add note');
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>INCIDENT MANAGEMENT & CASES</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
              {incidents.length} Cases
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Structured defensive investigations, timeline reconstruction, and response tracking
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium transition-colors shadow-xs"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Incident Case</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid: Incident List + Case Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Cases List */}
        <div className={selectedIncident ? 'lg:col-span-5 space-y-2.5' : 'lg:col-span-12 space-y-2.5'}>
          {incidents.length === 0 ? (
            <div className="p-12 rounded-lg bg-zinc-900 border border-zinc-800 text-center space-y-3">
              <AlertTriangle className="w-8 h-8 text-zinc-600 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-semibold font-mono text-zinc-200">No active incidents.</p>
                <p className="text-xs text-zinc-500 max-w-sm mx-auto">
                  When a confirmed security event requires coordinated remediation, escalate it into an incident case.
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="mt-2 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs transition-colors inline-flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Incident Case</span>
              </button>
            </div>
          ) : (
            incidents.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all space-y-2.5 ${
                    isSelected
                      ? 'bg-zinc-800/90 border-emerald-500/60 shadow-md'
                      : 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] bg-zinc-950 border border-zinc-700 text-amber-400">
                        {inc.priority}
                      </span>
                      <span className="font-mono text-zinc-400 text-[11px] font-bold">{inc.id}</span>
                      <span className="text-zinc-500 text-[10px] uppercase font-mono">[{inc.status}]</span>
                    </div>
                    <span className="font-mono text-[10px] text-zinc-500">
                      {new Date(inc.createdAt).toLocaleDateString()}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-zinc-100">{inc.title}</div>
                  <p className="text-[11px] text-zinc-400 line-clamp-2">{inc.description}</p>

                  <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 pt-1 border-t border-zinc-800/80">
                    <span>Linked Alerts: {inc.linkedAlertIds.length}</span>
                    <span>Tasks: {inc.tasks.filter(t => t.completed).length}/{inc.tasks.length}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Case Workspace */}
        {selectedIncident && (
          <div className="lg:col-span-7 bg-zinc-900 border border-zinc-800 rounded-lg p-5 space-y-5 text-xs text-zinc-200">
            {/* Case Header */}
            <div className="flex items-start justify-between pb-3 border-b border-zinc-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono font-bold text-sm text-emerald-400">{selectedIncident.id}</span>
                  <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 font-mono text-[10px] font-bold">
                    {selectedIncident.priority}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 font-mono text-[10px] uppercase">
                    {selectedIncident.severity}
                  </span>
                </div>
                <h2 className="text-base font-bold text-zinc-100">{selectedIncident.title}</h2>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-zinc-500 hover:text-zinc-300 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Status Changer & Report Generator */}
            <div className="flex items-center justify-between p-3 bg-zinc-950 rounded border border-zinc-800">
              <div className="flex items-center gap-2">
                <span className="text-zinc-400 text-[11px]">Case Status:</span>
                <select
                  value={selectedIncident.status}
                  onChange={(e) => handleStatusChange(e.target.value as any)}
                  className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs focus:outline-none"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <button
                onClick={onNavigateReports}
                className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs flex items-center gap-1.5 transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export Report</span>
              </button>
            </div>

            {/* Description */}
            <div className="space-y-1">
              <span className="font-mono text-zinc-400 font-bold uppercase text-[10px]">Case Summary:</span>
              <p className="p-3 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 leading-relaxed">
                {selectedIncident.description}
              </p>
            </div>

            {/* Task Checklist */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-zinc-300 font-bold uppercase text-xs flex items-center gap-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Response Action Checklist</span>
                </span>
                <span className="text-[10px] font-mono text-zinc-500">
                  {selectedIncident.tasks.filter(t => t.completed).length} of {selectedIncident.tasks.length} done
                </span>
              </div>

              <div className="space-y-1.5">
                {selectedIncident.tasks.map((task) => (
                  <div
                    key={task.id}
                    onClick={() => handleToggleTask(task.id, !task.completed)}
                    className="p-2.5 rounded bg-zinc-950 border border-zinc-800/80 hover:border-zinc-700 flex items-center gap-2.5 cursor-pointer transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={task.completed}
                      onChange={() => {}}
                      className="rounded border-zinc-700 text-emerald-600 focus:ring-emerald-500 bg-zinc-900"
                    />
                    <span className={`text-xs ${task.completed ? 'line-through text-zinc-500' : 'text-zinc-200'}`}>
                      {task.title}
                    </span>
                  </div>
                ))}
              </div>

              <form onSubmit={handleAddTask} className="flex gap-2 pt-1">
                <input
                  type="text"
                  placeholder="Add remediation task..."
                  value={newTaskTitle}
                  onChange={(e) => setNewTaskTitle(e.target.value)}
                  className="flex-1 px-3 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!newTaskTitle.trim()}
                  className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-white text-xs font-medium disabled:opacity-50"
                >
                  Add Task
                </button>
              </form>
            </div>

            {/* Investigation Timeline */}
            <div className="space-y-2.5 pt-2 border-t border-zinc-800">
              <span className="font-mono text-zinc-300 font-bold uppercase text-xs flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-zinc-400" />
                <span>Incident Timeline (Reconstruction)</span>
              </span>

              <div className="space-y-2">
                {selectedIncident.timeline.map((item) => (
                  <div key={item.id} className="p-2.5 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-zinc-200">{item.title}</span>
                      <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-[10px] text-zinc-400">
                        {item.evidenceState}
                      </span>
                    </div>
                    {item.description && <p className="text-zinc-400">{item.description}</p>}
                    <div className="text-[10px] text-zinc-500">{new Date(item.timestamp).toLocaleString()}</div>
                  </div>
                ))}
              </div>

              <form onSubmit={handleAddTimeline} className="space-y-2 p-3 bg-zinc-950 rounded border border-zinc-800">
                <input
                  type="text"
                  placeholder="Event title (e.g. Memory dump acquired)..."
                  value={newTimelineTitle}
                  onChange={(e) => setNewTimelineTitle(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                />
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Details or evidence source..."
                    value={newTimelineDesc}
                    onChange={(e) => setNewTimelineDesc(e.target.value)}
                    className="flex-1 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                  />
                  <select
                    value={newTimelineState}
                    onChange={(e) => setNewTimelineState(e.target.value as any)}
                    className="px-2 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-xs focus:outline-none"
                  >
                    <option value="CONFIRMED">CONFIRMED</option>
                    <option value="INFERRED">INFERRED</option>
                    <option value="UNKNOWN">UNKNOWN</option>
                  </select>
                  <button
                    type="submit"
                    disabled={!newTimelineTitle.trim()}
                    className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium disabled:opacity-50"
                  >
                    Add Entry
                  </button>
                </div>
              </form>
            </div>

            {/* Notes */}
            <div className="space-y-2 pt-2 border-t border-zinc-800">
              <span className="font-mono text-zinc-300 font-bold uppercase text-xs">Analyst Journal & Notes:</span>
              <div className="space-y-1.5">
                {selectedIncident.notes.map((n) => (
                  <div key={n.id} className="p-2.5 rounded bg-zinc-950 border border-zinc-800 text-[11px]">
                    <div className="flex items-center justify-between text-zinc-400 font-mono text-[10px] mb-1">
                      <span className="font-semibold text-zinc-200">{n.userName}</span>
                      <span>{new Date(n.createdAt).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-zinc-300">{n.note}</p>
                  </div>
                ))}
              </div>

              <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  placeholder="Record investigation findings or hypotheses..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  className="flex-1 px-3 py-1.5 rounded bg-zinc-950 border border-zinc-700 text-zinc-100 text-xs focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!newNote.trim()}
                  className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-white text-xs font-medium disabled:opacity-50"
                >
                  Save Note
                </button>
              </form>
            </div>
          </div>
        )}
      </div>

      {/* Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-zinc-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg max-w-lg w-full shadow-2xl p-6 text-zinc-100 text-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <h2 className="text-sm font-bold font-mono text-zinc-100">DECLARE SECURITY INCIDENT</h2>
              <button onClick={() => setShowCreateModal(false)} className="text-zinc-500 hover:text-zinc-300">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-3.5">
              <div>
                <label className="block text-zinc-400 mb-1 font-medium">Incident Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Unauthorized PowerShell Execution & Beaconing"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 text-xs focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">SLA Priority</label>
                  <select
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 text-xs focus:outline-none"
                  >
                    <option value="P1">P1 (Immediate 15m Response)</option>
                    <option value="P2">P2 (High Priority 1h)</option>
                    <option value="P3">P3 (Medium 4h)</option>
                    <option value="P4">P4 (Routine 24h)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-medium">Executive Description</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Describe initial detection vectors, affected hosts, and immediate response posture..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>

              {alerts.length > 0 && (
                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Link Triggering Alerts</label>
                  <div className="max-h-32 overflow-y-auto space-y-1 p-2 bg-zinc-950 rounded border border-zinc-800">
                    {alerts.map((al) => (
                      <label key={al.id} className="flex items-center gap-2 text-[11px] text-zinc-300 font-mono">
                        <input
                          type="checkbox"
                          checked={selectedAlertIds.includes(al.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedAlertIds([...selectedAlertIds, al.id]);
                            } else {
                              setSelectedAlertIds(selectedAlertIds.filter(id => id !== al.id));
                            }
                          }}
                          className="rounded border-zinc-700 text-emerald-600 focus:ring-emerald-500 bg-zinc-900"
                        />
                        <span className="font-bold text-amber-400">{al.id}</span>
                        <span className="truncate">{al.title}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium disabled:opacity-50"
                >
                  {loading ? 'Creating...' : 'Initialize Incident Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
