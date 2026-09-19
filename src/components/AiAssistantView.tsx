import React, { useState } from 'react';
import { Brain, Send, User, Sparkles, RefreshCw, AlertCircle, ShieldAlert } from 'lucide-react';
import { api } from '../api';

interface AiAssistantViewProps {
  activeAlertId?: string;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export const AiAssistantView: React.FC<AiAssistantViewProps> = ({ activeAlertId }) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "Hello Analyst. I am the VRSOC Grounded Security Copilot. I analyze authentic endpoint telemetry and detection rules across your workspace.\n\nAll my assessments strictly distinguish between **CONFIRMED** evidence, **INFERRED** hypotheses, and **UNKNOWN** gaps. How can I assist your investigation?",
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const promptChips = [
    "What alerts and detections are currently active in our workspace?",
    "Explain the evidence states: CONFIRMED vs INFERRED vs UNKNOWN",
    "How does PhishGuard ML score URL lexical features?",
    "What are standard host containment playbooks for suspicious PowerShell?"
  ];

  const handleSend = async (text = input) => {
    if (!text.trim() || loading) return;
    const userMsg: Message = {
      role: 'user',
      content: text.trim(),
      timestamp: new Date().toLocaleTimeString()
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);
    setError(null);

    try {
      const res = await api.chatAi(text.trim(), { alertId: activeAlertId });
      const assistantMsg: Message = {
        role: 'assistant',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString()
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      setError(err.message || 'AI Copilot response failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
            <span>GROUNDED SOC COPILOT</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-purple-950/60 text-purple-300 border border-purple-500/30 font-normal">
              GEMINI 3.8 FLASH
            </span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Strictly grounded in authentic workspace telemetry — zero hallucinated incidents
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Chat Area */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg flex flex-col h-[600px] overflow-hidden">
        {/* Messages Container */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4 text-xs">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.role === 'assistant' && (
                <div className="w-7 h-7 rounded bg-purple-950 border border-purple-500/40 flex items-center justify-center text-purple-300 shrink-0">
                  <Brain className="w-4 h-4" />
                </div>
              )}

              <div
                className={`p-3.5 rounded-lg max-w-2xl leading-relaxed space-y-1.5 ${
                  m.role === 'user'
                    ? 'bg-emerald-700 text-white'
                    : 'bg-zinc-950 border border-zinc-800 text-zinc-200'
                }`}
              >
                <div className="flex items-center justify-between gap-4 text-[10px] opacity-70 font-mono">
                  <span>{m.role === 'user' ? 'Analyst' : 'VRSOC Grounded AI'}</span>
                  <span>{m.timestamp}</span>
                </div>
                <div className="whitespace-pre-wrap font-sans">{m.content}</div>
              </div>

              {m.role === 'user' && (
                <div className="w-7 h-7 rounded bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-300 shrink-0">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded bg-purple-950 border border-purple-500/40 flex items-center justify-center text-purple-300">
                <RefreshCw className="w-4 h-4 animate-spin" />
              </div>
              <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-zinc-400 text-xs font-mono">
                Querying authentic workspace telemetry & synthesizing defense analysis...
              </div>
            </div>
          )}
        </div>

        {/* Prompt Chips */}
        <div className="px-5 py-2 border-t border-zinc-800 bg-zinc-950/60 flex items-center gap-2 overflow-x-auto scrollbar-none text-[11px]">
          <span className="text-zinc-500 font-mono text-[10px] shrink-0">Suggestions:</span>
          {promptChips.map((chip, i) => (
            <button
              key={i}
              onClick={() => handleSend(chip)}
              className="px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 whitespace-nowrap transition-colors"
            >
              {chip}
            </button>
          ))}
        </div>

        {/* Chat Input */}
        <div className="p-4 border-t border-zinc-800 bg-zinc-950">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              placeholder="Ask about workspace alerts, telemetry evidence, containment steps..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="flex-1 px-4 py-2 rounded bg-zinc-900 border border-zinc-700 text-zinc-100 text-xs focus:outline-none focus:border-purple-500 font-sans"
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="px-4 py-2 rounded bg-purple-700 hover:bg-purple-600 text-white font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
