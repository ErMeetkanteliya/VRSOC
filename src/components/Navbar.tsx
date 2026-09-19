import React, { useState } from 'react';
import { Shield, ShieldAlert, Key, Search, User, LogOut, Radio, Terminal, Cpu, RefreshCw, Copy, Check } from 'lucide-react';
import { Profile, Organization } from '../types';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  user: Profile | null;
  organization: Organization | null;
  environment: 'production' | 'training';
  onChangeEnvironment: (env: 'production' | 'training') => void;
  onOpenCommandPalette: () => void;
  onOpenAddAgent: () => void;
  onLogout: () => void;
  sseConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  user,
  organization,
  environment,
  onChangeEnvironment,
  onOpenCommandPalette,
  onOpenAddAgent,
  onLogout,
  sseConnected
}) => {
  const [copiedKey, setCopiedKey] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const handleCopyKey = () => {
    if (organization?.vrSocKey) {
      navigator.clipboard.writeText(organization.vrSocKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'agents', label: 'Endpoints & Agents' },
    { id: 'alerts', label: 'Alert Queue' },
    { id: 'incidents', label: 'Incidents & Cases' },
    { id: 'phishguard', label: 'PhishGuard ML' },
    { id: 'rules', label: 'Detection Rules' },
    { id: 'ai_assistant', label: 'AI Copilot' },
    { id: 'reports', label: 'Reports' },
    { id: 'audit_logs', label: 'Audit Logs' },
    { id: 'settings', label: 'Settings' }
  ];

  return (
    <header className="bg-zinc-950 border-b border-zinc-800 sticky top-0 z-40 text-zinc-100">
      {/* Top Banner for Environment Separation */}
      {environment === 'training' && (
        <div className="bg-amber-500/10 border-b border-amber-500/30 text-amber-300 px-4 py-1 text-xs flex items-center justify-between font-mono">
          <div className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span>TRAINING LAB ENVIRONMENT — Telemetry and events are isolated from production analytics.</span>
          </div>
          <button
            onClick={() => onChangeEnvironment('production')}
            className="hover:underline text-amber-200 font-semibold"
          >
            Switch to Production →
          </button>
        </div>
      )}

      {/* Main Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center justify-between h-14">
        {/* Brand & Organization */}
        <div className="flex items-center gap-4">
          <div
            onClick={() => onSelectTab('dashboard')}
            className="flex items-center gap-2.5 cursor-pointer select-none"
          >
            <div className="w-8 h-8 rounded bg-gradient-to-br from-emerald-600 to-teal-800 flex items-center justify-center border border-emerald-500/40 shadow-sm">
              <Shield className="w-4 h-4 text-emerald-100" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-wider font-mono text-zinc-100">VRSOC</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700">
                  DEFENSE
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 font-mono hidden sm:block">Learn • Detect • Investigate • Defend</p>
            </div>
          </div>

          {/* Org & 14-char Key */}
          {organization && (
            <div className="hidden lg:flex items-center gap-2 border-l border-zinc-800 pl-4">
              <span className="text-xs text-zinc-400 font-medium">{organization.name}</span>
              <button
                onClick={handleCopyKey}
                title="VRSOC 14-character security provisioning key"
                className="flex items-center gap-1.5 px-2 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 text-xs font-mono hover:bg-zinc-800 transition-colors"
              >
                <Key className="w-3 h-3 text-amber-400" />
                <span className="tracking-widest font-bold">{organization.vrSocKey}</span>
                {copiedKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-zinc-500" />}
              </button>
            </div>
          )}
        </div>

        {/* Action Controls & Utilities */}
        <div className="flex items-center gap-3">
          {/* Quick Command Palette Button */}
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-zinc-900 border border-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Quick Search...</span>
            <kbd className="hidden md:inline-block px-1.5 py-0.5 text-[10px] font-mono bg-zinc-800 text-zinc-400 rounded border border-zinc-700">
              Ctrl+K
            </kbd>
          </button>

          {/* Add Agent Trigger */}
          <button
            onClick={onOpenAddAgent}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-emerald-50 text-xs font-medium transition-colors shadow-sm"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Connect Agent</span>
          </button>

          {/* Realtime SSE indicator */}
          <div
            title={sseConnected ? 'Real-time telemetry stream active' : 'Connecting to real-time event pipeline...'}
            className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono"
          >
            <span className={`w-2 h-2 rounded-full ${sseConnected ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-500'}`} />
            <span className={sseConnected ? 'text-emerald-400' : 'text-zinc-500'}>
              {sseConnected ? 'LIVE' : 'SYNC'}
            </span>
          </div>

          {/* Environment Mode Toggle */}
          <div className="hidden md:flex rounded bg-zinc-900 p-0.5 border border-zinc-800 text-xs font-mono">
            <button
              onClick={() => onChangeEnvironment('production')}
              className={`px-2 py-0.5 rounded transition-colors ${
                environment === 'production'
                  ? 'bg-zinc-800 text-zinc-100 font-semibold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              PROD
            </button>
            <button
              onClick={() => onChangeEnvironment('training')}
              className={`px-2 py-0.5 rounded transition-colors ${
                environment === 'training'
                  ? 'bg-amber-500/20 text-amber-300 font-semibold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              LAB
            </button>
          </div>

          {/* User Profile / Menu */}
          {user && (
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 pl-2 border-l border-zinc-800 text-xs text-zinc-300 hover:text-zinc-100"
              >
                <div className="w-7 h-7 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-200 font-medium">
                  {user.fullName.charAt(0).toUpperCase()}
                </div>
                <div className="hidden lg:block text-left">
                  <div className="font-medium text-xs leading-none">{user.fullName}</div>
                  <div className="text-[10px] text-emerald-400 font-mono leading-tight mt-0.5">{user.role}</div>
                </div>
              </button>

              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-56 bg-zinc-900 border border-zinc-800 rounded-md shadow-xl py-1 text-xs text-zinc-300 z-50">
                  <div className="px-3 py-2 border-b border-zinc-800">
                    <p className="font-semibold text-zinc-100">{user.fullName}</p>
                    <p className="text-zinc-400 text-[11px] truncate">{user.email}</p>
                    <div className="mt-1 flex items-center gap-1 text-[10px] text-zinc-400 font-mono">
                      <span>MFA:</span>
                      <span className={user.mfaEnabled ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                        {user.mfaEnabled ? 'ENABLED' : 'UNENROLLED'}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => { onSelectTab('settings'); setShowUserMenu(false); }}
                    className="w-full text-left px-3 py-2 hover:bg-zinc-800 flex items-center gap-2"
                  >
                    <Key className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Security & VRSOC Key</span>
                  </button>
                  <button
                    onClick={() => { onLogout(); setShowUserMenu(false); }}
                    className="w-full text-left px-3 py-2 hover:bg-zinc-800 text-rose-400 flex items-center gap-2"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Horizontal Navigation Menu */}
      <nav className="border-t border-zinc-800/80 bg-zinc-950/90 overflow-x-auto scrollbar-none">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center gap-1 py-1">
          {navItems.map((item) => {
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`px-3 py-1.5 text-xs font-medium whitespace-nowrap rounded transition-colors ${
                  isActive
                    ? 'bg-zinc-800 text-emerald-400 border border-zinc-700/80 shadow-xs'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </nav>
    </header>
  );
};
