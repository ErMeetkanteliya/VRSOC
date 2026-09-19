import React, { useState } from 'react';
import { Key, Shield, RefreshCw, Copy, Check, AlertTriangle, Lock, User, Clock } from 'lucide-react';
import { Organization, Profile } from '../types';
import { api } from '../api';

interface SettingsViewProps {
  organization: Organization | null;
  profile: Profile | null;
  onOrganizationUpdated: (org: Organization) => void;
  onProfileUpdated: (prof: Profile) => void;
  environment: 'production' | 'training';
  onChangeEnvironment: (env: 'production' | 'training') => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  organization,
  profile,
  onOrganizationUpdated,
  onProfileUpdated,
  environment,
  onChangeEnvironment
}) => {
  const [copied, setCopied] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [rotateSuccess, setRotateSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // MFA Setup in Settings
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [verifyingMfa, setVerifyingMfa] = useState(false);

  const handleCopyKey = () => {
    if (organization?.vrSocKey) {
      navigator.clipboard.writeText(organization.vrSocKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRotateKey = async () => {
    if (!confirm('WARNING: Rotating your 14-character VRSOC Key will require updating the key on any new agents you wish to enroll. Existing enrolled agents will continue functioning. Do you wish to proceed?')) {
      return;
    }

    setRotating(true);
    setError(null);
    setRotateSuccess(null);
    try {
      const res = await api.rotateKey();
      if (organization) {
        const updatedOrg = { ...organization, vrSocKey: res.vrSocKey };
        onOrganizationUpdated(updatedOrg);
        setRotateSuccess(`Key successfully rotated. New 14-character key: ${res.vrSocKey}`);
      }
    } catch (err: any) {
      setError(err.message || 'Key rotation failed');
    } finally {
      setRotating(false);
    }
  };

  const handleStartMfa = async () => {
    try {
      const res = await api.getMfaSetup();
      setMfaSecret(res.mfaSecret);
      setShowMfaSetup(true);
    } catch (err: any) {
      setError(err.message || 'Failed to initialize MFA setup');
    }
  };

  const handleVerifyMfa = async () => {
    setVerifyingMfa(true);
    setError(null);
    try {
      const res = await api.verifyMfa(mfaToken);
      onProfileUpdated(res.profile);
      setShowMfaSetup(false);
      setMfaToken('');
    } catch (err: any) {
      setError(err.message || 'Invalid TOTP code format (6 digits required).');
    } finally {
      setVerifyingMfa(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div className="border-b border-zinc-800 pb-4">
        <h1 className="text-xl font-bold font-mono tracking-tight text-zinc-100 flex items-center gap-2">
          <span>ORGANIZATION SETTINGS & SECURITY</span>
          <span className="text-xs px-2 py-0.5 rounded font-mono uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 font-normal">
            ADMINISTRATIVE
          </span>
        </h1>
        <p className="text-xs text-zinc-400 mt-0.5">
          14-character VRSOC key management, multi-factor authentication, and telemetry retention
        </p>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {rotateSuccess && (
        <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <Check className="w-4 h-4 shrink-0" />
          <span>{rotateSuccess}</span>
        </div>
      )}

      {/* CARD 1: 14-CHARACTER VRSOC KEY */}
      <div className="p-5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-4 text-xs">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
          <div>
            <h2 className="text-sm font-bold font-mono text-zinc-100 uppercase tracking-wider flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              <span>VRSOC Security Provisioning Key</span>
            </h2>
            <p className="text-zinc-400 text-xs mt-0.5">
              Cryptographically secure 14-character hexadecimal key used to authorize endpoint agents
            </p>
          </div>
          <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 font-mono text-[10px] text-amber-400 font-bold">
            14-CHAR HEX
          </span>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 bg-zinc-950 rounded border border-zinc-800">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xl font-bold tracking-widest text-zinc-100 select-all">
              {organization?.vrSocKey || 'A7F29C81D40E5B'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyKey}
              className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Key'}</span>
            </button>

            <button
              onClick={handleRotateKey}
              disabled={rotating}
              className="px-3 py-1.5 rounded bg-amber-600/20 text-amber-300 border border-amber-500/30 hover:bg-amber-600/30 font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${rotating ? 'animate-spin' : ''}`} />
              <span>{rotating ? 'Rotating...' : 'Rotate Key'}</span>
            </button>
          </div>
        </div>

        <p className="text-zinc-400 text-[11px] leading-relaxed">
          Provide this key when running <code>vrsoc-agent.js --enroll &lt;KEY&gt;</code> on target endpoints. Rotating this key revokes pending enrollments but preserves already authorized endpoints.
        </p>
      </div>

      {/* CARD 2: MFA / SECURITY FACTOR */}
      <div className="p-5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-4 text-xs">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
          <div>
            <h2 className="text-sm font-bold font-mono text-zinc-100 uppercase tracking-wider flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>Multi-Factor Authentication (MFA / TOTP)</span>
            </h2>
            <p className="text-zinc-400 text-xs mt-0.5">
              RFC 6238 time-based one-time password protection for administrative actions
            </p>
          </div>

          <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
            profile?.mfaEnabled ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-zinc-800 text-zinc-400'
          }`}>
            {profile?.mfaEnabled ? 'ENROLLED & ACTIVE' : 'NOT ENROLLED'}
          </span>
        </div>

        {!profile?.mfaEnabled && !showMfaSetup && (
          <div className="flex items-center justify-between p-3 rounded bg-zinc-950 border border-zinc-800">
            <span className="text-zinc-300 text-xs">Protect your account with Google Authenticator or 1Password:</span>
            <button
              onClick={handleStartMfa}
              className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs"
            >
              Enable MFA
            </button>
          </div>
        )}

        {showMfaSetup && (
          <div className="p-4 rounded bg-zinc-950 border border-zinc-800 space-y-3">
            <span className="font-semibold text-zinc-200 block text-xs">Setup TOTP Authenticator:</span>
            <div className="p-2.5 rounded bg-zinc-900 border border-zinc-700 font-mono text-center tracking-widest text-amber-400 font-bold">
              {mfaSecret || 'JBSWY3DPEHPK3PXP'}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                maxLength={6}
                placeholder="Enter 6-digit code from app"
                value={mfaToken}
                onChange={(e) => setMfaToken(e.target.value)}
                className="flex-1 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-100 font-mono text-center text-xs focus:outline-none"
              />
              <button
                onClick={handleVerifyMfa}
                disabled={verifyingMfa || mfaToken.length !== 6}
                className="px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs disabled:opacity-50"
              >
                Confirm Token
              </button>
              <button
                onClick={() => setShowMfaSetup(false)}
                className="px-3 py-1.5 rounded bg-zinc-800 text-zinc-400 hover:text-white text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {profile?.mfaEnabled && (
          <div className="p-3 rounded bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 flex items-center gap-2">
            <Check className="w-4 h-4 shrink-0" />
            <span>Multi-factor authentication is configured and active for your user account.</span>
          </div>
        )}
      </div>

      {/* CARD 3: ORGANIZATION DETAILS & RETENTION */}
      <div className="p-5 rounded-lg bg-zinc-900 border border-zinc-800 space-y-4 text-xs">
        <h2 className="text-sm font-bold font-mono text-zinc-100 uppercase tracking-wider pb-3 border-b border-zinc-800">
          Organization Profile & Data Retention
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-zinc-500 font-mono text-[10px] block">Organization Name:</span>
            <span className="font-semibold text-zinc-200">{organization?.name || 'Acme Cyber Defense Lab'}</span>
          </div>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-zinc-500 font-mono text-[10px] block">Tenant Slug:</span>
            <span className="font-mono text-zinc-200">{organization?.slug || 'acme-cyber-defense-lab'}</span>
          </div>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-zinc-500 font-mono text-[10px] block">Telemetry Log Retention:</span>
            <span className="font-mono text-zinc-200">{organization?.retentionDays || 90} Days (Compliant)</span>
          </div>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-zinc-500 font-mono text-[10px] block">Active Environment Mode:</span>
            <div className="flex items-center gap-2 pt-0.5">
              <button
                onClick={() => onChangeEnvironment('production')}
                className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                  environment === 'production' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-zinc-800 text-zinc-500'
                }`}
              >
                PRODUCTION
              </button>
              <button
                onClick={() => onChangeEnvironment('training')}
                className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                  environment === 'training' ? 'bg-amber-950 text-amber-300 border border-amber-500/40' : 'bg-zinc-800 text-zinc-500'
                }`}
              >
                TRAINING LAB
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
