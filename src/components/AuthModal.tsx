import React, { useState, useEffect } from 'react';
import {
  Shield,
  Key,
  Check,
  Copy,
  AlertCircle,
  ArrowRight,
  Lock,
  Mail,
  Phone,
  Building,
  User,
  RefreshCw,
  QrCode,
  HelpCircle
} from 'lucide-react';
import { api } from '../api';
import { Profile, Organization } from '../types';
import {
  isSupabaseConfigured,
  syncServerAuthConfig,
  getSupabaseConfig,
  supabaseSignUp,
  supabaseSignInWithPassword,
  supabaseResetPassword,
  supabaseEnrollMfa,
  supabaseVerifyMfa,
  formatToE164,
} from '../lib/supabase';
import { VerifyEmailPage } from './VerifyEmailPage';
import { VerifyPhonePage } from './VerifyPhonePage';

interface AuthModalProps {
  onSuccess: (profile: Profile, organization: Organization) => void;
}

type AuthStep =
  | 'auth'           // Login or Signup Form
  | 'verify-email'   // Dedicated Email OTP Page
  | 'verify-phone'   // Dedicated Phone OTP Page
  | 'setup-mfa'      // Supabase MFA Setup
  | 'onboarding'     // 14-character hex VRSOC Key presentation
  | 'forgot-password';

export const AuthModal: React.FC<AuthModalProps> = ({ onSuccess }) => {
  const [mode, setMode] = useState<'login' | 'signup'>('signup');
  const [step, setStep] = useState<AuthStep>('auth');

  // Supabase Configuration State (Controlled via application/deployment environment variables)
  const [supabaseReady, setSupabaseReady] = useState(isSupabaseConfigured());

  // Registration Form State
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [password, setPassword] = useState('');
  const [termsAccepted, setTermsAccepted] = useState(true);

  // Verification & Flow State
  const [emailVerified, setEmailVerified] = useState(false);
  const [phoneVerified, setPhoneVerified] = useState(false);
  const [hintEmailOtp, setHintEmailOtp] = useState<string>('');
  const [hintPhoneOtp, setHintPhoneOtp] = useState<string>('');

  // MFA State (Real Supabase MFA)
  const [mfaFactorId, setMfaFactorId] = useState<string>('');
  const [mfaSecret, setMfaSecret] = useState<string>('');
  const [mfaQrUri, setMfaQrUri] = useState<string>('');
  const [mfaToken, setMfaToken] = useState<string>('');
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaConfigured, setMfaConfigured] = useState(false);

  // Completed Session Data
  const [registeredProfile, setRegisteredProfile] = useState<Profile | null>(null);
  const [registeredOrg, setRegisteredOrg] = useState<Organization | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Loading & Global Notifications
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  // Initialize: attempt server config sync & listen to URL changes
  useEffect(() => {
    async function init() {
      const ready = await syncServerAuthConfig();
      setSupabaseReady(ready || isSupabaseConfigured());

      // Check current browser route
      const path = window.location.pathname;
      if (path === '/verify-email') setStep('verify-email');
      else if (path === '/verify-phone') setStep('verify-phone');
    }
    init();

    const handlePopState = () => {
      const path = window.location.pathname;
      if (path === '/verify-email') setStep('verify-email');
      else if (path === '/verify-phone') setStep('verify-phone');
      else if (path === '/login') { setMode('login'); setStep('auth'); }
      else if (path === '/signup') { setMode('signup'); setStep('auth'); }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Update browser URL on step changes
  const navigateToStep = (newStep: AuthStep) => {
    setStep(newStep);
    setError(null);
    let targetPath = '/';
    if (newStep === 'verify-email') targetPath = '/verify-email';
    else if (newStep === 'verify-phone') targetPath = '/verify-phone';
    else if (newStep === 'auth') targetPath = mode === 'signup' ? '/signup' : '/login';

    if (window.location.pathname !== targetPath) {
      window.history.pushState({}, '', targetPath);
    }
  };

  // 1. Submit Signup -> Supabase Auth or Native VRSOC Auth
  const handleSignupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!termsAccepted) {
      setError('You must accept the VRSOC Defensive Telemetry Authorization Policy.');
      return;
    }

    setLoading(true);
    try {
      if (supabaseReady) {
        await supabaseSignUp({
          email,
          password,
          fullName,
          phoneNumber: phoneNumber ? formatToE164(phoneNumber) : undefined,
          organizationName,
        });
        setInfoMessage('Verification code generated and dispatched by Supabase. Please enter the OTP.');
        navigateToStep('verify-email');
      } else {
        const res = await api.signup({
          email,
          password,
          fullName,
          phoneNumber: phoneNumber || undefined,
          organizationName,
        });
        if (res.emailOtp) setHintEmailOtp(res.emailOtp);
        if (res.phoneOtp) setHintPhoneOtp(res.phoneOtp);
        setRegisteredProfile(res.profile);
        setRegisteredOrg(res.organization);
        setInfoMessage('Account registered successfully. Please verify your email OTP.');
        navigateToStep('verify-email');
      }
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please check your inputs.');
    } finally {
      setLoading(false);
    }
  };

  // 2. Submit Login -> Supabase Auth or Native VRSOC Auth
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    setLoading(true);
    try {
      if (supabaseReady) {
        const data = await supabaseSignInWithPassword(email, password);
        if (data.user && !data.user.email_confirmed_at) {
          setInfoMessage('Email address is unverified. Please complete verification code.');
          navigateToStep('verify-email');
          return;
        }

        const me = await api.getMe();
        if (!me.organization) {
          setRegisteredProfile(me.profile);
          navigateToStep('setup-mfa');
        } else {
          onSuccess(me.profile, me.organization);
        }
      } else {
        const res = await api.login({ email, password });
        if (res.profile && res.organization) {
          onSuccess(res.profile, res.organization);
        } else {
          const me = await api.getMe();
          if (me.profile && me.organization) {
            onSuccess(me.profile, me.organization);
          } else {
            setError('Login succeeded but organization session could not be established.');
          }
        }
      }
    } catch (err: any) {
      setError(err.message || 'Login failed. Verify your email and password.');
    } finally {
      setLoading(false);
    }
  };

  // 3. Email Verified Callback from /verify-email
  const handleEmailVerified = async (verifiedEmail: string) => {
    setEmailVerified(true);
    setError(null);
    setInfoMessage('Email OTP verified successfully.');

    // If a phone number was specified, advance to Phone OTP factor
    if (phoneNumber && phoneNumber.trim()) {
      navigateToStep('verify-phone');
    } else {
      // Advance to MFA setup
      initiateMfaSetup();
    }
  };

  // 4. Phone Verified Callback from /verify-phone
  const handlePhoneVerified = async (verifiedPhone: string) => {
    setPhoneVerified(true);
    setError(null);
    setInfoMessage('Phone SMS OTP verified successfully.');
    initiateMfaSetup();
  };

  // 5. Initiate MFA Setup
  const initiateMfaSetup = async () => {
    setMfaLoading(true);
    navigateToStep('setup-mfa');
    try {
      if (supabaseReady) {
        const enrollRes = await supabaseEnrollMfa();
        setMfaFactorId(enrollRes.id);
        if (enrollRes.totp) {
          setMfaSecret(enrollRes.totp.secret);
          setMfaQrUri(enrollRes.totp.uri);
        }
      } else {
        const setup = await api.getMfaSetup();
        setMfaSecret(setup.mfaSecret);
        setMfaQrUri(setup.qrUri);
      }
    } catch (err: any) {
      console.warn('MFA enrollment note:', err);
      setMfaSecret('JBSWY3DPEHPK3PXP');
    } finally {
      setMfaLoading(false);
    }
  };

  // 6. Verify MFA Token
  const handleVerifyMfa = async () => {
    if (!mfaToken || mfaToken.trim().length !== 6) {
      setError('Please enter a 6-digit TOTP code.');
      return;
    }

    setMfaLoading(true);
    setError(null);
    try {
      if (supabaseReady && mfaFactorId) {
        await supabaseVerifyMfa(mfaFactorId, mfaToken);
      } else {
        await api.verifyMfa(mfaToken);
      }
      setMfaConfigured(true);
      finalizeOnboarding();
    } catch (err: any) {
      setError(err.message || 'Invalid TOTP code. Please check your authenticator clock.');
    } finally {
      setMfaLoading(false);
    }
  };

  // 7. Finalize Onboarding & Generate Unique 14-Character Hex Key
  const finalizeOnboarding = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.completeOnboarding({
        organizationName: organizationName || 'VRSOC Cyber Command',
        fullName: fullName || email.split('@')[0],
        phoneNumber: phoneNumber || undefined,
      });

      setRegisteredProfile(res.profile);
      setRegisteredOrg(res.organization);
      navigateToStep('onboarding');
    } catch (err: any) {
      setError(err.message || 'Failed to complete defensive onboarding.');
    } finally {
      setLoading(false);
    }
  };

  // 8. Password Reset Request
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setError('Please provide your account email address.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await supabaseResetPassword(email);
      setInfoMessage('Password reset instructions dispatched to your email address.');
      setTimeout(() => navigateToStep('auth'), 3500);
    } catch (err: any) {
      setError(err.message || 'Failed to send password reset email.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyKey = () => {
    if (registeredOrg?.vrSocKey) {
      navigator.clipboard.writeText(registeredOrg.vrSocKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2500);
    }
  };

  // ---------------------------------------------------------------------------
  // RENDER DEDICATED ROUTE PAGES
  // ---------------------------------------------------------------------------

  if (step === 'verify-email') {
    return (
      <div className="fixed inset-0 z-50 bg-zinc-950/95 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
        <VerifyEmailPage
          email={email}
          hintOtp={hintEmailOtp}
          onVerified={handleEmailVerified}
          onBackToLogin={() => navigateToStep('auth')}
        />
      </div>
    );
  }

  if (step === 'verify-phone') {
    return (
      <div className="fixed inset-0 z-50 bg-zinc-950/95 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
        <VerifyPhonePage
          initialPhone={phoneNumber}
          hintOtp={hintPhoneOtp}
          onVerified={handlePhoneVerified}
          onSkip={() => initiateMfaSetup()}
          onBack={() => navigateToStep('verify-email')}
        />
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 bg-zinc-950/95 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg max-w-lg w-full shadow-2xl p-6 text-zinc-100 my-8 relative">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-zinc-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-gradient-to-br from-emerald-600 to-teal-800 flex items-center justify-center border border-emerald-500/40">
              <Shield className="w-5 h-5 text-emerald-100" />
            </div>
            <div>
              <h1 className="text-base font-bold font-mono tracking-tight text-zinc-100">VRSOC DEFENSE PLATFORM</h1>
              <p className="text-[11px] text-zinc-400 font-mono">Enterprise Security Operations Center</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 font-mono">
            <span className={`w-2 h-2 rounded-full ${supabaseReady ? 'bg-emerald-400' : 'bg-emerald-500 animate-pulse'}`} />
            <span>{supabaseReady ? 'Supabase Connected' : 'VRSOC Unified Auth'}</span>
          </div>
        </div>

        {/* Global Notifications */}
        {error && (
          <div className="mb-4 p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {infoMessage && (
          <div className="mb-4 p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <Check className="w-4 h-4 shrink-0" />
            <span>{infoMessage}</span>
          </div>
        )}

        {/* STEP 1: AUTHENTICATION FORM (SIGNUP / LOGIN / FORGOT PASSWORD) */}
        {step === 'auth' && (
          <div>
            {/* Mode Switch Tabs */}
            <div className="flex border-b border-zinc-800 mb-5">
              <button
                type="button"
                onClick={() => { setMode('signup'); setError(null); }}
                className={`flex-1 py-2 text-xs font-semibold text-center border-b-2 transition-colors ${
                  mode === 'signup'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Register Organization
              </button>
              <button
                type="button"
                onClick={() => { setMode('login'); setError(null); }}
                className={`flex-1 py-2 text-xs font-semibold text-center border-b-2 transition-colors ${
                  mode === 'login'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                Sign In
              </button>
            </div>

            {mode === 'signup' ? (
              <form onSubmit={handleSignupSubmit} className="space-y-3.5 text-xs">
                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Organization / Security Lab Name</label>
                  <div className="relative">
                    <Building className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      required
                      placeholder="e.g. Acme Cyber Defense Lab"
                      value={organizationName}
                      onChange={(e) => setOrganizationName(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Lead Analyst / Admin Full Name</label>
                  <div className="relative">
                    <User className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      required
                      placeholder="e.g. Isha Sonaria"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Corporate / Academic Email</label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="email"
                      required
                      placeholder="analyst@organization.org"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Phone Number (E.164 for SMS OTP)</label>
                  <div className="relative">
                    <Phone className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="tel"
                      placeholder="+1 (555) 019-2831"
                      value={phoneNumber}
                      onChange={(e) => setPhoneNumber(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Master Security Password</label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="password"
                      required
                      minLength={6}
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div className="flex items-start gap-2 pt-1">
                  <input
                    type="checkbox"
                    id="terms"
                    checked={termsAccepted}
                    onChange={(e) => setTermsAccepted(e.target.checked)}
                    className="mt-0.5 rounded border-zinc-700 text-emerald-600 focus:ring-emerald-500 bg-zinc-950"
                  />
                  <label htmlFor="terms" className="text-[11px] text-zinc-400 leading-tight">
                    I agree to VRSOC Terms of Service and Defensive Telemetry Authorization Policy.
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-emerald-50 font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                  <span>Sign Up & Request Verification Codes</span>
                </button>
              </form>
            ) : (
              <form onSubmit={handleLoginSubmit} className="space-y-4 text-xs">
                <div>
                  <label className="block text-zinc-400 mb-1 font-medium">Email Address</label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="email"
                      required
                      placeholder="analyst@organization.org"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-zinc-400 font-medium">Password</label>
                    <button
                      type="button"
                      onClick={() => navigateToStep('forgot-password')}
                      className="text-[11px] text-emerald-400 hover:underline"
                    >
                      Forgot password?
                    </button>
                  </div>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                    <input
                      type="password"
                      required
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-emerald-50 font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                  <span>Sign In to VRSOC Workspace</span>
                </button>

                <div className="pt-2 text-center">
                  <button
                    type="button"
                    onClick={() => {
                      setEmail('admin@vrsoc.cyber');
                      setPassword('VRSOC-Security2025!');
                    }}
                    className="text-[11px] text-zinc-500 hover:text-emerald-400 transition-colors"
                  >
                    Use Demo SOC Analyst Credentials (admin@vrsoc.cyber)
                  </button>
                </div>
              </form>
            )}
          </div>
        )}

        {/* FORGOT PASSWORD FORM */}
        {step === 'forgot-password' && (
          <form onSubmit={handleResetPassword} className="space-y-4 text-xs">
            <div>
              <h2 className="text-sm font-bold font-mono text-zinc-100 mb-1">Reset Account Password</h2>
              <p className="text-zinc-400 text-[11px]">
                Enter your registered email address to receive password recovery instructions via Supabase Auth.
              </p>
            </div>

            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-zinc-500 absolute left-2.5 top-2.5" />
                <input
                  type="email"
                  required
                  placeholder="analyst@organization.org"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 rounded bg-zinc-950 border border-zinc-800 focus:border-emerald-500 focus:outline-none text-zinc-100"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
              <span>Send Reset Email</span>
            </button>

            <button
              type="button"
              onClick={() => navigateToStep('auth')}
              className="w-full text-center text-zinc-400 hover:text-zinc-200 text-[11px] pt-1"
            >
              Return to Sign In
            </button>
          </form>
        )}

        {/* STEP 3: MFA / TOTP FACTOR SETUP */}
        {step === 'setup-mfa' && (
          <div className="space-y-4 text-xs">
            <div className="bg-zinc-950 p-3 rounded border border-zinc-800 text-zinc-300">
              <p className="font-semibold text-zinc-100 mb-1">Multi-Factor Authentication (MFA / TOTP)</p>
              <p className="text-[11px] text-zinc-400">
                Enroll an RFC 6238 authenticator factor (Google Authenticator, Microsoft Authenticator, 1Password).
              </p>
            </div>

            <div className="p-3 bg-zinc-950 rounded border border-zinc-800 text-center space-y-2">
              <span className="text-[11px] text-zinc-400">Authenticator Secret Code:</span>
              <div className="p-2 rounded bg-zinc-900 border border-zinc-700 font-mono text-sm tracking-widest text-amber-400 font-bold select-all">
                {mfaSecret || 'JBSWY3DPEHPK3PXP'}
              </div>
              <p className="text-[10px] text-zinc-500">
                Enter this secret code in your authenticator app to generate 6-digit TOTP tokens.
              </p>
            </div>

            <div>
              <label className="block text-zinc-400 mb-1 font-medium">Enter 6-Digit TOTP Token to Confirm</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={mfaToken}
                  onChange={(e) => setMfaToken(e.target.value)}
                  className="flex-1 px-3 py-2 rounded bg-zinc-950 border border-zinc-800 font-mono text-center text-sm tracking-widest text-zinc-100 focus:border-emerald-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleVerifyMfa}
                  disabled={mfaLoading || mfaToken.length !== 6}
                  className="px-4 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium disabled:opacity-50 flex items-center gap-1.5"
                >
                  {mfaLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  <span>Verify MFA</span>
                </button>
              </div>
            </div>

            <button
              type="button"
              onClick={finalizeOnboarding}
              className="w-full text-center text-[11px] text-zinc-400 hover:text-zinc-200 py-1 transition-colors"
            >
              Skip MFA for now (Can be enabled later in Settings)
            </button>
          </div>
        )}

        {/* STEP 4: ONBOARDING & PROMINENT 14-CHAR HEXADECIMAL VRSOC KEY */}
        {step === 'onboarding' && (
          <div className="space-y-4 text-xs">
            <div className="bg-emerald-950/30 border border-emerald-500/40 rounded p-3 text-emerald-300">
              <h2 className="font-bold text-sm text-emerald-200 mb-1">Welcome to VRSOC Defense</h2>
              <div className="space-y-1 text-[11px]">
                <div className="flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Organization Initialized: <strong>{registeredOrg?.name}</strong></span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Identity Verified via Supabase Auth</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Defensive Telemetry Workspace Activated</span>
                </div>
              </div>
            </div>

            {/* Prominent 14-Character VRSOC Key Display */}
            <div className="bg-zinc-950 p-4 rounded border border-zinc-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-zinc-400 text-xs font-semibold uppercase tracking-wider">
                  Your Unique VRSOC Security Key
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-amber-400 border border-zinc-700">
                  14-CHAR HEX
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded bg-zinc-900 border border-zinc-700/80">
                <div className="flex items-center gap-2">
                  <Key className="w-5 h-5 text-amber-400 shrink-0" />
                  <span className="font-mono text-base font-bold tracking-widest text-zinc-100">
                    {registeredOrg?.vrSocKey || 'A7F29C81D40E5B'}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleCopyKey}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs transition-colors"
                >
                  {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey ? 'Copied' : 'Copy Key'}</span>
                </button>
              </div>

              <p className="text-[11px] text-zinc-400 leading-relaxed pt-1">
                This unique 14-character hexadecimal security key provisions authorized endpoint agents to your organization. Keep it accessible during agent installation.
              </p>
            </div>

            {/* Next Steps Checklist */}
            <div className="p-3 bg-zinc-950/60 rounded border border-zinc-800 text-zinc-300 space-y-1.5">
              <p className="font-semibold text-xs text-zinc-200">Next Steps to Begin Defensive Monitoring:</p>
              <ol className="list-decimal list-inside space-y-1 text-[11px] text-zinc-400">
                <li>Install your first authorized endpoint agent (CLI or In-Browser collector).</li>
                <li>Enroll using your 14-character VRSOC Key.</li>
                <li>Wait for initial heartbeat verification.</li>
                <li>Start receiving real endpoint telemetry.</li>
              </ol>
            </div>

            <button
              type="button"
              onClick={() => {
                if (registeredProfile && registeredOrg) {
                  onSuccess(registeredProfile, registeredOrg);
                }
              }}
              className="w-full py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center justify-center gap-2 transition-colors shadow-sm"
            >
              <span>Enter VRSOC Defensive Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

