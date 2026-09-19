import React, { useState, useEffect, useRef } from 'react';
import { Mail, CheckCircle2, AlertCircle, RefreshCw, ArrowRight, Shield, ArrowLeft } from 'lucide-react';
import { supabaseVerifyEmailOtp, supabaseResendEmailOtp, isSupabaseConfigured } from '../lib/supabase';
import { api } from '../api';

interface VerifyEmailPageProps {
  email: string;
  hintOtp?: string;
  onVerified: (email: string) => void;
  onBackToLogin: () => void;
}

export const VerifyEmailPage: React.FC<VerifyEmailPageProps> = ({
  email,
  hintOtp,
  onVerified,
  onBackToLogin,
}) => {
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [cooldown, setCooldown] = useState<number>(60);
  const [resending, setResending] = useState(false);
  const [resendNotice, setResendNotice] = useState<string | null>(null);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // 60-second cooldown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  const handleDigitChange = (index: number, value: string) => {
    // Handle paste of full code
    if (value.length > 1) {
      const cleaned = value.replace(/\D/g, '').slice(0, 6);
      if (cleaned.length > 0) {
        const nextDigits = [...digits];
        for (let i = 0; i < 6; i++) {
          nextDigits[i] = cleaned[i] || '';
        }
        setDigits(nextDigits);
        const focusIdx = Math.min(cleaned.length, 5);
        inputRefs.current[focusIdx]?.focus();
        if (cleaned.length === 6) {
          triggerVerification(cleaned);
        }
        return;
      }
    }

    const char = value.slice(-1);
    if (char && !/^\d$/.test(char)) return;

    const nextDigits = [...digits];
    nextDigits[index] = char;
    setDigits(nextDigits);

    if (char && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Auto verify if all 6 filled
    const fullCode = nextDigits.join('');
    if (fullCode.length === 6) {
      triggerVerification(fullCode);
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const triggerVerification = async (otpCode: string) => {
    setError(null);
    setLoading(true);
    try {
      if (isSupabaseConfigured()) {
        await supabaseVerifyEmailOtp(email, otpCode);
      } else {
        await api.verifyEmailOtp(otpCode);
      }
      setSuccess(true);
      setTimeout(() => {
        onVerified(email);
      }, 1000);
    } catch (err: any) {
      setError(err.message || 'Invalid or expired email verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const code = digits.join('');
    if (code.length !== 6) {
      setError('Please enter all 6 digits of the verification code.');
      return;
    }
    triggerVerification(code);
  };

  const handleResend = async () => {
    if (cooldown > 0 || resending) return;
    setResending(true);
    setError(null);
    setResendNotice(null);
    try {
      if (isSupabaseConfigured()) {
        await supabaseResendEmailOtp(email);
        setResendNotice('New verification code sent to your email.');
      } else {
        const res = await api.resendEmailOtp();
        if (res.emailOtp) {
          setResendNotice(`Verification code dispatched. OTP: ${res.emailOtp}`);
        } else {
          setResendNotice(res.devHint || res.message || 'New verification code dispatched.');
        }
      }
      setCooldown(60);
      setTimeout(() => setResendNotice(null), 6000);
    } catch (err: any) {
      setError(err.message || 'Failed to resend verification code. Please wait.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div id="verify-email-page" className="w-full max-w-md mx-auto p-6 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl text-zinc-100">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center">
            <Mail className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-sm font-bold font-mono tracking-tight text-zinc-100">EMAIL OTP VERIFICATION</h2>
            <p className="text-[11px] text-zinc-400 font-mono">Defensive Telemetry Identity Factor</p>
          </div>
        </div>
        <div className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/50 border border-emerald-500/30">
          <Shield className="w-3 h-3" />
          <span>FACTOR 1</span>
        </div>
      </div>

      <div className="space-y-4 text-xs">
        <p className="text-zinc-300 leading-relaxed">
          A 6-digit one-time verification passcode has been dispatched to:
        </p>
        <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 font-mono text-xs text-emerald-400 flex items-center justify-between">
          <span className="truncate">{email}</span>
          <span className="text-[10px] text-zinc-500 shrink-0">E-MAIL OTP</span>
        </div>

        {hintOtp && !success && (
          <div className="p-3 rounded bg-zinc-950 border border-emerald-500/30 text-zinc-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Verification OTP: <strong className="font-mono text-emerald-400 text-sm tracking-widest">{hintOtp}</strong></span>
            </div>
            <button
              type="button"
              onClick={() => {
                const arr = hintOtp.slice(0, 6).split('');
                setDigits(arr);
                triggerVerification(hintOtp.slice(0, 6));
              }}
              className="px-2.5 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/50 text-[11px] text-emerald-300 font-medium transition-colors"
            >
              Auto-fill & Verify
            </button>
          </div>
        )}

        {error && (
          <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {resendNotice && (
          <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{resendNotice}</span>
          </div>
        )}

        {success ? (
          <div className="py-6 text-center space-y-2 bg-emerald-950/30 border border-emerald-500/30 rounded-lg">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto animate-bounce" />
            <p className="text-sm font-bold text-emerald-200">Email Verified Successfully</p>
            <p className="text-zinc-400 text-xs">Advancing to next security factor...</p>
          </div>
        ) : (
          <form onSubmit={handleManualSubmit} className="space-y-5">
            {/* 6 Digit Inputs */}
            <div>
              <label className="block text-zinc-400 mb-2 font-medium text-center">
                Enter 6-Digit Verification Code
              </label>
              <div className="flex items-center justify-center gap-2 sm:gap-2.5">
                {digits.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => {
                      inputRefs.current[idx] = el;
                    }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleDigitChange(idx, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(idx, e)}
                    disabled={loading || success}
                    className="w-11 h-12 text-center font-mono text-lg font-bold rounded bg-zinc-950 border border-zinc-700 text-emerald-400 focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 focus:outline-none transition-colors"
                  />
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="space-y-2.5 pt-2">
              <button
                type="submit"
                disabled={loading || digits.join('').length !== 6}
                className="w-full py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shadow-sm"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                <span>Confirm Email Verification Code</span>
              </button>

              <div className="flex items-center justify-between text-[11px] pt-1">
                <button
                  type="button"
                  onClick={onBackToLogin}
                  className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Return to Sign In</span>
                </button>

                <button
                  type="button"
                  onClick={handleResend}
                  disabled={cooldown > 0 || resending || loading}
                  className="text-zinc-400 hover:text-emerald-400 disabled:text-zinc-600 transition-colors font-medium flex items-center gap-1"
                >
                  {resending && <RefreshCw className="w-3 h-3 animate-spin" />}
                  <span>
                    {cooldown > 0 ? `Resend Code in ${cooldown}s` : 'Resend Verification Code'}
                  </span>
                </button>
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
