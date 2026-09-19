import React, { useState, useEffect, useRef } from 'react';
import { Phone, CheckCircle2, AlertCircle, RefreshCw, ArrowRight, Shield, ArrowLeft, Send } from 'lucide-react';
import { supabaseVerifyPhoneOtp, supabaseSendPhoneOtp, formatToE164, isSupabaseConfigured } from '../lib/supabase';
import { api } from '../api';

interface VerifyPhonePageProps {
  initialPhone: string;
  hintOtp?: string;
  onVerified: (phone: string) => void;
  onSkip: () => void;
  onBack: () => void;
}

export const VerifyPhonePage: React.FC<VerifyPhonePageProps> = ({
  initialPhone,
  hintOtp,
  onVerified,
  onSkip,
  onBack,
}) => {
  const [phoneNumber, setPhoneNumber] = useState(initialPhone || '');
  const [isEditingPhone, setIsEditingPhone] = useState(!initialPhone);
  const [smsSent, setSmsSent] = useState(Boolean(initialPhone || hintOtp));
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [sendingSms, setSendingSms] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [cooldown, setCooldown] = useState<number>(initialPhone ? 60 : 0);
  const [notice, setNotice] = useState<string | null>(null);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // 60-second cooldown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  // Focus on code input once SMS is sent
  useEffect(() => {
    if (smsSent && !isEditingPhone) {
      inputRefs.current[0]?.focus();
    }
  }, [smsSent, isEditingPhone]);

  const handleSendSms = async () => {
    const formatted = formatToE164(phoneNumber);
    if (!formatted && isSupabaseConfigured()) {
      setError('Please provide a valid phone number with international country code (e.g. +14155552671).');
      return;
    }

    setSendingSms(true);
    setError(null);
    setNotice(null);
    try {
      if (isSupabaseConfigured()) {
        await supabaseSendPhoneOtp(formatted);
        setNotice(`Verification code dispatched via SMS to ${formatted}`);
      } else {
        const res = await api.resendPhoneOtp();
        if (res.phoneOtp) {
          setNotice(`Verification code dispatched. OTP: ${res.phoneOtp}`);
        } else {
          setNotice(res.devHint || res.message || `Verification code dispatched to ${formatted || phoneNumber}`);
        }
      }
      setSmsSent(true);
      setIsEditingPhone(false);
      setCooldown(60);
      setTimeout(() => setNotice(null), 6000);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch SMS code. Please verify details.');
    } finally {
      setSendingSms(false);
    }
  };

  const handleDigitChange = (index: number, value: string) => {
    // Paste support
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
        const formatted = formatToE164(phoneNumber);
        await supabaseVerifyPhoneOtp(formatted, otpCode);
        setSuccess(true);
        setTimeout(() => {
          onVerified(formatted);
        }, 1000);
      } else {
        await api.verifyPhoneOtp(otpCode);
        setSuccess(true);
        setTimeout(() => {
          onVerified(phoneNumber);
        }, 1000);
      }
    } catch (err: any) {
      setError(err.message || 'Invalid or expired SMS OTP verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!smsSent) {
      handleSendSms();
      return;
    }
    const code = digits.join('');
    if (code.length !== 6) {
      setError('Please enter all 6 digits received via SMS.');
      return;
    }
    triggerVerification(code);
  };

  return (
    <div id="verify-phone-page" className="w-full max-w-md mx-auto p-6 bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl text-zinc-100">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center">
            <Phone className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-sm font-bold font-mono tracking-tight text-zinc-100">PHONE SMS OTP VERIFICATION</h2>
            <p className="text-[11px] text-zinc-400 font-mono">Mobile Out-of-Band Verification</p>
          </div>
        </div>
        <div className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/50 border border-emerald-500/30">
          <Shield className="w-3 h-3" />
          <span>FACTOR 2</span>
        </div>
      </div>

      <div className="space-y-4 text-xs">
        {hintOtp && !success && (
          <div className="p-3 rounded bg-zinc-950 border border-emerald-500/30 text-zinc-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>SMS OTP Code: <strong className="font-mono text-emerald-400 text-sm tracking-widest">{hintOtp}</strong></span>
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

        {notice && (
          <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{notice}</span>
          </div>
        )}

        {/* Phone Input / Display */}
        {isEditingPhone ? (
          <div className="space-y-3">
            <label className="block text-zinc-400 font-medium">Mobile Number (International E.164 format)</label>
            <div className="flex gap-2">
              <input
                type="tel"
                placeholder="+1 (555) 019-2831"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                className="flex-1 px-3 py-2 rounded bg-zinc-950 border border-zinc-700 font-mono text-xs text-zinc-100 focus:border-emerald-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleSendSms}
                disabled={sendingSms || !phoneNumber.trim()}
                className="px-3 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium flex items-center gap-1.5 disabled:opacity-50 transition-colors"
              >
                {sendingSms ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Send SMS</span>
              </button>
            </div>
            <p className="text-[11px] text-zinc-400">
              Format: +[country code][number]. E.g. +14155550199 or +447911123456.
            </p>
          </div>
        ) : (
          <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Target Phone (E.164)</span>
              <span className="font-mono text-xs text-emerald-400 font-bold">{formatToE164(phoneNumber)}</span>
            </div>
            <button
              type="button"
              onClick={() => setIsEditingPhone(true)}
              className="text-[11px] text-zinc-400 hover:text-zinc-200 underline"
            >
              Change
            </button>
          </div>
        )}

        {/* Success Confirmation */}
        {success ? (
          <div className="py-6 text-center space-y-2 bg-emerald-950/30 border border-emerald-500/30 rounded-lg">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto animate-bounce" />
            <p className="text-sm font-bold text-emerald-200">Phone Factor Verified</p>
            <p className="text-zinc-400 text-xs">Advancing to security setup...</p>
          </div>
        ) : (
          smsSent && !isEditingPhone && (
            <form onSubmit={handleSubmit} className="space-y-5 pt-2">
              <div>
                <label className="block text-zinc-400 mb-2 font-medium text-center">
                  Enter 6-Digit SMS Verification Code
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

              <div className="space-y-2.5 pt-2">
                <button
                  type="submit"
                  disabled={loading || digits.join('').length !== 6}
                  className="w-full py-2.5 px-4 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shadow-sm"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                  <span>Confirm Phone SMS Code</span>
                </button>

                <div className="flex items-center justify-between text-[11px] pt-1">
                  <button
                    type="button"
                    onClick={onBack}
                    className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>Back</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSendSms}
                    disabled={cooldown > 0 || sendingSms || loading}
                    className="text-zinc-400 hover:text-emerald-400 disabled:text-zinc-600 transition-colors font-medium flex items-center gap-1"
                  >
                    {sendingSms && <RefreshCw className="w-3 h-3 animate-spin" />}
                    <span>
                      {cooldown > 0 ? `Resend SMS in ${cooldown}s` : 'Resend SMS Code'}
                    </span>
                  </button>
                </div>
              </div>
            </form>
          )
        )}

        <div className="border-t border-zinc-800 pt-3 text-center">
          <button
            type="button"
            onClick={onSkip}
            className="text-[11px] text-zinc-400 hover:text-zinc-200 py-1 transition-colors"
          >
            Skip Phone Verification for now
          </button>
        </div>
      </div>
    </div>
  );
};
