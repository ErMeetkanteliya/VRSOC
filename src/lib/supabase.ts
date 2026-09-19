import { createClient, SupabaseClient, User, Session } from '@supabase/supabase-js';

// Application/Deployment environment configuration
let configuredUrl = (import.meta.env.VITE_SUPABASE_URL || '').trim();
let configuredAnonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY || '').trim();

let supabaseInstance: SupabaseClient | null = null;

function createInstance(url: string, anonKey: string): SupabaseClient | null {
  if (!url || !anonKey) return null;
  try {
    return createClient(url, anonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
        storage: typeof window !== 'undefined' ? window.localStorage : undefined,
      },
    });
  } catch (err) {
    console.error('[VRSOC Auth] Failed to create Supabase client instance:', err);
    return null;
  }
}

// Initialize single Supabase client if environment configuration is present
if (configuredUrl && configuredAnonKey) {
  supabaseInstance = createInstance(configuredUrl, configuredAnonKey);
}

export function getSupabase(): SupabaseClient | null {
  return supabaseInstance;
}

export function isSupabaseConfigured(): boolean {
  return Boolean(supabaseInstance && configuredUrl && configuredAnonKey);
}

export function getSupabaseConfig(): { url: string; isConfigured: boolean } {
  return { url: configuredUrl, isConfigured: isSupabaseConfigured() };
}

// Fetch deployment configuration from backend if not injected into frontend bundle
export async function syncServerAuthConfig(): Promise<boolean> {
  if (isSupabaseConfigured()) {
    return true;
  }
  try {
    const res = await fetch('/api/auth/config');
    if (res.ok) {
      const data = await res.json();
      if (data.supabaseUrl && data.supabaseAnonKey) {
        configuredUrl = data.supabaseUrl.trim();
        configuredAnonKey = data.supabaseAnonKey.trim();
        supabaseInstance = createInstance(configuredUrl, configuredAnonKey);
        return isSupabaseConfigured();
      }
    }
  } catch (err) {
    console.warn('[VRSOC Auth] Could not sync deployment auth config from backend:', err);
  }
  return false;
}

// -----------------------------------------------------------------------------
// SUPABASE AUTH INTERACTION METHODS
// -----------------------------------------------------------------------------

/**
 * 1. User Sign Up
 * Uses Supabase Auth signUp to register identity.
 * Supabase handles email verification sending.
 */
export async function supabaseSignUp(params: {
  email: string;
  password?: string;
  fullName: string;
  phoneNumber?: string;
  organizationName: string;
}) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured. Please set SUPABASE_URL and SUPABASE_ANON_KEY.');
  }

  // Generate strong random password if none provided
  const pwd = params.password && params.password.length >= 6
    ? params.password
    : Math.random().toString(36).slice(-10) + 'A1!';

  const { data, error } = await client.auth.signUp({
    email: params.email.trim(),
    password: pwd,
    options: {
      data: {
        full_name: params.fullName.trim(),
        phone_number: params.phoneNumber?.trim() || '',
        organization_name: params.organizationName.trim(),
      },
    },
  });

  if (error) {
    throw error;
  }

  if (data.session?.access_token) {
    localStorage.setItem('vrsoc_token', data.session.access_token);
  }

  return data;
}

/**
 * 2. Real Email OTP Verification
 * Validates the email OTP token using Supabase verifyOtp.
 * Tries 'email' verification type, with smart fallback to 'signup' if needed.
 */
export async function supabaseVerifyEmailOtp(email: string, otp: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured. Please set SUPABASE_URL and SUPABASE_ANON_KEY.');
  }

  const cleanEmail = email.trim();
  const cleanOtp = otp.trim();

  // Try type 'email'
  let result = await client.auth.verifyOtp({
    email: cleanEmail,
    token: cleanOtp,
    type: 'email',
  });

  // If failed with type mismatch, try type 'signup'
  if (result.error && (result.error.message.includes('type') || result.error.message.includes('token'))) {
    const signupResult = await client.auth.verifyOtp({
      email: cleanEmail,
      token: cleanOtp,
      type: 'signup',
    });
    if (!signupResult.error) {
      result = signupResult;
    }
  }

  if (result.error) {
    throw result.error;
  }

  if (result.data.session?.access_token) {
    localStorage.setItem('vrsoc_token', result.data.session.access_token);
  }

  return result.data;
}

/**
 * Resend Email Verification OTP
 */
export async function supabaseResendEmailOtp(email: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const { data, error } = await client.auth.resend({
    type: 'signup',
    email: email.trim(),
  });

  if (error) {
    // If signup resend fails, try generic email OTP sign in
    const otpResult = await client.auth.signInWithOtp({
      email: email.trim(),
    });
    if (otpResult.error) {
      throw error;
    }
    return otpResult.data;
  }

  return data;
}

/**
 * 3. Send/Request Phone OTP
 * Formats to E.164 and initiates SMS OTP verification via Supabase.
 */
export async function supabaseSendPhoneOtp(phone: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const formatted = formatToE164(phone);
  if (!formatted) {
    throw new Error('Invalid phone number format. Please use international E.164 format (e.g. +12125550199).');
  }

  // If user has an active session, update phone number (which triggers verification SMS)
  const session = await client.auth.getSession();
  if (session.data.session?.user) {
    const { data, error } = await client.auth.updateUser({
      phone: formatted,
    });
    if (error) {
      // If updateUser fails, fallback to signInWithOtp
      const otpRes = await client.auth.signInWithOtp({ phone: formatted });
      if (otpRes.error) throw error;
      return otpRes.data;
    }
    return data;
  } else {
    const { data, error } = await client.auth.signInWithOtp({
      phone: formatted,
    });
    if (error) throw error;
    return data;
  }
}

/**
 * 4. Real Phone SMS OTP Verification
 * Validates SMS OTP using Supabase verifyOtp with type 'sms'.
 */
export async function supabaseVerifyPhoneOtp(phone: string, otp: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const formatted = formatToE164(phone);
  const cleanOtp = otp.trim();

  // Try type 'sms'
  let result = await client.auth.verifyOtp({
    phone: formatted,
    token: cleanOtp,
    type: 'sms',
  });

  // If error, try type 'phone_change'
  if (result.error && (result.error.message.includes('type') || result.error.message.includes('token'))) {
    const changeResult = await client.auth.verifyOtp({
      phone: formatted,
      token: cleanOtp,
      type: 'phone_change',
    });
    if (!changeResult.error) {
      result = changeResult;
    }
  }

  if (result.error) {
    throw result.error;
  }

  if (result.data.session?.access_token) {
    localStorage.setItem('vrsoc_token', result.data.session.access_token);
  }

  return result.data;
}

/**
 * 5. Sign In With Password
 */
export async function supabaseSignInWithPassword(email: string, password: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const { data, error } = await client.auth.signInWithPassword({
    email: email.trim(),
    password,
  });

  if (error) {
    throw error;
  }

  if (data.session?.access_token) {
    localStorage.setItem('vrsoc_token', data.session.access_token);
  }

  return data;
}

/**
 * 6. Send Password Reset Email
 */
export async function supabaseResetPassword(email: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const { data, error } = await client.auth.resetPasswordForEmail(email.trim(), {
    redirectTo: typeof window !== 'undefined' ? `${window.location.origin}/reset-password` : undefined,
  });

  if (error) {
    throw error;
  }

  return data;
}

/**
 * 7. MFA Enrollment (TOTP)
 * Uses Supabase Auth MFA APIs
 */
export async function supabaseEnrollMfa() {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const { data, error } = await client.auth.mfa.enroll({
    factorType: 'totp',
    issuer: 'VRSOC Defensive Platform',
  });

  if (error) {
    throw error;
  }

  return data;
}

/**
 * 8. MFA Verification (Challenge and Verify)
 */
export async function supabaseVerifyMfa(factorId: string, code: string) {
  const client = getSupabase();
  if (!client) {
    throw new Error('Supabase is not configured.');
  }

  const cleanCode = code.trim();

  // Create challenge then verify
  const challengeRes = await client.auth.mfa.challenge({ factorId });
  if (challengeRes.error) {
    throw challengeRes.error;
  }

  const verifyRes = await client.auth.mfa.verify({
    factorId,
    challengeId: challengeRes.data.id,
    code: cleanCode,
  });

  if (verifyRes.error) {
    throw verifyRes.error;
  }

  if (verifyRes.data.access_token) {
    localStorage.setItem('vrsoc_token', verifyRes.data.access_token);
  }

  return verifyRes.data;
}

/**
 * 9. Get Current Active User & Session
 */
export async function getSupabaseSession(): Promise<{ user: User | null; session: Session | null }> {
  const client = getSupabase();
  if (!client) return { user: null, session: null };

  const { data } = await client.auth.getSession();
  return {
    user: data.session?.user || null,
    session: data.session || null,
  };
}

/**
 * 10. Sign Out
 */
export async function supabaseSignOut() {
  const client = getSupabase();
  if (client) {
    try {
      await client.auth.signOut();
    } catch (err) {
      console.warn('Supabase sign out error:', err);
    }
  }
  localStorage.removeItem('vrsoc_token');
}

/**
 * Helper to normalize and validate E.164 phone number
 */
export function formatToE164(phone: string): string {
  const cleaned = phone.replace(/[\s\-\(\)\.]/g, '');
  if (!cleaned) return '';
  if (cleaned.startsWith('+')) {
    return cleaned;
  }
  // Default to +1 if 10 digits without leading +
  if (cleaned.length === 10) {
    return `+1${cleaned}`;
  }
  if (cleaned.length === 11 && cleaned.startsWith('1')) {
    return `+${cleaned}`;
  }
  return `+${cleaned}`;
}
