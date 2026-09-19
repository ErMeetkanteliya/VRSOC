import { createClient, SupabaseClient, User } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
// Prioritize SUPABASE_SERVICE_ROLE_KEY for server operations, never exposed to client
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';

export const supabaseAdmin: SupabaseClient | null = (supabaseUrl && supabaseKey)
  ? createClient(supabaseUrl, supabaseKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    })
  : null;

/**
 * Validates Supabase environment variables on server startup
 */
export function checkSupabaseConfig(): { isConfigured: boolean; missingVars: string[] } {
  const missing: string[] = [];
  if (!process.env.VITE_SUPABASE_URL && !process.env.SUPABASE_URL) missing.push('VITE_SUPABASE_URL / SUPABASE_URL');
  if (!process.env.VITE_SUPABASE_ANON_KEY && !process.env.SUPABASE_ANON_KEY) missing.push('VITE_SUPABASE_ANON_KEY');
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) missing.push('SUPABASE_SERVICE_ROLE_KEY');

  const isConfigured = Boolean(supabaseUrl && supabaseKey);

  if (!isConfigured) {
    console.error(
      `\n======================================================================\n` +
      `[VRSOC STARTUP CONFIGURATION ERROR]:\n` +
      `VRSOC authentication is not configured. Please configure the application's\n` +
      `Supabase environment variables at the deployment level:\n` +
      `  - VITE_SUPABASE_URL\n` +
      `  - VITE_SUPABASE_ANON_KEY\n` +
      `  - SUPABASE_URL\n` +
      `  - SUPABASE_SERVICE_ROLE_KEY\n` +
      `Missing: ${missing.join(', ')}\n` +
      `End users will see an administrative configuration notice rather than manual inputs.\n` +
      `======================================================================\n`
    );
  } else {
    console.log(`[VRSOC Auth]: Configured with Supabase URL ${supabaseUrl} (Service role key active: ${Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY)})`);
  }

  return { isConfigured, missingVars: missing };
}

/**
 * Validates a Supabase JWT and returns the verified user
 */
export async function verifySupabaseToken(token: string): Promise<User | null> {
  if (!supabaseAdmin) return null;
  try {
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !user) {
      return null;
    }
    return user;
  } catch (err) {
    console.error('Error verifying Supabase token on server:', err);
    return null;
  }
}

/**
 * Returns public Supabase client config for frontend initialization
 * IMPORTANT: SUPABASE_SERVICE_ROLE_KEY is strictly withheld and never returned here.
 */
export function getPublicAuthConfig() {
  const publicUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '';
  const publicAnon = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '';
  return {
    supabaseUrl: publicUrl,
    supabaseAnonKey: publicAnon,
    isConfigured: Boolean(publicUrl && publicAnon),
  };
}
