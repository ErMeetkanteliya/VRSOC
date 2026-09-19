process.env.NODE_ENV = 'test';
import 'dotenv/config';
import http from 'http';
import { createClient } from '@supabase/supabase-js';
import { supabaseAdmin, getPublicAuthConfig } from '../server/supabase';
import { db } from '../server/db';
import { verifySupabaseToken } from '../server/supabase';
import { app } from '../server';

const TEST_PORT = 3005;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const SUPABASE_URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || 'http://127.0.0.1:54321';
const SUPABASE_ANON = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '';

interface TestResult {
  step: number;
  description: string;
  status: 'PASS' | 'FAIL';
  details?: string;
}

const results: TestResult[] = [];

function record(step: number, description: string, status: 'PASS' | 'FAIL', details?: string) {
  results.push({ step, description, status, details });
  const icon = status === 'PASS' ? '✅' : '❌';
  console.log(`${icon} [TEST ${step}] ${description}: ${status} ${details ? `(${details})` : ''}`);
}

async function runVerification() {
  console.log('======================================================================');
  console.log('VR_SOC — PHASE 02: AUTOMATED AUTHENTICATION HARDENING VERIFICATION');
  console.log('======================================================================\n');

  if (!supabaseAdmin) {
    throw new Error('Supabase Admin client is not configured.');
  }

  // Start test server instance
  const server = http.createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(TEST_PORT, '127.0.0.1', () => {
      console.log(`[Test Server] Running on ${BASE_URL}\n`);
      resolve();
    });
  });

  try {
    // 1. Protected endpoint without authentication returns 401
    try {
      const res = await fetch(`${BASE_URL}/api/alerts`);
      if (res.status === 401) {
        record(1, 'Protected endpoint without authentication returns 401', 'PASS', `HTTP ${res.status}`);
      } else {
        record(1, 'Protected endpoint without authentication returns 401', 'FAIL', `Expected 401, got ${res.status}`);
      }
    } catch (err: any) {
      record(1, 'Protected endpoint without authentication returns 401', 'FAIL', err.message);
    }

    // 2. Invalid authentication returns 401
    try {
      const res = await fetch(`${BASE_URL}/api/alerts`, {
        headers: { Authorization: 'Bearer invalid_garbage_token_xyz_123' }
      });
      if (res.status === 401) {
        record(2, 'Invalid authentication token returns 401', 'PASS', `HTTP ${res.status}`);
      } else {
        record(2, 'Invalid authentication token returns 401', 'FAIL', `Expected 401, got ${res.status}`);
      }
    } catch (err: any) {
      record(2, 'Invalid authentication token returns 401', 'FAIL', err.message);
    }

    // 3. Valid demo Supabase authentication succeeds
    let accessToken = '';
    let authUserId = '';
    try {
      const client = createClient(SUPABASE_URL, SUPABASE_ANON);
      const { data, error } = await client.auth.signInWithPassword({
        email: 'admin@vrsoc.cyber',
        password: 'VRSOC-Security2025!'
      });

      if (error || !data.session?.access_token) {
        record(3, 'Valid demo Supabase authentication succeeds', 'FAIL', error?.message || 'No token');
      } else {
        accessToken = data.session.access_token;
        authUserId = data.user.id;
        record(3, 'Valid demo Supabase authentication succeeds', 'PASS', `User ID: ${authUserId}`);
      }
    } catch (err: any) {
      record(3, 'Valid demo Supabase authentication succeeds', 'FAIL', err.message);
    }

    // 4. Valid Supabase access token resolves the correct user
    try {
      const verifiedUser = await verifySupabaseToken(accessToken);
      if (verifiedUser && verifiedUser.id === authUserId && verifiedUser.email === 'admin@vrsoc.cyber') {
        record(4, 'Valid Supabase access token resolves correct user', 'PASS', `${verifiedUser.email}`);
      } else {
        record(4, 'Valid Supabase access token resolves correct user', 'FAIL', `User mismatch`);
      }
    } catch (err: any) {
      record(4, 'Valid Supabase access token resolves correct user', 'FAIL', err.message);
    }

    // 5. Correct profile is resolved
    let resolvedProfileId = '';
    try {
      const profile = await db.getProfileById(authUserId);
      if (profile && profile.email === 'admin@vrsoc.cyber') {
        resolvedProfileId = profile.id;
        record(5, 'Correct application profile is resolved from PostgreSQL', 'PASS', `Role: ${profile.role}`);
      } else {
        record(5, 'Correct application profile is resolved from PostgreSQL', 'FAIL', 'Profile not found');
      }
    } catch (err: any) {
      record(5, 'Correct application profile is resolved from PostgreSQL', 'FAIL', err.message);
    }

    // 6. Correct organization membership is resolved
    try {
      const orgs = await db.getUserOrganizations(resolvedProfileId || authUserId);
      if (orgs.length > 0 && orgs[0].name === 'VRsecurity') {
        record(6, 'Correct organization membership is resolved', 'PASS', `Org: ${orgs[0].name} (${orgs[0].id})`);
      } else {
        record(6, 'Correct organization membership is resolved', 'FAIL', `Found ${orgs.length} orgs`);
      }
    } catch (err: any) {
      record(6, 'Correct organization membership is resolved', 'FAIL', err.message);
    }

    // 7. Authenticated protected request succeeds
    try {
      const res = await fetch(`${BASE_URL}/api/alerts`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (res.status === 200) {
        const data = await res.json();
        record(7, 'Authenticated protected API request succeeds', 'PASS', `Alerts count: ${data.alerts?.length ?? 0}`);
      } else {
        record(7, 'Authenticated protected API request succeeds', 'FAIL', `HTTP ${res.status}`);
      }
    } catch (err: any) {
      record(7, 'Authenticated protected API request succeeds', 'FAIL', err.message);
    }

    // 8. OTP values are absent from API responses
    try {
      const resResend = await fetch(`${BASE_URL}/api/auth/resend-email-otp`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const jsonResend = await resResend.json();
      const hasOtpLeak = Boolean(jsonResend.emailOtp || jsonResend.phoneOtp || jsonResend.otp || jsonResend.devHint);
      if (!hasOtpLeak) {
        record(8, 'OTP values and cleartext hints are absent from API responses', 'PASS', 'No OTP leaks');
      } else {
        record(8, 'OTP values and cleartext hints are absent from API responses', 'FAIL', JSON.stringify(jsonResend));
      }
    } catch (err: any) {
      record(8, 'OTP values and cleartext hints are absent from API responses', 'FAIL', err.message);
    }

    // 9. Service-role/secret values are not returned in public config
    try {
      const publicConfig = getPublicAuthConfig();
      const hasSecretKey = Boolean((publicConfig as any).supabaseServiceRoleKey || (publicConfig as any).serviceRoleKey);
      const resConfig = await fetch(`${BASE_URL}/api/auth/config`);
      const jsonConfig = await resConfig.json();
      const hasConfigSecret = Boolean(jsonConfig.supabaseServiceRoleKey || jsonConfig.serviceRoleKey || jsonConfig.service_role);

      if (!hasSecretKey && !hasConfigSecret) {
        record(9, 'Service-role/secret credentials are withheld from client responses', 'PASS', 'Safe public config');
      } else {
        record(9, 'Service-role/secret credentials are withheld from client responses', 'FAIL', 'Secret key detected in config');
      }
    } catch (err: any) {
      record(9, 'Service-role/secret credentials are withheld from client responses', 'FAIL', err.message);
    }

    // 10. /api/auth/me does not return a sessionToken field
    try {
      const resMe = await fetch(`${BASE_URL}/api/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const jsonMe = await resMe.json();
      if (resMe.status === 200 && jsonMe.profile && jsonMe.organization && !jsonMe.sessionToken) {
        record(10, '/api/auth/me returns profile & org without custom sessionToken field', 'PASS', `User: ${jsonMe.profile.email}`);
      } else {
        record(10, '/api/auth/me returns profile & org without custom sessionToken field', 'FAIL', `Returned: ${Object.keys(jsonMe).join(', ')}`);
      }
    } catch (err: any) {
      record(10, '/api/auth/me returns profile & org without custom sessionToken field', 'FAIL', err.message);
    }

    // 11. Logout clears application authentication state
    try {
      const resLogout = await fetch(`${BASE_URL}/api/auth/logout`, { method: 'POST' });
      const jsonLogout = await resLogout.json();
      if (resLogout.status === 200 && jsonLogout.success) {
        record(11, 'Logout endpoint terminates server cookies and returns success', 'PASS', jsonLogout.message);
      } else {
        record(11, 'Logout endpoint terminates server cookies and returns success', 'FAIL', `HTTP ${resLogout.status}`);
      }
    } catch (err: any) {
      record(11, 'Logout endpoint terminates server cookies and returns success', 'FAIL', err.message);
    }
  } finally {
    server.close();
  }

  console.log('\n======================================================================');
  const allPassed = results.every(r => r.status === 'PASS');
  console.log(`TOTAL TESTS: ${results.length} | PASSED: ${results.filter(r => r.status === 'PASS').length} | FAILED: ${results.filter(r => r.status === 'FAIL').length}`);
  console.log(`OVERALL STATUS: ${allPassed ? 'ALL PASS ✅' : 'FAIL ❌'}`);
  console.log('======================================================================\n');

  if (!allPassed) {
    process.exit(1);
  }
}

runVerification().catch((err) => {
  console.error('Fatal verification error:', err);
  process.exit(1);
});
