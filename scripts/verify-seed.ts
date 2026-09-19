import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '../server/supabase';
import { db } from '../server/db';

async function main() {
  if (!supabaseAdmin) {
    throw new Error('Supabase Admin client is not configured.');
  }

  const admin = supabaseAdmin;
  console.log('=== PHASE 01A SEED DATA & AUTH VERIFICATION ===\n');

  // 1. Table Record Counts
  const tables = [
    'organizations',
    'profiles',
    'organization_members',
    'agents',
    'detection_rules',
    'endpoint_events',
    'alerts',
    'alert_comments',
    'incidents',
    'incident_alerts',
    'incident_tasks',
    'incident_timeline',
    'phishing_scans',
    'indicators',
    'audit_logs',
    'reports'
  ];

  console.log('--- 1. Database Table Counts ---');
  const counts: Record<string, number> = {};
  for (const t of tables) {
    const { count, error } = await admin.from(t).select('*', { count: 'exact', head: true });
    if (error) {
      console.error(`Error querying ${t}:`, error.message);
      counts[t] = -1;
    } else {
      counts[t] = count || 0;
      console.log(`${t.padEnd(24)}: ${counts[t]}`);
    }
  }

  // 2. Auth User Verification
  console.log('\n--- 2. Supabase Auth Verification ---');
  const { data: userList } = await admin.auth.admin.listUsers();
  const demoUser = userList?.users?.find(u => u.email === 'admin@vrsoc.cyber');
  console.log('Auth user found:', Boolean(demoUser));
  console.log('Auth user ID:', demoUser?.id);
  console.log('Auth user email confirmed:', Boolean(demoUser?.email_confirmed_at));

  // 3. Client Sign-In Verification (simulating frontend login)
  console.log('\n--- 3. Client Sign-In with Password ---');
  const anonClient = createClient(
    process.env.VITE_SUPABASE_URL || 'http://127.0.0.1:54321',
    process.env.VITE_SUPABASE_ANON_KEY || ''
  );

  const { data: authData, error: authError } = await anonClient.auth.signInWithPassword({
    email: 'admin@vrsoc.cyber',
    password: 'VRSOC-Security2025!'
  });

  if (authError) {
    console.error('Sign-in failed:', authError.message);
  } else {
    console.log('Sign-in SUCCESS!');
    console.log('Access token acquired:', Boolean(authData.session?.access_token));
    console.log('User identity:', authData.user?.email);
  }

  // 4. Domain Layer Queries (using server/db.ts)
  console.log('\n--- 4. Backend Database Access Layer Verification ---');
  const orgs = await db.getUserOrganizations(demoUser!.id);
  console.log(`db.getUserOrganizations(): ${orgs.length} orgs found`);
  const demoOrg = orgs[0];
  console.log('Primary Demo Org:', demoOrg?.name, `(${demoOrg?.id})`);

  if (demoOrg) {
    const agents = await db.getAgents(demoOrg.id);
    console.log(`db.getAgents(${demoOrg.name}): ${agents.length} agents`);

    const alerts = await db.getAlerts(demoOrg.id);
    console.log(`db.getAlerts(${demoOrg.name}): ${alerts.length} alerts`);

    const incidents = await db.getIncidents(demoOrg.id);
    console.log(`db.getIncidents(${demoOrg.name}): ${incidents.length} incidents`);

    const rules = await db.getDetectionRules(demoOrg.id);
    console.log(`db.getDetectionRules(): ${rules.length} rules`);

    const metrics = await db.getRealMetrics(demoOrg.id);
    console.log('db.getRealMetrics():', metrics);
  }

  console.log('\n=== ALL VERIFICATIONS COMPLETE ===');
}

main().catch(console.error);
