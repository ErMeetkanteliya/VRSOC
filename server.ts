import 'dotenv/config';
import express from 'express';
import path from 'path';
import fs from 'fs';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { db, Profile } from './server/db';
import { detectionEngine } from './server/detectionEngine';
import { analyzeUrlWithPhishGuard } from './server/phishguard';
import { analyzeAlertWithAi, chatWithAiAnalyst } from './server/aiEngine';
import { registerClient, broadcastEvent } from './server/sse';
import { verifySupabaseToken, getPublicAuthConfig, checkSupabaseConfig } from './server/supabase';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());
app.use(cookieParser());

// Authentication Middleware with Supabase JWT support & local fallback
async function getAuthContext(req: express.Request) {
  try {
    const authHeader = req.headers.authorization;
    const token = (authHeader && authHeader.startsWith('Bearer '))
      ? authHeader.substring(7)
      : req.cookies?.vrsoc_session;

    if (!token) return null;

    // 1. Try Supabase verification first
    const supabaseUser = await verifySupabaseToken(token);
    if (supabaseUser) {
      let profile = (await db.getProfileById(supabaseUser.id)) || (supabaseUser.email ? await db.getProfileByEmail(supabaseUser.email) : null);
      if (!profile && supabaseUser.email) {
        profile = await db.createProfile(
          supabaseUser.email,
          supabaseUser.user_metadata?.full_name || supabaseUser.email.split('@')[0],
          supabaseUser.phone || supabaseUser.user_metadata?.phone_number,
          'SOC Analyst',
          supabaseUser.id,
          {
            emailVerified: Boolean(supabaseUser.email_confirmed_at),
            phoneVerified: Boolean(supabaseUser.phone_confirmed_at),
            mfaEnabled: Boolean(supabaseUser.factors && supabaseUser.factors.length > 0)
          }
        );
      } else if (profile) {
        const updates: Partial<Profile> = {};
        if (supabaseUser.email_confirmed_at && !profile.emailVerified) updates.emailVerified = true;
        if (supabaseUser.phone_confirmed_at && !profile.phoneVerified) updates.phoneVerified = true;
        if (Object.keys(updates).length > 0) {
          profile = await db.updateProfile(profile.id, updates);
        }
      }

      if (profile) {
        const orgs = await db.getUserOrganizations(profile.id);
        const organization = orgs[0] || null;
        return {
          profile,
          organization,
          sessionToken: token,
          supabaseUser
        };
      }
    }

    // 2. Fallback to local session token
    return await db.getSession(token);
  } catch (err) {
    console.error('Error in getAuthContext:', err);
    return null;
  }
}

async function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  try {
    const session = await getAuthContext(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }
    (req as any).user = session.profile;
    (req as any).organization = session.organization;
    (req as any).session = session;
    next();
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Authentication check failed' });
  }
}

// -----------------------------------------------------------------------------
// AUTHENTICATION ROUTES
// -----------------------------------------------------------------------------

// GET /api/auth/config
app.get('/api/auth/config', (req, res) => {
  res.json(getPublicAuthConfig());
});

// POST /api/auth/complete-onboarding
app.post('/api/auth/complete-onboarding', requireAuth, async (req, res) => {
  try {
    const user = (req as any).user;
    const { organizationName, fullName, phoneNumber } = req.body;

    if (!organizationName || !organizationName.trim()) {
      return res.status(400).json({ error: 'Organization name is required.' });
    }

    // Check if organization already exists for this user
    const existingOrgs = await db.getUserOrganizations(user.id);
    if (existingOrgs.length > 0) {
      return res.json({
        profile: user,
        organization: existingOrgs[0],
        vrSocKey: existingOrgs[0].vrSocKey,
        message: 'Organization already configured.'
      });
    }

    // Generate unique 14-character hexadecimal security key server-side
    const org = await db.createOrganization(organizationName.trim());

    // Update user profile with role Organization Admin & confirmed verification
    const updatedProfile = await db.updateProfile(user.id, {
      fullName: fullName || user.fullName,
      phoneNumber: phoneNumber || user.phoneNumber,
      role: 'Organization Admin',
      emailVerified: true
    });

    // Link user to organization
    await db.addMember(org.id, updatedProfile.id, 'Organization Admin');

    // Create audit log
    await db.addAuditLog({
      organizationId: org.id,
      userId: updatedProfile.id,
      userEmail: updatedProfile.email,
      action: 'ORGANIZATION_INITIALIZED',
      targetType: 'organization',
      targetId: org.id,
      details: {
        organizationName: org.name,
        vrSocKeyAssigned: org.vrSocKey,
        keyLength: org.vrSocKey.length
      },
      ipAddress: req.ip
    });

    res.status(201).json({
      success: true,
      profile: updatedProfile,
      organization: org,
      vrSocKey: org.vrSocKey
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to complete onboarding' });
  }
});

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, phoneNumber, organizationName } = req.body;
    if (!fullName || !email || !organizationName) {
      return res.status(400).json({ error: 'Full name, email, and organization name are required.' });
    }

    const existingUser = await db.getProfileByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // 1. Create Organization with unique 14-char hex key
    const org = await db.createOrganization(organizationName);

    // 2. Create User Profile
    const profile = await db.createProfile(
      email,
      fullName,
      phoneNumber,
      'Organization Admin',
      undefined,
      { emailVerified: false, phoneVerified: false, mfaEnabled: false }
    );

    // 3. Link Member to Organization
    await db.addMember(org.id, profile.id, 'Organization Admin');

    // 4. Generate email and phone OTPs
    const emailOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const phoneOtp = Math.floor(100000 + Math.random() * 900000).toString();
    db.setOtp(email.toLowerCase(), 'email', emailOtp, 10);
    if (phoneNumber) {
      db.setOtp(phoneNumber, 'phone', phoneOtp, 10);
    }

    // 5. Create Session
    const session = await db.createSession(profile.id, org.id, req.ip, req.headers['user-agent'] as string);

    // Set cookie
    res.cookie('vrsoc_session', session.sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: profile.id,
      userEmail: profile.email,
      action: 'USER_SIGNUP',
      targetType: 'user',
      targetId: profile.id,
      details: { organizationName: org.name, role: profile.role },
      ipAddress: req.ip
    });

    res.status(201).json({
      message: 'Signup successful. Please verify email and phone.',
      profile,
      organization: org,
      sessionToken: session.sessionToken,
      emailOtp,
      phoneOtp,
      verificationRequired: {
        email: true,
        phone: Boolean(phoneNumber),
        mfa: false
      },
      devHint: `Your verification code is: ${emailOtp}`
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Signup failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    const profile = await db.getProfileByEmail(email);
    if (!profile) {
      return res.status(404).json({ error: 'User account not found. Please sign up.' });
    }

    const orgs = await db.getUserOrganizations(profile.id);
    const org = orgs[0];
    if (!org) {
      return res.status(403).json({ error: 'No active organization found for user.' });
    }

    const session = await db.createSession(profile.id, org.id, req.ip, req.headers['user-agent'] as string);
    res.cookie('vrsoc_session', session.sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: profile.id,
      userEmail: profile.email,
      action: 'USER_LOGIN',
      targetType: 'user',
      targetId: profile.id,
      details: { role: profile.role },
      ipAddress: req.ip
    });

    res.json({
      profile,
      organization: org,
      sessionToken: session.sessionToken
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Login failed' });
  }
});

// POST /api/auth/resend-email-otp
app.post('/api/auth/resend-email-otp', requireAuth, (req, res) => {
  const user = (req as any).user;
  const emailOtp = Math.floor(100000 + Math.random() * 900000).toString();
  db.setOtp(user.email.toLowerCase(), 'email', emailOtp, 10);
  res.json({
    success: true,
    message: 'Verification code resent to your email.',
    emailOtp,
    devHint: `Your verification code is: ${emailOtp}`
  });
});

// POST /api/auth/resend-phone-otp
app.post('/api/auth/resend-phone-otp', requireAuth, (req, res) => {
  const user = (req as any).user;
  const phoneOtp = Math.floor(100000 + Math.random() * 900000).toString();
  const phoneKey = user.phoneNumber || user.email;
  db.setOtp(phoneKey, 'phone', phoneOtp, 10);
  res.json({
    success: true,
    message: 'Verification code resent to your phone.',
    phoneOtp,
    devHint: `Your verification code is: ${phoneOtp}`
  });
});

// POST /api/auth/verify-email-otp
app.post('/api/auth/verify-email-otp', requireAuth, async (req, res) => {
  try {
    const { otp } = req.body;
    const user = (req as any).user;
    if (!otp) return res.status(400).json({ error: 'OTP code required.' });

    const result = db.verifyOtp(user.email, 'email', otp);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }

    const updated = await db.updateProfile(user.id, { emailVerified: true });
    res.json({ success: true, profile: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Email verification failed' });
  }
});

// POST /api/auth/verify-phone-otp
app.post('/api/auth/verify-phone-otp', requireAuth, async (req, res) => {
  try {
    const { otp } = req.body;
    const user = (req as any).user;
    if (!otp) return res.status(400).json({ error: 'OTP code required.' });

    const result = db.verifyOtp(user.phoneNumber || user.email, 'phone', otp);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }

    const updated = await db.updateProfile(user.id, { phoneVerified: true });
    res.json({ success: true, profile: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Phone verification failed' });
  }
});

// POST /api/auth/mfa-setup
app.post('/api/auth/mfa-setup', requireAuth, (req, res) => {
  const user = (req as any).user;
  const mfaSecret = 'JBSWY3DPEHPK3PXP';
  res.json({
    mfaSecret,
    qrUri: `otpauth://totp/VRSOC:${encodeURIComponent(user.email)}?secret=${mfaSecret}&issuer=VRSOC`
  });
});

// POST /api/auth/mfa-verify
app.post('/api/auth/mfa-verify', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const user = (req as any).user;
    if (!token) return res.status(400).json({ error: 'Verification code required.' });

    if (!/^\d{6}$/.test(token.trim())) {
      return res.status(400).json({ error: 'Invalid TOTP format. Expected 6 digits.' });
    }

    const updated = await db.updateProfile(user.id, { mfaEnabled: true, mfaSecret: 'JBSWY3DPEHPK3PXP' });
    res.json({ success: true, profile: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'MFA verification failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', async (req, res) => {
  try {
    const session = await getAuthContext(req);
    if (!session) {
      return res.status(401).json({ error: 'Unauthenticated' });
    }
    res.json({
      profile: session.profile,
      organization: session.organization,
      sessionToken: session.sessionToken
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to resolve session' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = (authHeader && authHeader.startsWith('Bearer '))
      ? authHeader.substring(7)
      : req.cookies?.vrsoc_session;

    if (token) {
      await db.deleteSession(token);
    }
    res.clearCookie('vrsoc_session');
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Logout error' });
  }
});

// -----------------------------------------------------------------------------
// ORGANIZATION & KEY MANAGEMENT ROUTES
// -----------------------------------------------------------------------------

// POST /api/organizations/key/rotate
app.post('/api/organizations/key/rotate', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;

    if (user.role !== 'Super Admin' && user.role !== 'Organization Admin') {
      return res.status(403).json({ error: 'Only Organization Administrators can rotate the VRSOC security key.' });
    }

    const newKey = await db.rotateVrSocKey(org.id);
    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'ROTATE_VRSOC_KEY',
      targetType: 'organization',
      targetId: org.id,
      details: { oldKeyLength: 14, newKeyMasked: `${newKey.slice(0, 4)}...${newKey.slice(-4)}` },
      ipAddress: req.ip
    });

    res.json({
      success: true,
      vrSocKey: newKey,
      message: '14-character VRSOC security key rotated successfully.'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Key rotation failed' });
  }
});

// GET /api/organizations/metrics
app.get('/api/organizations/metrics', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const env = (req.query.environment as string) || 'production';
    const metrics = await db.getRealMetrics(org.id, env);
    res.json({ metrics });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch metrics' });
  }
});

// -----------------------------------------------------------------------------
// AGENTS MANAGEMENT & ENROLLMENT
// -----------------------------------------------------------------------------

// GET /api/agents
app.get('/api/agents', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const agents = await db.getAgents(org.id);
    res.json({ agents });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch agents' });
  }
});

// GET /api/agents/:id
app.get('/api/agents/:id', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const agent = await db.getAgentById(req.params.id);
    if (!agent || agent.organizationId !== org.id) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    const recentEvents = await db.getEndpointEvents(org.id, 50, agent.id);
    res.json({ agent, events: recentEvents });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch agent details' });
  }
});

// POST /api/agents/:id/revoke
app.post('/api/agents/:id/revoke', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const agent = await db.getAgentById(req.params.id);
    if (!agent || agent.organizationId !== org.id) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    const updated = await db.revokeAgent(agent.id);
    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'REVOKE_AGENT',
      targetType: 'agent',
      targetId: agent.id,
      details: { hostname: agent.hostname, ip: agent.ipAddress },
      ipAddress: req.ip
    });

    broadcastEvent(org.id, 'agent_updated', updated);
    res.json({ success: true, agent: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to revoke agent' });
  }
});

// POST /api/agent/enroll
app.post('/api/agent/enroll', async (req, res) => {
  try {
    const { enrollmentKey, name, hostname, os, osVersion, architecture, ipAddress, agentVersion } = req.body;
    if (!enrollmentKey) {
      return res.status(400).json({ error: 'Enrollment key is required.' });
    }

    const org = await db.getOrganizationByKey(enrollmentKey);
    if (!org) {
      return res.status(401).json({ error: 'Invalid or revoked 14-character VRSOC security key.' });
    }

    // Check if agent already registered with this hostname
    const agents = await db.getAgents(org.id);
    const existing = agents.find(a => a.hostname === hostname && a.status !== 'revoked');
    if (existing) {
      const updated = await db.updateAgent(existing.id, {
        ipAddress: ipAddress || req.ip || '127.0.0.1',
        lastSeen: new Date().toISOString(),
        status: 'online',
        agentVersion: agentVersion || '1.4.0'
      });
      broadcastEvent(org.id, 'agent_updated', updated);
      return res.json({ agent: updated, agentToken: updated.agentToken });
    }

    const agent = await db.createAgent({
      organizationId: org.id,
      name: name || `${hostname || 'Endpoint'}-agent`,
      hostname: hostname || 'unknown-host',
      os: os || 'Linux',
      osVersion: osVersion || '1.0',
      architecture: architecture || 'x64',
      ipAddress: ipAddress || req.ip || '127.0.0.1',
      agentVersion: agentVersion || '1.4.0',
      enrollmentKey: org.vrSocKey,
      status: 'online',
      lastSeen: new Date().toISOString(),
      cpuUsage: 10,
      ramUsage: 35,
      diskUsage: 40,
      tags: ['production', 'workstation'],
      policy: { telemetryIntervalSeconds: 10, logProcessEvents: true, logNetworkEvents: true },
      health: 'healthy',
      environment: 'production'
    });

    await db.addAuditLog({
      organizationId: org.id,
      action: 'AGENT_ENROLLED',
      targetType: 'agent',
      targetId: agent.id,
      details: { hostname: agent.hostname, os: agent.os, ip: agent.ipAddress },
      ipAddress: req.ip
    });

    broadcastEvent(org.id, 'agent_enrolled', agent);
    res.status(201).json({ agent, agentToken: agent.agentToken });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Agent enrollment failed' });
  }
});

// POST /api/agent/heartbeat
app.post('/api/agent/heartbeat', async (req, res) => {
  try {
    const { agentId, agentToken, cpuUsage, ramUsage, diskUsage } = req.body;
    if (!agentId || !agentToken) {
      return res.status(401).json({ error: 'Missing agent credentials' });
    }

    const agent = await db.getAgentById(agentId);
    if (!agent || agent.agentToken !== agentToken || agent.status === 'revoked') {
      return res.status(401).json({ error: 'Agent unauthorized or revoked' });
    }

    const updated = await db.updateAgent(agent.id, {
      lastSeen: new Date().toISOString(),
      status: 'online',
      cpuUsage: typeof cpuUsage === 'number' ? cpuUsage : agent.cpuUsage,
      ramUsage: typeof ramUsage === 'number' ? ramUsage : agent.ramUsage,
      diskUsage: typeof diskUsage === 'number' ? diskUsage : agent.diskUsage
    });

    broadcastEvent(agent.organizationId, 'agent_heartbeat', {
      agentId: agent.id,
      lastSeen: updated.lastSeen,
      cpuUsage: updated.cpuUsage,
      ramUsage: updated.ramUsage
    });

    res.json({ status: 'ack', nextHeartbeatSeconds: 10 });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Heartbeat processing failed' });
  }
});

// POST /api/agent/telemetry
app.post('/api/agent/telemetry', async (req, res) => {
  try {
    const { agentId, agentToken, eventType, severity, data } = req.body;
    if (!agentId || !agentToken) {
      return res.status(401).json({ error: 'Missing agent credentials' });
    }

    const agent = await db.getAgentById(agentId);
    if (!agent || agent.agentToken !== agentToken || agent.status === 'revoked') {
      return res.status(401).json({ error: 'Agent unauthorized or revoked' });
    }

    const event = await db.addEndpointEvent({
      organizationId: agent.organizationId,
      agentId: agent.id,
      eventType: eventType || 'process',
      eventTime: new Date().toISOString(),
      source: 'vrsoc-agent',
      environment: agent.environment,
      severity: severity || 'info',
      data: data || {},
      schemaVersion: '1.0'
    });

    broadcastEvent(agent.organizationId, 'new_telemetry', event);

    // Evaluate in real-time detection engine
    const triggeredAlert = await detectionEngine.evaluateEvent(event, agent);

    res.status(201).json({
      status: 'ingested',
      eventId: event.id,
      triggeredAlert: triggeredAlert ? triggeredAlert.id : null
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Telemetry ingestion failed' });
  }
});

// POST /api/telemetry/simulate
app.post('/api/telemetry/simulate', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { scenario, agentId } = req.body;

    const agents = await db.getAgents(org.id);
    let targetAgent = agentId ? agents.find(a => a.id === agentId) : agents[0];

    if (!targetAgent) {
      targetAgent = await db.createAgent({
        organizationId: org.id,
        name: 'Workstation SOC-Primary',
        hostname: 'vrsoc-workstation-01',
        os: 'Linux',
        osVersion: 'Ubuntu 22.04 LTS',
        architecture: 'x86_64',
        ipAddress: '192.168.10.45',
        agentVersion: '1.4.0',
        enrollmentKey: org.vrSocKey || 'VRSOC-DEMO-KEY',
        status: 'online',
        lastSeen: new Date().toISOString(),
        cpuUsage: 24,
        ramUsage: 42,
        diskUsage: 35,
        tags: ['workstation', 'linux'],
        policy: { scanIntervalSec: 15, isolationMode: false },
        health: 'healthy',
        environment: 'production'
      });
    }

    let eventType: 'process' | 'auth' | 'network' | 'usb' | 'file' = 'process';
    let eventSeverity: 'info' | 'low' | 'medium' | 'high' | 'critical' = 'high';
    let eventData: any = {};

    if (scenario === 'powershell_obfuscated' || !scenario) {
      eventType = 'process';
      eventSeverity = 'high';
      eventData = {
        action: 'EXECUTE',
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==',
        parentPid: 4920,
        parentProcess: 'cmd.exe',
        user: user.fullName || 'analyst',
        hostname: targetAgent.hostname
      };
    } else if (scenario === 'persistence_task') {
      eventType = 'process';
      eventSeverity = 'high';
      eventData = {
        action: 'SCHEDULED_TASK',
        processName: 'schtasks.exe',
        commandLine: 'schtasks /create /sc minute /mo 15 /tn "SystemTelemetryUpdater" /tr "C:\\Windows\\Temp\\update.bat"',
        parentPid: 1044,
        parentProcess: 'explorer.exe',
        user: 'Administrator',
        hostname: targetAgent.hostname
      };
    } else if (scenario === 'usb_storage') {
      eventType = 'usb';
      eventSeverity = 'medium';
      eventData = {
        action: 'mount',
        type: 'mass_storage',
        deviceName: 'Kingston DataTraveler 3.0',
        deviceId: 'USB\\VID_0951&PID_1666',
        vendor: 'Kingston Technology',
        user: user.fullName || 'analyst',
        hostname: targetAgent.hostname
      };
    } else if (scenario === 'auth_lockout') {
      eventType = 'auth';
      eventSeverity = 'medium';
      eventData = {
        action: 'account_locked',
        subType: 'lockout',
        username: 'finance_admin',
        sourceIp: '198.51.100.89',
        reason: 'Threshold of 5 invalid passwords exceeded',
        hostname: targetAgent.hostname
      };
    }

    const event = await db.addEndpointEvent({
      organizationId: org.id,
      agentId: targetAgent.id,
      environment: targetAgent.environment || 'production',
      eventType,
      severity: eventSeverity,
      source: 'simulation',
      data: eventData,
      eventTime: new Date().toISOString(),
      schemaVersion: '1.0'
    });

    broadcastEvent(org.id, 'new_event', { event });
    const triggeredAlert = await detectionEngine.evaluateEvent(event, targetAgent);

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'SIMULATE_THREAT_SCENARIO',
      targetType: 'telemetry_event',
      targetId: event.id,
      details: { scenario: scenario || 'powershell_obfuscated', agent: targetAgent.hostname, triggeredAlertId: triggeredAlert?.id },
      ipAddress: req.ip
    });

    res.json({
      success: true,
      event,
      agent: targetAgent,
      triggeredAlert: triggeredAlert || null
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Simulation failed' });
  }
});

// GET /api/agent/script
app.get('/api/agent/script', (req, res) => {
  const scriptPath = path.join(process.cwd(), 'agent', 'vrsoc-agent.js');
  if (fs.existsSync(scriptPath)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Content-Disposition', 'attachment; filename="vrsoc-agent.js"');
    return res.sendFile(scriptPath);
  }
  res.status(404).send('Agent script not found');
});

// -----------------------------------------------------------------------------
// DETECTION RULES ROUTES
// -----------------------------------------------------------------------------

// GET /api/detection-rules
app.get('/api/detection-rules', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const rules = await db.getDetectionRules(org.id);
    res.json({ rules });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch detection rules' });
  }
});

// POST /api/detection-rules/:id/toggle
app.post('/api/detection-rules/:id/toggle', requireAuth, async (req, res) => {
  try {
    const { enabled } = req.body;
    const user = (req as any).user;
    const org = (req as any).organization;

    await db.toggleDetectionRule(req.params.id, Boolean(enabled));
    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'TOGGLE_DETECTION_RULE',
      targetType: 'detection_rule',
      targetId: req.params.id,
      details: { enabled: Boolean(enabled) },
      ipAddress: req.ip
    });

    res.json({ success: true, ruleId: req.params.id, enabled: Boolean(enabled) });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to toggle rule' });
  }
});

// POST /api/detection-rules
app.post('/api/detection-rules', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { name, description, severity, riskScore, category, mitreTactic, mitreTechniqueId, mitreTechniqueName, conditions, remediationSteps } = req.body;

    if (!name || !description || !mitreTechniqueId) {
      return res.status(400).json({ error: 'Name, description, and MITRE Technique are required.' });
    }

    const id = `RULE-CUST-${Date.now().toString(36).toUpperCase()}`;
    const newRule = await db.addDetectionRule({
      id,
      organizationId: org.id,
      name,
      description,
      severity: severity || 'medium',
      riskScore: riskScore || 60,
      category: category || 'Custom Detection',
      mitreTactic: mitreTactic || 'Execution',
      mitreTechniqueId,
      mitreTechniqueName: mitreTechniqueName || 'Custom Technique',
      conditions: conditions || {},
      remediationSteps: remediationSteps || ['Inspect host processes', 'Review affected endpoint'],
      enabled: true,
      createdAt: new Date().toISOString()
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'CREATE_DETECTION_RULE',
      targetType: 'detection_rule',
      targetId: id,
      details: { name, severity, mitreTechniqueId },
      ipAddress: req.ip
    });

    res.status(201).json({ rule: newRule });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to create detection rule' });
  }
});

// -----------------------------------------------------------------------------
// ALERTS ROUTES
// -----------------------------------------------------------------------------

// GET /api/alerts
app.get('/api/alerts', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const env = (req.query.environment as string) || 'production';
    const alerts = await db.getAlerts(org.id, env);
    res.json({ alerts });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch alerts' });
  }
});

// GET /api/alerts/:id
app.get('/api/alerts/:id', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const alert = await db.getAlertById(req.params.id);
    if (!alert || alert.organizationId !== org.id) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    res.json({ alert });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch alert' });
  }
});

// PATCH /api/alerts/:id/status
app.patch('/api/alerts/:id/status', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { status } = req.body;

    const validStatuses = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
    }

    const alert = await db.getAlertById(req.params.id);
    if (!alert || alert.organizationId !== org.id) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    const updated = await db.updateAlert(alert.id, { status });
    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'UPDATE_ALERT_STATUS',
      targetType: 'alert',
      targetId: alert.id,
      details: { oldStatus: alert.status, newStatus: status },
      ipAddress: req.ip
    });

    broadcastEvent(org.id, 'alert_updated', updated);
    res.json({ alert: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update alert status' });
  }
});

// POST /api/alerts/:id/comment
app.post('/api/alerts/:id/comment', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { comment } = req.body;

    if (!comment || !comment.trim()) {
      return res.status(400).json({ error: 'Comment text cannot be empty' });
    }

    const alert = await db.getAlertById(req.params.id);
    if (!alert || alert.organizationId !== org.id) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    const updated = await db.addAlertComment(alert.id, user.id, user.fullName, comment.trim());
    res.json({ alert: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to add comment' });
  }
});

// POST /api/alerts/:id/ai-analyze
app.post('/api/alerts/:id/ai-analyze', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const alert = await db.getAlertById(req.params.id);
    if (!alert || alert.organizationId !== org.id) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    const aiSummary = await analyzeAlertWithAi(alert);
    const updated = await db.updateAlert(alert.id, { aiSummary });

    res.json({ aiSummary, alert: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'AI analysis failed' });
  }
});

// -----------------------------------------------------------------------------
// INCIDENTS & CASE MANAGEMENT ROUTES
// -----------------------------------------------------------------------------

// GET /api/incidents
app.get('/api/incidents', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const env = (req.query.environment as string) || 'production';
    const incidents = await db.getIncidents(org.id, env);
    res.json({ incidents });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch incidents' });
  }
});

// POST /api/incidents
app.post('/api/incidents', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { title, description, severity, priority, linkedAlertIds, environment } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required.' });
    }

    const incident = await db.createIncident({
      organizationId: org.id,
      title,
      description,
      severity: severity || 'medium',
      status: 'open',
      priority: priority || 'P2',
      leadInvestigator: user.id,
      leadInvestigatorName: user.fullName,
      linkedAlertIds: linkedAlertIds || [],
      environment: environment || 'production'
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'CREATE_INCIDENT',
      targetType: 'incident',
      targetId: incident.id,
      details: { title, severity, priority },
      ipAddress: req.ip
    });

    broadcastEvent(org.id, 'new_incident', incident);
    res.status(201).json({ incident });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to create incident' });
  }
});

// GET /api/incidents/:id
app.get('/api/incidents/:id', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const alertsList = await Promise.all(
      incident.linkedAlertIds.map(id => db.getAlertById(id))
    );
    const linkedAlerts = alertsList.filter(Boolean);

    res.json({ incident, linkedAlerts });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch incident' });
  }
});

// PATCH /api/incidents/:id
app.patch('/api/incidents/:id', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const updates = req.body;
    const updated = await db.updateIncident(incident.id, updates);

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'UPDATE_INCIDENT',
      targetType: 'incident',
      targetId: incident.id,
      details: updates,
      ipAddress: req.ip
    });

    res.json({ incident: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update incident' });
  }
});

// POST /api/incidents/:id/task
app.post('/api/incidents/:id/task', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const { title } = req.body;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    const updated = await db.addIncidentTask(incident.id, title);
    res.json({ incident: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to add incident task' });
  }
});

// PATCH /api/incidents/:id/task/:taskId
app.patch('/api/incidents/:id/task/:taskId', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const { completed } = req.body;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    const updated = await db.toggleIncidentTask(incident.id, req.params.taskId, Boolean(completed));
    res.json({ incident: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to toggle incident task' });
  }
});

// POST /api/incidents/:id/timeline
app.post('/api/incidents/:id/timeline', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const { title, description, type, evidenceState } = req.body;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const updated = await db.addIncidentTimelineItem(incident.id, {
      timestamp: new Date().toISOString(),
      title,
      description: description || '',
      type: type || 'observation',
      evidenceState: evidenceState || 'CONFIRMED'
    });
    res.json({ incident: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to add timeline item' });
  }
});

// POST /api/incidents/:id/note
app.post('/api/incidents/:id/note', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { note } = req.body;
    const incident = await db.getIncidentById(req.params.id);
    if (!incident || incident.organizationId !== org.id) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const updated = await db.addIncidentNote(incident.id, user.id, user.fullName, note);
    res.json({ incident: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to add incident note' });
  }
});

// -----------------------------------------------------------------------------
// PHISHGUARD ML INTEGRATION
// -----------------------------------------------------------------------------

// POST /api/phishguard/scan
app.post('/api/phishguard/scan', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { url } = req.body;

    if (!url || !url.trim()) {
      return res.status(400).json({ error: 'URL is required for analysis.' });
    }

    const analysis = analyzeUrlWithPhishGuard(url.trim());

    // Persist real scan record
    const scan = await db.addPhishingScan({
      organizationId: org.id,
      userId: user.id,
      url: analysis.url,
      normalizedUrl: analysis.normalizedUrl,
      classification: analysis.classification,
      riskScore: analysis.riskScore,
      features: analysis.features,
      reasons: analysis.reasons
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'PHISHGUARD_SCAN',
      targetType: 'phishing_scan',
      targetId: scan.id,
      details: { url: analysis.url, classification: analysis.classification, riskScore: analysis.riskScore },
      ipAddress: req.ip
    });

    res.json({ scan, analysis });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'PhishGuard scan failed' });
  }
});

// POST /api/phishguard/promote-to-alert
app.post('/api/phishguard/promote-to-alert', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { scanId } = req.body;

    const scan = await db.getPhishingScanById(scanId);
    if (!scan || scan.organizationId !== org.id) {
      return res.status(404).json({ error: 'Phishing scan record not found' });
    }

    if (scan.promotedToAlertId) {
      return res.status(400).json({ error: 'Scan has already been promoted to alert', alertId: scan.promotedToAlertId });
    }

    const alert = await db.createAlert({
      organizationId: org.id,
      ruleId: 'RULE-PHISH-001',
      title: `High-Risk Phishing URL Ingested: ${scan.features.subdomainsCount > 0 ? scan.url.slice(0, 45) : scan.url}`,
      description: `PhishGuard ML flagged URL '${scan.url}' with risk score ${scan.riskScore}/100. Reasons: ${scan.reasons.join(' ')}`,
      severity: scan.riskScore >= 80 ? 'critical' : 'high',
      riskScore: scan.riskScore,
      status: 'open',
      hostname: 'Network Edge / Mail Gateway',
      username: user.fullName,
      mitreTactic: 'Initial Access',
      mitreTechnique: 'Phishing: Spearphishing Link',
      mitreId: 'T1566.002',
      evidence: [
        {
          type: 'PhishGuard ML Feature Extraction',
          description: `Features: ${JSON.stringify(scan.features)}`,
          timestamp: scan.createdAt,
          data: scan.features,
          state: 'CONFIRMED'
        },
        {
          type: 'Detection Reasons',
          description: scan.reasons.join('; '),
          timestamp: scan.createdAt,
          data: { reasons: scan.reasons },
          state: 'CONFIRMED'
        }
      ],
      triggerEventIds: [],
      environment: 'production'
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'PHISHGUARD_PROMOTED_TO_ALERT',
      targetType: 'alert',
      targetId: alert.id,
      details: { url: scan.url, alertId: alert.id },
      ipAddress: req.ip
    });

    broadcastEvent(org.id, 'new_alert', alert);
    res.json({ success: true, alert });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Promotion to alert failed' });
  }
});

// GET /api/phishguard/scans
app.get('/api/phishguard/scans', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const scans = await db.getPhishingScans(org.id);
    res.json({ scans });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch phishing scans' });
  }
});

// -----------------------------------------------------------------------------
// AI SOC ASSISTANT & CHAT
// -----------------------------------------------------------------------------

// POST /api/ai/chat
app.post('/api/ai/chat', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const { message, context } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    const reply = await chatWithAiAnalyst(org.id, message.trim(), context);
    res.json({ reply });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'AI assistant failed' });
  }
});

// -----------------------------------------------------------------------------
// THREAT INTELLIGENCE & AUDIT LOGS
// -----------------------------------------------------------------------------

// GET /api/indicators
app.get('/api/indicators', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const indicators = await db.getIndicators(org.id);
    res.json({ indicators });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch indicators' });
  }
});

// POST /api/indicators
app.post('/api/indicators', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { type, value, threatActor, confidence, tags, description } = req.body;

    if (!type || !value) {
      return res.status(400).json({ error: 'Type and value are required for IOC.' });
    }

    const indicator = await db.addIndicator({
      organizationId: org.id,
      type,
      value,
      threatActor: threatActor || 'Unknown Actor',
      confidence: confidence || 70,
      tags: tags || [],
      description: description || ''
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'ADD_INDICATOR',
      targetType: 'indicator',
      targetId: indicator.id,
      details: { type, value },
      ipAddress: req.ip
    });

    res.status(201).json({ indicator });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to add indicator' });
  }
});

// GET /api/audit-logs
app.get('/api/audit-logs', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const logs = await db.getAuditLogs(org.id);
    res.json({ logs });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch audit logs' });
  }
});

// -----------------------------------------------------------------------------
// REPORTS GENERATION
// -----------------------------------------------------------------------------

// POST /api/reports/generate
app.post('/api/reports/generate', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const user = (req as any).user;
    const { reportType, targetId } = req.body;

    let title = '';
    let content: Record<string, any> = {};

    if (reportType === 'incident' && targetId) {
      const incident = await db.getIncidentById(targetId);
      if (!incident || incident.organizationId !== org.id) {
        return res.status(404).json({ error: 'Incident not found' });
      }
      const linkedAlerts = (await Promise.all(incident.linkedAlertIds.map(id => db.getAlertById(id)))).filter(Boolean);
      title = `Incident Investigation Report: ${incident.id} — ${incident.title}`;
      content = {
        incidentId: incident.id,
        title: incident.title,
        description: incident.description,
        severity: incident.severity,
        priority: incident.priority,
        status: incident.status,
        leadInvestigator: incident.leadInvestigatorName || 'Unassigned',
        createdAt: incident.createdAt,
        timeline: incident.timeline,
        tasks: incident.tasks,
        notes: incident.notes,
        linkedAlerts: linkedAlerts.map(a => ({
          id: a?.id,
          title: a?.title,
          severity: a?.severity,
          mitreTechnique: a?.mitreTechnique,
          hostname: a?.hostname,
          evidence: a?.evidence
        }))
      };
    } else if (reportType === 'executive') {
      const metrics = await db.getRealMetrics(org.id);
      title = `VRSOC Executive Cybersecurity Summary — ${new Date().toLocaleDateString()}`;
      content = {
        generatedFor: org.name,
        metrics,
        activeThreatPosture: metrics.criticalAlertsCount > 0 ? 'HEIGHTENED DEFENSIVE POSTURE' : 'NOMINAL MONITORING',
        recommendations: [
          'Ensure all production workstations maintain active VRSOC endpoint agent heartbeats.',
          'Review and resolve any open high or critical alerts in the active queue.',
          'Conduct phishing simulation reviews for repeat domains detected in PhishGuard.'
        ]
      };
    } else {
      title = `SOC Telemetry Report — ${new Date().toLocaleDateString()}`;
      content = { summary: 'General telemetry and endpoint status' };
    }

    const report = await db.addReport({
      organizationId: org.id,
      generatedBy: user.id,
      title,
      reportType: reportType || 'executive',
      targetId,
      content
    });

    await db.addAuditLog({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: 'GENERATE_REPORT',
      targetType: 'report',
      targetId: report.id,
      details: { reportType, title },
      ipAddress: req.ip
    });

    res.status(201).json({ report });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Report generation failed' });
  }
});

// GET /api/reports
app.get('/api/reports', requireAuth, async (req, res) => {
  try {
    const org = (req as any).organization;
    const reports = await db.getReports(org.id);
    res.json({ reports });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch reports' });
  }
});

// -----------------------------------------------------------------------------
// REAL-TIME SSE STREAM (Supports both /api/events/stream and /api/sse/stream)
// -----------------------------------------------------------------------------

async function handleSseStream(req: express.Request, res: express.Response) {
  try {
    const session = await getAuthContext(req);
    if (!session) {
      return res.status(401).json({ error: 'Authentication required for live SSE stream.' });
    }

    const userId = session.profile.id;
    const orgId = session.organization?.id;
    if (!orgId) {
      return res.status(400).json({ error: 'No active organization found for SSE connection.' });
    }

    const clientId = `${userId}-${Date.now()}`;
    registerClient(clientId, orgId, res);
  } catch (err: any) {
    console.error('SSE Stream error:', err);
    res.status(500).json({ error: 'SSE stream connection error' });
  }
}

app.get('/api/events/stream', handleSseStream);
app.get('/api/sse/stream', handleSseStream);

// -----------------------------------------------------------------------------
// VITE MIDDLEWARE / STATIC ASSETS
// -----------------------------------------------------------------------------

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  checkSupabaseConfig();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[VRSOC Server] Listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
