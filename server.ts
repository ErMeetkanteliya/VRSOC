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
import { getPublicAuthConfig, checkSupabaseConfig } from './server/supabase';
import { requireAuth, getAuthContext, extractBearerToken } from './server/auth';
import { requirePermission, requireAnyPermission, requireRole } from './server/authz';
import {
  correlationIdMiddleware,
  securityHeadersMiddleware,
  corsMiddleware,
  authLimiter,
  aiLimiter,
  phishguardLimiter,
  agentEnrollLimiter,
  telemetryLimiter
} from './server/security';
import {
  validateRequest,
  idParamSchema,
  ruleIdParamSchema,
  reportIdParamSchema,
  environmentQuerySchema,
  completeOnboardingSchema,
  signupSchema,
  loginSchema,
  otpVerifySchema,
  mfaVerifySchema,
  agentEnrollSchema,
  agentHeartbeatSchema,
  agentTelemetrySchema,
  telemetrySimulateSchema,
  detectionRuleToggleSchema,
  detectionRuleCreateSchema,
  alertStatusUpdateSchema,
  alertCommentSchema,
  incidentCreateSchema,
  incidentUpdateSchema,
  incidentTaskCreateSchema,
  incidentTaskIdParamSchema,
  incidentTaskToggleSchema,
  incidentTimelineCreateSchema,
  incidentNoteCreateSchema,
  phishguardScanSchema,
  phishguardPromoteSchema,
  aiChatSchema,
  indicatorCreateSchema,
  reportGenerateSchema
} from './server/validator';
import { errorHandler } from './server/errorHandler';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Security & Correlation Middleware
app.use(correlationIdMiddleware);
app.use(securityHeadersMiddleware);
app.use(corsMiddleware);

// Request Parsing & Size Limits (Bounded to 1MB max)
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// -----------------------------------------------------------------------------
// AUTHENTICATION ROUTES (SINGLE AUTHORITY: SUPABASE AUTH)
// -----------------------------------------------------------------------------

// GET /api/auth/config - Public configuration for client-side Supabase SDK
app.get('/api/auth/config', (req, res) => {
  res.json(getPublicAuthConfig());
});

// POST /api/auth/complete-onboarding - Requires authenticated Supabase session
app.post(
  '/api/auth/complete-onboarding',
  authLimiter,
  requireAuth,
  validateRequest({ body: completeOnboardingSchema }),
  async (req, res, next) => {
    try {
      const user = req.user!;
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
        fullName: fullName ? fullName.trim() : user.fullName,
        phoneNumber: phoneNumber ? phoneNumber.trim() : user.phoneNumber,
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
      next(err);
    }
  }
);

// POST /api/auth/signup - Identity created via Supabase Auth
app.post(
  '/api/auth/signup',
  authLimiter,
  validateRequest({ body: signupSchema }),
  async (req, res, next) => {
    try {
      const { fullName, email, phoneNumber, organizationName } = req.body;

      const auth = await getAuthContext(req);
      if (auth) {
        const org = await db.createOrganization(organizationName.trim());
        const updatedProfile = await db.updateProfile(auth.profile.id, {
          fullName: fullName.trim(),
          phoneNumber: phoneNumber ? phoneNumber.trim() : auth.profile.phoneNumber,
          role: 'Organization Admin'
        });
        await db.addMember(org.id, updatedProfile.id, 'Organization Admin');

        return res.status(201).json({
          message: 'Organization registered successfully.',
          profile: updatedProfile,
          organization: org,
          vrSocKey: org.vrSocKey
        });
      }

      // If unauthenticated, advise client to sign up via Supabase Auth
      res.status(200).json({
        message: 'Account registration initiated. Please verify your credentials with Supabase Auth.'
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/auth/login - Verified via Supabase Auth session/token
app.post(
  '/api/auth/login',
  authLimiter,
  validateRequest({ body: loginSchema }),
  async (req, res, next) => {
    try {
      const auth = await getAuthContext(req);
      if (!auth) {
        return res.status(401).json({ error: 'Authentication required. Please sign in with Supabase Auth.' });
      }

      res.json({
        profile: auth.profile,
        organization: auth.organization
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/auth/resend-email-otp - Handled by Supabase Auth
app.post('/api/auth/resend-email-otp', authLimiter, requireAuth, (req, res) => {
  res.json({
    success: true,
    message: 'Verification code request accepted. Please check your email inbox.'
  });
});

// POST /api/auth/resend-phone-otp - Handled by Supabase Auth
app.post('/api/auth/resend-phone-otp', authLimiter, requireAuth, (req, res) => {
  res.json({
    success: true,
    message: 'Phone verification request accepted. Please check your mobile messages.'
  });
});

// POST /api/auth/verify-email-otp - Verified via Supabase Auth
app.post(
  '/api/auth/verify-email-otp',
  authLimiter,
  requireAuth,
  validateRequest({ body: otpVerifySchema }),
  async (req, res, next) => {
    try {
      const auth = req.auth!;
      res.json({
        success: true,
        profile: auth.profile,
        emailVerified: auth.user.emailConfirmed
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/auth/verify-phone-otp - Verified via Supabase Auth
app.post(
  '/api/auth/verify-phone-otp',
  authLimiter,
  requireAuth,
  validateRequest({ body: otpVerifySchema }),
  async (req, res, next) => {
    try {
      const auth = req.auth!;
      res.json({
        success: true,
        profile: auth.profile,
        phoneVerified: auth.user.phoneConfirmed
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/auth/mfa-setup - Directs to Supabase Auth MFA
app.post('/api/auth/mfa-setup', authLimiter, requireAuth, (req, res) => {
  const auth = req.auth!;
  res.json({
    message: 'Please enroll TOTP multi-factor authentication directly via Supabase Auth MFA.',
    userEmail: auth.user.email
  });
});

// POST /api/auth/mfa-verify - Verified via Supabase Auth MFA
app.post(
  '/api/auth/mfa-verify',
  authLimiter,
  requireAuth,
  validateRequest({ body: mfaVerifySchema }),
  async (req, res, next) => {
    try {
      const auth = req.auth!;
      res.json({
        success: true,
        profile: auth.profile,
        mfaEnabled: auth.profile.mfaEnabled
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// GET /api/auth/me - Authoritative identity and organization context
app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const auth = req.auth!;
    res.json({
      profile: auth.profile,
      organization: auth.organization,
      membership: auth.membership || null,
      user: {
        id: auth.user.id,
        email: auth.user.email,
        emailConfirmed: auth.user.emailConfirmed,
        phoneConfirmed: auth.user.phoneConfirmed
      }
    });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/auth/logout - Terminates server cookies/state
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('vrsoc_session');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// -----------------------------------------------------------------------------
// ORGANIZATION & KEY MANAGEMENT ROUTES
// -----------------------------------------------------------------------------

// POST /api/organizations/key/rotate
app.post('/api/organizations/key/rotate', requireAuth, requirePermission('org:key:rotate'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const user = req.user!;

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
    next(err);
  }
});

// GET /api/organizations/metrics
app.get(
  '/api/organizations/metrics',
  requireAuth,
  requirePermission('metrics:read'),
  validateRequest({ query: environmentQuerySchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const env = (req.query.environment as string) || 'production';
      const metrics = await db.getRealMetrics(org.id, env);
      res.json({ metrics });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// AGENTS MANAGEMENT & ENROLLMENT
// -----------------------------------------------------------------------------

// GET /api/agents
app.get('/api/agents', requireAuth, requirePermission('agents:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const agents = await db.getAgents(org.id);
    res.json({ agents });
  } catch (err: any) {
    next(err);
  }
});

// GET /api/agents/:id
app.get(
  '/api/agents/:id',
  requireAuth,
  requirePermission('agents:read'),
  validateRequest({ params: idParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const agent = await db.getAgentById(req.params.id, org.id);
      if (!agent) {
        return res.status(404).json({ error: 'Agent not found' });
      }
      const recentEvents = await db.getEndpointEvents(org.id, 50, agent.id);
      res.json({ agent, events: recentEvents });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/agents/:id/revoke
app.post(
  '/api/agents/:id/revoke',
  requireAuth,
  requirePermission('agents:revoke'),
  validateRequest({ params: idParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const agent = await db.getAgentById(req.params.id, org.id);
      if (!agent) {
        return res.status(404).json({ error: 'Agent not found' });
      }

      const updated = await db.revokeAgent(agent.id, org.id);
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
      next(err);
    }
  }
);

// POST /api/agent/enroll
app.post(
  '/api/agent/enroll',
  agentEnrollLimiter,
  validateRequest({ body: agentEnrollSchema }),
  async (req, res, next) => {
    try {
      const { enrollmentKey, name, hostname, os, osVersion, architecture, ipAddress, agentVersion } = req.body;

      const org = await db.getOrganizationByKey(enrollmentKey);
      if (!org || org.status !== 'active') {
        return res.status(401).json({ error: 'Invalid or revoked 14-character VRSOC security key.' });
      }

      const cleanHostname = hostname ? hostname.trim() : 'unknown-host';

      // Check if agent already registered with this hostname in this organization
      const agents = await db.getAgents(org.id);
      const existing = agents.find(a => a.hostname.toLowerCase() === cleanHostname.toLowerCase() && a.status !== 'revoked');
      if (existing) {
        const { rawToken } = db.generateAgentToken();
        const { agent: updated } = await db.updateAgent(existing.id, {
          ipAddress: ipAddress || req.ip || '127.0.0.1',
          lastSeen: new Date().toISOString(),
          status: 'online',
          agentVersion: agentVersion || '1.4.0',
          rawToken
        }, org.id);

        await db.addAuditLog({
          organizationId: org.id,
          action: 'AGENT_RE_ENROLLED',
          targetType: 'agent',
          targetId: updated.id,
          details: { hostname: updated.hostname, ip: updated.ipAddress },
          ipAddress: req.ip
        });

        broadcastEvent(org.id, 'agent_updated', updated);
        return res.json({ agent: updated, agentToken: rawToken });
      }

      const { agent, agentToken } = await db.createAgent({
        organizationId: org.id,
        name: name ? name.trim() : `${cleanHostname}-agent`,
        hostname: cleanHostname,
        os: os ? os.trim() : 'Linux',
        osVersion: osVersion ? osVersion.trim() : '1.0',
        architecture: architecture ? architecture.trim() : 'x64',
        ipAddress: ipAddress ? ipAddress.trim() : (req.ip || '127.0.0.1'),
        agentVersion: agentVersion ? agentVersion.trim() : '1.4.0',
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
      res.status(201).json({ agent, agentToken });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/agent/heartbeat
app.post(
  '/api/agent/heartbeat',
  telemetryLimiter,
  validateRequest({ body: agentHeartbeatSchema }),
  async (req, res, next) => {
    try {
      const { agentId, agentToken: bodyToken, cpuUsage, ramUsage, diskUsage, activeProcessesCount, networkConnectionsCount } = req.body;
      const bearerToken = extractBearerToken(req);
      const token = bodyToken || bearerToken;

      if (!token) {
        return res.status(401).json({ error: 'Missing agent credentials' });
      }

      const authenticatedAgent = await db.getAgentByToken(token);
      if (!authenticatedAgent) {
        return res.status(401).json({ error: 'Agent unauthorized or invalid token' });
      }

      if (authenticatedAgent.status === 'revoked') {
        return res.status(401).json({ error: 'Agent unauthorized or revoked' });
      }

      if (agentId && authenticatedAgent.id !== agentId) {
        return res.status(403).json({ error: 'Agent credential does not match requested agent ID' });
      }

      const { agent: updated } = await db.updateAgent(authenticatedAgent.id, {
        lastSeen: new Date().toISOString(),
        status: 'online',
        cpuUsage: typeof cpuUsage === 'number' ? cpuUsage : authenticatedAgent.cpuUsage,
        ramUsage: typeof ramUsage === 'number' ? ramUsage : authenticatedAgent.ramUsage,
        diskUsage: typeof diskUsage === 'number' ? diskUsage : authenticatedAgent.diskUsage
      }, authenticatedAgent.organizationId);

      await db.addAgentHeartbeat({
        agentId: authenticatedAgent.id,
        organizationId: authenticatedAgent.organizationId,
        cpuPercent: updated.cpuUsage,
        ramPercent: updated.ramUsage,
        diskPercent: updated.diskUsage,
        activeProcessesCount: activeProcessesCount || 45,
        networkConnectionsCount: networkConnectionsCount || 8
      });

      broadcastEvent(authenticatedAgent.organizationId, 'agent_heartbeat', {
        agentId: authenticatedAgent.id,
        lastSeen: updated.lastSeen,
        cpuUsage: updated.cpuUsage,
        ramUsage: updated.ramUsage
      });

      res.json({ status: 'ack', nextHeartbeatSeconds: 10 });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/agent/telemetry
app.post(
  '/api/agent/telemetry',
  telemetryLimiter,
  validateRequest({ body: agentTelemetrySchema }),
  async (req, res, next) => {
    try {
      const { agentId, agentToken: bodyToken, eventType, severity, data, eventTime } = req.body;
      const bearerToken = extractBearerToken(req);
      const token = bodyToken || bearerToken;

      if (!token) {
        return res.status(401).json({ error: 'Missing agent credentials' });
      }

      const authenticatedAgent = await db.getAgentByToken(token);
      if (!authenticatedAgent) {
        return res.status(401).json({ error: 'Agent unauthorized or invalid token' });
      }

      if (authenticatedAgent.status === 'revoked') {
        return res.status(401).json({ error: 'Agent unauthorized or revoked' });
      }

      if (agentId && authenticatedAgent.id !== agentId) {
        return res.status(403).json({ error: 'Agent credential does not match requested agent ID' });
      }

      // Timestamp sanitization: prevent future timestamp spoofing
      const now = Date.now();
      let sanitizedEventTime = new Date().toISOString();
      if (eventTime) {
        const parsedTime = new Date(eventTime).getTime();
        if (!isNaN(parsedTime) && parsedTime <= now + 300000 && parsedTime >= now - (30 * 86400000)) {
          sanitizedEventTime = new Date(eventTime).toISOString();
        }
      }

      const event = await db.addEndpointEvent({
        organizationId: authenticatedAgent.organizationId,
        agentId: authenticatedAgent.id,
        eventType: eventType || 'process',
        eventTime: sanitizedEventTime,
        source: 'vrsoc-agent',
        environment: authenticatedAgent.environment,
        severity: severity || 'info',
        data: data || {},
        schemaVersion: '1.0'
      });

      broadcastEvent(authenticatedAgent.organizationId, 'new_telemetry', event);
      broadcastEvent(authenticatedAgent.organizationId, 'new_event', { event });

      // Evaluate in real-time detection engine
      const triggeredAlert = await detectionEngine.evaluateEvent(event, authenticatedAgent);

      res.status(201).json({
        status: 'ingested',
        eventId: event.id,
        triggeredAlert: triggeredAlert ? triggeredAlert.id : null
      });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/telemetry/simulate
app.post(
  '/api/telemetry/simulate',
  requireAuth,
  requirePermission('telemetry:simulate'),
  validateRequest({ body: telemetrySimulateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
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
      next(err);
    }
  }
);

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
app.get('/api/detection-rules', requireAuth, requirePermission('rules:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const rules = await db.getDetectionRules(org.id);
    res.json({ rules });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/detection-rules/:id/toggle
app.post(
  '/api/detection-rules/:id/toggle',
  requireAuth,
  requirePermission('rules:toggle'),
  validateRequest({ params: ruleIdParamSchema, body: detectionRuleToggleSchema }),
  async (req, res, next) => {
    try {
      const { enabled } = req.body;
      const user = req.user!;
      const org = req.organization!;

      const updatedRule = await db.toggleDetectionRule(req.params.id, Boolean(enabled), org.id);
      if (!updatedRule) {
        return res.status(404).json({ error: 'Detection rule not found' });
      }

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
      next(err);
    }
  }
);

// POST /api/detection-rules
app.post(
  '/api/detection-rules',
  requireAuth,
  requirePermission('rules:manage'),
  validateRequest({ body: detectionRuleCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { name, description, severity, riskScore, category, mitreTactic, mitreTechniqueId, mitreTechniqueName, conditions, remediationSteps } = req.body;

      const id = `RULE-CUST-${Date.now().toString(36).toUpperCase()}`;
      const newRule = await db.addDetectionRule({
        id,
        organizationId: org.id,
        name: name.trim(),
        description: description.trim(),
        severity: severity || 'medium',
        riskScore: riskScore !== undefined ? riskScore : 60,
        category: category || 'Custom Detection',
        mitreTactic: mitreTactic || 'Execution',
        mitreTechniqueId: mitreTechniqueId.trim(),
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
        details: { name: newRule.name, severity: newRule.severity, mitreTechniqueId: newRule.mitreTechniqueId },
        ipAddress: req.ip
      });

      res.status(201).json({ rule: newRule });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// ALERTS ROUTES
// -----------------------------------------------------------------------------

// GET /api/alerts
app.get(
  '/api/alerts',
  requireAuth,
  requirePermission('alerts:read'),
  validateRequest({ query: environmentQuerySchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const env = (req.query.environment as string) || 'production';
      const alerts = await db.getAlerts(org.id, env);
      res.json({ alerts });
    } catch (err: any) {
      next(err);
    }
  }
);

// GET /api/alerts/:id
app.get(
  '/api/alerts/:id',
  requireAuth,
  requirePermission('alerts:read'),
  validateRequest({ params: idParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const alert = await db.getAlertById(req.params.id, org.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }
      res.json({ alert });
    } catch (err: any) {
      next(err);
    }
  }
);

// PATCH /api/alerts/:id/status
app.patch(
  '/api/alerts/:id/status',
  requireAuth,
  requirePermission('alerts:update_status'),
  validateRequest({ params: idParamSchema, body: alertStatusUpdateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { status } = req.body;

      const alert = await db.getAlertById(req.params.id, org.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      const updated = await db.updateAlert(alert.id, { status }, org.id);
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
      next(err);
    }
  }
);

// POST /api/alerts/:id/comment
app.post(
  '/api/alerts/:id/comment',
  requireAuth,
  requirePermission('alerts:comment'),
  validateRequest({ params: idParamSchema, body: alertCommentSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { comment } = req.body;

      const alert = await db.getAlertById(req.params.id, org.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      const updated = await db.addAlertComment(alert.id, user.id, user.fullName, comment.trim(), org.id);
      res.json({ alert: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/alerts/:id/ai-analyze
app.post(
  '/api/alerts/:id/ai-analyze',
  requireAuth,
  requirePermission('alerts:ai_analyze'),
  validateRequest({ params: idParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const alert = await db.getAlertById(req.params.id, org.id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      const aiSummary = await analyzeAlertWithAi(alert);
      const updated = await db.updateAlert(alert.id, { aiSummary }, org.id);

      res.json({ aiSummary, alert: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// INCIDENTS & CASE MANAGEMENT ROUTES
// -----------------------------------------------------------------------------

// GET /api/incidents
app.get(
  '/api/incidents',
  requireAuth,
  requirePermission('incidents:read'),
  validateRequest({ query: environmentQuerySchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const env = (req.query.environment as string) || 'production';
      const incidents = await db.getIncidents(org.id, env);
      res.json({ incidents });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/incidents
app.post(
  '/api/incidents',
  requireAuth,
  requirePermission('incidents:create'),
  validateRequest({ body: incidentCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { title, description, severity, priority, linkedAlertIds, environment } = req.body;

      // Verify all linkedAlertIds belong to the authenticated organization
      let validLinkedAlertIds: string[] = [];
      if (linkedAlertIds && Array.isArray(linkedAlertIds)) {
        for (const alertId of linkedAlertIds) {
          const found = await db.getAlertById(alertId, org.id);
          if (found) {
            validLinkedAlertIds.push(alertId);
          }
        }
      }

      const incident = await db.createIncident({
        organizationId: org.id,
        title: title.trim(),
        description: description.trim(),
        severity: severity || 'medium',
        status: 'open',
        priority: priority || 'P2',
        leadInvestigator: user.id,
        leadInvestigatorName: user.fullName,
        linkedAlertIds: validLinkedAlertIds,
        environment: environment || 'production'
      });

      await db.addAuditLog({
        organizationId: org.id,
        userId: user.id,
        userEmail: user.email,
        action: 'CREATE_INCIDENT',
        targetType: 'incident',
        targetId: incident.id,
        details: { title: incident.title, severity: incident.severity, priority: incident.priority },
        ipAddress: req.ip
      });

      broadcastEvent(org.id, 'new_incident', incident);
      res.status(201).json({ incident });
    } catch (err: any) {
      next(err);
    }
  }
);

// GET /api/incidents/:id
app.get(
  '/api/incidents/:id',
  requireAuth,
  requirePermission('incidents:read'),
  validateRequest({ params: idParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      const alertsList = await Promise.all(
        incident.linkedAlertIds.map(id => db.getAlertById(id, org.id))
      );
      const linkedAlerts = alertsList.filter(Boolean);

      res.json({ incident, linkedAlerts });
    } catch (err: any) {
      next(err);
    }
  }
);

// PATCH /api/incidents/:id (MASS-ASSIGNMENT PROTECTED)
app.patch(
  '/api/incidents/:id',
  requireAuth,
  requirePermission('incidents:update'),
  validateRequest({ params: idParamSchema, body: incidentUpdateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      // Safe whitelisted updates from validated body
      const updates = req.body;
      const updated = await db.updateIncident(incident.id, updates, org.id);

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
      next(err);
    }
  }
);

// POST /api/incidents/:id/task
app.post(
  '/api/incidents/:id/task',
  requireAuth,
  requirePermission('incidents:manage_tasks'),
  validateRequest({ params: idParamSchema, body: incidentTaskCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const { title } = req.body;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }
      const updated = await db.addIncidentTask(incident.id, title.trim(), undefined, org.id);
      res.json({ incident: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// PATCH /api/incidents/:id/task/:taskId
app.patch(
  '/api/incidents/:id/task/:taskId',
  requireAuth,
  requirePermission('incidents:manage_tasks'),
  validateRequest({ params: incidentTaskIdParamSchema, body: incidentTaskToggleSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const { completed } = req.body;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }
      const updated = await db.toggleIncidentTask(incident.id, req.params.taskId, Boolean(completed), org.id);
      res.json({ incident: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/incidents/:id/timeline
app.post(
  '/api/incidents/:id/timeline',
  requireAuth,
  requirePermission('incidents:manage_timeline'),
  validateRequest({ params: idParamSchema, body: incidentTimelineCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const { title, description, type, evidenceState } = req.body;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      const updated = await db.addIncidentTimelineItem(incident.id, {
        timestamp: new Date().toISOString(),
        title: title.trim(),
        description: description ? description.trim() : '',
        type: type ? type.trim() : 'observation',
        evidenceState: evidenceState || 'CONFIRMED'
      }, org.id);
      res.json({ incident: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// POST /api/incidents/:id/note
app.post(
  '/api/incidents/:id/note',
  requireAuth,
  requirePermission('incidents:comment'),
  validateRequest({ params: idParamSchema, body: incidentNoteCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { note } = req.body;
      const incident = await db.getIncidentById(req.params.id, org.id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      const updated = await db.addIncidentNote(incident.id, user.id, user.fullName, note.trim(), org.id);
      res.json({ incident: updated });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// PHISHGUARD ML INTEGRATION
// -----------------------------------------------------------------------------

// POST /api/phishguard/scan
app.post(
  '/api/phishguard/scan',
  phishguardLimiter,
  requireAuth,
  requirePermission('phishguard:scan'),
  validateRequest({ body: phishguardScanSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { url } = req.body;

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
      next(err);
    }
  }
);

// POST /api/phishguard/promote-to-alert
app.post(
  '/api/phishguard/promote-to-alert',
  requireAuth,
  requirePermission('phishguard:promote'),
  validateRequest({ body: phishguardPromoteSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { scanId } = req.body;

      const scan = await db.getPhishingScanById(scanId, org.id);
      if (!scan) {
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
      next(err);
    }
  }
);

// GET /api/phishguard/scans
app.get('/api/phishguard/scans', requireAuth, requirePermission('phishguard:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const scans = await db.getPhishingScans(org.id);
    res.json({ scans });
  } catch (err: any) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// AI SOC ASSISTANT & CHAT
// -----------------------------------------------------------------------------

// POST /api/ai/chat
app.post(
  '/api/ai/chat',
  aiLimiter,
  requireAuth,
  requirePermission('ai:chat'),
  validateRequest({ body: aiChatSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const { message, context } = req.body;

      const reply = await chatWithAiAnalyst(org.id, message.trim(), context);
      res.json({ reply });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// THREAT INTELLIGENCE & AUDIT LOGS
// -----------------------------------------------------------------------------

// GET /api/indicators
app.get('/api/indicators', requireAuth, requirePermission('indicators:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const indicators = await db.getIndicators(org.id);
    res.json({ indicators });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/indicators
app.post(
  '/api/indicators',
  requireAuth,
  requirePermission('indicators:manage'),
  validateRequest({ body: indicatorCreateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { type, value, threatActor, confidence, tags, description } = req.body;

      const indicator = await db.addIndicator({
        organizationId: org.id,
        type,
        value: value.trim(),
        threatActor: threatActor ? threatActor.trim() : 'Unknown Actor',
        confidence: confidence !== undefined ? confidence : 70,
        tags: tags || [],
        description: description ? description.trim() : ''
      });

      await db.addAuditLog({
        organizationId: org.id,
        userId: user.id,
        userEmail: user.email,
        action: 'ADD_INDICATOR',
        targetType: 'indicator',
        targetId: indicator.id,
        details: { type, value: indicator.value },
        ipAddress: req.ip
      });

      res.status(201).json({ indicator });
    } catch (err: any) {
      next(err);
    }
  }
);

// GET /api/audit-logs
app.get('/api/audit-logs', requireAuth, requirePermission('audit:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const logs = await db.getAuditLogs(org.id);
    res.json({ logs });
  } catch (err: any) {
    next(err);
  }
});

// -----------------------------------------------------------------------------
// REPORTS GENERATION
// -----------------------------------------------------------------------------

// POST /api/reports/generate
app.post(
  '/api/reports/generate',
  requireAuth,
  requirePermission('reports:generate'),
  validateRequest({ body: reportGenerateSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const user = req.user!;
      const { reportType, targetId } = req.body;

      let title = '';
      let content: Record<string, any> = {};

      if (reportType === 'incident' && targetId) {
        const incident = await db.getIncidentById(targetId, org.id);
        if (!incident) {
          return res.status(404).json({ error: 'Incident not found' });
        }
        const linkedAlerts = (await Promise.all(incident.linkedAlertIds.map(id => db.getAlertById(id, org.id)))).filter(Boolean);
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
        details: { reportType: report.reportType, title },
        ipAddress: req.ip
      });

      res.status(201).json({ report });
    } catch (err: any) {
      next(err);
    }
  }
);

// GET /api/reports
app.get('/api/reports', requireAuth, requirePermission('reports:read'), async (req, res, next) => {
  try {
    const org = req.organization!;
    const reports = await db.getReports(org.id);
    res.json({ reports });
  } catch (err: any) {
    next(err);
  }
});

// GET /api/reports/:id
app.get(
  '/api/reports/:id',
  requireAuth,
  requirePermission('reports:read'),
  validateRequest({ params: reportIdParamSchema }),
  async (req, res, next) => {
    try {
      const org = req.organization!;
      const report = await db.getReportById(req.params.id, org.id);
      if (!report) {
        return res.status(404).json({ error: 'Report not found' });
      }
      res.json({ report });
    } catch (err: any) {
      next(err);
    }
  }
);

// -----------------------------------------------------------------------------
// REAL-TIME SSE STREAM (Supports both /api/events/stream and /api/sse/stream)
// -----------------------------------------------------------------------------

async function handleSseStream(req: express.Request, res: express.Response, next: express.NextFunction) {
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
    next(err);
  }
}

app.get('/api/events/stream', handleSseStream);
app.get('/api/sse/stream', handleSseStream);

// -----------------------------------------------------------------------------
// CANONICAL ERROR HANDLER MIDDLEWARE (Must be mounted after all API routes)
// -----------------------------------------------------------------------------
app.use(errorHandler);

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

const isDirectRun = Boolean(
  process.argv[1] &&
  (process.argv[1].endsWith('server.ts') ||
   process.argv[1].endsWith('server.cjs') ||
   process.argv[1].endsWith('server.js'))
);

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  startServer();
}

export { app, startServer };
