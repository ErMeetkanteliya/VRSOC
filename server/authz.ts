import express from 'express';
import { UserRole } from '../src/types';
import { db } from './db';

// Canonical Permissions for the existing VRSOC Product
export type Permission =
  // Organization & Security Key
  | 'org:read'
  | 'org:manage'
  | 'org:key:rotate'
  // Metrics & Dashboard
  | 'metrics:read'
  // Agents & Endpoints
  | 'agents:read'
  | 'agents:manage'
  | 'agents:revoke'
  // Telemetry & Simulation
  | 'telemetry:read'
  | 'telemetry:simulate'
  // Detection Rules
  | 'rules:read'
  | 'rules:manage'
  | 'rules:toggle'
  // Alerts & Comments
  | 'alerts:read'
  | 'alerts:update_status'
  | 'alerts:comment'
  | 'alerts:ai_analyze'
  // Incidents, Tasks & Timelines
  | 'incidents:read'
  | 'incidents:create'
  | 'incidents:update'
  | 'incidents:manage_tasks'
  | 'incidents:manage_timeline'
  | 'incidents:comment'
  // PhishGuard
  | 'phishguard:read'
  | 'phishguard:scan'
  | 'phishguard:promote'
  // Threat Intel & Indicators
  | 'indicators:read'
  | 'indicators:manage'
  // Audit Logs
  | 'audit:read'
  // Reports
  | 'reports:read'
  | 'reports:generate'
  // AI Copilot
  | 'ai:chat';

// Canonical Role-to-Permissions Mapping
export const ROLE_PERMISSIONS: Record<UserRole, readonly Permission[]> = {
  'Super Admin': [
    'org:read', 'org:manage', 'org:key:rotate',
    'metrics:read',
    'agents:read', 'agents:manage', 'agents:revoke',
    'telemetry:read', 'telemetry:simulate',
    'rules:read', 'rules:manage', 'rules:toggle',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create', 'incidents:update', 'incidents:manage_tasks', 'incidents:manage_timeline', 'incidents:comment',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read', 'indicators:manage',
    'audit:read',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'Organization Admin': [
    'org:read', 'org:manage', 'org:key:rotate',
    'metrics:read',
    'agents:read', 'agents:manage', 'agents:revoke',
    'telemetry:read', 'telemetry:simulate',
    'rules:read', 'rules:manage', 'rules:toggle',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create', 'incidents:update', 'incidents:manage_tasks', 'incidents:manage_timeline', 'incidents:comment',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read', 'indicators:manage',
    'audit:read',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'Instructor': [
    'org:read',
    'metrics:read',
    'agents:read', 'agents:manage', 'agents:revoke',
    'telemetry:read', 'telemetry:simulate',
    'rules:read', 'rules:manage', 'rules:toggle',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create', 'incidents:update', 'incidents:manage_tasks', 'incidents:manage_timeline', 'incidents:comment',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read', 'indicators:manage',
    'audit:read',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'SOC Analyst': [
    'org:read',
    'metrics:read',
    'agents:read', 'agents:manage', 'agents:revoke',
    'telemetry:read', 'telemetry:simulate',
    'rules:read', 'rules:manage', 'rules:toggle',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create', 'incidents:update', 'incidents:manage_tasks', 'incidents:manage_timeline', 'incidents:comment',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read', 'indicators:manage',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'Incident Responder': [
    'org:read',
    'metrics:read',
    'agents:read', 'agents:manage', 'agents:revoke',
    'telemetry:read',
    'rules:read',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create', 'incidents:update', 'incidents:manage_tasks', 'incidents:manage_timeline', 'incidents:comment',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'Threat Hunter': [
    'org:read',
    'metrics:read',
    'agents:read',
    'telemetry:read', 'telemetry:simulate',
    'rules:read', 'rules:manage', 'rules:toggle',
    'alerts:read', 'alerts:update_status', 'alerts:comment', 'alerts:ai_analyze',
    'incidents:read', 'incidents:create',
    'phishguard:read', 'phishguard:scan', 'phishguard:promote',
    'indicators:read', 'indicators:manage',
    'reports:read',
    'ai:chat'
  ],

  'Auditor': [
    'org:read',
    'metrics:read',
    'agents:read',
    'telemetry:read',
    'rules:read',
    'alerts:read', 'alerts:comment',
    'incidents:read',
    'phishguard:read',
    'indicators:read',
    'audit:read',
    'reports:read', 'reports:generate',
    'ai:chat'
  ],

  'Viewer': [
    'org:read',
    'metrics:read',
    'agents:read',
    'telemetry:read',
    'rules:read',
    'alerts:read',
    'incidents:read',
    'phishguard:read',
    'indicators:read',
    'reports:read'
  ],

  'Student': [
    'org:read',
    'metrics:read',
    'agents:read',
    'telemetry:read', 'telemetry:simulate',
    'rules:read',
    'alerts:read',
    'incidents:read',
    'phishguard:read', 'phishguard:scan',
    'indicators:read',
    'reports:read',
    'ai:chat'
  ]
};

/**
 * Checks if a given role has a specific permission
 */
export function hasPermission(role: UserRole | string | undefined, permission: Permission): boolean {
  if (!role) return false;
  const permissions = ROLE_PERMISSIONS[role as UserRole];
  if (!permissions) return false;
  return permissions.includes(permission);
}

/**
 * Checks if a given role has ANY of the specified permissions
 */
export function hasAnyPermission(role: UserRole | string | undefined, permissions: Permission[]): boolean {
  if (!role) return false;
  return permissions.some(p => hasPermission(role, p));
}

/**
 * Checks if a given role has ALL of the specified permissions
 */
export function hasAllPermissions(role: UserRole | string | undefined, permissions: Permission[]): boolean {
  if (!role) return false;
  return permissions.every(p => hasPermission(role, p));
}

/**
 * Helper to record authorization security audit log
 */
async function logAuthorizationFailure(req: express.Request, reason: string, requiredPermission?: string) {
  try {
    const user = req.user;
    const org = req.organization;
    if (org && user) {
      await db.addAuditLog({
        organizationId: org.id,
        userId: user.id,
        userEmail: user.email,
        action: 'ACCESS_DENIED',
        targetType: 'security_boundary',
        targetId: req.path,
        details: {
          method: req.method,
          path: req.path,
          userRole: user.role,
          requiredPermission,
          reason,
          ip: req.ip
        },
        ipAddress: req.ip
      });
    }
  } catch (err) {
    console.warn('[VRSOC AuthZ] Failed to record authorization audit log:', err);
  }
}

/**
 * Express Middleware: Requires authenticated user to hold a specific permission
 */
export function requirePermission(permission: Permission) {
  return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }

    if (!hasPermission(user.role, permission)) {
      await logAuthorizationFailure(req, `Role '${user.role}' lacks permission '${permission}'`, permission);
      res.status(403).json({
        error: `Forbidden. Your role '${user.role}' is not authorized to perform this operation.`
      });
      return;
    }

    next();
  };
}

/**
 * Express Middleware: Requires authenticated user to hold ANY of the specified permissions
 */
export function requireAnyPermission(...permissions: Permission[]) {
  return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }

    if (!hasAnyPermission(user.role, permissions)) {
      await logAuthorizationFailure(req, `Role '${user.role}' lacks any required permission: ${permissions.join(', ')}`);
      res.status(403).json({
        error: `Forbidden. Your role '${user.role}' is not authorized for this action.`
      });
      return;
    }

    next();
  };
}

/**
 * Express Middleware: Requires authenticated user to hold a specific role
 */
export function requireRole(...roles: UserRole[]) {
  return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }

    if (!roles.includes(user.role as UserRole)) {
      await logAuthorizationFailure(req, `Role '${user.role}' is not in allowed roles: ${roles.join(', ')}`);
      res.status(403).json({
        error: `Forbidden. Operation restricted to: ${roles.join(', ')}.`
      });
      return;
    }

    next();
  };
}
