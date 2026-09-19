import { z, ZodSchema } from 'zod';
import { Request, Response, NextFunction } from 'express';

// -----------------------------------------------------------------------------
// REQUEST VALIDATION MIDDLEWARE HELPER
// -----------------------------------------------------------------------------
interface ValidationSchemas {
  body?: ZodSchema<any>;
  query?: ZodSchema<any>;
  params?: ZodSchema<any>;
}

export function validateRequest(schemas: ValidationSchemas) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (schemas.params) {
        req.params = await schemas.params.parseAsync(req.params);
      }
      if (schemas.query) {
        req.query = await schemas.query.parseAsync(req.query);
      }
      if (schemas.body) {
        req.body = await schemas.body.parseAsync(req.body);
      }
      next();
    } catch (err: any) {
      if (err instanceof z.ZodError) {
        const details = err.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        }));
        return res.status(400).json({
          error: details[0]?.message || 'Validation failed',
          details,
          requestId: req.id
        });
      }
      next(err);
    }
  };
}

// -----------------------------------------------------------------------------
// SCHEMAS: COMMON & REUSABLE
// -----------------------------------------------------------------------------
export const idParamSchema = z.object({
  id: z.string().trim().min(1, 'Identifier is required').max(100, 'Identifier too long')
});

export const ruleIdParamSchema = z.object({
  id: z.string().trim().min(1, 'Rule identifier is required').max(100, 'Rule identifier too long')
});

export const reportIdParamSchema = z.object({
  id: z.string().trim().min(1, 'Report identifier is required').max(100, 'Report identifier too long')
});

export const environmentQuerySchema = z.object({
  environment: z.enum(['production', 'training', 'test', 'all', 'staging']).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: AUTHENTICATION
// -----------------------------------------------------------------------------
export const completeOnboardingSchema = z.object({
  organizationName: z.string().trim().min(1, 'Organization name is required.').max(100),
  fullName: z.string().trim().max(100).optional(),
  phoneNumber: z.string().trim().max(25).optional()
});

export const signupSchema = z.object({
  fullName: z.string().trim().min(1, 'Full name, email, and organization name are required.').max(100),
  email: z.string().trim().email('Invalid email format').max(255),
  phoneNumber: z.string().trim().max(25).optional(),
  organizationName: z.string().trim().min(1, 'Full name, email, and organization name are required.').max(100),
  password: z.string().max(128).optional()
});

export const loginSchema = z.object({
  email: z.string().trim().email().optional(),
  password: z.string().max(128).optional()
});

export const otpVerifySchema = z.object({
  otp: z.string().trim().max(20).optional()
});

export const mfaVerifySchema = z.object({
  token: z.string().trim().max(20).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: AGENTS & TELEMETRY
// -----------------------------------------------------------------------------
export const agentEnrollSchema = z.object({
  enrollmentKey: z.string().trim().min(1, 'Enrollment key is required.').max(64),
  name: z.string().trim().max(100).optional(),
  hostname: z.string().trim().max(100).optional(),
  os: z.string().trim().max(50).optional(),
  osVersion: z.string().trim().max(50).optional(),
  architecture: z.string().trim().max(50).optional(),
  ipAddress: z.string().trim().max(64).optional(),
  agentVersion: z.string().trim().max(50).optional()
});

export const agentHeartbeatSchema = z.object({
  agentId: z.string().trim().max(100).optional(),
  agentToken: z.string().trim().max(128).optional(),
  cpuUsage: z.number().min(0).max(100).optional(),
  ramUsage: z.number().min(0).max(100).optional(),
  diskUsage: z.number().min(0).max(100).optional()
});

export const agentTelemetrySchema = z.object({
  agentId: z.string().trim().max(100).optional(),
  agentToken: z.string().trim().max(128).optional(),
  eventType: z.enum(['process', 'file', 'network', 'auth', 'dns', 'registry', 'service', 'usb']).optional(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  data: z.record(z.any()).optional()
});

export const telemetrySimulateSchema = z.object({
  scenario: z.enum(['powershell_obfuscated', 'persistence_task', 'usb_storage', 'auth_lockout']).optional(),
  agentId: z.string().trim().max(100).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: DETECTION RULES
// -----------------------------------------------------------------------------
export const detectionRuleToggleSchema = z.object({
  enabled: z.boolean({ invalid_type_error: 'Enabled status must be a boolean' })
});

export const detectionRuleCreateSchema = z.object({
  name: z.string().trim().min(1, 'Name, description, and MITRE Technique are required.').max(150),
  description: z.string().trim().min(1, 'Name, description, and MITRE Technique are required.').max(1000),
  severity: z.enum(['informational', 'low', 'medium', 'high', 'critical']).optional(),
  riskScore: z.number().min(0).max(100).optional(),
  category: z.string().trim().max(100).optional(),
  mitreTactic: z.string().trim().max(100).optional(),
  mitreTechniqueId: z.string().trim().min(1, 'Name, description, and MITRE Technique are required.').max(50),
  mitreTechniqueName: z.string().trim().max(100).optional(),
  conditions: z.record(z.any()).optional(),
  remediationSteps: z.array(z.string().max(300)).max(20).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: ALERTS
// -----------------------------------------------------------------------------
export const alertStatusUpdateSchema = z.object({
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'false_positive'], {
    errorMap: () => ({ message: 'Invalid status. Must be one of: open, investigating, contained, resolved, false_positive' })
  })
});

export const alertAssignSchema = z.object({
  assignedTo: z.string().trim().max(100).nullable().optional()
});

export const alertLinkIncidentSchema = z.object({
  incidentId: z.string().trim().min(1, 'Incident ID is required.').max(100)
});

export const alertCommentSchema = z.object({
  comment: z.string().trim().min(1, 'Comment text cannot be empty').max(2000)
});

export const alertFilterQuerySchema = z.object({
  environment: z.enum(['production', 'training', 'test', 'all', 'staging']).optional(),
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'false_positive', 'all']).optional(),
  severity: z.enum(['informational', 'low', 'medium', 'high', 'critical', 'all']).optional(),
  agentId: z.string().trim().max(100).optional(),
  ruleId: z.string().trim().max(100).optional(),
  search: z.string().trim().max(200).optional(),
  limit: z.coerce.number().min(1).max(500).optional(),
  offset: z.coerce.number().min(0).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: INCIDENTS
// -----------------------------------------------------------------------------
export const incidentFilterQuerySchema = z.object({
  environment: z.enum(['production', 'training', 'test', 'all', 'staging']).optional(),
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'false_positive', 'all']).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical', 'all']).optional(),
  priority: z.enum(['P1', 'P2', 'P3', 'P4', 'all']).optional(),
  leadInvestigator: z.string().trim().max(100).optional(),
  search: z.string().trim().max(200).optional(),
  limit: z.coerce.number().min(1).max(500).optional(),
  offset: z.coerce.number().min(0).optional()
});

export const incidentCreateSchema = z.object({
  title: z.string().trim().min(1, 'Title and description are required.').max(200),
  description: z.string().trim().min(1, 'Title and description are required.').max(4000),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  priority: z.enum(['P1', 'P2', 'P3', 'P4']).optional(),
  linkedAlertIds: z.array(z.string().max(100)).max(50).optional(),
  leadInvestigator: z.string().trim().max(100).nullable().optional(),
  environment: z.enum(['production', 'training', 'test']).optional()
});

// Mass-assignment protected incident update schema: strictly whitelist mutable fields!
export const incidentUpdateSchema = z.object({
  title: z.string().trim().min(1).max(200).optional(),
  description: z.string().trim().max(4000).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  priority: z.enum(['P1', 'P2', 'P3', 'P4']).optional(),
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'false_positive']).optional(),
  leadInvestigator: z.string().trim().max(100).nullable().optional(),
  leadInvestigatorName: z.string().trim().max(100).optional(),
  lessonsLearned: z.string().trim().max(4000).optional(),
  linkedAlertIds: z.array(z.string().max(100)).max(50).optional(),
  environment: z.enum(['production', 'training', 'test']).optional(),
  tags: z.array(z.string().max(50)).max(20).optional()
}).strict({ message: 'Unrecognized or privileged fields cannot be updated.' });

export const incidentLinkAlertSchema = z.object({
  alertId: z.string().trim().min(1, 'Alert ID is required.').max(100)
});

export const incidentTaskCreateSchema = z.object({
  title: z.string().trim().min(1, 'Task title cannot be empty.').max(200),
  assignedTo: z.string().trim().max(100).nullable().optional()
});

export const incidentTaskIdParamSchema = z.object({
  id: z.string().trim().min(1).max(100),
  taskId: z.string().trim().min(1).max(100)
});

export const incidentTaskToggleSchema = z.object({
  completed: z.boolean({ invalid_type_error: 'Completed status must be a boolean' })
});

export const incidentTimelineCreateSchema = z.object({
  title: z.string().trim().min(1, 'Timeline item title is required.').max(200),
  description: z.string().trim().max(2000).optional(),
  type: z.enum(['alert', 'action', 'observation', 'containment']).optional(),
  evidenceState: z.enum(['CONFIRMED', 'INFERRED', 'UNKNOWN']).optional()
});

export const incidentNoteCreateSchema = z.object({
  note: z.string().trim().min(1, 'Note content cannot be empty.').max(4000)
});

// -----------------------------------------------------------------------------
// SCHEMAS: PHISHGUARD
// -----------------------------------------------------------------------------
export const phishguardScanSchema = z.object({
  url: z.string().trim().min(1, 'URL is required for analysis.').max(2048).refine(
    val => {
      try {
        const parsed = new URL(val.startsWith('http://') || val.startsWith('https://') ? val : `http://${val}`);
        return ['http:', 'https:'].includes(parsed.protocol);
      } catch {
        return false;
      }
    },
    { message: 'Valid URL structure (HTTP/HTTPS) is required.' }
  )
});

export const phishguardPromoteSchema = z.object({
  scanId: z.string().trim().min(1, 'Scan ID is required').max(100)
});

// -----------------------------------------------------------------------------
// SCHEMAS: AI SOC COPILOT
// -----------------------------------------------------------------------------
export const aiChatSchema = z.object({
  message: z.string().trim().min(1, 'Message cannot be empty.').max(4000, 'Message exceeds 4000 character limit'),
  context: z.object({
    alertId: z.string().trim().max(100).optional(),
    incidentId: z.string().trim().max(100).optional(),
    agentId: z.string().trim().max(100).optional()
  }).optional()
});

// -----------------------------------------------------------------------------
// SCHEMAS: THREAT INTEL & REPORTS
// -----------------------------------------------------------------------------
export const indicatorCreateSchema = z.object({
  type: z.enum(['ip', 'domain', 'hash', 'url', 'email'], {
    errorMap: () => ({ message: 'Type and value are required for IOC.' })
  }),
  value: z.string().trim().min(1, 'Type and value are required for IOC.').max(500),
  threatActor: z.string().trim().max(100).optional(),
  confidence: z.number().min(0).max(100).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  description: z.string().trim().max(1000).optional()
});

export const reportGenerateSchema = z.object({
  reportType: z.enum(['incident', 'executive', 'telemetry', 'compliance']).optional(),
  targetId: z.string().trim().max(100).optional()
});
