import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { logWarn } from './logging';

// Extended Express Request type to carry correlation ID
declare global {
  namespace Express {
    interface Request {
      id?: string;
    }
  }
}

// -----------------------------------------------------------------------------
// REQUEST CORRELATION ID MIDDLEWARE
// -----------------------------------------------------------------------------
export function correlationIdMiddleware(req: Request, res: Response, next: NextFunction) {
  const incomingId = req.header('x-request-id') || req.header('x-correlation-id');
  const requestId = (incomingId && /^[a-zA-Z0-9_-]{8,64}$/.test(incomingId))
    ? incomingId
    : crypto.randomUUID();

  req.id = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
}

// -----------------------------------------------------------------------------
// HELMET SECURITY HEADERS
// -----------------------------------------------------------------------------
export const securityHeadersMiddleware = helmet({
  contentSecurityPolicy: false, // Disabled for Vite client bundle & live dev server compatibility
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true
});

// -----------------------------------------------------------------------------
// CORS MIDDLEWARE (PRODUCTION SAFE, NO WILDCARD FOR CREDENTIALED TRAFFIC)
// -----------------------------------------------------------------------------
const ALLOWED_DEV_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3005',
  'http://127.0.0.1:3005',
  'http://localhost:3006',
  'http://127.0.0.1:3006',
  'http://localhost:3007',
  'http://127.0.0.1:3007'
];

export function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  const isDev = process.env.NODE_ENV !== 'production';
  const customAllowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

  let isAllowed = false;
  if (origin) {
    if (isDev) {
      // In dev mode allow localhost & local port origins
      if (ALLOWED_DEV_ORIGINS.includes(origin) || origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
        isAllowed = true;
      }
    } else {
      if (customAllowedOrigins.includes(origin)) {
        isAllowed = true;
      }
    }
  }

  if (isAllowed && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Accept');
  }

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
}

// -----------------------------------------------------------------------------
// RATE LIMITERS (IN-MEMORY, SAFE LIMITS PER ROUTE DOMAIN)
// -----------------------------------------------------------------------------

// Standard rate limit handler
function createRateLimitHandler(message: string) {
  return (req: Request, res: Response) => {
    logWarn(`Rate limit exceeded for IP: ${req.ip} on ${req.method} ${req.path}`, {
      ip: req.ip,
      path: req.path,
      requestId: req.id
    });
    res.status(429).json({
      error: message,
      requestId: req.id
    });
  };
}

// Auth endpoints limiter (signup, login, onboarding, OTP)
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler('Too many authentication attempts. Please try again later.')
});

// AI Chat limiter
export const aiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler('AI rate limit reached. Please wait a moment before sending more messages.')
});

// PhishGuard scanning limiter
export const phishguardLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 scans per minute
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler('PhishGuard scan rate limit reached. Please slow down your requests.')
});

// Agent enrollment limiter
export const agentEnrollLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // 60 enrollments per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler('Agent enrollment rate limit exceeded. Please try again later.')
});

// Telemetry & Heartbeat limiter
export const telemetryLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 events/heartbeats per minute
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler('Agent telemetry rate limit exceeded.')
});
