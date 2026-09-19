import express from 'express';
import { verifySupabaseToken } from './supabase';
import { db, Profile, Organization, OrganizationMember } from './db';

export interface AuthUser {
  id: string;
  email?: string;
  phone?: string;
  emailConfirmed: boolean;
  phoneConfirmed: boolean;
  appMetadata?: Record<string, any>;
  userMetadata?: Record<string, any>;
}

export interface AuthContext {
  user: AuthUser;
  profile: Profile;
  organization: Organization | null;
  membership?: OrganizationMember | null;
  sessionToken: string;
}

// Extend Express Request interface with typed auth context
declare global {
  namespace Express {
    interface Request {
      user?: Profile;
      organization?: Organization | null;
      auth?: AuthContext;
      session?: AuthContext;
    }
  }
}

/**
 * Extracts authentication token from standard sources:
 * 1. Authorization: Bearer <token>
 * 2. vrsoc_session cookie
 * 3. query param 'token' (for SSE EventSource connections where custom headers are unsupported)
 */
export function extractBearerToken(req: express.Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (token) return token;
  }

  if (req.cookies?.vrsoc_session && typeof req.cookies.vrsoc_session === 'string') {
    const token = req.cookies.vrsoc_session.trim();
    if (token) return token;
  }

  if (req.query?.token && typeof req.query.token === 'string') {
    const token = req.query.token.trim();
    if (token) return token;
  }

  return null;
}

/**
 * Canonical Server Authentication Resolution
 * Single Authority: Supabase Auth JWT -> Supabase User -> Profile -> Org Membership
 */
export async function getAuthContext(req: express.Request): Promise<AuthContext | null> {
  try {
    const token = extractBearerToken(req);
    if (!token) return null;

    // 1. Verify token exclusively via Supabase Auth
    const supabaseUser = await verifySupabaseToken(token);
    if (!supabaseUser || !supabaseUser.id) {
      return null;
    }

    const email = supabaseUser.email || '';
    const phone = supabaseUser.phone || supabaseUser.user_metadata?.phone_number || '';
    const emailConfirmed = Boolean(supabaseUser.email_confirmed_at);
    const phoneConfirmed = Boolean(supabaseUser.phone_confirmed_at);
    const hasMfa = Boolean(supabaseUser.factors && supabaseUser.factors.length > 0);

    // 2. Resolve or sync application profile in PostgreSQL
    let profile = await db.getProfileById(supabaseUser.id);
    if (!profile && email) {
      profile = await db.getProfileByEmail(email);
    }

    if (!profile) {
      // Create profile tied 1-to-1 to Supabase user ID
      const fullName = supabaseUser.user_metadata?.full_name || email.split('@')[0] || 'SOC Analyst';
      profile = await db.createProfile(
        email,
        fullName,
        phone || undefined,
        'SOC Analyst',
        supabaseUser.id,
        {
          emailVerified: emailConfirmed,
          phoneVerified: phoneConfirmed,
          mfaEnabled: hasMfa
        }
      );
    } else {
      // Keep verified and MFA flags aligned with authoritative Supabase user state
      const updates: Partial<Profile> = {};
      if (emailConfirmed && !profile.emailVerified) updates.emailVerified = true;
      if (phoneConfirmed && !profile.phoneVerified) updates.phoneVerified = true;
      if (hasMfa !== profile.mfaEnabled) updates.mfaEnabled = hasMfa;

      if (Object.keys(updates).length > 0) {
        profile = await db.updateProfile(profile.id, updates);
      }
    }

    // 3. Resolve Organization membership
    const orgs = await db.getUserOrganizations(profile.id);
    const organization = orgs.length > 0 ? orgs[0] : null;

    let membership: OrganizationMember | null = null;
    if (organization) {
      const members = await db.getMembers(organization.id);
      membership = members.find(m => m.userId === profile!.id) || null;
    }

    const authUser: AuthUser = {
      id: supabaseUser.id,
      email: supabaseUser.email,
      phone: supabaseUser.phone,
      emailConfirmed,
      phoneConfirmed,
      appMetadata: supabaseUser.app_metadata,
      userMetadata: supabaseUser.user_metadata
    };

    return {
      user: authUser,
      profile,
      organization,
      membership,
      sessionToken: token
    };
  } catch (err) {
    console.error('[VRSOC Auth] Error resolving auth context:', err);
    return null;
  }
}

/**
 * Express Authentication Middleware
 * Enforces valid Supabase Auth session for protected routes.
 */
export async function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> {
  try {
    const auth = await getAuthContext(req);
    if (!auth) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }

    req.user = auth.profile;
    req.organization = auth.organization;
    req.auth = auth;
    req.session = auth;

    next();
  } catch (err: any) {
    console.error('[VRSOC Auth] requireAuth middleware error:', err);
    res.status(500).json({ error: 'Authentication check failed.' });
  }
}
