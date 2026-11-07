import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserRole, AuditLogModel } from '../models';

const DEFAULT_INSECURE_SECRET = 'udyam_one_enterprise_secret_key_change_in_prod_2026';
const KNOWN_INSECURE_SECRETS = new Set([
  DEFAULT_INSECURE_SECRET,
  'secret',
  'jwt_secret',
  'changeme',
  'password',
  '123456',
  '12345678',
  'admin',
]);
const MIN_PRODUCTION_SECRET_LENGTH = 32;

/**
 * Validates JWT secret configuration:
 * - Fails application startup if JWT_SECRET is missing, placeholder/default, or insufficiently strong (< 32 chars) in production.
 * - In non-production, issues a security warning if running with a fallback key.
 */
export function validateJwtSecretConfig(): string {
  const isProd =
    process.env.NODE_ENV === 'production' ||
    process.env.ENVIRONMENT === 'production' ||
    process.env.DEPLOY_ENV === 'production';

  const rawSecret = process.env.JWT_SECRET?.trim();

  if (isProd) {
    if (!rawSecret) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: JWT_SECRET environment variable is missing in production. ' +
          'Application startup aborted to prevent unauthorized token forging.'
      );
    }
    if (KNOWN_INSECURE_SECRETS.has(rawSecret)) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: Default or placeholder JWT_SECRET is strictly prohibited in production. ' +
          'Configure a secure, high-entropy secret of at least 32 characters.'
      );
    }
    if (rawSecret.length < MIN_PRODUCTION_SECRET_LENGTH) {
      throw new Error(
        `FATAL CONFIGURATION ERROR: JWT_SECRET is insufficiently strong (${rawSecret.length} chars). ` +
          `A minimum of ${MIN_PRODUCTION_SECRET_LENGTH} characters is required for HMAC-SHA256 in production.`
      );
    }
    return rawSecret;
  }

  // Development / Test fallback with explicit warning
  if (!rawSecret || KNOWN_INSECURE_SECRETS.has(rawSecret)) {
    console.warn(
      '[SECURITY WARNING] Running with development JWT secret. Set a cryptographically strong JWT_SECRET in production.'
    );
    return rawSecret || DEFAULT_INSECURE_SECRET;
  }

  return rawSecret;
}

export function getJwtSecret(): string {
  return validateJwtSecretConfig();
}

export interface AuthTokenPayload {
  userId: string;
  email: string;
  name: string;
  role: UserRole;
  businessId?: string;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthTokenPayload;
}

export function signToken(payload: AuthTokenPayload): string {
  return jwt.sign(payload, getJwtSecret(), { expiresIn: '24h' });
}

export function verifyToken(token: string): AuthTokenPayload {
  return jwt.verify(token, getJwtSecret()) as AuthTokenPayload;
}

export function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Please provide a valid Bearer token.' });
    return;
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
}

export function optionalAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      req.user = verifyToken(authHeader.split(' ')[1]);
    } catch {
      // ignore invalid optional token
    }
  }
  next();
}

export const OPERATIONS_ROLES: readonly UserRole[] = [
  'Admin',
  'Sales Executive',
  'Channel Partner',
  'KYC Reviewer',
] as const;

export function isOperationsRole(role?: UserRole): boolean {
  return Boolean(role && OPERATIONS_ROLES.includes(role));
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: `Access denied. Role '${req.user.role}' is not authorized. Required one of: ${allowedRoles.join(', ')}`,
      });
      return;
    }
    next();
  };
}

/**
 * Server-side Customer Ownership & Data Isolation Enforcement:
 * - Requires authentication: If req.user is absent, returns allowed: false.
 * - Operations roles (Admin, Sales Executive, Channel Partner, KYC Reviewer) have explicit RBAC permissions.
 * - Customer role is strictly restricted to their verified businessId claim bound to the server-issued JWT.
 * - Client-supplied headers (e.g. x-customer-business-id) are NEVER accepted as a substitute for authenticated identity.
 */
export function verifyCustomerOwnership(
  req: AuthenticatedRequest,
  targetBusinessId: string
): { allowed: boolean; reason?: string } {
  if (!req.user) {
    return {
      allowed: false,
      reason: 'AUTHENTICATION REQUIRED: Private customer resources require an authenticated session.',
    };
  }

  // Explicit RBAC permission check for internal operations roles
  if (isOperationsRole(req.user.role)) {
    return { allowed: true };
  }

  // Strict tenant isolation for customer role
  if (req.user.role === 'Customer') {
    const tokenBizId = req.user.businessId;
    if (!tokenBizId) {
      return {
        allowed: false,
        reason:
          'DATA ISOLATION VIOLATION: Customer account is not bound to a verified business record.',
      };
    }

    if (tokenBizId !== targetBusinessId) {
      return {
        allowed: false,
        reason: `DATA ISOLATION VIOLATION: Authenticated customer token is bound to '${tokenBizId}' and cannot access resources belonging to '${targetBusinessId}'.`,
      };
    }

    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `ACCESS DENIED: Role '${req.user.role}' is not authorized to access customer data.`,
  };
}

const ALLOWED_BUSINESS_FIELDS = new Set([
  'businessId',
  'businessName',
  'legalName',
  'businessType',
  'segment',
  'address',
  'city',
  'state',
  'pinCode',
  'cityTier',
  'employeeCount',
  'numSites',
  'locations',
  'annualTurnoverBand',
  'hasGstin',
  'gstin',
  'hasUdyam',
  'udyamNumber',
  'contactName',
  'contactRole',
  'contactPhone',
  'contactEmail',
  'preferredLanguage',
  'currentInternet',
  'currentProvider',
  'monthlyTelecomSpendInr',
  'scenarioTag',
]);

/**
 * Prevents mass assignment of privileged or system-managed fields on business profile creation/updates.
 */
export function sanitizeBusinessPayload(raw: Record<string, any>): Record<string, any> {
  const clean: Record<string, any> = {};
  if (!raw || typeof raw !== 'object') return clean;
  for (const [key, val] of Object.entries(raw)) {
    if (ALLOWED_BUSINESS_FIELDS.has(key) && val !== undefined) {
      clean[key] = val;
    }
  }
  return clean;
}

export function maskGstin(gstin?: string): string {
  if (!gstin || gstin.length < 10) return gstin || '';
  return `${gstin.slice(0, 4)}*******${gstin.slice(-4)}`;
}

export function maskUdyam(udyam?: string): string {
  if (!udyam || udyam.length < 12) return udyam || '';
  return `${udyam.slice(0, 9)}****${udyam.slice(-3)}`;
}

export function maskPhone(phone?: string): string {
  if (!phone || phone.length < 6) return phone || '';
  return `${phone.slice(0, 3)}*****${phone.slice(-2)}`;
}

export function sanitizePiiInDetails(details?: Record<string, any>): Record<string, any> {
  if (!details || typeof details !== 'object') return {};
  const copy: Record<string, any> = { ...details };
  if (typeof copy.gstin === 'string') copy.gstin = maskGstin(copy.gstin);
  if (typeof copy.udyamNumber === 'string') copy.udyamNumber = maskUdyam(copy.udyamNumber);
  if (typeof copy.contactPhone === 'string') copy.contactPhone = maskPhone(copy.contactPhone);
  return copy;
}

export async function logAuditEvent(params: {
  action: string;
  module: string;
  actorId: string;
  actorRole: string;
  targetId: string;
  details?: Record<string, any>;
}): Promise<void> {
  try {
    const auditId = `AUD-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    await AuditLogModel.create({
      auditId,
      action: params.action,
      module: params.module,
      actorId: params.actorId,
      actorRole: params.actorRole,
      targetId: params.targetId,
      details: sanitizePiiInDetails(params.details),
      timestamp: new Date(),
    });
  } catch (err) {
    console.error('[AuditLog] Failed to record audit event:', err);
  }
}
