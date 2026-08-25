import type {
  CurrentPrincipalAuthorization,
  DomainStatus,
  FunctionalGrant,
  SessionId,
  UserId,
  Uuid,
} from '@kovcheg/contracts';

type AccountAccess = 'member';
export type AccountStatus = 'active' | 'deactivated';

export interface AccountRecord {
  readonly accountAccess: AccountAccess;
  readonly displayName: string;
  readonly domainStatus: DomainStatus;
  readonly email: string;
  readonly functionalGrants: readonly FunctionalGrant[];
  readonly status: AccountStatus;
  readonly userId: UserId;
}

export interface BootstrapAdministratorInput {
  readonly bootstrapId: string;
  readonly displayName: string;
  readonly email: string;
  readonly userId: UserId;
}

export interface CreateAccountInput {
  readonly displayName: string;
  readonly email: string;
}

export type UpdateAccountInput = CreateAccountInput;

export interface ChallengeRecordInput {
  readonly challengeId: Uuid;
  readonly codeVerifier: string;
  readonly expiresAt: number;
  readonly issuedAt: number;
  readonly maxAttempts: number;
}

export interface SessionRecordInput {
  readonly absoluteExpiresAt: number;
  readonly idleLifetimeMs: number;
  readonly issuedAt: number;
  readonly sessionId: SessionId;
  readonly tokenVerifier: string;
}

export type SessionPrincipal = CurrentPrincipalAuthorization;

export interface AuthorizationMutationInput {
  readonly reason: string;
  readonly version: number;
}

export interface AuthenticatedSession {
  readonly absoluteExpiresAt: number;
  readonly idleExpiresAt: number;
  readonly sessionId: SessionId;
  readonly sessionToken: string;
  readonly userId: UserId;
}

export interface ChallengeRequestAccepted {
  readonly challengeId: Uuid;
  readonly status: 'accepted';
}

export interface EmailChallengeMessage {
  readonly challengeId: Uuid;
  readonly code: string;
  readonly expiresAt: number;
  readonly recipient: string;
}

export interface AuthPolicy {
  readonly challenge: {
    readonly codeDigits: number;
    readonly maxAttempts: number;
    readonly resendCooldownMs: number;
    readonly ttlMs: number;
  };
  readonly rateLimits: {
    readonly challengeByEmail: RateLimitRule;
    readonly challengeByFingerprint: RateLimitRule;
    readonly challengeByNetwork: RateLimitRule;
    readonly verifyByChallenge: RateLimitRule;
    readonly verifyByNetwork: RateLimitRule;
  };
  readonly session: {
    readonly absoluteLifetimeMs: number;
    readonly idleLifetimeMs: number;
  };
}

export interface RateLimitRule {
  readonly limit: number;
  readonly windowMs: number;
}

export const emailChallengePolicy = Object.freeze({
  codeDigits: 6,
  maxAttempts: 5,
  resendCooldownMs: 60_000,
  ttlMs: 10 * 60_000,
});

export function normalizeEmail(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(normalized)) {
    throw new AuthError('auth.invalid-input', 'A valid email address is required');
  }

  return normalized;
}

export function normalizeDisplayName(value: string): string {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized.length < 1 || normalized.length > 120) {
    throw new AuthError(
      'auth.invalid-input',
      'A display name from 1 to 120 characters is required',
    );
  }

  return normalized;
}

export type AuthErrorCode =
  | 'auth.conflict'
  | 'auth.forbidden'
  | 'auth.invalid-input'
  | 'auth.invalid-or-expired-challenge'
  | 'auth.invalid-session'
  | 'auth.not-found'
  | 'auth.rate-limited'
  | 'auth.unavailable';

export class AuthError extends Error {
  constructor(
    readonly code: AuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export class AuthRepositoryConflictError extends Error {
  constructor() {
    super('The requested auth record conflicts with existing state');
    this.name = 'AuthRepositoryConflictError';
  }
}

export class AuthRepositoryAuthorizationError extends Error {
  constructor() {
    super('Administrative authorization failed');
    this.name = 'AuthRepositoryAuthorizationError';
  }
}

export class AuthRepositoryNotFoundError extends Error {
  constructor() {
    super('The requested auth record does not exist');
    this.name = 'AuthRepositoryNotFoundError';
  }
}
