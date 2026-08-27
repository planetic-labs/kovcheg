import type {
  CurrentPrincipalAuthorization,
  CorrelationId,
  DomainStatus,
  FunctionalGrant,
  SessionId,
  UserId,
  Uuid,
} from '@kovcheg/contracts';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

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

export interface EmailChallengeResponse {
  readonly challengeId: Uuid;
  readonly email: string;
  readonly next: 'code';
  readonly status: 'accepted';
}

export interface AuthSecurityResetResult {
  readonly invalidatedChallengeCount: number;
  readonly revokedApplicationSessionCount: number;
  readonly revokedPasskeyCount: number;
}

export type AuthPasskeyTransport = 'ble' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

export type AuthPasskeySignCountStatus =
  'advanced' | 'not_advanced' | 'not_supported' | 'regressed';

export interface AuthPasskeyCredential {
  readonly aaguid: Uuid;
  readonly accountId: UserId;
  readonly attestationFormat: string;
  readonly credentialId: Uint8Array;
  readonly lastBackupEligible: boolean;
  readonly lastBackupState: boolean;
  readonly passkeyId: Uuid;
  readonly publicKey: Uint8Array;
  readonly registeredBackupEligible: boolean;
  readonly registeredBackupState: boolean;
  readonly signCount: number;
  readonly transports: readonly AuthPasskeyTransport[];
}

export interface PasskeyRequestContext {
  readonly correlationId: CorrelationId;
  readonly fingerprint: string;
  readonly networkAddress: string;
}

export interface PasskeyRegistrationOptionsResponse {
  readonly ceremonyId: Uuid;
  readonly options: PublicKeyCredentialCreationOptionsJSON;
}

export interface PasskeyAuthenticationOptionsResponse {
  readonly ceremonyId: Uuid;
  readonly mediation: 'conditional';
  readonly options: PublicKeyCredentialRequestOptionsJSON;
}

export interface PasskeyRegistrationFinishInput {
  readonly ceremonyId: Uuid;
  readonly response: RegistrationResponseJSON;
}

export interface PasskeyAuthenticationFinishInput {
  readonly ceremonyId: Uuid;
  readonly response: AuthenticationResponseJSON;
}

export interface PasskeyRegistrationResult {
  readonly passkeyId: Uuid;
  readonly status: 'registered';
}

export interface PasskeyAuthenticationResult extends AuthenticatedSession {
  readonly signCountStatus: AuthPasskeySignCountStatus;
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
    readonly responseMinimumMs: number;
    readonly resendCooldownMs: number;
    readonly ttlMs: number;
  };
  readonly rateLimits: {
    readonly challengeByEmail: RateLimitRule;
    readonly challengeByFingerprint: RateLimitRule;
    readonly challengeByNetwork: RateLimitRule;
    readonly passkeyAuthenticationBeginByFingerprint: RateLimitRule;
    readonly passkeyAuthenticationBeginByNetwork: RateLimitRule;
    readonly passkeyAuthenticationFinishByFingerprint: RateLimitRule;
    readonly passkeyAuthenticationFinishByNetwork: RateLimitRule;
    readonly passkeyRegistrationBeginBySession: RateLimitRule;
    readonly passkeyRegistrationFinishBySession: RateLimitRule;
    readonly verifyByChallenge: RateLimitRule;
    readonly verifyByNetwork: RateLimitRule;
  };
  readonly passkey: {
    readonly challengeTtlMs: number;
    readonly timeoutMs: number;
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
  responseMinimumMs: 75,
  resendCooldownMs: 60_000,
  ttlMs: 10 * 60_000,
});

export const passkeyPolicy = Object.freeze({
  challengeTtlMs: 5 * 60_000,
  timeoutMs: 60_000,
});

export const passkeyRateLimitPolicy = Object.freeze({
  passkeyAuthenticationBeginByFingerprint: Object.freeze({
    limit: 20,
    windowMs: 15 * 60_000,
  }),
  passkeyAuthenticationBeginByNetwork: Object.freeze({ limit: 60, windowMs: 15 * 60_000 }),
  passkeyAuthenticationFinishByFingerprint: Object.freeze({
    limit: 10,
    windowMs: 15 * 60_000,
  }),
  passkeyAuthenticationFinishByNetwork: Object.freeze({ limit: 30, windowMs: 15 * 60_000 }),
  passkeyRegistrationBeginBySession: Object.freeze({ limit: 10, windowMs: 15 * 60_000 }),
  passkeyRegistrationFinishBySession: Object.freeze({ limit: 20, windowMs: 15 * 60_000 }),
});

export function normalizeEmail(value: string): string {
  return normalizeEmailSubmission(value).normalizedEmail;
}

export function normalizeEmailSubmission(value: string): Readonly<{
  displayEmail: string;
  normalizedEmail: string;
}> {
  const displayEmail = value.trim();
  const normalized = displayEmail.toLowerCase();
  if (normalized.length < 3 || normalized.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(normalized)) {
    throw new AuthError('auth.invalid-input', 'A valid email address is required');
  }
  return Object.freeze({ displayEmail, normalizedEmail: normalized });
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
  | 'auth.invalid-passkey'
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
