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

export interface ChallengeRequestAccepted {
  readonly challengeId: Uuid;
  readonly status: 'accepted';
}

export type PersonalGateChallengeResponse =
  | {
      readonly challengeId: Uuid;
      readonly next: 'code';
      readonly status: 'accepted';
    }
  | {
      readonly next: 'email';
      readonly status: 'accepted';
    };

export interface PersonalGateActivation {
  readonly accountId: UserId;
  readonly familyId: Uuid;
  readonly gateSessionId: Uuid;
  readonly gateToken: string;
  readonly reused: boolean;
}

export interface PersonalGateIssueResult {
  readonly accountId: UserId;
  readonly code: string;
  readonly familyId: Uuid;
}

export interface PersonalGateSecurityResetResult {
  readonly invalidatedChallengeCount: number;
  readonly revokedApplicationSessionCount: number;
  readonly revokedFamilyCount: number;
  readonly revokedGateSessionCount: number;
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

export const personalGateLifetimeMs = 7 * 24 * 60 * 60_000;
const personalGateCodeAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function normalizePersonalGateCode(value: string): string | null {
  const normalized = value
    .trim()
    .toUpperCase()
    .replaceAll('-', '')
    .replace(/[IL]/gu, '1')
    .replaceAll('O', '0');
  if (
    normalized.length !== 8 ||
    [...normalized].some((character) => !personalGateCodeAlphabet.includes(character))
  ) {
    return null;
  }
  return normalized;
}

export function formatPersonalGateCode(normalizedCode: string): string {
  if (normalizePersonalGateCode(normalizedCode) !== normalizedCode) {
    throw new AuthError('auth.invalid-input', 'Personal gate code has an invalid shape');
  }
  return `${normalizedCode.slice(0, 4)}-${normalizedCode.slice(4)}`;
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
  | 'auth.invalid-gate'
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
