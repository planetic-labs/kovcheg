import type { SessionId, UserId, Uuid } from '@kovcheg/contracts';

import {
  AuthError,
  AuthRepositoryConflictError,
  normalizeDisplayName,
  normalizeEmail,
} from './contracts.js';
import type {
  AccountRecord,
  AccountStatus,
  AuthenticatedSession,
  AuthPolicy,
  BootstrapAdministratorInput,
  ChallengeRequestAccepted,
  CreateAccountInput,
  RateLimitRule,
  SessionPrincipal,
} from './contracts.js';
import type {
  AuthCrypto,
  AuthRandomSource,
  AuthRepository,
  Clock,
  EmailChallengeDelivery,
  RateLimiter,
} from './ports.js';

export interface ChallengeRequestInput {
  readonly email: string;
  readonly fingerprint: string;
  readonly networkAddress: string;
}

export interface ChallengeVerificationInput {
  readonly challengeId: Uuid;
  readonly code: string;
  readonly networkAddress: string;
}

export interface AuthServiceDependencies {
  readonly clock: Clock;
  readonly crypto: AuthCrypto;
  readonly delivery: EmailChallengeDelivery;
  readonly policy: AuthPolicy;
  readonly random: AuthRandomSource;
  readonly rateLimiter: RateLimiter;
  readonly repository: AuthRepository;
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AuthError('auth.invalid-input', `${name} must be a positive integer`);
  }
}

function validatePolicy(policy: AuthPolicy): void {
  assertPositiveInteger('challenge.codeDigits', policy.challenge.codeDigits);
  assertPositiveInteger('challenge.maxAttempts', policy.challenge.maxAttempts);
  assertPositiveInteger('challenge.resendCooldownMs', policy.challenge.resendCooldownMs);
  assertPositiveInteger('challenge.ttlMs', policy.challenge.ttlMs);
  assertPositiveInteger('session.absoluteLifetimeMs', policy.session.absoluteLifetimeMs);
  assertPositiveInteger('session.idleLifetimeMs', policy.session.idleLifetimeMs);
  if (policy.session.idleLifetimeMs > policy.session.absoluteLifetimeMs) {
    throw new AuthError(
      'auth.invalid-input',
      'session.idleLifetimeMs cannot exceed session.absoluteLifetimeMs',
    );
  }

  for (const [name, rule] of Object.entries(policy.rateLimits)) {
    assertPositiveInteger(`${name}.limit`, rule.limit);
    assertPositiveInteger(`${name}.windowMs`, rule.windowMs);
  }
}

function normalizeRateLimitDimension(name: string, value: string): string {
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 256) {
    throw new AuthError('auth.invalid-input', `${name} is required`);
  }

  return normalized;
}

export class AuthService {
  constructor(private readonly dependencies: AuthServiceDependencies) {
    validatePolicy(dependencies.policy);
  }

  async authenticateSession(sessionToken: string): Promise<SessionPrincipal> {
    const tokenVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    const principal = await this.dependencies.repository.authenticateSession(
      tokenVerifier,
      this.dependencies.clock.now(),
    );
    if (principal === null) {
      throw new AuthError('auth.invalid-session', 'The session is invalid or expired');
    }

    return principal;
  }

  async bootstrapAdministrator(input: BootstrapAdministratorInput): Promise<{
    readonly account: AccountRecord;
    readonly created: boolean;
  }> {
    const normalizedInput = {
      bootstrapId: input.bootstrapId.trim(),
      displayName: normalizeDisplayName(input.displayName),
      email: normalizeEmail(input.email),
      userId: input.userId,
    };
    if (normalizedInput.bootstrapId.length < 16 || normalizedInput.bootstrapId.length > 200) {
      throw new AuthError(
        'auth.invalid-input',
        'bootstrapId must contain from 16 to 200 characters',
      );
    }

    try {
      return await this.dependencies.repository.bootstrapAdministrator(normalizedInput);
    } catch (error) {
      if (error instanceof AuthRepositoryConflictError) {
        throw new AuthError(
          'auth.conflict',
          'Administrator bootstrap conflicts with existing state',
        );
      }
      throw error;
    }
  }

  async createAccount(sessionToken: string, input: CreateAccountInput): Promise<AccountRecord> {
    await this.requireAdministrator(sessionToken);
    try {
      return await this.dependencies.repository.createAccount({
        displayName: normalizeDisplayName(input.displayName),
        email: normalizeEmail(input.email),
        userId: this.dependencies.random.userId(),
      });
    } catch (error) {
      if (error instanceof AuthRepositoryConflictError) {
        throw new AuthError('auth.conflict', 'An account already uses this identity');
      }
      throw error;
    }
  }

  async logout(sessionToken: string): Promise<void> {
    const tokenVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    await this.dependencies.repository.revokeSessionByVerifier(
      tokenVerifier,
      this.dependencies.clock.now(),
    );
  }

  async requestEmailChallenge(input: ChallengeRequestInput): Promise<ChallengeRequestAccepted> {
    const now = this.dependencies.clock.now();
    const email = normalizeEmail(input.email);
    const fingerprint = normalizeRateLimitDimension('fingerprint', input.fingerprint);
    const networkAddress = normalizeRateLimitDimension('networkAddress', input.networkAddress);
    await this.consumeRateLimits([
      {
        key: this.dependencies.crypto.rateLimitKey('challenge-email', email),
        rule: this.dependencies.policy.rateLimits.challengeByEmail,
      },
      {
        key: this.dependencies.crypto.rateLimitKey('challenge-fingerprint', fingerprint),
        rule: this.dependencies.policy.rateLimits.challengeByFingerprint,
      },
      {
        key: this.dependencies.crypto.rateLimitKey('challenge-network', networkAddress),
        rule: this.dependencies.policy.rateLimits.challengeByNetwork,
      },
    ]);

    const challengeId = this.dependencies.random.uuid();
    const code = this.dependencies.random.challengeCode(
      this.dependencies.policy.challenge.codeDigits,
    );
    const result = await this.dependencies.repository.issueChallengeForActiveAccount({
      challenge: {
        challengeId,
        codeVerifier: this.dependencies.crypto.challengeCodeVerifier(challengeId, code),
        expiresAt: now + this.dependencies.policy.challenge.ttlMs,
        issuedAt: now,
        maxAttempts: this.dependencies.policy.challenge.maxAttempts,
      },
      email,
      resendCooldownMs: this.dependencies.policy.challenge.resendCooldownMs,
    });

    if (result.kind === 'issued') {
      try {
        await this.dependencies.delivery.send({
          challengeId: result.challengeId,
          code,
          expiresAt: now + this.dependencies.policy.challenge.ttlMs,
          recipient: result.recipient,
        });
      } catch {
        await this.dependencies.repository.invalidateChallenge(challengeId, now);
      }
    }

    return Object.freeze({ challengeId, status: 'accepted' });
  }

  async revokeSession(administratorSessionToken: string, sessionId: SessionId): Promise<boolean> {
    await this.requireAdministrator(administratorSessionToken);
    return this.dependencies.repository.revokeSessionById(sessionId, this.dependencies.clock.now());
  }

  async setAccountStatus(
    administratorSessionToken: string,
    userId: UserId,
    status: AccountStatus,
  ): Promise<AccountRecord> {
    await this.requireAdministrator(administratorSessionToken);
    const account = await this.dependencies.repository.setAccountStatusAndRevoke({
      now: this.dependencies.clock.now(),
      status,
      userId,
    });
    if (account === null) {
      throw new AuthError('auth.not-found', 'The account does not exist');
    }

    return account;
  }

  async verifyEmailChallenge(input: ChallengeVerificationInput): Promise<AuthenticatedSession> {
    const now = this.dependencies.clock.now();
    const networkAddress = normalizeRateLimitDimension('networkAddress', input.networkAddress);
    await this.consumeRateLimits([
      {
        key: this.dependencies.crypto.rateLimitKey('verify-challenge', input.challengeId),
        rule: this.dependencies.policy.rateLimits.verifyByChallenge,
      },
      {
        key: this.dependencies.crypto.rateLimitKey('verify-network', networkAddress),
        rule: this.dependencies.policy.rateLimits.verifyByNetwork,
      },
    ]);

    const sessionToken = this.dependencies.random.opaqueToken();
    const sessionId = this.dependencies.random.sessionId();
    const code = /^\d{4,9}$/.test(input.code) ? input.code : 'invalid';
    const result = await this.dependencies.repository.consumeChallengeAndCreateSession({
      candidateCodeVerifier: this.dependencies.crypto.challengeCodeVerifier(
        input.challengeId,
        code,
      ),
      challengeId: input.challengeId,
      now,
      session: {
        absoluteExpiresAt: now + this.dependencies.policy.session.absoluteLifetimeMs,
        idleLifetimeMs: this.dependencies.policy.session.idleLifetimeMs,
        issuedAt: now,
        sessionId,
        tokenVerifier: this.dependencies.crypto.sessionTokenVerifier(sessionToken),
      },
    });
    if (result.kind === 'invalid') {
      throw new AuthError(
        'auth.invalid-or-expired-challenge',
        'The challenge is invalid or expired',
      );
    }

    return Object.freeze({
      absoluteExpiresAt: now + this.dependencies.policy.session.absoluteLifetimeMs,
      idleExpiresAt:
        now +
        Math.min(
          this.dependencies.policy.session.idleLifetimeMs,
          this.dependencies.policy.session.absoluteLifetimeMs,
        ),
      sessionId,
      sessionToken,
      userId: result.principal.userId,
    });
  }

  private async consumeRateLimits(
    limits: readonly { readonly key: string; readonly rule: RateLimitRule }[],
  ): Promise<void> {
    const now = this.dependencies.clock.now();
    for (const limit of limits) {
      const decision = await this.dependencies.rateLimiter.consume({
        key: limit.key,
        now,
        rule: limit.rule,
      });
      if (decision === 'limited') {
        throw new AuthError('auth.rate-limited', 'Too many authentication attempts');
      }
      if (decision === 'unavailable') {
        throw new AuthError('auth.unavailable', 'Authentication rate limiting is unavailable');
      }
    }
  }

  private async requireAdministrator(sessionToken: string): Promise<SessionPrincipal> {
    const principal = await this.authenticateSession(sessionToken);
    if (!principal.roles.includes('administrator')) {
      throw new AuthError('auth.forbidden', 'Administrator permission is required');
    }

    return principal;
  }
}
