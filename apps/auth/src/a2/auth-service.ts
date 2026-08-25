import type {
  CorrelationId,
  DomainStatus,
  FunctionalGrant,
  SessionId,
  UserId,
  Uuid,
} from '@kovcheg/contracts';

import {
  AuthError,
  AuthRepositoryAuthorizationError,
  AuthRepositoryConflictError,
  AuthRepositoryNotFoundError,
  normalizeDisplayName,
  normalizeEmail,
} from './contracts.js';
import type {
  AccountRecord,
  AccountStatus,
  AuthorizationMutationInput,
  AuthenticatedSession,
  AuthPolicy,
  BootstrapAdministratorInput,
  ChallengeRequestAccepted,
  CreateAccountInput,
  EmailChallengeMessage,
  RateLimitRule,
  SessionPrincipal,
  UpdateAccountInput,
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
  readonly deliveryTimeoutMs?: number | undefined;
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

function normalizeAuthorizationReason(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-z][a-z0-9.-]{2,63}$/u.test(normalized)) {
    throw new AuthError('auth.invalid-input', 'A technical authorization reason is required');
  }
  return normalized;
}

function normalizeAuthorizationVersion(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new AuthError('auth.invalid-input', 'A positive authorization version is required');
  }
  return value;
}

export class AuthService {
  private readonly deliveryTimeoutMs: number;

  constructor(private readonly dependencies: AuthServiceDependencies) {
    validatePolicy(dependencies.policy);
    this.deliveryTimeoutMs = dependencies.deliveryTimeoutMs ?? 5_000;
    assertPositiveInteger('deliveryTimeoutMs', this.deliveryTimeoutMs);
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

  async validateSession(sessionToken: string): Promise<SessionPrincipal> {
    const tokenVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    const principal = await this.dependencies.repository.validateSession(
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

  async createAccount(
    administratorSessionToken: string,
    input: CreateAccountInput,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.createAccountAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        displayName: normalizeDisplayName(input.displayName),
        email: normalizeEmail(input.email),
        userId: this.dependencies.random.userId(),
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  async logout(sessionToken: string): Promise<void> {
    const tokenVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    await this.dependencies.repository.revokeSessionByVerifier(
      tokenVerifier,
      this.dependencies.clock.now(),
    );
  }

  async grantFunctionalGrant(
    administratorSessionToken: string,
    userId: UserId,
    grant: FunctionalGrant,
    input: AuthorizationMutationInput,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.grantFunctionalGrantAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        grant,
        reason: normalizeAuthorizationReason(input.reason),
        userId,
        version: normalizeAuthorizationVersion(input.version),
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
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
      void this.deliverChallenge(
        {
          challengeId: result.challengeId,
          code,
          expiresAt: now + this.dependencies.policy.challenge.ttlMs,
          recipient: result.recipient,
        },
        now,
      );
    }

    return Object.freeze({ challengeId, status: 'accepted' });
  }

  async revokeAllSessions(
    administratorSessionToken: string,
    userId: UserId,
    correlationId: CorrelationId,
  ): Promise<number> {
    try {
      return await this.dependencies.repository.revokeAllSessionsAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        userId,
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  async revokeFunctionalGrant(
    administratorSessionToken: string,
    userId: UserId,
    grant: FunctionalGrant,
    input: AuthorizationMutationInput,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.revokeFunctionalGrantAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        grant,
        reason: normalizeAuthorizationReason(input.reason),
        userId,
        version: normalizeAuthorizationVersion(input.version),
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  private async deliverChallenge(message: EmailChallengeMessage, issuedAt: number): Promise<void> {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.dependencies.delivery.send(message),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error('Email challenge delivery timed out')),
            this.deliveryTimeoutMs,
          );
          timeout.unref?.();
        }),
      ]);
    } catch {
      await this.dependencies.repository
        .invalidateChallenge(message.challengeId, issuedAt)
        .catch(() => undefined);
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
    }
  }

  async revokeSession(
    administratorSessionToken: string,
    userId: UserId,
    sessionId: SessionId,
    correlationId: CorrelationId,
  ): Promise<boolean> {
    try {
      return await this.dependencies.repository.revokeSessionAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        sessionId,
        userId,
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  async setAccountStatus(
    administratorSessionToken: string,
    userId: UserId,
    status: AccountStatus,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.setAccountStatusAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        status,
        userId,
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  async setDomainStatus(
    administratorSessionToken: string,
    userId: UserId,
    domainStatus: DomainStatus,
    input: AuthorizationMutationInput,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.setDomainStatusAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        domainStatus,
        reason: normalizeAuthorizationReason(input.reason),
        userId,
        version: normalizeAuthorizationVersion(input.version),
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
  }

  async updateAccount(
    administratorSessionToken: string,
    userId: UserId,
    input: UpdateAccountInput,
    correlationId: CorrelationId,
  ): Promise<AccountRecord> {
    try {
      return await this.dependencies.repository.updateAccountAsAdministrator({
        ...this.administrativeContext(administratorSessionToken, correlationId),
        displayName: normalizeDisplayName(input.displayName),
        email: normalizeEmail(input.email),
        userId,
      });
    } catch (error) {
      this.mapAdministrativeError(error);
    }
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

  private administrativeContext(
    sessionToken: string,
    correlationId: CorrelationId,
  ): {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly now: number;
  } {
    return Object.freeze({
      actorSessionVerifier: this.dependencies.crypto.sessionTokenVerifier(sessionToken),
      correlationId,
      now: this.dependencies.clock.now(),
    });
  }

  private mapAdministrativeError(error: unknown): never {
    if (error instanceof AuthRepositoryAuthorizationError) {
      throw new AuthError('auth.forbidden', 'Administrative authorization failed');
    }
    if (error instanceof AuthRepositoryConflictError) {
      throw new AuthError('auth.conflict', 'The administrative operation conflicts');
    }
    if (error instanceof AuthRepositoryNotFoundError) {
      throw new AuthError('auth.not-found', 'The requested account does not exist');
    }
    throw error;
  }
}
