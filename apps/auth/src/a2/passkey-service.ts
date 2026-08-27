import { timingSafeEqual } from 'node:crypto';

import type { Uuid } from '@kovcheg/contracts';

import {
  AuthError,
  AuthRepositoryAuthorizationError,
  AuthRepositoryConflictError,
  AuthRepositoryNotFoundError,
} from './contracts.js';
import type {
  AuthPolicy,
  PasskeyAuthenticationFinishInput,
  PasskeyAuthenticationOptionsResponse,
  PasskeyAuthenticationResult,
  PasskeyRegistrationFinishInput,
  PasskeyRegistrationOptionsResponse,
  PasskeyRegistrationResult,
  PasskeyRequestContext,
  RateLimitRule,
} from './contracts.js';
import type {
  AuthCrypto,
  AuthRandomSource,
  AuthRepository,
  Clock,
  PasskeyCeremonyState,
  PasskeyCeremonyStore,
  RateLimiter,
  WebAuthnServer,
} from './ports.js';

interface PasskeyConfiguration {
  readonly origins: readonly string[];
  readonly rpId: string;
  readonly rpName: string;
}

export interface PasskeyServiceDependencies {
  readonly ceremonyStore: PasskeyCeremonyStore;
  readonly clock: Clock;
  readonly configuration: PasskeyConfiguration;
  readonly crypto: AuthCrypto;
  readonly policy: AuthPolicy;
  readonly random: AuthRandomSource;
  readonly rateLimiter: RateLimiter;
  readonly repository: AuthRepository;
  readonly webauthn: WebAuthnServer;
}

const credentialResponseLimit = 64 * 1024;
const base64UrlPattern = /^[A-Za-z0-9_-]{1,1366}$/u;

function invalidPasskey(): AuthError {
  return new AuthError('auth.invalid-passkey', 'The passkey ceremony is invalid or expired');
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AuthError('auth.invalid-input', `${name} must be a positive integer`);
  }
}

function normalizedDimension(name: string, value: string): string {
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 256) {
    throw new AuthError('auth.invalid-input', `${name} is required`);
  }
  return normalized;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function credentialId(value: string): Uint8Array | null {
  if (!base64UrlPattern.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length < 1 || decoded.length > 1024) return null;
  return Uint8Array.from(decoded);
}

function safeCredentialResponse(value: unknown): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8') <= credentialResponseLimit;
  } catch {
    return false;
  }
}

export class PasskeyService {
  constructor(private readonly dependencies: PasskeyServiceDependencies) {
    assertPositiveInteger('passkey.challengeTtlMs', dependencies.policy.passkey.challengeTtlMs);
    assertPositiveInteger('passkey.timeoutMs', dependencies.policy.passkey.timeoutMs);
    if (dependencies.policy.passkey.timeoutMs > dependencies.policy.passkey.challengeTtlMs) {
      throw new AuthError(
        'auth.invalid-input',
        'passkey.timeoutMs cannot exceed passkey.challengeTtlMs',
      );
    }
  }

  async beginRegistration(
    sessionToken: string,
    context: PasskeyRequestContext,
  ): Promise<PasskeyRegistrationOptionsResponse> {
    const now = this.dependencies.clock.now();
    const sessionVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    await this.consumeRateLimits([
      {
        key: this.dependencies.crypto.rateLimitKey(
          'passkey-registration-begin-session',
          sessionVerifier,
        ),
        rule: this.dependencies.policy.rateLimits.passkeyRegistrationBeginBySession,
      },
    ]);
    const principal = await this.dependencies.repository.validateSession(sessionVerifier, now);
    if (principal === null) throw new AuthError('auth.invalid-session', 'The session is invalid');
    const account = await this.dependencies.repository.findAccountById(principal.userId);
    if (account === null || account.status !== 'active') {
      throw new AuthError('auth.invalid-session', 'The session is invalid');
    }

    const options = await this.dependencies.webauthn.generateRegistrationOptions({
      accountId: principal.userId,
      accountLabel: account.displayName,
      rpId: this.dependencies.configuration.rpId,
      rpName: this.dependencies.configuration.rpName,
      timeoutMs: this.dependencies.policy.passkey.timeoutMs,
    });
    if (!base64UrlPattern.test(options.challenge)) {
      throw new AuthError('auth.unavailable', 'Passkey options are unavailable');
    }
    const ceremonyId = this.dependencies.random.uuid();
    const ceremony: PasskeyCeremonyState = Object.freeze({
      accountId: principal.userId,
      ceremony: 'registration',
      challenge: options.challenge,
      clientContextKey: this.clientContextKey(context),
      sessionVerifier,
    });
    if (
      (await this.dependencies.ceremonyStore.put(
        ceremonyId,
        ceremony,
        this.dependencies.policy.passkey.challengeTtlMs,
      )) !== 'stored'
    ) {
      throw new AuthError('auth.unavailable', 'Passkey ceremony storage is unavailable');
    }
    return Object.freeze({ ceremonyId, options });
  }

  async finishRegistration(
    sessionToken: string,
    input: PasskeyRegistrationFinishInput,
    context: PasskeyRequestContext,
  ): Promise<PasskeyRegistrationResult> {
    if (!safeCredentialResponse(input.response)) throw invalidPasskey();
    const now = this.dependencies.clock.now();
    const sessionVerifier = this.dependencies.crypto.sessionTokenVerifier(sessionToken);
    await this.consumeRateLimits([
      {
        key: this.dependencies.crypto.rateLimitKey(
          'passkey-registration-finish-session',
          sessionVerifier,
        ),
        rule: this.dependencies.policy.rateLimits.passkeyRegistrationFinishBySession,
      },
    ]);
    const principal = await this.dependencies.repository.validateSession(sessionVerifier, now);
    if (principal === null) throw new AuthError('auth.invalid-session', 'The session is invalid');
    const ceremony = await this.takeCeremony(input.ceremonyId, 'registration');
    if (
      ceremony.ceremony !== 'registration' ||
      ceremony.accountId !== principal.userId ||
      !safeEqual(ceremony.sessionVerifier, sessionVerifier) ||
      !safeEqual(ceremony.clientContextKey, this.clientContextKey(context))
    ) {
      throw invalidPasskey();
    }
    const verified = await this.dependencies.webauthn.verifyRegistration({
      expectedChallenge: ceremony.challenge,
      expectedOrigins: this.dependencies.configuration.origins,
      expectedRpId: this.dependencies.configuration.rpId,
      response: input.response,
    });
    if (verified === null || !verified.userVerified) throw invalidPasskey();
    const passkeyId = this.dependencies.random.uuid();
    try {
      const registered = await this.dependencies.repository.registerPasskey({
        actorSessionVerifier: sessionVerifier,
        aaguid: verified.aaguid,
        attestationFormat: verified.attestationFormat,
        backupEligible: verified.backupEligible,
        backupState: verified.backupState,
        correlationId: context.correlationId,
        credentialId: verified.credentialId,
        now,
        passkeyId,
        publicKey: verified.publicKey,
        signCount: verified.signCount,
        transports: verified.transports,
        userVerified: verified.userVerified,
      });
      if (registered.accountId !== principal.userId || registered.passkeyId !== passkeyId) {
        throw new AuthError('auth.unavailable', 'Passkey persistence returned invalid state');
      }
      return Object.freeze({ passkeyId, status: 'registered' });
    } catch (error) {
      this.mapRepositoryFailure(error);
    }
  }

  async beginAuthentication(
    context: PasskeyRequestContext,
  ): Promise<PasskeyAuthenticationOptionsResponse> {
    await this.consumeRateLimits(this.authenticationLimits('begin', context));
    const options = await this.dependencies.webauthn.generateAuthenticationOptions({
      rpId: this.dependencies.configuration.rpId,
      timeoutMs: this.dependencies.policy.passkey.timeoutMs,
    });
    if (!base64UrlPattern.test(options.challenge)) {
      throw new AuthError('auth.unavailable', 'Passkey options are unavailable');
    }
    const ceremonyId = this.dependencies.random.uuid();
    if (
      (await this.dependencies.ceremonyStore.put(
        ceremonyId,
        Object.freeze({
          ceremony: 'authentication',
          challenge: options.challenge,
          clientContextKey: this.clientContextKey(context),
        }),
        this.dependencies.policy.passkey.challengeTtlMs,
      )) !== 'stored'
    ) {
      throw new AuthError('auth.unavailable', 'Passkey ceremony storage is unavailable');
    }
    return Object.freeze({ ceremonyId, mediation: 'conditional', options });
  }

  async finishAuthentication(
    input: PasskeyAuthenticationFinishInput,
    context: PasskeyRequestContext,
  ): Promise<PasskeyAuthenticationResult> {
    if (!safeCredentialResponse(input.response)) throw invalidPasskey();
    await this.consumeRateLimits(this.authenticationLimits('finish', context));
    const ceremony = await this.takeCeremony(input.ceremonyId, 'authentication');
    if (
      ceremony.ceremony !== 'authentication' ||
      !safeEqual(ceremony.clientContextKey, this.clientContextKey(context))
    ) {
      throw invalidPasskey();
    }
    const decodedCredentialId = credentialId(input.response.id);
    if (decodedCredentialId === null) throw invalidPasskey();
    const now = this.dependencies.clock.now();
    const credential = await this.dependencies.repository.readPasskeyByCredentialId(
      decodedCredentialId,
      now,
    );
    if (credential === null) throw invalidPasskey();
    const verified = await this.dependencies.webauthn.verifyAuthentication({
      credential,
      expectedChallenge: ceremony.challenge,
      expectedOrigins: this.dependencies.configuration.origins,
      expectedRpId: this.dependencies.configuration.rpId,
      response: input.response,
    });
    if (verified === null || !verified.userVerified) throw invalidPasskey();

    const sessionToken = this.dependencies.random.opaqueToken();
    const sessionId = this.dependencies.random.sessionId();
    const absoluteExpiresAt = now + this.dependencies.policy.session.absoluteLifetimeMs;
    try {
      const completed = await this.dependencies.repository.completePasskeyLogin({
        assertionId: this.dependencies.random.uuid(),
        correlationId: context.correlationId,
        credentialId: credential.credentialId,
        expectedSignCount: credential.signCount,
        now,
        observedBackupEligible: verified.backupEligible,
        observedBackupState: verified.backupState,
        observedSignCount: verified.observedSignCount,
        session: {
          absoluteExpiresAt,
          idleLifetimeMs: this.dependencies.policy.session.idleLifetimeMs,
          issuedAt: now,
          sessionId,
          tokenVerifier: this.dependencies.crypto.sessionTokenVerifier(sessionToken),
        },
        userVerified: verified.userVerified,
      });
      if (
        completed === null ||
        completed.accountId !== credential.accountId ||
        completed.sessionId !== sessionId
      ) {
        throw invalidPasskey();
      }
      return Object.freeze({
        absoluteExpiresAt,
        idleExpiresAt:
          now +
          Math.min(
            this.dependencies.policy.session.idleLifetimeMs,
            this.dependencies.policy.session.absoluteLifetimeMs,
          ),
        sessionId,
        sessionToken,
        signCountStatus: completed.signCountStatus,
        userId: completed.accountId,
      });
    } catch (error) {
      this.mapRepositoryFailure(error);
    }
  }

  private authenticationLimits(
    stage: 'begin' | 'finish',
    context: PasskeyRequestContext,
  ): readonly { readonly key: string; readonly rule: RateLimitRule }[] {
    const fingerprint = normalizedDimension('fingerprint', context.fingerprint);
    const networkAddress = normalizedDimension('networkAddress', context.networkAddress);
    return Object.freeze([
      {
        key: this.dependencies.crypto.rateLimitKey(
          `passkey-authentication-${stage}-fingerprint`,
          fingerprint,
        ),
        rule:
          stage === 'begin'
            ? this.dependencies.policy.rateLimits.passkeyAuthenticationBeginByFingerprint
            : this.dependencies.policy.rateLimits.passkeyAuthenticationFinishByFingerprint,
      },
      {
        key: this.dependencies.crypto.rateLimitKey(
          `passkey-authentication-${stage}-network`,
          networkAddress,
        ),
        rule:
          stage === 'begin'
            ? this.dependencies.policy.rateLimits.passkeyAuthenticationBeginByNetwork
            : this.dependencies.policy.rateLimits.passkeyAuthenticationFinishByNetwork,
      },
    ]);
  }

  private clientContextKey(context: PasskeyRequestContext): string {
    const fingerprint = normalizedDimension('fingerprint', context.fingerprint);
    const networkAddress = normalizedDimension('networkAddress', context.networkAddress);
    return this.dependencies.crypto.rateLimitKey(
      'passkey-client-context',
      `${networkAddress}\0${fingerprint}`,
    );
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
      if (decision === 'unavailable') {
        throw new AuthError('auth.unavailable', 'Passkey rate limiting is unavailable');
      }
      if (decision === 'limited') throw invalidPasskey();
    }
  }

  private async takeCeremony(
    ceremonyId: Uuid,
    expected: PasskeyCeremonyState['ceremony'],
  ): Promise<PasskeyCeremonyState> {
    const result = await this.dependencies.ceremonyStore.take(ceremonyId);
    if (result.kind === 'unavailable') {
      throw new AuthError('auth.unavailable', 'Passkey ceremony storage is unavailable');
    }
    if (result.kind === 'missing' || result.state.ceremony !== expected) throw invalidPasskey();
    return result.state;
  }

  private mapRepositoryFailure(error: unknown): never {
    if (
      error instanceof AuthRepositoryAuthorizationError ||
      error instanceof AuthRepositoryConflictError ||
      error instanceof AuthRepositoryNotFoundError
    ) {
      throw invalidPasskey();
    }
    if (error instanceof AuthError) throw error;
    throw error;
  }
}
