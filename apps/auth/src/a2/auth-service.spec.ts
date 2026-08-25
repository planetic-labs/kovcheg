import { describe, expect, it } from 'vitest';

import type { CorrelationId, UserId } from '@kovcheg/contracts';

import { AuthService } from './auth-service.js';
import { AuthError, emailChallengePolicy } from './contracts.js';
import type { AuthPolicy } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource } from './crypto.js';
import {
  LocalAuthRepository,
  LocalEmailChallengeDelivery,
  LocalRateLimiter,
  ManualClock,
  UnavailableRateLimiter,
} from './local-adapters.js';
import type { EmailChallengeDelivery, RateLimiter } from './ports.js';

const administratorId = '00000000-0000-4000-8000-000000000011' satisfies UserId;
const administrationCorrelationId = 'auth-service-administration' as CorrelationId;
const startTime = Date.UTC(2026, 0, 1, 12, 0, 0);

function createPolicy(overrides: Partial<AuthPolicy['rateLimits']> = {}): AuthPolicy {
  const generousRule = Object.freeze({ limit: 50, windowMs: 10 * 60_000 });
  return Object.freeze({
    challenge: emailChallengePolicy,
    rateLimits: Object.freeze({
      challengeByEmail: generousRule,
      challengeByFingerprint: generousRule,
      challengeByNetwork: generousRule,
      verifyByChallenge: generousRule,
      verifyByNetwork: generousRule,
      ...overrides,
    }),
    session: Object.freeze({
      absoluteLifetimeMs: 60 * 60_000,
      idleLifetimeMs: 15 * 60_000,
    }),
  });
}

function createFixture(
  options: {
    readonly delivery?: EmailChallengeDelivery;
    readonly policy?: AuthPolicy;
    readonly rateLimiter?: RateLimiter;
    readonly repository?: LocalAuthRepository;
  } = {},
) {
  const clock = new ManualClock(startTime);
  const repository = options.repository ?? new LocalAuthRepository();
  const delivery = options.delivery ?? new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const crypto = new HmacAuthCrypto({
    challengePepper: 'c'.repeat(64),
    rateLimitPepper: 'r'.repeat(64),
    sessionPepper: 's'.repeat(64),
  });
  const dependencies = {
    clock,
    crypto,
    delivery,
    policy: options.policy ?? createPolicy(),
    random: new SystemAuthRandomSource(),
    rateLimiter: options.rateLimiter ?? new LocalRateLimiter(),
    repository,
  };
  return {
    clock,
    delivery,
    dependencies,
    repository,
    service: new AuthService(dependencies),
  };
}

async function bootstrap(fixture: ReturnType<typeof createFixture>) {
  return fixture.service.bootstrapAdministrator({
    bootstrapId: 'synthetic-bootstrap-id-0001',
    displayName: 'Test Administrator',
    email: 'administrator@example.invalid',
    userId: administratorId,
  });
}

async function login(fixture: ReturnType<typeof createFixture>, email: string, suffix: string) {
  const delivery = fixture.delivery;
  if (!(delivery instanceof LocalEmailChallengeDelivery)) {
    throw new Error('login helper requires local delivery');
  }
  const request = await fixture.service.requestEmailChallenge({
    email,
    fingerprint: `fingerprint-${suffix}`,
    networkAddress: `network-${suffix}`,
  });
  const message = delivery.messages.at(-1);
  if (message === undefined || message.challengeId !== request.challengeId) {
    throw new Error('Expected a delivered challenge');
  }
  return fixture.service.verifyEmailChallenge({
    challengeId: request.challengeId,
    code: message.code,
    networkAddress: `network-${suffix}`,
  });
}

describe('A2 administrator and account use cases', () => {
  it('bootstraps exactly one administrator under concurrent retries', async () => {
    const fixture = createFixture();
    const results = await Promise.all(Array.from({ length: 12 }, async () => bootstrap(fixture)));

    expect(results.filter((result) => result.created)).toHaveLength(1);
    expect(new Set(results.map((result) => result.account.userId))).toEqual(
      new Set([administratorId]),
    );
    expect(
      results.every((result) => result.account.functionalGrants.includes('platform_administrator')),
    ).toBe(true);
  });

  it('creates pre-authorized accounts and enforces admin-only status and session revocation', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const administratorSession = await login(
      fixture,
      'administrator@example.invalid',
      'administrator',
    );

    const account = await fixture.service.createAccount(
      administratorSession.sessionToken,
      {
        displayName: '  Test   Member  ',
        email: '  MEMBER@example.invalid ',
      },
      administrationCorrelationId,
    );
    expect(account).toMatchObject({
      accountAccess: 'member',
      displayName: 'Test Member',
      domainStatus: 'incubator_participant',
      email: 'member@example.invalid',
      functionalGrants: [],
      status: 'active',
    });

    await expect(
      fixture.service.createAccount(
        administratorSession.sessionToken,
        {
          displayName: 'Duplicate',
          email: 'member@example.invalid',
        },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.conflict' });

    const memberSession = await login(fixture, account.email, 'member');
    await expect(
      fixture.service.createAccount(
        memberSession.sessionToken,
        {
          displayName: 'Forbidden',
          email: 'forbidden@example.invalid',
        },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });

    await fixture.service.setAccountStatus(
      administratorSession.sessionToken,
      account.userId,
      'deactivated',
      administrationCorrelationId,
    );
    await expect(
      fixture.service.authenticateSession(memberSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });

    const deliveredBeforeInactiveRequest = (fixture.delivery as LocalEmailChallengeDelivery)
      .messages.length;
    await expect(
      fixture.service.requestEmailChallenge({
        email: account.email,
        fingerprint: 'fingerprint-inactive',
        networkAddress: 'network-inactive',
      }),
    ).resolves.toMatchObject({ status: 'accepted' });
    expect((fixture.delivery as LocalEmailChallengeDelivery).messages).toHaveLength(
      deliveredBeforeInactiveRequest,
    );

    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    await fixture.service.setAccountStatus(
      administratorSession.sessionToken,
      account.userId,
      'active',
      administrationCorrelationId,
    );
    const reactivatedSession = await login(fixture, account.email, 'reactivated');
    await expect(
      fixture.service.revokeSession(
        administratorSession.sessionToken,
        account.userId,
        reactivatedSession.sessionId,
        administrationCorrelationId,
      ),
    ).resolves.toBe(true);
    await expect(
      fixture.service.authenticateSession(reactivatedSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });

    await fixture.service.logout(administratorSession.sessionToken);
    await expect(
      fixture.service.authenticateSession(administratorSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
  });

  it('keeps owner-only platform administration separate from delegated functional grants', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const ownerSession = await login(fixture, 'administrator@example.invalid', 'owner');
    const delegated = await fixture.service.createAccount(
      ownerSession.sessionToken,
      {
        displayName: 'Delegated Administrator',
        email: 'delegated-administrator@example.invalid',
      },
      administrationCorrelationId,
    );
    await fixture.service.grantFunctionalGrant(
      ownerSession.sessionToken,
      delegated.userId,
      'platform_administrator',
      { reason: 'owner-delegated', version: 2 },
      administrationCorrelationId,
    );
    const delegatedSession = await login(fixture, delegated.email, 'delegated-administrator');
    const specialist = await fixture.service.createAccount(
      delegatedSession.sessionToken,
      { displayName: 'Synthetic Specialist', email: 'specialist@example.invalid' },
      administrationCorrelationId,
    );

    for (const [grant, version] of [
      ['editor', 2],
      ['chronicler', 3],
      ['technical_administrator', 4],
    ] as const) {
      await fixture.service.grantFunctionalGrant(
        delegatedSession.sessionToken,
        specialist.userId,
        grant,
        { reason: 'delegated-assignment', version },
        administrationCorrelationId,
      );
    }
    await expect(
      fixture.service.grantFunctionalGrant(
        delegatedSession.sessionToken,
        specialist.userId,
        'platform_administrator',
        { reason: 'delegated-denied', version: 5 },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });

    const specialistSession = await login(fixture, specialist.email, 'specialist');
    await expect(
      fixture.service.authenticateSession(specialistSession.sessionToken),
    ).resolves.toMatchObject({
      administrativeCapabilities: {
        canManageAccounts: false,
        canManageFunctionalGrants: false,
        canManagePlatformAdministrators: false,
      },
      diagnosticCapabilities: {
        canReadBuildAndMigrationVersions: true,
        canReadHealthAndReadiness: true,
        canReadQueueAndTechnicalState: true,
        canReadSanitizedDiagnostics: true,
      },
      functionalGrants: ['editor', 'chronicler', 'technical_administrator'],
      isServerOwner: false,
      materialCapabilities: [],
      sensitiveCapabilities: { canPerformSensitiveActions: false },
    });
  });

  it('keeps browser sessions independent, logs out only the current one, and deactivation revokes all', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const administratorSession = await login(
      fixture,
      'administrator@example.invalid',
      'session-policy-administrator',
    );
    const account = await fixture.service.createAccount(
      administratorSession.sessionToken,
      {
        displayName: 'Multi Session Account',
        email: 'multi-session@example.invalid',
      },
      administrationCorrelationId,
    );

    const browserSession = await login(fixture, account.email, 'browser');
    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const pwaSession = await login(fixture, account.email, 'pwa');

    expect(browserSession.sessionId).not.toBe(pwaSession.sessionId);
    expect(browserSession.sessionToken).not.toBe(pwaSession.sessionToken);

    await fixture.service.logout(browserSession.sessionToken);
    await expect(
      fixture.service.authenticateSession(browserSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
    await expect(
      fixture.service.authenticateSession(pwaSession.sessionToken),
    ).resolves.toMatchObject({ userId: account.userId });

    await fixture.service.setAccountStatus(
      administratorSession.sessionToken,
      account.userId,
      'deactivated',
      administrationCorrelationId,
    );
    await expect(
      fixture.service.authenticateSession(pwaSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
  });

  it('updates normalized profiles and isolates one-session and revoke-all operations', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const administratorSession = await login(
      fixture,
      'administrator@example.invalid',
      'administration-isolation',
    );
    const firstAccount = await fixture.service.createAccount(
      administratorSession.sessionToken,
      { displayName: 'First Account', email: 'first-account@example.invalid' },
      administrationCorrelationId,
    );
    const secondAccount = await fixture.service.createAccount(
      administratorSession.sessionToken,
      { displayName: 'Second Account', email: 'second-account@example.invalid' },
      administrationCorrelationId,
    );

    await expect(
      fixture.service.updateAccount(
        administratorSession.sessionToken,
        firstAccount.userId,
        { displayName: '  Updated   Account ', email: ' UPDATED@example.invalid ' },
        administrationCorrelationId,
      ),
    ).resolves.toMatchObject({
      displayName: 'Updated Account',
      email: 'updated@example.invalid',
    });
    await expect(
      fixture.service.updateAccount(
        administratorSession.sessionToken,
        secondAccount.userId,
        { displayName: 'Must Roll Back', email: 'updated@example.invalid' },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.conflict' });
    await expect(fixture.repository.findAccountById(secondAccount.userId)).resolves.toMatchObject({
      displayName: 'Second Account',
      email: 'second-account@example.invalid',
    });

    const firstSession = await login(fixture, 'updated@example.invalid', 'first-session');
    const secondAccountSession = await login(
      fixture,
      'second-account@example.invalid',
      'second-account-session',
    );
    await expect(
      fixture.service.revokeSession(
        administratorSession.sessionToken,
        firstAccount.userId,
        secondAccountSession.sessionId,
        administrationCorrelationId,
      ),
    ).resolves.toBe(false);
    await expect(
      fixture.service.authenticateSession(secondAccountSession.sessionToken),
    ).resolves.toMatchObject({ userId: secondAccount.userId });

    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const secondFirstAccountSession = await login(
      fixture,
      'updated@example.invalid',
      'second-first-account-session',
    );
    const revokeAllResults = await Promise.all(
      Array.from({ length: 8 }, async () =>
        fixture.service.revokeAllSessions(
          administratorSession.sessionToken,
          firstAccount.userId,
          administrationCorrelationId,
        ),
      ),
    );
    expect(revokeAllResults.reduce((total, count) => total + count, 0)).toBe(2);
    expect(revokeAllResults.filter((count) => count > 0)).toHaveLength(1);
    await expect(
      fixture.service.authenticateSession(firstSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
    await expect(
      fixture.service.authenticateSession(secondFirstAccountSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
    await expect(
      fixture.service.authenticateSession(secondAccountSession.sessionToken),
    ).resolves.toMatchObject({ userId: secondAccount.userId });
  });

  it('fails closed for missing, expired, revoked, and deactivated administrator sessions', async () => {
    const missingFixture = createFixture();
    await bootstrap(missingFixture);
    const missingTargetSession = await login(
      missingFixture,
      'administrator@example.invalid',
      'missing-target-setup',
    );
    const missingTarget = await missingFixture.service.createAccount(
      missingTargetSession.sessionToken,
      { displayName: 'Missing Actor Target', email: 'missing-target@example.invalid' },
      administrationCorrelationId,
    );
    await expect(
      missingFixture.service.updateAccount(
        'missing-administrator-session-token-value',
        missingTarget.userId,
        { displayName: 'Forbidden Change', email: 'forbidden-change@example.invalid' },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });
    await expect(
      missingFixture.service.updateAccount(
        missingTargetSession.sessionToken,
        '00000000-0000-4000-8000-000000000099',
        { displayName: 'Missing', email: 'missing@example.invalid' },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.not-found' });

    const expiredFixture = createFixture();
    await bootstrap(expiredFixture);
    const expiredSession = await login(
      expiredFixture,
      'administrator@example.invalid',
      'expired-administrator',
    );
    const expiredTarget = await expiredFixture.service.createAccount(
      expiredSession.sessionToken,
      { displayName: 'Expired Target', email: 'expired-target@example.invalid' },
      administrationCorrelationId,
    );
    expiredFixture.clock.advance(expiredFixture.dependencies.policy.session.idleLifetimeMs);
    await expect(
      expiredFixture.service.setAccountStatus(
        expiredSession.sessionToken,
        expiredTarget.userId,
        'deactivated',
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });
    await expect(
      expiredFixture.repository.findAccountById(expiredTarget.userId),
    ).resolves.toMatchObject({ status: 'active' });

    const revokedFixture = createFixture();
    await bootstrap(revokedFixture);
    const revokedSession = await login(
      revokedFixture,
      'administrator@example.invalid',
      'revoked-administrator',
    );
    await revokedFixture.service.logout(revokedSession.sessionToken);
    await expect(
      revokedFixture.service.createAccount(
        revokedSession.sessionToken,
        { displayName: 'Forbidden Account', email: 'revoked-actor@example.invalid' },
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });

    const deactivatedFixture = createFixture();
    await bootstrap(deactivatedFixture);
    const deactivatedSession = await login(
      deactivatedFixture,
      'administrator@example.invalid',
      'deactivated-administrator',
    );
    await deactivatedFixture.service.setAccountStatus(
      deactivatedSession.sessionToken,
      administratorId,
      'deactivated',
      administrationCorrelationId,
    );
    await expect(
      deactivatedFixture.service.revokeAllSessions(
        deactivatedSession.sessionToken,
        administratorId,
        administrationCorrelationId,
      ),
    ).rejects.toMatchObject({ code: 'auth.forbidden' });
  });
});

describe('A2 email challenge security', () => {
  it('returns the same neutral response shape and sends only for an active account', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const administratorSession = await login(
      fixture,
      'administrator@example.invalid',
      'neutral-admin',
    );
    const inactiveAccount = await fixture.service.createAccount(
      administratorSession.sessionToken,
      {
        displayName: 'Inactive Account',
        email: 'inactive@example.invalid',
      },
      administrationCorrelationId,
    );
    await fixture.service.setAccountStatus(
      administratorSession.sessionToken,
      inactiveAccount.userId,
      'deactivated',
      administrationCorrelationId,
    );
    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);

    const delivery = fixture.delivery as LocalEmailChallengeDelivery;
    const before = delivery.messages.length;
    const [known, unknown, inactive] = await Promise.all([
      fixture.service.requestEmailChallenge({
        email: 'administrator@example.invalid',
        fingerprint: 'fingerprint-known',
        networkAddress: 'network-known',
      }),
      fixture.service.requestEmailChallenge({
        email: 'unknown@example.invalid',
        fingerprint: 'fingerprint-unknown',
        networkAddress: 'network-unknown',
      }),
      fixture.service.requestEmailChallenge({
        email: 'inactive@example.invalid',
        fingerprint: 'fingerprint-inactive-2',
        networkAddress: 'network-inactive-2',
      }),
    ]);

    expect(known.status).toBe('accepted');
    expect(unknown.status).toBe('accepted');
    expect(inactive.status).toBe('accepted');
    expect(Object.keys(known).sort()).toEqual(Object.keys(unknown).sort());
    expect(Object.keys(unknown).sort()).toEqual(Object.keys(inactive).sort());
    expect(delivery.messages).toHaveLength(before + 1);
    expect(delivery.messages.at(-1)?.recipient).toBe('administrator@example.invalid');
  });

  it('does not expose provider latency through the challenge response', async () => {
    let resolveDeliveryStarted!: () => void;
    let resolveDeliveryFinished!: () => void;
    const deliveryStarted = new Promise<void>((resolve) => {
      resolveDeliveryStarted = resolve;
    });
    const deliveryFinished = new Promise<void>((resolve) => {
      resolveDeliveryFinished = resolve;
    });
    const fixture = createFixture({
      delivery: {
        send(): Promise<void> {
          resolveDeliveryStarted();
          return deliveryFinished;
        },
      },
    });
    await bootstrap(fixture);

    await expect(
      fixture.service.requestEmailChallenge({
        email: 'administrator@example.invalid',
        fingerprint: 'fingerprint-provider-latency',
        networkAddress: 'network-provider-latency',
      }),
    ).resolves.toMatchObject({ status: 'accepted' });
    await deliveryStarted;
    resolveDeliveryFinished();
  });

  it('enforces expiry, attempt limits, one-time use, and concurrent replay protection', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const delivery = fixture.delivery as LocalEmailChallengeDelivery;

    const expiredRequest = await fixture.service.requestEmailChallenge({
      email: 'administrator@example.invalid',
      fingerprint: 'fingerprint-expired',
      networkAddress: 'network-expired',
    });
    const expiredMessage = delivery.messages.at(-1);
    fixture.clock.advance(emailChallengePolicy.ttlMs);
    await expect(
      fixture.service.verifyEmailChallenge({
        challengeId: expiredRequest.challengeId,
        code: expiredMessage?.code ?? '',
        networkAddress: 'network-expired',
      }),
    ).rejects.toMatchObject({ code: 'auth.invalid-or-expired-challenge' });

    const exhaustedRequest = await fixture.service.requestEmailChallenge({
      email: 'administrator@example.invalid',
      fingerprint: 'fingerprint-attempts',
      networkAddress: 'network-attempts',
    });
    const exhaustedMessage = delivery.messages.at(-1);
    for (let attempt = 0; attempt < emailChallengePolicy.maxAttempts; attempt += 1) {
      await expect(
        fixture.service.verifyEmailChallenge({
          challengeId: exhaustedRequest.challengeId,
          code: '000000',
          networkAddress: 'network-attempts',
        }),
      ).rejects.toMatchObject({ code: 'auth.invalid-or-expired-challenge' });
    }
    await expect(
      fixture.service.verifyEmailChallenge({
        challengeId: exhaustedRequest.challengeId,
        code: exhaustedMessage?.code ?? '',
        networkAddress: 'network-attempts',
      }),
    ).rejects.toMatchObject({ code: 'auth.invalid-or-expired-challenge' });

    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const replayRequest = await fixture.service.requestEmailChallenge({
      email: 'administrator@example.invalid',
      fingerprint: 'fingerprint-replay',
      networkAddress: 'network-replay',
    });
    const replayMessage = delivery.messages.at(-1);
    const attempts = await Promise.allSettled([
      fixture.service.verifyEmailChallenge({
        challengeId: replayRequest.challengeId,
        code: replayMessage?.code ?? '',
        networkAddress: 'network-replay-a',
      }),
      fixture.service.verifyEmailChallenge({
        challengeId: replayRequest.challengeId,
        code: replayMessage?.code ?? '',
        networkAddress: 'network-replay-b',
      }),
    ]);
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    await expect(
      fixture.service.verifyEmailChallenge({
        challengeId: replayRequest.challengeId,
        code: replayMessage?.code ?? '',
        networkAddress: 'network-replay-c',
      }),
    ).rejects.toMatchObject({ code: 'auth.invalid-or-expired-challenge' });
  });

  it('invalidates the challenge without changing the neutral response when delivery fails', async () => {
    const fixture = createFixture({
      delivery: {
        send(): Promise<void> {
          return Promise.reject(new Error('synthetic delivery failure'));
        },
      },
    });
    await bootstrap(fixture);
    const response = await fixture.service.requestEmailChallenge({
      email: 'administrator@example.invalid',
      fingerprint: 'fingerprint-mail-down',
      networkAddress: 'network-mail-down',
    });

    expect(response.status).toBe('accepted');
    await expect(
      fixture.service.verifyEmailChallenge({
        challengeId: response.challengeId,
        code: '000000',
        networkAddress: 'network-mail-down',
      }),
    ).rejects.toMatchObject({ code: 'auth.invalid-or-expired-challenge' });
  });
});

describe('A2 rate limiting and session expiry', () => {
  it('prevents local state adapters from being used in production', () => {
    expect(() => new LocalAuthRepository({ NODE_ENV: 'production' })).toThrow(
      'Local auth repository is unavailable in production',
    );
    expect(() => new LocalRateLimiter({ NODE_ENV: 'production' })).toThrow(
      'Local rate limiter is unavailable in production',
    );
    expect(() => new LocalEmailChallengeDelivery({ NODE_ENV: 'production' })).toThrow(
      'Local email challenge delivery is unavailable in production',
    );
  });

  it('atomically limits concurrent requests for the same normalized email', async () => {
    const fixture = createFixture({
      policy: createPolicy({ challengeByEmail: { limit: 1, windowMs: 10 * 60_000 } }),
    });
    await bootstrap(fixture);

    const attempts = await Promise.allSettled([
      fixture.service.requestEmailChallenge({
        email: 'administrator@example.invalid',
        fingerprint: 'fingerprint-rate-a',
        networkAddress: 'network-rate-a',
      }),
      fixture.service.requestEmailChallenge({
        email: ' ADMINISTRATOR@example.invalid ',
        fingerprint: 'fingerprint-rate-b',
        networkAddress: 'network-rate-b',
      }),
    ]);
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    const rejected = attempts.find((attempt) => attempt.status === 'rejected');
    expect(rejected).toMatchObject({ reason: { code: 'auth.rate-limited' } });
  });

  it('fails new auth attempts closed when limiting is unavailable but preserves an existing session', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const session = await login(fixture, 'administrator@example.invalid', 'available');
    const unavailableService = new AuthService({
      ...fixture.dependencies,
      rateLimiter: new UnavailableRateLimiter(),
    });

    await expect(
      unavailableService.authenticateSession(session.sessionToken),
    ).resolves.toMatchObject({
      userId: administratorId,
    });
    await expect(
      unavailableService.requestEmailChallenge({
        email: 'unknown@example.invalid',
        fingerprint: 'fingerprint-unavailable',
        networkAddress: 'network-unavailable',
      }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });
  });

  it('enforces idle and absolute server-side expiry', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const idleSession = await login(fixture, 'administrator@example.invalid', 'idle');
    fixture.clock.advance(fixture.dependencies.policy.session.idleLifetimeMs);
    await expect(
      fixture.service.authenticateSession(idleSession.sessionToken),
    ).rejects.toBeInstanceOf(AuthError);

    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const absoluteSession = await login(fixture, 'administrator@example.invalid', 'absolute');
    const step = fixture.dependencies.policy.session.idleLifetimeMs - 1;
    while (fixture.clock.now() + step < absoluteSession.absoluteExpiresAt) {
      fixture.clock.advance(step);
      await expect(
        fixture.service.authenticateSession(absoluteSession.sessionToken),
      ).resolves.toMatchObject({ userId: administratorId });
    }
    fixture.clock.advance(absoluteSession.absoluteExpiresAt - fixture.clock.now());
    await expect(
      fixture.service.authenticateSession(absoluteSession.sessionToken),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });
  });

  it('does not convert background validation into user activity', async () => {
    const fixture = createFixture();
    await bootstrap(fixture);
    const session = await login(fixture, 'administrator@example.invalid', 'non-touch');
    fixture.clock.advance(fixture.dependencies.policy.session.idleLifetimeMs - 1);
    await expect(fixture.service.validateSession(session.sessionToken)).resolves.toMatchObject({
      userId: administratorId,
    });
    fixture.clock.advance(1);
    await expect(fixture.service.validateSession(session.sessionToken)).rejects.toMatchObject({
      code: 'auth.invalid-session',
    });
  });
});
