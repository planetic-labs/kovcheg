import type { CorrelationId, UserId } from '@kovcheg/contracts';
import { describe, expect, it } from 'vitest';

import { AuthService } from './auth-service.js';
import {
  emailChallengePolicy,
  normalizePersonalGateCode,
  personalGateLifetimeMs,
} from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource } from './crypto.js';
import {
  LocalAuthRepository,
  LocalEmailChallengeDelivery,
  LocalRateLimiter,
  ManualClock,
} from './local-adapters.js';
import { PersonalGateCookie } from './personal-gate-cookie.js';
import type { PersonalGateAbuseProtector, PersonalGateSourceDecision } from './ports.js';

const now = Date.UTC(2026, 7, 27, 12);
const correlationId = 'personal-gate-test' as CorrelationId;
const administratorId = '00000000-0000-4000-8000-000000000701' satisfies UserId;

class LocalGateProtector implements PersonalGateAbuseProtector {
  readonly misses = new Map<string, number>();
  readonly activations: string[] = [];
  activationUnavailable = false;
  unavailable = false;

  checkSource(sourceKey: string): Promise<PersonalGateSourceDecision> {
    if (this.unavailable) return Promise.resolve('unavailable' as const);
    return Promise.resolve((this.misses.get(sourceKey) ?? 0) >= 3 ? 'blocked' : 'allowed');
  }

  recordActivation(input: { readonly activationId: string; readonly sourceKey: string }) {
    if (this.unavailable || this.activationUnavailable) {
      return Promise.resolve('unavailable' as const);
    }
    if (!this.activations.includes(input.activationId)) this.activations.push(input.activationId);
    this.misses.delete(input.sourceKey);
    return Promise.resolve('recorded' as const);
  }

  recordSyntacticallyValidMiss(input: { readonly sourceKey: string }) {
    if (this.unavailable) return Promise.resolve('unavailable' as const);
    const count = (this.misses.get(input.sourceKey) ?? 0) + 1;
    this.misses.set(input.sourceKey, count);
    return Promise.resolve(count >= 3 ? ('blocked' as const) : ('allowed' as const));
  }
}

function policy() {
  const rule = Object.freeze({ limit: 100, windowMs: 15 * 60_000 });
  return Object.freeze({
    challenge: emailChallengePolicy,
    rateLimits: Object.freeze({
      challengeByEmail: rule,
      challengeByFingerprint: rule,
      challengeByNetwork: rule,
      verifyByChallenge: rule,
      verifyByNetwork: rule,
    }),
    session: Object.freeze({
      absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
      idleLifetimeMs: 7 * 24 * 60 * 60_000,
    }),
  });
}

async function fixture() {
  const clock = new ManualClock(now);
  const repository = new LocalAuthRepository({ NODE_ENV: 'test' });
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const protector = new LocalGateProtector();
  const crypto = new HmacAuthCrypto({
    challengePepper: 'c'.repeat(64),
    personalGatePepper: 'g'.repeat(64),
    rateLimitPepper: 'r'.repeat(64),
    sessionPepper: 's'.repeat(64),
  });
  const service = new AuthService({
    clock,
    crypto,
    delivery,
    gateAbuseProtector: protector,
    policy: policy(),
    random: new SystemAuthRandomSource(),
    rateLimiter: new LocalRateLimiter({ NODE_ENV: 'test' }),
    repository,
  });
  await service.bootstrapAdministrator({
    bootstrapId: 'personal-gate-bootstrap-0001',
    displayName: 'Synthetic Administrator',
    email: 'administrator@gate.invalid',
    userId: administratorId,
  });
  const administratorChallenge = await service.requestEmailChallenge({
    email: 'administrator@gate.invalid',
    fingerprint: 'setup-browser',
    networkAddress: 'setup-network',
  });
  const administratorMessage = delivery.messages.at(-1);
  if (administratorMessage === undefined) throw new Error('Missing setup challenge');
  const administratorSession = await service.verifyEmailChallenge({
    challengeId: administratorChallenge.challengeId,
    code: administratorMessage.code,
    networkAddress: 'setup-network',
  });
  const account = await service.createAccount(
    administratorSession.sessionToken,
    { displayName: 'Synthetic Member', email: 'member@gate.invalid' },
    correlationId,
  );
  delivery.messages.splice(0);
  return {
    account,
    administratorSession,
    clock,
    crypto,
    delivery,
    protector,
    repository,
    service,
  };
}

async function activate(value: Awaited<ReturnType<typeof fixture>>, code: string, browser: string) {
  const activation = await value.service.activatePersonalGate(code, browser, {
    correlationId,
    fingerprint: browser,
    networkAddress: 'synthetic-network',
  });
  if (activation === null) throw new Error('Expected gate activation');
  return activation;
}

describe('A6 personal entry gate', () => {
  it('normalizes Crockford ambiguity but rejects syntactic errors locally', () => {
    expect(normalizePersonalGateCode('ol23-4567')).toBe('01234567');
    expect(normalizePersonalGateCode('ABCD-EFGH')).toBe('ABCDEFGH');
    expect(normalizePersonalGateCode('ABCD-UFGH')).toBeNull();
    expect(normalizePersonalGateCode('short')).toBeNull();
  });

  it('uses a strict host-only cookie and never serializes verifier material', () => {
    const crypto = new HmacAuthCrypto({
      challengePepper: 'c'.repeat(64),
      personalGatePepper: 'g'.repeat(64),
      rateLimitPepper: 'r'.repeat(64),
      sessionPepper: 's'.repeat(64),
    });
    const credentials = crypto.personalGateActivationCredentials(
      '01234567',
      'synthetic-browser-0001',
    );
    expect(credentials.gateToken).toHaveLength(43);
    expect(credentials.gateTokenVerifier).toHaveLength(43);
    expect(credentials.gateTokenVerifier).not.toBe(credentials.gateToken);
    const cookie = new PersonalGateCookie().issue(credentials.gateToken);
    expect(cookie).toContain('__Host-kovcheg_gate=');
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).not.toContain(credentials.gateTokenVerifier);
  });

  it('keeps wrong email at the email step and accepts current email case-insensitively', async () => {
    const value = await fixture();
    const issued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const activation = await activate(value, issued.code.toLowerCase(), 'synthetic-browser-01');
    const wrong = await value.service.requestPersonalGateEmailChallenge(activation.gateToken, {
      correlationId,
      email: 'wrong@gate.invalid',
      fingerprint: 'synthetic-browser-01',
      networkAddress: 'synthetic-network',
    });
    expect(wrong).toEqual({ next: 'email', status: 'accepted' });
    expect(value.delivery.messages).toHaveLength(0);

    const correct = await value.service.requestPersonalGateEmailChallenge(activation.gateToken, {
      correlationId,
      email: '  MEMBER@GATE.INVALID ',
      fingerprint: 'synthetic-browser-01',
      networkAddress: 'synthetic-network',
    });
    expect(correct).toMatchObject({ next: 'code', status: 'accepted' });
    expect(value.delivery.messages).toHaveLength(1);
  });

  it('supports separate browsers, one-time challenge consume, revoke, and deactivation semantics', async () => {
    const value = await fixture();
    const issued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const first = await activate(value, issued.code, 'synthetic-browser-01');
    const repeated = await activate(value, issued.code, 'synthetic-browser-01');
    const second = await activate(value, issued.code, 'synthetic-browser-02');
    expect(repeated).toMatchObject({ gateSessionId: first.gateSessionId, reused: true });
    expect(second.gateSessionId).not.toBe(first.gateSessionId);

    const challenge = await value.service.requestPersonalGateEmailChallenge(first.gateToken, {
      correlationId,
      email: value.account.email,
      fingerprint: 'synthetic-browser-01',
      networkAddress: 'synthetic-network',
    });
    if (challenge.next !== 'code') throw new Error('Expected gate challenge');
    const message = value.delivery.messages.at(-1);
    if (message === undefined) throw new Error('Expected delivered challenge');
    const attempts = await Promise.allSettled(
      Array.from({ length: 8 }, async () =>
        value.service.verifyPersonalGateEmailChallenge(first.gateToken, {
          challengeId: challenge.challengeId,
          code: message.code,
          networkAddress: 'synthetic-network',
        }),
      ),
    );
    expect(attempts.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const authenticated = attempts.find(
      (
        result,
      ): result is PromiseFulfilledResult<
        Awaited<ReturnType<typeof value.service.verifyPersonalGateEmailChallenge>>
      > => result.status === 'fulfilled',
    )?.value;
    if (authenticated === undefined) throw new Error('Missing authenticated session');

    await value.service.revokePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      issued.familyId,
      correlationId,
    );
    await expect(value.service.validatePersonalGate(first.gateToken)).resolves.toBe(false);
    await expect(
      value.service.authenticateSession(authenticated.sessionToken),
    ).resolves.toMatchObject({
      userId: value.account.userId,
    });

    const reissued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const afterRevoke = await activate(value, reissued.code, 'synthetic-browser-03');
    await value.service.setAccountStatus(
      value.administratorSession.sessionToken,
      value.account.userId,
      'deactivated',
      correlationId,
    );
    await expect(value.service.validatePersonalGate(afterRevoke.gateToken)).resolves.toBe(false);
    await expect(
      value.service.authenticateSession(authenticated.sessionToken),
    ).rejects.toMatchObject({
      code: 'auth.invalid-session',
    });
  });

  it('enforces hidden pause and suspension without issuing a challenge', async () => {
    const value = await fixture();
    const issued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const activation = await activate(value, issued.code, 'synthetic-browser-04');
    for (let pause = 0; pause < 3; pause += 1) {
      for (let mismatch = 0; mismatch < 5; mismatch += 1) {
        await expect(
          value.service.requestPersonalGateEmailChallenge(activation.gateToken, {
            correlationId,
            email: `wrong-${pause}-${mismatch}@gate.invalid`,
            fingerprint: 'synthetic-browser-04',
            networkAddress: 'synthetic-network',
          }),
        ).resolves.toEqual({ next: 'email', status: 'accepted' });
      }
      value.clock.advance(15 * 60_000);
    }
    expect(value.delivery.messages).toHaveLength(0);
    await expect(value.service.validatePersonalGate(activation.gateToken)).resolves.toBe(false);
    await expect(
      value.service.requestPersonalGateEmailChallenge(activation.gateToken, {
        correlationId,
        email: value.account.email,
        fingerprint: 'synthetic-browser-04',
        networkAddress: 'synthetic-network',
      }),
    ).resolves.toEqual({ next: 'email', status: 'accepted' });
    await expect(
      value.service.resumePersonalGate(
        value.administratorSession.sessionToken,
        value.account.userId,
        issued.familyId,
        correlationId,
      ),
    ).resolves.toBe(true);
    await expect(
      activate(value, issued.code, 'synthetic-browser-after-resume'),
    ).resolves.toMatchObject({ reused: false });
  });

  it('counts only syntactically valid missing codes and fails closed on protection loss', async () => {
    const value = await fixture();
    const context = {
      correlationId,
      fingerprint: 'synthetic-browser-05',
      networkAddress: 'synthetic-network',
    };
    await expect(
      value.service.activatePersonalGate('invalid', 'synthetic-browser-05', context),
    ).resolves.toBeNull();
    expect(value.protector.misses.size).toBe(0);
    await Promise.all(
      Array.from({ length: 3 }, async () =>
        value.service.activatePersonalGate('0123-4567', 'synthetic-browser-05', context),
      ),
    );
    expect([...value.protector.misses.values()]).toContain(3);
    value.protector.unavailable = true;
    await expect(
      value.service.activatePersonalGate('0123-4567', 'synthetic-browser-06', {
        ...context,
        fingerprint: 'synthetic-browser-06',
      }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });
  });

  it('records a new-device signal exactly once after Redis recovers from activation loss', async () => {
    const value = await fixture();
    const issued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const context = {
      correlationId,
      fingerprint: 'synthetic-browser-recovery',
      networkAddress: 'synthetic-network',
    };
    value.protector.activationUnavailable = true;
    await expect(
      value.service.activatePersonalGate(issued.code, 'synthetic-browser-recovery', context),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });

    value.protector.activationUnavailable = false;
    await expect(
      value.service.activatePersonalGate(issued.code, 'synthetic-browser-recovery', context),
    ).resolves.toMatchObject({ reused: true });
    await value.service.activatePersonalGate(issued.code, 'synthetic-browser-recovery', context);
    expect(value.protector.activations).toHaveLength(1);
  });

  it('extends gate expiry only after successful OTP login', async () => {
    const value = await fixture();
    const issued = await value.service.issuePersonalGate(
      value.administratorSession.sessionToken,
      value.account.userId,
      correlationId,
    );
    const activation = await activate(value, issued.code, 'synthetic-browser-07');
    value.clock.advance(personalGateLifetimeMs - 60_000);
    const challenge = await value.service.requestPersonalGateEmailChallenge(activation.gateToken, {
      correlationId,
      email: value.account.email,
      fingerprint: 'synthetic-browser-07',
      networkAddress: 'synthetic-network',
    });
    if (challenge.next !== 'code') throw new Error('Expected challenge');
    const message = value.delivery.messages.at(-1);
    if (message === undefined) throw new Error('Expected challenge delivery');
    await value.service.verifyPersonalGateEmailChallenge(activation.gateToken, {
      challengeId: challenge.challengeId,
      code: message.code,
      networkAddress: 'synthetic-network',
    });
    value.clock.advance(2 * 60_000);
    await expect(value.service.validatePersonalGate(activation.gateToken)).resolves.toBe(true);
  });
});
