import type { UserId } from '@kovcheg/contracts';
import { loadServiceConfig } from '@kovcheg/config';
import { exportJWK, generateKeyPair } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';

import { createAuthApplication } from '../application.js';
import { emailChallengePolicy } from './contracts.js';
import { LocalAuthRepository, LocalEmailChallengeDelivery, ManualClock } from './local-adapters.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';
import { createAuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';

const administratorId = '00000000-0000-4000-8000-000000000031' satisfies UserId;
const openApplications: Awaited<ReturnType<typeof createAuthApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

const alwaysAllowRedis: RedisScriptClient = Object.freeze({
  eval(): Promise<unknown> {
    return Promise.resolve(1);
  },
});

async function testConfig(): Promise<EnabledAuthRuntimeConfig> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const rule = Object.freeze({ limit: 100, windowMs: 15 * 60_000 });
  return Object.freeze({
    authSecrets: Object.freeze({
      challengePepper: 'c'.repeat(64),
      rateLimitPepper: 'r'.repeat(64),
      sessionPepper: 's'.repeat(64),
    }),
    enabled: true,
    environment: 'test',
    oidc: Object.freeze({
      clients: Object.freeze([
        Object.freeze({
          clientId: 'synthetic-http-client',
          redirectUris: Object.freeze(['http://127.0.0.1/callback']),
          scopes: Object.freeze(['openid']),
          tokenEndpointAuthMethod: 'none' as const,
        }),
      ]),
      cookieKeys: Object.freeze(['k'.repeat(64), 'l'.repeat(64)]),
      issuer: 'http://127.0.0.1:4301',
      jwks: {
        keys: [
          {
            ...privateJwk,
            alg: 'ES256',
            kid: 'synthetic-http-signing-key',
            use: 'sig',
          },
        ],
      },
      sessionTtlSeconds: 3600,
    }),
    policy: Object.freeze({
      challenge: emailChallengePolicy,
      rateLimits: Object.freeze({
        challengeByEmail: rule,
        challengeByFingerprint: rule,
        challengeByNetwork: rule,
        verifyByChallenge: rule,
        verifyByNetwork: rule,
      }),
      session: Object.freeze({
        absoluteLifetimeMs: 60 * 60_000,
        idleLifetimeMs: 15 * 60_000,
      }),
    }),
    redisUrl: 'redis://127.0.0.1:6379',
    secureCookies: false,
  });
}

async function createFixture() {
  const clock = new ManualClock(Date.UTC(2026, 0, 1));
  const repository = new LocalAuthRepository({ NODE_ENV: 'test' });
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const runtime = await createAuthRuntime({
    clock,
    config: await testConfig(),
    delivery,
    redisClientFactory: {
      connect: () => Promise.resolve(alwaysAllowRedis),
    },
    repository,
  });
  await runtime.authService.bootstrapAdministrator({
    bootstrapId: 'synthetic-http-bootstrap-0001',
    displayName: 'HTTP Test Administrator',
    email: 'http-administrator@example.invalid',
    userId: administratorId,
  });
  const administratorChallenge = await runtime.authService.requestEmailChallenge({
    email: 'http-administrator@example.invalid',
    fingerprint: 'fixture-administrator',
    networkAddress: 'fixture-network',
  });
  const administratorMessage = delivery.messages.at(-1);
  if (administratorMessage === undefined) {
    throw new Error('Expected synthetic administrator challenge');
  }
  const administratorSession = await runtime.authService.verifyEmailChallenge({
    challengeId: administratorChallenge.challengeId,
    code: administratorMessage.code,
    networkAddress: 'fixture-network',
  });
  const activeAccount = await runtime.authService.createAccount(administratorSession.sessionToken, {
    displayName: 'Active HTTP Account',
    email: 'active-http@example.invalid',
  });
  const inactiveAccount = await runtime.authService.createAccount(
    administratorSession.sessionToken,
    {
      displayName: 'Inactive HTTP Account',
      email: 'inactive-http@example.invalid',
    },
  );
  await runtime.authService.setAccountStatus(
    administratorSession.sessionToken,
    inactiveAccount.userId,
    'deactivated',
  );
  delivery.messages.splice(0);

  const app = await createAuthApplication(
    loadServiceConfig('auth', { LOG_LEVEL: 'error', NODE_ENV: 'test' }),
    runtime,
  );
  openApplications.push(app);
  await app.listen(0, '127.0.0.1');
  return {
    activeAccount,
    administratorSession,
    baseUrl: await app.getUrl(),
    clock,
    delivery,
    runtime,
  };
}

async function requestChallenge(baseUrl: string, email: string): Promise<Response> {
  return fetch(`${baseUrl}/session/challenges`, {
    body: JSON.stringify({ email }),
    headers: { 'content-type': 'application/json', 'user-agent': 'synthetic-http-test' },
    method: 'POST',
  });
}

function responseCookie(response: Response): string {
  const setCookie = response.headers.getSetCookie()[0];
  if (setCookie === undefined) {
    throw new Error('Expected a session cookie');
  }
  return setCookie.split(';', 1)[0] ?? '';
}

describe('A2 auth HTTP runtime', () => {
  it('returns the same neutral response shape for known, inactive, and unknown email', async () => {
    const fixture = await createFixture();
    const [known, inactive, unknown, unauthorized, oidcUnauthorized, discovery] = await Promise.all(
      [
        requestChallenge(fixture.baseUrl, 'active-http@example.invalid'),
        requestChallenge(fixture.baseUrl, 'inactive-http@example.invalid'),
        requestChallenge(fixture.baseUrl, 'unknown-http@example.invalid'),
        fetch(`${fixture.baseUrl}/session`),
        fetch(`${fixture.baseUrl}/interaction/synthetic`),
        fetch(`${fixture.baseUrl}/.well-known/openid-configuration`),
      ],
    );

    expect([known.status, inactive.status, unknown.status]).toEqual([202, 202, 202]);
    const bodies = (await Promise.all([known.json(), inactive.json(), unknown.json()])) as Record<
      string,
      unknown
    >[];
    expect(bodies.map((body) => Object.keys(body).sort())).toEqual([
      ['challengeId', 'status'],
      ['challengeId', 'status'],
      ['challengeId', 'status'],
    ]);
    expect(bodies.map((body) => body.status)).toEqual(['accepted', 'accepted', 'accepted']);
    expect(
      [known, inactive, unknown].every((response) => !response.headers.has('set-cookie')),
    ).toBe(true);
    expect(fixture.delivery.messages).toHaveLength(1);
    expect(fixture.delivery.messages[0]?.recipient).toBe('active-http@example.invalid');
    expect(unauthorized.status).toBe(401);
    await expect(unauthorized.json()).resolves.toEqual({ error: 'auth.invalid-session' });
    expect(oidcUnauthorized.status).toBe(401);
    await expect(oidcUnauthorized.json()).resolves.toEqual({ error: 'auth.invalid-session' });
    expect(discovery.status).toBe(200);
    await expect(discovery.json()).resolves.toMatchObject({
      issuer: 'http://127.0.0.1:4301',
      response_types_supported: ['code'],
    });

    const rejectedVerifications = await Promise.all(
      bodies.slice(1).map(async (body) =>
        fetch(`${fixture.baseUrl}/session/challenges/${String(body.challengeId)}/verify`, {
          body: JSON.stringify({ code: '000000' }),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        }),
      ),
    );
    expect(rejectedVerifications.map((response) => response.status)).toEqual([401, 401]);
    expect(rejectedVerifications.every((response) => !response.headers.has('set-cookie'))).toBe(
      true,
    );
  });

  it('issues an HTTP-only server session cookie, logs out, and rejects the revoked token', async () => {
    const fixture = await createFixture();
    const challengeResponse = await requestChallenge(
      fixture.baseUrl,
      'active-http@example.invalid',
    );
    const challenge = (await challengeResponse.json()) as { challengeId: string };
    const message = fixture.delivery.messages.at(-1);
    if (message === undefined) {
      throw new Error('Expected active-account delivery');
    }
    const verification = await fetch(
      `${fixture.baseUrl}/session/challenges/${challenge.challengeId}/verify`,
      {
        body: JSON.stringify({ code: message.code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      },
    );
    expect(verification.status).toBe(200);
    const setCookie = verification.headers.getSetCookie()[0] ?? '';
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).not.toContain('Secure');
    const cookie = responseCookie(verification);

    const authenticated = await fetch(`${fixture.baseUrl}/session`, {
      headers: { cookie },
    });
    expect(authenticated.status).toBe(200);
    await expect(authenticated.json()).resolves.toMatchObject({
      userId: fixture.activeAccount.userId,
    });

    const logout = await fetch(`${fixture.baseUrl}/session`, {
      headers: { cookie },
      method: 'DELETE',
    });
    expect(logout.status).toBe(204);
    expect(logout.headers.getSetCookie()[0]).toContain('Max-Age=0');
    expect(await fetch(`${fixture.baseUrl}/session`, { headers: { cookie } })).toMatchObject({
      status: 401,
    });
  });

  it('rejects an existing session immediately after account deactivation', async () => {
    const fixture = await createFixture();
    const challenge = (await (
      await requestChallenge(fixture.baseUrl, 'active-http@example.invalid')
    ).json()) as { challengeId: string };
    const message = fixture.delivery.messages.at(-1);
    if (message === undefined) {
      throw new Error('Expected active-account delivery');
    }
    const verification = await fetch(
      `${fixture.baseUrl}/session/challenges/${challenge.challengeId}/verify`,
      {
        body: JSON.stringify({ code: message.code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      },
    );
    const cookie = responseCookie(verification);
    await fixture.runtime.authService.setAccountStatus(
      fixture.administratorSession.sessionToken,
      fixture.activeAccount.userId,
      'deactivated',
    );

    const response = await fetch(`${fixture.baseUrl}/session`, { headers: { cookie } });
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'auth.invalid-session' });
  });
});
