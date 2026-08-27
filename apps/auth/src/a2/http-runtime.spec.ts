import { correlationIdHeaderName } from '@kovcheg/contracts';
import type { CorrelationId, UserId } from '@kovcheg/contracts';
import { loadServiceConfig } from '@kovcheg/config';
import { exportJWK, generateKeyPair } from 'jose';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { afterEach, describe, expect, it } from 'vitest';

import { createAuthApplication } from '../application.js';
import { emailChallengePolicy, passkeyPolicy, passkeyRateLimitPolicy } from './contracts.js';
import { LocalAuthRepository, LocalEmailChallengeDelivery, ManualClock } from './local-adapters.js';
import type { WebAuthnServer } from './ports.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';
import { createAuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import { SimpleWebAuthnServer } from './webauthn-server.js';

const administratorId = '00000000-0000-4000-8000-000000000031' satisfies UserId;
const setupCorrelationId = 'http-runtime-setup' as CorrelationId;
const openApplications: Awaited<ReturnType<typeof createAuthApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

const alwaysAllowRedis: RedisScriptClient = Object.freeze({
  eval(script: string): Promise<unknown> {
    return Promise.resolve(script.includes("EXISTS', KEYS[1]") ? 0 : 1);
  },
  isReady(): boolean {
    return true;
  },
});

async function testConfig(
  rateLimitOverrides: Partial<EnabledAuthRuntimeConfig['policy']['rateLimits']> = {},
): Promise<EnabledAuthRuntimeConfig> {
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
      passkey: passkeyPolicy,
      rateLimits: Object.freeze({
        challengeByEmail: rule,
        challengeByFingerprint: rule,
        challengeByNetwork: rule,
        ...passkeyRateLimitPolicy,
        verifyByChallenge: rule,
        verifyByNetwork: rule,
        ...rateLimitOverrides,
      }),
      session: Object.freeze({
        absoluteLifetimeMs: 60 * 60_000,
        idleLifetimeMs: 15 * 60_000,
      }),
    }),
    redisUrl: 'redis://127.0.0.1:6379',
    secureCookies: false,
    webauthn: Object.freeze({
      origins: Object.freeze(['https://auth-http.invalid']),
      rpId: 'auth-http.invalid',
      rpName: 'Synthetic Auth',
    }),
  });
}

async function createFixture(
  rateLimitOverrides: Partial<EnabledAuthRuntimeConfig['policy']['rateLimits']> = {},
  redisClient: RedisScriptClient = alwaysAllowRedis,
  webauthn?: WebAuthnServer,
) {
  const clock = new ManualClock(Date.UTC(2026, 0, 1));
  const repository = new LocalAuthRepository({ NODE_ENV: 'test' });
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const runtime = await createAuthRuntime({
    clock,
    config: await testConfig(rateLimitOverrides),
    delivery,
    redisClientFactory: {
      connect: () => Promise.resolve(redisClient),
    },
    repository,
    ...(webauthn === undefined ? {} : { webauthn }),
  });
  await runtime.authService.bootstrapAdministrator({
    bootstrapId: 'synthetic-http-bootstrap-0001',
    displayName: 'HTTP Test Administrator',
    email: 'http-administrator@example.invalid',
    userId: administratorId,
  });
  const administratorChallenge = await runtime.authService.requestEmailChallenge({
    correlationId: setupCorrelationId,
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
  const activeAccount = await runtime.authService.createAccount(
    administratorSession.sessionToken,
    {
      displayName: 'Active HTTP Account',
      email: 'active-http@example.invalid',
    },
    setupCorrelationId,
  );
  const inactiveAccount = await runtime.authService.createAccount(
    administratorSession.sessionToken,
    {
      displayName: 'Inactive HTTP Account',
      email: 'inactive-http@example.invalid',
    },
    setupCorrelationId,
  );
  await runtime.authService.setAccountStatus(
    administratorSession.sessionToken,
    inactiveAccount.userId,
    'deactivated',
    setupCorrelationId,
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

class StatefulRedis implements RedisScriptClient {
  private readonly values = new Map<string, string>();

  eval(
    script: string,
    options?: { readonly arguments: readonly string[]; readonly keys: readonly string[] },
  ): Promise<unknown> {
    const key = options?.keys[0];
    if (script.includes("'SET', KEYS[1], ARGV[1], 'NX', 'PX'") && key !== undefined) {
      if (this.values.has(key)) return Promise.resolve(0);
      const value = options?.arguments[0];
      if (value === undefined) return Promise.resolve(0);
      this.values.set(key, value);
      return Promise.resolve(1);
    }
    if (script.includes("'GETDEL', KEYS[1]") && key !== undefined) {
      const value = this.values.get(key);
      this.values.delete(key);
      return Promise.resolve(value ?? false);
    }
    return Promise.resolve(script.includes("'EXISTS', KEYS[1]") ? 0 : 1);
  }

  isReady(): boolean {
    return true;
  }
}

class HttpSyntheticWebAuthn implements WebAuthnServer {
  private readonly options = new SimpleWebAuthnServer();

  generateAuthenticationOptions(
    input: Parameters<WebAuthnServer['generateAuthenticationOptions']>[0],
  ) {
    return this.options.generateAuthenticationOptions(input);
  }

  generateRegistrationOptions(input: Parameters<WebAuthnServer['generateRegistrationOptions']>[0]) {
    return this.options.generateRegistrationOptions(input);
  }

  verifyAuthentication(
    input: Parameters<WebAuthnServer['verifyAuthentication']>[0],
  ): ReturnType<WebAuthnServer['verifyAuthentication']> {
    return Promise.resolve({
      backupEligible: true,
      backupState: true,
      observedSignCount: input.credential.signCount + 1,
      userVerified: true,
    });
  }

  verifyRegistration(
    input: Parameters<WebAuthnServer['verifyRegistration']>[0],
  ): ReturnType<WebAuthnServer['verifyRegistration']> {
    return Promise.resolve({
      aaguid: '00000000-0000-0000-0000-000000000000' as const,
      attestationFormat: 'none',
      backupEligible: true,
      backupState: true,
      credentialId: Uint8Array.from(Buffer.from(input.response.id, 'base64url')),
      publicKey: Uint8Array.from([1, 2, 3, 4]),
      signCount: 0,
      transports: Object.freeze(['hybrid'] as const),
      userVerified: true,
    });
  }
}

function httpRegistrationResponse(credentialId: string): RegistrationResponseJSON {
  return {
    clientExtensionResults: {},
    id: credentialId,
    rawId: credentialId,
    response: {
      attestationObject: 'synthetic',
      clientDataJSON: 'synthetic',
      transports: ['hybrid'],
    },
    type: 'public-key',
  };
}

function httpAuthenticationResponse(credentialId: string): AuthenticationResponseJSON {
  return {
    clientExtensionResults: {},
    id: credentialId,
    rawId: credentialId,
    response: {
      authenticatorData: 'synthetic',
      clientDataJSON: 'synthetic',
      signature: 'synthetic',
      userHandle: Buffer.from(administratorId.replaceAll('-', ''), 'hex').toString('base64url'),
    },
    type: 'public-key',
  };
}

async function requestChallenge(
  baseUrl: string,
  email: string,
  forwardedFor?: string,
): Promise<Response> {
  return fetch(`${baseUrl}/session/challenges`, {
    body: JSON.stringify({ email }),
    headers: {
      'content-type': 'application/json',
      ...(forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor }),
      'user-agent': 'synthetic-http-test',
    },
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

function issuedCookie(
  runtime: Awaited<ReturnType<typeof createFixture>>['runtime'],
  token: string,
) {
  return runtime.sessionCookie.issue(token).split(';', 1)[0] ?? '';
}

async function loginThroughHttp(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  email: string,
): Promise<{ readonly cookie: string; readonly sessionId: string }> {
  const challengeResponse = await requestChallenge(fixture.baseUrl, email);
  const challenge = (await challengeResponse.json()) as { readonly challengeId: string };
  const message = fixture.delivery.messages.at(-1);
  if (message === undefined || message.challengeId !== challenge.challengeId) {
    throw new Error('Expected an HTTP challenge delivery');
  }
  const verification = await fetch(
    `${fixture.baseUrl}/session/challenges/${challenge.challengeId}/verify`,
    {
      body: JSON.stringify({ code: message.code }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    },
  );
  const body = (await verification.json()) as { readonly sessionId: string };
  return Object.freeze({ cookie: responseCookie(verification), sessionId: body.sessionId });
}

async function adminRequest(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  input: {
    readonly body?: unknown;
    readonly cookie?: string;
    readonly correlationId: string;
    readonly method: 'DELETE' | 'PATCH' | 'POST' | 'PUT';
    readonly path: string;
  },
): Promise<Response> {
  return fetch(`${fixture.baseUrl}${input.path}`, {
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    headers: {
      ...(input.cookie === undefined ? {} : { cookie: input.cookie }),
      [correlationIdHeaderName]: input.correlationId,
      ...(input.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    method: input.method,
  });
}

describe('A2 auth HTTP runtime', () => {
  it('reports ready only when the durable runtime dependencies are ready', async () => {
    const fixture = await createFixture();
    const response = await fetch(`${fixture.baseUrl}/health/ready`);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      service: 'auth',
      state: 'ready',
      status: 'ok',
    });
  });

  it('moves every valid email to the same neutral code state and delivers only to active accounts', async () => {
    const fixture = await createFixture();
    const [known, inactive, unknown, unauthorized, oidcUnauthorized, discovery] = await Promise.all(
      [
        requestChallenge(fixture.baseUrl, '  ACTIVE-HTTP@EXAMPLE.INVALID  '),
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
    expect(bodies.map((body) => Object.keys(body).sort())).toEqual(
      Array.from({ length: 3 }, () => ['challengeId', 'email', 'next', 'status']),
    );
    expect(bodies.map((body) => body.status)).toEqual(['accepted', 'accepted', 'accepted']);
    expect(bodies.map((body) => body.next)).toEqual(['code', 'code', 'code']);
    expect(bodies.map((body) => body.email)).toEqual([
      'ACTIVE-HTTP@EXAMPLE.INVALID',
      'inactive-http@example.invalid',
      'unknown-http@example.invalid',
    ]);
    expect(
      [known, inactive, unknown].every((response) => !response.headers.has('set-cookie')),
    ).toBe(true);
    expect(fixture.delivery.messages).toHaveLength(1);
    expect(fixture.delivery.messages[0]?.recipient).toBe('active-http@example.invalid');
    expect(unauthorized.status).toBe(401);
    await expect(unauthorized.json()).resolves.toMatchObject({ error: 'auth.invalid-session' });
    expect(oidcUnauthorized.status).toBe(401);
    await expect(oidcUnauthorized.json()).resolves.toMatchObject({ error: 'auth.invalid-session' });
    expect(discovery.status).toBe(200);
    await expect(discovery.json()).resolves.toMatchObject({
      issuer: 'http://127.0.0.1:4301',
      response_types_supported: ['code'],
    });

    const retiredGate = await fetch(`${fixture.baseUrl}/personal-gate/activate`, {
      body: JSON.stringify({ code: 'TEST-CODE' }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
    expect(retiredGate.status).toBe(404);
  });

  it('keeps hidden throttling neutral behind the trusted local proxy', async () => {
    const attempts = new Map<string, number>();
    const redisClient: RedisScriptClient = {
      eval(script, options): Promise<unknown> {
        if (script.includes("EXISTS', KEYS[1]")) return Promise.resolve(0);
        if (script.includes('device-activated')) return Promise.resolve(1);
        const key = options.keys[0];
        const limit = Number(options.arguments[2]);
        if (key === undefined || !Number.isSafeInteger(limit)) {
          return Promise.reject(new Error('Invalid synthetic rate-limit request'));
        }
        const count = attempts.get(key) ?? 0;
        attempts.set(key, count + 1);
        return Promise.resolve(count < limit ? 1 : 0);
      },
      isReady: () => true,
    };
    const fixture = await createFixture(
      { challengeByNetwork: { limit: 1, windowMs: 15 * 60_000 } },
      redisClient,
    );
    const [firstNetwork, secondNetwork] = await Promise.all([
      requestChallenge(fixture.baseUrl, 'network-a@example.invalid', '192.0.2.10'),
      requestChallenge(fixture.baseUrl, 'network-b@example.invalid', '192.0.2.11'),
    ]);
    const repeatedNetwork = await requestChallenge(
      fixture.baseUrl,
      'active-http@example.invalid',
      '192.0.2.10',
    );

    expect([firstNetwork.status, secondNetwork.status]).toEqual([202, 202]);
    expect(repeatedNetwork.status).toBe(202);
    const repeatedBody = (await repeatedNetwork.json()) as Record<string, unknown>;
    expect(Object.keys(repeatedBody).sort()).toEqual(['challengeId', 'email', 'next', 'status']);
    expect(repeatedBody).toMatchObject({
      email: 'active-http@example.invalid',
      next: 'code',
      status: 'accepted',
    });
    expect(fixture.delivery.messages).toHaveLength(0);
  });

  it('fails authentication closed during Redis loss and accepts login after recovery', async () => {
    let redisReady = true;
    const redisClient: RedisScriptClient = {
      eval(script): Promise<unknown> {
        return redisReady
          ? Promise.resolve(script.includes("EXISTS', KEYS[1]") ? 0 : 1)
          : Promise.reject(new Error('Synthetic Redis outage'));
      },
      isReady: () => redisReady,
    };
    const fixture = await createFixture({}, redisClient);

    redisReady = false;
    const unavailableReadiness = await fetch(`${fixture.baseUrl}/health/ready`);
    const unavailableChallenge = await requestChallenge(
      fixture.baseUrl,
      'active-http@example.invalid',
    );
    expect(unavailableReadiness.status).toBe(503);
    expect(unavailableChallenge.status).toBe(503);
    await expect(unavailableChallenge.json()).resolves.toMatchObject({
      error: 'auth.unavailable',
    });

    redisReady = true;
    expect(await fetch(`${fixture.baseUrl}/health/ready`)).toMatchObject({ status: 200 });
    const recoveredSession = await loginThroughHttp(fixture, 'active-http@example.invalid');
    expect(
      await fetch(`${fixture.baseUrl}/session`, {
        headers: { cookie: recoveredSession.cookie },
      }),
    ).toMatchObject({ status: 200 });
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

    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const secondChallengeResponse = await requestChallenge(
      fixture.baseUrl,
      'active-http@example.invalid',
    );
    const secondChallenge = (await secondChallengeResponse.json()) as { challengeId: string };
    const secondMessage = fixture.delivery.messages.at(-1);
    if (secondMessage === undefined) {
      throw new Error('Expected second active-account delivery');
    }
    const secondVerification = await fetch(
      `${fixture.baseUrl}/session/challenges/${secondChallenge.challengeId}/verify`,
      {
        body: JSON.stringify({ code: secondMessage.code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      },
    );
    const secondCookie = responseCookie(secondVerification);

    const logout = await fetch(`${fixture.baseUrl}/session`, {
      headers: { cookie },
      method: 'DELETE',
    });
    expect(logout.status).toBe(204);
    expect(logout.headers.getSetCookie()[0]).toContain('Max-Age=0');
    expect(await fetch(`${fixture.baseUrl}/session`, { headers: { cookie } })).toMatchObject({
      status: 401,
    });
    expect(
      await fetch(`${fixture.baseUrl}/session`, { headers: { cookie: secondCookie } }),
    ).toMatchObject({ status: 200 });
  });

  it('keeps internal service validation non-touch while browser session reads remain active', async () => {
    const fixture = await createFixture();
    const session = await loginThroughHttp(fixture, 'active-http@example.invalid');
    fixture.clock.advance(15 * 60_000 - 1);

    const valid = await fetch(`${fixture.baseUrl}/internal/session`, {
      headers: { cookie: session.cookie },
    });
    expect(valid.status).toBe(200);
    await expect(valid.json()).resolves.toMatchObject({ userId: fixture.activeAccount.userId });

    fixture.clock.advance(1);
    const expired = await fetch(`${fixture.baseUrl}/internal/session`, {
      headers: { cookie: session.cookie },
    });
    expect(expired.status).toBe(401);
  });

  it('exposes protected create, update, status, and scoped session revocation over HTTP', async () => {
    const fixture = await createFixture();
    const administratorCookie = issuedCookie(
      fixture.runtime,
      fixture.administratorSession.sessionToken,
    );
    const createdResponse = await adminRequest(fixture, {
      body: {
        displayName: '  Administrative   HTTP Account ',
        email: ' ADMINISTRATION@example.invalid ',
      },
      cookie: administratorCookie,
      correlationId: 'http-admin-create',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(createdResponse.status).toBe(201);
    expect(createdResponse.headers.get(correlationIdHeaderName)).toBe('http-admin-create');
    const created = (await createdResponse.json()) as {
      readonly displayName: string;
      readonly email: string;
      readonly userId: string;
    };
    expect(created).toMatchObject({
      displayName: 'Administrative HTTP Account',
      email: 'administration@example.invalid',
    });

    const unexpectedFieldResponse = await adminRequest(fixture, {
      body: {
        displayName: 'Rejected Account',
        email: 'rejected-account@example.invalid',
        unexpected: true,
      },
      cookie: administratorCookie,
      correlationId: 'http-admin-unexpected-field',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(unexpectedFieldResponse.status).toBe(400);
    await expect(unexpectedFieldResponse.json()).resolves.toEqual({
      correlationId: 'http-admin-unexpected-field',
      error: 'auth.invalid-input',
    });

    const updatedResponse = await adminRequest(fixture, {
      body: {
        displayName: 'Updated Administrative Account',
        email: 'updated-administration@example.invalid',
      },
      cookie: administratorCookie,
      correlationId: 'http-admin-update',
      method: 'PATCH',
      path: `/admin/accounts/${created.userId}`,
    });
    expect(updatedResponse.status).toBe(200);
    await expect(updatedResponse.json()).resolves.toMatchObject({
      displayName: 'Updated Administrative Account',
      email: 'updated-administration@example.invalid',
    });

    const conflictResponse = await adminRequest(fixture, {
      body: { displayName: 'Must Roll Back', email: 'active-http@example.invalid' },
      cookie: administratorCookie,
      correlationId: 'http-admin-update-conflict',
      method: 'PATCH',
      path: `/admin/accounts/${created.userId}`,
    });
    expect(conflictResponse.status).toBe(409);
    await expect(conflictResponse.json()).resolves.toEqual({
      correlationId: 'http-admin-update-conflict',
      error: 'auth.conflict',
    });

    const missingResponse = await adminRequest(fixture, {
      body: { displayName: 'Missing', email: 'missing-http@example.invalid' },
      cookie: administratorCookie,
      correlationId: 'http-admin-missing-target',
      method: 'PATCH',
      path: '/admin/accounts/00000000-0000-4000-8000-000000000099',
    });
    expect(missingResponse.status).toBe(404);
    await expect(missingResponse.json()).resolves.toEqual({
      correlationId: 'http-admin-missing-target',
      error: 'auth.not-found',
    });

    const firstSession = await loginThroughHttp(fixture, 'updated-administration@example.invalid');
    fixture.clock.advance(emailChallengePolicy.resendCooldownMs);
    const secondSession = await loginThroughHttp(fixture, 'updated-administration@example.invalid');
    const otherSession = await loginThroughHttp(fixture, 'active-http@example.invalid');

    const foreignRevoke = await adminRequest(fixture, {
      cookie: administratorCookie,
      correlationId: 'http-admin-revoke-foreign',
      method: 'DELETE',
      path: `/admin/accounts/${created.userId}/sessions/${otherSession.sessionId}`,
    });
    expect(foreignRevoke.status).toBe(200);
    await expect(foreignRevoke.json()).resolves.toEqual({ revoked: false });
    expect(
      await fetch(`${fixture.baseUrl}/session`, { headers: { cookie: otherSession.cookie } }),
    ).toMatchObject({ status: 200 });

    const oneRevoke = await adminRequest(fixture, {
      cookie: administratorCookie,
      correlationId: 'http-admin-revoke-one',
      method: 'DELETE',
      path: `/admin/accounts/${created.userId}/sessions/${firstSession.sessionId}`,
    });
    await expect(oneRevoke.json()).resolves.toEqual({ revoked: true });
    expect(
      await fetch(`${fixture.baseUrl}/session`, { headers: { cookie: firstSession.cookie } }),
    ).toMatchObject({ status: 401 });

    const revokeAllResponses = await Promise.all(
      Array.from({ length: 8 }, async (_, index) =>
        adminRequest(fixture, {
          cookie: administratorCookie,
          correlationId: `http-admin-revoke-all-${index + 1}`,
          method: 'DELETE',
          path: `/admin/accounts/${created.userId}/sessions`,
        }),
      ),
    );
    const revokeAllBodies = (await Promise.all(
      revokeAllResponses.map(async (response) => response.json()),
    )) as { readonly revokedSessionCount: number }[];
    expect(revokeAllBodies.reduce((sum, body) => sum + body.revokedSessionCount, 0)).toBe(1);
    expect(revokeAllBodies.filter((body) => body.revokedSessionCount > 0)).toHaveLength(1);
    expect(
      await fetch(`${fixture.baseUrl}/session`, { headers: { cookie: secondSession.cookie } }),
    ).toMatchObject({ status: 401 });

    const statusResponse = await adminRequest(fixture, {
      body: { status: 'deactivated' },
      cookie: administratorCookie,
      correlationId: 'http-admin-deactivate',
      method: 'PATCH',
      path: `/admin/accounts/${created.userId}/status`,
    });
    expect(statusResponse.status).toBe(200);
    await expect(statusResponse.json()).resolves.toMatchObject({ status: 'deactivated' });
  });

  it('rejects missing, ordinary, expired, revoked, and deactivated administrator sessions', async () => {
    const missingFixture = await createFixture();
    const missing = await adminRequest(missingFixture, {
      body: { displayName: 'Denied', email: 'denied-missing@example.invalid' },
      correlationId: 'http-admin-missing-session',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(missing.status).toBe(401);
    await expect(missing.json()).resolves.toEqual({
      correlationId: 'http-admin-missing-session',
      error: 'auth.invalid-session',
    });

    const ordinarySession = await loginThroughHttp(missingFixture, 'active-http@example.invalid');
    const ordinary = await adminRequest(missingFixture, {
      body: { displayName: 'Denied', email: 'denied-member@example.invalid' },
      cookie: ordinarySession.cookie,
      correlationId: 'http-admin-ordinary-session',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(ordinary.status).toBe(403);
    await expect(ordinary.json()).resolves.toEqual({
      correlationId: 'http-admin-ordinary-session',
      error: 'auth.forbidden',
    });

    const revokedCookie = issuedCookie(
      missingFixture.runtime,
      missingFixture.administratorSession.sessionToken,
    );
    expect(
      await fetch(`${missingFixture.baseUrl}/session`, {
        headers: { cookie: revokedCookie },
        method: 'DELETE',
      }),
    ).toMatchObject({ status: 204 });
    const revoked = await adminRequest(missingFixture, {
      body: { displayName: 'Denied', email: 'denied-revoked@example.invalid' },
      cookie: revokedCookie,
      correlationId: 'http-admin-revoked-session',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(revoked.status).toBe(403);

    const expiredFixture = await createFixture();
    const expiredCookie = issuedCookie(
      expiredFixture.runtime,
      expiredFixture.administratorSession.sessionToken,
    );
    expiredFixture.clock.advance((await testConfig()).policy.session.idleLifetimeMs);
    const expired = await adminRequest(expiredFixture, {
      body: { displayName: 'Denied', email: 'denied-expired@example.invalid' },
      cookie: expiredCookie,
      correlationId: 'http-admin-expired-session',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(expired.status).toBe(403);

    const deactivatedFixture = await createFixture();
    const deactivatedCookie = issuedCookie(
      deactivatedFixture.runtime,
      deactivatedFixture.administratorSession.sessionToken,
    );
    const deactivation = await adminRequest(deactivatedFixture, {
      body: { status: 'deactivated' },
      cookie: deactivatedCookie,
      correlationId: 'http-admin-deactivate-actor',
      method: 'PATCH',
      path: `/admin/accounts/${administratorId}/status`,
    });
    expect(deactivation.status).toBe(200);
    const deactivated = await adminRequest(deactivatedFixture, {
      body: { displayName: 'Denied', email: 'denied-deactivated@example.invalid' },
      cookie: deactivatedCookie,
      correlationId: 'http-admin-deactivated-session',
      method: 'POST',
      path: '/admin/accounts',
    });
    expect(deactivated.status).toBe(403);
  });

  it('keeps retired gate endpoints absent while preserving protected security reset', async () => {
    const fixture = await createFixture();
    const administratorCookie = issuedCookie(
      fixture.runtime,
      fixture.administratorSession.sessionToken,
    );
    const createdResponse = await adminRequest(fixture, {
      body: { displayName: 'Reset HTTP Account', email: 'reset-http@example.invalid' },
      cookie: administratorCookie,
      correlationId: 'http-reset-create-account',
      method: 'POST',
      path: '/admin/accounts',
    });
    const created = (await createdResponse.json()) as { readonly userId: UserId };
    const applicationSession = await loginThroughHttp(fixture, 'reset-http@example.invalid');

    const retiredPublic = await fetch(`${fixture.baseUrl}/personal-gate`, { method: 'GET' });
    const retiredAdmin = await adminRequest(fixture, {
      cookie: administratorCookie,
      correlationId: 'http-retired-gate',
      method: 'POST',
      path: `/admin/accounts/${created.userId}/personal-gate`,
    });
    expect([retiredPublic.status, retiredAdmin.status]).toEqual([404, 404]);

    const securityResetResponse = await adminRequest(fixture, {
      cookie: administratorCookie,
      correlationId: 'http-security-reset',
      method: 'POST',
      path: `/admin/accounts/${created.userId}/auth-security-reset`,
    });
    expect(securityResetResponse.status).toBe(201);
    await expect(securityResetResponse.json()).resolves.toMatchObject({
      revokedApplicationSessionCount: 1,
    });
    expect(
      await fetch(`${fixture.baseUrl}/session`, {
        headers: { cookie: applicationSession.cookie },
      }),
    ).toMatchObject({ status: 401 });
  });

  it('exposes session-bound registration and neutral discoverable passkey authentication', async () => {
    const fixture = await createFixture({}, new StatefulRedis(), new HttpSyntheticWebAuthn());
    const missingSession = await fetch(`${fixture.baseUrl}/passkeys/registration/options`, {
      method: 'POST',
    });
    expect(missingSession.status).toBe(401);
    await expect(missingSession.json()).resolves.toMatchObject({ error: 'auth.invalid-session' });

    const applicationSession = await loginThroughHttp(fixture, 'active-http@example.invalid');
    const registrationOptions = await fetch(`${fixture.baseUrl}/passkeys/registration/options`, {
      headers: {
        [correlationIdHeaderName]: 'http-passkey-registration-begin',
        cookie: applicationSession.cookie,
      },
      method: 'POST',
    });
    expect(registrationOptions.status).toBe(200);
    const registration = (await registrationOptions.json()) as {
      readonly ceremonyId: string;
      readonly options: { readonly authenticatorSelection?: { readonly residentKey?: string } };
    };
    expect(registration.options.authenticatorSelection?.residentKey).toBe('required');
    const credentialId = Buffer.from('synthetic-http-passkey').toString('base64url');
    const registrationFinish = await fetch(`${fixture.baseUrl}/passkeys/registration/verify`, {
      body: JSON.stringify({
        ceremonyId: registration.ceremonyId,
        response: httpRegistrationResponse(credentialId),
      }),
      headers: {
        [correlationIdHeaderName]: 'http-passkey-registration-finish',
        'content-type': 'application/json',
        cookie: applicationSession.cookie,
      },
      method: 'POST',
    });
    expect(registrationFinish.status).toBe(201);
    await expect(registrationFinish.json()).resolves.toMatchObject({ status: 'registered' });

    const authenticationOptions = await fetch(
      `${fixture.baseUrl}/passkeys/authentication/options`,
      { method: 'POST' },
    );
    expect(authenticationOptions.status).toBe(200);
    const authentication = (await authenticationOptions.json()) as {
      readonly ceremonyId: string;
      readonly mediation: string;
    };
    expect(authentication.mediation).toBe('conditional');
    const finishBody = JSON.stringify({
      ceremonyId: authentication.ceremonyId,
      response: httpAuthenticationResponse(credentialId),
    });
    const authenticationFinish = await fetch(`${fixture.baseUrl}/passkeys/authentication/verify`, {
      body: finishBody,
      headers: {
        [correlationIdHeaderName]: 'http-passkey-authentication-finish',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(authenticationFinish.status).toBe(200);
    expect(authenticationFinish.headers.getSetCookie()[0]).toContain('HttpOnly');
    const authenticationBody = (await authenticationFinish.json()) as Record<string, unknown>;
    expect(authenticationBody.userId).toBe(fixture.activeAccount.userId);
    expect(authenticationBody.sessionToken).toBeUndefined();

    const replay = await fetch(`${fixture.baseUrl}/passkeys/authentication/verify`, {
      body: finishBody,
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
    expect(replay.status).toBe(401);
    await expect(replay.json()).resolves.toMatchObject({ error: 'auth.invalid-passkey' });

    const unknownOptions = (await (
      await fetch(`${fixture.baseUrl}/passkeys/authentication/options`, { method: 'POST' })
    ).json()) as { readonly ceremonyId: string };
    const unknown = await fetch(`${fixture.baseUrl}/passkeys/authentication/verify`, {
      body: JSON.stringify({
        ceremonyId: unknownOptions.ceremonyId,
        response: httpAuthenticationResponse(Buffer.from('unknown-passkey').toString('base64url')),
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
    expect(unknown.status).toBe(401);
    await expect(unknown.json()).resolves.toMatchObject({ error: 'auth.invalid-passkey' });
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
      setupCorrelationId,
    );

    const response = await fetch(`${fixture.baseUrl}/session`, { headers: { cookie } });
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: 'auth.invalid-session' });
  });
});
