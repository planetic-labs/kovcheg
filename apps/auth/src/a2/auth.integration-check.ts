import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';

import { correlationIdHeaderName } from '@kovcheg/contracts';
import type { CorrelationId, UserId } from '@kovcheg/contracts';
import type { JWKS } from 'oidc-provider';

import { createAuthApplication } from '../application.js';
import { emailChallengePolicy } from './contracts.js';
import { LocalEmailChallengeDelivery, ManualClock } from './local-adapters.js';
import { StaticOidcClientRepository } from './oidc.js';
import {
  createAuthPostgresPool,
  createPostgresOidcStorageAdapter,
  PostgresAuthRepository,
} from './postgres.js';
import { nodeRedisScriptClientFactory } from './redis-client.js';
import { RedisRateLimiter } from './redis-rate-limiter.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';
import { createAuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';

let integrationStage = 'startup';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function correlationId(value: string): CorrelationId {
  return value as CorrelationId;
}

function signingKeys(): JWKS {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    keys: [
      {
        ...privateKey.export({ format: 'jwk' }),
        alg: 'ES256',
        kid: 'synthetic-integration-signing-key',
        use: 'sig',
      },
    ],
  };
}

function runtimeConfig(): EnabledAuthRuntimeConfig {
  const rule = Object.freeze({ limit: 100, windowMs: 15 * 60_000 });
  return Object.freeze({
    authSecrets: Object.freeze({
      challengePepper: 'integration-challenge-pepper'.repeat(3),
      rateLimitPepper: 'integration-rate-limit-pepper'.repeat(3),
      sessionPepper: 'integration-session-pepper'.repeat(3),
    }),
    enabled: true,
    environment: 'test',
    oidc: Object.freeze({
      clients: Object.freeze([
        Object.freeze({
          clientId: 'synthetic-integration-client',
          redirectUris: Object.freeze(['http://127.0.0.1/callback']),
          scopes: Object.freeze(['openid']),
          tokenEndpointAuthMethod: 'none' as const,
        }),
      ]),
      cookieKeys: Object.freeze([
        'integration-cookie-key-primary'.repeat(2),
        'integration-cookie-key-secondary'.repeat(2),
      ]),
      issuer: 'http://127.0.0.1:4302',
      jwks: signingKeys(),
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
        absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
        idleLifetimeMs: 7 * 24 * 60 * 60_000,
      }),
    }),
    redisUrl: process.env.AUTH_REDIS_URL ?? 'redis://redis:6379',
    secureCookies: false,
  });
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function responseCookie(response: Response): string {
  const setCookie = response.headers.getSetCookie()[0];
  assert(setCookie !== undefined, 'A successful verification must set a session cookie');
  return setCookie.split(';', 1)[0] ?? '';
}

function updateCookieJar(response: Response, jar: Map<string, string>): void {
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(';', 1)[0];
    const separator = pair?.indexOf('=') ?? -1;
    if (pair !== undefined && separator > 0) {
      jar.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }
}

function cookieHeader(jar: ReadonlyMap<string, string>): string {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

async function requestChallenge(baseUrl: string, email: string, suffix: string): Promise<Response> {
  return fetch(`${baseUrl}/session/challenges`, {
    body: JSON.stringify({ email }),
    headers: {
      'content-type': 'application/json',
      'user-agent': `synthetic-integration-${suffix}`,
    },
    method: 'POST',
  });
}

async function administrativeRequest(input: {
  readonly baseUrl: string;
  readonly body?: unknown;
  readonly cookie?: string;
  readonly correlationId: string;
  readonly method: 'DELETE' | 'PATCH' | 'POST';
  readonly path: string;
}): Promise<Response> {
  return fetch(`${input.baseUrl}${input.path}`, {
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    headers: {
      ...(input.cookie === undefined ? {} : { cookie: input.cookie }),
      [correlationIdHeaderName]: input.correlationId,
      ...(input.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    method: input.method,
  });
}

async function main(): Promise<void> {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const administratorId = randomUUID() as UserId;
  const administratorEmail = `administrator-${suffix}@auth.invalid`;
  const activeEmail = `active-${suffix}@auth.invalid`;
  const inactiveEmail = `inactive-${suffix}@auth.invalid`;
  const clock = new ManualClock(Date.UTC(2031, 0, 1));
  const pool = createAuthPostgresPool(process.env);
  const repository = new PostgresAuthRepository(pool);
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  let runtimeRedisClient: RedisScriptClient | undefined;
  const config = runtimeConfig();
  const storageAdapter = createPostgresOidcStorageAdapter(pool, () => clock.now());
  const runtime = await createAuthRuntime({
    clientRepository: new StaticOidcClientRepository(config.oidc.clients, { NODE_ENV: 'test' }),
    clock,
    closePersistence: async () => pool.end(),
    config,
    delivery,
    oidcStorageAdapter: storageAdapter,
    redisClientFactory: {
      async connect(url) {
        runtimeRedisClient = await nodeRedisScriptClientFactory.connect(url);
        return runtimeRedisClient;
      },
    },
    repository,
  });
  try {
    integrationStage = 'administrator-bootstrap';
    const bootstrapResults = await Promise.all(
      Array.from({ length: 8 }, async () =>
        runtime.authService.bootstrapAdministrator({
          bootstrapId: `synthetic-bootstrap-${suffix}`,
          displayName: 'Synthetic Integration Administrator',
          email: administratorEmail,
          userId: administratorId,
        }),
      ),
    );
    assert(
      bootstrapResults.filter((result) => result.created).length === 1,
      'Concurrent administrator bootstrap must create exactly once',
    );

    integrationStage = 'administrator-challenge-issue';
    const administratorChallenge = await runtime.authService.requestEmailChallenge({
      email: administratorEmail,
      fingerprint: `administrator-${suffix}`,
      networkAddress: 'integration-network-administrator',
    });
    const administratorMessage = delivery.messages.at(-1);
    assert(administratorMessage !== undefined, 'Administrator challenge must be delivered locally');
    integrationStage = 'administrator-challenge-consume';
    const administratorSession = await runtime.authService.verifyEmailChallenge({
      challengeId: administratorChallenge.challengeId,
      code: administratorMessage.code,
      networkAddress: 'integration-network-administrator',
    });
    integrationStage = 'account-management';
    const activeAccount = await runtime.authService.createAccount(
      administratorSession.sessionToken,
      {
        displayName: 'Synthetic Active Account',
        email: activeEmail,
      },
      correlationId(`integration-admin-create-active-${suffix}`),
    );
    const inactiveAccount = await runtime.authService.createAccount(
      administratorSession.sessionToken,
      {
        displayName: 'Synthetic Inactive Account',
        email: inactiveEmail,
      },
      correlationId(`integration-admin-create-inactive-${suffix}`),
    );
    await runtime.authService.setAccountStatus(
      administratorSession.sessionToken,
      inactiveAccount.userId,
      'deactivated',
      correlationId(`integration-admin-deactivate-inactive-${suffix}`),
    );
    clock.advance(emailChallengePolicy.resendCooldownMs);

    integrationStage = 'http-startup';
    const app = await createAuthApplication(undefined, runtime);
    await app.listen(4302, '127.0.0.1');
    const baseUrl = await app.getUrl();
    try {
      integrationStage = 'administrative-http';
      const administratorCookie = `${runtime.sessionCookie.name}=${administratorSession.sessionToken}`;
      const httpManagedEmail = `http-managed-${suffix}@auth.invalid`;
      const httpCreate = await administrativeRequest({
        baseUrl,
        body: { displayName: 'Synthetic HTTP Managed Account', email: httpManagedEmail },
        cookie: administratorCookie,
        correlationId: `integration-admin-http-create-${suffix}`,
        method: 'POST',
        path: '/admin/accounts',
      });
      assert(httpCreate.status === 201, 'The protected HTTP API must create an account');
      const httpManagedAccount = await readJson(httpCreate);
      const httpManagedAccountId = httpManagedAccount.userId;
      assert(typeof httpManagedAccountId === 'string', 'The HTTP-created account must have an ID');

      const httpUpdate = await administrativeRequest({
        baseUrl,
        body: {
          displayName: 'Synthetic HTTP Managed Account Updated',
          email: `HTTP-MANAGED-${suffix}@AUTH.INVALID`,
        },
        cookie: administratorCookie,
        correlationId: `integration-admin-http-update-${suffix}`,
        method: 'PATCH',
        path: `/admin/accounts/${httpManagedAccountId}`,
      });
      assert(httpUpdate.status === 200, 'The protected HTTP API must update an account');
      const httpUpdatedAccount = await readJson(httpUpdate);
      assert(
        httpUpdatedAccount.email === httpManagedEmail,
        'The protected HTTP update must normalize the email',
      );
      assert(
        httpUpdatedAccount.displayName === 'Synthetic HTTP Managed Account Updated',
        'The protected HTTP update must normalize the display name',
      );

      const httpConflict = await administrativeRequest({
        baseUrl,
        body: { displayName: 'Must Roll Back', email: activeEmail },
        cookie: administratorCookie,
        correlationId: `integration-admin-http-conflict-${suffix}`,
        method: 'PATCH',
        path: `/admin/accounts/${httpManagedAccountId}`,
      });
      assert(httpConflict.status === 409, 'A normalized-email conflict must be machine-readable');
      const conflictBody = await readJson(httpConflict);
      assert(
        conflictBody.error === 'auth.conflict' &&
          conflictBody.correlationId === `integration-admin-http-conflict-${suffix}`,
        'The conflict response must contain only its stable code and correlation ID',
      );

      const missingAdministrator = await administrativeRequest({
        baseUrl,
        body: { displayName: 'Denied', email: `denied-${suffix}@auth.invalid` },
        correlationId: `integration-admin-http-missing-${suffix}`,
        method: 'POST',
        path: '/admin/accounts',
      });
      assert(
        missingAdministrator.status === 401,
        'A missing administrator session must fail closed',
      );

      const firstManagedChallenge = await requestChallenge(
        baseUrl,
        httpManagedEmail,
        'http-managed-first',
      );
      const firstManagedChallengeBody = await readJson(firstManagedChallenge);
      const firstManagedMessage = delivery.messages.at(-1);
      assert(
        firstManagedMessage !== undefined,
        'The HTTP-managed account must receive a challenge',
      );
      const firstManagedVerification = await fetch(
        `${baseUrl}/session/challenges/${String(firstManagedChallengeBody.challengeId)}/verify`,
        {
          body: JSON.stringify({ code: firstManagedMessage.code }),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        },
      );
      const firstManagedCookie = responseCookie(firstManagedVerification);
      clock.advance(emailChallengePolicy.resendCooldownMs);
      const secondManagedChallenge = await requestChallenge(
        baseUrl,
        httpManagedEmail,
        'http-managed-second',
      );
      const secondManagedChallengeBody = await readJson(secondManagedChallenge);
      const secondManagedMessage = delivery.messages.at(-1);
      assert(secondManagedMessage !== undefined, 'A second managed challenge must be delivered');
      const secondManagedVerification = await fetch(
        `${baseUrl}/session/challenges/${String(secondManagedChallengeBody.challengeId)}/verify`,
        {
          body: JSON.stringify({ code: secondManagedMessage.code }),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        },
      );
      const secondManagedCookie = responseCookie(secondManagedVerification);
      const revokeAllResponses = await Promise.all(
        Array.from({ length: 8 }, async (_, index) =>
          administrativeRequest({
            baseUrl,
            cookie: administratorCookie,
            correlationId: `integration-admin-http-revoke-all-${suffix}-${index + 1}`,
            method: 'DELETE',
            path: `/admin/accounts/${httpManagedAccountId}/sessions`,
          }),
        ),
      );
      const revokeAllBodies = await Promise.all(revokeAllResponses.map(readJson));
      assert(
        revokeAllBodies.reduce(
          (total, body) => total + Number(body.revokedSessionCount ?? Number.NaN),
          0,
        ) === 2 &&
          revokeAllBodies.filter((body) => Number(body.revokedSessionCount) > 0).length === 1,
        'Concurrent HTTP revoke-all retries must revoke each managed session exactly once',
      );
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: firstManagedCookie } })).status ===
          401 &&
          (await fetch(`${baseUrl}/session`, { headers: { cookie: secondManagedCookie } }))
            .status === 401,
        'HTTP revoke-all must invalidate every target session',
      );

      integrationStage = 'neutral-http-responses';
      const deliveredBeforeNeutralRequests = delivery.messages.length;
      const [known, inactive, unknown, unauthorized] = await Promise.all([
        requestChallenge(baseUrl, activeEmail, 'known'),
        requestChallenge(baseUrl, inactiveEmail, 'inactive'),
        requestChallenge(baseUrl, `unknown-${suffix}@auth.invalid`, 'unknown'),
        fetch(`${baseUrl}/session`),
      ]);
      assert(
        known.status === 202 && inactive.status === 202 && unknown.status === 202,
        'Known, inactive, and unknown challenge requests must all return 202',
      );
      const neutralBodies = await Promise.all([known, inactive, unknown].map(readJson));
      const knownBody = neutralBodies[0];
      assert(knownBody !== undefined, 'Known challenge response body must exist');
      const responseShapes = neutralBodies.map((body) => Object.keys(body).sort().join(','));
      assert(
        new Set(responseShapes).size === 1 && responseShapes[0] === 'challengeId,status',
        'Known, inactive, and unknown challenge responses must be externally identical',
      );
      assert(
        delivery.messages.length === deliveredBeforeNeutralRequests + 1,
        'Only the active account may receive a challenge',
      );
      assert(unauthorized.status === 401, 'An unauthenticated session request must be rejected');

      const knownChallengeId = knownBody.challengeId;
      assert(typeof knownChallengeId === 'string', 'Known challenge ID must be returned');
      const knownMessage = delivery.messages.at(-1);
      assert(knownMessage !== undefined, 'Known challenge must have one delivery');
      integrationStage = 'concurrent-challenge-consume';
      const concurrentVerification = await Promise.all(
        Array.from({ length: 12 }, () =>
          fetch(`${baseUrl}/session/challenges/${knownChallengeId}/verify`, {
            body: JSON.stringify({ code: knownMessage.code }),
            headers: { 'content-type': 'application/json' },
            method: 'POST',
          }),
        ),
      );
      assert(
        concurrentVerification.filter((response) => response.status === 200).length === 1 &&
          concurrentVerification.filter((response) => response.status === 401).length === 11,
        'Concurrent challenge consumption must create exactly one session',
      );
      const successfulVerification = concurrentVerification.find(
        (response) => response.status === 200,
      );
      assert(successfulVerification !== undefined, 'One verification must succeed');
      const activeSessionPayload = await readJson(successfulVerification);
      const activeSessionId = activeSessionPayload.sessionId;
      assert(typeof activeSessionId === 'string', 'The active session ID must be returned');
      const activeCookie = responseCookie(successfulVerification);
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: activeCookie } })).status === 200,
        'A new durable session must authenticate',
      );
      const revokeOne = await administrativeRequest({
        baseUrl,
        cookie: administratorCookie,
        correlationId: `integration-admin-revoke-one-${suffix}`,
        method: 'DELETE',
        path: `/admin/accounts/${activeAccount.userId}/sessions/${activeSessionId}`,
      });
      assert(revokeOne.status === 200, 'Administrator session revoke must be available over HTTP');
      assert(
        (await readJson(revokeOne)).revoked === true,
        'Administrator session revoke must change one durable session',
      );
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: activeCookie } })).status === 401,
        'A revoked durable session must be rejected immediately',
      );

      integrationStage = 'logout';
      clock.advance(emailChallengePolicy.resendCooldownMs);
      const logoutChallenge = await requestChallenge(baseUrl, activeEmail, 'logout');
      const logoutBody = await readJson(logoutChallenge);
      const logoutMessage = delivery.messages.at(-1);
      assert(logoutMessage !== undefined, 'Logout fixture challenge must be delivered');
      const logoutVerification = await fetch(
        `${baseUrl}/session/challenges/${String(logoutBody.challengeId)}/verify`,
        {
          body: JSON.stringify({ code: logoutMessage.code }),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        },
      );
      const logoutCookie = responseCookie(logoutVerification);
      const firstLogoutSession = await readJson(logoutVerification);
      clock.advance(emailChallengePolicy.resendCooldownMs);
      const secondBrowserChallenge = await requestChallenge(baseUrl, activeEmail, 'second-browser');
      const secondBrowserBody = await readJson(secondBrowserChallenge);
      const secondBrowserMessage = delivery.messages.at(-1);
      assert(secondBrowserMessage !== undefined, 'Second browser challenge must be delivered');
      const secondBrowserIssuedAt = clock.now();
      const secondBrowserVerification = await fetch(
        `${baseUrl}/session/challenges/${String(secondBrowserBody.challengeId)}/verify`,
        {
          body: JSON.stringify({ code: secondBrowserMessage.code }),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        },
      );
      const secondBrowserCookie = responseCookie(secondBrowserVerification);
      const secondBrowserSession = await readJson(secondBrowserVerification);
      assert(
        firstLogoutSession.sessionId !== secondBrowserSession.sessionId,
        'A separate browser login must create an independent server session',
      );
      const logout = await fetch(`${baseUrl}/session`, {
        headers: { cookie: logoutCookie },
        method: 'DELETE',
      });
      assert(logout.status === 204, 'Logout must succeed without a response body');
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: logoutCookie } })).status === 401,
        'Logout must revoke the server-side session',
      );
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: secondBrowserCookie } })).status ===
          200,
        'Logout must not revoke another browser session',
      );

      integrationStage = 'session-sliding-expiry';
      assert(
        secondBrowserSession.absoluteExpiresAt ===
          secondBrowserIssuedAt + config.policy.session.absoluteLifetimeMs,
        'A new session must use the configured 30-day absolute lifetime',
      );
      await runtime.authService.authenticateSession(administratorSession.sessionToken);
      clock.advance(config.policy.session.idleLifetimeMs - 1);
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: secondBrowserCookie } })).status ===
          200,
        'Activity before seven idle days must keep the session valid',
      );
      await runtime.authService.authenticateSession(administratorSession.sessionToken);
      clock.advance(2);
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: secondBrowserCookie } })).status ===
          200,
        'Activity must extend idle expiry beyond the original seven-day boundary',
      );

      integrationStage = 'deactivation';
      clock.advance(emailChallengePolicy.resendCooldownMs);
      const deactivationChallenge = await runtime.authService.requestEmailChallenge({
        email: activeEmail,
        fingerprint: `deactivation-${suffix}`,
        networkAddress: 'integration-network-deactivation',
      });
      const deactivationMessage = delivery.messages.at(-1);
      assert(deactivationMessage !== undefined, 'Deactivation fixture challenge must be delivered');
      const deactivationSession = await runtime.authService.verifyEmailChallenge({
        challengeId: deactivationChallenge.challengeId,
        code: deactivationMessage.code,
        networkAddress: 'integration-network-deactivation',
      });
      const forbiddenAdministrativeRequest = await administrativeRequest({
        baseUrl,
        body: {
          displayName: 'Forbidden Synthetic Account',
          email: `forbidden-${suffix}@auth.invalid`,
        },
        cookie: `${runtime.sessionCookie.name}=${deactivationSession.sessionToken}`,
        correlationId: `integration-admin-forbidden-${suffix}`,
        method: 'POST',
        path: '/admin/accounts',
      });
      assert(
        forbiddenAdministrativeRequest.status === 403 &&
          (await readJson(forbiddenAdministrativeRequest)).error === 'auth.forbidden',
        'A non-administrator must be rejected by the protected HTTP API',
      );
      clock.advance(emailChallengePolicy.resendCooldownMs);
      const pendingChallenge = await runtime.authService.requestEmailChallenge({
        email: activeEmail,
        fingerprint: `pending-deactivation-${suffix}`,
        networkAddress: 'integration-network-pending-deactivation',
      });
      const pendingChallengeMessage = delivery.messages.at(-1);
      assert(
        pendingChallengeMessage !== undefined &&
          pendingChallengeMessage.challengeId === pendingChallenge.challengeId,
        'A pending challenge must exist before deactivation',
      );
      const deactivateAccount = await administrativeRequest({
        baseUrl,
        body: { status: 'deactivated' },
        cookie: administratorCookie,
        correlationId: `integration-admin-deactivate-active-${suffix}`,
        method: 'PATCH',
        path: `/admin/accounts/${activeAccount.userId}/status`,
      });
      assert(
        deactivateAccount.status === 200 &&
          (await readJson(deactivateAccount)).status === 'deactivated',
        'Administrative deactivation must succeed through its protected HTTP wrapper',
      );
      await runtime.authService
        .verifyEmailChallenge({
          challengeId: pendingChallenge.challengeId,
          code: pendingChallengeMessage.code,
          networkAddress: 'integration-network-pending-deactivation',
        })
        .then(
          () => {
            throw new Error('A pending challenge survived deactivation');
          },
          (error: unknown) => {
            assert(
              (error as { readonly code?: string }).code === 'auth.invalid-or-expired-challenge',
              'Deactivation must invalidate every pending challenge',
            );
          },
        );
      await runtime.authService.authenticateSession(deactivationSession.sessionToken).then(
        () => {
          throw new Error('A deactivated account retained its session');
        },
        (error: unknown) => {
          assert(
            (error as { readonly code?: string }).code === 'auth.invalid-session',
            'Deactivation must revoke every account session',
          );
        },
      );
      assert(
        (await fetch(`${baseUrl}/session`, { headers: { cookie: secondBrowserCookie } })).status ===
          401,
        'Deactivation must revoke every browser and PWA session for the account',
      );

      integrationStage = 'oidc-state';
      const artifactId = `artifact-${suffix}`;
      const oidcAdapter = storageAdapter('AuthorizationCode');
      await oidcAdapter.upsert(
        artifactId,
        { grantId: `grant-${suffix}`, state: { fixture: 'synthetic' } },
        300,
      );
      assert(
        (await oidcAdapter.find(artifactId))?.grantId === `grant-${suffix}`,
        'OIDC state must round-trip through PostgreSQL',
      );
      const consumes = await Promise.allSettled([
        oidcAdapter.consume(artifactId),
        oidcAdapter.consume(artifactId),
      ]);
      assert(
        consumes.filter((result) => result.status === 'fulfilled').length === 1 &&
          consumes.filter((result) => result.status === 'rejected').length === 1,
        'OIDC state consumption must be atomic and replay-protected',
      );
      assert(
        typeof (await oidcAdapter.find(artifactId))?.consumed === 'number',
        'Consumed OIDC state must retain its durable consumed marker',
      );

      integrationStage = 'oidc-code-flow';
      const verifier = 'integration-pkce-verifier'.repeat(3);
      const authorize = new URL(`${baseUrl}/auth`);
      authorize.search = new URLSearchParams({
        client_id: 'synthetic-integration-client',
        code_challenge: pkceChallenge(verifier),
        code_challenge_method: 'S256',
        nonce: `nonce-${suffix}`,
        redirect_uri: 'http://127.0.0.1/callback',
        response_type: 'code',
        scope: 'openid',
        state: `state-${suffix}`,
      }).toString();
      const oidcCookies = new Map<string, string>();
      const authorizeResponse = await fetch(authorize, { redirect: 'manual' });
      updateCookieJar(authorizeResponse, oidcCookies);
      assert(authorizeResponse.status === 303, 'OIDC authorization must start an interaction');
      const interactionLocation = authorizeResponse.headers.get('location');
      assert(
        interactionLocation !== null,
        'OIDC authorization must return an interaction location',
      );
      oidcCookies.set(runtime.sessionCookie.name, administratorSession.sessionToken);
      const interactionResponse = await fetch(new URL(interactionLocation, baseUrl), {
        headers: { cookie: cookieHeader(oidcCookies) },
        redirect: 'manual',
      });
      updateCookieJar(interactionResponse, oidcCookies);
      assert(interactionResponse.status === 303, 'An authenticated interaction must resume');
      const resumeLocation = interactionResponse.headers.get('location');
      assert(resumeLocation !== null, 'The OIDC interaction must return a resume location');
      const resumeResponse = await fetch(new URL(resumeLocation, baseUrl), {
        headers: { cookie: cookieHeader(oidcCookies) },
        redirect: 'manual',
      });
      assert(resumeResponse.status === 303, 'OIDC authorization must return one code');
      const callbackLocation = resumeResponse.headers.get('location');
      assert(
        callbackLocation !== null,
        'OIDC authorization must redirect to the registered client',
      );
      const callback = new URL(callbackLocation);
      assert(
        callback.origin + callback.pathname === 'http://127.0.0.1/callback' &&
          callback.searchParams.get('state') === `state-${suffix}`,
        'OIDC must preserve state and use the exact registered redirect URI',
      );
      const authorizationCode = callback.searchParams.get('code');
      assert(authorizationCode !== null, 'OIDC authorization must issue a code');
      const tokenBody = new URLSearchParams({
        client_id: 'synthetic-integration-client',
        code: authorizationCode,
        code_verifier: verifier,
        grant_type: 'authorization_code',
        redirect_uri: 'http://127.0.0.1/callback',
      });
      const tokenResponse = await fetch(`${baseUrl}/token`, {
        body: tokenBody,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        method: 'POST',
      });
      assert(tokenResponse.status === 200, 'Valid PKCE must exchange the code exactly once');
      const replayResponse = await fetch(`${baseUrl}/token`, {
        body: tokenBody,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        method: 'POST',
      });
      assert(replayResponse.status === 400, 'A durable authorization code replay must be rejected');

      integrationStage = 'oidc-session-expiry-with-valid-application-session';
      const deliveriesBeforeOidcSessionExpiry = delivery.messages.length;
      clock.advance((config.oidc.sessionTtlSeconds + 1) * 1000);
      await runtime.authService.authenticateSession(administratorSession.sessionToken);
      const renewedAuthorize = new URL(`${baseUrl}/auth`);
      renewedAuthorize.search = new URLSearchParams({
        client_id: 'synthetic-integration-client',
        code_challenge: pkceChallenge(`${verifier}-renewed`),
        code_challenge_method: 'S256',
        nonce: `nonce-renewed-${suffix}`,
        redirect_uri: 'http://127.0.0.1/callback',
        response_type: 'code',
        scope: 'openid',
        state: `state-renewed-${suffix}`,
      }).toString();
      const renewedAuthorizeResponse = await fetch(renewedAuthorize, {
        headers: { cookie: cookieHeader(oidcCookies) },
        redirect: 'manual',
      });
      updateCookieJar(renewedAuthorizeResponse, oidcCookies);
      assert(
        renewedAuthorizeResponse.status === 303,
        'An expired OIDC session must restart a bounded interaction',
      );
      const renewedInteractionLocation = renewedAuthorizeResponse.headers.get('location');
      assert(
        renewedInteractionLocation !== null && renewedInteractionLocation.includes('/interaction/'),
        'An expired OIDC session must require the application-session interaction seam',
      );
      const renewedInteractionResponse = await fetch(new URL(renewedInteractionLocation, baseUrl), {
        headers: { cookie: cookieHeader(oidcCookies) },
        redirect: 'manual',
      });
      updateCookieJar(renewedInteractionResponse, oidcCookies);
      assert(
        renewedInteractionResponse.status === 303,
        'A valid application session must complete the renewed OIDC interaction',
      );
      const renewedResumeLocation = renewedInteractionResponse.headers.get('location');
      assert(renewedResumeLocation !== null, 'The renewed OIDC interaction must resume');
      const renewedResumeResponse = await fetch(new URL(renewedResumeLocation, baseUrl), {
        headers: { cookie: cookieHeader(oidcCookies) },
        redirect: 'manual',
      });
      const renewedCallbackLocation = renewedResumeResponse.headers.get('location');
      assert(
        renewedResumeResponse.status === 303 && renewedCallbackLocation !== null,
        'The renewed OIDC authorization must return to the registered redirect URI',
      );
      const renewedCallback = new URL(renewedCallbackLocation);
      assert(
        renewedCallback.searchParams.get('state') === `state-renewed-${suffix}`,
        'The renewed OIDC authorization must preserve state',
      );
      assert(
        delivery.messages.length === deliveriesBeforeOidcSessionExpiry,
        'OIDC session expiry must not request a new email code while application-session is valid',
      );

      integrationStage = 'redis-rate-limit';
      const redisClient = runtimeRedisClient;
      assert(redisClient !== undefined, 'The runtime Redis client must be connected');
      const limiter = new RedisRateLimiter(redisClient, `kovcheg:auth:integration:${suffix}:`);
      const decisions = await Promise.all(
        Array.from({ length: 10 }, () =>
          limiter.consume({
            key: 'same-dimension',
            now: clock.now(),
            rule: { limit: 3, windowMs: 60_000 },
          }),
        ),
      );
      assert(
        decisions.filter((decision) => decision === 'allowed').length === 3 &&
          decisions.filter((decision) => decision === 'limited').length === 7,
        'Redis must atomically enforce the configured concurrent rate limit',
      );

      integrationStage = 'redis-failure';
      await redisClient.close?.();
      const redisFailure = await requestChallenge(
        baseUrl,
        `redis-failure-${suffix}@auth.invalid`,
        'redis-failure',
      );
      assert(redisFailure.status === 503, 'Redis failure must fail new authentication closed');
    } finally {
      await app.close();
    }
  } catch (error) {
    await runtime.close().catch(() => undefined);
    throw error;
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown integration failure';
  process.stderr.write(`Auth integration check failed at ${integrationStage}: ${message}\n`);
  process.exitCode = 1;
});
