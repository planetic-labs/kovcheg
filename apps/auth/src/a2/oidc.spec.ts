import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';

import type { UserId } from '@kovcheg/contracts';
import { decodeJwt, exportJWK, generateKeyPair } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';

import { AuthService } from './auth-service.js';
import { emailChallengePolicy } from './contracts.js';
import type { AuthPolicy } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource } from './crypto.js';
import {
  LocalAuthRepository,
  LocalEmailChallengeDelivery,
  LocalRateLimiter,
  ManualClock,
} from './local-adapters.js';
import { completeOidcInteraction, createOidcProvider, StaticOidcClientRepository } from './oidc.js';
import type { RegisteredOidcClient } from './oidc.js';

const oidcAccountId = '00000000-0000-4000-8000-000000000021' satisfies UserId;
const openServers = new Set<Server>();

afterEach(async () => {
  await Promise.all(
    [...openServers].map(
      async (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error === undefined) {
              resolve();
            } else {
              reject(error);
            }
          });
        }),
    ),
  );
  openServers.clear();
});

function policy(): AuthPolicy {
  const rule = Object.freeze({ limit: 50, windowMs: 10 * 60_000 });
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
      absoluteLifetimeMs: 60 * 60_000,
      idleLifetimeMs: 15 * 60_000,
    }),
  });
}

async function createAuthFixture() {
  const clock = new ManualClock(Date.UTC(2026, 0, 1));
  const repository = new LocalAuthRepository();
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const service = new AuthService({
    clock,
    crypto: new HmacAuthCrypto({
      challengePepper: 'c'.repeat(64),
      rateLimitPepper: 'r'.repeat(64),
      sessionPepper: 's'.repeat(64),
    }),
    delivery,
    policy: policy(),
    random: new SystemAuthRandomSource(),
    rateLimiter: new LocalRateLimiter(),
    repository,
  });
  await service.bootstrapAdministrator({
    bootstrapId: 'synthetic-bootstrap-id-oidc',
    displayName: 'OIDC Test Administrator',
    email: 'oidc-account@example.invalid',
    userId: oidcAccountId,
  });
  const challenge = await service.requestEmailChallenge({
    email: 'oidc-account@example.invalid',
    fingerprint: 'oidc-fingerprint',
    networkAddress: 'oidc-network',
  });
  const message = delivery.messages.at(-1);
  if (message === undefined) {
    throw new Error('Expected OIDC auth challenge delivery');
  }
  const session = await service.verifyEmailChallenge({
    challengeId: challenge.challengeId,
    code: message.code,
    networkAddress: 'oidc-network',
  });
  return { clock, repository, service, session };
}

async function createTestJwks() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  return {
    keys: [
      {
        ...privateJwk,
        alg: 'ES256',
        kid: 'synthetic-test-signing-key',
        use: 'sig',
      },
    ],
  };
}

function publicClient(redirectUri: string): RegisteredOidcClient {
  return Object.freeze({
    clientId: 'synthetic-public-client',
    redirectUris: Object.freeze([redirectUri]),
    scopes: Object.freeze(['openid']),
    tokenEndpointAuthMethod: 'none',
  });
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      if (address === null || typeof address === 'string') {
        reject(new Error('Expected a TCP test address'));
        return;
      }
      resolve(address.port);
    });
  });
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

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

describe('A2 OIDC provider configuration', () => {
  it('rejects wildcard, fragment, and unregistered-style redirect configuration', async () => {
    const fixture = await createAuthFixture();
    const jwks = await createTestJwks();
    const invalidRedirects = [
      'https://*.invalid/callback',
      'https://service.invalid/callback#fragment',
      'http://service.invalid/callback',
    ];

    for (const redirectUri of invalidRedirects) {
      await expect(
        createOidcProvider({
          accountRepository: fixture.repository,
          clientRepository: new StaticOidcClientRepository([publicClient(redirectUri)], {
            NODE_ENV: 'test',
          }),
          cookieKeys: ['k'.repeat(64), 'l'.repeat(64)],
          environment: 'test',
          issuer: 'http://127.0.0.1:4300',
          jwks,
          oidcSessionTtlSeconds: 3600,
          secureCookies: false,
        }),
      ).rejects.toMatchObject({ code: 'auth.invalid-input' });
    }
  });

  it('requires durable protocol storage and secure cookies outside tests', async () => {
    const fixture = await createAuthFixture();
    const jwks = await createTestJwks();
    await expect(
      createOidcProvider({
        accountRepository: fixture.repository,
        clientRepository: new StaticOidcClientRepository(
          [publicClient('https://service.invalid/callback')],
          { NODE_ENV: 'test' },
        ),
        cookieKeys: ['k'.repeat(64), 'l'.repeat(64)],
        environment: 'production',
        issuer: 'https://issuer.invalid',
        jwks,
        oidcSessionTtlSeconds: 3600,
        secureCookies: false,
      }),
    ).rejects.toMatchObject({ code: 'auth.invalid-input' });

    await expect(
      createOidcProvider({
        accountRepository: fixture.repository,
        clientRepository: new StaticOidcClientRepository(
          [publicClient('https://service.invalid/callback')],
          { NODE_ENV: 'test' },
        ),
        cookieKeys: ['k'.repeat(64), 'l'.repeat(64)],
        environment: 'production',
        issuer: 'https://issuer.invalid',
        jwks,
        oidcSessionTtlSeconds: 3600,
        secureCookies: true,
      }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });
  });
});

describe('A2 OIDC Authorization Code with PKCE', () => {
  it('publishes a restricted provider and completes a one-time S256 code flow', async () => {
    const fixture = await createAuthFixture();
    const callbackUri = 'http://127.0.0.1/callback';
    const requestHandler: {
      current?: (request: IncomingMessage, response: ServerResponse) => void;
    } = {};
    const server = createServer((request, response) => requestHandler.current?.(request, response));
    openServers.add(server);
    const port = await listen(server);
    const issuer = `http://127.0.0.1:${port}`;
    const provider = await createOidcProvider({
      accountRepository: fixture.repository,
      clientRepository: new StaticOidcClientRepository([publicClient(callbackUri)], {
        NODE_ENV: 'test',
      }),
      cookieKeys: ['k'.repeat(64), 'l'.repeat(64)],
      environment: 'test',
      issuer,
      jwks: await createTestJwks(),
      oidcSessionTtlSeconds: 3600,
      secureCookies: false,
    });
    const providerCallback = provider.callback();
    requestHandler.current = (request, response) => {
      if (request.url?.startsWith('/interaction/')) {
        void completeOidcInteraction({
          authService: fixture.service,
          clock: fixture.clock,
          provider,
          request,
          response,
          sessionToken: fixture.session.sessionToken,
        }).catch(() => {
          response.statusCode = 500;
          response.end();
        });
        return;
      }
      providerCallback(request, response);
    };

    const discoveryResponse = await fetch(`${issuer}/.well-known/openid-configuration`);
    expect(discoveryResponse.status).toBe(200);
    const discovery = (await discoveryResponse.json()) as Record<string, unknown>;
    expect(discovery.response_types_supported).toEqual(['code']);
    expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
    expect(discovery).not.toHaveProperty('registration_endpoint');

    const invalidRedirect = new URL(`${issuer}/auth`);
    invalidRedirect.search = new URLSearchParams({
      client_id: 'synthetic-public-client',
      code_challenge: pkceChallenge('v'.repeat(64)),
      code_challenge_method: 'S256',
      nonce: 'nonce-invalid-redirect',
      redirect_uri: 'http://127.0.0.1/not-registered',
      response_type: 'code',
      scope: 'openid',
      state: 'state-invalid-redirect',
    }).toString();
    const invalidRedirectResponse = await fetch(invalidRedirect, { redirect: 'manual' });
    expect(invalidRedirectResponse.status).toBe(400);
    expect(invalidRedirectResponse.headers.get('location')).toBeNull();

    const missingPkce = new URL(`${issuer}/auth`);
    missingPkce.search = new URLSearchParams({
      client_id: 'synthetic-public-client',
      nonce: 'nonce-missing-pkce',
      redirect_uri: callbackUri,
      response_type: 'code',
      scope: 'openid',
      state: 'state-missing-pkce',
    }).toString();
    const missingPkceResponse = await fetch(missingPkce, { redirect: 'manual' });
    expect([303, 400]).toContain(missingPkceResponse.status);
    const missingPkceLocation = missingPkceResponse.headers.get('location');
    if (missingPkceLocation !== null) {
      expect(new URL(missingPkceLocation).searchParams.get('error')).toBe('invalid_request');
    }

    const verifier = 'v'.repeat(64);
    const authorize = new URL(`${issuer}/auth`);
    authorize.search = new URLSearchParams({
      client_id: 'synthetic-public-client',
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: 'S256',
      nonce: 'nonce-valid-flow',
      redirect_uri: callbackUri,
      response_type: 'code',
      scope: 'openid',
      state: 'state-valid-flow',
    }).toString();
    const jar = new Map<string, string>();
    const authorizeResponse = await fetch(authorize, { redirect: 'manual' });
    updateCookieJar(authorizeResponse, jar);
    expect(authorizeResponse.status, await authorizeResponse.clone().text()).toBe(303);
    const interactionLocation = authorizeResponse.headers.get('location');
    expect(interactionLocation).not.toBeNull();

    const interactionResponse = await fetch(new URL(interactionLocation ?? '', issuer), {
      headers: { cookie: cookieHeader(jar) },
      redirect: 'manual',
    });
    updateCookieJar(interactionResponse, jar);
    expect(interactionResponse.status).toBe(303);
    const resumeLocation = interactionResponse.headers.get('location');
    expect(resumeLocation).not.toBeNull();

    const resumeResponse = await fetch(new URL(resumeLocation ?? '', issuer), {
      headers: { cookie: cookieHeader(jar) },
      redirect: 'manual',
    });
    expect(resumeResponse.status).toBe(303);
    const callbackLocation = resumeResponse.headers.get('location');
    expect(callbackLocation).not.toBeNull();
    const callback = new URL(callbackLocation ?? callbackUri, issuer);
    expect(callback.origin + callback.pathname).toBe(callbackUri);
    expect(callback.searchParams.get('state')).toBe('state-valid-flow');
    const authorizationCode = callback.searchParams.get('code');
    expect(authorizationCode).not.toBeNull();

    const tokenBody = new URLSearchParams({
      client_id: 'synthetic-public-client',
      code: authorizationCode ?? '',
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: callbackUri,
    });
    const tokenResponse = await fetch(`${issuer}/token`, {
      body: tokenBody,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
    });
    expect(tokenResponse.status).toBe(200);
    const tokenPayload = (await tokenResponse.json()) as Record<string, unknown>;
    expect(tokenPayload).toMatchObject({
      access_token: expect.any(String),
      id_token: expect.any(String),
      token_type: 'Bearer',
    });
    expect(decodeJwt(String(tokenPayload.id_token)).nonce).toBe('nonce-valid-flow');

    const replayResponse = await fetch(`${issuer}/token`, {
      body: tokenBody,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
    });
    expect(replayResponse.status).toBe(400);
    await expect(replayResponse.json()).resolves.toMatchObject({ error: 'invalid_grant' });
  });
});
