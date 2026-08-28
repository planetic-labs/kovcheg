import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { GET as oidcCallback } from '../../app/bff/auth/oidc/callback/route';
import { GET as oidcStart } from '../../app/bff/auth/oidc/start/route';

const oidcStartPath = '/bff/auth/oidc/start';
const oidcCallbackPath = '/bff/auth/oidc/callback';
const issuer = 'https://issuer.invalid';
const authorizationEndpoint = `${issuer}/auth`;
const tokenEndpoint = `${issuer}/token`;
const jwksUri = `${issuer}/jwks`;
const clientOrigin = 'https://client.invalid';
const redirectUri = `${clientOrigin}${oidcCallbackPath}`;
const clientId = 'synthetic-web-client';
const now = Date.UTC(2026, 7, 28, 12, 0, 0);
const stateKey = Buffer.alloc(32, 7).toString('base64url');
const internalOrigin = 'http://auth:3002';
const stateDirectory = mkdtempSync(join(tmpdir(), 'kovcheg-oidc-bff-'));
const stateKeyPath = join(stateDirectory, 'state-key');
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicJwk = {
  ...(publicKey.export({ format: 'jwk' }) as JsonWebKey),
  alg: 'ES256',
  kid: 'synthetic-signing-key',
  use: 'sig',
};

interface SyntheticOidcEnvironment {
  readonly KOVCHEG_AUTH_INTERNAL_URL?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_CLIENT_ID?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_ISSUER?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_REDIRECT_URI?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_STATE_KEY?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_STATE_KEY_FILE?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD?: string | undefined;
}

function environment(overrides: Partial<SyntheticOidcEnvironment> = {}): SyntheticOidcEnvironment {
  return {
    KOVCHEG_AUTH_INTERNAL_URL: internalOrigin,
    KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT: authorizationEndpoint,
    KOVCHEG_WEB_OIDC_CLIENT_ID: clientId,
    KOVCHEG_WEB_OIDC_ISSUER: issuer,
    KOVCHEG_WEB_OIDC_REDIRECT_URI: redirectUri,
    KOVCHEG_WEB_OIDC_STATE_KEY_FILE: stateKeyPath,
    KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD: 'none',
    ...overrides,
  };
}

function configure(source: SyntheticOidcEnvironment = environment()): void {
  for (const [name, value] of Object.entries(source)) {
    vi.stubEnv(name, value);
  }
  vi.stubEnv('KOVCHEG_WEB_OIDC_STATE_KEY', source.KOVCHEG_WEB_OIDC_STATE_KEY);
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json' },
    status,
  });
}

function discovery(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    authorization_endpoint: authorizationEndpoint,
    code_challenge_methods_supported: ['S256'],
    issuer,
    jwks_uri: jwksUri,
    response_types_supported: ['code'],
    token_endpoint: tokenEndpoint,
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
    ...overrides,
  };
}

function compactJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function idToken(nonce: string, claims: Partial<Record<string, unknown>> = {}): string {
  const header = compactJson({ alg: 'ES256', kid: publicJwk.kid, typ: 'JWT' });
  const payload = compactJson({
    aud: clientId,
    exp: Math.floor(now / 1000) + 300,
    iat: Math.floor(now / 1000),
    iss: issuer,
    nonce,
    sub: '00000000-0000-4000-8000-000000000701',
    ...claims,
  });
  const signingInput = `${header}.${payload}`;
  const signature = sign('sha256', Buffer.from(signingInput, 'ascii'), {
    dsaEncoding: 'ieee-p1363',
    key: privateKey,
  }).toString('base64url');
  return `${signingInput}.${signature}`;
}

function startRequest(): NextRequest {
  return new NextRequest(`${clientOrigin}${oidcStartPath}`);
}

function callbackRequest(location: URL, cookie?: string): NextRequest {
  return new NextRequest(location, {
    headers: cookie === undefined ? {} : { cookie },
  });
}

function forwardedRequest(publicLocation: string | URL, cookie?: string): NextRequest {
  const publicUrl = new URL(publicLocation, clientOrigin);
  const loopback = new URL(publicUrl.pathname + publicUrl.search, 'http://127.0.0.1:32000');
  return new NextRequest(loopback, {
    headers: {
      ...(cookie === undefined ? {} : { cookie }),
      host: publicUrl.host,
      'x-forwarded-host': publicUrl.host,
      'x-forwarded-proto': 'https',
    },
  });
}

function bindingCookie(response: Response): string {
  const setCookie = response.headers.get('set-cookie');
  if (setCookie === null) throw new Error('Expected an OIDC binding cookie');
  const pair = setCookie.split(';', 1)[0];
  if (pair === undefined) throw new Error('Expected an OIDC binding cookie pair');
  return pair;
}

async function begin(): Promise<{
  readonly authorization: URL;
  readonly cookie: string;
  readonly response: Response;
}> {
  const fetcher = vi.fn(async () => json(discovery()));
  vi.stubGlobal('fetch', fetcher);
  const response = await oidcStart(startRequest());
  const location = response.headers.get('location');
  if (location === null) throw new Error('Expected an OIDC authorization redirect');
  return { authorization: new URL(location), cookie: bindingCookie(response), response };
}

function successfulCallbackFetcher(nonce: string, claims: Partial<Record<string, unknown>> = {}) {
  return vi.fn(async (input: string | URL | Request, _init?: RequestInit) => {
    void _init;
    const url = input instanceof Request ? input.url : input.toString();
    if (url === `${internalOrigin}/.well-known/openid-configuration`) return json(discovery());
    if (url === `${internalOrigin}/token`) {
      return json({
        access_token: 'synthetic-access-token',
        expires_in: 300,
        id_token: idToken(nonce, claims),
        token_type: 'Bearer',
      });
    }
    if (url === `${internalOrigin}/jwks`) return json({ keys: [publicJwk] });
    if (url === `${internalOrigin}/internal/oidc/session`) {
      return new Response(null, {
        headers: {
          'set-cookie':
            '__Host-kovcheg_session=synthetic-session; Path=/; HttpOnly; Secure; SameSite=Lax',
        },
        status: 204,
      });
    }
    throw new Error('Unexpected synthetic OIDC request');
  });
}

function callbackLocation(authorization: URL, overrides: Record<string, string> = {}): URL {
  const location = new URL(redirectUri);
  location.search = new URLSearchParams({
    code: 'synthetic-authorization-code',
    iss: issuer,
    state: authorization.searchParams.get('state') ?? '',
    ...overrides,
  }).toString();
  return location;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

beforeAll(() => {
  writeFileSync(stateKeyPath, stateKey);
});

afterAll(() => {
  rmSync(stateDirectory, { force: true, recursive: true });
});

describe('A6 OIDC BFF configuration', () => {
  it('keeps an absent configuration fail-closed and permits only a file-backed public client', async () => {
    expect((await oidcStart(startRequest())).status).toBe(503);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(discovery())),
    );

    configure();
    expect((await oidcStart(startRequest())).status).toBe(303);

    for (const source of [
      environment({ KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD: 'client_secret_basic' }),
      environment({ KOVCHEG_WEB_OIDC_STATE_KEY: stateKey }),
      environment({ KOVCHEG_WEB_OIDC_STATE_KEY_FILE: '/synthetic/missing' }),
    ]) {
      configure(source);
      expect((await oidcStart(startRequest())).status).toBe(503);
    }
  });

  it('rejects redirect, issuer, and authorization endpoint drift', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(discovery())),
    );
    for (const source of [
      environment({ KOVCHEG_WEB_OIDC_REDIRECT_URI: `${clientOrigin}/unexpected` }),
      environment({ KOVCHEG_WEB_OIDC_REDIRECT_URI: `http://127.0.0.1${oidcCallbackPath}` }),
      environment({ KOVCHEG_WEB_OIDC_REDIRECT_URI: `https://localhost${oidcCallbackPath}` }),
      environment({ KOVCHEG_WEB_OIDC_ISSUER: 'https://issuer.invalid/' }),
      environment({ KOVCHEG_WEB_OIDC_ISSUER: 'https://issuer.invalid/path' }),
      environment({ KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT: 'https://other.invalid/auth' }),
    ]) {
      configure(source);
      expect((await oidcStart(startRequest())).status).toBe(503);
    }
  });
});

describe('A6 OIDC BFF start route', () => {
  it('creates only an S256 authorization redirect and a short-lived protected binding', async () => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const { authorization, response } = await begin();

    expect(response.status).toBe(303);
    expect(authorization.origin + authorization.pathname).toBe(authorizationEndpoint);
    expect([...authorization.searchParams.keys()].sort()).toEqual([
      'client_id',
      'code_challenge',
      'code_challenge_method',
      'nonce',
      'redirect_uri',
      'response_type',
      'scope',
      'state',
    ]);
    expect(authorization.searchParams.get('client_id')).toBe(clientId);
    expect(authorization.searchParams.get('redirect_uri')).toBe(redirectUri);
    expect(authorization.searchParams.get('response_type')).toBe('code');
    expect(authorization.searchParams.get('scope')).toBe('openid');
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(authorization.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(authorization.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(authorization.toString()).not.toContain('code_verifier');
    expect(authorization.toString()).not.toContain('client_secret');

    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-kovcheg_oidc=');
    expect(setCookie).toContain('Path=/');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('SameSite=lax');
    expect(setCookie).toContain('Max-Age=300');
    expect(setCookie).not.toContain(clientId);
    expect(setCookie).not.toContain(issuer);
  });

  it('accepts only the exact trusted-forwarded application host at the dual-host seam', async () => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(discovery())),
    );

    const accepted = await oidcStart(forwardedRequest(oidcStartPath));
    expect(accepted.status).toBe(303);
    const wrongHost = forwardedRequest(oidcStartPath);
    wrongHost.headers.set('x-forwarded-host', 'other-client.invalid');
    const rejected = await oidcStart(wrongHost);
    expect(rejected.status).toBe(503);
    expect(rejected.headers.get('set-cookie')).toBeNull();
  });

  it('returns the same fail-closed response for missing config, discovery drift, and transport failure', async () => {
    const missing = await oidcStart(startRequest());
    expect(missing.status).toBe(503);
    await expect(missing.json()).resolves.toEqual({ code: 'a6.oidc-not-configured', status: 503 });

    configure();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(discovery({ authorization_endpoint: `${issuer}/drift` }))),
    );
    const drift = await oidcStart(startRequest());
    expect(drift.status).toBe(503);
    expect(drift.headers.get('location')).toBeNull();
    expect(drift.headers.get('set-cookie')).toBeNull();

    for (const methods of [[], ['plain']]) {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => json(discovery({ code_challenge_methods_supported: methods }))),
      );
      const weakPkce = await oidcStart(startRequest());
      expect(weakPkce.status).toBe(503);
      expect(weakPkce.headers.get('location')).toBeNull();
    }

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Promise.reject(new Error('synthetic transport'))),
    );
    const unavailable = await oidcStart(startRequest());
    expect(unavailable.status).toBe(503);
    await expect(unavailable.json()).resolves.toEqual({
      code: 'a6.oidc-not-configured',
      status: 503,
    });
  });
});

describe('A6 OIDC BFF callback route', () => {
  it('bridges a validated public-client exchange into one same-origin application session', async () => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const started = await begin();
    const nonce = started.authorization.searchParams.get('nonce') ?? '';
    const challenge = started.authorization.searchParams.get('code_challenge') ?? '';
    const fetcher = successfulCallbackFetcher(nonce);
    vi.stubGlobal('fetch', fetcher);

    const response = await oidcCallback(
      callbackRequest(callbackLocation(started.authorization), started.cookie),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe(`${clientOrigin}/`);
    const tokenCall = fetcher.mock.calls.find(
      ([input]) => input.toString() === `${internalOrigin}/token`,
    );
    expect(tokenCall).toBeDefined();
    const tokenInit = tokenCall?.[1];
    if (tokenInit === undefined) throw new Error('Expected token request options');
    const tokenBody = tokenInit.body as URLSearchParams;
    expect(tokenBody.get('client_id')).toBe(clientId);
    expect(tokenBody.get('grant_type')).toBe('authorization_code');
    expect(tokenBody.get('redirect_uri')).toBe(redirectUri);
    expect(tokenBody.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(
      createHash('sha256')
        .update(tokenBody.get('code_verifier') ?? '', 'ascii')
        .digest('base64url'),
    ).toBe(challenge);
    expect(tokenBody.has('client_secret')).toBe(false);
    expect(new Headers(tokenInit.headers).has('authorization')).toBe(false);

    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-kovcheg_oidc=');
    expect(setCookie).toContain('Max-Age=0');
    expect(setCookie).toContain('__Host-kovcheg_session=synthetic-session');
    const bridgeCall = fetcher.mock.calls.find(
      ([input]) => input.toString() === `${internalOrigin}/internal/oidc/session`,
    );
    expect(bridgeCall).toBeDefined();
    expect(bridgeCall?.[1]?.body).toBe(JSON.stringify({ accessToken: 'synthetic-access-token' }));
    expect(new Headers(bridgeCall?.[1]?.headers).has('cookie')).toBe(false);
  });

  it.each([
    ['state mismatch', { state: 'x'.repeat(43) }],
    ['issuer mismatch', { iss: 'https://other.invalid' }],
  ])('rejects %s before token exchange', async (_name, override) => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const started = await begin();
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);

    const response = await oidcCallback(
      callbackRequest(callbackLocation(started.authorization, override), started.cookie),
    );

    expect(response.status).toBe(503);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects duplicate, unexpected, error, expired, and redirect-drift callbacks', async () => {
    configure();
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(now);
    const started = await begin();
    const state = started.authorization.searchParams.get('state') ?? '';
    const invalidLocations = [
      new URL(`${redirectUri}?code=synthetic-code-1&code=synthetic-code-2&state=${state}`),
      new URL(`${redirectUri}?code=synthetic-code&state=${state}&next=https%3A%2F%2Fevil.invalid`),
      new URL(`${redirectUri}?error=access_denied&state=${state}`),
    ];
    for (const location of invalidLocations) {
      const fetcher = vi.fn();
      vi.stubGlobal('fetch', fetcher);
      expect((await oidcCallback(callbackRequest(location, started.cookie))).status).toBe(503);
      expect(fetcher).not.toHaveBeenCalled();
    }

    nowSpy.mockReturnValue(now + 301_000);
    const expiredFetcher = vi.fn();
    vi.stubGlobal('fetch', expiredFetcher);
    expect(
      (await oidcCallback(callbackRequest(callbackLocation(started.authorization), started.cookie)))
        .status,
    ).toBe(503);
    expect(expiredFetcher).not.toHaveBeenCalled();

    nowSpy.mockReturnValue(now);
    vi.stubEnv('KOVCHEG_WEB_OIDC_REDIRECT_URI', `https://other-client.invalid${oidcCallbackPath}`);
    const driftFetcher = vi.fn();
    vi.stubGlobal('fetch', driftFetcher);
    expect(
      (await oidcCallback(callbackRequest(callbackLocation(started.authorization), started.cookie)))
        .status,
    ).toBe(503);
    expect(driftFetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['nonce', { nonce: 'mismatch' }],
    ['issuer', { iss: 'https://other.invalid' }],
    ['audience', { aud: 'other-client' }],
    ['expiry', { exp: Math.floor(now / 1000) - 1 }],
  ])('rejects an ID token with a %s mismatch without a session', async (_name, claims) => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const started = await begin();
    const fetcher = successfulCallbackFetcher(
      started.authorization.searchParams.get('nonce') ?? '',
      claims,
    );
    vi.stubGlobal('fetch', fetcher);

    const response = await oidcCallback(
      callbackRequest(callbackLocation(started.authorization), started.cookie),
    );

    expect(response.status).toBe(503);
    expect(response.headers.get('set-cookie') ?? '').not.toContain('kovcheg_session=');
  });

  it('rejects malformed token responses, transport failure, and replay without logging sensitive data', async () => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const logs = [
      vi.spyOn(console, 'error').mockImplementation(() => undefined),
      vi.spyOn(console, 'info').mockImplementation(() => undefined),
      vi.spyOn(console, 'log').mockImplementation(() => undefined),
      vi.spyOn(console, 'warn').mockImplementation(() => undefined),
    ];

    const malformedStart = await begin();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) =>
        input.toString().includes('.well-known')
          ? json(discovery())
          : json({ access_token: 'synthetic', id_token: 'malformed', token_type: 'Bearer' }),
      ),
    );
    const malformed = await oidcCallback(
      callbackRequest(callbackLocation(malformedStart.authorization), malformedStart.cookie),
    );
    expect(malformed.status).toBe(503);
    expect(malformed.headers.get('set-cookie') ?? '').not.toContain('kovcheg_session=');

    const transportStart = await begin();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        if (input.toString().includes('.well-known')) return json(discovery());
        throw new Error('synthetic token transport');
      }),
    );
    const failed = await oidcCallback(
      callbackRequest(callbackLocation(transportStart.authorization), transportStart.cookie),
    );
    expect(failed.status).toBe(503);

    const replayStart = await begin();
    const successfulFetcher = successfulCallbackFetcher(
      replayStart.authorization.searchParams.get('nonce') ?? '',
    );
    vi.stubGlobal('fetch', successfulFetcher);
    const callback = callbackLocation(replayStart.authorization);
    const first = await oidcCallback(callbackRequest(callback, replayStart.cookie));
    expect(first.headers.get('set-cookie') ?? '').toContain('Max-Age=0');
    const replayFetcher = vi.fn();
    vi.stubGlobal('fetch', replayFetcher);
    const replay = await oidcCallback(callbackRequest(callback));
    expect(replay.status).toBe(503);
    expect(replayFetcher).not.toHaveBeenCalled();

    for (const log of logs) expect(log).not.toHaveBeenCalled();
  });

  it('keeps a rejected active-account bridge neutral and emits no application session', async () => {
    configure();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const started = await begin();
    const fetcher = successfulCallbackFetcher(
      started.authorization.searchParams.get('nonce') ?? '',
    ).mockImplementationOnce(async () => json(discovery()));
    const upstream = successfulCallbackFetcher(
      started.authorization.searchParams.get('nonce') ?? '',
    );
    fetcher.mockImplementation(async (input, init) => {
      if (input.toString() === `${internalOrigin}/internal/oidc/session`) {
        return json({ error: 'auth.invalid-session' }, 401);
      }
      return upstream(input, init);
    });
    vi.stubGlobal('fetch', fetcher);

    const response = await oidcCallback(
      forwardedRequest(callbackLocation(started.authorization), started.cookie),
    );

    expect(response.status).toBe(503);
    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-kovcheg_oidc=');
    expect(setCookie).toContain('Max-Age=0');
    expect(setCookie).not.toContain('kovcheg_session=');
  });
});
