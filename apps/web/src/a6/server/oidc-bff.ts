import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import type { JsonWebKey as CryptoJsonWebKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { copySessionSetCookie, requestAuth, requestIsSecure } from './internal-http';

const oidcStartPath = '/bff/auth/oidc/start';
const oidcCallbackPath = '/bff/auth/oidc/callback';

const oidcBindingCookieName = '__Host-kovcheg_oidc';
const oidcBindingLifetimeSeconds = 5 * 60;
const maximumJsonBytes = 1024 * 1024;
const clientIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u;
const base64UrlPattern = /^[A-Za-z0-9_-]+$/u;
const authorizationCodePattern = /^[A-Za-z0-9._~-]{8,4096}$/u;
const bindingAad = Buffer.from('kovcheg-web-oidc-binding-v1', 'utf8');

interface OidcBffEnvironmentSource {
  readonly KOVCHEG_AUTH_INTERNAL_URL?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_CLIENT_ID?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_ISSUER?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_REDIRECT_URI?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_STATE_KEY?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_STATE_KEY_FILE?: string | undefined;
  readonly KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD?: string | undefined;
}

interface OidcBffConfig {
  readonly authorizationEndpoint: string;
  readonly clientId: string;
  readonly internalOrigin: string;
  readonly issuer: string;
  readonly redirectUri: string;
  readonly stateKey: Buffer;
  readonly tokenEndpointAuthMethod: 'none';
}

function processOidcEnvironment(): OidcBffEnvironmentSource {
  return {
    KOVCHEG_AUTH_INTERNAL_URL: process.env.KOVCHEG_AUTH_INTERNAL_URL,
    KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT: process.env.KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT,
    KOVCHEG_WEB_OIDC_CLIENT_ID: process.env.KOVCHEG_WEB_OIDC_CLIENT_ID,
    KOVCHEG_WEB_OIDC_ISSUER: process.env.KOVCHEG_WEB_OIDC_ISSUER,
    KOVCHEG_WEB_OIDC_REDIRECT_URI: process.env.KOVCHEG_WEB_OIDC_REDIRECT_URI,
    KOVCHEG_WEB_OIDC_STATE_KEY: process.env.KOVCHEG_WEB_OIDC_STATE_KEY,
    KOVCHEG_WEB_OIDC_STATE_KEY_FILE: process.env.KOVCHEG_WEB_OIDC_STATE_KEY_FILE,
    KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD:
      process.env.KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD,
  };
}

interface OidcDiscovery {
  readonly authorizationEndpoint: string;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly tokenEndpoint: string;
}

interface OidcBinding {
  readonly authorizationEndpoint: string;
  readonly clientId: string;
  readonly codeVerifier: string;
  readonly issuedAt: number;
  readonly issuer: string;
  readonly nonce: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly version: 1;
}

interface OidcBffDependencies {
  readonly environment?: OidcBffEnvironmentSource | undefined;
  readonly fetcher?: typeof fetch | undefined;
  readonly now?: (() => number) | undefined;
  readonly random?: ((size: number) => Buffer) | undefined;
}

function configurationError(): Error {
  return new Error('OIDC BFF configuration is invalid');
}

function normalizedHttpsUrl(value: string, kind: 'endpoint' | 'issuer' | 'redirect'): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw configurationError();
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== '' ||
    parsed.search !== '' ||
    parsed.hostname === 'localhost' ||
    parsed.hostname.endsWith('.localhost') ||
    value.includes('*')
  ) {
    throw configurationError();
  }
  if (kind === 'issuer') {
    if (parsed.pathname !== '/') throw configurationError();
    const normalized = parsed.toString().replace(/\/$/u, '');
    if (value !== normalized) throw configurationError();
    return normalized;
  }
  if (kind === 'redirect' && parsed.pathname !== oidcCallbackPath) throw configurationError();
  return parsed.toString();
}

function stateKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) throw configurationError();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.byteLength !== 32 || decoded.toString('base64url') !== value) {
    throw configurationError();
  }
  return decoded;
}

function bareInternalOrigin(value: string | undefined): string {
  let parsed: URL;
  try {
    parsed = new URL(value ?? 'http://auth:3002');
  } catch {
    throw configurationError();
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw configurationError();
  }
  return parsed.origin;
}

function stateKeyFile(path: string | undefined, inlineValue: string | undefined): Buffer {
  if (inlineValue !== undefined || path === undefined || path.trim().length === 0) {
    throw configurationError();
  }
  try {
    return stateKey(readFileSync(path, 'utf8').trim());
  } catch {
    throw configurationError();
  }
}

function loadOidcBffConfig(
  source: OidcBffEnvironmentSource = processOidcEnvironment(),
): OidcBffConfig | null {
  const relevant = [
    source.KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT,
    source.KOVCHEG_WEB_OIDC_CLIENT_ID,
    source.KOVCHEG_WEB_OIDC_ISSUER,
    source.KOVCHEG_WEB_OIDC_REDIRECT_URI,
    source.KOVCHEG_WEB_OIDC_STATE_KEY,
    source.KOVCHEG_WEB_OIDC_STATE_KEY_FILE,
    source.KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD,
  ];
  if (relevant.every((value) => value === undefined || value.trim().length === 0)) return null;

  const authorizationEndpoint = source.KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT?.trim();
  const clientId = source.KOVCHEG_WEB_OIDC_CLIENT_ID?.trim();
  const issuer = source.KOVCHEG_WEB_OIDC_ISSUER?.trim();
  const redirectUri = source.KOVCHEG_WEB_OIDC_REDIRECT_URI?.trim();
  const tokenEndpointAuthMethod = source.KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD?.trim();

  if (
    authorizationEndpoint === undefined ||
    clientId === undefined ||
    issuer === undefined ||
    redirectUri === undefined ||
    !clientIdPattern.test(clientId) ||
    tokenEndpointAuthMethod !== 'none'
  ) {
    throw configurationError();
  }

  const normalizedIssuer = normalizedHttpsUrl(issuer, 'issuer');
  const normalizedAuthorizationEndpoint = normalizedHttpsUrl(authorizationEndpoint, 'endpoint');
  const normalizedRedirectUri = normalizedHttpsUrl(redirectUri, 'redirect');
  if (new URL(normalizedAuthorizationEndpoint).origin !== new URL(normalizedIssuer).origin) {
    throw configurationError();
  }

  return Object.freeze({
    authorizationEndpoint: normalizedAuthorizationEndpoint,
    clientId,
    internalOrigin: bareInternalOrigin(source.KOVCHEG_AUTH_INTERNAL_URL),
    issuer: normalizedIssuer,
    redirectUri: normalizedRedirectUri,
    stateKey: stateKeyFile(
      source.KOVCHEG_WEB_OIDC_STATE_KEY_FILE,
      source.KOVCHEG_WEB_OIDC_STATE_KEY,
    ),
    tokenEndpointAuthMethod,
  });
}

function discoveryUrl(issuer: string): string {
  const parsed = new URL(issuer);
  const issuerPath = parsed.pathname === '/' ? '' : parsed.pathname;
  parsed.pathname = `/.well-known/openid-configuration${issuerPath}`;
  return parsed.toString();
}

function internalProviderUrl(config: OidcBffConfig, publicUrl: string): string {
  const external = new URL(publicUrl);
  if (external.origin !== config.issuer) throw new Error('OIDC provider URL is invalid');
  const internal = new URL(config.internalOrigin);
  internal.pathname = external.pathname;
  internal.search = external.search;
  return internal.toString();
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const body = await response.text();
  if (!response.ok || Buffer.byteLength(body, 'utf8') > maximumJsonBytes) {
    throw new Error('OIDC upstream response is unavailable');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    throw new Error('OIDC upstream response is unavailable');
  }
  const result = object(parsed);
  if (result === null) throw new Error('OIDC upstream response is unavailable');
  return result;
}

function secureProviderEndpoint(value: unknown, issuer: string): string {
  if (typeof value !== 'string') throw new Error('OIDC discovery is invalid');
  const normalized = normalizedHttpsUrl(value, 'endpoint');
  if (new URL(normalized).origin !== new URL(issuer).origin) {
    throw new Error('OIDC discovery is invalid');
  }
  return normalized;
}

async function discover(config: OidcBffConfig, fetcher: typeof fetch): Promise<OidcDiscovery> {
  const response = await fetcher(internalProviderUrl(config, discoveryUrl(config.issuer)), {
    cache: 'no-store',
    headers: { accept: 'application/json' },
    redirect: 'manual',
  });
  const metadata = await readJson(response);
  if (
    metadata.issuer !== config.issuer ||
    !Array.isArray(metadata.response_types_supported) ||
    !metadata.response_types_supported.includes('code') ||
    !Array.isArray(metadata.code_challenge_methods_supported) ||
    !metadata.code_challenge_methods_supported.includes('S256')
  ) {
    throw new Error('OIDC discovery is invalid');
  }
  if (
    Array.isArray(metadata.token_endpoint_auth_methods_supported) &&
    !metadata.token_endpoint_auth_methods_supported.includes(config.tokenEndpointAuthMethod)
  ) {
    throw new Error('OIDC discovery is invalid');
  }
  const authorizationEndpoint = secureProviderEndpoint(
    metadata.authorization_endpoint,
    config.issuer,
  );
  if (authorizationEndpoint !== config.authorizationEndpoint) {
    throw new Error('OIDC discovery is invalid');
  }
  return Object.freeze({
    authorizationEndpoint,
    issuer: config.issuer,
    jwksUri: secureProviderEndpoint(metadata.jwks_uri, config.issuer),
    tokenEndpoint: secureProviderEndpoint(metadata.token_endpoint, config.issuer),
  });
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

function sealBinding(binding: OidcBinding, key: Buffer, random: (size: number) => Buffer): string {
  const iv = random(12);
  if (iv.byteLength !== 12) throw new Error('OIDC randomness is unavailable');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(bindingAad);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(binding), 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${tag.toString('base64url')}`;
}

function bindingRecord(value: unknown): OidcBinding | null {
  const candidate = object(value);
  if (
    candidate?.version !== 1 ||
    typeof candidate.authorizationEndpoint !== 'string' ||
    typeof candidate.clientId !== 'string' ||
    typeof candidate.codeVerifier !== 'string' ||
    !Number.isSafeInteger(candidate.issuedAt) ||
    typeof candidate.issuer !== 'string' ||
    typeof candidate.nonce !== 'string' ||
    typeof candidate.redirectUri !== 'string' ||
    typeof candidate.state !== 'string'
  ) {
    return null;
  }
  return candidate as unknown as OidcBinding;
}

function openBinding(value: string, key: Buffer): OidcBinding | null {
  const parts = value.split('.');
  if (
    parts.length !== 4 ||
    parts[0] !== 'v1' ||
    parts.slice(1).some((part) => !base64UrlPattern.test(part ?? ''))
  ) {
    return null;
  }
  try {
    const iv = Buffer.from(parts[1] ?? '', 'base64url');
    const ciphertext = Buffer.from(parts[2] ?? '', 'base64url');
    const tag = Buffer.from(parts[3] ?? '', 'base64url');
    if (iv.byteLength !== 12 || ciphertext.byteLength < 1 || tag.byteLength !== 16) return null;
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(bindingAad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.byteLength > 4096) return null;
    return bindingRecord(JSON.parse(plaintext.toString('utf8')) as unknown);
  } catch {
    return null;
  }
}

function setBindingCookie(response: NextResponse, value: string, maxAge: number): void {
  response.cookies.set({
    httpOnly: true,
    maxAge,
    name: oidcBindingCookieName,
    path: '/',
    sameSite: 'lax',
    secure: true,
    value,
  });
}

function unavailable(clearBinding = false): NextResponse {
  const response = NextResponse.json(
    { code: 'a6.oidc-not-configured', status: 503 },
    { status: 503 },
  );
  response.headers.set('cache-control', 'no-store');
  if (clearBinding) setBindingCookie(response, '', 0);
  return response;
}

function requestMatchesConfig(request: NextRequest, config: OidcBffConfig, path: string): boolean {
  const redirect = new URL(config.redirectUri);
  const forwardedHost = request.headers.get('x-forwarded-host');
  const host = forwardedHost ?? request.headers.get('host') ?? request.nextUrl.host;
  if (!requestIsSecure(request) || host.includes(',') || /[\s/@\\]/u.test(host)) return false;
  let origin: string;
  try {
    origin = new URL(`https://${host}`).origin;
  } catch {
    return false;
  }
  return origin === redirect.origin && request.nextUrl.pathname === path;
}

function randomProtocolValue(random: (size: number) => Buffer): string {
  const value = random(32);
  if (value.byteLength !== 32) throw new Error('OIDC randomness is unavailable');
  return value.toString('base64url');
}

export async function startOidcAuthorization(
  request: NextRequest,
  dependencies: OidcBffDependencies = {},
): Promise<NextResponse> {
  try {
    const config = loadOidcBffConfig(dependencies.environment ?? processOidcEnvironment());
    if (config === null || !requestMatchesConfig(request, config, oidcStartPath)) {
      return unavailable();
    }
    const fetcher = dependencies.fetcher ?? fetch;
    const random = dependencies.random ?? randomBytes;
    const metadata = await discover(config, fetcher);
    const state = randomProtocolValue(random);
    const nonce = randomProtocolValue(random);
    const codeVerifier = randomProtocolValue(random);
    const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
    const binding: OidcBinding = Object.freeze({
      authorizationEndpoint: metadata.authorizationEndpoint,
      clientId: config.clientId,
      codeVerifier,
      issuedAt: Math.floor((dependencies.now ?? Date.now)() / 1000),
      issuer: config.issuer,
      nonce,
      redirectUri: config.redirectUri,
      state,
      version: 1,
    });
    const authorization = new URL(metadata.authorizationEndpoint);
    authorization.search = new URLSearchParams({
      client_id: config.clientId,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      nonce,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: 'openid',
      state,
    }).toString();
    const response = NextResponse.redirect(authorization, 303);
    response.headers.set('cache-control', 'no-store');
    setBindingCookie(
      response,
      sealBinding(binding, config.stateKey, random),
      oidcBindingLifetimeSeconds,
    );
    return response;
  } catch {
    return unavailable();
  }
}

function exactQuery(
  request: NextRequest,
): { readonly code: string; readonly issuer?: string | undefined; readonly state: string } | null {
  const parameters = request.nextUrl.searchParams;
  const keys = [...new Set(parameters.keys())];
  if (keys.some((key) => !['code', 'iss', 'state'].includes(key))) return null;
  if (
    parameters.getAll('code').length !== 1 ||
    parameters.getAll('state').length !== 1 ||
    parameters.getAll('iss').length > 1
  ) {
    return null;
  }
  const code = parameters.get('code');
  const state = parameters.get('state');
  const issuer = parameters.get('iss');
  if (
    code === null ||
    state === null ||
    !authorizationCodePattern.test(code) ||
    !base64UrlPattern.test(state)
  ) {
    return null;
  }
  return Object.freeze({ code, ...(issuer === null ? {} : { issuer }), state });
}

async function exchangeCode(input: {
  readonly code: string;
  readonly codeVerifier: string;
  readonly config: OidcBffConfig;
  readonly fetcher: typeof fetch;
  readonly tokenEndpoint: string;
}): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    code: input.code,
    code_verifier: input.codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: input.config.redirectUri,
  });
  const headers = new Headers({
    accept: 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
  });
  body.set('client_id', input.config.clientId);
  return readJson(
    await input.fetcher(internalProviderUrl(input.config, input.tokenEndpoint), {
      body,
      cache: 'no-store',
      headers,
      method: 'POST',
      redirect: 'manual',
    }),
  );
}

function base64Json(segment: string): Record<string, unknown> | null {
  if (!base64UrlPattern.test(segment)) return null;
  try {
    const bytes = Buffer.from(segment, 'base64url');
    if (bytes.byteLength < 2 || bytes.byteLength > 16 * 1024) return null;
    return object(JSON.parse(bytes.toString('utf8')) as unknown);
  } catch {
    return null;
  }
}

function validAudience(payload: Record<string, unknown>, clientId: string): boolean {
  if (payload.aud === clientId) return true;
  if (!Array.isArray(payload.aud) || payload.aud.some((item) => typeof item !== 'string')) {
    return false;
  }
  return payload.aud.includes(clientId) && (payload.aud.length === 1 || payload.azp === clientId);
}

async function verifyIdToken(input: {
  readonly clientId: string;
  readonly config: OidcBffConfig;
  readonly fetcher: typeof fetch;
  readonly idToken: string;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly nonce: string;
  readonly now: number;
}): Promise<void> {
  const parts = input.idToken.split('.');
  if (parts.length !== 3) throw new Error('OIDC ID token is invalid');
  const header = base64Json(parts[0] ?? '');
  const payload = base64Json(parts[1] ?? '');
  const signaturePart = parts[2] ?? '';
  if (
    header === null ||
    payload === null ||
    (header.alg !== 'ES256' && header.alg !== 'RS256') ||
    typeof header.kid !== 'string' ||
    header.kid.length < 1 ||
    !base64UrlPattern.test(signaturePart)
  ) {
    throw new Error('OIDC ID token is invalid');
  }
  const headerAlgorithm = header.alg;
  const headerKeyId = header.kid;
  const jwks = await readJson(
    await input.fetcher(internalProviderUrl(input.config, input.jwksUri), {
      cache: 'no-store',
      headers: { accept: 'application/json' },
      redirect: 'manual',
    }),
  );
  if (!Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 32) {
    throw new Error('OIDC JWKS is invalid');
  }
  const matches = jwks.keys.filter((candidate) => {
    const key = object(candidate);
    return key?.kid === headerKeyId && (key.alg === undefined || key.alg === headerAlgorithm);
  });
  if (matches.length !== 1) throw new Error('OIDC JWKS is invalid');
  const key = object(matches[0]);
  if (key === null || (key.use !== undefined && key.use !== 'sig')) {
    throw new Error('OIDC JWKS is invalid');
  }
  let publicKey;
  try {
    publicKey = createPublicKey({ format: 'jwk', key: key as CryptoJsonWebKey });
  } catch {
    throw new Error('OIDC JWKS is invalid');
  }
  const signature = Buffer.from(signaturePart, 'base64url');
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
  const validSignature =
    headerAlgorithm === 'ES256'
      ? verifySignature(
          'sha256',
          signingInput,
          { dsaEncoding: 'ieee-p1363', key: publicKey },
          signature,
        )
      : verifySignature('RSA-SHA256', signingInput, publicKey, signature);
  if (!validSignature) throw new Error('OIDC ID token is invalid');

  const nowSeconds = Math.floor(input.now / 1000);
  if (
    payload.iss !== input.issuer ||
    !validAudience(payload, input.clientId) ||
    typeof payload.sub !== 'string' ||
    payload.sub.length < 1 ||
    payload.sub.length > 200 ||
    typeof payload.nonce !== 'string' ||
    !constantTimeEqual(payload.nonce, input.nonce) ||
    !Number.isSafeInteger(payload.exp) ||
    (payload.exp as number) <= nowSeconds ||
    (payload.exp as number) > nowSeconds + 10 * 60 ||
    !Number.isSafeInteger(payload.iat) ||
    (payload.iat as number) > nowSeconds + 60 ||
    (payload.iat as number) < nowSeconds - 10 * 60 ||
    (payload.nbf !== undefined &&
      (!Number.isSafeInteger(payload.nbf) || (payload.nbf as number) > nowSeconds + 60))
  ) {
    throw new Error('OIDC ID token claims are invalid');
  }
}

export async function completeOidcAuthorization(
  request: NextRequest,
  dependencies: OidcBffDependencies = {},
): Promise<NextResponse> {
  try {
    const config = loadOidcBffConfig(dependencies.environment ?? processOidcEnvironment());
    if (config === null || !requestMatchesConfig(request, config, oidcCallbackPath)) {
      return unavailable(true);
    }
    const cookie = request.cookies.get(oidcBindingCookieName)?.value;
    const binding = cookie === undefined ? null : openBinding(cookie, config.stateKey);
    const query = exactQuery(request);
    const now = (dependencies.now ?? Date.now)();
    const nowSeconds = Math.floor(now / 1000);
    if (
      binding === null ||
      query === null ||
      binding.authorizationEndpoint !== config.authorizationEndpoint ||
      binding.clientId !== config.clientId ||
      binding.issuer !== config.issuer ||
      binding.redirectUri !== config.redirectUri ||
      binding.issuedAt > nowSeconds ||
      nowSeconds - binding.issuedAt > oidcBindingLifetimeSeconds ||
      !constantTimeEqual(query.state, binding.state) ||
      (query.issuer !== undefined && query.issuer !== config.issuer)
    ) {
      return unavailable(true);
    }
    const fetcher = dependencies.fetcher ?? fetch;
    const metadata = await discover(config, fetcher);
    const token = await exchangeCode({
      code: query.code,
      codeVerifier: binding.codeVerifier,
      config,
      fetcher,
      tokenEndpoint: metadata.tokenEndpoint,
    });
    if (
      typeof token.access_token !== 'string' ||
      token.access_token.length < 16 ||
      token.access_token.length > 4096 ||
      /\s/u.test(token.access_token) ||
      typeof token.id_token !== 'string' ||
      token.id_token.length < 16 ||
      token.id_token.length > 32 * 1024 ||
      token.token_type !== 'Bearer' ||
      !Number.isSafeInteger(token.expires_in) ||
      (token.expires_in as number) < 1 ||
      (token.expires_in as number) > 10 * 60 ||
      (token.scope !== undefined && token.scope !== 'openid') ||
      token.refresh_token !== undefined
    ) {
      return unavailable(true);
    }
    await verifyIdToken({
      clientId: config.clientId,
      config,
      fetcher,
      idToken: token.id_token,
      issuer: config.issuer,
      jwksUri: metadata.jwksUri,
      nonce: binding.nonce,
      now,
    });
    const bridge = await requestAuth(request, '/internal/oidc/session', {
      body: JSON.stringify({ accessToken: token.access_token }),
      cookies: 'none',
      fetcher,
      method: 'POST',
    });
    if (bridge.status !== 204) return unavailable(true);

    const response = NextResponse.redirect(new URL('/', config.redirectUri), 303);
    response.headers.set('cache-control', 'no-store');
    setBindingCookie(response, '', 0);
    if (!copySessionSetCookie(bridge, response)) return unavailable(true);
    return response;
  } catch {
    return unavailable(true);
  }
}
