import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { parseSessionPrincipal } from '../contracts';
import type { SessionPrincipal } from '../contracts';

const defaultAuthOrigin = 'http://auth:3002';
const defaultApiBaseUrl = 'http://edge:8080/api';

function authOrigin(): string {
  const origin = new URL(process.env.KOVCHEG_AUTH_INTERNAL_URL ?? defaultAuthOrigin);
  if (
    !['http:', 'https:'].includes(origin.protocol) ||
    origin.username !== '' ||
    origin.password !== '' ||
    origin.pathname !== '/' ||
    origin.search !== '' ||
    origin.hash !== ''
  ) {
    throw new Error('A6 auth upstream must be a bare HTTP(S) origin');
  }
  return origin.origin;
}

function apiBaseUrl(): string {
  const base = new URL(process.env.KOVCHEG_API_INTERNAL_URL ?? defaultApiBaseUrl);
  if (
    !['http:', 'https:'].includes(base.protocol) ||
    base.username !== '' ||
    base.password !== '' ||
    base.search !== '' ||
    base.hash !== ''
  ) {
    throw new Error('A6 API upstream must be an HTTP(S) base URL');
  }
  base.pathname = base.pathname.replace(/\/$/u, '');
  return base.toString().replace(/\/$/u, '');
}

type CookieForwarding = 'all' | 'none' | 'session';

function sessionCookieHeader(value: string | null): string | null {
  if (value === null) return null;
  const matches = value
    .split(';')
    .map((part) => part.trim())
    .filter((part) => {
      const name = part.slice(0, part.indexOf('='));
      return name === '__Host-kovcheg_session' || name === 'kovcheg_session';
    });
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

function selectedHeaders(
  request: NextRequest,
  includeBody: boolean,
  cookieForwarding: CookieForwarding,
): Headers {
  const headers = new Headers({ accept: 'application/json' });
  for (const name of ['user-agent', 'x-correlation-id', 'x-forwarded-for']) {
    const value = request.headers.get(name);
    if (value !== null) {
      headers.set(name, value);
    }
  }
  const cookie =
    cookieForwarding === 'all'
      ? request.headers.get('cookie')
      : cookieForwarding === 'session'
        ? sessionCookieHeader(request.headers.get('cookie'))
        : null;
  if (cookie !== null) headers.set('cookie', cookie);
  if (includeBody) {
    headers.set('content-type', 'application/json');
  }
  return headers;
}

export async function requestAuth(
  request: NextRequest,
  path: string,
  input: Readonly<{
    body?: string;
    cookies?: CookieForwarding;
    fetcher?: typeof fetch;
    method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  }>,
): Promise<Response> {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error('A6 auth upstream path must be absolute and origin-relative');
  }
  return (input.fetcher ?? fetch)(`${authOrigin()}${path}`, {
    ...(input.body === undefined ? {} : { body: input.body }),
    cache: 'no-store',
    headers: selectedHeaders(request, input.body !== undefined, input.cookies ?? 'all'),
    method: input.method,
  });
}

export async function requestApi(
  request: NextRequest,
  path: string,
  input: Readonly<{ body?: string; method: 'GET' | 'POST' }>,
): Promise<Response> {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error('A6 API upstream path must be absolute and origin-relative');
  }
  return fetch(`${apiBaseUrl()}${path}`, {
    ...(input.body === undefined ? {} : { body: input.body }),
    cache: 'no-store',
    headers: selectedHeaders(request, input.body !== undefined, 'all'),
    method: input.method,
  });
}

export async function readSession(request: NextRequest): Promise<SessionPrincipal | null> {
  const response = await requestAuth(request, '/session', { method: 'GET' });
  if (!response.ok) {
    return null;
  }
  return parseSessionPrincipal(await response.json().catch(() => null));
}

export function requestIsSecure(request: NextRequest): boolean {
  const forwardedProtocol = request.headers.get('x-forwarded-proto')?.split(',', 1)[0]?.trim();
  return forwardedProtocol === 'https' || request.nextUrl.protocol === 'https:';
}

export function copySetCookies(upstream: Response, downstream: NextResponse): void {
  const headers = upstream.headers as Headers & { getSetCookie?: () => string[] };
  const values = headers.getSetCookie?.() ?? [];
  if (values.length > 0) {
    for (const value of values) {
      downstream.headers.append('set-cookie', value);
    }
    return;
  }
  const value = upstream.headers.get('set-cookie');
  if (value !== null) {
    downstream.headers.append('set-cookie', value);
  }
}

export function copySessionSetCookie(upstream: Response, downstream: NextResponse): boolean {
  const headers = upstream.headers as Headers & { getSetCookie?: () => string[] };
  const values = headers.getSetCookie?.() ?? [];
  const candidates =
    values.length > 0
      ? values
      : upstream.headers.get('set-cookie') === null
        ? []
        : [upstream.headers.get('set-cookie') as string];
  const sessionCookies = candidates.filter((value) => {
    const name = value.slice(0, value.indexOf('='));
    return name === '__Host-kovcheg_session' || name === 'kovcheg_session';
  });
  if (sessionCookies.length !== 1) return false;
  for (const value of sessionCookies) {
    downstream.headers.append('set-cookie', value);
  }
  return true;
}

export async function relayJson(upstream: Response): Promise<NextResponse> {
  const text = await upstream.text();
  return new NextResponse(text.length > 0 ? text : null, {
    headers: {
      'cache-control': 'no-store',
      'content-type': upstream.headers.get('content-type') ?? 'application/json',
    },
    status: upstream.status,
  });
}

export function bffError(
  status: number,
  code:
    | 'a6.chat-list-contract-unavailable'
    | 'a6.forbidden'
    | 'a6.invalid-request'
    | 'a6.unauthenticated'
    | 'a6.unavailable',
): NextResponse {
  return NextResponse.json({ code, status }, { headers: { 'cache-control': 'no-store' }, status });
}
