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

function selectedHeaders(request: NextRequest, includeBody: boolean): Headers {
  const headers = new Headers({ accept: 'application/json' });
  for (const name of ['cookie', 'user-agent', 'x-correlation-id', 'x-forwarded-for']) {
    const value = request.headers.get(name);
    if (value !== null) {
      headers.set(name, value);
    }
  }
  if (includeBody) {
    headers.set('content-type', 'application/json');
  }
  return headers;
}

export async function requestAuth(
  request: NextRequest,
  path: string,
  input: Readonly<{ body?: string; method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT' }>,
): Promise<Response> {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error('A6 auth upstream path must be absolute and origin-relative');
  }
  return fetch(`${authOrigin()}${path}`, {
    ...(input.body === undefined ? {} : { body: input.body }),
    cache: 'no-store',
    headers: selectedHeaders(request, input.body !== undefined),
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
    headers: selectedHeaders(request, input.body !== undefined),
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
