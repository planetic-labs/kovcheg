import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { bffError, copySetCookies, requestAuth } from '../../../../a6/server/internal-http';

export async function GET(request: NextRequest): Promise<NextResponse> {
  let upstream: Response;
  try {
    upstream = await requestAuth(request, '/personal-gate', { method: 'GET' });
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  if (!upstream.ok) return bffError(503, 'a6.unavailable');
  const payload = (await upstream.json().catch(() => null)) as { readonly status?: unknown } | null;
  if (payload?.status !== 'active' && payload?.status !== 'required') {
    return bffError(503, 'a6.unavailable');
  }
  return NextResponse.json(
    { status: payload.status },
    { headers: { 'cache-control': 'no-store' } },
  );
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as {
    readonly clientIdempotencyKey?: unknown;
    readonly code?: unknown;
  } | null;
  if (typeof body?.code !== 'string' || typeof body.clientIdempotencyKey !== 'string') {
    return bffError(400, 'a6.invalid-request');
  }
  let upstream: Response;
  try {
    upstream = await requestAuth(request, '/personal-gate/activate', {
      body: JSON.stringify(body),
      method: 'POST',
    });
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  if (upstream.status !== 202) {
    return bffError(upstream.status >= 500 ? 503 : upstream.status, 'a6.unavailable');
  }
  const payload = (await upstream.json().catch(() => null)) as {
    readonly next?: unknown;
    readonly status?: unknown;
  } | null;
  if (payload?.status !== 'accepted' || (payload.next !== 'gate' && payload.next !== 'email')) {
    return bffError(503, 'a6.unavailable');
  }
  const response = NextResponse.json({ next: payload.next, status: 'accepted' }, { status: 202 });
  copySetCookies(upstream, response);
  response.headers.set('cache-control', 'no-store');
  return response;
}
