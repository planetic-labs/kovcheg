import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { copySessionSetCookie, requestAuth } from './internal-http';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

type PasskeyKind = 'authentication' | 'registration';

function objectValue(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function passkeyError(status: number): NextResponse {
  const response = NextResponse.json(
    { code: status === 401 ? 'a6.unauthenticated' : 'a6.unavailable', status },
    { status },
  );
  response.headers.set('cache-control', 'no-store');
  response.headers.set('referrer-policy', 'no-referrer');
  return response;
}

function passkeyJson(value: unknown, status = 200): NextResponse {
  const response = NextResponse.json(value, { status });
  response.headers.set('cache-control', 'no-store');
  response.headers.set('referrer-policy', 'no-referrer');
  return response;
}

function upstreamFailure(upstream: Response): NextResponse {
  return passkeyError(upstream.status >= 500 ? 503 : 401);
}

export async function passkeyOptions(
  request: NextRequest,
  kind: PasskeyKind,
): Promise<NextResponse> {
  let upstream: Response;
  try {
    upstream = await requestAuth(request, `/passkeys/${kind}/options`, {
      cookies: kind === 'registration' ? 'session' : 'none',
      method: 'POST',
    });
  } catch {
    return passkeyError(503);
  }
  if (!upstream.ok) return upstreamFailure(upstream);
  const payload = (await upstream.json().catch(() => null)) as unknown;
  if (
    !objectValue(payload) ||
    typeof payload.ceremonyId !== 'string' ||
    !uuidPattern.test(payload.ceremonyId) ||
    !objectValue(payload.options) ||
    (kind === 'authentication' && payload.mediation !== 'conditional')
  ) {
    return passkeyError(503);
  }
  return passkeyJson(
    kind === 'authentication'
      ? {
          ceremonyId: payload.ceremonyId,
          mediation: 'conditional',
          options: payload.options,
        }
      : { ceremonyId: payload.ceremonyId, options: payload.options },
  );
}

export async function passkeyVerify(
  request: NextRequest,
  kind: PasskeyKind,
): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as unknown;
  if (
    !objectValue(body) ||
    Object.keys(body).sort().join(',') !== 'ceremonyId,response' ||
    typeof body.ceremonyId !== 'string' ||
    !uuidPattern.test(body.ceremonyId) ||
    !objectValue(body.response)
  ) {
    return passkeyError(401);
  }

  let upstream: Response;
  try {
    upstream = await requestAuth(request, `/passkeys/${kind}/verify`, {
      body: JSON.stringify({ ceremonyId: body.ceremonyId, response: body.response }),
      cookies: kind === 'registration' ? 'session' : 'none',
      method: 'POST',
    });
  } catch {
    return passkeyError(503);
  }
  if (!upstream.ok) return upstreamFailure(upstream);

  const payload = (await upstream.json().catch(() => null)) as unknown;
  if (
    !objectValue(payload) ||
    (kind === 'registration'
      ? payload.status !== 'registered' ||
        typeof payload.passkeyId !== 'string' ||
        !uuidPattern.test(payload.passkeyId)
      : typeof payload.sessionId !== 'string' ||
        !uuidPattern.test(payload.sessionId) ||
        typeof payload.userId !== 'string' ||
        !uuidPattern.test(payload.userId))
  ) {
    return passkeyError(503);
  }

  const response = passkeyJson(
    kind === 'registration' ? { registered: true } : { authenticated: true },
    kind === 'registration' ? 201 : 200,
  );
  if (kind === 'authentication' && !copySessionSetCookie(upstream, response)) {
    return passkeyError(503);
  }
  return response;
}
