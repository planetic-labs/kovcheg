import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import {
  bffError,
  copySetCookies,
  requestAuth,
  requestIsSecure,
} from '../../../../../a6/server/internal-http';

const challengeCookieName = 'kovcheg_login_challenge';
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as { readonly code?: unknown } | null;
  const challengeId = request.cookies.get(challengeCookieName)?.value;
  if (
    typeof body?.code !== 'string' ||
    !/^\d{6}$/u.test(body.code) ||
    challengeId === undefined ||
    !uuidPattern.test(challengeId)
  ) {
    return bffError(400, 'a6.invalid-request');
  }

  let upstream: Response;
  try {
    upstream = await requestAuth(request, `/session/challenges/${challengeId}/verify`, {
      body: JSON.stringify({ code: body.code }),
      method: 'POST',
    });
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  if (!upstream.ok) {
    return bffError(
      upstream.status,
      upstream.status >= 500 ? 'a6.unavailable' : 'a6.unauthenticated',
    );
  }

  const response = NextResponse.json({ authenticated: true });
  copySetCookies(upstream, response);
  response.headers.append(
    'set-cookie',
    [
      `${challengeCookieName}=`,
      'Path=/bff/auth',
      'Max-Age=0',
      'HttpOnly',
      'SameSite=Strict',
      ...(requestIsSecure(request) ? ['Secure'] : []),
    ].join('; '),
  );
  response.headers.set('cache-control', 'no-store');
  return response;
}
