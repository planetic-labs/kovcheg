import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { bffError, requestAuth, requestIsSecure } from '../../../../a6/server/internal-http';

const challengeCookieName = 'kovcheg_login_challenge';
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as { readonly email?: unknown } | null;
  if (typeof body?.email !== 'string') {
    return bffError(400, 'a6.invalid-request');
  }
  let upstream: Response;
  try {
    upstream = await requestAuth(request, '/session/challenges', {
      body: JSON.stringify({ email: body.email }),
      method: 'POST',
    });
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  if (upstream.status !== 202) {
    return bffError(
      upstream.status,
      upstream.status >= 500 ? 'a6.unavailable' : 'a6.invalid-request',
    );
  }
  const payload = (await upstream.json().catch(() => null)) as {
    readonly challengeId?: unknown;
    readonly status?: unknown;
  } | null;
  if (
    payload?.status !== 'accepted' ||
    typeof payload.challengeId !== 'string' ||
    !uuidPattern.test(payload.challengeId)
  ) {
    return bffError(503, 'a6.unavailable');
  }

  const response = NextResponse.json({ status: 'accepted' }, { status: 202 });
  response.cookies.set({
    httpOnly: true,
    maxAge: 10 * 60,
    name: challengeCookieName,
    path: '/bff/auth',
    sameSite: 'strict',
    secure: requestIsSecure(request),
    value: payload.challengeId,
  });
  response.headers.set('cache-control', 'no-store');
  return response;
}
