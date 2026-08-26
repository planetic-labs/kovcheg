import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { bffError, copySetCookies, relayJson, requestAuth } from '../../../a6/server/internal-http';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    return relayJson(await requestAuth(request, '/session', { method: 'GET' }));
  } catch {
    return bffError(503, 'a6.unavailable');
  }
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  let upstream: Response;
  try {
    upstream = await requestAuth(request, '/session', { method: 'DELETE' });
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  const response = new NextResponse(null, { status: upstream.status });
  copySetCookies(upstream, response);
  response.headers.set('cache-control', 'no-store');
  return response;
}
