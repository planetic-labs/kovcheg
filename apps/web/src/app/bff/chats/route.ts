import type { NextRequest } from 'next/server';

import { bffError, readSession, relayJson, requestApi } from '../../../a6/server/internal-http';

export async function GET(request: NextRequest) {
  try {
    if ((await readSession(request)) === null) {
      return bffError(401, 'a6.unauthenticated');
    }
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  try {
    return relayJson(await requestApi(request, '/chats', { method: 'GET' }));
  } catch {
    return bffError(503, 'a6.unavailable');
  }
}
