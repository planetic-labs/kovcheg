import type { NextRequest } from 'next/server';

import {
  bffError,
  readSession,
  relayJson,
  requestApi,
} from '../../../../../a6/server/internal-http';

interface RouteContext {
  readonly params: Promise<{ readonly chatId: string }>;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const allowedQueryKeys = new Set(['afterSequence', 'beforeSequence', 'limit']);

async function target(request: NextRequest, context: RouteContext): Promise<string | null> {
  const { chatId } = await context.params;
  if (!uuidPattern.test(chatId)) return null;
  if (request.method === 'POST' && request.nextUrl.searchParams.size > 0) return null;
  for (const key of request.nextUrl.searchParams.keys()) {
    if (!allowedQueryKeys.has(key)) return null;
  }
  const query = request.nextUrl.searchParams.toString();
  return `/chats/${chatId}/messages${query.length > 0 ? `?${query}` : ''}`;
}

async function forward(request: NextRequest, context: RouteContext) {
  try {
    if ((await readSession(request)) === null) return bffError(401, 'a6.unauthenticated');
  } catch {
    return bffError(503, 'a6.unavailable');
  }
  const path = await target(request, context);
  if (path === null) return bffError(400, 'a6.invalid-request');
  try {
    const body = request.method === 'POST' ? await request.text() : undefined;
    return relayJson(
      await requestApi(request, path, {
        ...(body === undefined ? {} : { body }),
        method: request.method as 'GET' | 'POST',
      }),
    );
  } catch {
    return bffError(503, 'a6.unavailable');
  }
}

export function GET(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export function POST(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}
