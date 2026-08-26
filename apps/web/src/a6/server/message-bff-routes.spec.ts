import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  GET as readMessages,
  POST as createMessage,
} from '../../app/bff/chats/[chatId]/messages/route';

const chatId = '00000000-0000-4000-8000-000000000801';
const sessionId = '00000000-0000-4000-8000-000000000802';
const userId = '00000000-0000-4000-8000-000000000803';
const context = Object.freeze({ params: Promise.resolve({ chatId }) });

function request(path: string, init?: ConstructorParameters<typeof NextRequest>[1]): NextRequest {
  return new NextRequest(`http://localhost${path}`, init);
}

function principal() {
  return {
    accountAccess: 'member',
    accountStatus: 'active',
    administrativeCapabilities: {
      canManageAccounts: false,
      canManageDomainStatus: false,
      canManageFunctionalGrants: false,
      canManagePlatformAdministrators: false,
    },
    contractVersion: 2,
    diagnosticCapabilities: {
      canReadBuildAndMigrationVersions: false,
      canReadHealthAndReadiness: false,
      canReadQueueAndTechnicalState: false,
      canReadSanitizedDiagnostics: false,
    },
    domainStatus: 'incubator_participant',
    functionalGrants: [],
    isServerOwner: false,
    materialCapabilities: [],
    sensitiveCapabilities: { canPerformSensitiveActions: false },
    sessionId,
    sessionStatus: 'active',
    userId,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('A6 message BFF', () => {
  it('fails closed before the API call when the application session is invalid', async () => {
    const upstream = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'auth.invalid-session' }), {
        headers: { 'content-type': 'application/json' },
        status: 401,
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await readMessages(request(`/bff/chats/${chatId}/messages?limit=50`), context);
    expect(response.status).toBe(401);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('preserves the bounded history cursor query for the production API', async () => {
    const history = {
      contractVersion: 3,
      hasMore: false,
      items: [],
      nextAfterSequence: null,
      nextBeforeSequence: null,
    };
    const upstream = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(principal()), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(history), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      );
    vi.stubGlobal('fetch', upstream);

    const response = await readMessages(
      request(`/bff/chats/${chatId}/messages?afterSequence=7&limit=100`),
      context,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(history);
    expect(upstream).toHaveBeenNthCalledWith(
      2,
      `http://edge:8080/api/chats/${chatId}/messages?afterSequence=7&limit=100`,
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('forwards the client idempotency key and text without browser identity fields', async () => {
    const body = JSON.stringify({ clientMessageId: 'web:retry-001', text: 'Synthetic text' });
    const upstream = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(principal()), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ accepted: true }), {
          headers: { 'content-type': 'application/json' },
          status: 201,
        }),
      );
    vi.stubGlobal('fetch', upstream);

    const response = await createMessage(
      request(`/bff/chats/${chatId}/messages`, {
        body,
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
      context,
    );
    expect(response.status).toBe(201);
    expect(upstream).toHaveBeenNthCalledWith(
      2,
      `http://edge:8080/api/chats/${chatId}/messages`,
      expect.objectContaining({ body, method: 'POST' }),
    );
    expect(body).not.toContain('userId');
    expect(body).not.toContain('role');
  });
});
