import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { POST as requestChallenge } from '../../app/bff/auth/challenge/route';
import { POST as verifyChallenge } from '../../app/bff/auth/challenge/verify/route';
import { POST as createAccount } from '../../app/bff/admin/accounts/[[...path]]/route';
import { GET as readChats } from '../../app/bff/chats/route';
import { DELETE as logout } from '../../app/bff/session/route';

const challengeId = '00000000-0000-4000-8000-000000000601';
const sessionId = '00000000-0000-4000-8000-000000000602';
const userId = '00000000-0000-4000-8000-000000000603';

function request(path: string, init?: ConstructorParameters<typeof NextRequest>[1]): NextRequest {
  return new NextRequest(`http://localhost${path}`, init);
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.KOVCHEG_AUTH_INTERNAL_URL;
  delete process.env.KOVCHEG_API_INTERNAL_URL;
});

function principal(canManageAccounts: boolean) {
  return {
    accountAccess: 'member',
    accountStatus: 'active',
    administrativeCapabilities: {
      canManageAccounts,
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
    domainStatus: 'disciple',
    functionalGrants: [],
    isServerOwner: false,
    materialCapabilities: [],
    sensitiveCapabilities: { canPerformSensitiveActions: false },
    sessionId,
    sessionStatus: 'active',
    userId,
  };
}

describe('A6 same-origin auth BFF', () => {
  it('keeps the external challenge response neutral and the challenge ID HTTP-only', async () => {
    const upstream = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ challengeId, status: 'accepted' }), {
        headers: { 'content-type': 'application/json' },
        status: 202,
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await requestChallenge(
      request('/bff/auth/challenge', {
        body: JSON.stringify({ email: 'member@example.invalid' }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ status: 'accepted' });
    expect(response.headers.get('set-cookie')).toContain('HttpOnly');
    expect(upstream).toHaveBeenCalledWith(
      'http://auth:3002/session/challenges',
      expect.objectContaining({ body: JSON.stringify({ email: 'member@example.invalid' }) }),
    );
  });

  it('marks the BFF challenge cookie Secure behind a trusted HTTPS edge', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ challengeId, status: 'accepted' }), {
          headers: { 'content-type': 'application/json' },
          status: 202,
        }),
      ),
    );

    const response = await requestChallenge(
      request('/bff/auth/challenge', {
        body: JSON.stringify({ email: 'member@example.invalid' }),
        headers: {
          'content-type': 'application/json',
          'x-forwarded-proto': 'https',
        },
        method: 'POST',
      }),
    );

    expect(response.headers.get('set-cookie')).toContain('Secure');
  });

  it('verifies the six digits server-side and forwards only the A2 session cookie', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ sessionId, userId }), {
          headers: {
            'content-type': 'application/json',
            'set-cookie': 'kovcheg_session=synthetic-session; Path=/; HttpOnly; SameSite=Lax',
          },
          status: 200,
        }),
      ),
    );

    const response = await verifyChallenge(
      request('/bff/auth/challenge/verify', {
        body: JSON.stringify({ code: '123456' }),
        headers: {
          cookie: `kovcheg_login_challenge=${challengeId}`,
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ authenticated: true });
    expect(response.headers.get('set-cookie')).toContain('kovcheg_session=synthetic-session');
    expect(response.headers.get('set-cookie')).toContain('HttpOnly');
  });

  it('logs out only through A2 current-session DELETE and clears its cookie', async () => {
    const upstream = vi.fn().mockResolvedValue(
      new Response(null, {
        headers: {
          'set-cookie': 'kovcheg_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
        },
        status: 204,
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await logout(
      request('/bff/session', {
        headers: { cookie: 'kovcheg_session=synthetic-session' },
        method: 'DELETE',
      }),
    );

    expect(response.status).toBe(204);
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(upstream).toHaveBeenCalledWith(
      'http://auth:3002/session',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

describe('A6 administrative BFF gate', () => {
  it('does not call the administrative API without confirmed administrator role', async () => {
    const upstream = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(principal(false)), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await createAccount(
      request('/bff/admin/accounts', {
        body: JSON.stringify({
          displayName: 'Synthetic Member',
          email: 'member@example.invalid',
        }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
      { params: Promise.resolve({}) },
    );

    expect(response.status).toBe(403);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('forwards only the existing A2 create-account operation for an administrator', async () => {
    const upstream = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(principal(true)), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            accountAccess: 'member',
            displayName: 'Synthetic Member',
            domainStatus: 'incubator_participant',
            email: 'member@example.invalid',
            functionalGrants: [],
            status: 'active',
            userId: '00000000-0000-4000-8000-000000000604',
          }),
          { headers: { 'content-type': 'application/json' }, status: 201 },
        ),
      );
    vi.stubGlobal('fetch', upstream);

    const body = JSON.stringify({
      displayName: 'Synthetic Member',
      email: 'member@example.invalid',
    });
    const response = await createAccount(
      request('/bff/admin/accounts', {
        body,
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
      { params: Promise.resolve({}) },
    );

    expect(response.status).toBe(201);
    expect(upstream).toHaveBeenNthCalledWith(
      2,
      'http://auth:3002/admin/accounts',
      expect.objectContaining({ body, method: 'POST' }),
    );
    expect(body).not.toContain('role');
    expect(body).not.toContain('group');
  });
});

describe('A6 chat-list BFF contract', () => {
  it('authenticates first and forwards the current capability-bearing chat list', async () => {
    const chatList = {
      contractVersion: 2,
      items: [
        {
          capabilities: { canRead: true, canWrite: false },
          id: '00000000-0000-4000-8000-000000000605',
          kind: 'group',
        },
      ],
    };
    const upstream = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(principal(false)), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(chatList), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      );
    vi.stubGlobal('fetch', upstream);

    const response = await readChats(request('/bff/chats'));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(chatList);
    expect(upstream).toHaveBeenNthCalledWith(
      2,
      'http://edge:8080/api/chats',
      expect.objectContaining({ method: 'GET' }),
    );
  });
});
