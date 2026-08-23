import type { CorrelationId } from '@kovcheg/contracts';
import { describe, expect, it, vi } from 'vitest';

import type { ApplicationSessionError } from './application-session.js';
import { createApplicationSessionAuthenticator } from './application-session.js';

const correlationId = 'session-boundary-test' as CorrelationId;
const sessionToken = 'a'.repeat(43);
const activePrincipal = Object.freeze({
  roles: ['student'],
  sessionId: '00000000-0000-4000-8000-000000006101',
  userId: '00000000-0000-4000-8000-000000006001',
});

describe('application session boundary', () => {
  it('forwards only the host-only A2 cookie and accepts a server-issued principal', async () => {
    const fetchImplementation = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(activePrincipal), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      }),
    );
    const authenticator = createApplicationSessionAuthenticator(
      'production',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      fetchImplementation,
    );

    await expect(
      authenticator.authenticate(
        `unrelated=value; __Host-kovcheg_session=${sessionToken}; another=value`,
        correlationId,
      ),
    ).resolves.toEqual({
      sessionId: activePrincipal.sessionId,
      userId: activePrincipal.userId,
    });
    expect(fetchImplementation).toHaveBeenCalledWith(
      new URL('http://auth:3002/session'),
      expect.objectContaining({
        headers: {
          cookie: `__Host-kovcheg_session=${sessionToken}`,
          'x-correlation-id': correlationId,
        },
        method: 'GET',
        redirect: 'error',
      }),
    );
  });

  it.each([
    ['unknown', 401],
    ['expired', 401],
    ['revoked', 401],
    ['deactivated', 403],
  ])('rejects a server-declined %s session', async (_label, status) => {
    const authenticator = createApplicationSessionAuthenticator(
      'test',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      vi.fn().mockResolvedValue(new Response(null, { status })),
    );
    await expect(
      authenticator.authenticate(`kovcheg_session=${sessionToken}`, correlationId),
    ).rejects.toMatchObject({
      failure: 'unauthenticated',
    } satisfies Partial<ApplicationSessionError>);
  });

  it('does not accept browser identity headers or production cookies with a non-host prefix', async () => {
    const fetchImplementation = vi.fn();
    const authenticator = createApplicationSessionAuthenticator(
      'production',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      fetchImplementation,
    );
    await expect(authenticator.authenticate(undefined, correlationId)).rejects.toMatchObject({
      failure: 'unauthenticated',
    });
    await expect(
      authenticator.authenticate(`kovcheg_session=${sessionToken}`, correlationId),
    ).rejects.toMatchObject({ failure: 'unauthenticated' });
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it.each([
    undefined,
    'https://auth:3002/internal/session?token=unsafe',
    'https://user:password@auth:3002/internal/session',
    'https://example.invalid/internal/session',
    'http://auth:3002/not-session',
  ])('fails startup closed for an unavailable or unsafe production validation URL', (url) => {
    expect(() =>
      createApplicationSessionAuthenticator('production', {
        AUTH_SESSION_VALIDATION_URL: url,
      }),
    ).toThrow('Application session validation configuration is unavailable');
  });

  it('uses non-touch validation for background delivery and includes auth readiness', async () => {
    const fetchImplementation = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(activePrincipal), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ service: 'auth', state: 'ready', status: 'ok' }), {
          headers: { 'content-type': 'application/json' },
          status: 200,
        }),
      );
    const authenticator = createApplicationSessionAuthenticator(
      'production',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      fetchImplementation,
    );

    await expect(
      authenticator.validate(`__Host-kovcheg_session=${sessionToken}`, correlationId),
    ).resolves.toEqual({
      sessionId: activePrincipal.sessionId,
      userId: activePrincipal.userId,
    });
    await expect(authenticator.isReady()).resolves.toBe(true);
    expect(fetchImplementation.mock.calls.map(([url]) => String(url))).toEqual([
      'http://auth:3002/internal/session',
      'http://auth:3002/health/ready',
    ]);
  });

  it('accepts a slow readiness response within the two-second budget and fails closed', async () => {
    const slowFetch = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1_100));
      return new Response(JSON.stringify({ service: 'auth', state: 'ready', status: 'ok' }), {
        headers: { 'content-type': 'application/json' },
        status: 200,
      });
    });
    const slowAuthenticator = createApplicationSessionAuthenticator(
      'production',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      slowFetch,
    );
    await expect(slowAuthenticator.isReady()).resolves.toBe(true);

    const failedAuthenticator = createApplicationSessionAuthenticator(
      'production',
      { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
      vi.fn().mockRejectedValue(new Error('synthetic upstream failure')),
    );
    await expect(failedAuthenticator.isReady()).resolves.toBe(false);
  });

  it('sanitizes upstream failures and malformed principals as unavailable', async () => {
    for (const response of [
      new Response(null, { status: 503 }),
      new Response(JSON.stringify({ userId: activePrincipal.userId }), { status: 200 }),
    ]) {
      const authenticator = createApplicationSessionAuthenticator(
        'test',
        { AUTH_SESSION_VALIDATION_URL: 'http://auth:3002/internal/session' },
        vi.fn().mockResolvedValue(response),
      );
      await expect(
        authenticator.authenticate(`kovcheg_session=${sessionToken}`, correlationId),
      ).rejects.toMatchObject({ failure: 'unavailable' });
    }
  });
});
