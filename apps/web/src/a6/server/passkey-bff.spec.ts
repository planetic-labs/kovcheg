import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { POST as authenticationOptions } from '../../app/bff/auth/passkeys/authentication/options/route';
import { POST as authenticationVerify } from '../../app/bff/auth/passkeys/authentication/verify/route';
import { POST as registrationOptions } from '../../app/bff/auth/passkeys/registration/options/route';
import { POST as registrationVerify } from '../../app/bff/auth/passkeys/registration/verify/route';

const ceremonyId = '00000000-0000-4000-8000-000000000711';
const sessionId = '00000000-0000-4000-8000-000000000712';
const userId = '00000000-0000-4000-8000-000000000714';

function request(path: string, init?: ConstructorParameters<typeof NextRequest>[1]): NextRequest {
  return new NextRequest(`http://localhost${path}`, init);
}

function jsonResponse(value: unknown, status = 200, headers?: Headers): Response {
  return new Response(JSON.stringify(value), {
    headers: headers ?? { 'content-type': 'application/json' },
    status,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.KOVCHEG_AUTH_INTERNAL_URL;
});

describe('A6 passkey same-origin BFF', () => {
  it('forwards only the application session cookie to authenticated registration', async () => {
    const upstream = vi.fn().mockResolvedValue(
      jsonResponse({
        ceremonyId,
        options: { challenge: 'registration-challenge', rp: { name: 'Synthetic RP' } },
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await registrationOptions(
      request('/bff/auth/passkeys/registration/options', {
        headers: {
          cookie: 'retired_entry=unrelated; kovcheg_session=synthetic-session; unrelated=value',
        },
        method: 'POST',
      }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(upstream).toHaveBeenCalledWith(
      'http://auth:3002/passkeys/registration/options',
      expect.objectContaining({
        headers: expect.objectContaining({
          get: expect.any(Function),
        }),
        method: 'POST',
      }),
    );
    const headers = upstream.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('cookie')).toBe('kovcheg_session=synthetic-session');
    expect(headers.get('cookie')).not.toContain('retired_entry');
  });

  it('starts discoverable authentication without forwarding any browser cookies', async () => {
    const upstream = vi.fn().mockResolvedValue(
      jsonResponse({
        ceremonyId,
        mediation: 'conditional',
        options: { challenge: 'authentication-challenge', userVerification: 'required' },
      }),
    );
    vi.stubGlobal('fetch', upstream);

    const response = await authenticationOptions(
      request('/bff/auth/passkeys/authentication/options', {
        headers: { cookie: 'retired_entry=unrelated; kovcheg_session=synthetic-session' },
        method: 'POST',
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ceremonyId,
      mediation: 'conditional',
      options: { challenge: 'authentication-challenge', userVerification: 'required' },
    });
    const headers = upstream.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.has('cookie')).toBe(false);
  });

  it('copies only the application session cookie after authentication', async () => {
    const headers = new Headers({ 'content-type': 'application/json' });
    headers.append(
      'set-cookie',
      '__Host-kovcheg_session=synthetic-session; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
    headers.append('set-cookie', 'upstream_debug=private; Path=/');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ sessionId, userId }, 200, headers)),
    );

    const response = await authenticationVerify(
      request('/bff/auth/passkeys/authentication/verify', {
        body: JSON.stringify({ ceremonyId, response: { id: 'synthetic-credential' } }),
        headers: {
          cookie: 'retired_entry=unrelated',
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ authenticated: true });
    expect(response.headers.get('set-cookie')).toContain('__Host-kovcheg_session=');
    expect(response.headers.get('set-cookie')).not.toContain('upstream_debug');
  });

  it('keeps registration output minimal and rejects malformed verify bodies before fetch', async () => {
    const upstream = vi.fn().mockResolvedValue(
      jsonResponse({
        passkeyId: '00000000-0000-4000-8000-000000000713',
        status: 'registered',
      }),
    );
    vi.stubGlobal('fetch', upstream);
    const registered = await registrationVerify(
      request('/bff/auth/passkeys/registration/verify', {
        body: JSON.stringify({ ceremonyId, response: { id: 'synthetic-credential' } }),
        headers: {
          cookie: 'kovcheg_session=synthetic-session',
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
    );
    expect(registered.status).toBe(201);
    expect(await registered.json()).toEqual({ registered: true });

    upstream.mockClear();
    const malformed = await authenticationVerify(
      request('/bff/auth/passkeys/authentication/verify', {
        body: JSON.stringify({ ceremonyId, response: {}, unexpected: 'value' }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
    );
    expect(malformed.status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('fails closed when authentication does not provide exactly one session cookie', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ sessionId, userId })));
    const response = await authenticationVerify(
      request('/bff/auth/passkeys/authentication/verify', {
        body: JSON.stringify({ ceremonyId, response: { id: 'synthetic-credential' } }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      }),
    );
    expect(response.status).toBe(503);
    expect(response.headers.has('set-cookie')).toBe(false);
  });
});
