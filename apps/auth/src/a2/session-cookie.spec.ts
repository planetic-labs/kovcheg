import { describe, expect, it } from 'vitest';

import { SessionCookie } from './session-cookie.js';

describe('A2 session cookie lifecycle', () => {
  it('uses a host-only secure cookie in production and clears it deterministically', () => {
    const cookie = new SessionCookie({
      absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
      environment: 'production',
      secure: true,
    });
    const token = 'a'.repeat(43);
    const issued = cookie.issue(token);

    expect(cookie.name).toBe('__Host-kovcheg_session');
    expect(issued).toContain('__Host-kovcheg_session=');
    expect(issued).toContain('Path=/');
    expect(issued).toContain('HttpOnly');
    expect(issued).toContain('SameSite=Lax');
    expect(issued).toContain('Secure');
    expect(issued).toContain('Max-Age=2592000');
    expect(issued).not.toContain('Domain=');
    expect(cookie.read(`other=value; __Host-kovcheg_session=${token}`)).toBe(token);
    expect(cookie.clear()).toContain('Max-Age=0');
  });

  it('rejects insecure production cookies and malformed inbound tokens', () => {
    expect(
      () =>
        new SessionCookie({
          absoluteLifetimeMs: 60_000,
          environment: 'production',
          secure: false,
        }),
    ).toThrow('Production session cookies must be secure');

    const cookie = new SessionCookie({
      absoluteLifetimeMs: 60_000,
      environment: 'test',
      secure: false,
    });
    expect(cookie.read('kovcheg_session=short')).toBeNull();
    expect(cookie.read('kovcheg_session=unsafe%20value')).toBeNull();
  });
});
