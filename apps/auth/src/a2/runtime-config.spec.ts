import { describe, expect, it } from 'vitest';

import { loadAuthRuntimeConfig } from './runtime-config.js';

function enabledSource() {
  return {
    AUTH_ADMIN_BOOTSTRAP_JSON: JSON.stringify({
      bootstrapId: 'synthetic-bootstrap-config-0001',
      displayName: 'Synthetic Bootstrap Administrator',
      email: 'synthetic-bootstrap@auth.invalid',
      userId: '00000000-0000-4000-8000-000000000071',
    }),
    AUTH_CHALLENGE_PEPPER: 'c'.repeat(64),
    AUTH_PERSONAL_GATE_PEPPER: 'g'.repeat(64),
    AUTH_OIDC_CLIENTS_JSON: JSON.stringify([
      {
        clientId: 'synthetic-client',
        redirectUris: ['http://127.0.0.1/callback'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'none',
      },
    ]),
    AUTH_OIDC_COOKIE_KEYS_JSON: JSON.stringify(['k'.repeat(64), 'l'.repeat(64)]),
    AUTH_OIDC_ISSUER: 'http://127.0.0.1:4300',
    AUTH_OIDC_JWKS_JSON: JSON.stringify({
      keys: [{ alg: 'ES256', crv: 'P-256', d: 'synthetic', kty: 'EC', x: 'x', y: 'y' }],
    }),
    AUTH_RATE_LIMIT_PEPPER: 'r'.repeat(64),
    AUTH_REDIS_URL: 'redis://127.0.0.1:6379',
    AUTH_RUNTIME_ENABLED: 'true',
    AUTH_SESSION_PEPPER: 's'.repeat(64),
  } as const;
}

describe('A2 runtime configuration', () => {
  it('keeps auth behavior disabled by default without reading secret inputs', () => {
    expect(loadAuthRuntimeConfig('production', {})).toEqual({ enabled: false });
  });

  it('wires explicit clients, JWKS, Redis, cookie keys, and auth peppers without defaults', () => {
    const config = loadAuthRuntimeConfig('test', enabledSource());
    expect(config).toMatchObject({
      enabled: true,
      environment: 'test',
      bootstrapAdministrator: {
        email: 'synthetic-bootstrap@auth.invalid',
        userId: '00000000-0000-4000-8000-000000000071',
      },
      oidc: {
        clients: [{ clientId: 'synthetic-client', tokenEndpointAuthMethod: 'none' }],
        issuer: 'http://127.0.0.1:4300',
        sessionTtlSeconds: 12 * 60 * 60,
      },
      policy: {
        session: {
          absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
          idleLifetimeMs: 7 * 24 * 60 * 60_000,
        },
      },
      redisUrl: 'redis://127.0.0.1:6379',
      secureCookies: false,
    });
  });

  it('fails closed when enabled configuration is incomplete or Redis is not Redis', () => {
    expect(() => loadAuthRuntimeConfig('production', { AUTH_RUNTIME_ENABLED: 'true' })).toThrow(
      'AUTH_OIDC_CLIENTS_JSON is required',
    );
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_REDIS_URL: 'https://example.invalid',
      }),
    ).toThrow('AUTH_REDIS_URL must use redis or rediss');
  });

  it('loads secret material from container secret files without inline duplication', () => {
    const directory = mkdtempSync(join(tmpdir(), 'kovcheg-auth-config-'));
    try {
      const paths = {
        challenge: join(directory, 'challenge'),
        cookies: join(directory, 'cookies'),
        jwks: join(directory, 'jwks'),
        gate: join(directory, 'gate'),
        rate: join(directory, 'rate'),
        session: join(directory, 'session'),
      };
      writeFileSync(paths.challenge, 'c'.repeat(64));
      writeFileSync(paths.gate, 'g'.repeat(64));
      writeFileSync(paths.cookies, JSON.stringify(['k'.repeat(64), 'l'.repeat(64)]));
      writeFileSync(
        paths.jwks,
        JSON.stringify({
          keys: [{ alg: 'ES256', crv: 'P-256', d: 'synthetic', kty: 'EC', x: 'x', y: 'y' }],
        }),
      );
      writeFileSync(paths.rate, 'r'.repeat(64));
      writeFileSync(paths.session, 's'.repeat(64));

      const config = loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_CHALLENGE_PEPPER: undefined,
        AUTH_CHALLENGE_PEPPER_FILE: paths.challenge,
        AUTH_OIDC_COOKIE_KEYS_JSON: undefined,
        AUTH_OIDC_COOKIE_KEYS_JSON_FILE: paths.cookies,
        AUTH_OIDC_JWKS_JSON: undefined,
        AUTH_OIDC_JWKS_JSON_FILE: paths.jwks,
        AUTH_PERSONAL_GATE_PEPPER: undefined,
        AUTH_PERSONAL_GATE_PEPPER_FILE: paths.gate,
        AUTH_RATE_LIMIT_PEPPER: undefined,
        AUTH_RATE_LIMIT_PEPPER_FILE: paths.rate,
        AUTH_SESSION_PEPPER: undefined,
        AUTH_SESSION_PEPPER_FILE: paths.session,
      });
      expect(config).toMatchObject({
        authSecrets: {
          challengePepper: 'c'.repeat(64),
          personalGatePepper: 'g'.repeat(64),
          rateLimitPepper: 'r'.repeat(64),
          sessionPepper: 's'.repeat(64),
        },
        enabled: true,
      });
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });
});
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
