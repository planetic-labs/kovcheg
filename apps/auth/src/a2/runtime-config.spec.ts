import { describe, expect, it } from 'vitest';

import { loadAuthRuntimeConfig } from './runtime-config.js';

function enabledSource() {
  return {
    AUTH_CHALLENGE_PEPPER: 'c'.repeat(64),
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
      oidc: {
        clients: [{ clientId: 'synthetic-client', tokenEndpointAuthMethod: 'none' }],
        issuer: 'http://127.0.0.1:4300',
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
});
