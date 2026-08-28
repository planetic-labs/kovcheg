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
    AUTH_OIDC_CLIENTS_JSON: JSON.stringify([
      {
        clientId: 'synthetic-client',
        redirectUris: ['http://127.0.0.1/callback'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'none',
      },
    ]),
    AUTH_OIDC_APPLICATION_CLIENT_ID: 'synthetic-client',
    AUTH_OIDC_APPLICATION_REDIRECT_URI: 'http://127.0.0.1/callback',
    AUTH_OIDC_COOKIE_KEYS_JSON: JSON.stringify(['k'.repeat(64), 'l'.repeat(64)]),
    AUTH_OIDC_ISSUER: 'http://127.0.0.1:4300',
    AUTH_OIDC_JWKS_JSON: JSON.stringify({
      keys: [{ alg: 'ES256', crv: 'P-256', d: 'synthetic', kty: 'EC', x: 'x', y: 'y' }],
    }),
    AUTH_RATE_LIMIT_PEPPER: 'r'.repeat(64),
    AUTH_REDIS_URL: 'redis://127.0.0.1:6379',
    AUTH_RUNTIME_ENABLED: 'true',
    AUTH_SESSION_PEPPER: 's'.repeat(64),
    AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://auth-config.invalid']),
    AUTH_WEBAUTHN_RP_ID: 'auth-config.invalid',
    AUTH_WEBAUTHN_RP_NAME: 'Synthetic Auth',
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
        applicationClientId: 'synthetic-client',
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
      webauthn: {
        origins: ['https://auth-config.invalid'],
        rpId: 'auth-config.invalid',
        rpName: 'Synthetic Auth',
      },
    });
  });

  it('fails closed when enabled configuration is incomplete or Redis is not Redis', () => {
    expect(() => loadAuthRuntimeConfig('production', { AUTH_RUNTIME_ENABLED: 'true' })).toThrow(
      'AUTH_OIDC_CLIENTS_JSON or AUTH_OIDC_CLIENTS_JSON_FILE is required',
    );
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_REDIS_URL: 'https://example.invalid',
      }),
    ).toThrow('AUTH_REDIS_URL must use redis or rediss');
  });

  it('binds the application bridge to one exact public openid client and redirect', () => {
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_OIDC_APPLICATION_CLIENT_ID: 'other-client',
      }),
    ).toThrow('The application OIDC client must be one exact public openid client');
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_OIDC_APPLICATION_REDIRECT_URI: 'http://127.0.0.1/other',
      }),
    ).toThrow('The application OIDC client must be one exact public openid client');
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_OIDC_CLIENTS_JSON: JSON.stringify([
          {
            clientId: 'synthetic-client',
            clientSecret: 's'.repeat(32),
            redirectUris: ['http://127.0.0.1/callback'],
            scopes: ['openid'],
            tokenEndpointAuthMethod: 'client_secret_basic',
          },
        ]),
      }),
    ).toThrow('The application OIDC client must be one exact public openid client');
  });

  it('allows only the exact production RP and bounded synthetic test origins', () => {
    expect(() =>
      loadAuthRuntimeConfig('production', {
        ...enabledSource(),
        AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://auth-config.invalid']),
        AUTH_WEBAUTHN_RP_ID: 'auth-config.invalid',
      }),
    ).toThrow('Production WebAuthn RP ID is not permitted');
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://auth-config.invalid/not-an-origin']),
      }),
    ).toThrow('WebAuthn origin is not permitted');
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://unrelated.invalid']),
      }),
    ).toThrow('WebAuthn origin is not permitted');
  });

  it('loads secret material from container secret files without inline duplication', () => {
    const directory = mkdtempSync(join(tmpdir(), 'kovcheg-auth-config-'));
    try {
      const paths = {
        bootstrap: join(directory, 'bootstrap'),
        challenge: join(directory, 'challenge'),
        clients: join(directory, 'clients'),
        cookies: join(directory, 'cookies'),
        jwks: join(directory, 'jwks'),
        rate: join(directory, 'rate'),
        session: join(directory, 'session'),
      };
      writeFileSync(paths.bootstrap, enabledSource().AUTH_ADMIN_BOOTSTRAP_JSON);
      writeFileSync(paths.clients, enabledSource().AUTH_OIDC_CLIENTS_JSON);
      writeFileSync(paths.challenge, 'c'.repeat(64));
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
        AUTH_ADMIN_BOOTSTRAP_JSON: undefined,
        AUTH_ADMIN_BOOTSTRAP_JSON_FILE: paths.bootstrap,
        AUTH_CHALLENGE_PEPPER: undefined,
        AUTH_CHALLENGE_PEPPER_FILE: paths.challenge,
        AUTH_OIDC_COOKIE_KEYS_JSON: undefined,
        AUTH_OIDC_COOKIE_KEYS_JSON_FILE: paths.cookies,
        AUTH_OIDC_JWKS_JSON: undefined,
        AUTH_OIDC_JWKS_JSON_FILE: paths.jwks,
        AUTH_OIDC_CLIENTS_JSON: undefined,
        AUTH_OIDC_CLIENTS_JSON_FILE: paths.clients,
        AUTH_RATE_LIMIT_PEPPER: undefined,
        AUTH_RATE_LIMIT_PEPPER_FILE: paths.rate,
        AUTH_SESSION_PEPPER: undefined,
        AUTH_SESSION_PEPPER_FILE: paths.session,
      });
      expect(config).toMatchObject({
        authSecrets: {
          challengePepper: 'c'.repeat(64),
          rateLimitPepper: 'r'.repeat(64),
          sessionPepper: 's'.repeat(64),
        },
        enabled: true,
        bootstrapAdministrator: {
          email: 'synthetic-bootstrap@auth.invalid',
        },
        oidc: {
          clients: [{ clientId: 'synthetic-client' }],
        },
      });
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it('requires exact file-or-inline exclusivity for structured deployment inputs', () => {
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_OIDC_CLIENTS_JSON_FILE: '/synthetic/not-read',
      }),
    ).toThrow('AUTH_OIDC_CLIENTS_JSON and AUTH_OIDC_CLIENTS_JSON_FILE are mutually exclusive');
    expect(() =>
      loadAuthRuntimeConfig('test', {
        ...enabledSource(),
        AUTH_ADMIN_BOOTSTRAP_JSON_FILE: '/synthetic/not-read',
      }),
    ).toThrow(
      'AUTH_ADMIN_BOOTSTRAP_JSON and AUTH_ADMIN_BOOTSTRAP_JSON_FILE are mutually exclusive',
    );
  });

  it('binds a production RP to the explicit deployment allowlist', () => {
    expect(() =>
      loadAuthRuntimeConfig('production', {
        ...enabledSource(),
        AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://auth-config.invalid']),
        AUTH_WEBAUTHN_PRODUCTION_RP_ID: 'different.invalid',
      }),
    ).toThrow('Production WebAuthn RP ID is not permitted');
    expect(
      loadAuthRuntimeConfig('production', {
        ...enabledSource(),
        AUTH_WEBAUTHN_ORIGINS_JSON: JSON.stringify(['https://auth-config.invalid']),
        AUTH_WEBAUTHN_PRODUCTION_RP_ID: 'auth-config.invalid',
      }),
    ).toMatchObject({ enabled: true, webauthn: { rpId: 'auth-config.invalid' } });
  });
});
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
