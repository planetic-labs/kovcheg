import type { JWKS } from 'oidc-provider';
import type { UserId } from '@kovcheg/contracts';

import { AuthError, emailChallengePolicy } from './contracts.js';
import type { AuthPolicy, BootstrapAdministratorInput } from './contracts.js';
import type { AuthSecretMaterial } from './crypto.js';
import type { RegisteredOidcClient } from './oidc.js';

export type AuthRuntimeEnvironment = 'development' | 'production' | 'test';

export interface DisabledAuthRuntimeConfig {
  readonly enabled: false;
}

export interface EnabledAuthRuntimeConfig {
  readonly authSecrets: AuthSecretMaterial;
  readonly bootstrapAdministrator?: BootstrapAdministratorInput | undefined;
  readonly enabled: true;
  readonly environment: AuthRuntimeEnvironment;
  readonly oidc: {
    readonly clients: readonly RegisteredOidcClient[];
    readonly cookieKeys: readonly string[];
    readonly issuer: string;
    readonly jwks: JWKS;
    readonly sessionTtlSeconds: number;
  };
  readonly policy: AuthPolicy;
  readonly redisUrl: string;
  readonly secureCookies: boolean;
}

export type AuthRuntimeConfig = DisabledAuthRuntimeConfig | EnabledAuthRuntimeConfig;

export interface AuthRuntimeEnvironmentSource {
  readonly AUTH_ADMIN_BOOTSTRAP_JSON?: string | undefined;
  readonly AUTH_CHALLENGE_PEPPER?: string | undefined;
  readonly AUTH_OIDC_CLIENTS_JSON?: string | undefined;
  readonly AUTH_OIDC_COOKIE_KEYS_JSON?: string | undefined;
  readonly AUTH_OIDC_ISSUER?: string | undefined;
  readonly AUTH_OIDC_JWKS_JSON?: string | undefined;
  readonly AUTH_RATE_LIMIT_PEPPER?: string | undefined;
  readonly AUTH_REDIS_URL?: string | undefined;
  readonly AUTH_RUNTIME_ENABLED?: string | undefined;
  readonly AUTH_SESSION_PEPPER?: string | undefined;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const defaultPolicy: AuthPolicy = Object.freeze({
  challenge: emailChallengePolicy,
  rateLimits: Object.freeze({
    challengeByEmail: Object.freeze({ limit: 5, windowMs: 15 * 60_000 }),
    challengeByFingerprint: Object.freeze({ limit: 10, windowMs: 15 * 60_000 }),
    challengeByNetwork: Object.freeze({ limit: 30, windowMs: 15 * 60_000 }),
    verifyByChallenge: Object.freeze({ limit: 8, windowMs: 15 * 60_000 }),
    verifyByNetwork: Object.freeze({ limit: 40, windowMs: 15 * 60_000 }),
  }),
  session: Object.freeze({
    absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
    idleLifetimeMs: 7 * 24 * 60 * 60_000,
  }),
});

function required(source: AuthRuntimeEnvironmentSource, key: keyof AuthRuntimeEnvironmentSource) {
  const value = source[key]?.trim();
  if (value === undefined || value.length === 0) {
    throw new AuthError('auth.unavailable', `${key} is required when auth runtime is enabled`);
  }
  return value;
}

function parseJson(value: string, name: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new AuthError('auth.invalid-input', `${name} must be valid JSON`);
  }
}

function stringArray(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new AuthError('auth.invalid-input', `${name} must be an array of strings`);
  }
  return Object.freeze([...value]);
}

function parseClients(value: unknown): readonly RegisteredOidcClient[] {
  if (!Array.isArray(value)) {
    throw new AuthError('auth.invalid-input', 'AUTH_OIDC_CLIENTS_JSON must be an array');
  }
  return Object.freeze(
    value.map((item): RegisteredOidcClient => {
      if (item === null || typeof item !== 'object') {
        throw new AuthError('auth.invalid-input', 'OIDC client entries must be objects');
      }
      const candidate = item as Record<string, unknown>;
      if (typeof candidate.clientId !== 'string') {
        throw new AuthError('auth.invalid-input', 'OIDC clientId must be a string');
      }
      const redirectUris = stringArray(candidate.redirectUris, 'OIDC redirectUris');
      const scopes = stringArray(candidate.scopes, 'OIDC scopes');
      if (candidate.tokenEndpointAuthMethod === 'none') {
        return Object.freeze({
          clientId: candidate.clientId,
          redirectUris,
          scopes,
          tokenEndpointAuthMethod: 'none',
        });
      }
      if (
        candidate.tokenEndpointAuthMethod === 'client_secret_basic' &&
        typeof candidate.clientSecret === 'string'
      ) {
        return Object.freeze({
          clientId: candidate.clientId,
          clientSecret: candidate.clientSecret,
          redirectUris,
          scopes,
          tokenEndpointAuthMethod: 'client_secret_basic',
        });
      }
      throw new AuthError('auth.invalid-input', 'OIDC client authentication method is invalid');
    }),
  );
}

function parseJwks(value: unknown): JWKS {
  if (value === null || typeof value !== 'object') {
    throw new AuthError('auth.invalid-input', 'AUTH_OIDC_JWKS_JSON must be an object');
  }
  const keys = (value as Record<string, unknown>).keys;
  if (!Array.isArray(keys) || keys.some((key) => key === null || typeof key !== 'object')) {
    throw new AuthError('auth.invalid-input', 'AUTH_OIDC_JWKS_JSON must contain a keys array');
  }
  return { keys: keys as JWKS['keys'] };
}

function parseBootstrap(value: string | undefined): BootstrapAdministratorInput | undefined {
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }
  const parsed = parseJson(value, 'AUTH_ADMIN_BOOTSTRAP_JSON');
  if (parsed === null || typeof parsed !== 'object') {
    throw new AuthError('auth.invalid-input', 'AUTH_ADMIN_BOOTSTRAP_JSON must be an object');
  }
  const candidate = parsed as Record<string, unknown>;
  if (
    typeof candidate.bootstrapId !== 'string' ||
    typeof candidate.displayName !== 'string' ||
    typeof candidate.email !== 'string' ||
    typeof candidate.userId !== 'string' ||
    !uuidPattern.test(candidate.userId)
  ) {
    throw new AuthError('auth.invalid-input', 'AUTH_ADMIN_BOOTSTRAP_JSON is invalid');
  }
  return Object.freeze({
    bootstrapId: candidate.bootstrapId,
    displayName: candidate.displayName,
    email: candidate.email,
    userId: candidate.userId as UserId,
  });
}

function validateRedisUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthError('auth.invalid-input', 'AUTH_REDIS_URL must be absolute');
  }
  if (
    !['redis:', 'rediss:'].includes(parsed.protocol) ||
    parsed.hash !== '' ||
    parsed.search !== ''
  ) {
    throw new AuthError('auth.invalid-input', 'AUTH_REDIS_URL must use redis or rediss');
  }
  return value;
}

export function loadAuthRuntimeConfig(
  environment: AuthRuntimeEnvironment,
  source: AuthRuntimeEnvironmentSource = process.env,
): AuthRuntimeConfig {
  if (source.AUTH_RUNTIME_ENABLED !== 'true') {
    return Object.freeze({ enabled: false });
  }
  const clients = parseClients(
    parseJson(required(source, 'AUTH_OIDC_CLIENTS_JSON'), 'AUTH_OIDC_CLIENTS_JSON'),
  );
  const cookieKeys = stringArray(
    parseJson(required(source, 'AUTH_OIDC_COOKIE_KEYS_JSON'), 'AUTH_OIDC_COOKIE_KEYS_JSON'),
    'AUTH_OIDC_COOKIE_KEYS_JSON',
  );
  const jwks = parseJwks(parseJson(required(source, 'AUTH_OIDC_JWKS_JSON'), 'AUTH_OIDC_JWKS_JSON'));
  return Object.freeze({
    authSecrets: Object.freeze({
      challengePepper: required(source, 'AUTH_CHALLENGE_PEPPER'),
      rateLimitPepper: required(source, 'AUTH_RATE_LIMIT_PEPPER'),
      sessionPepper: required(source, 'AUTH_SESSION_PEPPER'),
    }),
    bootstrapAdministrator: parseBootstrap(source.AUTH_ADMIN_BOOTSTRAP_JSON),
    enabled: true,
    environment,
    oidc: Object.freeze({
      clients,
      cookieKeys,
      issuer: required(source, 'AUTH_OIDC_ISSUER'),
      jwks,
      sessionTtlSeconds: 12 * 60 * 60,
    }),
    policy: defaultPolicy,
    redisUrl: validateRedisUrl(required(source, 'AUTH_REDIS_URL')),
    secureCookies: environment === 'production',
  });
}
