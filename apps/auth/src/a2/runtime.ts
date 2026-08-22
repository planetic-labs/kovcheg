import type Provider from 'oidc-provider';

import { AuthService } from './auth-service.js';
import { AuthError } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource, systemClock } from './crypto.js';
import { LocalAuthRepository, LocalEmailChallengeDelivery } from './local-adapters.js';
import {
  ConfiguredOidcClientRepository,
  createOidcProvider,
  StaticOidcClientRepository,
} from './oidc.js';
import type { OidcClientRepository, OidcStorageAdapter } from './oidc.js';
import type { AuthRandomSource, AuthRepository, Clock, EmailChallengeDelivery } from './ports.js';
import { RedisRateLimiter } from './redis-rate-limiter.js';
import type { RedisScriptClientFactory } from './redis-rate-limiter.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import { SessionCookie } from './session-cookie.js';

export interface AuthRuntime {
  readonly authService: AuthService;
  readonly clock: Clock;
  close(): Promise<void>;
  readonly oidcProvider: Provider;
  readonly sessionCookie: SessionCookie;
}

export const authRuntimeToken = Symbol('auth-runtime');

export interface CreateAuthRuntimeInput {
  readonly clientRepository?: OidcClientRepository;
  readonly config: EnabledAuthRuntimeConfig;
  readonly delivery: EmailChallengeDelivery;
  readonly oidcStorageAdapter?: OidcStorageAdapter;
  readonly random?: AuthRandomSource;
  readonly redisClientFactory: RedisScriptClientFactory;
  readonly repository: AuthRepository;
  readonly clock?: Clock;
}

export async function createAuthRuntime(input: CreateAuthRuntimeInput): Promise<AuthRuntime> {
  const clientRepository =
    input.clientRepository ?? new ConfiguredOidcClientRepository(input.config.oidc.clients);
  if (
    input.config.environment === 'production' &&
    (input.repository instanceof LocalAuthRepository ||
      input.delivery instanceof LocalEmailChallengeDelivery ||
      clientRepository instanceof StaticOidcClientRepository)
  ) {
    throw new AuthError('auth.unavailable', 'Test auth adapters are unavailable in production');
  }

  const redisClient = await input.redisClientFactory.connect(input.config.redisUrl);
  const clock = input.clock ?? systemClock;
  const authService = new AuthService({
    clock,
    crypto: new HmacAuthCrypto(input.config.authSecrets),
    delivery: input.delivery,
    policy: input.config.policy,
    random: input.random ?? new SystemAuthRandomSource(),
    rateLimiter: new RedisRateLimiter(redisClient),
    repository: input.repository,
  });
  const sessionCookie = new SessionCookie({
    absoluteLifetimeMs: input.config.policy.session.absoluteLifetimeMs,
    environment: input.config.environment,
    secure: input.config.secureCookies,
  });
  let oidcProvider: Provider;
  try {
    oidcProvider = await createOidcProvider({
      accountRepository: input.repository,
      clientRepository,
      cookieKeys: input.config.oidc.cookieKeys,
      environment: input.config.environment,
      issuer: input.config.oidc.issuer,
      jwks: input.config.oidc.jwks,
      oidcSessionTtlSeconds: input.config.oidc.sessionTtlSeconds,
      secureCookies: input.config.secureCookies,
      ...(input.oidcStorageAdapter === undefined
        ? {}
        : { storageAdapter: input.oidcStorageAdapter }),
    });
  } catch (error) {
    await redisClient.close?.();
    throw error;
  }

  return Object.freeze({
    authService,
    clock,
    close: async () => {
      await redisClient.close?.();
    },
    oidcProvider,
    sessionCookie,
  });
}
