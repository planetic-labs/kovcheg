import type Provider from 'oidc-provider';

import { AuthService } from './auth-service.js';
import { AuthError } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource, systemClock } from './crypto.js';
import { ConfiguredOidcClientRepository, createOidcProvider } from './oidc.js';
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
  isReady(): Promise<boolean>;
  readonly oidcProvider: Provider;
  readonly sessionCookie: SessionCookie;
}

export const authRuntimeToken = Symbol('auth-runtime');

export interface CreateAuthRuntimeInput {
  readonly clientRepository?: OidcClientRepository;
  readonly closePersistence?: (() => Promise<void>) | undefined;
  readonly config: EnabledAuthRuntimeConfig;
  readonly delivery: EmailChallengeDelivery;
  readonly oidcStorageAdapter?: OidcStorageAdapter;
  readonly oidcStorageAdapterProductionSafe?: true | undefined;
  readonly random?: AuthRandomSource;
  readonly redisClientFactory: RedisScriptClientFactory;
  readonly repository: AuthRepository;
  readonly clock?: Clock;
}

export async function createAuthRuntime(input: CreateAuthRuntimeInput): Promise<AuthRuntime> {
  const clientRepository: OidcClientRepository =
    input.clientRepository ?? new ConfiguredOidcClientRepository(input.config.oidc.clients);
  if (
    input.config.environment === 'production' &&
    (input.clientRepository === undefined ||
      input.repository.productionSafe !== true ||
      input.delivery.productionSafe !== true ||
      clientRepository.productionSafe !== true ||
      input.redisClientFactory.productionSafe !== true ||
      input.oidcStorageAdapterProductionSafe !== true ||
      clientRepository instanceof ConfiguredOidcClientRepository)
  ) {
    throw new AuthError('auth.unavailable', 'Test auth adapters are unavailable in production');
  }

  let redisClient: Awaited<ReturnType<RedisScriptClientFactory['connect']>>;
  try {
    redisClient = await input.redisClientFactory.connect(input.config.redisUrl);
  } catch (error) {
    await input.closePersistence?.();
    throw error;
  }
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
    try {
      await redisClient.close?.();
    } finally {
      await input.closePersistence?.();
    }
    throw error;
  }

  return Object.freeze({
    authService,
    clock,
    close: async () => {
      try {
        await redisClient.close?.();
      } finally {
        await input.closePersistence?.();
      }
    },
    isReady: async () =>
      redisClient.isReady() && (await input.repository.isReady().catch(() => false)),
    oidcProvider,
    sessionCookie,
  });
}
