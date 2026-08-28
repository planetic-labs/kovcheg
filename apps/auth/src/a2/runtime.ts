import type Provider from 'oidc-provider';

import { AuthService } from './auth-service.js';
import { AuthError } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource, systemClock } from './crypto.js';
import { ConfiguredOidcClientRepository, createOidcProvider } from './oidc.js';
import type { OidcClientRepository, OidcStorageAdapter } from './oidc.js';
import type {
  AuthRandomSource,
  AuthRepository,
  Clock,
  EmailChallengeDelivery,
  WebAuthnServer,
} from './ports.js';
import { RedisPasskeyCeremonyStore } from './passkey-ceremony-store.js';
import { PasskeyService } from './passkey-service.js';
import { RedisRateLimiter } from './redis-rate-limiter.js';
import type { RedisScriptClientFactory } from './redis-rate-limiter.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import { SessionCookie } from './session-cookie.js';
import { SimpleWebAuthnServer } from './webauthn-server.js';

export interface AuthRuntime {
  readonly authService: AuthService;
  readonly clock: Clock;
  close(): Promise<void>;
  isReady(): Promise<boolean>;
  readonly oidcProvider: Provider;
  readonly oidcApplicationClientId: string;
  readonly passkeyService: PasskeyService;
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
  readonly webauthn?: WebAuthnServer | undefined;
  readonly webauthnProductionSafe?: true | undefined;
}

export async function createAuthRuntime(input: CreateAuthRuntimeInput): Promise<AuthRuntime> {
  const clientRepository: OidcClientRepository =
    input.clientRepository ?? new ConfiguredOidcClientRepository(input.config.oidc.clients);
  const oidcApplicationClientId =
    input.config.oidc.applicationClientId ??
    (input.config.environment === 'test'
      ? input.config.oidc.clients.find(
          (client) => client.tokenEndpointAuthMethod === 'none' && client.scopes[0] === 'openid',
        )?.clientId
      : undefined);
  if (oidcApplicationClientId === undefined) {
    throw new AuthError('auth.unavailable', 'The application OIDC client is unavailable');
  }
  if (
    input.config.environment === 'production' &&
    (input.clientRepository === undefined ||
      input.repository.productionSafe !== true ||
      input.delivery.productionSafe !== true ||
      clientRepository.productionSafe !== true ||
      input.redisClientFactory.productionSafe !== true ||
      input.oidcStorageAdapterProductionSafe !== true ||
      (input.webauthn !== undefined && input.webauthnProductionSafe !== true) ||
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
  const crypto = new HmacAuthCrypto(input.config.authSecrets);
  const random = input.random ?? new SystemAuthRandomSource();
  const rateLimiter = new RedisRateLimiter(redisClient);
  const authService = new AuthService({
    clock,
    crypto,
    delivery: input.delivery,
    policy: input.config.policy,
    random,
    rateLimiter,
    repository: input.repository,
  });
  const passkeyService = new PasskeyService({
    ceremonyStore: new RedisPasskeyCeremonyStore(redisClient),
    clock,
    configuration: input.config.webauthn,
    crypto,
    policy: input.config.policy,
    random,
    rateLimiter,
    repository: input.repository,
    webauthn: input.webauthn ?? new SimpleWebAuthnServer(),
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
    oidcApplicationClientId,
    passkeyService,
    sessionCookie,
  });
}
