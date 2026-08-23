import { AuthError } from './contracts.js';
import {
  createAuthPostgresPool,
  createPostgresOidcStorageAdapter,
  PostgresAuthRepository,
  PostgresOidcClientRepository,
} from './postgres.js';
import { nodeRedisScriptClientFactory } from './redis-client.js';
import { createAuthRuntime } from './runtime.js';
import type { AuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import type { AuthPostgresEnvironment } from './postgres.js';
import type { EmailChallengeDelivery } from './ports.js';

export interface AuthDeliveryEnvironmentSource {
  readonly AUTH_EMAIL_DELIVERY_ADAPTER?: string | undefined;
}

export async function loadEmailChallengeDelivery(
  environment: EnabledAuthRuntimeConfig['environment'],
  source: AuthDeliveryEnvironmentSource = process.env,
): Promise<EmailChallengeDelivery> {
  if (environment !== 'production' && source.AUTH_EMAIL_DELIVERY_ADAPTER === 'local') {
    const { LocalEmailChallengeDelivery } = await import('./local-adapters.js');
    return new LocalEmailChallengeDelivery({ NODE_ENV: environment });
  }
  throw new AuthError(
    'auth.unavailable',
    'A provider-neutral email challenge delivery adapter is required',
  );
}

export async function createDurableAuthRuntime(input: {
  readonly config: EnabledAuthRuntimeConfig;
  readonly delivery: EmailChallengeDelivery;
  readonly postgresEnvironment?: AuthPostgresEnvironment | undefined;
}): Promise<AuthRuntime> {
  const pool = createAuthPostgresPool(input.postgresEnvironment);
  const repository = new PostgresAuthRepository(pool);
  const runtime = await createAuthRuntime({
    clientRepository: new PostgresOidcClientRepository(pool, input.config.oidc.clients),
    closePersistence: async () => pool.end(),
    config: input.config,
    delivery: input.delivery,
    oidcStorageAdapter: createPostgresOidcStorageAdapter(pool),
    oidcStorageAdapterProductionSafe: true,
    redisClientFactory: nodeRedisScriptClientFactory,
    repository,
  });
  try {
    if (input.config.bootstrapAdministrator !== undefined) {
      await runtime.authService.bootstrapAdministrator(input.config.bootstrapAdministrator);
    }
    return runtime;
  } catch (error) {
    await runtime.close();
    throw error;
  }
}
