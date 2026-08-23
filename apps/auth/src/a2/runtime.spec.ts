import { describe, expect, it } from 'vitest';

import { emailChallengePolicy } from './contracts.js';
import { LocalAuthRepository, LocalEmailChallengeDelivery } from './local-adapters.js';
import { createAuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import { loadEmailChallengeDelivery } from './runtime-infrastructure.js';

describe('A2 production runtime boundary', () => {
  it('keeps local email delivery out of production composition', async () => {
    await expect(
      loadEmailChallengeDelivery('production', { AUTH_EMAIL_DELIVERY_ADAPTER: 'local' }),
    ).rejects.toThrow('provider-neutral email challenge delivery adapter is required');
    await expect(
      loadEmailChallengeDelivery('test', { AUTH_EMAIL_DELIVERY_ADAPTER: 'local' }),
    ).resolves.toBeInstanceOf(LocalEmailChallengeDelivery);
  });

  it('rejects test repositories and delivery adapters even if they were constructed explicitly', async () => {
    const rule = Object.freeze({ limit: 10, windowMs: 60_000 });
    const config: EnabledAuthRuntimeConfig = {
      authSecrets: {
        challengePepper: 'c'.repeat(64),
        rateLimitPepper: 'r'.repeat(64),
        sessionPepper: 's'.repeat(64),
      },
      enabled: true,
      environment: 'production',
      oidc: {
        clients: [
          {
            clientId: 'synthetic-production-client',
            redirectUris: ['https://client.invalid/callback'],
            scopes: ['openid'],
            tokenEndpointAuthMethod: 'none',
          },
        ],
        cookieKeys: ['k'.repeat(64), 'l'.repeat(64)],
        issuer: 'https://issuer.invalid',
        jwks: { keys: [] },
        sessionTtlSeconds: 3600,
      },
      policy: {
        challenge: emailChallengePolicy,
        rateLimits: {
          challengeByEmail: rule,
          challengeByFingerprint: rule,
          challengeByNetwork: rule,
          verifyByChallenge: rule,
          verifyByNetwork: rule,
        },
        session: { absoluteLifetimeMs: 60_000, idleLifetimeMs: 30_000 },
      },
      redisUrl: 'rediss://redis.invalid:6379',
      secureCookies: true,
    };

    await expect(
      createAuthRuntime({
        clientRepository: {
          listRegisteredClients: () => Promise.resolve(config.oidc.clients),
        },
        config,
        delivery: new LocalEmailChallengeDelivery({ NODE_ENV: 'test' }),
        redisClientFactory: {
          connect: () => Promise.resolve({ eval: () => Promise.resolve(1) }),
        },
        repository: new LocalAuthRepository({ NODE_ENV: 'test' }),
      }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });
  });
});
