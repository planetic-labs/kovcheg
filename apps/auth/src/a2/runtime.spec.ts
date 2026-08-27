import { describe, expect, it } from 'vitest';

import { emailChallengePolicy, passkeyPolicy, passkeyRateLimitPolicy } from './contracts.js';
import { LocalAuthRepository, LocalEmailChallengeDelivery } from './local-adapters.js';
import { ResendEmailChallengeDelivery } from './resend-email-challenge-delivery.js';
import { createAuthRuntime } from './runtime.js';
import type { EnabledAuthRuntimeConfig } from './runtime-config.js';
import { loadEmailChallengeDelivery } from './runtime-infrastructure.js';

describe('A2 production runtime boundary', () => {
  it('keeps local email delivery out of production composition', async () => {
    await expect(
      loadEmailChallengeDelivery('production', { AUTH_EMAIL_DELIVERY_ADAPTER: 'local' }),
    ).rejects.toThrow('Email challenge delivery configuration is unavailable');
    await expect(
      loadEmailChallengeDelivery('test', { AUTH_EMAIL_DELIVERY_ADAPTER: 'local' }),
    ).resolves.toBeInstanceOf(LocalEmailChallengeDelivery);
  });

  it('loads Resend only from complete server-side configuration and fails closed otherwise', async () => {
    await expect(
      loadEmailChallengeDelivery('production', { AUTH_EMAIL_DELIVERY_ADAPTER: 'resend' }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });

    const delivery = await loadEmailChallengeDelivery(
      'production',
      {
        AUTH_EMAIL_DELIVERY_ADAPTER: 'resend',
        AUTH_EMAIL_FROM_ADDRESS: 'sender@auth.invalid',
        AUTH_EMAIL_FROM_NAME: 'Synthetic Auth Sender',
        RESEND_API_KEY: 'synthetic-test-key-material',
      },
      () => ({
        send: () => Promise.resolve({ data: { id: 'synthetic-email-id' }, error: null }),
      }),
    );

    expect(delivery).toBeInstanceOf(ResendEmailChallengeDelivery);
    expect(delivery.productionSafe).toBe(true);
  });

  it('rejects test repositories and delivery adapters even if they were constructed explicitly', async () => {
    const rule = Object.freeze({ limit: 10, windowMs: 60_000 });
    const config: EnabledAuthRuntimeConfig = {
      authSecrets: {
        challengePepper: 'c'.repeat(64),
        personalGatePepper: 'g'.repeat(64),
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
        passkey: passkeyPolicy,
        rateLimits: {
          challengeByEmail: rule,
          challengeByFingerprint: rule,
          challengeByNetwork: rule,
          ...passkeyRateLimitPolicy,
          verifyByChallenge: rule,
          verifyByNetwork: rule,
        },
        session: { absoluteLifetimeMs: 60_000, idleLifetimeMs: 30_000 },
      },
      redisUrl: 'rediss://redis.invalid:6379',
      secureCookies: true,
      webauthn: {
        origins: ['https://auth.m6z.ru'],
        rpId: 'auth.m6z.ru',
        rpName: 'Kovcheg',
      },
    };

    await expect(
      createAuthRuntime({
        clientRepository: {
          listRegisteredClients: () => Promise.resolve(config.oidc.clients),
        },
        config,
        delivery: new LocalEmailChallengeDelivery({ NODE_ENV: 'test' }),
        redisClientFactory: {
          connect: () => Promise.resolve({ eval: () => Promise.resolve(1), isReady: () => true }),
        },
        repository: new LocalAuthRepository({ NODE_ENV: 'test' }),
      }),
    ).rejects.toMatchObject({ code: 'auth.unavailable' });
  });
});
