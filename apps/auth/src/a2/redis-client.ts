import { createClient } from 'redis';

import { AuthError } from './contracts.js';
import type { RedisScriptClient, RedisScriptClientFactory } from './redis-rate-limiter.js';

export const nodeRedisScriptClientFactory: RedisScriptClientFactory = Object.freeze({
  productionSafe: true,
  async connect(url: string): Promise<RedisScriptClient> {
    const client = createClient({
      socket: {
        connectTimeout: 5_000,
        reconnectStrategy: false,
      },
      url,
    });
    client.on('error', () => undefined);
    try {
      await client.connect();
      await client.ping();
      return Object.freeze({
        async close(): Promise<void> {
          if (client.isOpen) {
            await client.close();
          }
        },
        eval(
          script: string,
          options: { readonly arguments: readonly string[]; readonly keys: readonly string[] },
        ): Promise<unknown> {
          return client.eval(script, {
            arguments: [...options.arguments],
            keys: [...options.keys],
          });
        },
      });
    } catch {
      if (client.isOpen) {
        await client.close().catch(() => undefined);
      }
      throw new AuthError('auth.unavailable', 'Authentication rate limiting is unavailable');
    }
  },
});
