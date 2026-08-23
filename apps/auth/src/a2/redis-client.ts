import { createClient } from 'redis';

import { AuthError } from './contracts.js';
import type { RedisScriptClient, RedisScriptClientFactory } from './redis-rate-limiter.js';

export function authRedisReconnectDelay(retries: number): number {
  const boundedRetries = Number.isSafeInteger(retries) && retries > 0 ? Math.min(retries, 4) : 0;
  return Math.min(250 * 2 ** boundedRetries, 4_000);
}

export const nodeRedisScriptClientFactory: RedisScriptClientFactory = Object.freeze({
  productionSafe: true,
  async connect(url: string): Promise<RedisScriptClient> {
    const client = createClient({
      socket: {
        connectTimeout: 5_000,
        reconnectStrategy: (retries) => authRedisReconnectDelay(retries),
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
        isReady(): boolean {
          return client.isReady;
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
