import { describe, expect, it } from 'vitest';

import { RedisRateLimiter } from './redis-rate-limiter.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';

class SimulatedRedisClient implements RedisScriptClient {
  readonly calls: { readonly arguments: readonly string[]; readonly keys: readonly string[] }[] =
    [];
  private readonly attempts = new Map<string, number[]>();
  private tail: Promise<void> = Promise.resolve();

  eval(
    _script: string,
    options: { readonly arguments: readonly string[]; readonly keys: readonly string[] },
  ): Promise<unknown> {
    const result = this.tail.then(() => {
      this.calls.push(options);
      const [nowText, windowText, limitText] = options.arguments;
      const key = options.keys[0];
      if (
        nowText === undefined ||
        windowText === undefined ||
        limitText === undefined ||
        key === undefined
      ) {
        throw new Error('invalid synthetic Redis call');
      }
      const now = Number(nowText);
      const windowMs = Number(windowText);
      const limit = Number(limitText);
      const recent = (this.attempts.get(key) ?? []).filter((attempt) => attempt > now - windowMs);
      if (recent.length >= limit) {
        this.attempts.set(key, recent);
        return 0;
      }
      recent.push(now);
      this.attempts.set(key, recent);
      return 1;
    });
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  isReady(): boolean {
    return true;
  }
}

describe('A2 Redis rate limiter', () => {
  it('allows only the configured number of concurrent attempts through one atomic script', async () => {
    const client = new SimulatedRedisClient();
    const limiter = new RedisRateLimiter(client);
    const decisions = await Promise.all(
      Array.from({ length: 10 }, async () =>
        limiter.consume({
          key: 'synthetic-hmac-dimension',
          now: 1_000,
          rule: { limit: 3, windowMs: 60_000 },
        }),
      ),
    );

    expect(decisions.filter((decision) => decision === 'allowed')).toHaveLength(3);
    expect(decisions.filter((decision) => decision === 'limited')).toHaveLength(7);
    expect(client.calls).toHaveLength(10);
    expect(new Set(client.calls.map((call) => call.keys[0]))).toEqual(
      new Set(['kovcheg:auth:rate:synthetic-hmac-dimension']),
    );
  });

  it('fails closed when Redis errors or returns an unexpected response', async () => {
    const failing = new RedisRateLimiter({
      eval(): Promise<unknown> {
        return Promise.reject(new Error('synthetic Redis failure'));
      },
      isReady: () => false,
    });
    const malformed = new RedisRateLimiter({
      eval(): Promise<unknown> {
        return Promise.resolve(null);
      },
      isReady: () => true,
    });
    const input = { key: 'synthetic-key', now: 1_000, rule: { limit: 1, windowMs: 1_000 } };

    await expect(failing.consume(input)).resolves.toBe('unavailable');
    await expect(malformed.consume(input)).resolves.toBe('unavailable');
  });
});
