import type { UserId, Uuid } from '@kovcheg/contracts';
import { describe, expect, it } from 'vitest';

import { RedisPasskeyCeremonyStore } from './passkey-ceremony-store.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';

const ceremonyId = '00000000-0000-4000-8000-000000001521' as Uuid;

class ScriptedRedis implements RedisScriptClient {
  readonly calls: {
    readonly arguments: readonly string[];
    readonly keys: readonly string[];
    readonly script: string;
  }[] = [];
  responses: unknown[] = [];

  eval(
    script: string,
    options?: { readonly arguments: readonly string[]; readonly keys: readonly string[] },
  ): Promise<unknown> {
    this.calls.push({
      arguments: options?.arguments ?? [],
      keys: options?.keys ?? [],
      script,
    });
    const response = this.responses.shift();
    if (response instanceof Error) return Promise.reject(response);
    return Promise.resolve(response);
  }

  isReady(): boolean {
    return true;
  }
}

describe('RedisPasskeyCeremonyStore', () => {
  it('stores bounded server-side state with NX/PX and consumes it through GETDEL', async () => {
    const redis = new ScriptedRedis();
    const store = new RedisPasskeyCeremonyStore(redis);
    const state = Object.freeze({
      accountId: '00000000-0000-4000-8000-000000001522' as UserId,
      ceremony: 'registration' as const,
      challenge: 'c'.repeat(32),
      clientContextKey: 'x'.repeat(43),
      sessionVerifier: 's'.repeat(43),
    });
    redis.responses.push(1, JSON.stringify(state), false);

    await expect(store.put(ceremonyId, state, 300_000)).resolves.toBe('stored');
    await expect(store.take(ceremonyId)).resolves.toEqual({ kind: 'found', state });
    await expect(store.take(ceremonyId)).resolves.toEqual({ kind: 'missing' });

    expect(redis.calls[0]?.script).toContain("'NX', 'PX'");
    expect(redis.calls[0]?.arguments[1]).toBe('300000');
    expect(redis.calls[0]?.keys[0]).toBe(`kovcheg:auth:passkey:ceremony:${ceremonyId}`);
    expect(redis.calls[1]?.script).toContain("'GETDEL', KEYS[1]");
    expect(redis.calls[1]?.arguments).toEqual([]);
  });

  it('fails closed for write/read failures and malformed stored state', async () => {
    const redis = new ScriptedRedis();
    const store = new RedisPasskeyCeremonyStore(redis);
    redis.responses.push(new Error('synthetic write failure'));
    await expect(
      store.put(
        ceremonyId,
        {
          ceremony: 'authentication',
          challenge: 'c'.repeat(32),
          clientContextKey: 'x'.repeat(43),
        },
        300_000,
      ),
    ).resolves.toBe('unavailable');

    redis.responses.push('{"ceremony":"authentication"}', new Error('synthetic read failure'));
    await expect(store.take(ceremonyId)).resolves.toEqual({ kind: 'unavailable' });
    await expect(store.take(ceremonyId)).resolves.toEqual({ kind: 'unavailable' });
  });
});
