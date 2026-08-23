import { describe, expect, it } from 'vitest';

import { loadRealtimeApiRuntimeOptions } from './realtime.config.js';

describe('realtime API runtime configuration', () => {
  it('allows an absent Redis URL for the non-realtime foundation', () => {
    expect(loadRealtimeApiRuntimeOptions({})).toMatchObject({ redisUrl: null });
  });

  it('accepts a valid internal Redis URL', () => {
    expect(loadRealtimeApiRuntimeOptions({ REDIS_URL: 'redis://redis:6379' })).toMatchObject({
      redisUrl: 'redis://redis:6379',
    });
  });

  it('fails closed when a configured Redis URL is invalid', () => {
    expect(() => loadRealtimeApiRuntimeOptions({ REDIS_URL: 'not-a-redis-url' })).toThrow(
      'REDIS_URL is invalid',
    );
  });
});
