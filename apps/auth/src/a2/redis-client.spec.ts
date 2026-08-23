import { describe, expect, it } from 'vitest';

import { authRedisReconnectDelay } from './redis-client.js';

describe('A2 Redis reconnect policy', () => {
  it('uses bounded exponential retries instead of permanently disabling reconnect', () => {
    expect([0, 1, 2, 3, 4, 5, 100].map(authRedisReconnectDelay)).toEqual([
      250, 500, 1_000, 2_000, 4_000, 4_000, 4_000,
    ]);
  });
});
