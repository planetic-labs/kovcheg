import { randomUUID } from 'node:crypto';

import type { RateLimitRule } from './contracts.js';
import type { RateLimitDecision, RateLimiter } from './ports.js';

export interface RedisScriptClient {
  close?(): Promise<void>;
  eval(
    script: string,
    options: {
      readonly arguments: readonly string[];
      readonly keys: readonly string[];
    },
  ): Promise<unknown>;
  isReady(): boolean;
}

export interface RedisScriptClientFactory {
  readonly productionSafe?: true;
  connect(url: string): Promise<RedisScriptClient>;
}

const consumeScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  redis.call('PEXPIRE', key, window)
  return 0
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return 1
`;

export class RedisRateLimiter implements RateLimiter {
  constructor(
    private readonly client: RedisScriptClient,
    private readonly keyPrefix = 'kovcheg:auth:rate:',
  ) {
    if (!/^[A-Za-z0-9:_-]{1,80}$/.test(keyPrefix)) {
      throw new Error('Redis rate-limit key prefix is invalid');
    }
  }

  async consume(input: {
    readonly key: string;
    readonly now: number;
    readonly rule: RateLimitRule;
  }): Promise<RateLimitDecision> {
    try {
      const decision = await this.client.eval(consumeScript, {
        arguments: [
          String(input.now),
          String(input.rule.windowMs),
          String(input.rule.limit),
          `${input.now}:${randomUUID()}`,
        ],
        keys: [`${this.keyPrefix}${input.key}`],
      });
      if (decision === 1 || decision === '1') {
        return 'allowed';
      }
      if (decision === 0 || decision === '0') {
        return 'limited';
      }
      return 'unavailable';
    } catch {
      return 'unavailable';
    }
  }
}

export const redisRateLimitConsumeScript = consumeScript;
