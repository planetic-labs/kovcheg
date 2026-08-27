import type { CorrelationId } from '@kovcheg/contracts';

import type {
  PersonalGateAbuseProtector,
  PersonalGateInvalidDecision,
  PersonalGateSourceDecision,
} from './ports.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';

const checkSourceScript = `
return redis.call('EXISTS', KEYS[1])
`;

const recordMissScript = `
local attempts_key = KEYS[1]
local blocked_key = KEYS[2]
local blocked_sources_key = KEYS[3]
local signal_stream = KEYS[4]
local source_key = ARGV[1]
local now = ARGV[2]
local correlation_id = ARGV[3]

if redis.call('EXISTS', blocked_key) == 1 then
  return 2
end

local attempts = redis.call('INCR', attempts_key)
redis.call('PEXPIRE', attempts_key, 86400000)
if attempts < 3 then
  return 1
end

redis.call('SET', blocked_key, '1')
redis.call('SADD', blocked_sources_key, source_key)
redis.call('PEXPIRE', blocked_sources_key, 86400000)
local blocked_sources = redis.call('SCARD', blocked_sources_key)
local severity = blocked_sources >= 3 and 'critical' or 'warning'
redis.call('XADD', signal_stream, 'MAXLEN', '~', 1000, '*',
  'event', 'auth.personal-gate.source-blocked',
  'severity', severity,
  'sourceKey', source_key,
  'correlationId', correlation_id,
  'occurredAt', now)
return blocked_sources >= 3 and 3 or 2
`;

const activationScript = `
redis.call('DEL', KEYS[1])
local first_record = redis.call('SET', KEYS[3], '1', 'NX', 'PX', 604800000)
if not first_record then
  return 1
end
redis.call('XADD', KEYS[2], 'MAXLEN', '~', 1000, '*',
  'event', 'auth.personal-gate.device-activated',
  'severity', 'information',
  'sourceKey', ARGV[1],
  'correlationId', ARGV[2],
  'occurredAt', ARGV[3])
return 1
`;

export class RedisPersonalGateAbuseProtector implements PersonalGateAbuseProtector {
  constructor(
    private readonly client: RedisScriptClient,
    private readonly prefix = 'kovcheg:auth:personal-gate:',
  ) {
    if (!/^[A-Za-z0-9:_-]{1,80}$/u.test(prefix)) {
      throw new Error('Redis personal-gate key prefix is invalid');
    }
  }

  async checkSource(sourceKey: string): Promise<PersonalGateSourceDecision> {
    try {
      const result = await this.client.eval(checkSourceScript, {
        arguments: [],
        keys: [this.blockedKey(sourceKey)],
      });
      if (result === 0 || result === '0') return 'allowed';
      if (result === 1 || result === '1') return 'blocked';
      return 'unavailable';
    } catch {
      return 'unavailable';
    }
  }

  async recordActivation(input: {
    readonly activationId: string;
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly sourceKey: string;
  }): Promise<'recorded' | 'unavailable'> {
    try {
      const result = await this.client.eval(activationScript, {
        arguments: [input.sourceKey, input.correlationId, String(input.now)],
        keys: [
          this.attemptsKey(input.sourceKey),
          `${this.prefix}signals`,
          `${this.prefix}activation-recorded:${input.activationId}`,
        ],
      });
      return result === 1 || result === '1' ? 'recorded' : 'unavailable';
    } catch {
      return 'unavailable';
    }
  }

  async recordSyntacticallyValidMiss(input: {
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly sourceKey: string;
  }): Promise<PersonalGateInvalidDecision> {
    try {
      const result = await this.client.eval(recordMissScript, {
        arguments: [input.sourceKey, String(input.now), input.correlationId],
        keys: [
          this.attemptsKey(input.sourceKey),
          this.blockedKey(input.sourceKey),
          `${this.prefix}blocked-sources`,
          `${this.prefix}signals`,
        ],
      });
      if (result === 1 || result === '1') return 'allowed';
      if (result === 2 || result === '2') return 'blocked';
      if (result === 3 || result === '3') return 'critical';
      return 'unavailable';
    } catch {
      return 'unavailable';
    }
  }

  private attemptsKey(sourceKey: string): string {
    return `${this.prefix}attempts:${sourceKey}`;
  }

  private blockedKey(sourceKey: string): string {
    return `${this.prefix}blocked:${sourceKey}`;
  }
}
