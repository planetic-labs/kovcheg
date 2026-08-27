import type { CorrelationId } from '@kovcheg/contracts';
import { describe, expect, it } from 'vitest';

import { RedisPersonalGateAbuseProtector } from './personal-gate-abuse.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';

describe('A6 Redis personal-gate activation protection', () => {
  it('uses opaque source keys, blocks the third miss, and emits bounded signals', async () => {
    const calls: {
      readonly arguments: readonly string[];
      readonly keys: readonly string[];
      readonly script: string;
    }[] = [];
    const results: unknown[] = [0, 1, 2, 3, 1];
    const client: RedisScriptClient = {
      eval(script, options) {
        calls.push({ arguments: options.arguments, keys: options.keys, script });
        return Promise.resolve(results.shift());
      },
      isReady: () => true,
    };
    const protector = new RedisPersonalGateAbuseProtector(client);
    const sourceKey = 'o'.repeat(43);
    const common = {
      activationId: '00000000-0000-4000-8000-000000000701' as const,
      correlationId: 'gate-protection-test' as CorrelationId,
      now: Date.UTC(2026, 7, 27),
      sourceKey,
    };
    await expect(protector.checkSource(sourceKey)).resolves.toBe('allowed');
    await expect(protector.recordSyntacticallyValidMiss(common)).resolves.toBe('allowed');
    await expect(protector.recordSyntacticallyValidMiss(common)).resolves.toBe('blocked');
    await expect(protector.recordSyntacticallyValidMiss(common)).resolves.toBe('critical');
    await expect(protector.recordActivation(common)).resolves.toBe('recorded');

    expect(calls.flatMap((call) => call.keys).join('\n')).not.toContain('192.0.2.');
    expect(calls.flatMap((call) => call.arguments)).not.toContain('XXXX-XXXX');
    expect(calls.some((call) => call.script.includes("'severity', severity"))).toBe(true);
    expect(calls.some((call) => call.script.includes('device-activated'))).toBe(true);
    expect(calls.at(-1)?.keys.at(-1)).toContain(common.activationId);
  });

  it('fails closed on Redis exceptions and unexpected script results', async () => {
    let reject = true;
    const client: RedisScriptClient = {
      eval: () => (reject ? Promise.reject(new Error('synthetic outage')) : Promise.resolve(9)),
      isReady: () => false,
    };
    const protector = new RedisPersonalGateAbuseProtector(client);
    await expect(protector.checkSource('o'.repeat(43))).resolves.toBe('unavailable');
    reject = false;
    await expect(
      protector.recordSyntacticallyValidMiss({
        correlationId: 'gate-protection-test' as CorrelationId,
        now: 1,
        sourceKey: 'o'.repeat(43),
      }),
    ).resolves.toBe('unavailable');
  });
});
