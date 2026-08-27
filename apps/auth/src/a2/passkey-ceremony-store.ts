import type { UserId, Uuid } from '@kovcheg/contracts';

import type {
  PasskeyCeremonyState,
  PasskeyCeremonyStore,
  TakePasskeyCeremonyResult,
} from './ports.js';
import type { RedisScriptClient } from './redis-rate-limiter.js';

const putScript = `
local result = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2])
return result and 1 or 0
`;

const takeScript = `
local value = redis.call('GETDEL', KEYS[1])
return value or false
`;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const verifierPattern = /^[A-Za-z0-9_-]{43}$/u;
const challengePattern = /^[A-Za-z0-9_-]{16,512}$/u;

function state(value: unknown): PasskeyCeremonyState | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (
    !challengePattern.test(String(candidate.challenge ?? '')) ||
    !verifierPattern.test(String(candidate.clientContextKey ?? ''))
  ) {
    return null;
  }
  if (
    candidate.ceremony === 'authentication' &&
    Object.keys(candidate).sort().join(',') === 'ceremony,challenge,clientContextKey'
  ) {
    return Object.freeze({
      ceremony: 'authentication',
      challenge: candidate.challenge as string,
      clientContextKey: candidate.clientContextKey as string,
    });
  }
  if (
    candidate.ceremony === 'registration' &&
    Object.keys(candidate).sort().join(',') ===
      'accountId,ceremony,challenge,clientContextKey,sessionVerifier' &&
    uuidPattern.test(String(candidate.accountId ?? '')) &&
    verifierPattern.test(String(candidate.sessionVerifier ?? ''))
  ) {
    return Object.freeze({
      accountId: candidate.accountId as UserId,
      ceremony: 'registration',
      challenge: candidate.challenge as string,
      clientContextKey: candidate.clientContextKey as string,
      sessionVerifier: candidate.sessionVerifier as string,
    });
  }
  return null;
}

export class RedisPasskeyCeremonyStore implements PasskeyCeremonyStore {
  constructor(
    private readonly client: RedisScriptClient,
    private readonly prefix = 'kovcheg:auth:passkey:ceremony:',
  ) {
    if (!/^[A-Za-z0-9:_-]{1,80}$/u.test(prefix)) {
      throw new Error('Redis passkey ceremony key prefix is invalid');
    }
  }

  async put(
    ceremonyId: Uuid,
    ceremonyState: PasskeyCeremonyState,
    ttlMs: number,
  ): Promise<'stored' | 'unavailable'> {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) return 'unavailable';
    try {
      const result = await this.client.eval(putScript, {
        arguments: [JSON.stringify(ceremonyState), String(ttlMs)],
        keys: [this.key(ceremonyId)],
      });
      return result === 1 || result === '1' ? 'stored' : 'unavailable';
    } catch {
      return 'unavailable';
    }
  }

  async take(ceremonyId: Uuid): Promise<TakePasskeyCeremonyResult> {
    try {
      const result = await this.client.eval(takeScript, {
        arguments: [],
        keys: [this.key(ceremonyId)],
      });
      if (result === null || result === false || result === 0 || result === '0') {
        return Object.freeze({ kind: 'missing' });
      }
      if (typeof result !== 'string') return Object.freeze({ kind: 'unavailable' });
      let parsed: unknown;
      try {
        parsed = JSON.parse(result) as unknown;
      } catch {
        return Object.freeze({ kind: 'unavailable' });
      }
      const parsedState = state(parsed);
      return parsedState === null
        ? Object.freeze({ kind: 'unavailable' })
        : Object.freeze({ kind: 'found', state: parsedState });
    } catch {
      return Object.freeze({ kind: 'unavailable' });
    }
  }

  private key(ceremonyId: Uuid): string {
    return `${this.prefix}${ceremonyId}`;
  }
}
