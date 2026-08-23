import { readFileSync } from 'node:fs';

export interface RealtimeApiEnvironment {
  readonly INSTANCE_ID?: string | undefined;
  readonly REALTIME_RELAY_TOKEN_FILE?: string | undefined;
  readonly REDIS_URL?: string | undefined;
}

export interface RealtimeApiRuntimeOptions {
  readonly instanceId: string;
  readonly redisUrl: string | null;
  readonly relayToken: string | null;
}

const instanceIdExpression = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const relayTokenExpression = /^[A-Za-z0-9._:-]{32,256}$/u;

export function loadRealtimeApiRuntimeOptions(
  environment: RealtimeApiEnvironment = process.env,
): RealtimeApiRuntimeOptions {
  const instanceId = environment.INSTANCE_ID?.trim() || 'api';
  if (!instanceIdExpression.test(instanceId)) {
    throw new Error('INSTANCE_ID is invalid');
  }

  const redisUrlValue = environment.REDIS_URL?.trim();
  const redisUrl =
    redisUrlValue && /^redis:\/\/[A-Za-z0-9_.-]+(?::[0-9]{1,5})?\/?$/u.test(redisUrlValue)
      ? redisUrlValue
      : null;

  const tokenFile = environment.REALTIME_RELAY_TOKEN_FILE?.trim();
  let relayToken: string | null = null;
  if (tokenFile) {
    const candidate = readFileSync(tokenFile, 'utf8').replace(/[\r\n]+$/u, '');
    if (!relayTokenExpression.test(candidate)) {
      throw new Error('Realtime relay token is invalid');
    }
    relayToken = candidate;
  }

  return Object.freeze({ instanceId, redisUrl, relayToken });
}
