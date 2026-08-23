import { readFileSync } from 'node:fs';

export interface RealtimeWorkerEnvironment {
  readonly INSTANCE_ID?: string | undefined;
  readonly REALTIME_RELAY_TOKEN_FILE?: string | undefined;
  readonly REALTIME_RELAY_URL?: string | undefined;
  readonly REDIS_URL?: string | undefined;
}

export interface RealtimeWorkerOptions {
  readonly consumerName: string;
  readonly redisUrl: string;
  readonly relayToken: string;
  readonly relayUrl: string;
}

const safeNameExpression = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const relayTokenExpression = /^[A-Za-z0-9._:-]{32,256}$/u;

export function loadRealtimeWorkerOptions(
  environment: RealtimeWorkerEnvironment = process.env,
): RealtimeWorkerOptions | null {
  const redisUrl = environment.REDIS_URL?.trim();
  const relayUrl = environment.REALTIME_RELAY_URL?.trim();
  const tokenFile = environment.REALTIME_RELAY_TOKEN_FILE?.trim();
  if (!redisUrl || !relayUrl || !tokenFile) {
    return null;
  }
  if (!/^redis:\/\/[A-Za-z0-9_.-]+(?::[0-9]{1,5})?\/?$/u.test(redisUrl)) {
    throw new Error('REDIS_URL is invalid');
  }
  if (!/^http:\/\/[A-Za-z0-9_.-]+(?::[0-9]{1,5})?\/[A-Za-z0-9_./-]+$/u.test(relayUrl)) {
    throw new Error('REALTIME_RELAY_URL must be an internal HTTP endpoint');
  }
  const consumerName = `${environment.INSTANCE_ID?.trim() || 'worker'}-${process.pid}`;
  if (!safeNameExpression.test(consumerName)) {
    throw new Error('Realtime consumer name is invalid');
  }
  const relayToken = readFileSync(tokenFile, 'utf8').replace(/[\r\n]+$/u, '');
  if (!relayTokenExpression.test(relayToken)) {
    throw new Error('Realtime relay token is invalid');
  }
  return Object.freeze({ consumerName, redisUrl, relayToken, relayUrl });
}
