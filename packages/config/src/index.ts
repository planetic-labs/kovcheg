import type { ServiceName } from '@kovcheg/contracts';

export type RuntimeEnvironment = 'development' | 'production' | 'test';
export type LogLevel = 'debug' | 'error' | 'info' | 'warn';

export interface EnvironmentSource {
  readonly HOST?: string | undefined;
  readonly LOG_LEVEL?: string | undefined;
  readonly NODE_ENV?: string | undefined;
  readonly PORT?: string | undefined;
}

export interface ServiceRuntimeConfig {
  readonly host: string;
  readonly logLevel: LogLevel;
  readonly nodeEnv: RuntimeEnvironment;
  readonly port: number;
  readonly service: ServiceName;
}

export const serviceDefaults = Object.freeze({
  api: Object.freeze({ host: '127.0.0.1', port: 3001 }),
  auth: Object.freeze({ host: '127.0.0.1', port: 3002 }),
  web: Object.freeze({ host: '127.0.0.1', port: 3000 }),
  worker: Object.freeze({ host: '127.0.0.1', port: 3003 }),
}) satisfies Readonly<Record<ServiceName, Readonly<{ host: string; port: number }>>>;

export class ConfigurationError extends Error {
  constructor(key: keyof EnvironmentSource, expectation: string) {
    super(`Invalid ${key}; expected ${expectation}`);
    this.name = 'ConfigurationError';
  }
}

function parseNodeEnvironment(value: string | undefined): RuntimeEnvironment {
  const candidate = value ?? 'development';
  if (candidate === 'development' || candidate === 'production' || candidate === 'test') {
    return candidate;
  }

  throw new ConfigurationError('NODE_ENV', 'development, test, or production');
}

function parseLogLevel(value: string | undefined): LogLevel {
  const candidate = value ?? 'info';
  if (
    candidate === 'debug' ||
    candidate === 'error' ||
    candidate === 'info' ||
    candidate === 'warn'
  ) {
    return candidate;
  }

  throw new ConfigurationError('LOG_LEVEL', 'debug, info, warn, or error');
}

function parseHost(value: string | undefined, fallback: string): string {
  const candidate = value?.trim() || fallback;
  if (candidate.length > 0 && !candidate.includes('://')) {
    return candidate;
  }

  throw new ConfigurationError('HOST', 'a hostname or IP address without a URL scheme');
}

function parsePort(value: string | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }

  if (!/^\d+$/.test(value)) {
    throw new ConfigurationError('PORT', 'an integer from 1 through 65535');
  }

  const port = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new ConfigurationError('PORT', 'an integer from 1 through 65535');
  }

  return port;
}

export function loadServiceConfig(
  service: ServiceName,
  environment: EnvironmentSource = process.env,
): ServiceRuntimeConfig {
  const defaults = serviceDefaults[service];

  return Object.freeze({
    host: parseHost(environment.HOST, defaults.host),
    logLevel: parseLogLevel(environment.LOG_LEVEL),
    nodeEnv: parseNodeEnvironment(environment.NODE_ENV),
    port: parsePort(environment.PORT, defaults.port),
    service,
  });
}
