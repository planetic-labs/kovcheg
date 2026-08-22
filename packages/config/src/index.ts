import { buildMetadataContractVersion } from '@kovcheg/contracts';
import type { BuildMetadata, ServiceName } from '@kovcheg/contracts';

export type RuntimeEnvironment = 'development' | 'production' | 'test';
export type LogLevel = 'debug' | 'error' | 'info' | 'warn';
export type NestLogLevel = 'debug' | 'error' | 'fatal' | 'log' | 'warn';

export interface EnvironmentSource {
  readonly BUILD_COMMIT_SHA?: string | undefined;
  readonly BUILD_IMAGE_DIGEST?: string | undefined;
  readonly HOST?: string | undefined;
  readonly LOG_LEVEL?: string | undefined;
  readonly NODE_ENV?: string | undefined;
  readonly PORT?: string | undefined;
}

export interface ServiceRuntimeConfig {
  readonly build: BuildMetadata;
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

function parseOptionalMetadata(
  key: 'BUILD_COMMIT_SHA' | 'BUILD_IMAGE_DIGEST',
  value: string | undefined,
  expression: RegExp,
  expectation: string,
): string | null {
  const candidate = value?.trim();
  if (!candidate) {
    return null;
  }

  if (!expression.test(candidate)) {
    throw new ConfigurationError(key, expectation);
  }

  return candidate;
}

export function toNestLoggerLevels(logLevel: LogLevel): NestLogLevel[] {
  switch (logLevel) {
    case 'error':
      return ['fatal', 'error'];
    case 'warn':
      return ['fatal', 'error', 'warn'];
    case 'info':
      return ['fatal', 'error', 'warn', 'log'];
    case 'debug':
      return ['fatal', 'error', 'warn', 'log', 'debug'];
  }
}

export function loadServiceConfig(
  service: ServiceName,
  environment: EnvironmentSource = process.env,
): ServiceRuntimeConfig {
  const defaults = serviceDefaults[service];

  return Object.freeze({
    build: Object.freeze({
      commitSha: parseOptionalMetadata(
        'BUILD_COMMIT_SHA',
        environment.BUILD_COMMIT_SHA,
        /^[0-9a-f]{40}$/,
        'a lowercase 40-character Git commit SHA',
      ),
      contractVersion: buildMetadataContractVersion,
      imageDigest: parseOptionalMetadata(
        'BUILD_IMAGE_DIGEST',
        environment.BUILD_IMAGE_DIGEST,
        /^sha256:[0-9a-f]{64}$/,
        'a sha256 image digest',
      ),
      migrationVersion: null,
    }),
    host: parseHost(environment.HOST, defaults.host),
    logLevel: parseLogLevel(environment.LOG_LEVEL),
    nodeEnv: parseNodeEnvironment(environment.NODE_ENV),
    port: parsePort(environment.PORT, defaults.port),
    service,
  });
}
