import { describe, expect, it } from 'vitest';

import {
  ConfigurationError,
  loadServiceConfig,
  serviceDefaults,
  toNestLoggerLevels,
} from './index.js';

describe('foundation configuration', () => {
  it('keeps public defaults immutable', () => {
    expect(Object.isFrozen(serviceDefaults)).toBe(true);
    expect(Object.isFrozen(serviceDefaults.api)).toBe(true);
  });

  it('loads a typed service configuration without secret values', () => {
    expect(
      loadServiceConfig('api', {
        BUILD_COMMIT_SHA: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        BUILD_IMAGE_DIGEST:
          'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        HOST: '127.0.0.1',
        LOG_LEVEL: 'debug',
        NODE_ENV: 'test',
        PORT: '4101',
      }),
    ).toEqual({
      build: {
        commitSha: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        contractVersion: 1,
        imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        migrationVersion: null,
      },
      host: '127.0.0.1',
      logLevel: 'debug',
      nodeEnv: 'test',
      port: 4101,
      service: 'api',
    });
  });

  it('rejects invalid ports without echoing their values', () => {
    expect(() => loadServiceConfig('auth', { PORT: 'invalid-value' })).toThrow(
      new ConfigurationError('PORT', 'an integer from 1 through 65535'),
    );
  });

  it('keeps unknown build provenance null instead of inventing values', () => {
    expect(loadServiceConfig('worker', { NODE_ENV: 'test' }).build).toEqual({
      commitSha: null,
      contractVersion: 1,
      imageDigest: null,
      migrationVersion: null,
    });
  });

  it('rejects malformed build metadata without echoing it', () => {
    expect(() => loadServiceConfig('api', { BUILD_COMMIT_SHA: 'not-a-commit' })).toThrow(
      new ConfigurationError('BUILD_COMMIT_SHA', 'a lowercase 40-character Git commit SHA'),
    );
  });

  it('maps LOG_LEVEL to the built-in NestJS logger', () => {
    expect(toNestLoggerLevels('error')).toEqual(['fatal', 'error']);
    expect(toNestLoggerLevels('debug')).toEqual(['fatal', 'error', 'warn', 'log', 'debug']);
  });
});
