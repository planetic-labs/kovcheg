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
        KOVCHEG_APP_ENV: 'development',
        LOG_LEVEL: 'debug',
        NODE_ENV: 'test',
        PORT: '4101',
      }),
    ).toEqual({
      applicationEnvironment: 'development',
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
    expect(() =>
      loadServiceConfig('auth', {
        KOVCHEG_APP_ENV: 'development',
        PORT: 'invalid-value',
      }),
    ).toThrow(new ConfigurationError('PORT', 'an integer from 1 through 65535'));
  });

  it('keeps unknown build provenance null instead of inventing values', () => {
    expect(
      loadServiceConfig('worker', { KOVCHEG_APP_ENV: 'development', NODE_ENV: 'test' }).build,
    ).toEqual({
      commitSha: null,
      contractVersion: 1,
      imageDigest: null,
      migrationVersion: null,
    });
  });

  it('rejects malformed build metadata without echoing it', () => {
    expect(() =>
      loadServiceConfig('api', {
        BUILD_COMMIT_SHA: 'not-a-commit',
        KOVCHEG_APP_ENV: 'development',
      }),
    ).toThrow(
      new ConfigurationError('BUILD_COMMIT_SHA', 'a lowercase 40-character Git commit SHA'),
    );
  });

  it.each([
    ['development', 'development'],
    ['development', 'test'],
    ['development', 'production'],
    ['staging', 'production'],
    ['production', 'production'],
  ] as const)(
    'accepts logical %s with technical NODE_ENV=%s for every application service',
    (applicationEnvironment, nodeEnvironment) => {
      for (const service of ['api', 'auth', 'web', 'worker'] as const) {
        expect(
          loadServiceConfig(service, {
            KOVCHEG_APP_ENV: applicationEnvironment,
            NODE_ENV: nodeEnvironment,
          }).applicationEnvironment,
        ).toBe(applicationEnvironment);
      }
    },
  );

  it.each([undefined, '', 'test', 'Production', ' staging '])(
    'rejects a missing, empty, or unknown logical environment without echoing it',
    (applicationEnvironment) => {
      expect(() =>
        loadServiceConfig('api', {
          KOVCHEG_APP_ENV: applicationEnvironment,
          NODE_ENV: 'production',
        }),
      ).toThrow(new ConfigurationError('KOVCHEG_APP_ENV', 'development, staging, or production'));
    },
  );

  it.each([
    ['staging', 'development'],
    ['staging', 'test'],
    ['production', 'development'],
    ['production', 'test'],
  ] as const)(
    'rejects logical %s with unsafe technical NODE_ENV=%s',
    (applicationEnvironment, nodeEnvironment) => {
      expect(() =>
        loadServiceConfig('worker', {
          KOVCHEG_APP_ENV: applicationEnvironment,
          NODE_ENV: nodeEnvironment,
        }),
      ).toThrow(
        new ConfigurationError(
          'NODE_ENV',
          'production when KOVCHEG_APP_ENV is staging or production',
        ),
      );
    },
  );

  it('does not infer production from NODE_ENV', () => {
    expect(() => loadServiceConfig('auth', { NODE_ENV: 'production' })).toThrow(
      new ConfigurationError('KOVCHEG_APP_ENV', 'development, staging, or production'),
    );
  });

  it('maps LOG_LEVEL to the built-in NestJS logger', () => {
    expect(toNestLoggerLevels('error')).toEqual(['fatal', 'error']);
    expect(toNestLoggerLevels('debug')).toEqual(['fatal', 'error', 'warn', 'log', 'debug']);
  });
});
