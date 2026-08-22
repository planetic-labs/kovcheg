import { describe, expect, it } from 'vitest';

import { ConfigurationError, loadServiceConfig, serviceDefaults } from './index.js';

describe('foundation configuration', () => {
  it('keeps public defaults immutable', () => {
    expect(Object.isFrozen(serviceDefaults)).toBe(true);
    expect(Object.isFrozen(serviceDefaults.api)).toBe(true);
  });

  it('loads a typed service configuration without secret values', () => {
    expect(
      loadServiceConfig('api', {
        HOST: '127.0.0.1',
        LOG_LEVEL: 'debug',
        NODE_ENV: 'test',
        PORT: '4101',
      }),
    ).toEqual({
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
});
