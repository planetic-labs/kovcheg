import { describe, expect, it } from 'vitest';

import { loadWebRuntimeConfig } from './runtime-config.js';

describe('web runtime configuration', () => {
  it('uses typed public defaults', () => {
    expect(
      loadWebRuntimeConfig({ KOVCHEG_APP_ENV: 'development', NODE_ENV: 'test' }),
    ).toMatchObject({
      applicationEnvironment: 'development',
      build: {
        commitSha: null,
        contractVersion: 1,
        imageDigest: null,
        migrationVersion: null,
      },
      host: '127.0.0.1',
      nodeEnv: 'test',
      port: 3000,
      service: 'web',
    });
  });

  it('rejects invalid bind configuration before serving requests', () => {
    expect(() =>
      loadWebRuntimeConfig({
        HOST: 'https://127.0.0.1',
        KOVCHEG_APP_ENV: 'development',
        NODE_ENV: 'test',
      }),
    ).toThrow('Invalid HOST; expected a hostname or IP address without a URL scheme');
  });
});
