import { describe, expect, it } from 'vitest';

import { loadWebRuntimeConfig } from './runtime-config.js';

describe('web runtime configuration', () => {
  it('uses typed public defaults', () => {
    expect(loadWebRuntimeConfig({ NODE_ENV: 'test' })).toMatchObject({
      host: '127.0.0.1',
      nodeEnv: 'test',
      port: 3000,
      service: 'web',
    });
  });
});
