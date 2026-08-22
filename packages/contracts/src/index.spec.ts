import { describe, expect, it } from 'vitest';

import { coreModuleNames, createServiceHealth, foundationContractVersion } from './index.js';

describe('foundation contracts', () => {
  it('exports an explicit contract version', () => {
    expect(foundationContractVersion).toBe(1);
  });

  it('creates a typed readiness response', () => {
    expect(createServiceHealth('api', 'ready')).toEqual({
      contractVersion: 1,
      service: 'api',
      state: 'ready',
      status: 'ok',
    });
  });

  it('keeps the core module boundary explicit', () => {
    expect(coreModuleNames).toEqual([
      'identity',
      'session',
      'authorization',
      'users',
      'chats',
      'messages',
      'realtime',
      'notifications',
    ]);
  });
});
