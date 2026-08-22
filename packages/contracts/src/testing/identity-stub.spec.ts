import { describe, expect, it } from 'vitest';

import type { UserId } from '../index.js';
import { createSyntheticIdentityStub, syntheticUserIds } from './identity-stub.js';

describe('SyntheticIdentityStub', () => {
  it('keeps stable UUIDs for future integration tests', () => {
    expect(syntheticUserIds).toEqual({
      activePrimary: '00000000-0000-4000-8000-000000000001',
      activeSecondary: '00000000-0000-4000-8000-000000000002',
      deactivated: '00000000-0000-4000-8000-000000000003',
    });
  });

  it('resolves active and deactivated synthetic identities without personal data', async () => {
    const stub = createSyntheticIdentityStub();

    await expect(stub.findById(syntheticUserIds.activePrimary)).resolves.toEqual({
      status: 'active',
      userId: syntheticUserIds.activePrimary,
    });
    await expect(stub.findById(syntheticUserIds.deactivated)).resolves.toEqual({
      status: 'deactivated',
      userId: syntheticUserIds.deactivated,
    });
    expect(stub.identities.every((identity) => !('email' in identity))).toBe(true);
  });

  it('returns null for an unknown synthetic UUID', async () => {
    const stub = createSyntheticIdentityStub();
    const unknownUserId = '00000000-0000-4000-8000-000000000099' satisfies UserId;

    await expect(stub.findById(unknownUserId)).resolves.toBeNull();
  });

  it('fails loudly in a production runtime', () => {
    expect(() => createSyntheticIdentityStub({ NODE_ENV: 'production' })).toThrow(
      'Synthetic identity fixtures are unavailable in production',
    );
  });
});
