import type { IdentityReader, IdentityRecord, UserId } from '../index.js';

export const syntheticUserIds = Object.freeze({
  activePrimary: '00000000-0000-4000-8000-000000000001',
  activeSecondary: '00000000-0000-4000-8000-000000000002',
  deactivated: '00000000-0000-4000-8000-000000000003',
}) satisfies Readonly<Record<string, UserId>>;

const syntheticIdentities: readonly IdentityRecord[] = Object.freeze([
  Object.freeze({ userId: syntheticUserIds.activePrimary, status: 'active' }),
  Object.freeze({ userId: syntheticUserIds.activeSecondary, status: 'active' }),
  Object.freeze({ userId: syntheticUserIds.deactivated, status: 'deactivated' }),
]);

export class SyntheticIdentityStub implements IdentityReader {
  readonly identities = syntheticIdentities;

  findById(userId: UserId): Promise<IdentityRecord | null> {
    return Promise.resolve(this.identities.find((identity) => identity.userId === userId) ?? null);
  }
}

export function createSyntheticIdentityStub(): SyntheticIdentityStub {
  return new SyntheticIdentityStub();
}
