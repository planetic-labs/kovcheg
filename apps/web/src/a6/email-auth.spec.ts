import { describe, expect, it } from 'vitest';

import { parseEmailChallengeResponse, prepareEmailSubmission } from './email-auth';

describe('A6 Variant E email transition', () => {
  it('outer-trims the display value while preserving case, dots, and plus tags', () => {
    expect(prepareEmailSubmission('  USER.Name+Tag@Example.invalid  ')).toBe(
      'USER.Name+Tag@Example.invalid',
    );
  });

  it('rejects local syntax errors without inventing account lookup behavior', () => {
    expect(prepareEmailSubmission('missing-at.example.invalid')).toBeNull();
    expect(prepareEmailSubmission('name @example.invalid')).toBeNull();
    expect(prepareEmailSubmission('name@ example.invalid')).toBeNull();
  });

  it.each(['active', 'unknown', 'deactivated', 'throttled'])(
    'parses the same neutral code transition for a %s outcome',
    (outcome) => {
      expect(
        parseEmailChallengeResponse({
          email: `${outcome}@example.invalid`,
          next: 'code',
          status: 'accepted',
        }),
      ).toEqual({
        email: `${outcome}@example.invalid`,
        next: 'code',
        status: 'accepted',
      });
    },
  );

  it('rejects non-neutral or malformed transport payloads', () => {
    expect(
      parseEmailChallengeResponse({
        email: 'member@example.invalid',
        next: 'email',
        status: 'accepted',
      }),
    ).toBeNull();
    expect(parseEmailChallengeResponse({ next: 'code', status: 'accepted' })).toBeNull();
  });
});
