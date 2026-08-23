import { describe, expect, it } from 'vitest';

import { resolveChatListOutcome } from './chat-list-state';

describe('A6 chat-list startup state', () => {
  it('never turns the first zero response into a normal empty state', () => {
    expect(resolveChatListOutcome(0, false)).toEqual({ kind: 'reload-required' });
  });

  it('turns a repeated zero after reload into a configuration error', () => {
    expect(resolveChatListOutcome(0, true)).toEqual({ kind: 'configuration-error' });
  });

  it('accepts a non-empty active-user list', () => {
    expect(resolveChatListOutcome(1, true)).toEqual({ kind: 'ready' });
  });
});
