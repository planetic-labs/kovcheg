import { describe, expect, it } from 'vitest';

import { foundationStatus } from './foundation.js';

describe('web foundation', () => {
  it('exposes a smoke-testable status', () => {
    expect(foundationStatus).toBe('ready');
  });
});
