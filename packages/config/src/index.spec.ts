import { describe, expect, it } from 'vitest';

import { serviceDefaults } from './index.js';

describe('foundation configuration', () => {
  it('keeps public defaults immutable', () => {
    expect(Object.isFrozen(serviceDefaults)).toBe(true);
  });
});
