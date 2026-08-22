import { describe, expect, it } from 'vitest';

import { foundationContractVersion } from './index.js';

describe('foundation contracts', () => {
  it('exports an explicit contract version', () => {
    expect(foundationContractVersion).toBe(1);
  });
});
