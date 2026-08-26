import { describe, expect, it } from 'vitest';

import manifest from './manifest';

describe('A6 PWA manifest', () => {
  it('supports standalone desktop and mobile installation without A6.5 surfaces', () => {
    const value = manifest();
    expect(value).toMatchObject({
      display: 'standalone',
      orientation: 'any',
      scope: '/',
      start_url: '/',
    });
    expect(JSON.stringify(value)).not.toMatch(/push|service.?worker|subscription/iu);
  });
});
