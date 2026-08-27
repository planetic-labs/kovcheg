import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';

import { proxy } from './proxy';

describe('A6 document privacy boundary', () => {
  it('prevents URL fragments from becoming referrers', () => {
    const response = proxy(new NextRequest('https://example.invalid/#local-fragment'));
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
  });
});
