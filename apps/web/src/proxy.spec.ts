import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';

import { proxy } from './proxy';

describe('A6 document privacy boundary', () => {
  it('prevents personal gate fragments from becoming referrers', () => {
    const response = proxy(new NextRequest('https://example.invalid/#gate=0123-4567'));
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
  });
});
