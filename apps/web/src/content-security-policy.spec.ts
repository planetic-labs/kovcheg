import { describe, expect, it } from 'vitest';

import { contentSecurityPolicy } from './content-security-policy.js';

describe('web content security policy', () => {
  it('requires a nonce without wildcard or unsafe production directives', () => {
    const policy = contentSecurityPolicy('test-nonce', false);

    expect(policy).toContain("connect-src 'self'");
    expect(policy).toContain("script-src 'self' 'nonce-test-nonce' 'strict-dynamic'");
    expect(policy).toContain("style-src 'self' 'nonce-test-nonce'");
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("'unsafe-eval'");
    expect(policy).not.toMatch(/(?:^|\s)wss?:/);
  });

  it('allows only the documented local development fallbacks', () => {
    const policy = contentSecurityPolicy('development-nonce', true);

    expect(policy).toContain(
      "script-src 'self' 'nonce-development-nonce' 'strict-dynamic' 'unsafe-eval'",
    );
    expect(policy).toContain("style-src 'self' 'unsafe-inline'");
  });
});
