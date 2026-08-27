import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const source = readFileSync(fileURLToPath(new URL('./client-shell.tsx', import.meta.url)), 'utf8');

describe('A6 personal gate UI contract', () => {
  it('cleans the fragment before exchanging the code and keeps wrong email at email entry', () => {
    const cleanup = source.indexOf('window.history.replaceState');
    const activation = source.indexOf('void activateGate(initialGateCode)');
    expect(cleanup).toBeGreaterThan(-1);
    expect(activation).toBeGreaterThan(cleanup);
    expect(source).toContain("if (payload?.next === 'code') setStep('code')");
  });

  it('renders exactly one current gate, email, or code control without CAPTCHA', () => {
    expect(source).toContain("hidden={step !== 'gate'}");
    expect(source).toContain("hidden={step !== 'email'}");
    expect(source).toContain("step === 'code'");
    expect(source.toLowerCase()).not.toContain('captcha');
    expect(source).not.toContain('trusted device');
  });

  it('adds quiet conditional passkey mediation without a pre-authentication button', () => {
    const workspace = source.indexOf('function Workspace');
    const registrationAction = source.indexOf('Добавить passkey');
    expect(source).toContain('conditionalPasskeyStarted.current');
    expect(source).toContain('attemptConditionalPasskey()');
    expect(source).toContain('autoComplete="webauthn"');
    expect(source).toContain('autoComplete="username webauthn"');
    expect(registrationAction).toBeGreaterThan(workspace);
    expect(source.slice(0, workspace)).not.toContain('Добавить passkey');
  });
});
