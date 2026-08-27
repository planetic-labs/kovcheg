import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const source = readFileSync(fileURLToPath(new URL('./client-shell.tsx', import.meta.url)), 'utf8');

describe('A6 Variant E email/passkey UI contract', () => {
  it('starts at email without the retired entry gate or a pre-authentication help surface', () => {
    const workspace = source.indexOf('function Workspace');
    const retiredBffRoute = fileURLToPath(new URL('./bff/auth/gate/route.ts', import.meta.url));
    expect(source).toContain("useState<'code' | 'email'>('email')");
    expect(source.slice(0, workspace)).not.toMatch(/personal.?gate|gateCode|\/bff\/auth\/gate/iu);
    expect(source.slice(0, workspace)).not.toContain('<ProblemReportEntry');
    expect(existsSync(retiredBffRoute)).toBe(false);
  });

  it('keeps one current email or code surface and restores edit-back state directly', () => {
    const editBackStart = source.indexOf('aria-label="Вернуться к вводу email"');
    const editBackEnd = source.indexOf('type="button"', editBackStart);
    const editBackAction = source.slice(editBackStart, editBackEnd);
    const restoreEmail = editBackAction.indexOf('setEmail(submittedEmail);');
    const showEmailStep = editBackAction.indexOf("setStep('email');");

    expect(source).toContain("step === 'email'");
    expect(source).toContain("step === 'code'");
    expect(source).toContain('email.length > 0');
    expect(source).toContain('aria-label="Продолжить"');
    expect(source).toContain('aria-label="Вернуться к вводу email"');
    expect(source).toContain('className="auth-email-display"');
    expect(source).toContain('{submittedEmail}');
    expect(restoreEmail).toBeGreaterThan(-1);
    expect(restoreEmail).toBeLessThan(showEmailStep);
    expect(editBackAction).not.toContain("setEmail('')");
    expect(editBackAction.match(/requestAnimationFrame/gu)).toHaveLength(1);
    expect(editBackAction).toContain('requestAnimationFrame(() => emailInput.current?.focus());');
    expect(source).toContain('Запросить новый код');
  });

  it('uses the same parsed code transition while local and transport failures stay at email', () => {
    expect(source).toContain('prepareEmailSubmission(value)');
    expect(source).toContain('cancelPasskeyCeremony()');
    expect(source).toContain("emailFallbackChosen ? 'email' : 'username webauthn'");
    expect(source).toContain('parseEmailChallengeResponse(await jsonOrNull(response))');
    expect(source).toContain("if (!resend) setStep('email')");
    expect(source).not.toContain("setStep('gate')");
  });

  it('preserves quiet conditional passkey mediation and authenticated registration only', () => {
    const workspace = source.indexOf('function Workspace');
    const registrationAction = source.indexOf('Добавить passkey');
    expect(source).toContain('conditionalPasskeyStarted.current');
    expect(source).toContain('attemptConditionalPasskey()');
    expect(source).toContain("'username webauthn'");
    expect(registrationAction).toBeGreaterThan(workspace);
    expect(source.slice(0, workspace)).not.toContain('Добавить passkey');
  });
});
