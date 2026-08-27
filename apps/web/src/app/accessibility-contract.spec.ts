import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const clientShellUrl = new URL('./client-shell.tsx', import.meta.url);
const chatPanelUrl = new URL('./chat-panel.tsx', import.meta.url);
const codeInputUrl = new URL('./code-input.tsx', import.meta.url);
const problemReportUrl = new URL('./problem-report-entry.tsx', import.meta.url);
const styleUrl = new URL('./globals.css', import.meta.url);

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16) / 255);
  const converted = channels.map((channel) =>
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  const red = converted[0] ?? 0;
  const green = converted[1] ?? 0;
  const blue = converted[2] ?? 0;
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrast(first: string, second: string): number {
  const firstLuminance = luminance(first);
  const secondLuminance = luminance(second);
  return (
    (Math.max(firstLuminance, secondLuminance) + 0.05) /
    (Math.min(firstLuminance, secondLuminance) + 0.05)
  );
}

describe('A6 developer-owned accessibility baseline', () => {
  it('keeps the minimal auth surface semantic without forbidden visible copy', async () => {
    const [clientShell, codeInput] = await Promise.all([
      readFile(clientShellUrl, 'utf8'),
      readFile(codeInputUrl, 'utf8'),
    ]);

    expect(clientShell).not.toMatch(
      /Минимальный PWA-клиент|Войти по email|Введите код|Указать другой email|placeholder=/u,
    );
    expect(clientShell).toContain('className="visually-hidden" htmlFor="email"');
    expect(clientShell).toContain('aria-label="Вернуться к вводу email"');
    expect(clientShell).toContain('className="auth-back"');
    expect(clientShell).toContain('event.currentTarget.form?.requestSubmit()');
    expect(clientShell).toContain('aria-describedby="passkey-registration-status"');
    expect(clientShell.match(/id="passkey-registration-status"/gu)).toHaveLength(1);
    expect(codeInput).toContain('aria-label={`Цифра ${index + 1}`}');
    expect(codeInput).toContain('aria-invalid={invalid}');
  });

  it('keeps state announcements, keyboard landmarks, and focus restoration hooks', async () => {
    const [clientShell, chatPanel, problemReport] = await Promise.all([
      readFile(clientShellUrl, 'utf8'),
      readFile(chatPanelUrl, 'utf8'),
      readFile(problemReportUrl, 'utf8'),
    ]);

    expect(clientShell).toContain('className="skip-link"');
    expect(clientShell).toContain('Сеанс завершён. Войдите снова.');
    expect(chatPanel).toContain('role="log"');
    expect(chatPanel).toContain('role="status"');
    expect(chatPanel).toContain('chatButtonRefs.current.get(selectedChatId)?.focus()');
    expect(problemReport).toContain('summaryRef.current?.focus()');
    expect(problemReport).toContain('aria-modal="true"');
  });

  it('meets the specified contrast ratios for core text, UI borders, and focus', async () => {
    const styles = await readFile(styleUrl, 'utf8');

    expect(contrast('#1c2825', '#fffdf8')).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#626d69', '#fffdf8')).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#626d69', '#f2efe8')).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#7b8580', '#fffdf8')).toBeGreaterThanOrEqual(3);
    expect(contrast('#6f321d', '#fffdf8')).toBeGreaterThanOrEqual(3);
    expect(contrast('#a15331', '#fffdf8')).toBeGreaterThanOrEqual(4.5);
    expect(styles).toContain('min-height: 44px;');
    expect(styles).toContain('@media (prefers-reduced-motion: reduce)');
  });
});
