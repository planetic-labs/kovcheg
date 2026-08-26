import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const sourceUrl = new URL('./problem-report-entry.tsx', import.meta.url);

describe('A6 problem-report entry', () => {
  it('exposes the accessible entry and an honest unavailable surface', async () => {
    const source = await readFile(sourceUrl, 'utf8');

    expect(source).toContain('aria-label="Открыть помощь"');
    expect(source).toContain('Сообщить о проблеме');
    expect(source).toContain('aria-modal="true"');
    expect(source).toContain('role="dialog"');
    expect(source).toContain('normalizeProblemReportContext(context)');
    expect(source).toContain('Сейчас сведения не отправляются и не');
    expect(source).toContain('сохраняются.');
    expect(source).not.toContain('<form');
    expect(source).not.toContain('type="submit"');
  });

  it('contains no submission, persistence, clipboard, or capture primitive', async () => {
    const source = await readFile(sourceUrl, 'utf8');

    for (const forbidden of [
      'fetch(',
      'XMLHttpRequest',
      'sendBeacon',
      'localStorage',
      'sessionStorage',
      'indexedDB',
      'clipboard',
      'getDisplayMedia',
      'getUserMedia',
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(source).toContain("event.key === 'Escape'");
    expect(source).toContain("event.key !== 'Tab'");
    expect(source).toContain('closeButtonRef.current?.focus()');
    expect(source).toContain('summaryRef.current?.focus()');
  });
});
