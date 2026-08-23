import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const sourceUrl = new URL('./chat-panel.tsx', import.meta.url);
const styleUrl = new URL('./globals.css', import.meta.url);
const assetUrl = new URL('../../public/SERDTsA.png', import.meta.url);

describe('A6 visible send control', () => {
  it('keeps the approved public asset byte-identical', async () => {
    const asset = await readFile(assetUrl);
    expect(createHash('sha256').update(asset).digest('hex')).toBe(
      '0198fab41da9b42c464f0997682365df112b690a716f45bd386c2c82dbcf2182',
    );
  });

  it('exposes a visible accessible submit that follows the draft state', async () => {
    const [source, styles] = await Promise.all([
      readFile(sourceUrl, 'utf8'),
      readFile(styleUrl, 'utf8'),
    ]);

    expect(source).toContain('<form className="composer" onSubmit={submitDraft}>');
    expect(source).toMatch(
      /aria-label="Отправить сообщение"[\s\S]*className="send-button"[\s\S]*disabled=\{draft\.trim\(\)\.length === 0\}[\s\S]*type="submit"/u,
    );
    expect(source).not.toContain('className="visually-hidden" type="submit"');
    expect(styles).toContain("url('/SERDTsA.png')");
    expect(styles).toContain('border: 1px solid var(--line);');
    expect(styles).toContain('.send-button:disabled');
  });
});
